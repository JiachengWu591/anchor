//! 线路控制器（P1b；设计见 P1 详细设计“线路切换控制器”一节）。
//!
//! 线路组是 selector，选哪条线路由这里决定。只在当前线路坏了或明显更差时才换，每次换线都有原因：
//! - down：当前线路探测失败，立刻把所有线路测一遍，换到可用里最好的一条；全部不可用只报告一次。
//! - flaky：当前线路 5 分钟成功率低于 90%，另一条不低于 99%。
//! - slow：当前线路的延迟中位数比最好的一条高出 150 ms 且高出 50% 以上，持续 5 分钟。
//! - manual：用户用 anchor line use / pin 指定。
//!
//! 距上一次换线不到 2 分钟时不因 flaky / slow 换线（down 照换）；固定了线路或手动模式时只报告、不换；
//! 旧线路恢复了也不回切。不用 sing-box 的 urltest 自己选线：它只在定时检测时反应，延迟差一点
//! （容差 50 ms）就换，来回抖，也不留换线原因，归因无从谈起。
//!
//! 这里只有判断，不碰网络：驱动它的线程（用户代理的 lines 模块）负责探测、调用 Clash API、写时间线。

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
pub struct Tuning {
    /// 评分看最近这么久的探测
    pub window: Duration,
    /// 当前线路的探测间隔：有 AI 连接（或线路正出问题）时、空闲时
    pub active_every: Duration,
    pub idle_every: Duration,
    /// 其他线路的探测间隔
    pub others_every: Duration,
    pub flaky_below: f64,
    pub healthy_from: f64,
    /// 样本少于这么多时不做 flaky / slow 的判断
    pub min_samples_current: usize,
    pub min_samples_other: usize,
    pub slow_abs_ms: u64,
    pub slow_ratio: f64,
    pub slow_for: Duration,
    /// 距上一次换线不到这么久，不因 flaky / slow 换线
    pub dwell: Duration,
}

impl Tuning {
    pub fn new(active_every: Duration, others_every: Duration) -> Self {
        Self {
            window: Duration::from_secs(300),
            active_every,
            idle_every: Duration::from_secs(15).max(active_every),
            others_every,
            flaky_below: 0.90,
            healthy_from: 0.99,
            min_samples_current: 10,
            min_samples_other: 5,
            slow_abs_ms: 150,
            slow_ratio: 1.5,
            slow_for: Duration::from_secs(300),
            dwell: Duration::from_secs(120),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineSpec {
    pub name: String,
    /// 数字小的优先（评分接近时）；没写的排在写了的后面
    pub priority: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// 把线路组切到 to
    Switch { from: String, to: String, reason: &'static str, ms: Option<u64> },
    /// 当前线路不通，但线路被固定（pinned）或是手动模式（manual）：只报告，恢复前只报一次
    LineDown { line: String, why: &'static str },
    /// 所有线路都不通（恢复前只报一次）
    AllDown { line: String },
    /// 报告过故障之后恢复可用
    Recovered { line: String },
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Step {
    pub actions: Vec<Action>,
    /// 当前线路刚探测失败：驱动方应立刻把所有线路测一遍，再调用 on_sweep
    pub sweep: bool,
}

/// 一条线路的评分（anchor line list 显示）。
#[derive(Debug, Clone, PartialEq)]
pub struct LineView {
    pub name: String,
    pub priority: u32,
    pub current: bool,
    pub pinned: bool,
    pub samples: usize,
    /// 最近 5 分钟的成功率（0～1）；没有样本时为 None
    pub rate: Option<f64>,
    pub median_ms: Option<u64>,
    /// 最近一次探测：Some(Some(ms)) 成功，Some(None) 失败，None 还没测过
    pub last: Option<Option<u64>>,
}

#[derive(Default)]
struct Stats {
    samples: VecDeque<(Instant, Option<u64>)>,
    last_probe: Option<Instant>,
}

impl Stats {
    fn prune(&mut self, now: Instant, window: Duration) {
        while self.samples.front().is_some_and(|(t, _)| now.saturating_duration_since(*t) > window) {
            self.samples.pop_front();
        }
    }

    fn rate(&self) -> Option<f64> {
        if self.samples.is_empty() {
            return None;
        }
        Some(self.samples.iter().filter(|(_, r)| r.is_some()).count() as f64 / self.samples.len() as f64)
    }

    fn median(&self) -> Option<u64> {
        let mut v: Vec<u64> = self.samples.iter().filter_map(|(_, r)| *r).collect();
        if v.is_empty() {
            return None;
        }
        v.sort_unstable();
        Some(v[v.len() / 2])
    }

    fn last(&self) -> Option<Option<u64>> {
        self.samples.back().map(|(_, r)| *r)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Down {
    No,
    /// 报告过“当前线路不通”（固定或手动模式）
    Line,
    /// 报告过“所有线路都不通”
    All,
}

pub struct Controller {
    lines: Vec<LineSpec>,
    stats: HashMap<String, Stats>,
    current: String,
    pinned: Option<String>,
    /// 自动换线（配置里 lines = "auto"）
    auto: bool,
    t: Tuning,
    last_switch: Option<Instant>,
    /// 当前线路从什么时候起一直比 (另一条) 明显慢
    slow_since: Option<Instant>,
    down: Down,
}

impl Controller {
    /// lines 不能为空。起始线路：固定的那条；否则优先级最高（数字最小）的一条。
    pub fn new(lines: Vec<LineSpec>, auto: bool, pinned: Option<String>, t: Tuning) -> Self {
        let pinned = pinned.filter(|p| lines.iter().any(|l| &l.name == p));
        let current = pinned.clone().unwrap_or_else(|| lines.iter().min_by_key(|l| l.priority).map(|l| l.name.clone()).unwrap_or_default());
        let stats = lines.iter().map(|l| (l.name.clone(), Stats::default())).collect();
        Self { lines, stats, current, pinned, auto, t, last_switch: None, slow_since: None, down: Down::No }
    }

    pub fn current(&self) -> &str {
        &self.current
    }

    pub fn pinned(&self) -> Option<&str> {
        self.pinned.as_deref()
    }

    /// 线路正出问题（报告过当前线路或全部线路不通）
    pub fn degraded(&self) -> bool {
        self.down != Down::No
    }

    pub fn all_down(&self) -> bool {
        self.down == Down::All
    }

    /// 现在该探测哪些线路，并记下已经安排。active：此刻有 AI 连接。
    pub fn due(&mut self, now: Instant, active: bool) -> Vec<String> {
        let cur_every = if active || self.degraded() { self.t.active_every } else { self.t.idle_every };
        let mut out = Vec::new();
        for l in &self.lines {
            let every = if l.name == self.current { cur_every } else { self.t.others_every };
            let st = self.stats.entry(l.name.clone()).or_default();
            if st.last_probe.is_none_or(|t| now.saturating_duration_since(t) >= every) {
                st.last_probe = Some(now);
                out.push(l.name.clone());
            }
        }
        out
    }

    /// 立刻测一次当前线路（刚记到断联时用）：下一次 due 就会把它排上。
    pub fn probe_now(&mut self) {
        if let Some(st) = self.stats.get_mut(&self.current) {
            st.last_probe = None;
        }
    }

    fn record(&mut self, now: Instant, line: &str, result: Option<u64>) {
        let window = self.t.window;
        if let Some(st) = self.stats.get_mut(line) {
            st.samples.push_back((now, result));
            st.prune(now, window);
        }
    }

    /// 一次定时探测的结果。
    pub fn on_probe(&mut self, now: Instant, line: &str, result: Option<u64>) -> Step {
        self.record(now, line, result);
        if line == self.current {
            if result.is_none() {
                return Step { actions: vec![], sweep: true };
            }
            let mut actions = Vec::new();
            if self.down != Down::No {
                self.down = Down::No;
                actions.push(Action::Recovered { line: self.current.clone() });
            }
            actions.extend(self.evaluate(now));
            return Step { actions, sweep: false };
        }
        Step { actions: self.evaluate(now).into_iter().collect(), sweep: false }
    }

    /// 当前线路探测失败后，把所有线路测了一遍的结果。
    pub fn on_sweep(&mut self, now: Instant, results: &[(String, Option<u64>)]) -> Vec<Action> {
        for (line, r) in results {
            self.record(now, line, *r);
            if let Some(st) = self.stats.get_mut(line) {
                st.last_probe = Some(now);
            }
        }
        let ok = |name: &str| results.iter().find(|(l, _)| l == name).and_then(|(_, r)| *r);
        let mut actions = Vec::new();
        // 复测时当前线路是通的：刚才是偶发失败，不换
        if ok(&self.current).is_some() {
            if self.down != Down::No {
                self.down = Down::No;
                actions.push(Action::Recovered { line: self.current.clone() });
            }
            return actions;
        }
        let candidates: Vec<&LineSpec> = self.lines.iter().filter(|l| l.name != self.current && ok(&l.name).is_some()).collect();
        if candidates.is_empty() {
            if self.down != Down::All {
                self.down = Down::All;
                actions.push(Action::AllDown { line: self.current.clone() });
            }
            return actions;
        }
        let stuck = if self.pinned.is_some() {
            Some("pinned")
        } else if !self.auto {
            Some("manual")
        } else {
            None
        };
        if let Some(why) = stuck {
            if self.down == Down::No {
                self.down = Down::Line;
                actions.push(Action::LineDown { line: self.current.clone(), why });
            }
            return actions;
        }
        let best = self.choose(&candidates, |n| ok(n)).name.clone();
        let was_down = self.down != Down::No;
        actions.push(self.switch(now, &best, "down", ok(&best)));
        if was_down {
            actions.push(Action::Recovered { line: best });
        }
        actions
    }

    fn switch(&mut self, now: Instant, to: &str, reason: &'static str, ms: Option<u64>) -> Action {
        let from = std::mem::replace(&mut self.current, to.to_string());
        self.last_switch = Some(now);
        self.slow_since = None;
        self.down = Down::No;
        Action::Switch { from, to: to.to_string(), reason, ms }
    }

    /// 在候选里选最好的：按优先级（数字小在前）、配置顺序依次看，后面的只有“明显更好”才顶替前面的。
    /// 明显更好：成功率高出 5 个百分点以上；或成功率相近、延迟中位数低出 50 ms 且 20% 以上。
    fn choose<'a>(&self, candidates: &[&'a LineSpec], sweep_ms: impl Fn(&str) -> Option<u64>) -> &'a LineSpec {
        let rate = |n: &str| self.stats.get(n).and_then(Stats::rate).unwrap_or(1.0);
        let median = |n: &str| self.stats.get(n).and_then(Stats::median).or_else(|| sweep_ms(n));
        let mut order: Vec<&LineSpec> = candidates.to_vec();
        order.sort_by_key(|l| l.priority);
        let mut best = order[0];
        for c in &order[1..] {
            let (rc, rb) = (rate(&c.name), rate(&best.name));
            let better = if (rc - rb).abs() > 0.05 {
                rc > rb
            } else {
                match (median(&c.name), median(&best.name)) {
                    (Some(mc), Some(mb)) => mc + 50 < mb && (mc as f64) * 1.2 < mb as f64,
                    _ => false,
                }
            };
            if better {
                best = c;
            }
        }
        best
    }

    /// flaky / slow：当前线路还通着，但明显不如另一条。
    fn evaluate(&mut self, now: Instant) -> Option<Action> {
        if !self.auto || self.pinned.is_some() || self.down != Down::No {
            self.slow_since = None;
            return None;
        }
        let window = self.t.window;
        for st in self.stats.values_mut() {
            st.prune(now, window);
        }
        let cur = self.stats.get(&self.current)?;
        let (cur_n, cur_rate, cur_median) = (cur.samples.len(), cur.rate()?, cur.median());
        // 其他线路里样本够、最近一次探测是通的
        let others: Vec<&LineSpec> = self
            .lines
            .iter()
            .filter(|l| l.name != self.current)
            .filter(|l| self.stats.get(&l.name).is_some_and(|s| s.samples.len() >= self.t.min_samples_other && matches!(s.last(), Some(Some(_)))))
            .collect();
        let rate = |n: &str| self.stats.get(n).and_then(Stats::rate).unwrap_or(0.0);
        let median = |n: &str| self.stats.get(n).and_then(Stats::median);
        let settled = self.last_switch.is_none_or(|t| now.saturating_duration_since(t) >= self.t.dwell);

        // slow：先更新“持续了多久”，再看能不能换
        let faster: Vec<&LineSpec> = others
            .iter()
            .copied()
            .filter(|l| rate(&l.name) >= self.t.flaky_below.max(cur_rate - 0.05))
            .filter(|l| match (cur_median, median(&l.name)) {
                (Some(c), Some(o)) => c > o + self.t.slow_abs_ms && c as f64 > o as f64 * self.t.slow_ratio,
                _ => false,
            })
            .collect();
        if faster.is_empty() || cur_n < self.t.min_samples_current {
            self.slow_since = None;
        } else {
            self.slow_since.get_or_insert(now);
        }

        if !settled || cur_n < self.t.min_samples_current {
            return None;
        }
        if cur_rate < self.t.flaky_below {
            let healthy: Vec<&LineSpec> = others.iter().copied().filter(|l| rate(&l.name) >= self.t.healthy_from).collect();
            if !healthy.is_empty() {
                let to = self.choose(&healthy, |_| None).name.clone();
                let ms = median(&to);
                return Some(self.switch(now, &to, "flaky", ms));
            }
        }
        if self.slow_since.is_some_and(|t| now.saturating_duration_since(t) >= self.t.slow_for) && !faster.is_empty() {
            let to = self.choose(&faster, |_| None).name.clone();
            let ms = median(&to);
            return Some(self.switch(now, &to, "slow", ms));
        }
        None
    }

    fn known(&self, name: &str) -> Result<(), String> {
        if self.lines.iter().any(|l| l.name == name) {
            Ok(())
        } else {
            let names: Vec<&str> = self.lines.iter().map(|l| l.name.as_str()).collect();
            Err(format!("没有叫 {name} 的线路（有：{}）", names.join("、")))
        }
    }

    /// anchor line use：手动换线。固定着别的线路时拒绝。
    pub fn use_line(&mut self, now: Instant, name: &str) -> Result<Vec<Action>, String> {
        self.known(name)?;
        if let Some(p) = &self.pinned
            && p != name
        {
            return Err(format!("线路已固定在 {p}：先运行 anchor line unpin，或用 anchor line pin {name} 改固定到这一条"));
        }
        Ok(self.go(now, name))
    }

    /// anchor line pin：固定线路（同时切过去）。固定后不自动换线。
    pub fn pin(&mut self, now: Instant, name: &str) -> Result<Vec<Action>, String> {
        self.known(name)?;
        self.pinned = Some(name.to_string());
        Ok(self.go(now, name))
    }

    pub fn unpin(&mut self) -> Option<String> {
        // 取消固定后，下一次探测失败会按规则换线；之前报告过的“线路不通”留给恢复或换线来清
        self.pinned.take()
    }

    fn go(&mut self, now: Instant, name: &str) -> Vec<Action> {
        if self.current == name {
            return vec![];
        }
        let ms = self.stats.get(name).and_then(|s| s.last()).flatten();
        vec![self.switch(now, name, "manual", ms)]
    }

    pub fn view(&mut self, now: Instant) -> Vec<LineView> {
        let window = self.t.window;
        self.lines
            .iter()
            .map(|l| {
                let st = self.stats.entry(l.name.clone()).or_default();
                st.prune(now, window);
                LineView {
                    name: l.name.clone(),
                    priority: l.priority,
                    current: l.name == self.current,
                    pinned: self.pinned.as_deref() == Some(l.name.as_str()),
                    samples: st.samples.len(),
                    rate: st.rate(),
                    median_ms: st.median(),
                    last: st.last(),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn ctl(auto: bool, pinned: Option<&str>) -> (Controller, Instant) {
        let lines = vec![LineSpec { name: "a".into(), priority: 1 }, LineSpec { name: "b".into(), priority: 2 }, LineSpec { name: "c".into(), priority: 2 }];
        (Controller::new(lines, auto, pinned.map(String::from), Tuning::new(secs(3), secs(30))), Instant::now())
    }

    fn sweep(v: &[(&str, Option<u64>)]) -> Vec<(String, Option<u64>)> {
        v.iter().map(|(n, r)| (n.to_string(), *r)).collect()
    }

    /// 喂 n 次探测，每次间隔 step 秒；返回最后的时间和期间出现的动作
    fn feed(c: &mut Controller, mut t: Instant, n: usize, step: u64, f: impl Fn(usize) -> Vec<(&'static str, Option<u64>)>) -> (Instant, Vec<Action>) {
        let mut out = Vec::new();
        for i in 0..n {
            t += secs(step);
            for (line, r) in f(i) {
                out.extend(c.on_probe(t, line, r).actions);
            }
        }
        (t, out)
    }

    #[test]
    fn starts_on_the_pinned_or_highest_priority_line() {
        assert_eq!(ctl(true, None).0.current(), "a");
        assert_eq!(ctl(true, Some("c")).0.current(), "c");
        assert_eq!(ctl(true, Some("gone")).0.current(), "a", "固定的线路已经不在配置里");
    }

    #[test]
    fn probes_current_often_and_others_rarely() {
        let (mut c, t0) = ctl(true, None);
        assert_eq!(c.due(t0, true), ["a", "b", "c"], "启动时都测一遍");
        assert!(c.due(t0 + secs(2), true).is_empty());
        assert_eq!(c.due(t0 + secs(3), true), ["a"], "有 AI 连接：当前线路 3 秒一次");
        assert!(c.due(t0 + secs(10), false).is_empty(), "空闲：15 秒一次");
        assert_eq!(c.due(t0 + secs(18), false), ["a"]);
        assert_eq!(c.due(t0 + secs(30), true), ["a", "b", "c"], "其他线路 30 秒一次");
        c.probe_now();
        assert_eq!(c.due(t0 + secs(31), false), ["a"]);
    }

    #[test]
    fn current_failure_sweeps_then_switches_to_the_best_available() {
        let (mut c, t0) = ctl(true, None);
        assert_eq!(c.on_probe(t0, "a", Some(100)), Step::default());
        let s = c.on_probe(t0 + secs(3), "a", None);
        assert!(s.sweep && s.actions.is_empty());
        // b、c 优先级相同、延迟相近：按配置顺序用 b
        let a = c.on_sweep(t0 + secs(4), &sweep(&[("a", None), ("b", Some(300)), ("c", Some(280))]));
        assert_eq!(a, [Action::Switch { from: "a".into(), to: "b".into(), reason: "down", ms: Some(300) }]);
        assert_eq!(c.current(), "b");
        // 旧线路恢复了也不回切
        let (_, acts) = feed(&mut c, t0 + secs(4), 200, 3, |_| vec![("b", Some(300)), ("a", Some(250))]);
        assert!(acts.is_empty(), "a 恢复了、也快一点，但没到 slow 的门槛，不回切：{acts:?}");
    }

    #[test]
    fn a_clearly_faster_candidate_beats_priority() {
        let (mut c, t0) = ctl(true, None);
        c.on_probe(t0, "a", None);
        let a = c.on_sweep(t0, &sweep(&[("a", None), ("b", Some(900)), ("c", Some(200))]));
        assert!(matches!(&a[0], Action::Switch { to, .. } if to == "c"), "c 比 b 快得多：{a:?}");
    }

    #[test]
    fn transient_failure_keeps_the_line() {
        let (mut c, t0) = ctl(true, None);
        assert!(c.on_probe(t0, "a", None).sweep);
        assert!(c.on_sweep(t0, &sweep(&[("a", Some(120)), ("b", Some(300)), ("c", None)])).is_empty());
        assert_eq!(c.current(), "a");
    }

    #[test]
    fn all_down_is_reported_once_and_recovery_switches() {
        let (mut c, t0) = ctl(true, None);
        let none = sweep(&[("a", None), ("b", None), ("c", None)]);
        c.on_probe(t0, "a", None);
        assert_eq!(c.on_sweep(t0, &none), [Action::AllDown { line: "a".into() }]);
        assert!(c.degraded() && c.all_down());
        c.on_probe(t0 + secs(3), "a", None);
        assert!(c.on_sweep(t0 + secs(3), &none).is_empty(), "只报告一次");
        assert_eq!(c.due(t0 + secs(100), false).first().map(String::as_str), Some("a"));
        assert!(c.due(t0 + secs(103), false).contains(&"a".to_string()), "出问题时即使空闲也按 3 秒探测");
        // c 先恢复：换过去，并报告恢复
        c.on_probe(t0 + secs(106), "a", None);
        let a = c.on_sweep(t0 + secs(106), &sweep(&[("a", None), ("b", None), ("c", Some(250))]));
        assert_eq!(a, [Action::Switch { from: "a".into(), to: "c".into(), reason: "down", ms: Some(250) }, Action::Recovered { line: "c".into() }]);
        assert!(!c.degraded());
    }

    #[test]
    fn all_down_then_current_recovers_in_place() {
        let (mut c, t0) = ctl(true, None);
        c.on_probe(t0, "a", None);
        c.on_sweep(t0, &sweep(&[("a", None), ("b", None), ("c", None)]));
        assert_eq!(c.on_probe(t0 + secs(3), "a", Some(90)).actions, [Action::Recovered { line: "a".into() }]);
    }

    #[test]
    fn pinned_or_manual_mode_only_reports() {
        for (auto, pin, why) in [(true, Some("a"), "pinned"), (false, None, "manual")] {
            let (mut c, t0) = ctl(auto, pin);
            c.on_probe(t0, "a", None);
            let others_ok = sweep(&[("a", None), ("b", Some(200)), ("c", Some(200))]);
            assert_eq!(c.on_sweep(t0, &others_ok), [Action::LineDown { line: "a".into(), why }]);
            c.on_probe(t0 + secs(3), "a", None);
            assert!(c.on_sweep(t0 + secs(3), &others_ok).is_empty(), "只报告一次");
            assert_eq!(c.current(), "a");
            assert_eq!(c.on_probe(t0 + secs(6), "a", Some(80)).actions, [Action::Recovered { line: "a".into() }]);
        }
    }

    #[test]
    fn flaky_line_is_left_for_a_healthy_one_but_not_within_the_dwell_time() {
        let (mut c, t0) = ctl(true, None);
        // a 每 5 次失败 1 次（80%），b 全部成功；失败后的复测是通的，所以不算 down
        let (t, acts) = feed(&mut c, t0, 40, 3, |i| vec![("a", if i % 5 == 0 { None } else { Some(100) }), ("b", Some(200))]);
        let first = acts.iter().find(|a| matches!(a, Action::Switch { .. })).expect("应因 flaky 换线");
        assert!(matches!(first, Action::Switch { from, to, reason: "flaky", .. } if from == "a" && to == "b"), "{first:?}");
        // 刚换完 2 分钟内：b 变差、a 变好，也不因 flaky 换回去
        let (_, acts) = feed(&mut c, t, 30, 3, |i| vec![("b", if i % 3 == 0 { None } else { Some(200) }), ("a", Some(100))]);
        assert!(acts.is_empty(), "停留时间内不换：{acts:?}");
    }

    #[test]
    fn slow_line_is_left_only_after_five_minutes() {
        let (mut c, t0) = ctl(true, None);
        // a 400 ms，b 150 ms：高出 250 ms、2.7 倍
        let (t, acts) = feed(&mut c, t0, 90, 3, |_| vec![("a", Some(400)), ("b", Some(150))]);
        assert!(acts.is_empty(), "不到 5 分钟（要先攒够样本）不换：{acts:?}");
        let (_, acts) = feed(&mut c, t, 40, 3, |_| vec![("a", Some(400)), ("b", Some(150))]);
        assert!(matches!(acts.first(), Some(Action::Switch { to, reason: "slow", .. }) if to == "b"), "{acts:?}");
        // 差距不够大（高出 100 ms）不算慢
        let (mut c, t0) = ctl(true, None);
        let (_, acts) = feed(&mut c, t0, 250, 3, |_| vec![("a", Some(300)), ("b", Some(200))]);
        assert!(acts.is_empty());
    }

    #[test]
    fn manual_use_and_pin() {
        let (mut c, t0) = ctl(true, None);
        assert_eq!(c.use_line(t0, "b").unwrap(), [Action::Switch { from: "a".into(), to: "b".into(), reason: "manual", ms: None }]);
        assert!(c.use_line(t0, "b").unwrap().is_empty(), "已经在用");
        assert!(c.use_line(t0, "nope").is_err());
        assert_eq!(c.pin(t0, "c").unwrap().len(), 1);
        assert_eq!((c.current(), c.pinned()), ("c", Some("c")));
        assert!(c.use_line(t0, "a").unwrap_err().contains("unpin"), "固定着别的线路时不让手动换");
        assert_eq!(c.unpin().as_deref(), Some("c"));
        assert!(c.use_line(t0, "a").is_ok());
        let v = c.view(t0);
        assert!(v.iter().any(|l| l.name == "a" && l.current && !l.pinned));
    }
}
