//! 出口核对与锁定的状态机（P1b；决定见 docs/p1b-decisions.md 的 Q2）。
//!
//! 只有逻辑，不做网络请求：调用方在 `due()` 返回来源时去问那个 IP 回显服务，把结果交给
//! `on_check()`，再执行返回的动作（锁住 / 放行 AI 通道、记时间线、发通知）。
//!
//! - 网络变化、内核启动、出口不可达之后：先锁住，一个来源返回基线 IP 就放行（先核对再放行）。
//! - 放行期间定时核对：两个不同来源都说变了才锁住，避免回显服务偶发出错时误锁。
//! - 锁住后继续核对：回到基线自动放行；只有接受新 IP 才需要用户操作（anchor baseline）。
//! - 出口可达、但回显服务都连不上：保持锁住并通知。

use serde::Serialize;
use serde_json::{Value, json};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// 为什么要先锁住再核对。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// 内核（重新）启动：sing-box 以 Lock 模式启动
    KernelStart,
    /// 网卡、地址或默认路由变化（VPN 重连、换网络）
    NetworkChange,
    /// 用户要求立即核对
    Recheck,
}

impl Trigger {
    pub fn name(self) -> &'static str {
        match self {
            Trigger::KernelStart => "kernel_start",
            Trigger::NetworkChange => "network_change",
            Trigger::Recheck => "recheck",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// 出口与基线一致，AI 通道放行
    Open,
    /// 锁住，正在核对
    Verifying,
    /// 两个来源确认出口 IP 与基线不同
    Changed,
    /// 出口可达，但回显服务都连不上，没法核对
    Unverifiable,
    /// 没有登记基线
    NoBaseline,
}

impl State {
    pub fn name(self) -> &'static str {
        match self {
            State::Open => "open",
            State::Verifying => "verifying",
            State::Changed => "changed",
            State::Unverifiable => "unverifiable",
            State::NoBaseline => "no_baseline",
        }
    }
    pub fn locked(self) -> bool {
        self != State::Open
    }
}

/// 一次核对的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Check {
    Match,
    Mismatch(String),
    /// 回显服务没给出可用的结果；exit_up：出口本身是否可达（经内核测整条链路）
    Failed { exit_up: bool, reason: String },
}

/// 回显到的 IP 与基线比较。地址族不同（IPv4 基线、回显到 IPv6）不算变化，当作这次没核对成。
pub fn classify(baseline: &str, ip: &str) -> Check {
    match (baseline.trim().parse::<IpAddr>(), ip.trim().parse::<IpAddr>()) {
        (Ok(b), Ok(a)) if b == a => Check::Match,
        (Ok(b), Ok(a)) if b.is_ipv4() != a.is_ipv4() => {
            Check::Failed { exit_up: true, reason: format!("回显到 {a}，与基线的地址族不同，这次不作判断") }
        }
        (Ok(_), Ok(a)) => Check::Mismatch(a.to_string()),
        _ if baseline.trim().eq_ignore_ascii_case(ip.trim()) => Check::Match,
        _ => Check::Mismatch(ip.trim().to_string()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// AI 通道拒绝新连接
    Lock,
    /// AI 通道放行
    Unlock,
    /// 记一条时间线事件
    Event(&'static str, Value),
    /// 系统通知：级别、标题、正文
    Notify(Severity, String, String),
}

#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// 放行期间的定时核对
    pub open_every: Duration,
    /// 定时核对发现不一致后，隔多久用另一个来源确认
    pub confirm_after: Duration,
    /// 锁住核对时的重试间隔；锁住超过 slow_after 后改用 retry_slow
    pub retry: Duration,
    pub retry_slow: Duration,
    pub slow_after: Duration,
    /// 出口可达、回显服务连续失败这么久，算“无法核对”
    pub unverifiable_after: Duration,
    /// 出口已变化或无法核对时，多久再核对一次（等它回到基线）
    pub locked_every: Duration,
    /// 网络变化、内核启动之后这段时间里，锁住时一律按 retry 快速重试：
    /// 隧道刚恢复时头几次核对常常失败，等 locked_every 会把恢复拖慢 10 秒
    pub fast_window: Duration,
}

impl Timing {
    pub fn new(open_every: Duration) -> Self {
        Self {
            open_every,
            confirm_after: Duration::from_secs(10),
            // 隧道刚恢复时连接会立即失败（不可达），重试很便宜；1 秒一次能在隧道真正可用后尽快放行
            retry: Duration::from_secs(1),
            retry_slow: Duration::from_secs(5),
            slow_after: Duration::from_secs(30),
            unverifiable_after: Duration::from_secs(20),
            locked_every: Duration::from_secs(10),
            fast_window: Duration::from_secs(30),
        }
    }
}

/// 给状态显示用（托盘、anchor status）。
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct View {
    /// open / verifying / changed / unverifiable / no_baseline（用户代理还没开始核对时为空）
    pub state: String,
    pub locked: bool,
    /// 这次为什么锁住：kernel_start / network_change / recheck / exit_down / periodic / no_baseline
    pub reason: String,
    pub baseline: String,
    /// 出口已变化时，实际的出口 IP
    pub actual: Option<String>,
    /// 最近一次回显到的 IP
    pub last_ip: Option<String>,
    /// 最近一次核对时出口不可达
    pub exit_down: bool,
    pub locked_ms: Option<u64>,
}

pub struct Machine {
    baseline: String,
    sources: usize,
    t: Timing,
    state: State,
    reason: &'static str,
    actual: Option<String>,
    last_ip: Option<String>,
    exit_down: bool,
    next_at: Instant,
    next_source: usize,
    /// 已经看到一次不一致，等另一个来源确认：(IP, 来源)
    suspect: Option<(String, usize)>,
    locked_at: Option<Instant>,
    /// 出口可达但回显服务一直失败，从何时开始
    echo_fail_since: Option<Instant>,
    /// 最近一次网络变化 / 内核启动之后的快速重试期截止时间
    fast_until: Option<Instant>,
}

impl Machine {
    /// 内核以 Lock 模式启动，所以一开始就是锁住的。sources：可轮换的回显服务个数。
    pub fn new(baseline: &str, sources: usize, t: Timing, now: Instant) -> (Self, Vec<Action>) {
        let baseline = baseline.trim().to_string();
        let mut m = Self {
            baseline,
            sources,
            t,
            state: State::Verifying,
            reason: Trigger::KernelStart.name(),
            actual: None,
            last_ip: None,
            exit_down: false,
            next_at: now,
            next_source: 0,
            suspect: None,
            locked_at: Some(now),
            echo_fail_since: None,
            fast_until: Some(now + t.fast_window),
        };
        if m.baseline.is_empty() {
            m.state = State::NoBaseline;
            m.reason = "no_baseline";
            return (
                m,
                vec![
                    Action::Lock,
                    Action::Event("exit_locked", json!({ "reason": "no_baseline" })),
                    Action::Notify(
                        Severity::Warn,
                        "还没有登记出口基线，AI 通道保持锁住".into(),
                        "在开始菜单打开的终端里运行 anchor baseline，登记当前出口后自动放行。".into(),
                    ),
                ],
            );
        }
        (m, vec![Action::Lock])
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn view(&self, now: Instant) -> View {
        View {
            state: self.state.name().into(),
            locked: self.state.locked(),
            reason: if self.state.locked() { self.reason.into() } else { String::new() },
            baseline: self.baseline.clone(),
            actual: self.actual.clone().filter(|_| self.state == State::Changed),
            last_ip: self.last_ip.clone(),
            exit_down: self.exit_down,
            locked_ms: self.locked_at.filter(|_| self.state.locked()).map(|t| ms(now.saturating_duration_since(t))),
        }
    }

    /// 网络变化、内核启动或用户要求：先锁住，立即核对。
    pub fn trigger(&mut self, now: Instant, tr: Trigger) -> Vec<Action> {
        if self.state != State::NoBaseline {
            self.fast_until = Some(now + self.t.fast_window);
        }
        match self.state {
            State::NoBaseline => vec![],
            State::Open => {
                self.lock(now, State::Verifying, tr.name());
                self.next_at = now;
                vec![Action::Lock, Action::Event("exit_locked", json!({ "reason": tr.name() }))]
            }
            State::Verifying | State::Unverifiable => {
                self.echo_fail_since = None;
                self.suspect = None;
                self.next_at = now;
                vec![Action::Lock]
            }
            State::Changed => {
                self.next_at = now;
                vec![Action::Lock]
            }
        }
    }

    /// 该核对了就返回要问的来源编号。
    pub fn due(&self, now: Instant) -> Option<usize> {
        if self.sources == 0 || self.state == State::NoBaseline || now < self.next_at {
            return None;
        }
        Some(self.next_source % self.sources)
    }

    pub fn on_check(&mut self, now: Instant, source: usize, check: Check) -> Vec<Action> {
        self.next_source = (source + 1) % self.sources.max(1);
        match check {
            Check::Match => self.on_match(now),
            Check::Mismatch(ip) => self.on_mismatch(now, source, ip),
            Check::Failed { exit_up, reason } => self.on_failed(now, exit_up, reason),
        }
    }

    fn on_match(&mut self, now: Instant) -> Vec<Action> {
        self.suspect = None;
        self.echo_fail_since = None;
        self.exit_down = false;
        self.last_ip = Some(self.baseline.clone());
        self.next_at = now + self.t.open_every;
        let prev = self.state;
        if prev == State::Open || prev == State::NoBaseline {
            return vec![];
        }
        let locked_ms = self.locked_at.map(|t| ms(now.saturating_duration_since(t))).unwrap_or(0);
        let why = if prev == State::Changed { "back_to_baseline" } else { "verified" };
        let mut out = vec![
            Action::Unlock,
            Action::Event(
                "exit_unlocked",
                json!({ "reason": why, "trigger": self.reason, "ip": self.baseline, "locked_ms": locked_ms }),
            ),
        ];
        match prev {
            State::Changed => out.push(Action::Notify(
                Severity::Info,
                "出口已回到基线，AI 通道已恢复".into(),
                format!("出口 IP {}，与基线一致。", self.baseline),
            )),
            State::Unverifiable => out.push(Action::Notify(
                Severity::Info,
                "出口核对通过，AI 通道已恢复".into(),
                format!("出口 IP {}，与基线一致。", self.baseline),
            )),
            _ => {}
        }
        self.state = State::Open;
        self.actual = None;
        self.locked_at = None;
        out
    }

    fn on_mismatch(&mut self, now: Instant, source: usize, ip: String) -> Vec<Action> {
        self.echo_fail_since = None;
        self.exit_down = false;
        self.last_ip = Some(ip.clone());
        if self.state == State::Changed {
            // 有明确答案：还在别的出口上。不用快速重试，切回来时会有网络变化
            self.actual = Some(ip);
            self.next_at = now + self.t.locked_every;
            return vec![];
        }
        let confirmed = matches!(&self.suspect, Some((_, first)) if *first != source || self.sources == 1);
        if !confirmed {
            self.suspect = Some((ip, source));
            // 放行中：隔一会儿再用另一个来源确认；已经锁住：立刻确认，锁着不怕等
            self.next_at = if self.state == State::Open { now + self.t.confirm_after } else { now };
            return vec![];
        }
        let was_open = self.state == State::Open;
        let trigger = if was_open { "periodic" } else { self.reason };
        let mut out = Vec::new();
        if was_open {
            out.push(Action::Lock);
        }
        self.lock(now, State::Changed, trigger);
        self.suspect = None;
        self.actual = Some(ip.clone());
        self.next_at = now + self.t.locked_every;
        out.push(Action::Event("exit_ip_changed", json!({ "baseline": self.baseline, "actual": ip, "trigger": trigger })));
        out.push(Action::Notify(
            Severity::Error,
            "出口 IP 已变化，AI 通道已锁住".into(),
            format!("基线 {}，现在 {ip}。切回原来的出口会自动恢复；确认要换成新 IP，运行 anchor baseline。", self.baseline),
        ));
        out
    }

    fn on_failed(&mut self, now: Instant, exit_up: bool, reason: String) -> Vec<Action> {
        self.exit_down = !exit_up;
        let mut out = Vec::new();
        match self.state {
            State::Open if !exit_up => {
                // 出口不可达：AI 连接本来就会失败。先锁住，恢复后核对一致再放行
                self.lock(now, State::Verifying, "exit_down");
                self.next_at = now + self.t.retry;
                out.push(Action::Lock);
                out.push(Action::Event("exit_locked", json!({ "reason": "exit_down", "error": reason })));
            }
            // 只是回显服务出错，出口通着：不锁，下一轮再核对
            State::Open => self.next_at = now + self.t.open_every,
            State::Verifying => {
                if exit_up {
                    let since = *self.echo_fail_since.get_or_insert(now);
                    if now.saturating_duration_since(since) >= self.t.unverifiable_after {
                        self.state = State::Unverifiable;
                        out.push(Action::Event("exit_unverifiable", json!({ "error": reason })));
                        out.push(Action::Notify(
                            Severity::Warn,
                            "无法核对出口，AI 通道保持锁住".into(),
                            "出口能连通，但 IP 回显服务都连不上。恢复后会自动核对并放行。".into(),
                        ));
                    }
                } else {
                    self.echo_fail_since = None;
                }
                let slow = !self.fast(now) && self.locked_at.is_some_and(|t| now.saturating_duration_since(t) >= self.t.slow_after);
                self.next_at = now + if slow { self.t.retry_slow } else { self.t.retry };
            }
            State::Unverifiable | State::Changed => self.next_at = now + self.locked_retry(now),
            State::NoBaseline => {}
        }
        out
    }

    fn fast(&self, now: Instant) -> bool {
        self.fast_until.is_some_and(|t| now < t)
    }

    /// 已变化 / 无法核对时的重试间隔：网络刚变化时快，平时慢。
    fn locked_retry(&self, now: Instant) -> Duration {
        if self.fast(now) { self.t.retry } else { self.t.locked_every }
    }

    fn lock(&mut self, now: Instant, state: State, reason: &'static str) {
        if !self.state.locked() {
            self.locked_at = Some(now);
        }
        self.state = state;
        self.reason = reason;
    }
}

fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    const B: &str = "198.51.100.7";

    fn timing() -> Timing {
        Timing::new(Duration::from_secs(60))
    }

    fn kinds(a: &[Action]) -> Vec<String> {
        a.iter()
            .map(|x| match x {
                Action::Lock => "lock".to_string(),
                Action::Unlock => "unlock".to_string(),
                Action::Event(k, _) => format!("event:{k}"),
                Action::Notify(s, _, _) => format!("notify:{s:?}"),
            })
            .collect()
    }

    /// 内核启动后核对通过，进入放行状态。
    fn open(now: Instant) -> Machine {
        let (mut m, a) = Machine::new(B, 2, timing(), now);
        assert_eq!(kinds(&a), ["lock"]);
        assert_eq!(m.state(), State::Verifying);
        assert_eq!(m.due(now), Some(0));
        let a = m.on_check(now, 0, Check::Match);
        assert_eq!(kinds(&a), ["unlock", "event:exit_unlocked"], "启动时核对通过不发通知");
        assert_eq!(m.state(), State::Open);
        m
    }

    #[test]
    fn starts_locked_and_opens_after_one_match() {
        let t0 = Instant::now();
        let m = open(t0);
        assert_eq!(m.due(t0 + Duration::from_secs(59)), None);
        assert_eq!(m.due(t0 + Duration::from_secs(60)), Some(1), "来源轮换");
        assert!(!m.view(t0).locked);
    }

    #[test]
    fn no_baseline_stays_locked_and_never_checks() {
        let t0 = Instant::now();
        let (mut m, a) = Machine::new("  ", 2, timing(), t0);
        assert_eq!(kinds(&a), ["lock", "event:exit_locked", "notify:Warn"]);
        assert_eq!(m.state(), State::NoBaseline);
        assert_eq!(m.due(t0 + Duration::from_secs(600)), None);
        assert!(m.trigger(t0, Trigger::NetworkChange).is_empty());
        assert!(m.view(t0).locked);
    }

    #[test]
    fn periodic_change_needs_a_second_source_before_locking() {
        let t0 = Instant::now();
        let mut m = open(t0);
        let t1 = t0 + Duration::from_secs(60);
        assert!(m.on_check(t1, 1, Check::Mismatch("203.0.113.9".into())).is_empty(), "一个来源说变了：先不锁");
        assert_eq!(m.state(), State::Open);
        assert_eq!(m.due(t1 + Duration::from_secs(9)), None);
        let t2 = t1 + Duration::from_secs(10);
        assert_eq!(m.due(t2), Some(0), "隔 10 秒换另一个来源确认");
        let a = m.on_check(t2, 0, Check::Mismatch("203.0.113.9".into()));
        assert_eq!(kinds(&a), ["lock", "event:exit_ip_changed", "notify:Error"]);
        assert_eq!(m.state(), State::Changed);
        let v = m.view(t2);
        assert!(v.locked);
        assert_eq!(v.actual.as_deref(), Some("203.0.113.9"));
        assert_eq!(v.reason, "periodic");
    }

    #[test]
    fn a_second_source_that_matches_clears_the_suspicion() {
        let t0 = Instant::now();
        let mut m = open(t0);
        let t1 = t0 + Duration::from_secs(60);
        m.on_check(t1, 1, Check::Mismatch("203.0.113.9".into()));
        let a = m.on_check(t1 + Duration::from_secs(10), 0, Check::Match);
        assert!(a.is_empty());
        assert_eq!(m.state(), State::Open);
        // 之后同一个来源再说一次不一致，也只是新的怀疑，不会和旧的凑成确认
        assert!(m.on_check(t1 + Duration::from_secs(70), 1, Check::Mismatch("203.0.113.9".into())).is_empty());
    }

    #[test]
    fn network_change_locks_first_then_verifies() {
        let t0 = Instant::now();
        let mut m = open(t0);
        let t1 = t0 + Duration::from_secs(5);
        let a = m.trigger(t1, Trigger::NetworkChange);
        assert_eq!(kinds(&a), ["lock", "event:exit_locked"]);
        assert_eq!(m.due(t1), Some(1), "立即核对，不等定时");
        let a = m.on_check(t1 + Duration::from_millis(800), 1, Check::Match);
        assert_eq!(kinds(&a), ["unlock", "event:exit_unlocked"], "出口没变：放行，不发通知");
        if let Action::Event(_, d) = &a[1] {
            assert_eq!(d["trigger"], "network_change");
            assert_eq!(d["locked_ms"], 800);
        }
    }

    #[test]
    fn locked_check_confirms_immediately_with_another_source() {
        let t0 = Instant::now();
        let mut m = open(t0);
        m.trigger(t0, Trigger::NetworkChange);
        assert!(m.on_check(t0, 1, Check::Mismatch("203.0.113.9".into())).is_empty());
        assert_eq!(m.due(t0), Some(0), "锁着不怕等：立刻换来源确认");
        let a = m.on_check(t0, 0, Check::Mismatch("203.0.113.9".into()));
        assert_eq!(kinds(&a), ["event:exit_ip_changed", "notify:Error"], "已经锁住，不再发 Lock");
        assert_eq!(m.state(), State::Changed);
    }

    #[test]
    fn back_to_baseline_unlocks_automatically() {
        let t0 = Instant::now();
        let mut m = open(t0);
        m.trigger(t0, Trigger::NetworkChange);
        m.on_check(t0, 1, Check::Mismatch("203.0.113.9".into()));
        m.on_check(t0, 0, Check::Mismatch("203.0.113.9".into()));
        assert_eq!(m.due(t0 + Duration::from_secs(9)), None);
        // 用户在 VPN 客户端里切回原来的服务器：网络变化，立即核对
        let t1 = t0 + Duration::from_secs(30);
        assert_eq!(kinds(&m.trigger(t1, Trigger::NetworkChange)), ["lock"]);
        assert_eq!(m.state(), State::Changed, "核对通过前仍算已变化");
        let a = m.on_check(t1, 1, Check::Match);
        assert_eq!(kinds(&a), ["unlock", "event:exit_unlocked", "notify:Info"]);
        if let Action::Event(_, d) = &a[1] {
            assert_eq!(d["reason"], "back_to_baseline");
        }
        assert_eq!(m.state(), State::Open);
    }

    #[test]
    fn after_a_network_change_locked_states_retry_fast() {
        // 实测：切回原服务器后，隧道刚恢复的第一次核对失败（不可达），
        // 已变化状态按 10 秒重试，放行拖到了隧道恢复后 15 秒
        let t0 = Instant::now();
        let mut m = open(t0);
        m.trigger(t0, Trigger::NetworkChange);
        m.on_check(t0, 1, Check::Mismatch("198.51.100.99".into()));
        m.on_check(t0, 0, Check::Mismatch("198.51.100.99".into()));
        assert_eq!(m.state(), State::Changed);
        // 还在别的服务器上：有明确答案，10 秒后再核对，不会每 2 秒问一次
        m.on_check(t0 + Duration::from_secs(10), 1, Check::Mismatch("198.51.100.99".into()));
        assert_eq!(m.due(t0 + Duration::from_secs(19)), None);
        // 一分钟后用户切回原服务器
        let t1 = t0 + Duration::from_secs(60);
        m.trigger(t1, Trigger::NetworkChange);
        m.on_check(t1, 1, Check::Failed { exit_up: false, reason: "不可达".into() });
        assert_eq!(m.due(t1 + Duration::from_millis(900)), None);
        assert!(m.due(t1 + Duration::from_secs(1)).is_some(), "网络刚变化：1 秒后重试，不是 10 秒");
        let a = m.on_check(t1 + Duration::from_secs(1), 0, Check::Match);
        assert_eq!(kinds(&a), ["unlock", "event:exit_unlocked", "notify:Info"]);

        // 快速重试期过了，已变化状态恢复 10 秒一次
        m.trigger(t1 + Duration::from_secs(3), Trigger::NetworkChange);
        m.on_check(t1 + Duration::from_secs(3), 1, Check::Mismatch("198.51.100.99".into()));
        m.on_check(t1 + Duration::from_secs(3), 0, Check::Mismatch("198.51.100.99".into()));
        let late = t1 + Duration::from_secs(40);
        m.on_check(late, 1, Check::Failed { exit_up: false, reason: "不可达".into() });
        assert_eq!(m.due(late + Duration::from_secs(9)), None);
        assert!(m.due(late + Duration::from_secs(10)).is_some());
    }

    #[test]
    fn exit_down_while_open_locks_until_verified() {
        let t0 = Instant::now();
        let mut m = open(t0);
        let t1 = t0 + Duration::from_secs(60);
        let a = m.on_check(t1, 1, Check::Failed { exit_up: false, reason: "超时".into() });
        assert_eq!(kinds(&a), ["lock", "event:exit_locked"]);
        assert!(m.view(t1).exit_down);
        // 出口不可达不算“无法核对”：多久都不发这条通知
        let mut t = t1;
        for _ in 0..30 {
            t += Duration::from_secs(5);
            assert!(m.on_check(t, 0, Check::Failed { exit_up: false, reason: "超时".into() }).is_empty());
        }
        assert_eq!(m.state(), State::Verifying);
        assert_eq!(m.due(t + Duration::from_secs(4)), None, "锁住 30 秒后放慢到 5 秒一次");
        assert_eq!(kinds(&m.on_check(t + Duration::from_secs(5), 1, Check::Match)), ["unlock", "event:exit_unlocked"]);
    }

    #[test]
    fn echo_failures_with_exit_up_become_unverifiable() {
        let t0 = Instant::now();
        let mut m = open(t0);
        // 回显服务失败但出口通：放行中不锁
        assert!(m.on_check(t0 + Duration::from_secs(60), 1, Check::Failed { exit_up: true, reason: "502".into() }).is_empty());
        assert_eq!(m.state(), State::Open);

        m.trigger(t0 + Duration::from_secs(61), Trigger::NetworkChange);
        let fail = || Check::Failed { exit_up: true, reason: "502".into() };
        let mut t = t0 + Duration::from_secs(61);
        let mut seen = Vec::new();
        for _ in 0..12 {
            seen.extend(kinds(&m.on_check(t, 0, fail())));
            t += Duration::from_secs(2);
        }
        assert_eq!(seen, ["event:exit_unverifiable", "notify:Warn"], "只通知一次");
        assert_eq!(m.state(), State::Unverifiable);
        let a = m.on_check(t + Duration::from_secs(10), 1, Check::Match);
        assert_eq!(kinds(&a), ["unlock", "event:exit_unlocked", "notify:Info"]);
    }

    #[test]
    fn single_source_can_confirm_itself() {
        let t0 = Instant::now();
        let (mut m, _) = Machine::new(B, 1, timing(), t0);
        m.on_check(t0, 0, Check::Match);
        let t1 = t0 + Duration::from_secs(60);
        m.on_check(t1, 0, Check::Mismatch("203.0.113.9".into()));
        assert_eq!(m.due(t1 + Duration::from_secs(10)), Some(0));
        let a = m.on_check(t1 + Duration::from_secs(10), 0, Check::Mismatch("203.0.113.9".into()));
        assert_eq!(m.state(), State::Changed, "{a:?}");
    }

    #[test]
    fn classify_ignores_address_family_mismatch() {
        assert_eq!(classify(B, " 198.51.100.7\n"), Check::Match);
        assert_eq!(classify(B, "203.0.113.9"), Check::Mismatch("203.0.113.9".into()));
        assert!(matches!(classify(B, "2001:db8::1"), Check::Failed { exit_up: true, .. }));
        assert_eq!(classify("2001:db8::1", "2001:0db8::0001"), Check::Match);
    }
}
