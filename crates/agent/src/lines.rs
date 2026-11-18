//! 线路控制器的执行者（每次会话一个线程）。判断在 anchor_core::linectl，这里负责：
//! - 按它给的节奏探测各条线路（Clash API 单条测速），当前线路失败时立刻把所有线路测一遍；
//! - 经 Clash API 把线路组（selector）切到它选的线路，内核重启后重新应用；
//! - 处理 anchor line use / pin / unpin；
//! - 写时间线、发通知、更新 anchor line list 和状态里看到的内容。
//!
//! 当前线路的探测记在 line 段（断联归因看它），其他线路记在 line_other 段。

use crate::shared::{KernelState, Level, Shared};
use anchor_core::config::{Config, LineMode};
use anchor_core::linectl::{Action, Controller, LineSpec, Tuning};
use anchor_core::log;
use anchor_core::net::ClashApi;
use anchor_core::singbox::{TAG_IN, TAG_LINES};
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const PROBE_TIMEOUT_MS: u32 = 2500;
/// 多久看一次有没有 AI 连接
const ACTIVE_EVERY: Duration = Duration::from_secs(3);
/// 最近这么久之内见过 AI 连接（或记到过断联），就算“有 AI 连接”，当前线路按 3 秒探测。
/// 实测：线路一断，在途的连接跟着断，新连接立刻失败，查连接数总是 0；只看此刻的连接数的话，
/// 恰恰在线路出事时把探测降到 15 秒一次。
const ACTIVE_FOR: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub enum LineCmd {
    Use(String),
    Pin(String),
    Unpin,
}

pub type Reply = Sender<Result<String, String>>;

/// 没有配置线路时不启动（返回 None）。
pub fn spawn(sh: Arc<Shared>, cfg: &Config, stop: Arc<AtomicBool>, kernel_gen: Arc<AtomicU64>) -> Option<JoinHandle<()>> {
    *sh.lines_view.lock().unwrap_or_else(|e| e.into_inner()) = None;
    if cfg.lines.is_empty() {
        return None;
    }
    let specs: Vec<LineSpec> =
        cfg.lines.iter().map(|l| LineSpec { name: l.name.clone().unwrap_or_default(), priority: l.priority.unwrap_or(u32::MAX) }).collect();
    let auto = cfg.switch.lines == LineMode::Auto;
    let pinned = std::fs::read_to_string(sh.paths.line_pin()).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let every = cfg.switch.watch_every();
    let others = humantime::parse_duration(cfg.switch.probe_interval.trim()).unwrap_or(Duration::from_secs(30));
    let ctl = Controller::new(specs, auto, pinned, Tuning::new(every.unwrap_or(Duration::from_secs(3)), others));
    let d = Driver { sh, api: ClashApi::new(cfg), url: cfg.switch.probe_url.clone(), auto, probing: every.is_some(), ctl, applied: None };
    Some(thread::spawn(move || d.run(&stop, &kernel_gen)))
}

struct Driver {
    sh: Arc<Shared>,
    api: ClashApi,
    url: String,
    auto: bool,
    /// [switch] watch_interval 没关：定时探测。关了就只听命令
    probing: bool,
    ctl: Controller,
    /// 已经让哪一代内核选了哪条线路
    applied: Option<(u64, String)>,
}

impl Driver {
    fn run(mut self, stop: &AtomicBool, kernel_gen: &AtomicU64) {
        log::line(&format!(
            "线路控制器：{} 条线路，起始 {}{}",
            self.ctl.view(Instant::now()).len(),
            self.ctl.current(),
            match (self.ctl.pinned(), self.auto) {
                (Some(_), _) => "（已固定）",
                (None, false) => "（手动模式，不自动换线）",
                _ => "",
            }
        ));
        let (tx, rx) = mpsc::channel::<(String, Option<u64>, String)>();
        let mut last_active: Option<Instant> = None;
        let mut active_checked: Option<Instant> = None;
        let mut last_err = String::new();
        self.publish();
        while !stop.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(200));
            self.commands();
            if self.sh.status().kernel != KernelState::Running {
                continue;
            }
            let kg = kernel_gen.load(Ordering::SeqCst);
            if self.applied.as_ref().is_none_or(|(g, l)| *g != kg || l != self.ctl.current()) {
                match self.api.select(TAG_LINES, self.ctl.current()) {
                    Ok(()) => {
                        self.applied = Some((kg, self.ctl.current().to_string()));
                        self.sh.status().line = Some(self.ctl.current().to_string());
                        last_err.clear();
                    }
                    Err(e) => {
                        let msg = format!("{e:#}");
                        if msg != last_err {
                            log::line(&format!("切换线路组到 {} 失败，稍后重试：{msg}", self.ctl.current()));
                            last_err = msg;
                        }
                        continue;
                    }
                }
            }
            while let Ok((line, r, note)) = rx.try_recv() {
                // 正在停止，或内核这时退出了（API 也不通）：不算线路故障，内核由守护线程处理
                if r.is_none() && (stop.load(Ordering::SeqCst) || self.api.current_line().is_none()) {
                    continue;
                }
                let seg = if line == self.ctl.current() { "line" } else { "line_other" };
                self.sh.tl.probe(seg, &line, r.is_some(), r, &note);
                let step = self.ctl.on_probe(Instant::now(), &line, r);
                self.act(step.actions);
                if step.sweep {
                    self.sweep(stop);
                }
            }
            if self.probing {
                let now = Instant::now();
                if active_checked.is_none_or(|t| now.duration_since(t) >= ACTIVE_EVERY) {
                    if self.api.connections_on(TAG_IN).unwrap_or(0) > 0 {
                        last_active = Some(now);
                    }
                    active_checked = Some(now);
                }
                // 断联采集刚记到一次断联：马上测当前线路，不等下一轮
                if self.sh.line_kick.swap(false, Ordering::SeqCst) {
                    last_active = Some(now);
                    self.ctl.probe_now();
                }
                let active = last_active.is_some_and(|t| now.duration_since(t) < ACTIVE_FOR);
                for line in self.ctl.due(now, active) {
                    let (api, url, tx) = (self.api.clone(), self.url.clone(), tx.clone());
                    thread::spawn(move || {
                        let _ = tx.send(probe(&api, &line, &url));
                    });
                }
            }
            self.publish();
        }
        *self.sh.lines_view.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// 当前线路探测失败：所有线路并发测一遍，交给控制器决定换不换。
    fn sweep(&mut self, stop: &AtomicBool) {
        let names: Vec<String> = self.ctl.view(Instant::now()).into_iter().map(|l| l.name).collect();
        let results: Vec<(String, Option<u64>, String)> = thread::scope(|s| {
            let hs: Vec<_> = names.iter().map(|n| s.spawn(|| probe(&self.api, n, &self.url))).collect();
            hs.into_iter().filter_map(|h| h.join().ok()).collect()
        });
        if stop.load(Ordering::SeqCst) || self.api.current_line().is_none() {
            return;
        }
        for (line, r, note) in &results {
            let seg = if line == self.ctl.current() { "line" } else { "line_other" };
            let note = if note.is_empty() { "复测".to_string() } else { format!("复测：{note}") };
            self.sh.tl.probe(seg, line, r.is_some(), *r, &note);
        }
        let pairs: Vec<(String, Option<u64>)> = results.into_iter().map(|(l, r, _)| (l, r)).collect();
        let actions = self.ctl.on_sweep(Instant::now(), &pairs);
        self.act(actions);
    }

    fn act(&mut self, actions: Vec<Action>) {
        // 线路断着的时候出口也测不通，AI 通道多半因“出口不可达”锁着。线路一回来就请出口核对立刻重测，
        // 不等它自己的重试（锁久了是 5 秒一次），这样线路恢复后几秒内就能放行。
        let back = actions.iter().any(|a| matches!(a, Action::Recovered { .. } | Action::Switch { reason: "down", .. }));
        for a in actions {
            match a {
                Action::Switch { from, to, reason, ms } => {
                    // 立刻切过去；失败的话主循环会重试
                    if self.api.select(TAG_LINES, &to).is_ok()
                        && let Some((g, l)) = &mut self.applied
                    {
                        *l = to.clone();
                        let _ = g;
                    }
                    {
                        let mut st = self.sh.status();
                        st.line = Some(to.clone());
                        st.lines_down = false;
                    }
                    log::line(&format!("线路 {from} → {to}（{}）", reason_text(reason)));
                    self.sh.tl.event("line_switch", json!({ "from": from, "to": to, "reason": reason, "ms": ms }));
                    if matches!(reason, "flaky" | "slow") {
                        self.sh.notify(Level::Info, "已换线路", &format!("{from} {}，已换到 {to}。出口 IP 不变。", reason_text(reason)));
                    }
                }
                Action::LineDown { line, why } => {
                    self.sh.status().lines_down = true;
                    self.sh.tl.event("line_down", json!({ "line": line, "why": why }));
                    let hint = if why == "pinned" {
                        "线路已固定，不会自动切换（anchor line unpin 取消固定）"
                    } else {
                        "手动模式不会自动切换（anchor line use 换线）"
                    };
                    self.sh.notify(Level::Warn, "当前线路不可用", &format!("线路 {line} 探测失败。{hint}；AI 新连接会失败，不会直连。"));
                }
                Action::AllDown { line } => {
                    self.sh.status().lines_down = true;
                    self.sh.tl.event("all_lines_down", json!({ "line": line }));
                    self.sh.notify(Level::Error, "所有线路都不可用", "AI 新连接会失败，不会直连；出口 IP 不会因此改变。线路恢复后会再通知。");
                }
                Action::Recovered { line } => {
                    {
                        let mut st = self.sh.status();
                        st.lines_down = false;
                        st.line = Some(line.clone());
                    }
                    self.sh.tl.event("line_recovered", json!({ "line": line }));
                    self.sh.notify(Level::Info, "线路已恢复", &format!("当前线路 {line}，AI 通道可用。"));
                }
            }
        }
        if back && self.sh.status().exit.locked {
            self.sh.recheck.store(true, Ordering::SeqCst);
            self.sh.poke();
        }
    }

    fn commands(&mut self) {
        let cmds: Vec<(LineCmd, Reply)> = std::mem::take(&mut *self.sh.line_cmds.lock().unwrap_or_else(|e| e.into_inner()));
        for (cmd, reply) in cmds {
            let now = Instant::now();
            let r = match cmd {
                LineCmd::Use(name) => self.ctl.use_line(now, &name).map(|a| {
                    let msg = if a.is_empty() { format!("已经在用 {name}") } else { format!("已切换到 {name}；已建立的连接留在原线路上，出口 IP 不变") };
                    (a, msg)
                }),
                LineCmd::Pin(name) => self.ctl.pin(now, &name).and_then(|a| {
                    std::fs::write(self.sh.paths.line_pin(), &name).map_err(|e| format!("记不下固定的线路：{e}"))?;
                    Ok((a, format!("已固定在 {name}：不再自动换线，直到 anchor line unpin")))
                }),
                LineCmd::Unpin => {
                    let _ = std::fs::remove_file(self.sh.paths.line_pin());
                    Ok((vec![], match self.ctl.unpin() {
                        Some(p) => format!("已取消固定（原来固定在 {p}）{}", if self.auto { "，恢复自动换线" } else { "" }),
                        None => "没有固定线路".into(),
                    }))
                }
            };
            let r = r.map(|(actions, msg)| {
                self.act(actions);
                msg
            });
            self.publish();
            let _ = reply.send(r);
        }
    }

    /// 更新 anchor line list 和状态里看到的内容。
    fn publish(&mut self) {
        let mode = match (self.ctl.pinned(), self.auto) {
            (Some(_), _) => "pinned",
            (None, true) => "auto",
            (None, false) => "manual",
        };
        self.sh.status().line_mode = mode.into();
        let lines: Vec<Value> = self
            .ctl
            .view(Instant::now())
            .into_iter()
            .map(|l| {
                json!({
                    "name": l.name,
                    "priority": (l.priority != u32::MAX).then_some(l.priority),
                    "current": l.current,
                    "pinned": l.pinned,
                    "samples": l.samples,
                    "rate": l.rate,
                    "median_ms": l.median_ms,
                    "last_ok": l.last.map(|r| r.is_some()),
                    "last_ms": l.last.flatten(),
                })
            })
            .collect();
        let v = json!({ "mode": mode, "current": self.ctl.current(), "pinned": self.ctl.pinned(), "all_down": self.ctl.all_down(), "lines": lines });
        *self.sh.lines_view.lock().unwrap_or_else(|e| e.into_inner()) = Some(v);
    }
}

fn probe(api: &ClashApi, line: &str, url: &str) -> (String, Option<u64>, String) {
    match api.delay(line, url, PROBE_TIMEOUT_MS) {
        Ok(ms) => (line.to_string(), Some(ms), String::new()),
        Err(e) => (line.to_string(), None, format!("{e:#}").chars().take(200).collect()),
    }
}

pub fn reason_text(reason: &str) -> &'static str {
    match reason {
        "down" => "探测失败",
        "flaky" => "不稳定",
        "slow" => "明显偏慢",
        "manual" => "手动",
        _ => "其他",
    }
}
