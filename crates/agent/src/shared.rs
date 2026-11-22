//! 用户代理各线程共享的状态。

use anchor_core::config::{Config, Paths};
use anchor_core::exitlock::View as ExitView;
use anchor_core::log;
use anchor_core::stall::{LocalHealth, Stuck};
use anchor_core::timeline::Timeline;
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum KernelState {
    #[default]
    Starting,
    Running,
    Restarting,
    Stopped,
    Error,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct GuardView {
    /// running：服务在运行；not_installed：没有服务；denied：无权访问；error：其他错误；unknown：还没查过
    pub svc: String,
    pub rules: usize,
    pub disabled: usize,
    pub missing: usize,
    pub paused_until: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Status {
    pub kernel: KernelState,
    pub kernel_pid: Option<u32>,
    pub kernel_restarts: u32,
    pub kernel_error: Option<String>,
    pub listen: String,
    /// 现在用的出口的名字（主出口或 anchor exit use 选的备用出口）
    pub exit_name: String,
    pub line: Option<String>,
    pub line_mode: String,
    pub lines: usize,
    /// 当前线路（固定或手动模式）或全部线路（自动模式）不可用
    pub lines_down: bool,
    pub config_error: Option<String>,
    pub guard: GuardView,
    /// 出口核对与锁定
    pub exit: ExitView,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone)]
pub struct Note {
    pub level: Level,
    pub title: String,
    pub body: String,
}

pub struct Shared {
    pub paths: Paths,
    pub tl: Timeline,
    /// 用户代理退出
    pub stop: AtomicBool,
    /// 重新读取配置并重启内核
    pub reload: AtomicBool,
    pub started: SystemTime,
    pub tray: bool,
    /// 网卡地址或默认路由变化的次数（网络变化监听写，出口核对读）
    pub net_gen: AtomicU64,
    /// 用户要求立即核对出口
    pub recheck: AtomicBool,
    /// 当前会话使用的配置（断联突发探测要用）；配置有误、还没开始会话时为空
    pub cfg: Mutex<Option<Arc<Config>>>,
    /// anchor line use / pin / unpin：线路控制器线程取走处理，经通道回话
    pub line_cmds: Mutex<Vec<(crate::lines::LineCmd, crate::lines::Reply)>>,
    /// 刚记到一次断联：请线路控制器立刻测当前线路
    pub line_kick: AtomicBool,
    /// 各线路的评分（anchor line list）；没有配置线路、会话没在运行时为空
    pub lines_view: Mutex<Option<serde_json::Value>>,
    /// 本机网络各段探测的最新结果（持续探测写，出口迟迟连不上时用它判断卡在哪一段）
    health: Mutex<LocalHealth>,
    /// 面板的本机网页服务：用到时才启动
    pub panel: crate::panel::Panel,
    st: Mutex<Status>,
    notes: Mutex<VecDeque<Note>>,
    stop_reason: Mutex<String>,
    pokes: Mutex<u64>,
    poked: Condvar,
}

impl Shared {
    pub fn new(paths: Paths, tl: Timeline, tray: bool) -> Self {
        let st = Status { guard: GuardView { svc: "unknown".into(), ..Default::default() }, ..Default::default() };
        Self {
            paths,
            tl,
            stop: AtomicBool::new(false),
            reload: AtomicBool::new(false),
            started: SystemTime::now(),
            tray,
            net_gen: AtomicU64::new(0),
            recheck: AtomicBool::new(false),
            cfg: Mutex::new(None),
            line_cmds: Mutex::new(Vec::new()),
            line_kick: AtomicBool::new(false),
            lines_view: Mutex::new(None),
            health: Mutex::new(LocalHealth::default()),
            panel: crate::panel::Panel::default(),
            st: Mutex::new(st),
            notes: Mutex::new(VecDeque::new()),
            stop_reason: Mutex::new(String::new()),
            pokes: Mutex::new(0),
            poked: Condvar::new(),
        }
    }

    /// 叫醒等在 wait_poke 上的线程（出口核对）：网络变化、内核启动、核对结果到了。
    pub fn poke(&self) {
        *self.pokes.lock().unwrap_or_else(|e| e.into_inner()) += 1;
        self.poked.notify_all();
    }

    pub fn pokes(&self) -> u64 {
        *self.pokes.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// 等到有新的 poke（计数不再是 seen）或超时，返回最新计数。
    pub fn wait_poke(&self, seen: u64, timeout: Duration) -> u64 {
        let g = self.pokes.lock().unwrap_or_else(|e| e.into_inner());
        let (g, _) = self.poked.wait_timeout_while(g, timeout, |n| *n == seen).unwrap_or_else(|e| e.into_inner());
        *g
    }

    pub fn status(&self) -> MutexGuard<'_, Status> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn local_health(&self) -> MutexGuard<'_, LocalHealth> {
        self.health.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// 发一条系统通知（托盘气泡）；同时写日志。
    pub fn notify(&self, level: Level, title: &str, body: &str) {
        log::line(&format!("通知：{title}：{body}"));
        if self.tray {
            let mut q = self.notes.lock().unwrap_or_else(|e| e.into_inner());
            q.push_back(Note { level, title: title.into(), body: body.into() });
            while q.len() > 5 {
                q.pop_front();
            }
        }
    }

    pub fn config(&self) -> Option<Arc<Config>> {
        self.cfg.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn take_notes(&self) -> Vec<Note> {
        self.notes.lock().unwrap_or_else(|e| e.into_inner()).drain(..).collect()
    }

    pub fn request_stop(&self, reason: &str) {
        let mut r = self.stop_reason.lock().unwrap_or_else(|e| e.into_inner());
        if r.is_empty() {
            *r = reason.to_string();
        }
        self.stop.store(true, Ordering::SeqCst);
    }

    pub fn stopping(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    pub fn stop_reason(&self) -> String {
        self.stop_reason.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// 托盘图标的级别和提示文字。
    pub fn summary(&self) -> (Level, String) {
        let st = self.status();
        summarize(&st)
    }
}

pub fn summarize(st: &Status) -> (Level, String) {
    let line = st.line.as_deref().unwrap_or("—");
    if let Some(e) = &st.config_error {
        return (Level::Error, format!("配置有误：{}", first_line(e)));
    }
    let (level, head) = match st.kernel {
        KernelState::Running if st.lines_down => (Level::Error, "线路不可用".to_string()),
        KernelState::Running if st.exit.locked => exit_summary(&st.exit),
        KernelState::Running if st.lines == 0 && !st.exit.baseline.is_empty() => {
            (Level::Info, format!("运行中 · 出口 {}", st.exit.baseline))
        }
        KernelState::Running => (Level::Info, format!("运行中 · 线路 {line}")),
        KernelState::Starting => (Level::Warn, "内核启动中".to_string()),
        KernelState::Restarting => (Level::Warn, "内核重启中".to_string()),
        KernelState::Stopped => (Level::Error, "内核已停止".to_string()),
        KernelState::Error => (Level::Error, format!("内核错误：{}", first_line(st.kernel_error.as_deref().unwrap_or("")))),
    };
    let guard = match st.guard.svc.as_str() {
        "running" if st.guard.paused_until.is_some() => Some("守卫已暂停"),
        "running" if st.guard.missing > 0 => Some("守卫未覆盖全部程序"),
        "running" => None,
        "not_installed" => Some("未安装特权服务"),
        "unknown" => None,
        _ => Some("守卫状态未知"),
    };
    match guard {
        Some(g) => (if level == Level::Info { Level::Warn } else { level }, format!("{head} · {g}")),
        None => (level, head),
    }
}

/// AI 通道被出口锁定时的提示。
fn exit_summary(e: &ExitView) -> (Level, String) {
    match e.state.as_str() {
        "changed" => (Level::Error, format!("出口 IP 已变化（现在 {}），AI 通道已锁住", e.actual.as_deref().unwrap_or("未知"))),
        "unverifiable" => (Level::Error, "无法核对出口，AI 通道已锁住".into()),
        "no_baseline" => (Level::Warn, "未登记出口基线，AI 通道已锁住".into()),
        _ if e.exit_down => match e.stuck.as_deref() {
            // 迟迟连不上、已经判断出卡在哪一段：一并显示
            Some(what) => (Level::Error, format!("出口不可达（{}），AI 通道已锁住", Stuck::label(what))),
            None => (Level::Error, "出口不可达，AI 通道已锁住".into()),
        },
        _ => (Level::Warn, "正在核对出口".into()),
    }
}

fn first_line(s: &str) -> &str {
    s.lines().next().unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_levels() {
        let mut st = Status { kernel: KernelState::Running, line: Some("line-a".into()), lines: 2, ..Default::default() };
        st.guard.svc = "running".into();
        assert_eq!(summarize(&st), (Level::Info, "运行中 · 线路 line-a".into()));
        st.guard.svc = "not_installed".into();
        assert_eq!(summarize(&st).0, Level::Warn);
        st.lines_down = true;
        assert_eq!(summarize(&st), (Level::Error, "线路不可用 · 未安装特权服务".into()));
        st.config_error = Some("第 3 行\n详情".into());
        assert_eq!(summarize(&st), (Level::Error, "配置有误：第 3 行".into()));
    }

    #[test]
    fn summary_shows_exit_lock() {
        let mut st = Status { kernel: KernelState::Running, ..Default::default() };
        st.guard.svc = "running".into();
        st.exit = ExitView { state: "open".into(), baseline: "198.51.100.7".into(), ..Default::default() };
        assert_eq!(summarize(&st), (Level::Info, "运行中 · 出口 198.51.100.7".into()), "没有线路时显示出口");

        st.exit.locked = true;
        st.exit.state = "verifying".into();
        assert_eq!(summarize(&st), (Level::Warn, "正在核对出口".into()));
        st.exit.exit_down = true;
        assert_eq!(summarize(&st), (Level::Error, "出口不可达，AI 通道已锁住".into()));
        st.exit.stuck = Some("vpn_stuck".into());
        assert_eq!(summarize(&st), (Level::Error, "出口不可达（VPN 卡住了），AI 通道已锁住".into()));
        st.exit.stuck = None;
        st.exit.state = "changed".into();
        st.exit.actual = Some("203.0.113.9".into());
        assert_eq!(summarize(&st), (Level::Error, "出口 IP 已变化（现在 203.0.113.9），AI 通道已锁住".into()));
        // 内核没在运行时，先说内核
        st.kernel = KernelState::Restarting;
        assert_eq!(summarize(&st), (Level::Warn, "内核重启中".into()));
    }
}
