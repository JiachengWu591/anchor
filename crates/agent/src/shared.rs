//! 用户代理各线程共享的状态。

use anchor_core::config::Paths;
use anchor_core::log;
use anchor_core::timeline::Timeline;
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::SystemTime;

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
    pub line: Option<String>,
    pub line_mode: String,
    pub lines: usize,
    /// 当前线路（手动模式）或全部线路（自动模式）不可用
    pub lines_down: bool,
    pub config_error: Option<String>,
    pub guard: GuardView,
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
    st: Mutex<Status>,
    notes: Mutex<VecDeque<Note>>,
    stop_reason: Mutex<String>,
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
            st: Mutex::new(st),
            notes: Mutex::new(VecDeque::new()),
            stop_reason: Mutex::new(String::new()),
        }
    }

    pub fn status(&self) -> MutexGuard<'_, Status> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
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

fn first_line(s: &str) -> &str {
    s.lines().next().unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_levels() {
        let mut st = Status { kernel: KernelState::Running, line: Some("line-a".into()), ..Default::default() };
        st.guard.svc = "running".into();
        assert_eq!(summarize(&st), (Level::Info, "运行中 · 线路 line-a".into()));
        st.guard.svc = "not_installed".into();
        assert_eq!(summarize(&st).0, Level::Warn);
        st.lines_down = true;
        assert_eq!(summarize(&st), (Level::Error, "线路不可用 · 未安装特权服务".into()));
        st.config_error = Some("第 3 行\n详情".into());
        assert_eq!(summarize(&st), (Level::Error, "配置有误：第 3 行".into()));
    }
}
