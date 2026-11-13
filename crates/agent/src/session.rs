//! 一次“会话”= 按当前配置运行内核和线路看门狗。收到重新加载请求或退出时结束，再按新配置开始下一次。

use crate::shared::{KernelState, Level, Shared};
use anchor_core::config::{Config, LineMode, host_port};
use anchor_core::kernel::{self, KernelEvent};
use anchor_core::log;
use anchor_core::watch::{self, WatchEvent};
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

/// 连续意外退出这么多次仍未恢复，就通知用户。
const NOTIFY_AFTER_RESTARTS: u32 = 3;

pub fn run(sh: Arc<Shared>) {
    while !sh.stopping() {
        sh.reload.store(false, Ordering::SeqCst);
        match Config::load(&sh.paths) {
            Ok(cfg) => {
                sh.status().config_error = None;
                one(&sh, &cfg);
            }
            Err(e) => {
                let msg = format!("{e:#}");
                let changed = sh.status().config_error.as_deref() != Some(msg.as_str());
                if changed {
                    sh.status().config_error = Some(msg.clone());
                    sh.status().kernel = KernelState::Stopped;
                    sh.tl.event("config_error", json!({ "message": msg }));
                    sh.notify(Level::Error, "AI Anchor 配置有误", "改好 anchor.toml 后在托盘菜单选“重新加载配置”。AI 程序此时没有网络，不会直连。");
                }
                wait_reload(&sh, Some(Duration::from_secs(30)));
            }
        }
    }
}

/// 等到要求重新加载或退出；timeout 到了也返回（用于定期重试）。
fn wait_reload(sh: &Shared, timeout: Option<Duration>) {
    let deadline = timeout.map(|t| Instant::now() + t);
    while !sh.stopping() && !sh.reload.load(Ordering::SeqCst) {
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return;
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn one(sh: &Arc<Shared>, cfg: &Config) {
    {
        let mut st = sh.status();
        st.listen = host_port(&cfg.proxy.listen, cfg.proxy.port);
        st.lines = cfg.lines.len();
        st.line_mode = match cfg.switch.lines {
            LineMode::Auto => "auto".into(),
            LineMode::Manual => "manual".into(),
        };
        st.line = None;
        st.lines_down = false;
        st.kernel = KernelState::Starting;
        st.kernel_error = None;
    }
    let (sb, json_path) = match kernel::prepare(cfg, &sh.paths) {
        Ok(v) => v,
        Err(e) => {
            let msg = format!("{e:#}");
            {
                let mut st = sh.status();
                st.kernel = KernelState::Error;
                st.kernel_error = Some(msg.clone());
            }
            sh.tl.event("kernel_error", json!({ "message": msg }));
            sh.notify(Level::Error, "AI Anchor 内核无法启动", &msg);
            // 端口被占用等情况可能自行消失：1 分钟后重试
            wait_reload(sh, Some(Duration::from_secs(60)));
            return;
        }
    };

    let sess_stop = Arc::new(AtomicBool::new(false));
    // 把“退出 / 重新加载”转成本次会话的停止信号
    let bridge = {
        let sh = sh.clone();
        let s = sess_stop.clone();
        thread::spawn(move || {
            while !s.load(Ordering::SeqCst) {
                if sh.stopping() || sh.reload.load(Ordering::SeqCst) {
                    s.store(true, Ordering::SeqCst);
                }
                thread::sleep(Duration::from_millis(100));
            }
        })
    };
    let watcher = {
        let sh = sh.clone();
        watch::spawn(cfg, sess_stop.clone(), move |ev| on_watch(&sh, ev))
    };
    if let Some((every, _)) = &watcher {
        log::line(&format!("线路看门狗：每 {} 探测当前线路", humantime::format_duration(*every)));
    }

    let mut failing = 0u32;
    let r = kernel::supervise(cfg, &sh.paths, &sb, &json_path, &sess_stop, &kernel::Options { background: true }, &mut |ev| {
        on_kernel(sh, ev, &mut failing)
    });
    if let Err(e) = r {
        let msg = format!("{e:#}");
        sh.status().kernel = KernelState::Error;
        sh.status().kernel_error = Some(msg.clone());
        sh.tl.event("kernel_error", json!({ "message": msg }));
        sh.notify(Level::Error, "AI Anchor 内核出错", &msg);
        wait_reload(sh, Some(Duration::from_secs(60)));
    }
    sess_stop.store(true, Ordering::SeqCst);
    let _ = bridge.join();
    if let Some((_, h)) = watcher {
        let _ = h.join();
    }
}

fn on_kernel(sh: &Shared, ev: KernelEvent, failing: &mut u32) {
    match ev {
        KernelEvent::Started { pid, listening } => {
            {
                let mut st = sh.status();
                st.kernel = KernelState::Running;
                st.kernel_pid = Some(pid);
            }
            log::line(&format!("内核已启动（pid {pid}{}）", if listening { "" } else { "，5 秒内没有开始监听" }));
            sh.tl.event("kernel_start", json!({ "pid": pid, "listening": listening }));
        }
        KernelEvent::Exited { pid, code, uptime, restart_in } => {
            *failing += 1;
            {
                let mut st = sh.status();
                st.kernel = KernelState::Restarting;
                st.kernel_restarts += 1;
            }
            log::line(&format!(
                "内核意外退出（pid {pid}，退出码 {code:?}，运行 {}），{} 后重启",
                humantime::format_duration(Duration::from_secs(uptime.as_secs())),
                humantime::format_duration(restart_in)
            ));
            if *failing == NOTIFY_AFTER_RESTARTS {
                let msg = format!("sing-box 连续退出 {failing} 次，仍在重试。查看日志：{}", sh.paths.log_dir().join("sing-box.log").display());
                sh.tl.event("kernel_error", json!({ "message": msg }));
                sh.notify(Level::Error, "AI Anchor 内核反复退出", &msg);
            }
        }
        KernelEvent::Recovered { pid, code, uptime, down } => {
            {
                let mut st = sh.status();
                st.kernel = KernelState::Running;
                st.kernel_pid = Some(pid);
            }
            log::line(&format!("内核已恢复（pid {pid}），中断 {} 毫秒", down.as_millis()));
            sh.tl.event(
                "kernel_restart",
                json!({ "pid": pid, "exit_code": code, "uptime_ms": uptime.as_millis() as u64, "down_ms": down.as_millis() as u64 }),
            );
            if *failing >= NOTIFY_AFTER_RESTARTS {
                sh.notify(Level::Info, "AI Anchor 内核已恢复", "AI 通道恢复可用。");
            }
            *failing = 0;
        }
        KernelEvent::Stopped => {
            sh.status().kernel = KernelState::Stopped;
            log::line("内核已停止");
        }
    }
}

fn on_watch(sh: &Shared, ev: WatchEvent) {
    match ev {
        WatchEvent::Probe { line, ok, ms, note } => {
            sh.tl.probe("line", &line, ok, ms, &note);
            // 当前线路的定时探测（组测速的结果不代表当前线路）
            if ok && note.is_empty() {
                sh.status().line = Some(line);
            }
        }
        WatchEvent::Switched { from, to, ms } => {
            {
                let mut st = sh.status();
                st.line = Some(to.clone());
                st.lines_down = false;
            }
            log::line(&format!("线路 {from} 探测失败，已切换到 {to}"));
            sh.tl.event("line_switch", json!({ "from": from, "to": to, "reason": "down", "ms": ms }));
        }
        WatchEvent::LineDown { line } => {
            sh.status().lines_down = true;
            sh.tl.event("line_down", json!({ "line": line }));
            sh.notify(Level::Warn, "当前线路不可用", &format!("线路 {line} 探测失败。手动模式不会自动切换；AI 新连接会失败，不会直连。"));
        }
        WatchEvent::AllDown { line } => {
            sh.status().lines_down = true;
            sh.tl.event("all_lines_down", json!({ "line": line }));
            sh.notify(Level::Error, "所有线路都不可用", "AI 新连接会失败，不会直连；出口 IP 不会因此改变。线路恢复后会再通知。");
        }
        WatchEvent::Recovered { line } => {
            {
                let mut st = sh.status();
                st.lines_down = false;
                st.line = Some(line.clone());
            }
            sh.tl.event("line_recovered", json!({ "line": line }));
            sh.notify(Level::Info, "线路已恢复", &format!("当前线路 {line}，AI 通道可用。"));
        }
    }
}
