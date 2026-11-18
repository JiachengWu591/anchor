//! 一次“会话”= 按当前配置运行内核、线路控制器、出口核对和持续探测。收到重新加载请求或退出时结束，再按新配置开始下一次。

use crate::shared::{KernelState, Level, Shared};
use anchor_core::config::{Config, LineMode, host_port};
use anchor_core::kernel::{self, KernelEvent};
use anchor_core::log;
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

/// 连续意外退出这么多次仍未恢复，就通知用户。
const NOTIFY_AFTER_RESTARTS: u32 = 3;

pub fn run(sh: Arc<Shared>) {
    // 上一次会话用的出口：换了就记一条 exit_switch
    let mut last_exit: Option<String> = None;
    while !sh.stopping() {
        sh.reload.store(false, Ordering::SeqCst);
        match Config::load(&sh.paths) {
            Ok(cfg) => {
                sh.status().config_error = None;
                let cfg = Arc::new(cfg);
                let name = cfg.exit_name();
                if let Some(prev) = last_exit.replace(name.clone())
                    && prev != name
                {
                    log::line(&format!("出口 {prev} → {name}（anchor exit use）"));
                    sh.tl.event("exit_switch", json!({ "from": prev, "to": name, "label": cfg.exit.label() }));
                }
                *sh.cfg.lock().unwrap_or_else(|e| e.into_inner()) = Some(cfg.clone());
                one(&sh, &cfg);
            }
            Err(e) => {
                *sh.cfg.lock().unwrap_or_else(|e| e.into_inner()) = None;
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
        st.exit_name = cfg.exit_name();
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
    // AI 通道以锁住状态启动，出口核对通过后才放行
    let (sb, json_path) = match kernel::prepare(cfg, &sh.paths, true) {
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
    // 内核每次（重新）开始监听加一：它以锁住状态启动，出口核对要重新来过，线路组也要重新选
    let kernel_gen = Arc::new(AtomicU64::new(0));
    let line_ctl = crate::lines::spawn(sh.clone(), cfg, sess_stop.clone(), kernel_gen.clone());
    let exit_guard = crate::exitguard::spawn(sh.clone(), cfg, sess_stop.clone(), kernel_gen.clone());
    // 本地网络、整条链路的持续探测，断联归因用
    let health = crate::health::spawn(sh.clone(), cfg, sess_stop.clone());

    let mut failing = 0u32;
    let r = kernel::supervise(cfg, &sh.paths, &sb, &json_path, &sess_stop, &kernel::Options { background: true }, &mut |ev| {
        let started = matches!(ev, KernelEvent::Started { .. } | KernelEvent::Recovered { .. });
        on_kernel(sh, ev, &mut failing);
        if started {
            kernel_gen.fetch_add(1, Ordering::SeqCst);
            sh.poke();
        }
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
    sh.poke();
    let _ = bridge.join();
    let _ = exit_guard.join();
    let _ = health.join();
    if let Some(h) = line_ctl {
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
