//! anchor-agent：AI Anchor 用户代理。以当前用户运行，登录时自启，托盘常驻。
//!
//! 守护 sing-box、线路看门狗、时间线、系统通知；向特权服务查询守卫状态。不改防火墙。
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod api;
mod guardpoll;
mod session;
mod shared;
mod tray;

use anchor_core::config::Paths;
use anchor_core::ipc::{self, AlreadyRunning};
use anchor_core::timeline::{Timeline, now_ms};
use anchor_core::{log, win};
use anyhow::Result;
use clap::Parser;
use serde_json::json;
use shared::Shared;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "anchor-agent", version, about = "AI Anchor 用户代理：守护内核、线路看门狗、时间线、托盘与通知")]
struct Args {
    /// 数据目录，默认 %LOCALAPPDATA%\AIAnchor（也可用环境变量 ANCHOR_HOME）
    #[arg(long, value_name = "DIR")]
    home: Option<PathBuf>,
    /// 不显示托盘图标（调试用；日志同时输出到 stderr）
    #[arg(long)]
    no_tray: bool,
}

fn main() {
    let args = Args::parse();
    // 在 MSIX 应用包里（例如从 Claude 桌面版的终端启动）运行时，时间线、日志都会被重定向到该应用的私有目录，
    // 内核和看门狗也留在它的环境里。不创建任何文件，直接退出。
    if let Some(p) = win::sandbox() {
        eprintln!(
            "anchor-agent 不能在 MSIX 应用 {} 里运行（应用包 {}）：写入的文件会被重定向到它的私有目录。\
             请从开始菜单打开的终端运行 anchor agent start，或注销后由登录自启启动。",
            p.app(),
            p.full_name
        );
        std::process::exit(2);
    }
    if let Err(e) = real_main(args) {
        log::line(&format!("anchor-agent 退出：{e:#}"));
        std::process::exit(1);
    }
}

fn real_main(args: Args) -> Result<()> {
    let paths = Paths::resolve(args.home)?;
    std::fs::create_dir_all(paths.log_dir())?;
    log::init(Some(paths.agent_log()), args.no_tray || cfg!(debug_assertions));

    let sid = win::current_user_sid()?;
    let listener = match ipc::Listener::bind(ipc::AGENT_PIPE, &ipc::sddl(&["SY", &sid], &[])) {
        Ok(l) => l,
        Err(e) if e.is::<AlreadyRunning>() => {
            log::line("已经有一个 anchor-agent 在运行，本次退出");
            return Ok(());
        }
        Err(e) => return Err(e),
    };

    let tl = Timeline::open(&paths.timeline_db())?;
    tl.event("agent_start", json!({ "version": anchor_core::VERSION, "pid": std::process::id(), "home": paths.home }));
    log::line(&format!("anchor-agent {} 启动；数据目录 {}", anchor_core::VERSION, paths.home.display()));
    let sh = Arc::new(Shared::new(paths, tl, !args.no_tray));

    let pipe_stop = Arc::new(AtomicBool::new(false));
    {
        let sh = sh.clone();
        let s = pipe_stop.clone();
        thread::spawn(move || listener.run(s, move |req| api::handle(&sh, req)));
    }
    let sessions = {
        let sh = sh.clone();
        thread::spawn(move || session::run(sh))
    };
    {
        let sh = sh.clone();
        thread::spawn(move || guardpoll::run(sh));
    }
    {
        let sh = sh.clone();
        thread::spawn(move || maintenance(sh));
    }

    if sh.tray {
        if let Err(e) = tray::run(sh.clone()) {
            log::line(&format!("托盘不可用，改为无托盘运行：{e:#}"));
            wait_stop(&sh);
        }
    } else {
        let s = sh.clone();
        ctrlc::set_handler(move || s.request_stop("Ctrl+C"))?;
        wait_stop(&sh);
    }
    sh.request_stop("托盘退出");
    let _ = sessions.join();
    pipe_stop.store(true, Ordering::SeqCst);
    ipc::wake(ipc::AGENT_PIPE);
    sh.tl.event("agent_stop", json!({ "reason": sh.stop_reason() }));
    log::line(&format!("anchor-agent 已退出（{}）", sh.stop_reason()));
    Ok(())
}

fn wait_stop(sh: &Shared) {
    while !sh.stopping() {
        thread::sleep(Duration::from_millis(200));
    }
}

/// 每天清理一次超出保留期的时间线数据。
fn maintenance(sh: Arc<Shared>) {
    let mut next = std::time::Instant::now() + Duration::from_secs(60);
    while !sh.stopping() {
        thread::sleep(Duration::from_millis(500));
        if std::time::Instant::now() < next {
            continue;
        }
        next = std::time::Instant::now() + Duration::from_secs(86_400);
        match sh.tl.prune(now_ms()) {
            Ok((p, e)) if p + e > 0 => log::line(&format!("时间线清理：探测 {p} 条，事件 {e} 条")),
            Ok(_) => {}
            Err(e) => log::line(&format!("时间线清理失败：{e:#}")),
        }
    }
}
