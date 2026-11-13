//! anchor-svc：AI Anchor 特权服务。只做一件事：让防火墙守卫规则覆盖当前安装的 AI 程序。
//! 不运行内核，不联网，不执行配置里的任何程序路径。

mod daemon;
mod install;

use anchor_core::{ipc, log, win};
use anyhow::Result;
use clap::{Parser, Subcommand};
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use windows_service::service::{ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

#[derive(Parser)]
#[command(name = "anchor-svc", version, about = "AI Anchor 特权服务：维护防火墙守卫规则，应用更新后自动刷新")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// 安装并启动服务（需要管理员）
    Install {
        /// 登记的用户 SID，默认当前用户
        #[arg(long)]
        user_sid: Option<String>,
        /// 该用户的 AI Anchor 数据目录，默认 %LOCALAPPDATA%\AIAnchor
        #[arg(long)]
        home: Option<PathBuf>,
        /// 出错时停住窗口（从提权窗口运行时使用）
        #[arg(long, hide = true)]
        pause: bool,
    },
    /// 停止并删除服务（需要管理员）；防火墙规则保留
    Uninstall {
        #[arg(long, hide = true)]
        pause: bool,
    },
    /// 由服务控制管理器调用
    #[command(hide = true)]
    Service,
    /// 在前台运行（调试用）：按当前用户运行，Ctrl+C 停止
    Console {
        /// AI Anchor 数据目录
        #[arg(long)]
        home: Option<PathBuf>,
        /// 扫描的用户配置文件目录，默认当前用户
        #[arg(long)]
        profile: Option<PathBuf>,
        /// 只计算要改的规则，不写入（不需要管理员）
        #[arg(long)]
        dry_run: bool,
        /// 定时检查间隔
        #[arg(long, default_value = "5m")]
        poll: humantime::Duration,
    },
}

fn main() {
    let cli = Cli::parse();
    let (r, pause) = match cli.cmd {
        Cmd::Install { user_sid, home, pause } => (install::install(user_sid, home), pause),
        Cmd::Uninstall { pause } => (install::uninstall(), pause),
        Cmd::Service => (run_dispatcher(), false),
        Cmd::Console { home, profile, dry_run, poll } => (console(home, profile, dry_run, poll.into()), false),
    };
    if let Err(e) = r {
        eprintln!("错误：{e:#}");
        if pause {
            eprint!("按回车键关闭…");
            let _ = std::io::stdin().read_line(&mut String::new());
        }
        std::process::exit(1);
    }
    if pause {
        eprint!("完成。按回车键关闭…");
        let _ = std::io::stdin().read_line(&mut String::new());
    }
}

fn console(home: Option<PathBuf>, profile: Option<PathBuf>, dry_run: bool, poll: Duration) -> Result<()> {
    log::init(None, true);
    let sid = win::current_user_sid()?;
    let profile = match profile {
        Some(p) => p,
        None => win::profile_dir(&sid)?,
    };
    let home = match home {
        Some(h) => h,
        None => anchor_core::config::Paths::resolve(None)?.home,
    };
    if !dry_run {
        win::require_admin()?;
    }
    let stop = Arc::new(AtomicBool::new(false));
    let s = stop.clone();
    ctrlc::set_handler(move || {
        s.store(true, Ordering::SeqCst);
        ipc::wake(ipc::SVC_PIPE);
    })?;
    // 控制台模式以当前用户运行，当前用户要能创建管道实例
    let sddl = ipc::sddl(&["SY", "BA", &sid], &[]);
    daemon::run(daemon::Ctx { user_sid: sid, home, profile, dry_run, poll }, stop, &sddl)
}

define_windows_service!(ffi_service_main, service_main);

fn run_dispatcher() -> Result<()> {
    service_dispatcher::start(install::SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

fn service_main(_args: Vec<OsString>) {
    log::init(Some(install::log_file()), false);
    if let Err(e) = run_service() {
        log::line(&format!("服务异常退出：{e:#}"));
    }
}

fn status(state: ServiceState) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    }
}

fn run_service() -> Result<()> {
    let stop = Arc::new(AtomicBool::new(false));
    let s = stop.clone();
    let handle = service_control_handler::register(install::SERVICE_NAME, move |ctrl| match ctrl {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            s.store(true, Ordering::SeqCst);
            ipc::wake(ipc::SVC_PIPE);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    handle.set_service_status(status(ServiceState::Running))?;
    let r = (|| {
        let st = install::load_state()?;
        let profile = win::profile_dir(&st.user_sid)?;
        let sddl = ipc::sddl(&["SY", "BA"], &[&st.user_sid]);
        let ctx = daemon::Ctx { user_sid: st.user_sid, home: st.home, profile, dry_run: false, poll: Duration::from_secs(300) };
        daemon::run(ctx, stop, &sddl)
    })();
    handle.set_service_status(status(ServiceState::Stopped))?;
    r
}
