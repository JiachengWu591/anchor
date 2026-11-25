//! 安装和卸载 Windows 服务（需要管理员）。
//!
//! 服务以 LocalSystem 运行，所以程序和状态都放在普通用户不能写的位置：
//! 程序复制到 %ProgramFiles%\AI Anchor\anchor-svc.exe；状态写到 %ProgramData%\AIAnchor（重设访问控制）。

use anchor_core::win;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use windows_service::service::{
    Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl, ServiceFailureActions,
    ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

pub const SERVICE_NAME: &str = "AIAnchorSvc";
const DISPLAY_NAME: &str = "AI Anchor Guard";
const DESCRIPTION: &str = "维护 AI Anchor 的防火墙守卫规则：AI 程序只能经本机 AI 通道联网，应用更新后自动覆盖新版本。";

/// 安装时登记的信息，服务启动时读取。
#[derive(Debug, Serialize, Deserialize)]
pub struct SvcState {
    pub user_sid: String,
    pub home: PathBuf,
}

pub fn data_dir() -> PathBuf {
    std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData")).join("AIAnchor")
}

pub fn state_file() -> PathBuf {
    data_dir().join("svc.toml")
}

pub fn log_file() -> PathBuf {
    data_dir().join("svc.log")
}

pub fn program_dir() -> PathBuf {
    std::env::var_os("ProgramFiles").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Program Files")).join("AI Anchor")
}

pub fn load_state() -> Result<SvcState> {
    let p = state_file();
    let text = std::fs::read_to_string(&p).with_context(|| format!("读取 {} 失败（服务没有安装完整？）", p.display()))?;
    toml::from_str(&text).with_context(|| format!("{} 格式错误", p.display()))
}

fn icacls(args: &[&str]) -> Result<()> {
    let out = Command::new(win::system32("icacls.exe")).args(args).output().context("无法运行 icacls")?;
    if !out.status.success() {
        bail!("icacls 失败：{}", String::from_utf8_lossy(&out.stdout).trim());
    }
    Ok(())
}

/// 只允许 SYSTEM 和管理员写，普通用户只读。用 SID 写，不依赖系统语言里的组名。
///
/// 显式权限只设在目录上（带继承标志），目录里已有的文件改为从目录继承。
///
/// 旧版这里用 /T 把带 (OI)(CI) 的授权直接套到了文件上：重装时 svc.log 已经存在，
/// 它的权限列表因此变成空的，谁都打不开（临时目录里复现过），连改所有者都会失败，
/// 第二次重装就卡在这里。所以只有目录本身的设置失败才中止；已有文件先重设为继承
/// （管理员组是它们的所有者，总能改权限），还打不开的就删掉（管理员对目录有完全控制，可以删其中的文件）。
fn lock_down(dir: &Path) -> Result<()> {
    let d = dir.to_string_lossy().trim_end_matches('\\').to_string();
    icacls(&[&d, "/setowner", "*S-1-5-32-544", "/Q"])?;
    icacls(&[&d, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX", "/Q"])?;
    if std::fs::read_dir(dir)?.next().is_none() {
        return Ok(());
    }
    let children = format!("{d}\\*");
    if let Err(e) = icacls(&[&children, "/reset", "/T", "/C", "/Q"]) {
        println!("提示：重设已有文件的权限时有错误，下面逐个检查：{e:#}");
    }
    let _ = icacls(&[&children, "/setowner", "*S-1-5-32-544", "/T", "/C", "/Q"]);
    for e in std::fs::read_dir(dir)?.flatten() {
        let p = e.path();
        // 用目录项里的类型，不打开文件：权限损坏的文件连属性都读不了
        if e.file_type().is_ok_and(|t| t.is_file()) && std::fs::File::open(&p).is_err() {
            match std::fs::remove_file(&p) {
                Ok(()) => println!("已删除权限损坏、无法访问的旧文件 {}", p.display()),
                Err(err) => bail!("{} 无法访问，也删不掉：{err}", p.display()),
            }
        }
    }
    Ok(())
}

fn wait_state(svc: &windows_service::service::Service, want: ServiceState, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if svc.query_status().map(|s| s.current_state == want).unwrap_or(false) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    false
}

pub fn install(user_sid: Option<String>, home: Option<PathBuf>) -> Result<()> {
    win::require_admin()?;
    let sid = match user_sid {
        Some(s) => s,
        None => win::current_user_sid()?,
    };
    if !sid.starts_with("S-1-5-21-") {
        bail!("登记的用户 {sid} 不是普通用户账户，请用 --user-sid 指定");
    }
    let profile = win::profile_dir(&sid)?;
    let home = home.unwrap_or_else(|| profile.join("AppData").join("Local").join("AIAnchor"));
    if !home.join("anchor.toml").is_file() {
        println!("提示：{} 还没有 anchor.toml，服务在读到有效配置之前不会改动任何守卫规则。", home.display());
    }

    // 1. 状态目录：重设所有者和访问控制，再写登记信息。不需要停服务，所以先做：
    //    这一步出错时旧服务照常运行，守卫维护不中断
    let data = data_dir();
    std::fs::create_dir_all(&data)?;
    lock_down(&data)?;
    let state = SvcState { user_sid: sid.clone(), home: home.clone() };
    let sf = state_file();
    let _ = std::fs::remove_file(&sf);
    std::fs::write(&sf, toml::to_string(&state)?)?;

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
    let access = ServiceAccess::QUERY_STATUS | ServiceAccess::START | ServiceAccess::STOP | ServiceAccess::CHANGE_CONFIG;
    let existing = manager.open_service(SERVICE_NAME, access).ok();
    if let Some(svc) = &existing
        && svc.query_status()?.current_state != ServiceState::Stopped
    {
        println!("停止正在运行的旧版服务…");
        let _ = svc.stop();
        if !wait_state(svc, ServiceState::Stopped, Duration::from_secs(15)) {
            bail!("旧版服务 15 秒内没有停止，请稍后重试");
        }
    }

    // 2. 复制程序、注册或更新服务。旧服务已经停了：这里出错就把服务重新启动，免得守卫维护就此停下
    let exe = program_dir().join("anchor-svc.exe");
    let had_service = existing.is_some();
    let svc = match copy_and_register(&manager, existing, &exe, access) {
        Ok(svc) => svc,
        Err(e) => {
            if had_service
                && let Ok(old) = manager.open_service(SERVICE_NAME, ServiceAccess::START)
                && old.start::<&str>(&[]).is_ok()
            {
                println!("安装没有完成，已重新启动原来的服务，守卫维护没有中断。");
            }
            return Err(e);
        }
    };
    svc.start::<&str>(&[])?;
    if !wait_state(&svc, ServiceState::Running, Duration::from_secs(15)) {
        bail!("服务没有在 15 秒内启动，查看日志：{}", log_file().display());
    }
    println!("已安装并启动服务 {SERVICE_NAME}（{DISPLAY_NAME}）。");
    println!("  程序      {}", exe.display());
    println!("  登记用户  {sid}");
    println!("  数据目录  {}", home.display());
    println!("  服务日志  {}", log_file().display());
    println!("服务会立即刷新一次守卫规则，之后应用安装或更新时自动刷新，并每 5 分钟检查一次。");
    Ok(())
}

/// 程序复制到只有管理员能写的目录，注册或更新服务：开机自启，失败后 5 秒重启。
fn copy_and_register(manager: &ServiceManager, existing: Option<Service>, exe: &Path, access: ServiceAccess) -> Result<Service> {
    std::fs::create_dir_all(program_dir())?;
    let me = std::env::current_exe()?;
    if !anchor_core::util::same_path(&me, exe) {
        std::fs::copy(&me, exe).with_context(|| format!("复制到 {} 失败", exe.display()))?;
    }
    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe.to_path_buf(),
        launch_arguments: vec![OsString::from("service")],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };
    let svc = match existing {
        Some(svc) => {
            svc.change_config(&info)?;
            svc
        }
        None => manager.create_service(&info, access)?,
    };
    svc.set_description(DESCRIPTION)?;
    let restart = ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(5) };
    svc.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![restart.clone(), restart.clone(), restart]),
    })?;
    Ok(svc)
}

pub fn uninstall(remove_rules: bool) -> Result<()> {
    win::require_admin()?;
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE) {
        Ok(svc) => {
            if svc.query_status()?.current_state != ServiceState::Stopped {
                let _ = svc.stop();
                wait_state(&svc, ServiceState::Stopped, Duration::from_secs(15));
            }
            svc.delete()?;
            println!("已删除服务 {SERVICE_NAME}。");
        }
        Err(_) => println!("服务 {SERVICE_NAME} 没有安装。"),
    }
    let exe = program_dir().join("anchor-svc.exe");
    if exe.exists() && std::fs::remove_file(&exe).is_ok() {
        let _ = std::fs::remove_dir(program_dir());
    }
    let _ = std::fs::remove_file(state_file());
    if remove_rules {
        // 服务已经删了，不会再把规则补回来
        let n = anchor_core::guard::remove_all()?;
        println!("已移除 {n} 条防火墙守卫规则。");
    } else {
        println!("防火墙守卫规则保持不变（AI 程序仍然只能经通道联网）。要移除规则：anchor guard remove");
    }
    Ok(())
}
