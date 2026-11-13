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
    ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceType,
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

fn program_dir() -> PathBuf {
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
fn lock_down(dir: &Path) -> Result<()> {
    let d = dir.to_string_lossy();
    icacls(&[&d, "/setowner", "*S-1-5-32-544", "/T", "/Q"])?;
    icacls(&[&d, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX", "/T", "/Q"])
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

    // 1. 程序复制到只有管理员能写的目录
    let dir = program_dir();
    std::fs::create_dir_all(&dir)?;
    let exe = dir.join("anchor-svc.exe");
    let me = std::env::current_exe()?;
    if !anchor_core::util::same_path(&me, &exe) {
        std::fs::copy(&me, &exe).with_context(|| format!("复制到 {} 失败", exe.display()))?;
    }

    // 2. 状态目录：重设所有者和访问控制，再写登记信息
    let data = data_dir();
    std::fs::create_dir_all(&data)?;
    lock_down(&data)?;
    let state = SvcState { user_sid: sid.clone(), home: home.clone() };
    let sf = state_file();
    let _ = std::fs::remove_file(&sf);
    std::fs::write(&sf, toml::to_string(&state)?)?;

    // 3. 注册或更新服务：开机自启，失败后 5 秒重启
    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe.clone(),
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

pub fn uninstall() -> Result<()> {
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
    println!("防火墙守卫规则保持不变（AI 程序仍然只能经通道联网）。要移除规则：anchor guard remove");
    Ok(())
}
