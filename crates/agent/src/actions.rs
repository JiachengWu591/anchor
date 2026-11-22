//! 托盘菜单和面板共用的几个操作。

use crate::shared::{Level, Shared};
use anchor_core::win::wide;
use anyhow::{Context, Result, bail};
use std::os::windows::process::CommandExt;
use std::ptr::{null, null_mut};
use std::sync::atomic::Ordering;
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

const CREATE_NEW_CONSOLE: u32 = 0x10;

/// 在新控制台窗口里运行 anchor.exe 的一条命令（结束后等回车再关）。
pub fn run_cli(sh: &Shared, args: &[&str]) -> Result<()> {
    let exe = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join("anchor.exe"))).context("无法确定程序目录")?;
    std::process::Command::new(&exe)
        .arg("--home")
        .arg(&sh.paths.home)
        .args(args)
        .arg("--pause")
        .creation_flags(CREATE_NEW_CONSOLE)
        .spawn()
        .with_context(|| format!("无法运行 {}", exe.display()))?;
    Ok(())
}

pub fn open_folder(sh: &Shared) -> Result<()> {
    let explorer = std::env::var_os("SystemRoot").map(std::path::PathBuf::from).unwrap_or_else(|| r"C:\Windows".into()).join("explorer.exe");
    std::process::Command::new(explorer).arg(&sh.paths.home).spawn().context("无法打开资源管理器")?;
    Ok(())
}

/// 先锁住 AI 通道，立即核对出口（与网络变化时的处理相同）。
pub fn recheck(sh: &Shared) {
    sh.recheck.store(true, Ordering::SeqCst);
    sh.poke();
}

pub fn reload(sh: &Shared) {
    sh.reload.store(true, Ordering::SeqCst);
    sh.notify(Level::Info, "正在重新加载配置", "内核会按新配置重启，几秒内恢复。");
}

/// 用默认浏览器打开一个本机地址。
pub fn open_url(url: &str) -> Result<()> {
    if !url.starts_with("http://127.0.0.1:") {
        bail!("只打开本机面板的地址");
    }
    let (verb, target) = (wide("open"), wide(url));
    let r = unsafe { ShellExecuteW(null_mut(), verb.as_ptr(), target.as_ptr(), null(), null(), SW_SHOWNORMAL) };
    // 返回值大于 32 表示成功
    if r as usize <= 32 {
        bail!("默认浏览器打不开 {url}");
    }
    Ok(())
}
