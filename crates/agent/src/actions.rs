//! 托盘菜单和面板共用的几个操作。

use crate::shared::{Level, Shared};
use anchor_core::win::wide;
use anyhow::{Context, Result, bail};
use std::os::windows::process::CommandExt;
use std::process::{Child, Command};
use std::ptr::{null, null_mut};
use std::sync::Mutex;
use std::sync::atomic::Ordering;
use windows_sys::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetStdHandle};
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

const CREATE_NEW_CONSOLE: u32 = 0x10;

/// 启动一个用自己的控制台输入输出的进程：不把本进程的标准输入、输出传给它。
///
/// 用 anchor agent start（或升级）启动的用户代理，三样都指向 NUL。照常传下去的话，新窗口里什么都不显示，
/// 要人回答的地方读到的是“输入结束”，窗口一闪就关。Command 只有在三样都是空的时候才不传，
/// 所以启动的那一下先把它们置空，启动完再放回去。
fn spawn_in_own_console(cmd: &mut Command) -> std::io::Result<Child> {
    static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());
    let _guard = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        let saved = [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE].map(|id| (id, GetStdHandle(id)));
        for (id, _) in saved {
            SetStdHandle(id, null_mut());
        }
        let r = cmd.creation_flags(CREATE_NEW_CONSOLE).spawn();
        for (id, h) in saved {
            SetStdHandle(id, h);
        }
        r
    }
}

/// 在新控制台窗口里运行 anchor.exe 的一条命令（结束后等回车再关）。
pub fn run_cli(sh: &Shared, args: &[&str]) -> Result<()> {
    let exe = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join("anchor.exe"))).context("无法确定程序目录")?;
    let mut cmd = Command::new(&exe);
    cmd.arg("--home").arg(&sh.paths.home).args(args).arg("--pause");
    spawn_in_own_console(&mut cmd).with_context(|| format!("无法运行 {}", exe.display()))?;
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
    shell_open(url)
}

/// 用默认浏览器打开某个版本在 GitHub 上的发布页。
pub fn open_release(version: &str) -> Result<()> {
    shell_open(&anchor_core::update::release_page(version).context("版本号格式不对")?)
}

fn shell_open(url: &str) -> Result<()> {
    let (verb, target) = (wide("open"), wide(url));
    let r = unsafe { ShellExecuteW(null_mut(), verb.as_ptr(), target.as_ptr(), null(), null(), SW_SHOWNORMAL) };
    // 返回值大于 32 表示成功
    if r as usize <= 32 {
        bail!("默认浏览器打不开 {url}");
    }
    Ok(())
}
