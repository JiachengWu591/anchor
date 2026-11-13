//! 最小的原生托盘：图标随状态变化（正常 / 注意 / 故障），右键菜单，系统通知用托盘气泡。
//! 面板留到 P2。

use crate::shared::{Level, Shared};
use anchor_core::log;
use anchor_core::win::wide;
use anyhow::{Result, bail};
use std::ffi::c_void;
use std::os::windows::process::CommandExt;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicPtr, AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Shell::{
    NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIIF_ERROR, NIIF_INFO, NIIF_WARNING, NIM_ADD, NIM_DELETE, NIM_MODIFY,
    NOTIFYICONDATAW, Shell_NotifyIconW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, DestroyWindow, DispatchMessageW, GetCursorPos,
    GetMessageW, IDI_ERROR, IDI_INFORMATION, IDI_WARNING, LoadIconW, MF_GRAYED, MF_SEPARATOR, MF_STRING, MSG, PostMessageW,
    PostQuitMessage, RegisterClassW, RegisterWindowMessageW, SetForegroundWindow, SetTimer, TPM_NONOTIFY, TPM_RETURNCMD,
    TPM_RIGHTBUTTON, TrackPopupMenu, TranslateMessage, WM_APP, WM_CLOSE, WM_DESTROY, WM_ENDSESSION, WM_LBUTTONUP, WM_RBUTTONUP,
    WM_TIMER, WNDCLASSW, WS_OVERLAPPED,
};

const WM_TRAY: u32 = WM_APP + 1;
const ID_STATUS: usize = 1;
const ID_TIMELINE: usize = 10;
const ID_CHECK: usize = 11;
const ID_FOLDER: usize = 12;
const ID_RELOAD: usize = 20;
const ID_QUIT: usize = 30;
const CREATE_NEW_CONSOLE: u32 = 0x10;

static SHARED: OnceLock<Arc<Shared>> = OnceLock::new();
static HWND_: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
static TASKBAR_CREATED: AtomicU32 = AtomicU32::new(0);

/// 让托盘消息循环醒来检查退出标志（其他线程调用）。
pub fn wake() {
    let h = HWND_.load(Ordering::SeqCst);
    if !h.is_null() {
        unsafe { PostMessageW(h, WM_CLOSE, 0, 0) };
    }
}

fn copy_into(dst: &mut [u16], s: &str) {
    let w: Vec<u16> = s.encode_utf16().take(dst.len() - 1).collect();
    dst[..w.len()].copy_from_slice(&w);
    dst[w.len()] = 0;
}

fn icon_for(level: Level) -> *mut c_void {
    let id = match level {
        Level::Info => IDI_INFORMATION,
        Level::Warn => IDI_WARNING,
        Level::Error => IDI_ERROR,
    };
    unsafe { LoadIconW(null_mut(), id) }
}

fn base_data(hwnd: HWND) -> NOTIFYICONDATAW {
    let mut d: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
    d.cbSize = size_of::<NOTIFYICONDATAW>() as u32;
    d.hWnd = hwnd;
    d.uID = 1;
    d
}

struct Icon {
    level: Option<Level>,
    tip: String,
}

static ICON: std::sync::Mutex<Icon> = std::sync::Mutex::new(Icon { level: None, tip: String::new() });

fn update_icon(hwnd: HWND, force_add: bool) {
    let Some(sh) = SHARED.get() else { return };
    let (level, text) = sh.summary();
    let tip = format!("AI Anchor：{text}");
    let mut cur = ICON.lock().unwrap_or_else(|e| e.into_inner());
    if !force_add && cur.level == Some(level) && cur.tip == tip {
        return;
    }
    let mut d = base_data(hwnd);
    d.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    d.uCallbackMessage = WM_TRAY;
    d.hIcon = icon_for(level);
    copy_into(&mut d.szTip, &tip);
    let op = if force_add || cur.level.is_none() { NIM_ADD } else { NIM_MODIFY };
    if unsafe { Shell_NotifyIconW(op, &d) } == 0 && op == NIM_ADD {
        // 已存在（例如资源管理器没有重启）时改为更新
        unsafe { Shell_NotifyIconW(NIM_MODIFY, &d) };
    }
    cur.level = Some(level);
    cur.tip = tip;
}

fn balloon(hwnd: HWND, level: Level, title: &str, body: &str) {
    let mut d = base_data(hwnd);
    d.uFlags = NIF_INFO;
    copy_into(&mut d.szInfoTitle, title);
    copy_into(&mut d.szInfo, body);
    d.dwInfoFlags = match level {
        Level::Info => NIIF_INFO,
        Level::Warn => NIIF_WARNING,
        Level::Error => NIIF_ERROR,
    };
    unsafe { Shell_NotifyIconW(NIM_MODIFY, &d) };
}

/// 在新控制台窗口里运行 anchor.exe 的一条命令（结束后等回车再关）。
fn run_cli(args: &[&str]) {
    let Some(sh) = SHARED.get() else { return };
    let Some(exe) = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join("anchor.exe"))) else { return };
    let r = std::process::Command::new(&exe)
        .arg("--home")
        .arg(&sh.paths.home)
        .args(args)
        .arg("--pause")
        .creation_flags(CREATE_NEW_CONSOLE)
        .spawn();
    if let Err(e) = r {
        sh.notify(Level::Error, "无法打开命令行", &format!("{}：{e}", exe.display()));
    }
}

fn show_menu(hwnd: HWND) {
    let Some(sh) = SHARED.get() else { return };
    let (_, text) = sh.summary();
    unsafe {
        let m = CreatePopupMenu();
        let item = |flags, id, s: &str| {
            let w = wide(s);
            AppendMenuW(m, flags, id, w.as_ptr());
        };
        item(MF_STRING | MF_GRAYED, ID_STATUS, &format!("AI Anchor：{text}"));
        AppendMenuW(m, MF_SEPARATOR, 0, null());
        item(MF_STRING, ID_TIMELINE, "查看时间线（最近 24 小时）");
        item(MF_STRING, ID_CHECK, "运行体检");
        item(MF_STRING, ID_FOLDER, "打开数据目录");
        AppendMenuW(m, MF_SEPARATOR, 0, null());
        item(MF_STRING, ID_RELOAD, "重新加载配置");
        item(MF_STRING, ID_QUIT, "退出 AI Anchor");
        let mut pt = POINT { x: 0, y: 0 };
        GetCursorPos(&mut pt);
        // 不先设前台窗口，菜单在点击别处时不会消失
        SetForegroundWindow(hwnd);
        let cmd = TrackPopupMenu(m, TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_NONOTIFY, pt.x, pt.y, 0, hwnd, null()) as usize;
        DestroyMenu(m);
        match cmd {
            ID_TIMELINE => run_cli(&["timeline", "--since", "24h"]),
            ID_CHECK => run_cli(&["check"]),
            ID_FOLDER => {
                let explorer = std::env::var_os("SystemRoot").map(std::path::PathBuf::from).unwrap_or_else(|| r"C:\Windows".into()).join("explorer.exe");
                let _ = std::process::Command::new(explorer).arg(&sh.paths.home).spawn();
            }
            ID_RELOAD => {
                sh.reload.store(true, Ordering::SeqCst);
                sh.notify(Level::Info, "正在重新加载配置", "内核会按新配置重启，几秒内恢复。");
            }
            ID_QUIT => {
                sh.request_stop("托盘菜单退出");
                DestroyWindow(hwnd);
            }
            _ => {}
        }
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    let tc = TASKBAR_CREATED.load(Ordering::SeqCst);
    match msg {
        WM_TRAY => {
            let ev = lp as u32;
            if ev == WM_RBUTTONUP || ev == WM_LBUTTONUP {
                show_menu(hwnd);
            }
            0
        }
        WM_TIMER => {
            if let Some(sh) = SHARED.get() {
                if sh.stopping() {
                    unsafe { DestroyWindow(hwnd) };
                    return 0;
                }
                update_icon(hwnd, false);
                for n in sh.take_notes() {
                    balloon(hwnd, n.level, &n.title, &n.body);
                }
            }
            0
        }
        WM_CLOSE => {
            if SHARED.get().is_some_and(|s| s.stopping()) {
                unsafe { DestroyWindow(hwnd) };
            }
            0
        }
        WM_ENDSESSION => {
            if wp != 0
                && let Some(sh) = SHARED.get()
            {
                sh.request_stop("注销或关机");
            }
            0
        }
        WM_DESTROY => {
            let d = base_data(hwnd);
            unsafe {
                Shell_NotifyIconW(NIM_DELETE, &d);
                PostQuitMessage(0);
            }
            0
        }
        m if tc != 0 && m == tc => {
            // 资源管理器重启后托盘图标会消失，重新添加
            update_icon(hwnd, true);
            0
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wp, lp) },
    }
}

/// 在当前线程运行托盘消息循环，直到退出。
pub fn run(sh: Arc<Shared>) -> Result<()> {
    let _ = SHARED.set(sh);
    unsafe {
        let hinst = GetModuleHandleW(null());
        let class = wide("AIAnchorTray");
        let wc = WNDCLASSW {
            style: 0,
            lpfnWndProc: Some(wndproc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: hinst,
            hIcon: null_mut(),
            hCursor: null_mut(),
            hbrBackground: null_mut(),
            lpszMenuName: null(),
            lpszClassName: class.as_ptr(),
        };
        if RegisterClassW(&wc) == 0 {
            bail!("RegisterClassW 失败：{}", std::io::Error::last_os_error());
        }
        TASKBAR_CREATED.store(RegisterWindowMessageW(wide("TaskbarCreated").as_ptr()), Ordering::SeqCst);
        // 普通隐藏窗口（不是仅消息窗口），才能收到 TaskbarCreated 广播
        let title = wide("AI Anchor");
        let hwnd = CreateWindowExW(0, class.as_ptr(), title.as_ptr(), WS_OVERLAPPED, 0, 0, 0, 0, null_mut(), null_mut(), hinst, null());
        if hwnd.is_null() {
            bail!("CreateWindowExW 失败：{}", std::io::Error::last_os_error());
        }
        HWND_.store(hwnd, Ordering::SeqCst);
        update_icon(hwnd, true);
        SetTimer(hwnd, 1, 1000, None);
        log::line("托盘图标已就绪");
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        HWND_.store(null_mut(), Ordering::SeqCst);
    }
    Ok(())
}
