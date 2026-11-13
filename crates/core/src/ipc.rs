//! 本机接口：命名管道上一行一个 JSON，带协议版本号。一次连接只处理一个请求。
//!
//! 用户代理 \\.\pipe\ai-anchor-agent 只允许当前用户访问；
//! 特权服务 \\.\pipe\ai-anchor-svc 只允许登记的用户、管理员和 SYSTEM 访问。
//! 两个管道都拒绝远程客户端。客户端以“仅识别”级别连接，服务端无法冒用调用者的身份。

use crate::win::wide;
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::ptr::null_mut;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_GENERIC_READ, FILE_WRITE_DATA, FlushFileBuffers, PIPE_ACCESS_DUPLEX,
    SECURITY_IDENTIFICATION,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT, WaitNamedPipeW,
};

pub const PROTO: u32 = 1;
pub const AGENT_PIPE: &str = r"\\.\pipe\ai-anchor-agent";
pub const SVC_PIPE: &str = r"\\.\pipe\ai-anchor-svc";
const MAX_MSG: u64 = 1 << 20;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub v: u32,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub v: u32,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub result: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Response {
    pub fn ok(result: Value) -> Self {
        Self { v: PROTO, ok: true, result, error: None }
    }
    pub fn err(msg: impl fmt::Display) -> Self {
        Self { v: PROTO, ok: false, result: Value::Null, error: Some(msg.to_string()) }
    }
    pub fn from_result(r: Result<Value>) -> Self {
        match r {
            Ok(v) => Self::ok(v),
            Err(e) => Self::err(format!("{e:#}")),
        }
    }
}

#[derive(Debug)]
pub enum CallError {
    /// 管道不存在：对方没有运行
    NotRunning,
    /// 管道的访问控制拒绝了当前用户
    Denied,
    /// 对方处理了请求但返回错误
    Remote(String),
    Io(std::io::Error),
    Proto(String),
}

impl fmt::Display for CallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRunning => write!(f, "没有运行"),
            Self::Denied => write!(f, "拒绝访问（当前用户不是安装时登记的用户？）"),
            Self::Remote(e) => write!(f, "{e}"),
            Self::Io(e) => write!(f, "通信失败：{e}"),
            Self::Proto(e) => write!(f, "响应格式错误：{e}"),
        }
    }
}
impl std::error::Error for CallError {}

fn open(pipe: &str, wait: Duration) -> Result<File, CallError> {
    let deadline = Instant::now() + wait;
    loop {
        let r = OpenOptions::new().access_mode(CLIENT_ACCESS).security_qos_flags(SECURITY_IDENTIFICATION).open(pipe);
        match r {
            Ok(f) => return Ok(f),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) && Instant::now() < deadline => {
                unsafe { WaitNamedPipeW(wide(pipe).as_ptr(), 500) };
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(CallError::NotRunning),
            Err(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => return Err(CallError::Denied),
            Err(e) => return Err(CallError::Io(e)),
        }
    }
}

/// 发送一个请求并等待响应。
pub fn call(pipe: &str, method: &str, params: Value) -> Result<Value, CallError> {
    let f = open(pipe, Duration::from_secs(3))?;
    let req = Request { v: PROTO, method: method.to_string(), params };
    let mut line = serde_json::to_string(&req).map_err(|e| CallError::Proto(e.to_string()))?;
    line.push('\n');
    (&f).write_all(line.as_bytes()).map_err(CallError::Io)?;
    (&f).flush().map_err(CallError::Io)?;
    let mut buf = String::new();
    BufReader::new((&f).take(MAX_MSG)).read_line(&mut buf).map_err(CallError::Io)?;
    if buf.trim().is_empty() {
        return Err(CallError::Proto("对方没有返回内容".into()));
    }
    let resp: Response = serde_json::from_str(buf.trim()).map_err(|e| CallError::Proto(e.to_string()))?;
    if resp.v != PROTO {
        return Err(CallError::Proto(format!("协议版本不一致（对方 {}，本机 {PROTO}），请把各组件升级到同一版本", resp.v)));
    }
    if resp.ok { Ok(resp.result) } else { Err(CallError::Remote(resp.error.unwrap_or_default())) }
}

/// 对方是否在运行（管道存在即可，不论能否访问）。
pub fn is_running(pipe: &str) -> bool {
    !matches!(open(pipe, Duration::from_millis(500)), Err(CallError::NotRunning))
}

struct SecDesc(PSECURITY_DESCRIPTOR);
impl Drop for SecDesc {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}

fn sec_desc(sddl: &str) -> Result<SecDesc> {
    let mut psd: PSECURITY_DESCRIPTOR = null_mut();
    let ok = unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(wide(sddl).as_ptr(), SDDL_REVISION_1, &mut psd, null_mut()) };
    if ok == 0 {
        bail!("安全描述符格式错误：{}", std::io::Error::last_os_error());
    }
    Ok(SecDesc(psd))
}

/// 管道的访问控制。full 里的账户（可用 SY、BA 这类别名）拥有全部权限，能创建管道实例；
/// clients 里的账户只能读写，不能再创建同名实例冒充服务端。
pub fn sddl(full: &[&str], clients: &[&str]) -> String {
    let mut s = String::from("D:P");
    for a in full {
        s.push_str(&format!("(A;;GA;;;{a})"));
    }
    for a in clients {
        s.push_str(&format!("(A;;0x{CLIENT_ACCESS:x};;;{a})"));
    }
    s
}

/// 客户端需要的权限：读，和写数据。不含 FILE_APPEND_DATA（对管道即“创建实例”）。
const CLIENT_ACCESS: u32 = FILE_GENERIC_READ | FILE_WRITE_DATA;

/// 一个命名管道的服务端。
pub struct Listener {
    name: String,
    wname: Vec<u16>,
    sd: SecDesc,
    first: Option<HANDLE>,
}
unsafe impl Send for Listener {}

#[derive(Debug)]
pub struct AlreadyRunning;
impl fmt::Display for AlreadyRunning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "已经有一个实例在运行")
    }
}
impl std::error::Error for AlreadyRunning {}

impl Listener {
    /// 创建第一个管道实例。同名管道已存在时返回 AlreadyRunning，可用作单实例锁。
    pub fn bind(pipe: &str, sddl: &str) -> Result<Self> {
        let mut l = Self { name: pipe.to_string(), wname: wide(pipe), sd: sec_desc(sddl)?, first: None };
        match l.create(true) {
            Ok(h) => l.first = Some(h),
            Err(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => return Err(AlreadyRunning.into()),
            Err(e) => bail!("创建命名管道 {pipe} 失败：{e}"),
        }
        Ok(l)
    }

    fn create(&self, first: bool) -> std::io::Result<HANDLE> {
        let sa = SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: self.sd.0, bInheritHandle: 0 };
        let open_mode = PIPE_ACCESS_DUPLEX | if first { FILE_FLAG_FIRST_PIPE_INSTANCE } else { 0 };
        let h = unsafe {
            CreateNamedPipeW(
                self.wname.as_ptr(),
                open_mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                64 * 1024,
                64 * 1024,
                0,
                &sa,
            )
        };
        if h == INVALID_HANDLE_VALUE { Err(std::io::Error::last_os_error()) } else { Ok(h) }
    }

    /// 接受连接直到 stop 置位（置位后调用 wake 让阻塞的等待返回）。每个连接一个线程。
    pub fn run<F>(mut self, stop: Arc<AtomicBool>, handler: F)
    where
        F: Fn(Request) -> Response + Send + Sync + 'static,
    {
        let handler = Arc::new(handler);
        let mut next = self.first.take();
        while !stop.load(Ordering::SeqCst) {
            let h = match next.take() {
                Some(h) => h,
                None => match self.create(false) {
                    Ok(h) => h,
                    Err(e) => {
                        eprintln!("创建管道实例失败：{e}");
                        std::thread::sleep(Duration::from_secs(1));
                        continue;
                    }
                },
            };
            let connected = unsafe { ConnectNamedPipe(h, null_mut()) } != 0 || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;
            let file = unsafe { File::from_raw_handle(h as _) };
            if !connected || stop.load(Ordering::SeqCst) {
                continue;
            }
            let handler = handler.clone();
            std::thread::spawn(move || serve_one(file, &*handler));
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

fn serve_one(file: File, handler: &dyn Fn(Request) -> Response) {
    let h = file.as_raw_handle() as HANDLE;
    let mut buf = String::new();
    let resp = match BufReader::new((&file).take(MAX_MSG)).read_line(&mut buf) {
        Ok(_) => match serde_json::from_str::<Request>(buf.trim()) {
            Ok(req) if req.v != PROTO => {
                Response::err(format!("协议版本不一致（对方 {}，本机 {PROTO}），请把各组件升级到同一版本", req.v))
            }
            Ok(req) => handler(req),
            Err(e) => Response::err(format!("请求格式错误：{e}")),
        },
        Err(e) => Response::err(format!("读取请求失败：{e}")),
    };
    if let Ok(mut line) = serde_json::to_string(&resp) {
        line.push('\n');
        let _ = (&file).write_all(line.as_bytes());
        unsafe {
            FlushFileBuffers(h);
            DisconnectNamedPipe(h);
        }
    }
}

/// 让阻塞在等待连接上的服务端返回（停止时调用）。
pub fn wake(pipe: &str) {
    let _ = OpenOptions::new().access_mode(CLIENT_ACCESS).security_qos_flags(SECURITY_IDENTIFICATION).open(pipe);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn round_trip_over_a_real_pipe() {
        let name = format!(r"\\.\pipe\ai-anchor-test-{}", crate::util::random_hex());
        let sid = crate::win::current_user_sid().unwrap();
        let l = Listener::bind(&name, &sddl(&["SY", &sid], &[])).unwrap();
        // 同名第二个实例被拒绝：单实例锁
        assert!(Listener::bind(&name, &sddl(&["SY", &sid], &[])).err().unwrap().is::<AlreadyRunning>());
        let stop = Arc::new(AtomicBool::new(false));
        let s = stop.clone();
        let t = std::thread::spawn(move || {
            l.run(s, |req| match req.method.as_str() {
                "echo" => Response::ok(req.params),
                _ => Response::err("未知方法"),
            })
        });
        assert_eq!(call(&name, "echo", json!({"a": 1})).unwrap(), json!({"a": 1}));
        assert!(matches!(call(&name, "nope", Value::Null), Err(CallError::Remote(_))));
        assert!(is_running(&name));
        stop.store(true, Ordering::SeqCst);
        wake(&name);
        t.join().unwrap();
        assert!(matches!(call(&format!("{name}-missing"), "echo", Value::Null), Err(CallError::NotRunning)));
    }

    #[test]
    fn sddl_gives_clients_read_write_only() {
        assert_eq!(sddl(&["SY", "BA"], &["S-1-5-21-1"]), "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12008b;;;S-1-5-21-1)");
        assert_eq!(CLIENT_ACCESS & 0x4, 0, "不能包含创建管道实例的权限");
    }
}
