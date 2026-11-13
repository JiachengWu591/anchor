//! 管理用户代理 anchor-agent：启动、停止、重新加载、登录自启。

use crate::config::Paths;
use crate::ipc::{self, AGENT_PIPE, CallError};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const RUN_VALUE: &str = "AI Anchor";
const DETACHED_PROCESS: u32 = 0x0000_0008;
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;

/// 与 anchor.exe 同目录的组件。
pub fn sibling(name: &str) -> Result<PathBuf> {
    let p = std::env::current_exe()?.parent().context("无法确定程序目录")?.join(name);
    if !p.is_file() {
        bail!("找不到 {}：它应当和 anchor.exe 放在同一目录", p.display());
    }
    Ok(p)
}

pub fn running() -> bool {
    ipc::is_running(AGENT_PIPE)
}

pub fn call(method: &str, params: Value) -> Result<Value, CallError> {
    ipc::call(AGENT_PIPE, method, params)
}

/// 登录自启和手动启动使用的命令行。
fn command_line(exe: &std::path::Path, home: &std::path::Path) -> String {
    format!("\"{}\" --home \"{}\"", exe.display(), home.display().to_string().trim_end_matches('\\'))
}

pub fn start(paths: &Paths) -> Result<()> {
    if running() {
        println!("anchor-agent 已在运行。");
        return Ok(());
    }
    let exe = sibling("anchor-agent.exe")?;
    let spawn = |flags: u32| {
        Command::new(&exe)
            .arg("--home")
            .arg(&paths.home)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(flags)
            .spawn()
    };
    // 脱离当前终端的作业对象，关掉终端后用户代理继续运行
    spawn(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB)
        .or_else(|_| spawn(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP))
        .with_context(|| format!("无法启动 {}", exe.display()))?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if running() {
            println!("anchor-agent 已启动（日志 {}）。", paths.agent_log().display());
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    bail!("anchor-agent 10 秒内没有就绪，查看日志：{}", paths.agent_log().display())
}

pub fn stop() -> Result<()> {
    match call("stop", Value::Null) {
        Err(CallError::NotRunning) => {
            println!("anchor-agent 没有运行。");
            return Ok(());
        }
        Err(e) => bail!("通知 anchor-agent 退出失败：{e}"),
        Ok(_) => {}
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if !running() {
            println!("anchor-agent 已退出，内核随之停止。守卫规则仍然有效：AI 程序此时没有网络，不会直连。");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    bail!("anchor-agent 10 秒内没有退出")
}

pub fn reload() -> Result<()> {
    call("reload", Value::Null).map_err(|e| anyhow::anyhow!("anchor-agent {e}"))?;
    println!("已通知 anchor-agent 重新读取配置，内核会按新配置重启。");
    Ok(())
}

/// 记录一条事件到时间线（用户代理没运行时忽略）。
pub fn record(kind: &str, detail: Value) {
    let _ = call("event", json!({ "kind": kind, "detail": detail }));
}

pub fn autostart_entry() -> Option<String> {
    winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER).open_subkey(RUN_KEY).ok()?.get_value(RUN_VALUE).ok()
}

pub fn install(paths: &Paths) -> Result<()> {
    let exe = sibling("anchor-agent.exe")?;
    let (key, _) = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER).create_subkey(RUN_KEY)?;
    let line = command_line(&exe, &paths.home);
    key.set_value(RUN_VALUE, &line)?;
    println!("已设置登录后自动启动：HKCU\\{RUN_KEY}\\{RUN_VALUE}");
    println!("  {line}");
    start(paths)
}

pub fn uninstall() -> Result<()> {
    let key = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER).open_subkey_with_flags(RUN_KEY, winreg::enums::KEY_SET_VALUE)?;
    match key.delete_value(RUN_VALUE) {
        Ok(()) => println!("已取消登录后自动启动。"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => println!("没有设置登录后自动启动。"),
        Err(e) => return Err(e.into()),
    }
    stop()
}

pub fn print_status(paths: &Paths) -> Result<()> {
    let auto = autostart_entry();
    match call("status", Value::Null) {
        Ok(v) => {
            let st = &v["status"];
            println!("anchor-agent {} 运行中（pid {}）：{}", v["version"].as_str().unwrap_or("?"), v["pid"], v["summary"].as_str().unwrap_or(""));
            println!("  内核      {}{}", kernel_state(st["kernel"].as_str().unwrap_or("")), match st["kernel_pid"].as_u64() {
                Some(p) => format!("（pid {p}，意外退出 {} 次）", st["kernel_restarts"]),
                None => String::new(),
            });
            if let Some(e) = st["kernel_error"].as_str() {
                println!("            {e}");
            }
            if let Some(e) = st["config_error"].as_str() {
                println!("  配置      有误：{e}");
            }
            println!("  时间线    {}", v["timeline"].as_str().unwrap_or(""));
            println!("  托盘      {}", if v["tray"].as_bool().unwrap_or(false) { "显示" } else { "不显示（--no-tray）" });
        }
        Err(CallError::NotRunning) => println!("anchor-agent 没有运行（anchor agent start）。"),
        Err(e) => println!("anchor-agent 状态未知：{e}"),
    }
    match auto {
        Some(line) => println!("  登录自启  已设置：{line}"),
        None => println!("  登录自启  未设置（anchor agent install）"),
    }
    let _ = paths;
    Ok(())
}

pub fn kernel_state(s: &str) -> &'static str {
    match s {
        "running" => "运行中",
        "starting" => "启动中",
        "restarting" => "重启中",
        "stopped" => "已停止",
        "error" => "无法启动",
        _ => "未知",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_line_quotes_paths_and_drops_trailing_backslash() {
        let l = command_line(std::path::Path::new(r"C:\Program Files\AI Anchor\anchor-agent.exe"), std::path::Path::new(r"D:\a b\AIAnchor\"));
        assert_eq!(l, r#""C:\Program Files\AI Anchor\anchor-agent.exe" --home "D:\a b\AIAnchor""#);
    }
}
