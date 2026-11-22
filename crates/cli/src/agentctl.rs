//! 管理用户代理 anchor-agent：启动、停止、重新加载、登录自启。

use crate::config::Paths;
use crate::ipc::{self, AGENT_PIPE, CallError};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// 当前数据目录的用户代理管道（main 里按 --home / ANCHOR_HOME 设定）。
static PIPE: OnceLock<String> = OnceLock::new();

pub fn init(paths: &Paths) {
    let _ = PIPE.set(ipc::agent_pipe(&paths.home));
}

fn pipe() -> &'static str {
    PIPE.get().map_or(AGENT_PIPE, String::as_str)
}

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
    ipc::is_running(pipe())
}

pub fn call(method: &str, params: Value) -> Result<Value, CallError> {
    ipc::call(pipe(), method, params)
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

/// anchor panel：请用户代理打开面板窗口；print 时只输出地址。面板的网页由用户代理提供。
pub fn panel(print: bool) -> Result<()> {
    let method = if print { "panel.url" } else { "panel.open" };
    let v = match call(method, Value::Null) {
        Ok(v) => v,
        Err(CallError::NotRunning) => bail!("anchor-agent 没有运行，先运行 anchor agent start"),
        Err(e) => bail!("打开面板失败：{e}（用户代理可能还是旧版本，重装并重启它）"),
    };
    match v["url"].as_str() {
        Some(url) if print => println!("{url}"),
        _ => println!("已打开面板。"),
    }
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
            if let Some(line) = exit_line(&st["exit"]) {
                println!("  {line}");
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

/// 出口锁定的一行说明（用户代理状态里的 exit）；还没开始核对时返回 None。
pub fn exit_line(e: &Value) -> Option<String> {
    let state = e["state"].as_str().filter(|s| !s.is_empty())?;
    let baseline = e["baseline"].as_str().unwrap_or("");
    let secs = e["locked_ms"].as_u64().map(|m| format!("，已锁住 {} 秒", m / 1000)).unwrap_or_default();
    Some(match state {
        "open" => format!("AI 通道  已放行：出口与基线 {baseline} 一致"),
        "changed" => format!(
            "AI 通道  已锁住：出口 IP 已变化（现在 {}，基线 {baseline}{secs}）。切回原出口会自动恢复；确认换成新 IP 运行 anchor baseline",
            e["actual"].as_str().unwrap_or("未知")
        ),
        "unverifiable" => format!("AI 通道  已锁住：出口能连通，但 IP 回显服务都连不上，无法核对{secs}"),
        "no_baseline" => "AI 通道  已锁住：还没有登记出口基线（anchor baseline）".to_string(),
        _ if e["exit_down"].as_bool().unwrap_or(false) => {
            // 迟迟连不上、用户代理已经判断出卡在哪一段时，一并说明
            let what = e["stuck"].as_str().map(|w| format!("（{}）", anchor_core::stall::Stuck::label(w))).unwrap_or_default();
            format!("AI 通道  已锁住：出口不可达{what}，恢复后核对一致再放行{secs}")
        }
        _ => format!("AI 通道  正在核对出口{secs}"),
    })
}

/// anchor exit check：请用户代理立即核对出口，等到有结果（最多 15 秒）。
pub fn exit_check() -> Result<()> {
    call("exit.recheck", Value::Null).map_err(|e| anyhow::anyhow!("anchor-agent {e}"))?;
    println!("已请求立即核对出口：AI 通道先锁住，与基线一致后放行。");
    let started = Instant::now();
    let mut saw_verifying = false;
    loop {
        std::thread::sleep(Duration::from_millis(250));
        let v = call("status", Value::Null).map_err(|e| anyhow::anyhow!("anchor-agent {e}"))?;
        let e = &v["status"]["exit"];
        let state = e["state"].as_str().unwrap_or("");
        saw_verifying |= state == "verifying";
        let settled = state != "verifying" && (saw_verifying || started.elapsed() > Duration::from_secs(3));
        if settled || started.elapsed() > Duration::from_secs(15) {
            if let Some(line) = exit_line(e) {
                println!("{line}");
            }
            return Ok(());
        }
    }
}

/// 用户代理报告 AI 通道被出口锁定（不含正在核对这种几秒内就会结束的情况）时返回原因。
pub fn exit_locked_reason() -> Option<String> {
    let v = call("status", Value::Null).ok()?;
    let e = &v["status"]["exit"];
    match e["state"].as_str()? {
        "changed" | "unverifiable" | "no_baseline" => exit_line(e).map(|l| l.trim_start_matches("AI 通道").trim().to_string()),
        _ if e["exit_down"].as_bool().unwrap_or(false) => exit_line(e).map(|l| l.trim_start_matches("AI 通道").trim().to_string()),
        _ => None,
    }
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
    fn exit_line_per_state() {
        use serde_json::json;
        assert_eq!(exit_line(&json!({})), None, "还没开始核对");
        assert!(exit_line(&json!({ "state": "open", "baseline": "198.51.100.7" })).unwrap().contains("已放行"));
        let changed = exit_line(&json!({ "state": "changed", "baseline": "1.1.1.1", "actual": "2.2.2.2", "locked_ms": 12500 })).unwrap();
        assert!(changed.contains("现在 2.2.2.2") && changed.contains("已锁住 12 秒") && changed.contains("anchor baseline"), "{changed}");
        assert!(exit_line(&json!({ "state": "verifying", "exit_down": true })).unwrap().contains("出口不可达"));
        // 迟迟连不上、已经判断出卡在哪一段
        let stuck = exit_line(&json!({ "state": "verifying", "exit_down": true, "stuck": "vpn_stuck", "locked_ms": 41000 })).unwrap();
        assert_eq!(stuck, "AI 通道  已锁住：出口不可达（VPN 卡住了），恢复后核对一致再放行，已锁住 41 秒");
    }

    #[test]
    fn command_line_quotes_paths_and_drops_trailing_backslash() {
        let l = command_line(std::path::Path::new(r"C:\Program Files\AI Anchor\anchor-agent.exe"), std::path::Path::new(r"D:\a b\AIAnchor\"));
        assert_eq!(l, r#""C:\Program Files\AI Anchor\anchor-agent.exe" --home "D:\a b\AIAnchor""#);
    }
}
