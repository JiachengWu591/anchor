//! 管理特权服务 anchor-svc，以及经它维护守卫规则。

use crate::agentctl::sibling;
use crate::config::Paths;
use crate::ipc::{self, CallError, SVC_PIPE};
use crate::util::confirm;
use crate::win;
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::path::Path;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};
use windows_sys::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

pub fn running() -> bool {
    ipc::is_running(SVC_PIPE)
}

pub fn call(method: &str, params: Value) -> Result<Value, CallError> {
    ipc::call(SVC_PIPE, method, params)
}

fn quote_arg(s: &str) -> String {
    format!("\"{}\"", s.trim_end_matches('\\'))
}

/// 以管理员身份运行 anchor-svc.exe（弹出 UAC 确认），等待结束并返回退出码。
fn run_elevated(exe: &Path, params: &str) -> Result<u32> {
    let verb = win::wide("runas");
    let file = win::wide(&exe.to_string_lossy());
    let params = win::wide(params);
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = params.as_ptr();
    info.nShow = SW_SHOWNORMAL;
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        bail!("没有以管理员身份运行（UAC 被取消？）：{}", std::io::Error::last_os_error());
    }
    if info.hProcess.is_null() {
        bail!("无法等待提权进程结束");
    }
    let mut code = 0u32;
    unsafe {
        WaitForSingleObject(info.hProcess, INFINITE);
        GetExitCodeProcess(info.hProcess, &mut code);
        CloseHandle(info.hProcess);
    }
    Ok(code)
}

pub fn install(paths: &Paths) -> Result<()> {
    let exe = sibling("anchor-svc.exe")?;
    let sid = win::current_user_sid()?;
    let home = paths.home.to_string_lossy().to_string();
    if win::is_elevated() {
        let st = std::process::Command::new(&exe).args(["install", "--user-sid", &sid, "--home", &home]).status()?;
        if !st.success() {
            bail!("anchor-svc install 失败");
        }
        return Ok(());
    }
    println!("安装服务需要管理员权限，将弹出确认窗口…");
    let params = format!("install --user-sid {sid} --home {} --pause", quote_arg(&home));
    let code = run_elevated(&exe, &params)?;
    if code != 0 {
        bail!("anchor-svc install 失败（退出码 {code}），原因见提权窗口里的输出");
    }
    if running() {
        println!("特权服务已安装并运行。");
        print_status(false)?;
    }
    Ok(())
}

pub fn uninstall() -> Result<()> {
    let exe = sibling("anchor-svc.exe")?;
    if win::is_elevated() {
        let st = std::process::Command::new(&exe).arg("uninstall").status()?;
        if !st.success() {
            bail!("anchor-svc uninstall 失败");
        }
        return Ok(());
    }
    println!("卸载服务需要管理员权限，将弹出确认窗口…");
    let code = run_elevated(&exe, "uninstall --pause")?;
    if code != 0 {
        bail!("anchor-svc uninstall 失败（退出码 {code}）");
    }
    println!("特权服务已卸载。守卫规则保持不变。");
    Ok(())
}

/// 启动 AI 程序前请服务刷新一次守卫（应用刚更新、服务还没轮询到时补上新版本）。
pub fn refresh_before_launch(label: &str) {
    match call("guard.refresh", json!({ "source": format!("启动 {label} 前") })) {
        Ok(v) => {
            let added = v["added"].as_array().map(Vec::len).unwrap_or(0);
            if added > 0 {
                println!("守卫已补上 {added} 个新程序路径（应用可能刚更新过）。");
            }
        }
        Err(CallError::NotRunning) => {}
        Err(e) => eprintln!("警告：请特权服务刷新守卫失败：{e}"),
    }
}

/// 经服务写入守卫：补上缺的规则，删掉配置之外和已失效的规则。
pub fn guard_install() -> Result<()> {
    let v = call("guard.refresh", json!({ "prune": true, "source": "anchor guard install" })).map_err(svc_err)?;
    print_refresh(&v);
    print_status(false)
}

pub fn guard_pause(minutes: u64, yes: bool) -> Result<()> {
    if !yes
        && !confirm(&format!("暂停守卫 {minutes} 分钟：这段时间通道断开时 AI 程序可能直连，到时自动恢复。继续？[y/N] "))?
    {
        println!("未修改。");
        return Ok(());
    }
    let v = call("guard.pause", json!({ "minutes": minutes })).map_err(svc_err)?;
    println!("守卫已暂停，到 {} 自动恢复（提前恢复：anchor guard resume）。", v["paused_until"].as_str().unwrap_or("?"));
    Ok(())
}

pub fn guard_resume() -> Result<()> {
    call("guard.resume", Value::Null).map_err(svc_err)?;
    println!("守卫已恢复。");
    Ok(())
}

fn svc_err(e: CallError) -> anyhow::Error {
    anyhow::anyhow!("特权服务：{e}")
}

fn print_refresh(v: &Value) {
    let list = |k: &str| v[k].as_array().cloned().unwrap_or_default();
    let (added, removed) = (list("added"), list("removed"));
    if added.is_empty() && removed.is_empty() {
        println!("守卫规则已是最新，没有变化。");
    }
    for a in &added {
        println!("  + {}", a.as_str().unwrap_or(""));
    }
    for r in &removed {
        println!("  - {}", r.as_str().unwrap_or(""));
    }
    if v["dry_run"].as_bool().unwrap_or(false) {
        println!("（服务以演练模式运行，以上变化没有真正写入）");
    }
}

/// 打印服务看到的守卫状态。fresh 为 true 时先让服务刷新一次。
pub fn print_status(fresh: bool) -> Result<()> {
    let v = call("guard.status", json!({ "fresh": fresh })).map_err(svc_err)?;
    let rules = v["rules"].as_array().cloned().unwrap_or_default();
    let disabled = rules.iter().filter(|r| r["enabled"] == false).count();
    println!("特权服务 anchor-svc {} 运行中；守卫规则 {} 条（停用 {disabled} 条）", v["version"].as_str().unwrap_or("?"), rules.len());
    for r in &rules {
        let flag = if r["enabled"].as_bool().unwrap_or(false) { "启用" } else { "停用" };
        println!("  [{flag}] {}\n         {}", r["name"].as_str().unwrap_or(""), r["program"].as_str().unwrap_or(""));
    }
    if let Some(until) = v["paused_until"].as_str() {
        println!("守卫暂停中，到 {until} 自动恢复。");
    }
    let missing = v["missing"].as_array().cloned().unwrap_or_default();
    let expected = v["expected"].as_array().map(Vec::len).unwrap_or(0);
    if missing.is_empty() {
        println!("配置里的 {expected} 个程序都已受守卫。");
    } else {
        println!("未受守卫的程序（服务下次刷新时补上；立即刷新：anchor guard install）：");
        for t in &missing {
            println!("  - {}：{}", t["label"].as_str().unwrap_or(""), t["path"].as_str().unwrap_or(""));
        }
    }
    for s in v["skipped"].as_array().cloned().unwrap_or_default() {
        println!("跳过 {}：{}", s["label"].as_str().unwrap_or(""), s["why"].as_str().unwrap_or(""));
    }
    if let Some(e) = v["config_error"].as_str() {
        println!("注意：服务读取 anchor.toml 失败（有之前读到的有效配置就沿用，没有就不改任何规则）：{e}");
    }
    let last = &v["last_refresh"];
    if !last.is_null() {
        let state = if last["ok"].as_bool().unwrap_or(false) { "成功".to_string() } else { format!("失败：{}", last["error"].as_str().unwrap_or("")) };
        println!("上次刷新 {}（{}）{state}", last["time"].as_str().unwrap_or(""), last["source"].as_str().unwrap_or(""));
    }
    if v["dry_run"].as_bool().unwrap_or(false) {
        println!("服务以演练模式运行（console --dry-run），不会真正修改规则。");
    }
    Ok(())
}

pub fn print_service_status() -> Result<()> {
    match call("guard.status", Value::Null) {
        Ok(_) => print_status(false),
        Err(CallError::NotRunning) => {
            println!("特权服务没有运行。安装：anchor service install（会弹出管理员确认）");
            Ok(())
        }
        Err(e) => {
            println!("特权服务状态未知：{e}");
            Ok(())
        }
    }
    .context("读取服务状态失败")
}

#[cfg(test)]
mod tests {
    #[test]
    fn quote_arg_drops_trailing_backslash() {
        assert_eq!(super::quote_arg(r"C:\a b\"), r#""C:\a b""#);
    }
}
