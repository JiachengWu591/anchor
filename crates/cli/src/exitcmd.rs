//! anchor exit list / use：看有哪些出口，手动切换出口（P1b“备用出口”）。
//!
//! 换出口就是换 AI 服务看到的 IP，所以只由用户发起，不会自动切换。每个出口有自己的基线：
//! 主出口的在 [expect]，备用出口的在它那一项的 expect 里，切过去后用 anchor baseline 登记。
//!
//! 切换前先关闭正在运行的 AI 程序（要确认）：同一个会话不能前半段一个 IP、后半段另一个 IP。
//! 桌面客户端和 AI 专用浏览器在切换后重新打开；命令行工具需要用户自己重新运行。

use crate::agentctl;
use crate::apps::{self, Kind};
use crate::config::{Config, ExitEntry, Paths};
use crate::util::pad;
use crate::{launch, ps, util};
use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub fn list(paths: &Paths) -> Result<()> {
    let cfg = Config::load(paths)?;
    println!("{}{}{}基线 IP", pad("", 8), pad("名称", 16), pad("出口", 44));
    for r in rows(&cfg.exits) {
        println!("{}{}{}{}", pad(&r[0], 8), pad(&r[1], 16), pad(&r[2], 44), r[3]);
    }
    if cfg.exits.len() > 1 {
        println!("\n切换：anchor exit use <名称>（会先关闭正在运行的 AI 程序）；登记现在所用出口的基线：anchor baseline");
    } else {
        println!("\n没有配置备用出口（anchor.toml 里的 [[backup_exits]]）。");
    }
    Ok(())
}

/// 标记、名称、出口、基线 IP。
pub fn rows(exits: &[ExitEntry]) -> Vec<[String; 4]> {
    exits
        .iter()
        .map(|e| {
            let mark = if e.active { "当前" } else { "" };
            let kind = if e.primary { "（主出口）" } else { "" };
            let ip = if e.baseline_ip.is_empty() { "未登记".to_string() } else { e.baseline_ip.clone() };
            [mark.to_string(), e.name.clone(), format!("{}{kind}", e.label), ip]
        })
        .collect()
}

/// 一个正在运行、切换出口前要关掉的 AI 程序。
struct Running {
    label: String,
    what: What,
}

enum What {
    /// 桌面客户端：切换后用 anchor launch 重新打开
    Desktop { id: &'static str, exe: PathBuf },
    /// 命令行工具：不重新打开
    Cli { exe: PathBuf },
    /// AI 专用浏览器（按配置目录认）
    Browser { profile: PathBuf },
}

fn running_ai(cfg: &Config, paths: &Paths) -> Vec<Running> {
    let mut out = Vec::new();
    for f in apps::scan() {
        let enabled = cfg.apps.desktop.iter().chain(cfg.apps.cli.iter()).any(|x| x == f.id);
        if !enabled || !apps::running(&f.exe) {
            continue;
        }
        let what = if f.kind == Kind::Desktop { What::Desktop { id: f.id, exe: f.exe.clone() } } else { What::Cli { exe: f.exe.clone() } };
        out.push(Running { label: f.label.to_string(), what });
    }
    let profile = paths.browser_profile(&cfg.browser.profile);
    if !browser_pids(&profile).is_empty() {
        out.push(Running { label: "AI 专用浏览器".into(), what: What::Browser { profile } });
    }
    out
}

/// 以这个配置目录运行的浏览器进程。
fn browser_pids(profile: &std::path::Path) -> Vec<u32> {
    let script = format!(
        "$p = {}\nGet-CimInstance Win32_Process | Where-Object {{ $_.CommandLine -and $_.CommandLine.Contains('--user-data-dir=' + $p) }} | ForEach-Object {{ $_.ProcessId }}",
        ps::quote(&profile.display().to_string())
    );
    ps::run_ok(&script).map(|t| t.lines().filter_map(|l| l.trim().parse().ok()).collect()).unwrap_or_default()
}

/// 先请程序自己关窗口，5 秒后还在的强制结束。
fn close(r: &Running) -> Result<()> {
    let select = match &r.what {
        What::Desktop { exe, .. } | What::Cli { exe } => {
            let stem = exe.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
            format!(
                "function Targets {{ Get-Process -Name {} -ErrorAction SilentlyContinue | Where-Object {{ $_.Path -eq {} }} }}",
                ps::quote(&stem),
                ps::quote(&exe.display().to_string())
            )
        }
        What::Browser { profile } => format!(
            "function Targets {{ $p = {}; Get-CimInstance Win32_Process | Where-Object {{ $_.CommandLine -and $_.CommandLine.Contains('--user-data-dir=' + $p) }} | ForEach-Object {{ Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue }} }}",
            ps::quote(&profile.display().to_string())
        ),
    };
    let script = format!(
        "{select}\n\
         Targets | ForEach-Object {{ [void]$_.CloseMainWindow() }}\n\
         $deadline = (Get-Date).AddSeconds(5)\n\
         while ((Get-Date) -lt $deadline -and @(Targets).Count -gt 0) {{ Start-Sleep -Milliseconds 250 }}\n\
         Targets | Stop-Process -Force -ErrorAction SilentlyContinue\n\
         Start-Sleep -Milliseconds 500\n\
         @(Targets).Count"
    );
    let left = ps::run_ok(&script)?;
    if left.trim() != "0" {
        bail!("{} 没能关掉（还剩 {} 个进程）。请手动完全退出它，再重新运行这条命令", r.label, left.trim());
    }
    Ok(())
}

pub fn use_exit(paths: &Paths, name: &str, yes: bool) -> Result<()> {
    let cfg = Config::load(paths)?;
    let Some(target) = cfg.exits.iter().find(|e| e.name == name) else {
        let names: Vec<&str> = cfg.exits.iter().map(|e| e.name.as_str()).collect();
        bail!("没有叫 {name} 的出口（有：{}）", names.join("、"));
    };
    if target.active {
        println!("已经在用出口 {name}。");
        return Ok(());
    }
    let from = cfg.exit_name();
    println!("出口 {from} → {name}：{}", target.label);
    println!("AI 服务看到的 IP 会改变{}。", if target.baseline_ip.is_empty() { "；这个出口还没有登记基线" } else { "" });

    let running = running_ai(&cfg, paths);
    if running.is_empty() {
        if !yes && !util::confirm("确认切换？[y/N] ")? {
            println!("未切换。");
            return Ok(());
        }
    } else {
        println!("切换前要先完全退出这些 AI 程序（同一个会话不能前后用两个出口 IP）：");
        for r in &running {
            let after = match r.what {
                What::Cli { .. } => "切换后需要你自己重新运行",
                _ => "切换后自动重新打开",
            };
            println!("  - {}（{after}）", r.label);
        }
        if !yes && !util::confirm("现在关闭它们并切换出口？没保存的内容可能丢失。[y/N] ")? {
            println!("未切换。");
            return Ok(());
        }
        for r in &running {
            close(r)?;
            println!("已关闭 {}", r.label);
        }
    }

    if target.primary {
        match std::fs::remove_file(paths.active_exit()) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e).context("记不下所选的出口"),
            _ => {}
        }
    } else {
        std::fs::write(paths.active_exit(), name).context("记不下所选的出口")?;
    }

    if !agentctl::running() {
        println!("已选用出口 {name}。用户代理没有运行，下次启动时生效（anchor agent start）。");
        return Ok(());
    }
    agentctl::reload()?;
    let open = wait_settled(name)?;
    let cfg = Config::load(paths)?;
    if cfg.expect.ip.trim().is_empty() {
        println!("出口 {name} 还没有登记基线，AI 通道保持锁住。确认它的 IP 是你要的之后运行：anchor baseline");
    }
    for r in &running {
        let again = match &r.what {
            What::Desktop { id, .. } if open => launch::launch_desktop(&cfg, id),
            What::Browser { .. } if open => launch::launch_browser(&cfg, paths, None),
            What::Desktop { id, .. } => {
                println!("AI 通道还没放行，没有重新打开 {}；放行后运行：anchor launch {id}", r.label);
                Ok(())
            }
            What::Browser { .. } => {
                println!("AI 通道还没放行，没有重新打开 AI 专用浏览器；放行后运行：anchor browser");
                Ok(())
            }
            What::Cli { .. } => {
                println!("{} 已关闭；需要时用 anchor run 重新运行。", r.label);
                Ok(())
            }
        };
        if let Err(e) = again {
            println!("没能重新打开 {}：{e:#}", r.label);
        }
    }
    Ok(())
}

/// 等用户代理按新出口重启内核并核对出口（最多 25 秒）。返回 AI 通道是否已经放行。
fn wait_settled(name: &str) -> Result<bool> {
    let started = Instant::now();
    loop {
        std::thread::sleep(Duration::from_millis(300));
        if let Ok(v) = agentctl::call("status", Value::Null) {
            let st = &v["status"];
            let exit = &st["exit"];
            let state = exit["state"].as_str().unwrap_or("");
            // 内核已经按新配置起来，出口核对也有了结论
            let ready = st["exit_name"].as_str() == Some(name) && st["kernel"].as_str() == Some("running") && state != "verifying" && !state.is_empty();
            if ready || started.elapsed() > Duration::from_secs(25) {
                if let Some(line) = agentctl::exit_line(exit) {
                    println!("{line}");
                }
                return Ok(ready && exit["locked"].as_bool() == Some(false));
            }
        } else if started.elapsed() > Duration::from_secs(25) {
            return Err(anyhow!("用户代理 25 秒内没有回应；用 anchor agent status 查看"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_rows() {
        let e = |name: &str, ip: &str, active, primary| ExitEntry { name: name.into(), label: format!("{name}（socks 203.0.113.1:1080）"), baseline_ip: ip.into(), active, primary };
        let r = rows(&[e("home", "203.0.113.10", false, true), e("b1", "", true, false)]);
        assert_eq!(r[0], ["", "home", "home（socks 203.0.113.1:1080）（主出口）", "203.0.113.10"].map(String::from));
        assert_eq!(r[1], ["当前", "b1", "b1（socks 203.0.113.1:1080）", "未登记"].map(String::from));
    }
}
