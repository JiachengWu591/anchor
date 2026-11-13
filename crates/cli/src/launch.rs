//! 启动器：先确认通道就绪（内核在运行、出口 IP 与基线一致），再带代理参数启动 AI 程序。

use crate::apps::{self, Kind};
use crate::config::{Config, Paths};
use crate::{guard, net, ps};
use anyhow::{Context, Result, bail};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const NO_PROXY: &str = "localhost,127.0.0.1,::1";
const DETACHED_PROCESS: u32 = 0x0000_0008;
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

/// 启动前检查。不通过就不启动，返回原因。
pub fn readiness(cfg: &Config) -> Result<String> {
    if !net::port_open(&cfg.proxy.listen, cfg.proxy.port) {
        bail!("内核未运行（{} 没有监听）：先启动 AI Anchor（anchor agent start）", cfg.proxy_url());
    }
    if cfg.expect.ip.trim().is_empty() {
        bail!("还没有登记出口基线：先运行 anchor baseline");
    }
    let agent = net::agent_via_proxy(cfg, Duration::from_secs(10))?;
    let info = net::fetch_exit(&agent, &cfg.check)
        .context("经通道访问 IP 回显服务失败，线路或出口可能不可用；运行 anchor check 查看是哪一段")?;
    if !net::same_ip(&info.ip, &cfg.expect.ip) {
        bail!(
            "出口 IP 与基线不一致（基线 {}，实际 {}），已拒绝启动。确认出口确实更换后，运行 anchor baseline 重新登记。",
            cfg.expect.ip,
            info.ip
        );
    }
    Ok(info.ip)
}

/// anchor run：注入 HTTPS_PROXY / HTTP_PROXY 运行命令行工具，返回其退出码。
pub fn run_cli(cfg: &Config, program: &str, args: &[String]) -> Result<i32> {
    let path = resolve_program(program)?;
    let ip = readiness(cfg)?;
    let proxy = cfg.proxy_url();
    eprintln!("[anchor] 通道就绪，出口 {ip}；经 {proxy} 运行 {}", path.display());
    // 交互式工具自己处理 Ctrl+C（例如中断当前回答），anchor 不能先退出。
    let _ = ctrlc::set_handler(|| {});
    let status = Command::new(&path)
        .args(args)
        .env("HTTPS_PROXY", &proxy)
        .env("HTTP_PROXY", &proxy)
        .env("NO_PROXY", NO_PROXY)
        .env("NODE_USE_ENV_PROXY", "1")
        .status()
        .with_context(|| format!("无法启动 {}", path.display()))?;
    Ok(status.code().unwrap_or(1))
}

fn resolve_program(program: &str) -> Result<PathBuf> {
    if program.contains(['\\', '/']) {
        let p = PathBuf::from(program);
        if p.is_file() {
            return Ok(p);
        }
        bail!("找不到程序：{program}");
    }
    let found = apps::which_all(program);
    found
        .iter()
        .find(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("exe")))
        .or_else(|| found.first())
        .cloned()
        .with_context(|| format!("在 PATH 里找不到 {program}"))
}

/// Chromium / Electron 通用的代理参数。
pub fn chromium_proxy_args(cfg: &Config) -> Vec<String> {
    vec![format!("--proxy-server={}", cfg.proxy_url()), "--disable-quic".into()]
}

pub fn launch_desktop(cfg: &Config, id: &str) -> Result<()> {
    let found = apps::scan();
    let app = found
        .iter()
        .find(|f| f.id == id && f.kind == Kind::Desktop)
        .with_context(|| format!("没有找到桌面客户端 {id}。可选：claude-desktop、chatgpt-desktop、cursor（运行 anchor scan 查看本机已安装的）"))?;
    // Electron 应用是单实例的：已经在运行时，新参数会被丢弃，程序继续用旧实例的网络设置。
    if apps::running(&app.exe) {
        bail!("{} 已在运行。请先完全退出它（包括系统托盘图标），再用 anchor launch 启动，否则代理参数不会生效。", app.label);
    }
    let ip = readiness(cfg)?;
    // 应用可能刚更新：先请特权服务刷新一次守卫，再检查覆盖情况
    crate::svcctl::refresh_before_launch(app.label);
    match guard::status(cfg) {
        Ok(st) if !st.covers(&app.exe) => {
            eprintln!("警告：{} 没有守卫规则，通道断开时它可能直连。运行 anchor guard install 可补上。", app.label)
        }
        Err(e) => eprintln!("警告：无法读取守卫状态：{e:#}"),
        _ => {}
    }
    Command::new(&app.launcher)
        .args(chromium_proxy_args(cfg))
        .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
        .spawn()
        .with_context(|| format!("无法启动 {}", app.launcher.display()))?;
    crate::agentctl::record("app_launch", serde_json::json!({ "app": id, "exe": app.exe }));
    println!("已启动 {}：经 {} 联网，出口 {ip}。", app.label, cfg.proxy_url());
    Ok(())
}

pub fn browser_exe(cfg: &Config) -> Result<PathBuf> {
    if !cfg.browser.path.trim().is_empty() {
        let p = PathBuf::from(cfg.browser.path.trim());
        if p.is_file() {
            return Ok(p);
        }
        bail!("[browser] path 不存在：{}", p.display());
    }
    let env = |k: &str| std::env::var_os(k).map(PathBuf::from);
    let (rel, name): (&[&str], &str) = match cfg.browser.engine.as_str() {
        "chrome" => (&["Google", "Chrome", "Application"], "chrome.exe"),
        _ => (&["Microsoft", "Edge", "Application"], "msedge.exe"),
    };
    ["ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"]
        .iter()
        .filter_map(|k| env(k))
        .map(|base| rel.iter().fold(base, |p, s| p.join(s)).join(name))
        .find(|p| p.is_file())
        .with_context(|| format!("找不到 {name}：安装它，或在 [browser] path 里指定路径"))
}

/// AI 专用浏览器参数：独立配置目录（独立实例，不影响日常浏览器）、固定代理、
/// 禁 QUIC、WebRTC 不走代理外的 UDP、界面和 Accept-Language 与出口一致。
pub fn browser_args(cfg: &Config, paths: &Paths, url: &str) -> Vec<String> {
    let mut args = vec![format!("--user-data-dir={}", paths.browser_profile(&cfg.browser.profile).display())];
    args.extend(chromium_proxy_args(cfg));
    args.extend([
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp".to_string(),
        format!("--lang={}", cfg.expect.language),
        "--no-first-run".into(),
        "--no-default-browser-check".into(),
        url.to_string(),
    ]);
    args
}

pub fn launch_browser(cfg: &Config, paths: &Paths, url: Option<&str>) -> Result<()> {
    let exe = browser_exe(cfg)?;
    let ip = readiness(cfg)?;
    std::fs::create_dir_all(paths.browser_profile(&cfg.browser.profile))?;
    let url = url.unwrap_or(&cfg.browser.start_url);
    Command::new(&exe)
        .args(browser_args(cfg, paths, url))
        .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
        .spawn()
        .with_context(|| format!("无法启动 {}", exe.display()))?;
    crate::agentctl::record("app_launch", serde_json::json!({ "app": "browser", "exe": exe }));
    println!("已打开 AI 专用浏览器（{}），出口 {ip}，配置目录 {}。", exe.display(), paths.browser_profile(&cfg.browser.profile).display());
    Ok(())
}

/// 创建“应用名 - AI Anchor”快捷方式，指向 anchor launch / anchor browser。
pub fn create_shortcut(paths: &Paths, target: &str, dir: Option<&Path>) -> Result<()> {
    let (label, args, icon) = if target == "browser" {
        let cfg = Config::load(paths)?;
        ("AI 专用浏览器".to_string(), "browser --pause-on-error".to_string(), browser_exe(&cfg)?)
    } else {
        let f = apps::scan()
            .into_iter()
            .find(|f| f.id == target && f.kind == Kind::Desktop)
            .with_context(|| format!("没有找到 {target}。可选：claude-desktop、chatgpt-desktop、cursor、browser"))?;
        (f.label.to_string(), format!("launch {target} --pause-on-error"), f.exe)
    };
    let me = std::env::current_exe()?;
    // 结尾的反斜杠会把右引号转义掉，先去掉。
    let home = paths.home.display().to_string();
    let arguments = format!("--home \"{}\" {args}", home.trim_end_matches('\\'));
    let dir_expr = match dir {
        Some(d) => ps::quote(&d.to_string_lossy()),
        None => "[Environment]::GetFolderPath('Desktop')".to_string(),
    };
    let script = format!(
        "$ErrorActionPreference = 'Stop'\n\
         $p = Join-Path ({dir_expr}) {name}\n\
         $s = (New-Object -ComObject WScript.Shell).CreateShortcut($p)\n\
         $s.TargetPath = {target}\n\
         $s.Arguments = {arguments}\n\
         $s.WorkingDirectory = {home}\n\
         $s.IconLocation = {icon}\n\
         $s.Description = {desc}\n\
         $s.Save()\n\
         $p",
        name = ps::quote(&format!("{label} - AI Anchor.lnk")),
        target = ps::quote(&me.to_string_lossy()),
        arguments = ps::quote(&arguments),
        home = ps::quote(&paths.home.to_string_lossy()),
        icon = ps::quote(&format!("{},0", icon.display())),
        desc = ps::quote("先确认 AI 通道就绪，再带代理参数启动"),
    );
    let out = ps::run_ok(&script)?;
    println!("已创建快捷方式：{}", out.trim());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_args_isolate_profile_and_force_proxy() {
        let cfg = Config::parse("[exit]\ntype = \"socks\"\n[expect]\nlanguage = \"ja-JP\"\n").unwrap();
        let paths = Paths { home: r"C:\anchor".into() };
        let a = browser_args(&cfg, &paths, "https://claude.ai");
        assert_eq!(a[0], r"--user-data-dir=C:\anchor\browser\ai-anchor");
        assert!(a.contains(&"--proxy-server=http://127.0.0.1:17890".to_string()));
        assert!(a.contains(&"--disable-quic".to_string()));
        assert!(a.contains(&"--force-webrtc-ip-handling-policy=disable_non_proxied_udp".to_string()));
        assert!(a.contains(&"--lang=ja-JP".to_string()));
        assert_eq!(a.last().unwrap(), "https://claude.ai");
    }
}
