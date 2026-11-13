//! 内核管理：生成配置、校验、以独立子进程运行 sing-box 并在意外退出后重启。
//! sing-box 是 GPL-3.0，只作为独立程序调用，不链接其代码。

use crate::config::{Config, Paths, host_port};
use crate::{net, singbox};
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::sleep;
use std::time::{Duration, Instant};

pub fn find_singbox(cfg: &Config, paths: &Paths) -> Result<PathBuf> {
    if !cfg.core.path.trim().is_empty() {
        let p = PathBuf::from(cfg.core.path.trim());
        if p.is_file() {
            return Ok(p);
        }
        bail!("[core] path 指向的 sing-box 不存在：{}", p.display());
    }
    let mut candidates = vec![paths.bin_dir().join("sing-box.exe")];
    if let Some(dir) = std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf)) {
        candidates.push(dir.join("sing-box.exe"));
    }
    if let Some(path) = std::env::var_os("PATH") {
        candidates.extend(std::env::split_paths(&path).map(|d| d.join("sing-box.exe")));
    }
    candidates.into_iter().find(|p| p.is_file()).with_context(|| {
        format!(
            "找不到 sing-box.exe。请从 https://github.com/SagerNet/sing-box/releases 下载 Windows 版（1.12 或更高），\
             解压后把 sing-box.exe 放到 {}，或在 anchor.toml 的 [core] path 里指定。",
            paths.bin_dir().display()
        )
    })
}

pub fn write_config(cfg: &Config, paths: &Paths) -> Result<PathBuf> {
    std::fs::create_dir_all(paths.run_dir())?;
    std::fs::create_dir_all(paths.log_dir())?;
    let v = singbox::generate(cfg, paths)?;
    let p = paths.singbox_json();
    std::fs::write(&p, serde_json::to_string_pretty(&v)?)?;
    Ok(p)
}

pub fn check_config(sb: &Path, json: &Path) -> Result<()> {
    let out = Command::new(sb)
        .arg("check")
        .arg("-c")
        .arg(json)
        .output()
        .with_context(|| format!("无法运行 {}", sb.display()))?;
    if !out.status.success() {
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        bail!("sing-box check 未通过：{}", strip_ansi(&text).trim());
    }
    Ok(())
}

/// 去掉终端颜色控制序列（sing-box 的错误输出带颜色）。
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn strip_ansi_removes_color_codes() {
        assert_eq!(super::strip_ansi("\u{1b}[31mFATAL\u{1b}[0m[0000] x"), "FATAL[0000] x");
    }
}

/// 前台运行并守护内核；Ctrl+C 退出。P1 起改为 Windows 服务。
pub fn up(cfg: &Config, paths: &Paths) -> Result<()> {
    let sb = find_singbox(cfg, paths)?;
    let json = write_config(cfg, paths)?;
    check_config(&sb, &json)?;
    let listen = host_port(&cfg.proxy.listen, cfg.proxy.port);
    if net::port_open(&cfg.proxy.listen, cfg.proxy.port) {
        bail!("{listen} 已被占用：可能已经有一个 anchor up 在运行，或被其他程序占用");
    }

    let stop = Arc::new(AtomicBool::new(false));
    {
        let s = stop.clone();
        ctrlc::set_handler(move || s.store(true, Ordering::SeqCst)).context("无法注册 Ctrl+C 处理")?;
    }

    if let Some(every) = crate::watch::spawn(cfg, stop.clone()) {
        println!("线路看门狗：每 {} 探测当前线路，失败时立即重新选线。", humantime::format_duration(every));
    }

    let log = paths.log_dir().join("sing-box.log");
    let mut backoff = 1u64;
    loop {
        let started = Instant::now();
        let mut child = Command::new(&sb)
            .arg("run")
            .arg("-c")
            .arg(&json)
            .arg("-D")
            .arg(paths.run_dir())
            .spawn()
            .with_context(|| format!("无法启动 {}", sb.display()))?;
        let _ = std::fs::write(paths.pid_file(), child.id().to_string());

        if wait_port(cfg, &mut child, Duration::from_secs(5)) {
            println!("内核已启动（pid {}）：AI 代理端口 {listen}，日志 {}。按 Ctrl+C 停止。", child.id(), log.display());
        } else {
            eprintln!("内核 5 秒内没有开始监听，查看日志：{}", log.display());
        }

        let status = loop {
            if let Some(st) = child.try_wait()? {
                break st;
            }
            if stop.load(Ordering::SeqCst) {
                // 同一控制台里 sing-box 也会收到 Ctrl+C，给它 3 秒自行退出。
                let deadline = Instant::now() + Duration::from_secs(3);
                while Instant::now() < deadline && child.try_wait()?.is_none() {
                    sleep(Duration::from_millis(100));
                }
                if child.try_wait()?.is_none() {
                    let _ = child.kill();
                }
                break child.wait()?;
            }
            sleep(Duration::from_millis(200));
        };

        if stop.load(Ordering::SeqCst) {
            let _ = std::fs::remove_file(paths.pid_file());
            println!("内核已停止。守卫规则仍然有效：AI 程序此时没有网络，不会直连。");
            return Ok(());
        }
        if started.elapsed() > Duration::from_secs(60) {
            backoff = 1;
        }
        eprintln!("内核意外退出（{status}），{backoff} 秒后重启。日志：{}", log.display());
        let until = Instant::now() + Duration::from_secs(backoff);
        while Instant::now() < until {
            if stop.load(Ordering::SeqCst) {
                let _ = std::fs::remove_file(paths.pid_file());
                return Ok(());
            }
            sleep(Duration::from_millis(200));
        }
        backoff = (backoff * 2).min(30);
    }
}

fn wait_port(cfg: &Config, child: &mut Child, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if net::port_open(&cfg.proxy.listen, cfg.proxy.port) {
            return true;
        }
        if child.try_wait().ok().flatten().is_some() {
            return false;
        }
        sleep(Duration::from_millis(200));
    }
    false
}
