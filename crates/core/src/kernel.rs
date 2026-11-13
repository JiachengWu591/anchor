//! 内核管理：生成配置、校验、以独立子进程运行 sing-box 并在意外退出后重启。
//! sing-box 是 GPL-3.0，只作为独立程序调用，不链接其代码。

use crate::config::{Config, Paths, host_port};
use crate::{net, singbox, win};
use anyhow::{Context, Result, bail};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::sleep;
use std::time::{Duration, Instant};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

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

/// 内核状态变化，由 supervise 回调报告。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelEvent {
    /// 启动；listening 表示 5 秒内开始监听 AI 端口
    Started { pid: u32, listening: bool },
    /// 意外退出，restart_in 之后重启
    Exited { pid: u32, code: Option<i32>, uptime: Duration, restart_in: Duration },
    /// 意外退出后重新开始监听；down 从第一次退出算起
    Recovered { pid: u32, code: Option<i32>, uptime: Duration, down: Duration },
    /// 收到停止信号，内核已停止
    Stopped,
}

/// 预检：找到 sing-box，写入并校验配置，确认 AI 端口空闲。返回 (sing-box 路径, 配置路径)。
pub fn prepare(cfg: &Config, paths: &Paths) -> Result<(PathBuf, PathBuf)> {
    let sb = find_singbox(cfg, paths)?;
    let json = write_config(cfg, paths)?;
    check_config(&sb, &json)?;
    if net::port_open(&cfg.proxy.listen, cfg.proxy.port) {
        bail!(
            "{} 已被占用：可能已经有 anchor-agent 或 anchor up 在运行，或被其他程序占用",
            host_port(&cfg.proxy.listen, cfg.proxy.port)
        );
    }
    Ok((sb, json))
}

pub struct Options {
    /// 后台运行：不弹控制台窗口，停止时直接结束进程
    pub background: bool,
}

/// 运行并守护内核，直到 stop 置位。意外退出后按 1、2、4…30 秒退避重启；稳定运行 60 秒后退避清零。
/// 内核放在“关闭即结束”的作业对象里：调用方进程被强制结束时，内核随之退出，不会占着端口。
pub fn supervise(
    cfg: &Config,
    paths: &Paths,
    sb: &Path,
    json: &Path,
    stop: &AtomicBool,
    opts: &Options,
    on: &mut dyn FnMut(KernelEvent),
) -> Result<()> {
    let job = win::KillOnClose::new().ok();
    let mut backoff = 1u64;
    // 第一次意外退出的时间、退出码和运行时长；恢复监听后清空
    let mut crashed: Option<(Instant, Option<i32>, Duration)> = None;
    loop {
        let started = Instant::now();
        let mut cmd = Command::new(sb);
        cmd.arg("run").arg("-c").arg(json).arg("-D").arg(paths.run_dir());
        if opts.background {
            cmd.creation_flags(CREATE_NO_WINDOW).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        }
        let mut child = cmd.spawn().with_context(|| format!("无法启动 {}", sb.display()))?;
        if let Some(j) = &job {
            let _ = j.assign(&child);
        }
        let pid = child.id();
        let _ = std::fs::write(paths.pid_file(), pid.to_string());

        let listening = wait_port(cfg, &mut child, Duration::from_secs(5));
        match crashed {
            Some((at, code, uptime)) if listening => {
                on(KernelEvent::Recovered { pid, code, uptime, down: at.elapsed() });
                crashed = None;
            }
            Some(_) => {}
            None => on(KernelEvent::Started { pid, listening }),
        }

        let status = loop {
            if let Some(st) = child.try_wait()? {
                break st;
            }
            if stop.load(Ordering::SeqCst) {
                if !opts.background {
                    // 同一控制台里 sing-box 也会收到 Ctrl+C，给它 3 秒自行退出。
                    let deadline = Instant::now() + Duration::from_secs(3);
                    while Instant::now() < deadline && child.try_wait()?.is_none() {
                        sleep(Duration::from_millis(100));
                    }
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
            on(KernelEvent::Stopped);
            return Ok(());
        }
        let uptime = started.elapsed();
        if uptime > Duration::from_secs(60) {
            backoff = 1;
        }
        let code = status.code();
        if crashed.is_none() {
            crashed = Some((Instant::now(), code, uptime));
        }
        on(KernelEvent::Exited { pid, code, uptime, restart_in: Duration::from_secs(backoff) });
        let until = Instant::now() + Duration::from_secs(backoff);
        while Instant::now() < until {
            if stop.load(Ordering::SeqCst) {
                let _ = std::fs::remove_file(paths.pid_file());
                on(KernelEvent::Stopped);
                return Ok(());
            }
            sleep(Duration::from_millis(100));
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
        sleep(Duration::from_millis(100));
    }
    false
}
