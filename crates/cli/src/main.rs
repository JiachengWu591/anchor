//! anchor：AI Anchor 命令行。
//! 让 AI 程序走固定出口；通道不可用时阻断，而不是直连。本机其他程序的网络不受影响。
//!
//! P1 起内核由用户代理 anchor-agent 常驻守护，守卫由特权服务 anchor-svc 自动维护；
//! 命令行查状态、看时间线、管理这两个后台进程。没有安装它们时，P0 的前台用法照常可用。

mod agentctl;
mod check;
mod launch;
mod sandbox;
mod svcctl;
mod timeline;

pub use anchor_core::{apps, config, guard, ipc, kernel, net, netenv, ps, rules, singbox, util, watch, win};

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use config::{Config, Paths, host_port};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[derive(Parser)]
#[command(name = "anchor", version, about = "AI Anchor：让 AI 程序走固定出口，通道不可用时阻断而不是直连")]
struct Cli {
    /// 数据目录，默认 %LOCALAPPDATA%\AIAnchor（也可用环境变量 ANCHOR_HOME）
    #[arg(long, global = true, value_name = "DIR")]
    home: Option<PathBuf>,
    /// 结束后等回车再关闭窗口（托盘菜单打开的窗口使用）
    #[arg(long, global = true, hide = true)]
    pause: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// 生成示例配置 anchor.toml
    Init {
        /// 覆盖已有配置
        #[arg(long)]
        force: bool,
    },
    /// 把 anchor.toml 翻译成 sing-box 配置并校验
    Gen {
        /// 只打印到标准输出，不写文件
        #[arg(long)]
        stdout: bool,
    },
    /// 用户代理（常驻后台：守护内核、看门狗、时间线、托盘）
    Agent {
        #[command(subcommand)]
        action: AgentCmd,
    },
    /// 特权服务（自动维护防火墙守卫规则）
    Service {
        #[command(subcommand)]
        action: SvcCmd,
    },
    /// 前台运行并守护内核（调试用；平时由 anchor-agent 常驻守护）
    Up,
    /// 查看后台进程、内核、线路、出口和守卫状态
    Status,
    /// 按时间顺序查看事件：内核重启、线路切换、守卫刷新……
    Timeline {
        /// 查看多久以内的，例如 1h、30m、7d
        #[arg(long, default_value = "24h")]
        since: humantime::Duration,
        /// 只看这些类型，例如 --kind line_switch --kind kernel_restart
        #[arg(long)]
        kind: Vec<String>,
        /// 列出探测明细而不是事件
        #[arg(long)]
        probes: bool,
        /// 最多显示多少条
        #[arg(long, default_value_t = 500)]
        limit: usize,
        /// 输出 JSON
        #[arg(long)]
        json: bool,
    },
    /// 一次性体检：本地网络、线路、出口、AI 服务、一致性、守卫
    Check {
        /// 输出 JSON
        #[arg(long)]
        json: bool,
    },
    /// 经通道测量出口，并登记为基线（expect.ip / timezone / country）
    Baseline {
        /// 不询问，直接写入
        #[arg(long)]
        yes: bool,
    },
    /// 扫描本机已安装的 AI 程序
    Scan,
    /// 防火墙守卫：保证 AI 程序只能经 AI 通道联网
    Guard {
        #[command(subcommand)]
        action: GuardCmd,
    },
    /// 注入代理环境变量运行命令行工具，例如：anchor run claude
    Run {
        /// 程序名或路径
        program: String,
        /// 传给程序的参数
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// 确认通道就绪后，带代理参数启动桌面客户端：claude-desktop / chatgpt-desktop / cursor
    Launch {
        app: String,
        #[arg(long, hide = true)]
        pause_on_error: bool,
    },
    /// 打开 AI 专用浏览器（独立配置目录，不影响日常浏览器）
    Browser {
        /// 要打开的网址，默认 [browser] start_url
        url: Option<String>,
        #[arg(long, hide = true)]
        pause_on_error: bool,
    },
    /// 创建“应用名 - AI Anchor”快捷方式（默认放在桌面）
    Shortcut {
        /// claude-desktop / chatgpt-desktop / cursor / browser
        target: String,
        /// 快捷方式所在目录
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// 输出 AI 域名规则集，供插件模式或其他代理软件使用
    Rules {
        /// singbox / mihomo / list
        #[arg(long, default_value = "singbox")]
        format: String,
    },
    /// 把被 MSIX 应用（如 Claude 桌面版）重定向到其私有目录的数据目录副本合并回原位置
    Repair,
}

#[derive(Subcommand)]
enum AgentCmd {
    /// 在后台启动
    Start,
    /// 退出（内核随之停止）
    Stop,
    /// 重新读取 anchor.toml，按新配置重启内核
    Reload,
    /// 查看状态
    Status,
    /// 设置登录后自动启动，并立即启动
    Install,
    /// 取消登录后自动启动，并退出
    Uninstall,
}

#[derive(Subcommand)]
enum SvcCmd {
    /// 安装并启动（弹出管理员确认）
    Install,
    /// 停止并删除（弹出管理员确认）；守卫规则保留
    Uninstall,
    /// 查看状态
    Status,
}

#[derive(Subcommand)]
enum GuardCmd {
    /// 预览将写入的规则和 PowerShell 脚本（不需要管理员）
    Plan,
    /// 写入守卫规则：装了特权服务时经服务刷新，否则需要管理员
    Install,
    /// 查看守卫规则和覆盖情况
    Status,
    /// 删除全部守卫规则（需要管理员；装了特权服务时先卸载服务）
    Remove {
        #[arg(long)]
        yes: bool,
    },
    /// 临时暂停守卫（需确认；装了特权服务时到时自动恢复）
    Pause {
        #[arg(long)]
        yes: bool,
        /// 暂停多少分钟（仅特权服务支持）
        #[arg(long, default_value_t = 10)]
        minutes: u64,
    },
    /// 恢复守卫
    Resume,
}

fn main() {
    let cli = Cli::parse();
    let pause = cli.pause;
    let code = match real_main(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("错误：{e:#}");
            1
        }
    };
    if pause {
        eprint!("\n按回车键关闭…");
        let _ = std::io::stdin().read_line(&mut String::new());
    }
    std::process::exit(code);
}

/// 在 MSIX 应用的终端里运行会出问题的命令：写数据目录、启动后台进程或 AI 程序、改登录自启。
fn unsafe_in_package(cmd: &Cmd) -> bool {
    matches!(
        cmd,
        Cmd::Init { .. }
            | Cmd::Gen { .. }
            | Cmd::Up
            | Cmd::Baseline { .. }
            | Cmd::Launch { .. }
            | Cmd::Browser { .. }
            | Cmd::Repair
            | Cmd::Agent { action: AgentCmd::Start | AgentCmd::Install | AgentCmd::Uninstall }
    )
}

fn real_main(cli: Cli) -> Result<i32> {
    let paths = Paths::resolve(cli.home)?;
    let pkg = if unsafe_in_package(&cli.cmd) || matches!(cli.cmd, Cmd::Check { .. }) { win::sandbox() } else { None };
    if !matches!(cli.cmd, Cmd::Rules { .. } | Cmd::Repair) {
        sandbox::warn_private_copies(&paths);
    }
    if let Some(p) = &pkg
        && unsafe_in_package(&cli.cmd)
    {
        return Err(sandbox::refuse(p));
    }
    match cli.cmd {
        Cmd::Init { force } => init(&paths, force)?,
        Cmd::Gen { stdout } => gen_config(&paths, stdout)?,
        Cmd::Agent { action } => match action {
            AgentCmd::Start => agentctl::start(&paths)?,
            AgentCmd::Stop => agentctl::stop()?,
            AgentCmd::Reload => agentctl::reload()?,
            AgentCmd::Status => agentctl::print_status(&paths)?,
            AgentCmd::Install => agentctl::install(&paths)?,
            AgentCmd::Uninstall => agentctl::uninstall()?,
        },
        Cmd::Service { action } => match action {
            SvcCmd::Install => svcctl::install(&paths)?,
            SvcCmd::Uninstall => svcctl::uninstall()?,
            SvcCmd::Status => svcctl::print_service_status()?,
        },
        Cmd::Up => up(&paths)?,
        Cmd::Status => status(&paths)?,
        Cmd::Timeline { since, kind, probes, limit, json } => {
            timeline::print(&paths, &timeline::Query { since: since.into(), kinds: kind, probes, limit, json })?
        }
        Cmd::Check { json } => {
            let cfg = Config::load(&paths)?;
            let report = check::run(&cfg);
            // 在 MSIX 应用里写的记录会进它的私有目录，不写
            let file = if pkg.is_none() { Some(check::save(&paths, &report)?) } else { None };
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                check::print(&report);
                match (&file, &pkg) {
                    (Some(f), _) => println!("记录已追加到 {}", f.display()),
                    (None, Some(p)) => println!("（在 {} 的终端里运行，这次体检不写入记录文件）", p.app()),
                    _ => {}
                }
            }
            return Ok(if report.healthy { 0 } else { 2 });
        }
        Cmd::Baseline { yes } => baseline(&paths, yes)?,
        Cmd::Scan => scan(&paths),
        Cmd::Guard { action } => guard_cmd(&paths, action)?,
        Cmd::Run { program, args } => return launch::run_cli(&Config::load(&paths)?, &program, &args),
        Cmd::Launch { app, pause_on_error } => {
            pause_if_err(pause_on_error, || launch::launch_desktop(&Config::load(&paths)?, &app))?
        }
        Cmd::Browser { url, pause_on_error } => {
            pause_if_err(pause_on_error, || launch::launch_browser(&Config::load(&paths)?, &paths, url.as_deref()))?
        }
        Cmd::Shortcut { target, dir } => launch::create_shortcut(&paths, &target, dir.as_deref())?,
        Cmd::Rules { format } => rules::print(&format)?,
        Cmd::Repair => sandbox::repair(&paths)?,
    }
    Ok(0)
}

fn guard_cmd(paths: &Paths, action: GuardCmd) -> Result<()> {
    let svc = svcctl::running();
    match action {
        GuardCmd::Plan => {
            let plan = guard::plan(&Config::load(paths)?)?;
            guard::print_plan(&plan);
            println!("\n--- anchor guard install 会以管理员身份执行以下 PowerShell ---\n{}", guard::install_script(&plan));
        }
        GuardCmd::Install if svc => svcctl::guard_install()?,
        GuardCmd::Install => guard::install(&Config::load(paths)?)?,
        GuardCmd::Status if svc => svcctl::print_status(true)?,
        GuardCmd::Status => {
            guard::print_status(&guard::status(&Config::load(paths)?)?);
            println!("（没有安装特权服务：应用更新后需重新运行 anchor guard install。安装：anchor service install）");
        }
        GuardCmd::Remove { .. } if svc => {
            bail!("特权服务在运行，删掉的规则会被它补回。先运行 anchor service uninstall，再删除规则")
        }
        GuardCmd::Remove { yes } => guard::remove(yes)?,
        GuardCmd::Pause { yes, minutes } if svc => svcctl::guard_pause(minutes, yes)?,
        GuardCmd::Pause { yes, .. } => guard::set_enabled(false, yes)?,
        GuardCmd::Resume if svc => svcctl::guard_resume()?,
        GuardCmd::Resume => guard::set_enabled(true, true)?,
    }
    Ok(())
}

/// 从快捷方式启动时，出错后停住窗口让用户看到原因。
fn pause_if_err(pause: bool, f: impl FnOnce() -> Result<()>) -> Result<()> {
    let r = f();
    if let (Err(e), true) = (&r, pause) {
        eprintln!("错误：{e:#}");
        eprint!("按回车键关闭…");
        let _ = std::io::stdin().read_line(&mut String::new());
        std::process::exit(1);
    }
    r
}

fn init(paths: &Paths, force: bool) -> Result<()> {
    let p = paths.config();
    if p.exists() && !force {
        bail!("配置已存在：{}（要覆盖请加 --force）", p.display());
    }
    std::fs::create_dir_all(&paths.home)?;
    std::fs::write(&p, config::example(&util::random_hex()))?;
    println!("已生成配置：{}", p.display());
    println!("下一步：");
    println!("  1. 编辑 [exit] 和 [[lines]]，换成你自己的出口和线路");
    println!("  2. 把 sing-box.exe（1.12 或更高）放到 {}", paths.bin_dir().display());
    println!("  3. anchor agent install：登录后自动启动用户代理（守护内核、托盘）");
    println!("  4. anchor baseline 登记出口");
    println!("  5. anchor service install：安装特权服务，自动维护守卫规则（弹出管理员确认）");
    Ok(())
}

fn gen_config(paths: &Paths, stdout: bool) -> Result<()> {
    let cfg = Config::load(paths)?;
    if stdout {
        println!("{}", serde_json::to_string_pretty(&singbox::generate(&cfg, paths)?)?);
        return Ok(());
    }
    let p = kernel::write_config(&cfg, paths)?;
    println!("已生成 sing-box 配置：{}", p.display());
    match kernel::find_singbox(&cfg, paths) {
        Ok(sb) => {
            kernel::check_config(&sb, &p)?;
            println!("sing-box check 通过（{}）", sb.display());
        }
        Err(e) => println!("跳过 sing-box check：{e:#}"),
    }
    if agentctl::running() {
        println!("anchor-agent 在运行：执行 anchor agent reload 让新配置生效。");
    }
    Ok(())
}

/// P0 的前台模式：守护内核并打印看门狗事件，Ctrl+C 停止。
fn up(paths: &Paths) -> Result<()> {
    if agentctl::running() {
        bail!("anchor-agent 正在运行，它已经在守护内核。要前台调试，先运行 anchor agent stop");
    }
    let cfg = Config::load(paths)?;
    let (sb, json) = kernel::prepare(&cfg, paths)?;
    let stop = Arc::new(AtomicBool::new(false));
    {
        let s = stop.clone();
        ctrlc::set_handler(move || s.store(true, Ordering::SeqCst))?;
    }
    let now = util::now_rfc3339;
    let watcher = watch::spawn(&cfg, stop.clone(), move |ev| match ev {
        watch::WatchEvent::Probe { .. } => {}
        watch::WatchEvent::Switched { from, to, ms } => {
            let ms = ms.map(|m| format!("，{m} ms")).unwrap_or_default();
            println!("[{}] 线路 {from} 探测失败，已切换到 {to}{ms}；出口 IP 不变", now());
        }
        watch::WatchEvent::LineDown { line } => eprintln!(
            "[{}] 线路 {line} 探测失败。手动模式不会自动切换；出口 IP 不变，新连接会失败，直到线路恢复或手动切换",
            now()
        ),
        watch::WatchEvent::AllDown { line } => eprintln!(
            "[{}] 所有线路都不可用（当前 {line} 探测失败）。出口 IP 不会因此改变；新连接会失败，直到有线路恢复",
            now()
        ),
        watch::WatchEvent::Recovered { line } => println!("[{}] 线路已恢复，当前 {line}", now()),
    });
    if let Some((every, _)) = &watcher {
        println!("线路看门狗：每 {} 探测当前线路，失败时立即重新选线。", humantime::format_duration(*every));
    }
    let listen = host_port(&cfg.proxy.listen, cfg.proxy.port);
    let log = paths.log_dir().join("sing-box.log");
    kernel::supervise(&cfg, paths, &sb, &json, &stop, &kernel::Options { background: false }, &mut |ev| match ev {
        kernel::KernelEvent::Started { pid, listening: true } => {
            println!("内核已启动（pid {pid}）：AI 代理端口 {listen}，日志 {}。按 Ctrl+C 停止。", log.display())
        }
        kernel::KernelEvent::Started { .. } => eprintln!("内核 5 秒内没有开始监听，查看日志：{}", log.display()),
        kernel::KernelEvent::Exited { code, restart_in, .. } => eprintln!(
            "内核意外退出（退出码 {}），{} 后重启。日志：{}",
            code.map(|c| c.to_string()).unwrap_or_else(|| "无".into()),
            humantime::format_duration(restart_in),
            log.display()
        ),
        kernel::KernelEvent::Recovered { pid, down, .. } => println!("内核已恢复（pid {pid}），中断 {} 毫秒", down.as_millis()),
        kernel::KernelEvent::Stopped => println!("内核已停止。守卫规则仍然有效：AI 程序此时没有网络，不会直连。"),
    })?;
    stop.store(true, Ordering::SeqCst);
    if let Some((_, h)) = watcher {
        let _ = h.join();
    }
    Ok(())
}

fn baseline(paths: &Paths, yes: bool) -> Result<()> {
    let cfg = Config::load(paths)?;
    if !net::port_open(&cfg.proxy.listen, cfg.proxy.port) {
        bail!("内核未运行：先启动 AI Anchor（anchor agent start）");
    }
    let agent = net::agent_via_proxy(&cfg, Duration::from_secs(10))?;
    let info = net::fetch_exit(&agent, &cfg.check)?;
    println!("经通道测得的出口：");
    println!("  IP    {}", info.ip);
    println!("  位置  {}", info.place());
    println!("  时区  {}", info.timezone.as_deref().unwrap_or("未知"));
    println!("  网络  {}", info.org.as_deref().unwrap_or("未知"));
    println!("  来源  {}", info.source);
    if !cfg.expect.ip.is_empty() && !net::same_ip(&cfg.expect.ip, &info.ip) {
        println!("注意：与已登记的基线 {} 不同。", cfg.expect.ip);
    }
    if !yes && !util::confirm("登记为固定出口基线？[y/N] ")? {
        println!("未修改。");
        return Ok(());
    }
    config::set_expect(paths, &info)?;
    println!("已写入 {}", paths.config().display());
    Ok(())
}

fn scan(paths: &Paths) {
    let cfg = Config::load(paths).ok();
    let enabled = |id: &str| {
        cfg.as_ref().is_some_and(|c| c.apps.desktop.iter().chain(c.apps.cli.iter()).any(|x| x == id))
    };
    let found = apps::scan();
    if found.is_empty() {
        println!("没有发现已知的 AI 程序。");
        return;
    }
    for f in &found {
        let kind = if f.kind == apps::Kind::Desktop { "桌面" } else { "命令行" };
        let guard = if f.guardable { "可守卫" } else { "不可守卫" };
        let on = if enabled(f.id) { "已纳入" } else { "未纳入" };
        println!("{}  [{kind} · {guard} · {on}]  名称 {}", f.label, f.id);
        println!("    程序  {}", f.exe.display());
        if f.launcher != f.exe {
            println!("    启动  {}", f.launcher.display());
        }
        if !f.note.is_empty() {
            println!("    说明  {}", f.note);
        }
    }
    if cfg.is_none() {
        println!("\n（还没有配置，“已纳入”按 anchor init 生成的默认配置为准）");
    }
}

/// 状态里不依赖配置的部分（后台进程、网络、特权服务）总是显示；配置读不了时只跳过出口和线路。
fn status(paths: &Paths) -> Result<()> {
    let cfg = Config::load(paths);
    let up = cfg.as_ref().is_ok_and(|c| net::port_open(&c.proxy.listen, c.proxy.port));

    if let Some(p) = win::sandbox() {
        println!("终端  运行在 MSIX 应用 {} 里：查看类命令可用，init、agent start 等写入类命令请在开始菜单打开的终端里运行", p.app());
    }
    if let Err(e) = &cfg {
        println!("配置  读取失败：{e:#}");
    }
    let agent = agentctl::call("status", Value::Null).ok();
    match &agent {
        Some(v) => {
            let st = &v["status"];
            let restarts = st["kernel_restarts"].as_u64().unwrap_or(0);
            let restarts = if restarts > 0 { format!("，意外退出 {restarts} 次") } else { String::new() };
            let listen = st["listen"].as_str().filter(|s| !s.is_empty()).map(|s| format!("，AI 代理端口 {s}")).unwrap_or_default();
            println!("后台  anchor-agent 运行中：{}", v["summary"].as_str().unwrap_or(""));
            println!(
                "内核  {}{listen}{}{restarts}",
                agentctl::kernel_state(st["kernel"].as_str().unwrap_or("")),
                st["kernel_pid"].as_u64().map(|p| format!("（pid {p}）")).unwrap_or_default()
            );
            // 配置错误上面已经单独显示过
            if let Some(e) = st["kernel_error"].as_str().or(st["config_error"].as_str().filter(|_| cfg.is_ok())) {
                println!("      {e}");
            }
        }
        None => {
            let auto = if agentctl::autostart_entry().is_some() { "已设置登录自启" } else { "未设置登录自启（anchor agent install）" };
            println!("后台  anchor-agent 没有运行（anchor agent start）；{auto}");
            let pid = std::fs::read_to_string(paths.pid_file()).unwrap_or_default();
            match &cfg {
                Ok(c) if up => println!(
                    "内核  运行中（前台 anchor up），AI 代理端口 {}{}",
                    host_port(&c.proxy.listen, c.proxy.port),
                    if pid.trim().is_empty() { String::new() } else { format!("（pid {}）", pid.trim()) }
                ),
                Ok(_) => println!("内核  未运行"),
                Err(_) => println!("内核  未运行（没有可用配置）"),
            }
        }
    }

    match netenv::default_route() {
        Some(d) if d.is_tunnel() => {
            let state = if d.up { "已连接" } else { "未连接" };
            println!("网络  经 VPN / 隧道 {}，{state}；线路和出口的流量都走它", d.describe());
        }
        Some(d) => println!("网络  直连，默认网卡 {}", d.describe()),
        None => println!("网络  没有默认路由"),
    }

    match &cfg {
        Ok(c) => status_routes(c, up),
        Err(_) => println!("出口  未知（没有可用配置；anchor init 生成，或 anchor repair 找回）"),
    }

    match svcctl::call("guard.status", Value::Null) {
        Ok(v) => {
            let rules = v["rules"].as_array().cloned().unwrap_or_default();
            let disabled = rules.iter().filter(|r| r["enabled"] == false).count();
            let missing = v["missing"].as_array().map(Vec::len).unwrap_or(0);
            let missing = if missing > 0 { format!("，{missing} 个未覆盖") } else { String::new() };
            let paused = v["paused_until"].as_str().map(|u| format!("，暂停到 {u}")).unwrap_or_default();
            let cfg_err = if v["config_error"].is_string() { "；服务读不到配置，规则保持不变" } else { "" };
            println!("守卫  特权服务维护中：{} 条规则（停用 {disabled}）{missing}{paused}{cfg_err}；详情 anchor guard status", rules.len());
        }
        Err(ipc::CallError::NotRunning) => match cfg.as_ref().map_err(|e| anyhow::anyhow!("{e:#}")).and_then(guard::status) {
            Ok(st) => {
                let missing = if st.missing.is_empty() { String::new() } else { format!("，{} 个未覆盖", st.missing.len()) };
                println!("守卫  {} 条规则（停用 {}）{missing}；没有特权服务，应用更新后需手动 anchor guard install", st.rules.len(), st.disabled());
            }
            Err(e) => println!("守卫  没有特权服务；无法读取守卫状态：{e:#}"),
        },
        Err(e) => println!("守卫  特权服务状态未知：{e}"),
    }
    if agent.is_some() {
        println!("时间线  anchor timeline");
    }
    Ok(())
}

/// 出口和线路（需要配置）。
fn status_routes(cfg: &Config, up: bool) {
    println!("出口  {}；基线 IP {}", cfg.exit.label(), if cfg.expect.ip.is_empty() { "未登记" } else { &cfg.expect.ip });
    if !cfg.backup_exits.is_empty() {
        println!("      备用出口 {} 个（P1b 起支持确认后切换）", cfg.backup_exits.len());
    }

    if cfg.lines.is_empty() {
        println!("线路  未配置，直接连接出口");
    } else {
        let mode = match cfg.switch.lines {
            config::LineMode::Auto => "自动切换",
            config::LineMode::Manual => "手动",
        };
        let api = net::ClashApi::new(&cfg);
        let current = if up { api.current_line() } else { None };
        println!("线路  {} 条，{mode}；当前 {}", cfg.lines.len(), current.as_deref().unwrap_or("未知"));
        for l in &cfg.lines {
            let name = l.name.as_deref().unwrap_or_default();
            let last = if up {
                api.get(&format!("/proxies/{name}"))
                    .ok()
                    .and_then(|v| v["history"].as_array().and_then(|h| h.last()).and_then(|x| x["delay"].as_u64()))
                    .map(|d| format!("最近探测 {d} ms"))
                    .unwrap_or_else(|| "暂无探测".into())
            } else {
                String::new()
            };
            println!("      - {}  {last}", l.label());
        }
    }
}
