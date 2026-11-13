//! AI Anchor P0 原型（命令行版）。
//! 让 AI 程序走固定出口；通道不可用时阻断，而不是直连。本机其他程序的网络不受影响。

mod apps;
mod check;
mod config;
mod guard;
mod kernel;
mod launch;
mod net;
mod netenv;
mod ps;
mod rules;
mod singbox;
mod util;
mod watch;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use config::{Config, Paths, host_port};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "anchor", version, about = "AI Anchor P0 原型：让 AI 程序走固定出口，通道不可用时阻断而不是直连")]
struct Cli {
    /// 数据目录，默认 %LOCALAPPDATA%\AIAnchor（也可用环境变量 ANCHOR_HOME）
    #[arg(long, global = true, value_name = "DIR")]
    home: Option<PathBuf>,
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
    /// 启动并守护代理内核（前台运行，Ctrl+C 停止）
    Up,
    /// 查看内核、线路、出口和守卫状态
    Status,
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
}

#[derive(Subcommand)]
enum GuardCmd {
    /// 预览将写入的规则和 PowerShell 脚本（不需要管理员）
    Plan,
    /// 写入守卫规则（需要管理员）
    Install,
    /// 查看守卫规则和覆盖情况
    Status,
    /// 删除全部守卫规则（需要管理员）
    Remove {
        #[arg(long)]
        yes: bool,
    },
    /// 临时暂停守卫（需要管理员，需确认）
    Pause {
        #[arg(long)]
        yes: bool,
    },
    /// 恢复守卫（需要管理员）
    Resume,
}

fn main() {
    let cli = Cli::parse();
    match real_main(cli) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("错误：{e:#}");
            std::process::exit(1);
        }
    }
}

fn real_main(cli: Cli) -> Result<i32> {
    let paths = Paths::resolve(cli.home)?;
    match cli.cmd {
        Cmd::Init { force } => init(&paths, force)?,
        Cmd::Gen { stdout } => gen_config(&paths, stdout)?,
        Cmd::Up => kernel::up(&Config::load(&paths)?, &paths)?,
        Cmd::Status => status(&paths)?,
        Cmd::Check { json } => {
            let cfg = Config::load(&paths)?;
            let report = check::run(&cfg);
            let file = check::save(&paths, &report)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                check::print(&report);
                println!("记录已追加到 {}", file.display());
            }
            return Ok(if report.healthy { 0 } else { 2 });
        }
        Cmd::Baseline { yes } => baseline(&paths, yes)?,
        Cmd::Scan => scan(&paths),
        Cmd::Guard { action } => {
            let cfg = Config::load(&paths)?;
            match action {
                GuardCmd::Plan => {
                    let plan = guard::plan(&cfg)?;
                    guard::print_plan(&plan);
                    println!("\n--- anchor guard install 会以管理员身份执行以下 PowerShell ---\n{}", guard::install_script(&plan));
                }
                GuardCmd::Install => guard::install(&cfg)?,
                GuardCmd::Status => guard::print_status(&guard::status(&cfg)?),
                GuardCmd::Remove { yes } => guard::remove(yes)?,
                GuardCmd::Pause { yes } => guard::set_enabled(false, yes)?,
                GuardCmd::Resume => guard::set_enabled(true, true)?,
            }
        }
        Cmd::Run { program, args } => return launch::run_cli(&Config::load(&paths)?, &program, &args),
        Cmd::Launch { app, pause_on_error } => {
            pause_if_err(pause_on_error, || launch::launch_desktop(&Config::load(&paths)?, &app))?
        }
        Cmd::Browser { url, pause_on_error } => {
            pause_if_err(pause_on_error, || launch::launch_browser(&Config::load(&paths)?, &paths, url.as_deref()))?
        }
        Cmd::Shortcut { target, dir } => launch::create_shortcut(&paths, &target, dir.as_deref())?,
        Cmd::Rules { format } => rules::print(&format)?,
    }
    Ok(0)
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
    println!("  3. anchor up 启动内核；另开一个终端运行 anchor baseline 登记出口");
    println!("  4. 管理员终端运行 anchor guard install 写入守卫规则");
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
    Ok(())
}

fn baseline(paths: &Paths, yes: bool) -> Result<()> {
    let cfg = Config::load(paths)?;
    if !net::port_open(&cfg.proxy.listen, cfg.proxy.port) {
        bail!("内核未运行：先在另一个终端运行 anchor up");
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

fn status(paths: &Paths) -> Result<()> {
    let cfg = Config::load(paths)?;
    let listen = host_port(&cfg.proxy.listen, cfg.proxy.port);
    let up = net::port_open(&cfg.proxy.listen, cfg.proxy.port);
    let pid = std::fs::read_to_string(paths.pid_file()).unwrap_or_default();
    if up {
        println!("内核  运行中，AI 代理端口 {listen}{}", if pid.trim().is_empty() { String::new() } else { format!("（pid {}）", pid.trim()) });
    } else {
        println!("内核  未运行（anchor up）");
    }

    match netenv::default_route() {
        Some(d) if d.is_tunnel() => {
            let state = if d.up { "已连接" } else { "未连接" };
            println!("网络  经 VPN / 隧道 {}，{state}；线路和出口的流量都走它", d.describe());
        }
        Some(d) => println!("网络  直连，默认网卡 {}", d.describe()),
        None => println!("网络  没有默认路由"),
    }

    println!("出口  {}；基线 IP {}", cfg.exit.label(), if cfg.expect.ip.is_empty() { "未登记" } else { &cfg.expect.ip });
    if !cfg.backup_exits.is_empty() {
        println!("      备用出口 {} 个（P1 起支持确认后切换）", cfg.backup_exits.len());
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

    match guard::status(&cfg) {
        Ok(st) => {
            let missing = if st.missing.is_empty() { String::new() } else { format!("，{} 个未覆盖", st.missing.len()) };
            println!("守卫  {} 条规则（停用 {}）{missing}；详情 anchor guard status", st.rules.len(), st.disabled());
        }
        Err(e) => println!("守卫  无法读取：{e:#}"),
    }
    Ok(())
}
