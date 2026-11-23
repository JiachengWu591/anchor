//! anchor upgrade：把新编译的程序换进安装目录，代替手工的四步
//! （anchor agent stop、复制两个程序、anchor agent start）。
//!
//! - 内容相同的文件不动。用户代理的程序没有变化时不重启它，AI 通道不中断。
//! - 新文件先复制到安装目录里（*.new），都复制完才停用户代理：停下的时间只有改名和启动那几秒。
//! - 旧文件改名留着（*.old）。新的用户代理没有启动成功，就换回旧文件并把旧的启动起来。
//! - 正在运行的程序可以改名，不能覆盖：所以用安装目录里的 anchor.exe 升级它自己也行，
//!   它的旧文件留到下次升级时再删。
//!
//! 特权服务默认不动：它装在 %ProgramFiles%，替换要管理员权限。加 --service 才一起更新，
//! 做法是以管理员身份运行新编译的 anchor-svc.exe upgrade（见 svcctl::upgrade_from），那边自己负责停、换、启动和换回。

use crate::agentctl;
use crate::config::Paths;
use crate::svcctl::{self, Installed};
use crate::util::{same_content, same_path};
use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, QueryFullProcessImageNameW,
    WaitForSingleObject,
};

const CLI: &str = "anchor.exe";
const AGENT: &str = "anchor-agent.exe";
const SVC: &str = "anchor-svc.exe";
/// 新编译的目录里必须有的。
const REQUIRED: [&str; 2] = [CLI, AGENT];
/// 有就一起带上的：安装目录里的这一份只是 anchor service install / upgrade 用的安装源。
const OPTIONAL: [&str; 1] = [SVC];

const STOP_WAIT: Duration = Duration::from_secs(15);
const START_WAIT: Duration = Duration::from_secs(15);

pub struct Args {
    /// 新编译的程序所在目录；不写就是本程序所在的目录
    pub dir: Option<PathBuf>,
    /// 安装目录；不写时按运行中的用户代理、登录自启的设置来找
    pub to: Option<PathBuf>,
    pub dry_run: bool,
    /// 特权服务也一起更新（弹出管理员确认）
    pub service: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Change {
    Same,
    Replace,
    Add,
}

#[derive(Debug)]
struct Item {
    name: &'static str,
    change: Change,
}

#[derive(Debug)]
struct Plan {
    from: PathBuf,
    to: PathBuf,
    items: Vec<Item>,
}

impl Plan {
    fn changed(&self) -> impl Iterator<Item = &Item> {
        self.items.iter().filter(|i| i.change != Change::Same)
    }

    fn changes(&self, name: &str) -> bool {
        self.changed().any(|i| i.name == name)
    }
}

fn with_suffix(dir: &Path, name: &str, suffix: &str) -> PathBuf {
    dir.join(format!("{name}{suffix}"))
}

/// 绝对路径，去掉末尾的反斜杠。
fn tidy(p: &Path) -> PathBuf {
    std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf()).components().collect()
}

/// 登录自启的那一行（"程序" --home "数据目录"）里的程序和数据目录。
fn parse_autostart(line: &str) -> Option<(PathBuf, PathBuf)> {
    let mut parts = line.split('"');
    let (_, exe, mid, home) = (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    (mid.trim() == "--home" && !exe.is_empty() && !home.is_empty()).then(|| (PathBuf::from(exe), PathBuf::from(home)))
}

/// 登录自启指向的安装目录。只认数据目录相同的那一条：用别的数据目录做测试时，不能找到正式的安装目录上去。
fn autostart_dir(paths: &Paths) -> Option<PathBuf> {
    let (exe, home) = parse_autostart(&agentctl::autostart_entry()?)?;
    same_path(&tidy(&home), &tidy(&paths.home)).then(|| exe.parent().map(Path::to_path_buf)).flatten()
}

/// 从哪里装到哪里。
/// - 写了目录：那是新程序，装到本程序所在的目录（用安装好的 anchor 升级自己）。
/// - 没写：本程序就是新编译的，装到用户代理所在的目录；用户代理没运行就看登录自启。
fn resolve(here: &Path, dir: Option<&Path>, to: Option<&Path>, agent_dir: Option<&Path>, autostart: Option<&Path>) -> Result<(PathBuf, PathBuf)> {
    let from = tidy(dir.unwrap_or(here));
    let to = match (to, dir) {
        (Some(t), _) => tidy(t),
        (None, Some(_)) => tidy(here),
        (None, None) => tidy(agent_dir.or(autostart).context(
            "找不到安装目录：用户代理没有运行，也没有设置登录自启。用 --to 写明安装目录，例如 anchor upgrade --to <安装目录>",
        )?),
    };
    if same_path(&from, &to) {
        bail!(
            "新程序和安装目录是同一个目录：{}\n\
             把新编译的目录写在后面：anchor upgrade <目录>；或者直接运行新编译出来的那个 anchor.exe upgrade",
            to.display()
        );
    }
    Ok((from, to))
}

fn plan(from: &Path, to: &Path) -> Result<Plan> {
    for name in REQUIRED {
        if !from.join(name).is_file() {
            bail!("{} 里没有 {name}：这不是编译好的程序目录（先运行 cargo build --release --workspace）", from.display());
        }
    }
    if !to.join(CLI).is_file() && !to.join(AGENT).is_file() {
        bail!("{} 里没有 anchor.exe，也没有 anchor-agent.exe：这不像是安装目录。第一次安装请手工复制", to.display());
    }
    let mut items = Vec::new();
    for name in REQUIRED.into_iter().chain(OPTIONAL) {
        let (src, dst) = (from.join(name), to.join(name));
        if !src.is_file() {
            continue;
        }
        let change = if !dst.exists() {
            Change::Add
        } else if same_content(&src, &dst).with_context(|| format!("比较 {name} 失败"))? {
            Change::Same
        } else {
            Change::Replace
        };
        items.push(Item { name, change });
    }
    Ok(Plan { from: from.to_path_buf(), to: to.to_path_buf(), items })
}

/// 删掉上次升级留下的 *.old 和没用上的 *.new。删不掉的（还在运行）留着。
fn clear_leftovers(to: &Path) {
    for name in REQUIRED.into_iter().chain(OPTIONAL) {
        for suffix in [".old", ".new"] {
            let _ = std::fs::remove_file(with_suffix(to, name, suffix));
        }
    }
}

fn remove_staged(plan: &Plan) {
    for i in plan.changed() {
        let _ = std::fs::remove_file(with_suffix(&plan.to, i.name, ".new"));
    }
}

/// 把要换的文件复制到安装目录里，名字后面加 .new。这一步不影响正在运行的程序；出错时不留下东西。
fn stage(plan: &Plan) -> Result<()> {
    for i in plan.changed() {
        let (src, tmp) = (plan.from.join(i.name), with_suffix(&plan.to, i.name, ".new"));
        let copied = std::fs::copy(&src, &tmp)
            .with_context(|| format!("复制 {} 到 {} 失败", src.display(), tmp.display()))
            .and_then(|n| {
                let want = std::fs::metadata(&src)?.len();
                if n != want { bail!("{} 只复制了 {n} 字节，应为 {want} 字节", i.name) } else { Ok(()) }
            });
        if let Err(e) = copied {
            remove_staged(plan);
            return Err(e);
        }
    }
    Ok(())
}

/// 换上新文件：旧的改名为 .old，.new 改成正式名字。中途出错就把已经换的换回去。
fn swap(plan: &Plan) -> Result<()> {
    let mut done: Vec<&Item> = Vec::new();
    for i in plan.changed() {
        let (cur, old, new) = (plan.to.join(i.name), with_suffix(&plan.to, i.name, ".old"), with_suffix(&plan.to, i.name, ".new"));
        let r = (|| -> Result<()> {
            if i.change == Change::Replace {
                std::fs::rename(&cur, &old).with_context(|| format!("给旧的 {} 改名失败（有别的程序占着它？）", i.name))?;
            }
            std::fs::rename(&new, &cur).with_context(|| format!("换上新的 {} 失败", i.name)).inspect_err(|_| {
                if i.change == Change::Replace {
                    let _ = std::fs::rename(&old, &cur);
                }
            })
        })();
        if let Err(e) = r {
            undo(&plan.to, &done);
            remove_staged(plan);
            return Err(e);
        }
        done.push(i);
    }
    Ok(())
}

/// 把换上的文件换回去。新文件先改名让开（正在运行的程序也能改名），再把 .old 改回来。
fn undo(to: &Path, done: &[&Item]) {
    for i in done {
        let (cur, old, new) = (to.join(i.name), with_suffix(to, i.name, ".old"), with_suffix(to, i.name, ".new"));
        if std::fs::rename(&cur, &new).is_ok() && i.change == Change::Replace {
            let _ = std::fs::rename(&old, &cur);
        }
        let _ = std::fs::remove_file(&new);
    }
}

/// 删掉旧文件。还在运行的删不掉（用安装目录里的 anchor.exe 升级它自己时），返回这些文件的名字。
fn remove_old(plan: &Plan) -> Vec<&'static str> {
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut left: Vec<&'static str> = plan.changed().filter(|i| i.change == Change::Replace).map(|i| i.name).collect();
    loop {
        left.retain(|name| {
            let old = with_suffix(&plan.to, name, ".old");
            std::fs::remove_file(&old).is_err() && old.exists()
        });
        // 刚退出的用户代理，程序文件要过一小会儿才放开
        if left.is_empty() || Instant::now() >= deadline {
            return left;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// 正在运行的用户代理（本数据目录的那一个）。
struct Agent {
    pid: u32,
    /// 它的程序所在目录；查不到时为 None
    dir: Option<PathBuf>,
    /// 它有没有显示托盘图标：重启时照原样
    tray: bool,
}

fn running_agent() -> Option<Agent> {
    let v = agentctl::call("status", Value::Null).ok()?;
    let pid = u32::try_from(v["pid"].as_u64()?).ok()?;
    let dir = process_path(pid).and_then(|p| p.parent().map(Path::to_path_buf));
    Some(Agent { pid, dir, tray: v["tray"].as_bool().unwrap_or(true) })
}

/// 进程的程序文件路径。进程不存在或无权查询时返回 None。
fn process_path(pid: u32) -> Option<PathBuf> {
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return None;
    }
    let mut buf = vec![0u16; 32768];
    let mut len = buf.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len) };
    unsafe { CloseHandle(h) };
    (ok != 0).then(|| PathBuf::from(String::from_utf16_lossy(&buf[..len as usize])))
}

/// 等一个进程退出；到时间还在运行返回 false。进程已经不存在（打不开）也算退出。
fn wait_exit(pid: u32, timeout: Duration) -> bool {
    let h = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
    if h.is_null() {
        return true;
    }
    let r = unsafe { WaitForSingleObject(h, u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX - 1)) };
    unsafe { CloseHandle(h) };
    r == WAIT_OBJECT_0
}

/// 请用户代理退出，等到进程真的结束（内核随它停止、程序文件放开）。
fn stop_agent(agent: &Agent) -> Result<()> {
    agentctl::call("stop", Value::Null).map_err(|e| anyhow::anyhow!("通知用户代理退出失败：{e}"))?;
    let deadline = Instant::now() + STOP_WAIT;
    while agentctl::running() {
        if Instant::now() >= deadline {
            bail!("用户代理 {} 秒内没有退出", STOP_WAIT.as_secs());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    if !wait_exit(agent.pid, deadline.saturating_duration_since(Instant::now()).max(Duration::from_secs(2))) {
        bail!("用户代理（pid {}）{} 秒内没有结束", agent.pid, STOP_WAIT.as_secs());
    }
    Ok(())
}

/// 启动用户代理并等它就绪。没有就绪（进程自己退出了，或者到时间还没有响应）就结束它并返回错误。
fn start_agent(exe: &Path, home: &Path, no_tray: bool) -> Result<u32> {
    let mut child = agentctl::spawn_agent(exe, home, no_tray)?;
    let deadline = Instant::now() + START_WAIT;
    loop {
        if agentctl::running() {
            return Ok(child.id());
        }
        if let Ok(Some(status)) = child.try_wait() {
            bail!("用户代理刚启动就退出了（退出码 {}）", status.code().map_or("未知".to_string(), |c| c.to_string()));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("用户代理 {} 秒内没有就绪", START_WAIT.as_secs());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// 文件的修改时间（复制时保留，所以就是编译时间），如 11-22 06:43。
fn built(p: &Path) -> String {
    let ms = std::fs::metadata(p)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64);
    match ms {
        // 2026-11-22 06:43:08 → 11-22 06:43
        Some(ms) => anchor_core::timeline::local_time(ms).get(5..16).unwrap_or("?").to_string(),
        None => "?".into(),
    }
}

fn describe(plan: &Plan, i: &Item) -> String {
    let name = crate::util::pad(i.name, 18);
    match i.change {
        Change::Same => format!("  {name}没有变化"),
        Change::Add => format!("  {name}新增（编译于 {}）", built(&plan.from.join(i.name))),
        Change::Replace => format!("  {name}更新（编译于 {} → {}）", built(&plan.to.join(i.name)), built(&plan.from.join(i.name))),
    }
}

/// 特权服务和新编译的不是同一个文件时提一句。每次编译出来的文件都会不同，所以这不等于必须更新。
fn service_note(svc: Option<Installed>, installed: &Path) -> Option<String> {
    (svc == Some(Installed::Differs)).then(|| {
        format!(
            "特权服务没有动，还是之前安装的那一份（编译于 {}）。守卫规则、程序扫描或配置格式有改动时才需要更新它：anchor service upgrade，或者升级时加 --service（会弹出管理员确认）",
            built(installed)
        )
    })
}

/// 加了 --service 时，文件清单里特权服务的那一行。
fn describe_service(svc: Installed, new: &Path, installed: &Path) -> String {
    let name = crate::util::pad("特权服务", 18);
    match svc {
        Installed::Missing => format!("  {name}没有安装，跳过"),
        Installed::Same => format!("  {name}没有变化"),
        Installed::Differs => format!("  {name}更新（编译于 {} → {}），要管理员确认", built(installed), built(new)),
    }
}

/// 启动后等出口核对有结果（最多 10 秒），返回那一行状态。
fn exit_state_line() -> Option<String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let v = agentctl::call("status", Value::Null).ok()?;
        let e = &v["status"]["exit"];
        let settled = !matches!(e["state"].as_str().unwrap_or(""), "" | "verifying");
        if settled || Instant::now() >= deadline {
            return agentctl::exit_line(e);
        }
        std::thread::sleep(Duration::from_millis(300));
    }
}

pub fn run(paths: &Paths, args: &Args) -> Result<()> {
    let me = std::env::current_exe()?;
    let here = me.parent().context("无法确定程序目录")?;
    let agent = running_agent();
    let agent_dir = agent.as_ref().and_then(|a| a.dir.clone());
    let (from, to) = resolve(here, args.dir.as_deref(), args.to.as_deref(), agent_dir.as_deref(), autostart_dir(paths).as_deref())?;
    let plan = plan(&from, &to)?;
    let (svc_new, installed) = (plan.from.join(SVC), svcctl::installed_exe());
    let svc = if svc_new.is_file() { Some(svcctl::compare(&svc_new, &installed)?) } else { None };
    if args.service && svc.is_none() {
        bail!(
            "{} 里没有 anchor-svc.exe，更新不了特权服务。去掉 --service，或者先编译整个工作区（cargo build --release --workspace）",
            plan.from.display()
        );
    }

    println!("升级 AI Anchor");
    println!("  新程序  {}", plan.from.display());
    println!("  安装到  {}", plan.to.display());
    for i in &plan.items {
        println!("{}", describe(&plan, i));
    }
    if args.service
        && let Some(s) = svc
    {
        println!("{}", describe_service(s, &svc_new, &installed));
    }
    let note = if args.service { None } else { service_note(svc, &installed) };
    let files = plan.changed().next().is_some();
    let do_svc = args.service && svc == Some(Installed::Differs);

    if !files && !do_svc {
        println!("已经是这个版本，没有改动。");
        if let Some(n) = note {
            println!("{n}");
        }
        return Ok(());
    }
    if files {
        upgrade_files(paths, &plan, agent.as_ref(), args.dry_run)?;
    }
    if args.dry_run {
        if do_svc {
            println!("会更新特权服务：弹出管理员确认，服务停几秒后用新程序启动。防火墙守卫规则不动，AI 通道不受影响。");
        }
        if let Some(n) = note {
            println!("{n}");
        }
        println!("（预览，没有做任何改动。去掉 --dry-run 执行）");
        return Ok(());
    }
    if do_svc {
        // 用新编译的那一份去换：比较时用的就是它
        svcctl::upgrade_from(&svc_new)
            .map_err(|e| if files { e.context("anchor.exe 和 anchor-agent.exe 已经升级好了，只有特权服务没换") } else { e })?;
    }
    println!("升级完成。");
    if let Some(n) = note {
        println!("{n}");
    }
    Ok(())
}

/// 换程序文件，需要时重启用户代理。预览时只说会做什么。
fn upgrade_files(paths: &Paths, plan: &Plan, agent: Option<&Agent>, dry_run: bool) -> Result<()> {
    // 用户代理的程序没变就不重启它；它没在运行就只换文件
    let restart = agent.filter(|_| plan.changes(AGENT));
    if let Some(a) = restart
        && let Some(d) = &a.dir
        && !same_path(&tidy(d), &plan.to)
    {
        bail!(
            "这个数据目录的用户代理运行在 {}，不在要升级的目录里。没有做任何改动。先确认安装目录，或者用 --to 写明",
            d.display()
        );
    }
    let plain = match (agent, restart.is_some()) {
        (_, true) => "会重启用户代理：AI 通道中断几秒，核对出口后放行。",
        (Some(_), false) => "用户代理的程序没有变化，不重启它，AI 通道不受影响。",
        (None, _) => "用户代理没有运行，只换文件，不启动它。",
    };
    if dry_run {
        println!("{plain}");
        return Ok(());
    }

    clear_leftovers(&plan.to);
    stage(plan)?;
    let down_since = Instant::now();
    if let Some(a) = restart {
        println!("停止用户代理…");
        if let Err(e) = stop_agent(a) {
            remove_staged(plan);
            return Err(e.context("没有换文件，安装目录和原来一样"));
        }
    }
    let agent_exe = plan.to.join(AGENT);
    let no_tray = restart.is_some_and(|a| !a.tray);
    if let Err(e) = swap(plan) {
        // 文件已经换回去了；刚才停掉的用户代理要重新启动
        let back = restart.map(|_| start_agent(&agent_exe, &paths.home, no_tray));
        return Err(e.context(match back {
            Some(Err(_)) => "换文件失败，已换回原来的文件，但原来的用户代理没有启动起来：运行 anchor agent start",
            Some(Ok(_)) => "换文件失败，已换回原来的文件，并重新启动了原来的用户代理",
            None => "换文件失败，已换回原来的文件",
        }));
    }
    if restart.is_some() {
        println!("启动新的用户代理…");
        match start_agent(&agent_exe, &paths.home, no_tray) {
            Ok(pid) => println!("用户代理已启动（pid {pid}），中间停了 {:.1} 秒。", down_since.elapsed().as_secs_f32()),
            Err(e) => {
                let done: Vec<&Item> = plan.changed().collect();
                undo(&plan.to, &done);
                let back = start_agent(&agent_exe, &paths.home, no_tray);
                return Err(e.context(match back {
                    Ok(_) => "新的用户代理没有启动成功。已换回原来的文件，并重新启动了原来的用户代理",
                    Err(_) => "新的用户代理没有启动成功。已换回原来的文件，但原来的用户代理也没有启动起来：运行 anchor agent start，日志在数据目录的 logs\\agent.log",
                }));
            }
        }
    } else {
        println!("{plain}");
    }

    let left = remove_old(plan);
    if !left.is_empty() {
        // 只会是正在运行的本程序
        println!("旧的 {} 还在运行，暂时留作 .old，下次升级时删除。", left.join("、"));
    }
    if restart.is_some()
        && let Some(line) = exit_state_line()
    {
        println!("{line}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::fs::OpenOptionsExt;

    struct Dirs {
        root: PathBuf,
        from: PathBuf,
        to: PathBuf,
    }

    impl Dirs {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("anchor-upgrade-{}", crate::util::random_hex()));
            let (from, to) = (root.join("build"), root.join("inst"));
            std::fs::create_dir_all(&from).unwrap();
            std::fs::create_dir_all(&to).unwrap();
            Self { root, from, to }
        }

        fn put(&self, dir: &Path, name: &str, text: &str) {
            std::fs::write(dir.join(name), text).unwrap();
        }

        fn read(&self, name: &str) -> String {
            std::fs::read_to_string(self.to.join(name)).unwrap_or_else(|_| "<没有>".into())
        }

        fn names(&self) -> Vec<String> {
            let mut v: Vec<String> = std::fs::read_dir(&self.to).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
            v.sort();
            v
        }
    }

    impl Drop for Dirs {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn changes(p: &Plan) -> Vec<(&'static str, Change)> {
        p.items.iter().map(|i| (i.name, i.change)).collect()
    }

    #[test]
    fn where_from_and_where_to() {
        let (here, build, inst, auto) = (Path::new(r"C:\here"), Path::new(r"D:\build"), Path::new(r"C:\inst"), Path::new(r"C:\auto"));
        let r = |dir, to, agent, autostart| resolve(here, dir, to, agent, autostart).map_err(|e| e.to_string());
        // 运行新编译的程序：装到用户代理所在的目录；它没运行就看登录自启
        assert_eq!(r(None, None, Some(inst), Some(auto)), Ok((here.into(), inst.into())));
        assert_eq!(r(None, None, None, Some(auto)), Ok((here.into(), auto.into())));
        assert!(r(None, None, None, None).unwrap_err().contains("--to"));
        // 写了目录：那是新程序，装到本程序所在的目录，不去猜
        assert_eq!(r(Some(build), None, Some(inst), Some(auto)), Ok((build.into(), here.into())));
        // --to 最优先
        assert_eq!(r(None, Some(inst), Some(auto), None), Ok((here.into(), inst.into())));
        assert_eq!(r(Some(build), Some(inst), None, None), Ok((build.into(), inst.into())));
        // 同一个目录：不分大小写，不管末尾有没有反斜杠
        assert!(r(None, None, Some(Path::new(r"c:\HERE\")), None).unwrap_err().contains("同一个目录"));
        assert!(r(Some(here), None, None, None).unwrap_err().contains("同一个目录"));
    }

    #[test]
    fn autostart_line() {
        let (exe, home) = parse_autostart(r#""C:\Program Files\AI Anchor\anchor-agent.exe" --home "D:\a b\AIAnchor""#).unwrap();
        assert_eq!((exe, home), (PathBuf::from(r"C:\Program Files\AI Anchor\anchor-agent.exe"), PathBuf::from(r"D:\a b\AIAnchor")));
        assert_eq!(parse_autostart(r"C:\x\anchor-agent.exe --home D:\h"), None, "不是本程序写的格式就不认");
        assert_eq!(parse_autostart(r#""C:\x\other.exe" --flag "y""#), None);
        assert_eq!(parse_autostart(""), None);
    }

    #[test]
    fn plan_compares_content_and_checks_both_directories() {
        let d = Dirs::new();
        assert!(plan(&d.from, &d.to).unwrap_err().to_string().contains("没有 anchor.exe"), "新程序目录是空的");
        d.put(&d.from, CLI, "cli 2");
        d.put(&d.from, AGENT, "agent 1");
        assert!(plan(&d.from, &d.to).unwrap_err().to_string().contains("不像是安装目录"));

        d.put(&d.to, CLI, "cli 1");
        d.put(&d.to, AGENT, "agent 1");
        let p = plan(&d.from, &d.to).unwrap();
        assert_eq!(changes(&p), [(CLI, Change::Replace), (AGENT, Change::Same)], "新程序目录里没有服务程序就不列");
        assert!(p.changes(CLI) && !p.changes(AGENT));

        // 长度相同、内容不同也算变了；服务程序安装目录里没有就是新增
        d.put(&d.from, AGENT, "agent 2");
        d.put(&d.from, SVC, "svc 1");
        assert_eq!(changes(&plan(&d.from, &d.to).unwrap()), [(CLI, Change::Replace), (AGENT, Change::Replace), (SVC, Change::Add)]);
    }

    #[test]
    fn stage_swap_and_remove_old() {
        let d = Dirs::new();
        d.put(&d.from, CLI, "cli 2");
        d.put(&d.from, AGENT, "agent 1");
        d.put(&d.from, SVC, "svc 2");
        d.put(&d.to, CLI, "cli 1");
        d.put(&d.to, AGENT, "agent 1");
        d.put(&d.to, "anchor.exe.old", "上次升级留下的");
        d.put(&d.to, "sing-box.exe", "别的文件不碰");
        let p = plan(&d.from, &d.to).unwrap();

        clear_leftovers(&d.to);
        stage(&p).unwrap();
        assert_eq!(d.names(), ["anchor-agent.exe", "anchor-svc.exe.new", "anchor.exe", "anchor.exe.new", "sing-box.exe"]);
        assert_eq!(d.read(CLI), "cli 1", "复制完之前不动正在用的文件");

        swap(&p).unwrap();
        assert_eq!((d.read(CLI), d.read(AGENT), d.read(SVC)), ("cli 2".into(), "agent 1".into(), "svc 2".into()));
        assert_eq!(d.read("anchor.exe.old"), "cli 1", "旧文件先留着");

        // 换回去：新增的删掉，替换的恢复
        let done: Vec<&Item> = p.changed().collect();
        undo(&d.to, &done);
        assert_eq!(d.names(), ["anchor-agent.exe", "anchor.exe", "sing-box.exe"]);
        assert_eq!(d.read(CLI), "cli 1");

        // 再来一遍，这次删掉旧文件
        stage(&p).unwrap();
        swap(&p).unwrap();
        assert_eq!(remove_old(&p), Vec::<&str>::new());
        assert_eq!(d.names(), ["anchor-agent.exe", "anchor-svc.exe", "anchor.exe", "sing-box.exe"]);
        assert_eq!(changes(&plan(&d.from, &d.to).unwrap()), [(CLI, Change::Same), (AGENT, Change::Same), (SVC, Change::Same)]);
    }

    #[test]
    fn a_file_that_cannot_be_renamed_puts_everything_back() {
        let d = Dirs::new();
        d.put(&d.from, CLI, "cli 2");
        d.put(&d.from, AGENT, "agent 2");
        d.put(&d.to, CLI, "cli 1");
        d.put(&d.to, AGENT, "agent 1");
        let p = plan(&d.from, &d.to).unwrap();
        stage(&p).unwrap();
        // 第二个文件被别的程序独占打开：改不了名
        let held = std::fs::OpenOptions::new().read(true).share_mode(0).open(d.to.join(AGENT)).unwrap();
        let err = swap(&p).unwrap_err().to_string();
        assert!(err.contains("anchor-agent.exe"), "{err}");
        drop(held);
        assert_eq!(d.names(), ["anchor-agent.exe", "anchor.exe"], "已经换上的第一个文件换回去了，.new 和 .old 都不留");
        assert_eq!((d.read(CLI), d.read(AGENT)), ("cli 1".into(), "agent 1".into()));
    }

    #[test]
    fn staging_failure_leaves_nothing_behind() {
        let d = Dirs::new();
        d.put(&d.from, CLI, "cli 2");
        d.put(&d.from, AGENT, "agent 2");
        d.put(&d.to, CLI, "cli 1");
        d.put(&d.to, AGENT, "agent 1");
        let p = plan(&d.from, &d.to).unwrap();
        // 计划之后新程序少了一个（比如又在重新编译）
        std::fs::remove_file(d.from.join(AGENT)).unwrap();
        assert!(stage(&p).unwrap_err().to_string().contains("anchor-agent.exe"));
        assert_eq!(d.names(), ["anchor-agent.exe", "anchor.exe"]);
    }

    #[test]
    fn service_note_only_when_the_installed_one_differs() {
        let d = Dirs::new();
        let installed = d.to.join(SVC);
        assert_eq!(service_note(None, &installed), None, "新程序里没有服务程序");
        assert_eq!(service_note(Some(Installed::Missing), &installed), None, "没有装服务");
        assert_eq!(service_note(Some(Installed::Same), &installed), None, "同一个文件");
        d.put(&d.to, SVC, "svc 1");
        let note = service_note(Some(Installed::Differs), &installed).unwrap();
        assert!(note.contains("anchor service upgrade") && note.contains("--service"), "{note}");
    }

    #[test]
    fn service_line_in_the_file_list() {
        let d = Dirs::new();
        let (new, installed) = (d.from.join(SVC), d.to.join(SVC));
        d.put(&d.from, SVC, "svc 2");
        d.put(&d.to, SVC, "svc 1");
        assert!(describe_service(Installed::Missing, &new, &installed).contains("没有安装，跳过"));
        assert!(describe_service(Installed::Same, &new, &installed).contains("没有变化"));
        assert!(describe_service(Installed::Differs, &new, &installed).contains("要管理员确认"));
    }

    #[test]
    fn this_process_can_be_found_and_has_not_exited() {
        let me = std::env::current_exe().unwrap();
        assert!(same_path(&process_path(std::process::id()).unwrap(), &me));
        assert!(!wait_exit(std::process::id(), Duration::from_millis(50)));
        // 一个跑完就退出的进程
        let mut child = std::process::Command::new(crate::win::system32("cmd.exe")).args(["/c", "exit 0"]).spawn().unwrap();
        let pid = child.id();
        assert!(wait_exit(pid, Duration::from_secs(10)));
        child.wait().unwrap();
    }
}
