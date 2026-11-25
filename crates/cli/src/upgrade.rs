//! anchor upgrade：把新编译的程序换进安装目录，代替手工的四步
//! （anchor agent stop、复制两个程序、anchor agent start）。
//!
//! - 内容相同的文件不动。用户代理的程序没有变化时不重启它，AI 通道不中断。
//! - 新文件先复制到安装目录里（*.new），都复制完才停用户代理：停下的时间只有改名和启动那几秒。
//! - 旧文件改名留着（*.old）。新的用户代理没有启动成功，就换回旧文件并把旧的启动起来。
//! - 正在运行的程序可以改名，不能覆盖：所以用安装目录里的 anchor.exe 升级它自己也行，
//!   它的旧文件留到下次升级时再删。
//!
//! 换下来的那一版留在安装目录的 previous\ 里（三个程序的完整一份，外加一个记着“换上去的是哪一版”的小文件）。
//! anchor upgrade --rollback 就是从 previous\ 再升级一次：停、换、启动、起不来就换回，都是同一段代码；
//! 换完之后 previous\ 里是刚才那一版，所以再运行一次就换回去。
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
pub(crate) const REQUIRED: [&str; 2] = [CLI, AGENT];
/// 有就一起带上的：安装目录里的这一份只是 anchor service install / upgrade 用的安装源。
const OPTIONAL: [&str; 1] = [SVC];

/// 升级时换下来的那一版放在安装目录的这个子目录里。
const PREVIOUS: &str = "previous";
/// previous\ 里的记号：换上去的那一版（文件名、大小、修改时间）。退回之前用它确认安装目录还是那一版。
const MARK: &str = "replaced-by.txt";
const MARK_HEADER: &str = "# anchor upgrade 留下的上一版。下面是换上去的那一版：文件名、大小、修改时间（毫秒）。\n# anchor upgrade --rollback 用它确认安装目录在那之后没有被别的方式改过。\n";

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
    /// 退回上一版：从安装目录的 previous\ 换回去
    pub rollback: bool,
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
    /// 这是退回上一版（from 是安装目录里的 previous）：只影响说法，做法一样
    rollback: bool,
}

impl Plan {
    fn changed(&self) -> impl Iterator<Item = &Item> {
        self.items.iter().filter(|i| i.change != Change::Same)
    }

    fn changes(&self, name: &str) -> bool {
        self.changed().any(|i| i.name == name)
    }
}

pub(crate) fn with_suffix(dir: &Path, name: &str, suffix: &str) -> PathBuf {
    dir.join(format!("{name}{suffix}"))
}

/// 绝对路径，去掉末尾的反斜杠。
pub(crate) fn tidy(p: &Path) -> PathBuf {
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

pub(crate) fn names() -> impl Iterator<Item = &'static str> {
    REQUIRED.into_iter().chain(OPTIONAL)
}

/// 退回上一版时的两个目录：安装目录里的 previous，和安装目录。
/// 安装目录的找法和升级一样；都找不到时，本程序所在的目录里有 previous 就用它。
fn resolve_rollback(here: &Path, to: Option<&Path>, agent_dir: Option<&Path>, autostart: Option<&Path>) -> Result<(PathBuf, PathBuf)> {
    let here = here.join(PREVIOUS).is_dir().then_some(here);
    let to = tidy(to.or(agent_dir).or(autostart).or(here).context(
        "找不到安装目录：用户代理没有运行，也没有设置登录自启。用 --to 写明安装目录，例如 anchor upgrade --rollback --to <安装目录>",
    )?);
    Ok((to.join(PREVIOUS), to))
}

/// 一个目录里这几个程序的大小和修改时间，一行一个。复制时修改时间保留，所以同一版在哪里都是同一串。
fn fingerprint(dir: &Path) -> String {
    names()
        .filter_map(|name| {
            let m = std::fs::metadata(dir.join(name)).ok()?;
            let ms = m.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?.as_millis();
            Some(format!("{name}\t{}\t{ms}\n", m.len()))
        })
        .collect()
}

/// previous 能不能拿来退回：要完整，而且它记着的“换上去的那一版”就是安装目录里现在的这一版。
/// 对不上说明 previous 不是现在这一版的上一版（留的时候出过错，或者安装目录后来被别的方式改过），退回去会装错。
fn check_previous(prev: &Path, to: &Path) -> Result<()> {
    if !prev.is_dir() {
        bail!(
            "{} 里没有留下上一版（没有 previous 目录）。上一版是 anchor upgrade 换文件时留下的：这个安装还没有用带这个功能的版本升级过",
            to.display()
        );
    }
    let by_hand = format!("确实要装 previous 里的那一份，可以把它当成新程序来升级：anchor upgrade \"{}\"", prev.display());
    for name in REQUIRED {
        if !prev.join(name).is_file() {
            bail!("{} 里没有 {name}，上一版不完整，没有做任何改动。{by_hand}", prev.display());
        }
    }
    let mark = std::fs::read_to_string(prev.join(MARK)).unwrap_or_default();
    let recorded: String = mark.lines().filter(|l| !l.starts_with('#')).map(|l| format!("{l}\n")).collect();
    if recorded.is_empty() {
        bail!("{} 里没有 {MARK}：上次留上一版时没有留完，不能确定它是哪一版。没有做任何改动。{by_hand}", prev.display());
    }
    if recorded != fingerprint(to) {
        bail!(
            "{} 里的程序和上次升级换上去的不是同一版：上次升级之后，安装目录被别的方式改过（手工复制，或者用不带这个功能的版本升级过）。\
             previous 里的不是现在这一版的上一版，没有做任何改动。{by_hand}",
            to.display()
        );
    }
    Ok(())
}

fn plan(from: &Path, to: &Path) -> Result<Plan> {
    for name in REQUIRED {
        if !from.join(name).is_file() {
            bail!("{} 里没有 {name}：这不是编译好的程序目录（先运行 cargo build --release --workspace）", from.display());
        }
    }
    if !to.join(CLI).is_file() && !to.join(AGENT).is_file() {
        bail!("{} 里没有 anchor.exe，也没有 anchor-agent.exe：这不像是安装目录。第一次安装用 anchor install", to.display());
    }
    let mut items = Vec::new();
    for name in names() {
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
    Ok(Plan { from: from.to_path_buf(), to: to.to_path_buf(), items, rollback: false })
}

/// 删掉上次升级留下的 *.old 和没用上的 *.new。删不掉的（还在运行）留着。
fn clear_leftovers(to: &Path) {
    for name in names() {
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

/// 复制一个文件，并核对复制的字节数。
pub(crate) fn copy_whole(src: &Path, dst: &Path, name: &str) -> Result<()> {
    let n = std::fs::copy(src, dst).with_context(|| format!("复制 {} 到 {} 失败", src.display(), dst.display()))?;
    let want = std::fs::metadata(src)?.len();
    if n != want { bail!("{name} 只复制了 {n} 字节，应为 {want} 字节") } else { Ok(()) }
}

/// 把要换的文件复制到安装目录里，名字后面加 .new。这一步不影响正在运行的程序；出错时不留下东西。
fn stage(plan: &Plan) -> Result<()> {
    for i in plan.changed() {
        let (src, tmp) = (plan.from.join(i.name), with_suffix(&plan.to, i.name, ".new"));
        if let Err(e) = copy_whole(&src, &tmp, i.name) {
            remove_staged(plan);
            return Err(e);
        }
    }
    Ok(())
}

/// 把安装目录里现在的程序（三个都算，没变的也算）复制到 previous\ 里，名字后面加 .new。
/// previous\ 里原有的那一版先不动：升级没成的话它还是有效的。出错时不留下东西。
fn stage_previous(to: &Path) -> Result<()> {
    let dir = to.join(PREVIOUS);
    std::fs::create_dir_all(&dir).with_context(|| format!("建不了目录 {}", dir.display()))?;
    clear_leftovers(&dir);
    for name in names() {
        let src = to.join(name);
        if !src.is_file() {
            continue;
        }
        if let Err(e) = copy_whole(&src, &with_suffix(&dir, name, ".new"), name) {
            discard_previous(to);
            return Err(e);
        }
    }
    Ok(())
}

/// 升级没有成：刚才复制的那一份不要了。previous\ 里原有的那一版照旧。
fn discard_previous(to: &Path) {
    let dir = to.join(PREVIOUS);
    for name in names() {
        let _ = std::fs::remove_file(with_suffix(&dir, name, ".new"));
    }
    // 空的才删得掉：原来就有上一版的话，目录留着
    let _ = std::fs::remove_dir(&dir);
}

/// 升级成了：previous\ 换成刚才复制的那一份，并记下换上去的是哪一版。
/// 先删记号、最后写记号：中途出错的话 previous\ 里没有记号，check_previous 不会拿它去退回。
fn commit_previous(to: &Path) -> Result<()> {
    let dir = to.join(PREVIOUS);
    let mark = dir.join(MARK);
    if mark.exists() {
        std::fs::remove_file(&mark).with_context(|| format!("删不掉 {}", mark.display()))?;
    }
    for name in names() {
        let (cur, new, old) = (dir.join(name), with_suffix(&dir, name, ".new"), with_suffix(&dir, name, ".old"));
        if cur.exists() {
            // 正在运行的程序也能改名（运行 previous\anchor.exe upgrade 时的它自己）；删不掉的 .old 下次再清
            std::fs::rename(&cur, &old).with_context(|| format!("给 previous 里的 {name} 改名失败（有别的程序占着它？）"))?;
        }
        if new.exists() {
            std::fs::rename(&new, &cur).with_context(|| format!("往 previous 里放 {name} 失败"))?;
        }
        let _ = std::fs::remove_file(&old);
    }
    std::fs::write(&mark, format!("{MARK_HEADER}{}", fingerprint(to))).with_context(|| format!("写不了 {}", mark.display()))
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
pub(crate) fn built(p: &Path) -> String {
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
        Change::Replace => format!(
            "  {name}{}（编译于 {} → {}）",
            if plan.rollback { "退回" } else { "更新" },
            built(&plan.to.join(i.name)),
            built(&plan.from.join(i.name))
        ),
    }
}

/// 特权服务和新编译的不是同一个文件时提一句。每次编译出来的文件都会不同，所以这不等于必须更新。
/// rollback 是上一版里的那一份服务程序：退回时提的是“要不要把它也换回去”。
fn service_note(svc: Option<Installed>, installed: &Path, rollback: Option<&Path>) -> Option<String> {
    (svc == Some(Installed::Differs)).then(|| match rollback {
        None => format!(
            "特权服务没有动，还是之前安装的那一份（编译于 {}）。守卫规则、程序扫描或配置格式有改动时才需要更新它：anchor service upgrade，或者升级时加 --service（会弹出管理员确认）",
            built(installed)
        ),
        Some(prev) => format!(
            "特权服务没有动（编译于 {}）。上一版里的那一份编译于 {}；要把它也换回去：anchor upgrade --rollback --service（会弹出管理员确认）",
            built(installed),
            built(prev)
        ),
    })
}

/// 退回完成之后的提示：安装目录里已经是上一版了，服务要跟上就用它旁边的那一份。
fn service_note_after_rollback(installed: &Path) -> String {
    format!(
        "特权服务没有动（编译于 {}）。要把它也换成这一版里的那一份：anchor service upgrade（会弹出管理员确认）",
        built(installed)
    )
}

/// 加了 --service 时，文件清单里特权服务的那一行。
fn describe_service(svc: Installed, new: &Path, installed: &Path, rollback: bool) -> String {
    let name = crate::util::pad("特权服务", 18);
    match svc {
        Installed::Missing => format!("  {name}没有安装，跳过"),
        Installed::Same => format!("  {name}没有变化"),
        Installed::Differs => format!(
            "  {name}{}（编译于 {} → {}），要管理员确认",
            if rollback { "换成上一版里的那一份" } else { "更新" },
            built(installed),
            built(new)
        ),
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
    let back = args.rollback;
    let (from, to) = if back {
        let (from, to) = resolve_rollback(here, args.to.as_deref(), agent_dir.as_deref(), autostart_dir(paths).as_deref())?;
        check_previous(&from, &to)?;
        (from, to)
    } else {
        resolve(here, args.dir.as_deref(), args.to.as_deref(), agent_dir.as_deref(), autostart_dir(paths).as_deref())?
    };
    let mut plan = plan(&from, &to)?;
    plan.rollback = back;
    let (svc_new, installed) = (plan.from.join(SVC), svcctl::installed_exe());
    let svc = if svc_new.is_file() { Some(svcctl::compare(&svc_new, &installed)?) } else { None };
    if args.service && svc.is_none() {
        if back {
            bail!("上一版里没有 anchor-svc.exe，换不了特权服务。去掉 --service");
        }
        bail!(
            "{} 里没有 anchor-svc.exe，更新不了特权服务。去掉 --service，或者先编译整个工作区（cargo build --release --workspace）",
            plan.from.display()
        );
    }

    if back {
        println!("退回 AI Anchor 的上一版");
        println!("  上一版  {}", plan.from.display());
        println!("  安装在  {}", plan.to.display());
    } else {
        println!("升级 AI Anchor");
        println!("  新程序  {}", plan.from.display());
        println!("  安装到  {}", plan.to.display());
    }
    for i in &plan.items {
        println!("{}", describe(&plan, i));
    }
    if args.service
        && let Some(s) = svc
    {
        println!("{}", describe_service(s, &svc_new, &installed, back));
    }
    let note = if args.service { None } else { service_note(svc, &installed, back.then_some(svc_new.as_path())) };
    let files = plan.changed().next().is_some();
    let do_svc = args.service && svc == Some(Installed::Differs);

    if !files && !do_svc {
        println!("{}", if back { "上一版和现在装的一样，没有改动。" } else { "已经是这个版本，没有改动。" });
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
            println!(
                "{}：弹出管理员确认，服务停几秒后用{}启动。防火墙守卫规则不动，AI 通道不受影响。",
                if back { "会把特权服务换成上一版里的那一份" } else { "会更新特权服务" },
                if back { "它" } else { "新程序" }
            );
        }
        if let Some(n) = note {
            println!("{n}");
        }
        println!("（预览，没有做任何改动。去掉 --dry-run 执行）");
        return Ok(());
    }
    if do_svc {
        // 升级：用新编译的那一份去换，比较时用的就是它。
        // 退回：换完文件之后 previous 里已经是刚才那一版了，上一版的服务程序现在在安装目录里。
        let source = if back && files { plan.to.join(SVC) } else { svc_new.clone() };
        svcctl::upgrade_from(&source).map_err(|e| {
            if files {
                e.context(if back {
                    "anchor.exe 和 anchor-agent.exe 已经退回上一版，只有特权服务没换"
                } else {
                    "anchor.exe 和 anchor-agent.exe 已经升级好了，只有特权服务没换"
                })
            } else {
                e
            }
        })?;
    }
    println!("{}", if back { "已退回上一版。" } else { "升级完成。" });
    if back && files && note.is_some() {
        // 文件已经换回去了：这时候再说“加 --rollback --service”就错了，那会把文件又换回来
        println!("{}", service_note_after_rollback(&installed));
    } else if let Some(n) = note {
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
    let prev = plan.to.join(PREVIOUS);
    let which = if plan.rollback { "上一版的" } else { "新的" };
    if dry_run {
        println!("{plain}");
        if plan.rollback {
            println!("现在的这一版会留在 {}，再运行一次 anchor upgrade --rollback 就换回来。", prev.display());
        } else {
            println!("现在的这一版会留在 {}，之后可以退回：anchor upgrade --rollback", prev.display());
        }
        return Ok(());
    }

    clear_leftovers(&plan.to);
    stage(plan)?;
    if let Err(e) = stage_previous(&plan.to) {
        remove_staged(plan);
        return Err(e.context("给现在的这一版留一份时出错。没有换文件，安装目录和原来一样"));
    }
    let down_since = Instant::now();
    if let Some(a) = restart {
        println!("停止用户代理…");
        if let Err(e) = stop_agent(a) {
            remove_staged(plan);
            discard_previous(&plan.to);
            return Err(e.context("没有换文件，安装目录和原来一样"));
        }
    }
    let agent_exe = plan.to.join(AGENT);
    let no_tray = restart.is_some_and(|a| !a.tray);
    if let Err(e) = swap(plan) {
        discard_previous(&plan.to);
        // 文件已经换回去了；刚才停掉的用户代理要重新启动
        let back = restart.map(|_| start_agent(&agent_exe, &paths.home, no_tray));
        return Err(e.context(match back {
            Some(Err(_)) => "换文件失败，已换回原来的文件，但原来的用户代理没有启动起来：运行 anchor agent start",
            Some(Ok(_)) => "换文件失败，已换回原来的文件，并重新启动了原来的用户代理",
            None => "换文件失败，已换回原来的文件",
        }));
    }
    if restart.is_some() {
        println!("启动{which}用户代理…");
        match start_agent(&agent_exe, &paths.home, no_tray) {
            Ok(pid) => println!("用户代理已启动（pid {pid}），中间停了 {:.1} 秒。", down_since.elapsed().as_secs_f32()),
            Err(e) => {
                let done: Vec<&Item> = plan.changed().collect();
                undo(&plan.to, &done);
                discard_previous(&plan.to);
                let back = start_agent(&agent_exe, &paths.home, no_tray);
                return Err(e.context(match back {
                    Ok(_) => format!("{which}用户代理没有启动成功。已换回原来的文件，并重新启动了原来的用户代理"),
                    Err(_) => format!(
                        "{which}用户代理没有启动成功。已换回原来的文件，但原来的用户代理也没有启动起来：运行 anchor agent start，日志在数据目录的 logs\\agent.log"
                    ),
                }));
            }
        }
    } else {
        println!("{plain}");
    }

    // 文件已经换好。留上一版出错不算升级失败，只是这次退不回去
    let kept = commit_previous(&plan.to).inspect_err(|_| discard_previous(&plan.to));

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
    match kept {
        Ok(()) if plan.rollback => println!("刚才那一版留在 {}，再运行一次 anchor upgrade --rollback 就换回来。", prev.display()),
        Ok(()) => println!("换下来的那一版留在 {}，要退回去：anchor upgrade --rollback", prev.display()),
        Err(e) => println!("注意：换下来的那一版没有留成（{e:#}）。这次不能用 anchor upgrade --rollback 退回。"),
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
        assert_eq!(service_note(None, &installed, None), None, "新程序里没有服务程序");
        assert_eq!(service_note(Some(Installed::Missing), &installed, None), None, "没有装服务");
        assert_eq!(service_note(Some(Installed::Same), &installed, None), None, "同一个文件");
        d.put(&d.to, SVC, "svc 1");
        let note = service_note(Some(Installed::Differs), &installed, None).unwrap();
        assert!(note.contains("anchor service upgrade") && note.contains("--service"), "{note}");
        // 退回时：提的是把上一版里的那一份也换回去
        assert_eq!(service_note(Some(Installed::Same), &installed, Some(&d.from.join(SVC))), None);
        let note = service_note(Some(Installed::Differs), &installed, Some(&d.from.join(SVC))).unwrap();
        assert!(note.contains("--rollback --service") && !note.contains("anchor service upgrade"), "{note}");
        // 退回完成之后：文件已经是上一版，不能再让人加 --rollback
        let note = service_note_after_rollback(&installed);
        assert!(note.contains("anchor service upgrade") && !note.contains("--rollback"), "{note}");
    }

    #[test]
    fn service_line_in_the_file_list() {
        let d = Dirs::new();
        let (new, installed) = (d.from.join(SVC), d.to.join(SVC));
        d.put(&d.from, SVC, "svc 2");
        d.put(&d.to, SVC, "svc 1");
        assert!(describe_service(Installed::Missing, &new, &installed, false).contains("没有安装，跳过"));
        assert!(describe_service(Installed::Same, &new, &installed, false).contains("没有变化"));
        let line = describe_service(Installed::Differs, &new, &installed, false);
        assert!(line.contains("更新") && line.contains("要管理员确认"), "{line}");
        let line = describe_service(Installed::Differs, &new, &installed, true);
        assert!(line.contains("换成上一版里的那一份") && line.contains("要管理员确认"), "{line}");
    }

    fn list(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        v.sort();
        v
    }

    fn texts(dir: &Path) -> (String, String, String) {
        let t = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap_or_else(|_| "<没有>".into());
        (t(CLI), t(AGENT), t(SVC))
    }

    fn three(a: &str, b: &str, c: &str) -> (String, String, String) {
        (a.into(), b.into(), c.into())
    }

    /// 换文件的那几步，按 upgrade_files 里的顺序（不含用户代理）。
    fn install(p: &Plan) {
        clear_leftovers(&p.to);
        stage(p).unwrap();
        stage_previous(&p.to).unwrap();
        swap(p).unwrap();
        assert_eq!(remove_old(p), Vec::<&str>::new());
        commit_previous(&p.to).unwrap();
    }

    /// 安装目录里是第 1 版（三个程序），新程序目录里是第 2 版：anchor.exe 和服务程序变了，用户代理没变。
    fn v1_installed_v2_built() -> Dirs {
        let d = Dirs::new();
        d.put(&d.to, CLI, "cli 1");
        d.put(&d.to, AGENT, "agent 1");
        d.put(&d.to, SVC, "svc 1");
        d.put(&d.from, CLI, "cli 2");
        d.put(&d.from, AGENT, "agent 1");
        d.put(&d.from, SVC, "svc 22");
        d
    }

    #[test]
    fn the_replaced_version_is_kept_and_can_be_put_back() {
        let d = v1_installed_v2_built();
        d.put(&d.to, "sing-box.exe", "别的文件不留");
        let prev = d.to.join(PREVIOUS);

        // 升级：换文件之前，现在的这一版先复制到 previous 里，名字带 .new
        let p = plan(&d.from, &d.to).unwrap();
        stage(&p).unwrap();
        stage_previous(&d.to).unwrap();
        assert_eq!(list(&prev), ["anchor-agent.exe.new", "anchor-svc.exe.new", "anchor.exe.new"]);
        assert!(check_previous(&prev, &d.to).is_err(), "还没换完，不能拿来退回");
        swap(&p).unwrap();
        assert_eq!(remove_old(&p), Vec::<&str>::new());
        commit_previous(&d.to).unwrap();
        assert_eq!(texts(&d.to), three("cli 2", "agent 1", "svc 22"));
        assert_eq!(list(&prev), ["anchor-agent.exe", "anchor-svc.exe", "anchor.exe", MARK]);
        assert_eq!(texts(&prev), three("cli 1", "agent 1", "svc 1"), "没变的用户代理也留一份：previous 是完整的一版");
        check_previous(&prev, &d.to).unwrap();

        // 退回：从 previous 再升级一次
        let mut back = plan(&prev, &d.to).unwrap();
        back.rollback = true;
        assert_eq!(changes(&back), [(CLI, Change::Replace), (AGENT, Change::Same), (SVC, Change::Replace)]);
        assert!(describe(&back, &back.items[0]).contains("退回") && describe(&p, &p.items[0]).contains("更新"));
        install(&back);
        assert_eq!(texts(&d.to), three("cli 1", "agent 1", "svc 1"));
        assert_eq!(texts(&prev), three("cli 2", "agent 1", "svc 22"), "previous 里是刚才那一版");
        assert_eq!(d.names(), ["anchor-agent.exe", "anchor-svc.exe", "anchor.exe", PREVIOUS, "sing-box.exe"]);

        // 再退一次就换回来
        check_previous(&prev, &d.to).unwrap();
        let mut again = plan(&prev, &d.to).unwrap();
        again.rollback = true;
        install(&again);
        assert_eq!(texts(&d.to), three("cli 2", "agent 1", "svc 22"));
        assert_eq!(texts(&prev), three("cli 1", "agent 1", "svc 1"));
        assert_eq!(list(&prev), ["anchor-agent.exe", "anchor-svc.exe", "anchor.exe", MARK]);
    }

    #[test]
    fn a_previous_that_is_not_the_version_before_this_one_is_refused() {
        let d = v1_installed_v2_built();
        let prev = d.to.join(PREVIOUS);
        let why = |d: &Dirs| check_previous(&d.to.join(PREVIOUS), &d.to).unwrap_err().to_string();
        assert!(why(&d).contains("没有留下上一版"), "还没有升级过");

        install(&plan(&d.from, &d.to).unwrap());
        check_previous(&prev, &d.to).unwrap();

        // 升级之后安装目录被手工换了一个文件：previous 不再是它的上一版
        d.put(&d.to, CLI, "手工复制的另一版");
        let err = why(&d);
        assert!(err.contains("别的方式改过") && err.contains("没有做任何改动"), "{err}");
        assert!(err.contains("anchor upgrade \""), "告诉人怎么手工装 previous 里的那一份：{err}");

        // 没有记号：上次没有留完
        std::fs::remove_file(prev.join(MARK)).unwrap();
        assert!(why(&d).contains(MARK));
        // 少了一个程序
        std::fs::remove_file(prev.join(AGENT)).unwrap();
        assert!(why(&d).contains("不完整"));
    }

    #[test]
    fn an_upgrade_that_is_undone_keeps_the_earlier_previous() {
        // 还没有上一版时：复制到一半的那一份删掉，目录也不留
        let d = v1_installed_v2_built();
        let prev = d.to.join(PREVIOUS);
        let p = plan(&d.from, &d.to).unwrap();
        stage(&p).unwrap();
        stage_previous(&d.to).unwrap();
        remove_staged(&p);
        discard_previous(&d.to);
        assert!(!prev.exists());
        assert_eq!(d.names(), ["anchor-agent.exe", "anchor-svc.exe", "anchor.exe"]);

        // 已经有上一版（第 1 版）时，第 3 版没装成：previous 里还是第 1 版，还能退回
        install(&p);
        d.put(&d.from, CLI, "cli 333");
        let p3 = plan(&d.from, &d.to).unwrap();
        stage(&p3).unwrap();
        stage_previous(&d.to).unwrap();
        assert_eq!(list(&prev).len(), 7, "三个程序、三个 .new、一个记号");
        remove_staged(&p3);
        discard_previous(&d.to);
        assert_eq!(list(&prev), ["anchor-agent.exe", "anchor-svc.exe", "anchor.exe", MARK]);
        assert_eq!(texts(&prev), three("cli 1", "agent 1", "svc 1"));
        check_previous(&prev, &d.to).unwrap();
    }

    #[test]
    fn a_previous_that_could_not_be_replaced_is_not_used() {
        let d = v1_installed_v2_built();
        let prev = d.to.join(PREVIOUS);
        install(&plan(&d.from, &d.to).unwrap());

        // 装第 3 版；往 previous 里放第 2 版时，第二个文件被别的程序打开着，改不了名
        d.put(&d.from, CLI, "cli 333");
        d.put(&d.from, AGENT, "agent 333");
        let p3 = plan(&d.from, &d.to).unwrap();
        stage(&p3).unwrap();
        stage_previous(&d.to).unwrap();
        swap(&p3).unwrap();
        let held = std::fs::OpenOptions::new().read(true).share_mode(1).open(prev.join(AGENT)).unwrap();
        let err = commit_previous(&d.to).unwrap_err().to_string();
        assert!(err.contains("anchor-agent.exe"), "{err}");
        drop(held);
        discard_previous(&d.to);

        // 升级本身成了；previous 里是两版混着的，没有记号，不能拿去退回
        assert_eq!(texts(&d.to).0, "cli 333");
        assert_eq!((texts(&prev).0, texts(&prev).1), ("cli 2".to_string(), "agent 1".to_string()), "第一个换了，第二个没换");
        let err = check_previous(&prev, &d.to).unwrap_err().to_string();
        assert!(err.contains(MARK), "{err}");

        // 下一次升级把 previous 重新留好
        d.put(&d.from, CLI, "cli 4444");
        install(&plan(&d.from, &d.to).unwrap());
        assert_eq!(texts(&prev), three("cli 333", "agent 333", "svc 22"));
        check_previous(&prev, &d.to).unwrap();
    }

    #[test]
    fn where_the_previous_version_is_looked_for() {
        let d = Dirs::new();
        let (inst, auto) = (Path::new(r"C:\inst"), Path::new(r"C:\auto"));
        let r = |to, agent, autostart| resolve_rollback(&d.from, to, agent, autostart).map_err(|e| e.to_string());
        let at = |dir: &Path| Ok((dir.join(PREVIOUS), dir.to_path_buf()));
        // 和升级一样：--to 最优先，然后是用户代理所在的目录，然后是登录自启
        assert_eq!(r(Some(inst), Some(auto), None), at(inst));
        assert_eq!(r(None, Some(inst), Some(auto)), at(inst));
        assert_eq!(r(None, None, Some(auto)), at(auto));
        assert!(r(None, None, None).unwrap_err().contains("--to"), "本程序所在的目录里没有 previous");
        // 都找不到时：本程序所在的目录里有 previous，那它就是安装目录
        std::fs::create_dir_all(d.from.join(PREVIOUS)).unwrap();
        assert_eq!(r(None, None, None), at(&tidy(&d.from)));
        assert_eq!(r(None, Some(inst), None), at(inst), "找得到用户代理时不用它");
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
