//! anchor uninstall：把 AI Anchor 从这台电脑上拿掉。和 anchor install、anchor agent install、anchor service install 反着来。
//!
//! 顺序（先做要管理员的那一步：被取消的话别的都还没动）：
//! 1. 特权服务和防火墙守卫规则：以管理员身份运行 anchor-svc uninstall --remove-rules，一次确认。
//!    规则要和服务一起删：只删服务，规则留着，AI 程序就一直只能连本机，而 anchor 已经不在了。
//! 2. 停掉从安装目录运行的用户代理，取消指向安装目录的登录自启。
//! 3. 删掉指向安装目录的“… - AI Anchor”快捷方式（默认看桌面）。
//! 4. 删掉安装目录里 AI Anchor 自己的文件；目录空了就删目录。不认识的文件不碰，目录因此留着。
//!    正在运行的本程序删不掉：等它退出后由一个隐藏的 PowerShell 删。
//! 5. 从用户的 PATH 里去掉安装目录。
//!
//! 数据目录（配置、时间线、日志、sing-box）不删，结束时写明在哪里。
//! 每一步只动指向这个安装目录的东西：指向别处的登录自启、快捷方式、用户代理都不碰。

use crate::agentctl::{RUN_KEY, RUN_VALUE};
use crate::config::Paths;
use crate::install::{announce_env_change, default_dir, norm, read_path, user_env, write_path};
use crate::upgrade::{MARK, PREVIOUS, autostart_dir, names, parse_autostart, running_agent, stop_agent, tidy, with_suffix};
use crate::util::{confirm, pad, same_path};
use crate::{guard, ps, svcctl, win};
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE};

pub struct Args {
    /// 安装目录；不写时按运行中的用户代理、登录自启、默认位置来找
    pub to: Option<PathBuf>,
    pub yes: bool,
    pub dry_run: bool,
    /// 不动特权服务和守卫规则（测试用：这一步要管理员确认，会影响整台电脑）
    pub keep_guard: bool,
    /// 找快捷方式的目录；不写就是桌面
    pub shortcut_dir: Option<PathBuf>,
}

const SHORTCUT_SUFFIX: &str = " - AI Anchor.lnk";

/// 要卸载哪个目录：--to 最优先，然后是运行中的用户代理所在的目录、登录自启指向的目录、默认的安装目录（存在的话）。
/// 不猜本程序所在的目录：从编译目录运行时，那里不是安装目录。
fn find_dir(to: Option<&Path>, agent_dir: Option<&Path>, autostart: Option<&Path>, default: Option<&Path>) -> Result<PathBuf> {
    let dir = to.or(agent_dir).or(autostart).or(default).context(
        "找不到安装目录：用户代理没有运行，没有设置登录自启，默认位置也没有装过。用 --to 写明安装目录，例如 anchor uninstall --to <安装目录>",
    )?;
    Ok(tidy(dir))
}

/// 看起来是 cargo 的编译目录（target\debug、target\release）：不能当安装目录来删。
fn is_build_dir(dir: &Path) -> bool {
    ["deps", ".fingerprint", "build", "incremental"].iter().any(|d| dir.join(d).is_dir())
}

fn check_dir(dir: &Path) -> Result<()> {
    if !dir.is_dir() {
        bail!("{} 不存在", dir.display());
    }
    if is_build_dir(dir) {
        bail!("{} 是编译目录，不是安装目录：卸载不会删它。用 --to 写明安装目录", dir.display());
    }
    if !["anchor.exe", "anchor-agent.exe"].iter().any(|n| dir.join(n).is_file()) {
        bail!("{} 里没有 anchor.exe，也没有 anchor-agent.exe：这不像是安装目录", dir.display());
    }
    Ok(())
}

/// 安装目录里有什么：AI Anchor 自己放的文件（要删）、别的（留着）。
#[derive(Debug, Default, PartialEq, Eq)]
struct Files {
    /// AI Anchor 放进去的：三个程序、升级留下的 .old / .new、上一版目录里的这些和 replaced-by.txt
    ours: Vec<PathBuf>,
    /// 不是 AI Anchor 放的（文件名，previous 里的带上 previous\ 前缀）：留着，目录也就留着
    others: Vec<String>,
}

fn ours_in(dir: &Path, with_mark: bool) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = names()
        .flat_map(|n| [dir.join(n), with_suffix(dir, n, ".old"), with_suffix(dir, n, ".new")])
        .collect();
    if with_mark {
        v.push(dir.join(MARK));
    }
    v
}

fn inventory(dir: &Path) -> Files {
    let mut f = Files::default();
    let prev = dir.join(PREVIOUS);
    let mine: Vec<PathBuf> = ours_in(dir, false).into_iter().chain(ours_in(&prev, true)).collect();
    let mut list = |d: &Path, prefix: &str| {
        let Ok(rd) = std::fs::read_dir(d) else { return };
        let mut entries: Vec<_> = rd.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let p = e.path();
            if prefix.is_empty() && e.file_name().to_string_lossy().eq_ignore_ascii_case(PREVIOUS) && p.is_dir() {
                continue;
            }
            if p.is_file() && mine.iter().any(|m| same_path(m, &p)) {
                f.ours.push(p);
            } else {
                f.others.push(format!("{prefix}{}", e.file_name().to_string_lossy()));
            }
        }
    };
    list(dir, "");
    list(&prev, &format!("{PREVIOUS}\\"));
    f
}

/// 删文件。本程序自己删不掉（还在运行），放进 later，等退出后再删。删不掉的别的文件记下原因。
fn delete(files: &[PathBuf], me: &Path) -> (Vec<PathBuf>, Vec<(PathBuf, String)>) {
    let (mut later, mut failed) = (Vec::new(), Vec::new());
    for p in files {
        if same_path(p, me) {
            later.push(p.clone());
            continue;
        }
        if let Err(e) = std::fs::remove_file(p) {
            failed.push((p.clone(), e.to_string()));
        }
    }
    (later, failed)
}

/// 空了就删：先上一版的目录，再安装目录。
fn remove_empty_dirs(dir: &Path) {
    let _ = std::fs::remove_dir(dir.join(PREVIOUS));
    let _ = std::fs::remove_dir(dir);
}

/// 等本进程退出后，删掉剩下的文件和空目录。用一个隐藏的 PowerShell 做，不留窗口。
fn delete_after_exit(files: &[PathBuf], dir: &Path) -> Result<()> {
    let list = |v: &[PathBuf]| v.iter().map(|p| ps::quote(&p.to_string_lossy())).collect::<Vec<_>>().join(", ");
    let dirs = [dir.join(PREVIOUS), dir.to_path_buf()];
    let script = format!(
        "$ErrorActionPreference = 'SilentlyContinue'\n\
         Wait-Process -Id {pid} -Timeout 60\n\
         Start-Sleep -Milliseconds 300\n\
         foreach ($f in @({files})) {{ Remove-Item -LiteralPath $f -Force }}\n\
         foreach ($d in @({dirs})) {{ if ((Test-Path -LiteralPath $d) -and -not (Get-ChildItem -LiteralPath $d -Force)) {{ Remove-Item -LiteralPath $d -Force }} }}",
        pid = std::process::id(),
        files = list(files),
        dirs = list(&dirs),
    );
    ps::spawn_detached(&script)
}

/// 去掉 PATH 里等于这个目录的项（写法不同也算），别的项原样留着。没有要去掉的返回 None。
fn path_without(value: &str, dir: &Path) -> Option<String> {
    let want = norm(&dir.to_string_lossy());
    let parts: Vec<&str> = value.split(';').collect();
    let kept: Vec<&str> = parts.iter().copied().filter(|e| e.trim().is_empty() || norm(e) != want).collect();
    (kept.len() != parts.len()).then(|| kept.join(";"))
}

/// 从这个注册表键的 Path 里去掉目录，类型不变。返回有没有改。
fn remove_from_path(key: &RegKey, dir: &Path) -> Result<bool> {
    let Some((old, vtype)) = read_path(key)? else { return Ok(false) };
    match path_without(&old, dir) {
        Some(new) => {
            write_path(key, &new, vtype)?;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// 登录自启那一行指向的程序在不在这个目录里。不是本程序写的格式就不认。
fn autostart_points_into(line: &str, dir: &Path) -> bool {
    parse_autostart(line).is_some_and(|(exe, _)| exe.parent().is_some_and(|p| same_path(&tidy(p), dir)))
}

/// 登录自启指向这个目录时删掉它。返回删了没有。键由调用方给：正式用的是 HKCU 的 Run，测试用临时的键。
fn remove_autostart(key: &RegKey, dir: &Path) -> Result<bool> {
    let line: String = match key.get_value(RUN_VALUE) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e).context("读不了登录自启"),
    };
    if !autostart_points_into(&line, dir) {
        return Ok(false);
    }
    key.delete_value(RUN_VALUE).context("删不掉登录自启")?;
    Ok(true)
}

fn run_key(write: bool) -> Result<RegKey> {
    let flags = if write { KEY_READ | KEY_SET_VALUE } else { KEY_READ };
    RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(RUN_KEY, flags).context("打不开登录自启的注册表键")
}

/// 快捷方式指向的是不是这个目录里的 anchor.exe。
fn shortcut_is_ours(target: &Path, dir: &Path) -> bool {
    target.file_name().is_some_and(|n| n.eq_ignore_ascii_case("anchor.exe")) && target.parent().is_some_and(|p| same_path(&tidy(p), dir))
}

/// 目录里所有“… - AI Anchor.lnk”和它们指向的程序（读快捷方式要用 PowerShell）。
fn shortcuts(dir: &Path) -> Result<Vec<(PathBuf, PathBuf)>> {
    let has_any = std::fs::read_dir(dir).map(|rd| rd.flatten().any(|e| e.file_name().to_string_lossy().ends_with(SHORTCUT_SUFFIX))).unwrap_or(false);
    if !has_any {
        return Ok(Vec::new());
    }
    let out = ps::run_ok(&format!(
        "$sh = New-Object -ComObject WScript.Shell\n\
         Get-ChildItem -LiteralPath {} -Filter {} | ForEach-Object {{ $_.FullName + '|' + $sh.CreateShortcut($_.FullName).TargetPath }}",
        ps::quote(&dir.to_string_lossy()),
        ps::quote(&format!("*{SHORTCUT_SUFFIX}")),
    ))?;
    Ok(out
        .lines()
        .filter_map(|l| l.split_once('|'))
        .map(|(lnk, target)| (PathBuf::from(lnk.trim()), PathBuf::from(target.trim())))
        .collect())
}

fn desktop() -> Option<PathBuf> {
    let out = ps::run_ok("[Environment]::GetFolderPath('Desktop')").ok()?;
    let p = out.trim();
    (!p.is_empty()).then(|| PathBuf::from(p))
}

/// 管理员那一步：以管理员身份运行 anchor-svc uninstall --remove-rules。已经是管理员就直接运行。
fn remove_service_and_rules(svc_exe: &Path) -> Result<()> {
    if !svc_exe.is_file() {
        bail!("{} 不存在：删特权服务和守卫规则要用它", svc_exe.display());
    }
    if win::is_elevated() {
        let st = std::process::Command::new(svc_exe).args(["uninstall", "--remove-rules"]).status()?;
        if !st.success() {
            bail!("anchor-svc uninstall 失败");
        }
        return Ok(());
    }
    println!("删除特权服务和守卫规则，要管理员确认，将弹出确认窗口…");
    let code = svcctl::run_elevated(svc_exe, "uninstall --remove-rules --pause")?;
    if code != 0 {
        bail!("anchor-svc uninstall 失败（退出码 {code}），原因见提权窗口里的输出");
    }
    Ok(())
}

pub fn run(paths: &Paths, args: &Args) -> Result<()> {
    let me = std::env::current_exe()?;
    let here = tidy(me.parent().context("无法确定程序目录")?);
    let agent = running_agent();
    let agent_dir = agent.as_ref().and_then(|a| a.dir.as_deref().map(tidy));
    let default = default_dir().ok().filter(|d| d.join("anchor.exe").is_file() || d.join("anchor-agent.exe").is_file());
    let dir = find_dir(args.to.as_deref(), agent_dir.as_deref(), autostart_dir(paths).as_deref(), default.as_deref())?;
    check_dir(&dir)?;

    // ---- 现在的情况（只读）
    let files = inventory(&dir);
    let stop = agent.as_ref().filter(|_| agent_dir.as_deref().is_some_and(|d| same_path(d, &dir)));
    let autostart = crate::agentctl::autostart_entry();
    let autostart_ours = autostart.as_deref().is_some_and(|l| autostart_points_into(l, &dir));
    let svc_installed = svcctl::installed_exe().exists() || svcctl::running();
    let rules = if args.keep_guard { Ok(0) } else { guard::rule_count() };
    let lnk_dir = args.shortcut_dir.clone().or_else(desktop);
    let links: Vec<PathBuf> = match &lnk_dir {
        Some(d) => shortcuts(d)?.into_iter().filter(|(_, t)| shortcut_is_ours(t, &dir)).map(|(l, _)| l).collect(),
        None => Vec::new(),
    };
    let on_path = user_env(false).and_then(|k| read_path(&k)).map(|v| v.is_some_and(|(text, _)| path_without(&text, &dir).is_some()));

    println!("卸载 AI Anchor");
    let row = |k: &str, v: String| println!("  {}{v}", pad(k, 12));
    row("安装目录", dir.display().to_string());
    if files.ours.is_empty() {
        row("程序", "没有 AI Anchor 的文件".into());
    } else {
        let mut shown: Vec<String> = files.ours.iter().filter_map(|p| p.strip_prefix(&dir).ok()).map(|p| p.display().to_string()).collect();
        shown.sort();
        row("要删的文件", shown.join("、"));
    }
    if !files.others.is_empty() {
        row("留下的文件", format!("{}（不是 AI Anchor 放的，不删；目录因此留着）", files.others.join("、")));
    }
    row(
        "用户代理",
        match (&agent, stop) {
            (_, Some(_)) => "在运行（从安装目录），会停掉".into(),
            (Some(a), None) => format!("在运行，但不是从这个目录（{}），不动", a.dir.as_deref().map_or("?".into(), |d| d.display().to_string())),
            (None, _) => "没有运行".into(),
        },
    );
    row(
        "登录自启",
        match (&autostart, autostart_ours) {
            (Some(_), true) => "指向安装目录，会取消".into(),
            (Some(_), false) => "指向别处，不动".into(),
            (None, _) => "没有设置".into(),
        },
    );
    let do_admin = !args.keep_guard && (svc_installed || rules.as_ref().is_ok_and(|n| *n > 0));
    if args.keep_guard {
        row("特权服务", "不动（--keep-guard）".into());
        row("守卫规则", "不动（--keep-guard）。规则在，AI 程序就只能连本机：卸载之后它们上不了网，要自己删规则".into());
    } else {
        row("特权服务", if svc_installed { "已安装，会停止并删除（要管理员确认）".into() } else { "没有安装".into() });
        row(
            "守卫规则",
            match &rules {
                Ok(0) => "没有".into(),
                Ok(n) => format!("{n} 条，会删除（要管理员确认）。删除后 AI 程序不经 AI Anchor 也能直接上网"),
                Err(e) => format!("查不了（{e:#}）。仍然会请服务程序删除"),
            },
        );
    }
    match (&lnk_dir, links.is_empty()) {
        (Some(_), false) => row(
            "快捷方式",
            format!("{} 个指向安装目录，会删：{}", links.len(), links.iter().filter_map(|l| l.file_name()).map(|n| n.to_string_lossy().into_owned()).collect::<Vec<_>>().join("、")),
        ),
        (Some(d), true) => row("快捷方式", format!("{} 里没有指向安装目录的", d.display())),
        (None, _) => row("快捷方式", "找不到桌面，不查".into()),
    }
    row(
        "用户的 PATH",
        match &on_path {
            Ok(true) => "有安装目录，会去掉".into(),
            Ok(false) => "没有安装目录，不改".into(),
            Err(e) => format!("读不了（{e:#}），不改"),
        },
    );
    row("数据目录", format!("{}：配置、时间线、日志、sing-box 都留着，不删", paths.home.display()));

    if args.dry_run {
        println!("（预览，没有做任何改动。去掉 --dry-run 执行）");
        return Ok(());
    }
    if !args.yes && !confirm("确认卸载？[y/N] ")? {
        println!("没有卸载。");
        return Ok(());
    }

    // 1. 要管理员的那一步先做：被取消或失败，别的都还没动
    if do_admin {
        remove_service_and_rules(&here.join("anchor-svc.exe")).map_err(|e| e.context("没有卸载：别的都还没动"))?;
        let left = guard::rule_count();
        let svc_left = svcctl::installed_exe().exists();
        match (&left, svc_left) {
            (Ok(0), false) => println!("特权服务和守卫规则已删除。"),
            _ => println!(
                "注意：删完之后核对，服务程序{}、守卫规则{}。",
                if svc_left { "还在" } else { "已删除" },
                left.as_ref().map_or_else(|e| format!("查不了（{e:#}）"), |n| format!("还有 {n} 条"))
            ),
        }
    }
    // 2. 用户代理和登录自启
    if let Some(a) = stop {
        println!("停止用户代理…");
        stop_agent(a)?;
    }
    if autostart_ours && run_key(true).and_then(|k| remove_autostart(&k, &dir))? {
        println!("已取消登录后自动启动。");
    }
    // 3. 快捷方式
    for l in &links {
        match std::fs::remove_file(l) {
            Ok(()) => println!("已删除快捷方式 {}", l.display()),
            Err(e) => println!("删不掉快捷方式 {}：{e}", l.display()),
        }
    }
    // 4. 文件
    let (later, failed) = delete(&files.ours, &me);
    for (p, e) in &failed {
        println!("删不掉 {}：{e}（有别的程序在用它？）", p.display());
    }
    remove_empty_dirs(&dir);
    if !later.is_empty() {
        delete_after_exit(&later, &dir)?;
    }
    let gone = !dir.exists();
    match (gone, later.is_empty(), files.others.is_empty() && failed.is_empty()) {
        (true, _, _) => println!("已删除安装目录 {}", dir.display()),
        (false, false, true) => println!("程序已删除；正在运行的 anchor.exe 等这条命令结束后删，安装目录随后删除。"),
        (false, _, _) => println!("程序已删除；安装目录里还有别的文件，目录留着：{}", dir.display()),
    }
    // 5. PATH
    if matches!(on_path, Ok(true)) {
        match user_env(true).and_then(|k| remove_from_path(&k, &dir)) {
            Ok(true) => {
                announce_env_change();
                println!("已从用户的 PATH 里去掉安装目录。");
            }
            Ok(false) => {}
            Err(e) => println!("注意：PATH 没有改成（{e:#}）。自己从用户的 PATH 里去掉 {}", dir.display()),
        }
    }
    println!("卸载完成。数据目录留着：{}；不要了就自己删掉。", paths.home.display());
    if args.keep_guard {
        println!("特权服务和守卫规则没有动。要删规则：以管理员身份在 PowerShell 里运行 Remove-NetFirewallRule -Group 'AI Anchor Guard'");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install::PATH_VALUE as PV;
    use winreg::RegValue;
    use winreg::enums::{REG_EXPAND_SZ, REG_SZ};

    struct Dir(PathBuf);

    impl Dir {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("anchor-uninstall-{}", crate::util::random_hex()));
            std::fs::create_dir_all(&root).unwrap();
            Self(root)
        }

        fn put(&self, rel: &str) {
            let p = self.0.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, rel).unwrap();
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn rel(d: &Dir, v: &[PathBuf]) -> Vec<String> {
        v.iter().map(|p| p.strip_prefix(&d.0).unwrap().display().to_string()).collect()
    }

    #[test]
    fn where_to_uninstall_from() {
        let (to, agent, auto, def) = (Path::new(r"C:\to"), Path::new(r"C:\agent"), Path::new(r"C:\auto"), Path::new(r"C:\def"));
        let r = |a, b, c, d| find_dir(a, b, c, d).map_err(|e| e.to_string());
        assert_eq!(r(Some(to), Some(agent), Some(auto), Some(def)), Ok(to.into()));
        assert_eq!(r(None, Some(agent), Some(auto), Some(def)), Ok(agent.into()));
        assert_eq!(r(None, None, Some(auto), Some(def)), Ok(auto.into()));
        assert_eq!(r(None, None, None, Some(def)), Ok(def.into()));
        assert!(r(None, None, None, None).unwrap_err().contains("--to"), "不猜本程序所在的目录");
    }

    #[test]
    fn only_an_install_directory_is_accepted() {
        let d = Dir::new();
        assert!(check_dir(&d.0.join("nope")).unwrap_err().to_string().contains("不存在"));
        assert!(check_dir(&d.0).unwrap_err().to_string().contains("不像是安装目录"));
        d.put("anchor.exe");
        check_dir(&d.0).unwrap();
        // 编译目录：有 deps 之类的子目录
        std::fs::create_dir_all(d.0.join("deps")).unwrap();
        assert!(check_dir(&d.0).unwrap_err().to_string().contains("编译目录"));
    }

    #[test]
    fn only_what_ai_anchor_put_there_is_removed() {
        let d = Dir::new();
        for f in [
            "anchor.exe", "anchor-agent.exe", "anchor-svc.exe", "anchor.exe.old", "anchor-agent.exe.new",
            "anchor.exe.bak", "notes.txt",
            r"previous\anchor.exe", r"previous\anchor-agent.exe", r"previous\anchor-svc.exe", r"previous\replaced-by.txt", r"previous\anchor.exe.old",
            r"previous\mine.txt",
        ] {
            d.put(f);
        }
        std::fs::create_dir_all(d.0.join("sub")).unwrap();
        let f = inventory(&d.0);
        let mut ours = rel(&d, &f.ours);
        ours.sort();
        assert_eq!(
            ours,
            [
                "anchor-agent.exe", "anchor-agent.exe.new", "anchor-svc.exe", "anchor.exe", "anchor.exe.old",
                r"previous\anchor-agent.exe", r"previous\anchor-svc.exe", r"previous\anchor.exe", r"previous\anchor.exe.old", r"previous\replaced-by.txt",
            ]
        );
        assert_eq!(f.others, ["anchor.exe.bak", "notes.txt", "sub", r"previous\mine.txt"], "用户的 .bak、别的文件和目录都不碰");

        // 删：本程序删不掉，留到退出后
        let me = d.0.join("anchor.exe");
        let (later, failed) = delete(&f.ours, &me);
        assert_eq!(rel(&d, &later), ["anchor.exe"]);
        assert!(failed.is_empty());
        remove_empty_dirs(&d.0);
        assert!(d.0.join(PREVIOUS).join("mine.txt").exists() && d.0.join("anchor.exe.bak").exists() && d.0.join("anchor.exe").exists());
        assert_eq!(inventory(&d.0).ours.len(), 1, "只剩本程序");
    }

    #[test]
    fn an_empty_install_directory_goes_away() {
        let d = Dir::new();
        let dir = d.0.join("AIAnchor");
        for f in ["anchor.exe", "anchor-agent.exe", r"previous\anchor.exe", r"previous\replaced-by.txt"] {
            d.put(&format!(r"AIAnchor\{f}"));
        }
        let f = inventory(&dir);
        assert!(f.others.is_empty());
        let (later, failed) = delete(&f.ours, Path::new(r"C:\elsewhere\anchor.exe"));
        assert!(later.is_empty() && failed.is_empty());
        remove_empty_dirs(&dir);
        assert!(!dir.exists());
    }

    #[test]
    fn path_entries_are_removed_and_nothing_else_changes() {
        let dir = Path::new(r"C:\Users\u\AppData\Local\Programs\AIAnchor");
        assert_eq!(path_without(r"C:\tools;C:\x", dir), None, "不在里面");
        assert_eq!(path_without(r"C:\tools;C:\Users\u\AppData\Local\Programs\AIAnchor", dir), Some(r"C:\tools".into()));
        assert_eq!(path_without(r"C:\Users\u\AppData\Local\Programs\AIAnchor", dir), Some(String::new()));
        assert_eq!(
            path_without(r"  %USERPROFILE%\bin ;;c:\users\U\appdata\local\programs\aianchor\;C:\tools;", dir),
            Some(r"  %USERPROFILE%\bin ;;C:\tools;".into()),
            "写法不同也认；别的项、空项、结尾的分号原样留着"
        );
        assert_eq!(path_without(r#""C:\Users\u\AppData\Local\Programs\AIAnchor";A;C:/Users/u/AppData/Local/Programs/AIAnchor"#, dir), Some("A".into()), "出现几次去掉几次");
        assert_eq!(path_without(r"C:\Users\u\AppData\Local\Programs\AIAnchor2;C:\Users\u\AppData\Local\Programs", dir), None, "前缀相同不算");
    }

    /// 临时的注册表键（HKCU\Software 下，测完删掉）。用户真正的 PATH 和登录自启都不碰。
    struct TempKey {
        name: String,
        key: RegKey,
    }

    impl TempKey {
        fn new() -> Self {
            let name = format!(r"Software\AIAnchorTest-{}", crate::util::random_hex());
            let (key, _) = RegKey::predef(HKEY_CURRENT_USER).create_subkey(&name).unwrap();
            Self { name, key }
        }
    }

    impl Drop for TempKey {
        fn drop(&mut self) {
            let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&self.name);
        }
    }

    #[test]
    fn the_path_value_keeps_its_type() {
        let dir = Path::new(r"C:\x\AIAnchor");
        let t = TempKey::new();
        assert!(t.name.starts_with(r"Software\AIAnchorTest-"));
        assert!(!remove_from_path(&t.key, dir).unwrap(), "没有 Path");
        for vtype in [REG_SZ, REG_EXPAND_SZ] {
            write_path(&t.key, r"%USERPROFILE%\bin;C:\x\AIAnchor;C:\tools", vtype.clone()).unwrap();
            assert!(remove_from_path(&t.key, dir).unwrap());
            assert_eq!(read_path(&t.key).unwrap(), Some((r"%USERPROFILE%\bin;C:\tools".into(), vtype)));
            assert!(!remove_from_path(&t.key, dir).unwrap(), "第二次没有可去的，不写");
        }
        // 读不懂的不碰
        t.key.set_raw_value(PV, &RegValue { bytes: vec![1, 0, 0, 0].into(), vtype: winreg::enums::REG_DWORD }).unwrap();
        assert!(remove_from_path(&t.key, dir).is_err());
        assert_eq!(t.key.get_value::<u32, _>(PV).unwrap(), 1);
    }

    #[test]
    fn autostart_is_removed_only_when_it_points_here() {
        let dir = Path::new(r"C:\Users\u\AppData\Local\Programs\AIAnchor");
        let here = r#""C:\Users\u\AppData\Local\Programs\AIAnchor\anchor-agent.exe" --home "C:\Users\u\AppData\Local\AIAnchor""#;
        let there = r#""D:\other\anchor-agent.exe" --home "C:\Users\u\AppData\Local\AIAnchor""#;
        assert!(autostart_points_into(here, dir));
        assert!(autostart_points_into(&here.to_lowercase(), dir), "不分大小写");
        assert!(!autostart_points_into(there, dir));
        assert!(!autostart_points_into(r"C:\Users\u\AppData\Local\Programs\AIAnchor\anchor-agent.exe --home x", dir), "不是本程序写的格式");

        let t = TempKey::new();
        assert!(!remove_autostart(&t.key, dir).unwrap(), "没有设置");
        t.key.set_value(RUN_VALUE, &there).unwrap();
        assert!(!remove_autostart(&t.key, dir).unwrap());
        assert_eq!(t.key.get_value::<String, _>(RUN_VALUE).unwrap(), there, "指向别处的不动");
        t.key.set_value(RUN_VALUE, &here).unwrap();
        assert!(remove_autostart(&t.key, dir).unwrap());
        assert!(t.key.get_value::<String, _>(RUN_VALUE).is_err());
    }

    #[test]
    fn shortcuts_that_point_here() {
        let dir = Path::new(r"C:\Users\u\AppData\Local\Programs\AIAnchor");
        assert!(shortcut_is_ours(Path::new(r"C:\Users\u\AppData\Local\Programs\AIAnchor\anchor.exe"), dir));
        assert!(shortcut_is_ours(Path::new(r"c:\users\u\appdata\local\programs\aianchor\ANCHOR.EXE"), dir));
        assert!(!shortcut_is_ours(Path::new(r"D:\other\anchor.exe"), dir));
        assert!(!shortcut_is_ours(Path::new(r"C:\Users\u\AppData\Local\Programs\AIAnchor\anchor-agent.exe"), dir));
        assert!(!shortcut_is_ours(Path::new(""), dir));
    }
}
