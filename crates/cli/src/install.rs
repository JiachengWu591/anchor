//! anchor install：第一次安装。把新编译的程序复制到安装目录，再把安装目录加进用户的 PATH。
//!
//! - 只管程序文件和 PATH。sing-box、配置、登录自启、特权服务是后面的步骤，结束时列出来。
//! - 已经装过（目录里已有 anchor.exe 或 anchor-agent.exe）就拒绝：换成新版本是 anchor upgrade 的事，
//!   它会处理正在运行的用户代理，并把换下来的那一版留着。
//! - PATH 只在末尾加一项。别的项原样留着，注册表里原来是什么类型（REG_SZ / REG_EXPAND_SZ）还是什么类型；
//!   读不懂的（不是文字类型、不是合法的 UTF-16）不碰。

use crate::config::Paths;
use crate::upgrade::{REQUIRED, built, copy_whole, names, tidy, with_suffix};
use crate::util::{pad, same_path};
use crate::win::{expand_env, wide};
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use windows_sys::Win32::Foundation::LPARAM;
use windows_sys::Win32::UI::WindowsAndMessaging::{HWND_BROADCAST, SMTO_ABORTIFHUNG, SendMessageTimeoutW, WM_SETTINGCHANGE};
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_EXPAND_SZ, REG_SZ, RegType};
use winreg::{RegKey, RegValue};

pub struct Args {
    /// 安装目录；不写就是 %LOCALAPPDATA%\Programs\AIAnchor
    pub to: Option<PathBuf>,
    /// 不改 PATH
    pub no_path: bool,
    pub dry_run: bool,
}

/// 用户环境变量在注册表里的位置（HKEY_CURRENT_USER 下）。
const ENV_KEY: &str = "Environment";
const PATH_VALUE: &str = "Path";

fn default_dir() -> Result<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA").filter(|v| !v.is_empty()).context("没有环境变量 LOCALAPPDATA：用 --to 写明安装目录")?;
    Ok(PathBuf::from(base).join("Programs").join("AIAnchor"))
}

/// PATH 里的一项，整理成可以比较的样子：去掉引号和末尾的反斜杠，展开 %变量%，不分大小写。
fn norm(entry: &str) -> String {
    let e = expand_env(entry.trim().trim_matches('"'), &[]);
    e.replace('/', "\\").trim_end_matches('\\').to_lowercase()
}

fn path_has(value: &str, dir: &Path) -> bool {
    let want = norm(&dir.to_string_lossy());
    value.split(';').any(|e| !e.trim().is_empty() && norm(e) == want)
}

/// 在末尾加一项。原来的内容一个字都不改。
fn path_with(value: &str, dir: &Path) -> String {
    let dir = dir.to_string_lossy();
    if value.is_empty() {
        dir.into_owned()
    } else if value.ends_with(';') {
        format!("{value}{dir}")
    } else {
        format!("{value};{dir}")
    }
}

/// 注册表里的 Path：内容和类型。没有这一项时返回 None。读不懂的报错，不猜。
fn read_path(key: &RegKey) -> Result<Option<(String, RegType)>> {
    let v = match key.get_raw_value(PATH_VALUE) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).context("读不了注册表里的 Path"),
    };
    if !matches!(v.vtype, REG_SZ | REG_EXPAND_SZ) {
        bail!("注册表里的 Path 不是文字类型（{:?}）", v.vtype);
    }
    if v.bytes.len() % 2 != 0 {
        bail!("注册表里的 Path 长度不对（{} 字节）", v.bytes.len());
    }
    let units: Vec<u16> = v.bytes.chunks_exact(2).map(|b| u16::from_le_bytes([b[0], b[1]])).collect();
    // 结尾的 0 不算内容；中间不该有 0
    let end = units.iter().rposition(|u| *u != 0).map_or(0, |i| i + 1);
    let text = String::from_utf16(&units[..end]).ok().filter(|s| !s.contains('\0')).context("注册表里的 Path 不是合法的文字")?;
    Ok(Some((text, v.vtype)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathChange {
    Added,
    Already,
}

/// 把目录加进这个注册表键里的 Path（已经有了就不动）。键由调用方给：正式用的是用户的环境变量，测试用的是一个临时的键。
fn add_to_path(key: &RegKey, dir: &Path) -> Result<PathChange> {
    if dir.to_string_lossy().contains(';') {
        bail!("目录名里有分号，放不进 PATH：{}", dir.display());
    }
    // 原来没有这一项时新建成 REG_EXPAND_SZ，和系统自己建的一样
    let (old, vtype) = read_path(key)?.unwrap_or((String::new(), REG_EXPAND_SZ));
    if path_has(&old, dir) {
        return Ok(PathChange::Already);
    }
    let new = path_with(&old, dir);
    let bytes: Vec<u8> = new.encode_utf16().chain(std::iter::once(0)).flat_map(u16::to_le_bytes).collect();
    key.set_raw_value(PATH_VALUE, &RegValue { bytes: bytes.into(), vtype }).context("写不了注册表里的 Path")?;
    Ok(PathChange::Added)
}

fn user_env(write: bool) -> Result<RegKey> {
    let flags = if write { KEY_READ | KEY_WRITE } else { KEY_READ };
    RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(ENV_KEY, flags).context("打不开用户的环境变量（注册表 HKCU\\Environment）")
}

/// 告诉正在运行的程序“环境变量变了”：资源管理器收到后，之后从它启动的终端才看得到新的 PATH。
fn announce_env_change() {
    let what = wide("Environment");
    let mut result = 0usize;
    unsafe { SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, what.as_ptr() as LPARAM, SMTO_ABORTIFHUNG, 2000, &mut result) };
}

/// 先都复制成 .new，都复制完再改成正式的名字。中途出错，把这次放进去的都拿掉。
fn install_files(from: &Path, to: &Path, files: &[&'static str]) -> Result<()> {
    let made_dir = !to.exists();
    std::fs::create_dir_all(to).with_context(|| format!("建不了目录 {}", to.display()))?;
    let undo = |placed: &[&str]| {
        for name in files {
            let _ = std::fs::remove_file(with_suffix(to, name, ".new"));
        }
        for name in placed {
            let _ = std::fs::remove_file(to.join(name));
        }
        if made_dir {
            // 空的才删得掉
            let _ = std::fs::remove_dir(to);
        }
    };
    for name in files {
        if let Err(e) = copy_whole(&from.join(name), &with_suffix(to, name, ".new"), name) {
            undo(&[]);
            return Err(e);
        }
    }
    let mut placed: Vec<&str> = Vec::new();
    for name in files {
        if let Err(e) = std::fs::rename(with_suffix(to, name, ".new"), to.join(name)) {
            undo(&placed);
            return Err(e).with_context(|| format!("放不进 {name}"));
        }
        placed.push(name);
    }
    Ok(())
}

/// 能不能装：本程序旁边要有完整的一套，目标不能是本程序所在的目录，也不能已经装过。
fn check(here: &Path, to: &Path) -> Result<Vec<&'static str>> {
    for name in REQUIRED {
        if !here.join(name).is_file() {
            bail!(
                "{} 里没有 {name}：要运行编译出来的那个 anchor.exe（先运行 cargo build --release --workspace）",
                here.display()
            );
        }
    }
    if same_path(here, to) {
        bail!(
            "安装目录就是本程序所在的目录（{}），没有什么可复制的。要装到别处，用 --to 写明；这里如果已经是装好的那一份，换新版本要运行新编译出来的那个 anchor.exe upgrade",
            to.display()
        );
    }
    if let Some(name) = REQUIRED.into_iter().find(|name| to.join(name).exists()) {
        bail!(
            "{} 里已经有 {name}：已经装过了，没有做任何改动。换成新编译的版本用 anchor upgrade（在这里运行：{} upgrade）",
            to.display(),
            here.join("anchor.exe").display()
        );
    }
    Ok(names().filter(|name| here.join(name).is_file()).collect())
}

/// 装完之后还要做的事。已经有的（sing-box、配置）标出来。
fn next_steps(paths: &Paths, to: &Path, on_path: bool) -> Vec<String> {
    let have = |p: PathBuf| if p.is_file() { "（已经有了，跳过）" } else { "" };
    let mut v = Vec::new();
    if on_path {
        v.push("接下来（新开一个终端，anchor 这个命令才认得）：".to_string());
    } else {
        v.push(format!("接下来（安装目录不在 PATH 里：下面的 anchor 要写成 {}）：", to.join("anchor.exe").display()));
    }
    let sb = paths.bin_dir().join("sing-box.exe");
    v.push(format!("  1. 下载 sing-box 的 Windows 版，把 sing-box.exe 放到 {}{}", paths.bin_dir().display(), have(sb)));
    v.push(format!("  2. anchor init，然后编辑 {}，填你自己的出口；anchor gen 检查配置{}", paths.config().display(), have(paths.config())));
    v.push("  3. anchor agent install    设置登录自启并立即启动（托盘里出现图标）".to_string());
    v.push("  4. anchor baseline         登记出口基线；anchor check 体检".to_string());
    v.push("  5. anchor service install  安装特权服务（弹出管理员确认）".to_string());
    v
}

pub fn run(paths: &Paths, args: &Args) -> Result<()> {
    let me = std::env::current_exe()?;
    let here = tidy(me.parent().context("无法确定程序目录")?);
    let to = tidy(&match &args.to {
        Some(t) => t.clone(),
        None => default_dir()?,
    });
    let files = check(&here, &to)?;

    // PATH 现在的情况只读一遍；读不了不拦着装文件，照实说
    let already = if args.no_path { Ok(false) } else { user_env(false).and_then(|k| read_path(&k)).map(|v| v.is_some_and(|(text, _)| path_has(&text, &to))) };

    println!("安装 AI Anchor");
    println!("  新程序  {}", here.display());
    println!("  安装到  {}", to.display());
    for name in &files {
        println!("  {}安装（编译于 {}）", pad(name, 18), built(&here.join(name)));
    }
    let label = pad("用户的 PATH", 18);
    match (&already, args.no_path) {
        (_, true) => println!("  {label}不改（--no-path）"),
        (Ok(true), _) => println!("  {label}已经有安装目录，不改"),
        (Ok(false), _) => println!("  {label}在末尾加上安装目录"),
        (Err(e), _) => println!("  {label}读不了（{e:#}），不改"),
    }
    if args.dry_run {
        println!("（预览，没有做任何改动。去掉 --dry-run 执行）");
        return Ok(());
    }

    install_files(&here, &to, &files)?;
    println!("程序已复制到 {}", to.display());

    let on_path = match (already, args.no_path) {
        (_, true) => false,
        (Ok(true), _) => true,
        (Err(_), _) => false,
        (Ok(false), _) => match user_env(true).and_then(|k| add_to_path(&k, &to)) {
            Ok(change) => {
                if change == PathChange::Added {
                    announce_env_change();
                    println!("已把安装目录加进用户的 PATH。已经开着的终端看不到，要新开一个。");
                }
                true
            }
            Err(e) => {
                println!("注意：PATH 没有改成（{e:#}）。程序已经装好；要用 anchor 这个命令，自己把 {} 加进 PATH。", to.display());
                false
            }
        },
    };
    for line in next_steps(paths, &to, on_path) {
        println!("{line}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Dirs {
        root: PathBuf,
        from: PathBuf,
        to: PathBuf,
    }

    impl Dirs {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("anchor-install-{}", crate::util::random_hex()));
            let (from, to) = (root.join("build"), root.join("Programs").join("AIAnchor"));
            std::fs::create_dir_all(&from).unwrap();
            Self { root, from, to }
        }

        fn built(self, names: &[&str]) -> Self {
            for n in names {
                std::fs::write(self.from.join(n), format!("{n} 1")).unwrap();
            }
            self
        }
    }

    impl Drop for Dirs {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn list(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        v.sort();
        v
    }

    const ALL: [&str; 3] = ["anchor.exe", "anchor-agent.exe", "anchor-svc.exe"];

    #[test]
    fn installs_into_a_directory_that_does_not_exist_yet() {
        let d = Dirs::new().built(&ALL);
        std::fs::write(d.from.join("anchor.pdb"), "别的文件不带").unwrap();
        let files = check(&d.from, &d.to).unwrap();
        assert_eq!(files, ALL);
        install_files(&d.from, &d.to, &files).unwrap();
        assert_eq!(list(&d.to), ["anchor-agent.exe", "anchor-svc.exe", "anchor.exe"], "不留 .new，不带别的文件");
        assert_eq!(std::fs::read_to_string(d.to.join("anchor-agent.exe")).unwrap(), "anchor-agent.exe 1");

        // 没有编译服务程序：装两个
        let d = Dirs::new().built(&ALL[..2]);
        let files = check(&d.from, &d.to).unwrap();
        install_files(&d.from, &d.to, &files).unwrap();
        assert_eq!(list(&d.to), ["anchor-agent.exe", "anchor.exe"]);
    }

    #[test]
    fn refuses_what_is_not_a_first_install() {
        let why = |d: &Dirs| check(&d.from, &d.to).unwrap_err().to_string();
        // 本程序旁边不是完整的一套
        let d = Dirs::new().built(&["anchor.exe"]);
        assert!(why(&d).contains("没有 anchor-agent.exe"));
        // 已经装过：哪怕只有其中一个程序
        let d = Dirs::new().built(&ALL);
        std::fs::create_dir_all(&d.to).unwrap();
        assert!(check(&d.from, &d.to).is_ok(), "目录在、里面是空的，可以装");
        std::fs::write(d.to.join("anchor-agent.exe"), "装过的").unwrap();
        let err = why(&d);
        assert!(err.contains("已经装过了") && err.contains("anchor upgrade") && err.contains("没有做任何改动"), "{err}");
        assert_eq!(list(&d.to), ["anchor-agent.exe"]);
        // 装到本程序所在的目录
        assert!(check(&d.from, &d.from).unwrap_err().to_string().contains("就是本程序所在的目录"));
    }

    #[test]
    fn a_failed_install_leaves_nothing_behind() {
        // 目标目录原来不存在：连目录都不留
        let d = Dirs::new().built(&ALL);
        let files = check(&d.from, &d.to).unwrap();
        std::fs::remove_file(d.from.join("anchor-svc.exe")).unwrap();
        assert!(install_files(&d.from, &d.to, &files).unwrap_err().to_string().contains("anchor-svc.exe"));
        assert!(!d.to.exists());
        // 目标目录原来就有、里面有别人的文件：只拿掉这次放的
        let d = Dirs::new().built(&ALL);
        std::fs::create_dir_all(&d.to).unwrap();
        std::fs::write(d.to.join("notes.txt"), "原来就有的").unwrap();
        let files = check(&d.from, &d.to).unwrap();
        std::fs::remove_file(d.from.join("anchor-svc.exe")).unwrap();
        assert!(install_files(&d.from, &d.to, &files).is_err());
        assert_eq!(list(&d.to), ["notes.txt"]);
    }

    #[test]
    fn path_entries_are_compared_loosely_and_appended_exactly() {
        let dir = Path::new(r"C:\Users\u\AppData\Local\Programs\AIAnchor");
        let other = r"C:\Windows\system32;C:\tools";
        assert!(!path_has(other, dir) && !path_has("", dir));
        assert!(path_has(r"C:\tools;C:\Users\u\AppData\Local\Programs\AIAnchor", dir));
        assert!(path_has(r"c:\users\U\appdata\local\programs\aianchor\;C:\tools", dir), "不分大小写，不管末尾的反斜杠");
        assert!(path_has(r#"C:\tools;"C:\Users\u\AppData\Local\Programs\AIAnchor""#, dir), "带引号的");
        assert!(path_has("C:/Users/u/AppData/Local/Programs/AIAnchor", dir), "正斜杠");
        assert!(!path_has(r"C:\Users\u\AppData\Local\Programs\AIAnchor2;C:\Users\u\AppData\Local\Programs", dir), "只是前缀相同不算");
        // 写成 %变量% 的也认：用一个本进程里肯定有的变量
        let root = std::env::var("SystemRoot").unwrap();
        assert!(path_has(r"%SystemRoot%\System32", &Path::new(&root).join("system32")));

        assert_eq!(path_with("", dir), r"C:\Users\u\AppData\Local\Programs\AIAnchor");
        assert_eq!(path_with(other, dir), format!(r"{other};C:\Users\u\AppData\Local\Programs\AIAnchor"));
        assert_eq!(path_with(r"C:\tools;", dir), r"C:\tools;C:\Users\u\AppData\Local\Programs\AIAnchor", "原来以分号结尾：不多加一个");
        assert_eq!(path_with(r"  %USERPROFILE%\bin ;;C:\x", dir), format!(r"  %USERPROFILE%\bin ;;C:\x;{}", dir.display()), "原来的内容一个字都不改");
    }

    /// 在注册表里建一个临时的键来试（HKCU\Software 下，测完删掉）。用户真正的环境变量在 HKCU\Environment，这里不碰。
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

        fn set(&self, text: &str, vtype: RegType) {
            let bytes: Vec<u8> = text.encode_utf16().chain(std::iter::once(0)).flat_map(u16::to_le_bytes).collect();
            self.key.set_raw_value(PATH_VALUE, &RegValue { bytes: bytes.into(), vtype }).unwrap();
        }
    }

    impl Drop for TempKey {
        fn drop(&mut self) {
            let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&self.name);
        }
    }

    #[test]
    fn the_registry_value_keeps_its_type_and_its_other_entries() {
        assert_ne!(ENV_KEY, "", "正式用的键");
        let dir = Path::new(r"C:\Users\u\AppData\Local\Programs\AIAnchor");
        let t = TempKey::new();
        assert!(t.name.starts_with(r"Software\AIAnchorTest-"), "不是用户的环境变量");

        // 原来没有 Path：新建成 REG_EXPAND_SZ
        assert_eq!(read_path(&t.key).unwrap(), None);
        assert_eq!(add_to_path(&t.key, dir).unwrap(), PathChange::Added);
        assert_eq!(read_path(&t.key).unwrap(), Some((dir.display().to_string(), REG_EXPAND_SZ)));
        assert_eq!(add_to_path(&t.key, dir).unwrap(), PathChange::Already, "再来一次什么都不做");

        // 原来是 REG_EXPAND_SZ、带 %变量%：类型不变，原来的内容原样在前面
        let old = r"%USERPROFILE%\.cargo\bin;C:\tools;";
        t.set(old, REG_EXPAND_SZ);
        assert_eq!(add_to_path(&t.key, dir).unwrap(), PathChange::Added);
        assert_eq!(read_path(&t.key).unwrap(), Some((format!("{old}{}", dir.display()), REG_EXPAND_SZ)));
        let raw = t.key.get_raw_value(PATH_VALUE).unwrap();
        assert_eq!(&raw.bytes[raw.bytes.len() - 2..], [0, 0], "结尾有且只有一个 0");
        assert_ne!(&raw.bytes[raw.bytes.len() - 4..raw.bytes.len() - 2], [0, 0]);

        // 原来是 REG_SZ：还是 REG_SZ
        t.set(r"C:\tools", REG_SZ);
        assert_eq!(add_to_path(&t.key, dir).unwrap(), PathChange::Added);
        assert_eq!(read_path(&t.key).unwrap(), Some((format!(r"C:\tools;{}", dir.display()), REG_SZ)));

        // 已经在里面（写法不同）：不动
        t.set(r"C:\tools;c:\users\u\appdata\local\programs\aianchor\", REG_SZ);
        assert_eq!(add_to_path(&t.key, dir).unwrap(), PathChange::Already);
        assert_eq!(read_path(&t.key).unwrap().unwrap().0, r"C:\tools;c:\users\u\appdata\local\programs\aianchor\");
    }

    #[test]
    fn a_path_value_that_cannot_be_read_is_left_alone() {
        let dir = Path::new(r"C:\x\AIAnchor");
        let t = TempKey::new();
        // 不是文字类型
        t.key.set_value(PATH_VALUE, &7u32).unwrap();
        assert!(add_to_path(&t.key, dir).unwrap_err().to_string().contains("不是文字类型"));
        assert_eq!(t.key.get_value::<u32, _>(PATH_VALUE).unwrap(), 7);
        // 不是合法的 UTF-16（落单的代理项）
        let bad: Vec<u8> = [0x0043u16, 0xD800, 0x0044, 0].into_iter().flat_map(u16::to_le_bytes).collect();
        t.key.set_raw_value(PATH_VALUE, &RegValue { bytes: bad.clone().into(), vtype: REG_SZ }).unwrap();
        assert!(add_to_path(&t.key, dir).is_err());
        assert_eq!(t.key.get_raw_value(PATH_VALUE).unwrap().bytes.to_vec(), bad, "原样留着");
        // 目录名里有分号
        t.set(r"C:\tools", REG_SZ);
        assert!(add_to_path(&t.key, Path::new(r"C:\a;b")).unwrap_err().to_string().contains("分号"));
        assert_eq!(read_path(&t.key).unwrap().unwrap().0, r"C:\tools");
    }

    #[test]
    fn what_is_left_to_do_after_installing() {
        let d = Dirs::new();
        let paths = Paths { home: d.root.join("home") };
        let text = next_steps(&paths, &d.to, true).join("\n");
        assert!(text.contains("新开一个终端") && text.contains("sing-box.exe") && text.contains("anchor init") && text.contains("anchor service install"), "{text}");
        assert!(!text.contains("跳过"));
        // 配置和 sing-box 已经有了：标出来
        std::fs::create_dir_all(paths.bin_dir()).unwrap();
        std::fs::write(paths.bin_dir().join("sing-box.exe"), "x").unwrap();
        std::fs::write(paths.config(), "x").unwrap();
        let text = next_steps(&paths, &d.to, false).join("\n");
        assert_eq!(text.matches("已经有了，跳过").count(), 2, "{text}");
        assert!(text.contains("不在 PATH 里") && text.contains(&d.to.join("anchor.exe").display().to_string()));
    }
}
