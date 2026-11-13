//! 发现本机 AI 程序：桌面客户端（MSIX / Squirrel / 普通安装）和命令行工具。

use crate::ps;
use crate::util::{exists_any, same_path};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Desktop,
    Cli,
}

#[derive(Debug, Clone)]
pub struct Found {
    /// 配置里使用的名称，如 claude-desktop、claude
    pub id: &'static str,
    pub label: &'static str,
    pub kind: Kind,
    /// 真正联网的程序（守卫规则、运行中检测按它匹配）
    pub exe: PathBuf,
    /// 启动时执行的程序（MSIX 应用用执行别名，才能带参数并保持包身份）
    pub launcher: PathBuf,
    pub guardable: bool,
    pub note: String,
}

fn env_dir(var: &str) -> Option<PathBuf> {
    std::env::var_os(var).map(PathBuf::from)
}

/// MSIX 包从哪里查。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsixSource {
    /// 当前用户已登记的包（Get-AppxPackage）
    CurrentUser,
    /// 本机所有版本（HKLM 包仓库，只有管理员可写），只取文件仍存在的；供特权服务使用
    Machine,
    /// 不查（测试用）
    Skip,
}

/// 扫描的起点。命令行和用户代理用当前进程的环境；特权服务按登记用户的配置文件目录构造。
#[derive(Debug, Clone)]
pub struct Roots {
    /// %LOCALAPPDATA%
    pub local: Option<PathBuf>,
    /// %APPDATA%
    pub roaming: Option<PathBuf>,
    /// %USERPROFILE%
    pub profile: Option<PathBuf>,
    /// 查找命令行工具的目录（PATH）
    pub path_dirs: Vec<PathBuf>,
    pub msix: MsixSource,
}

impl Roots {
    pub fn current() -> Self {
        Self {
            local: env_dir("LOCALAPPDATA"),
            roaming: env_dir("APPDATA"),
            profile: env_dir("USERPROFILE"),
            path_dirs: std::env::var_os("PATH").map(|p| std::env::split_paths(&p).collect()).unwrap_or_default(),
            msix: MsixSource::CurrentUser,
        }
    }

    pub fn for_profile(profile: &Path, path_dirs: Vec<PathBuf>) -> Self {
        Self {
            local: Some(profile.join("AppData").join("Local")),
            roaming: Some(profile.join("AppData").join("Roaming")),
            profile: Some(profile.to_path_buf()),
            path_dirs,
            msix: MsixSource::Machine,
        }
    }
}

pub fn scan() -> Vec<Found> {
    scan_with(&Roots::current())
}

pub fn scan_with(r: &Roots) -> Vec<Found> {
    let mut out: Vec<Found> = Vec::new();
    let local = r.local.clone();
    let alias = |name: &str| -> Option<PathBuf> {
        let p = local.as_ref()?.join("Microsoft").join("WindowsApps").join(name);
        exists_any(&p).then_some(p)
    };
    let machine = r.msix == MsixSource::Machine;

    // 1. MSIX 包（微软商店 / 官方 MSIX 安装包）
    let packages = match r.msix {
        MsixSource::CurrentUser => msix_packages(),
        MsixSource::Machine => machine_packages(),
        MsixSource::Skip => vec![],
    };
    for (name, loc) in packages {
        if name == "Claude" {
            let exe = loc.join("app").join("Claude.exe");
            if machine && !exists_any(&exe) {
                continue;
            }
            out.push(Found {
                id: "claude-desktop",
                label: "Claude 桌面版",
                kind: Kind::Desktop,
                launcher: alias("claude-desktop.exe").unwrap_or_else(|| exe.clone()),
                exe,
                guardable: true,
                note: "MSIX 安装：应用更新后路径会变；装了特权服务时守卫自动刷新".into(),
            });
        } else if name.starts_with("OpenAI.") {
            let exe = loc.join("app").join("ChatGPT.exe");
            if exists_any(&exe) {
                out.push(Found {
                    id: "chatgpt-desktop",
                    label: "ChatGPT 桌面版",
                    kind: Kind::Desktop,
                    launcher: alias("chatgpt-desktop.exe").unwrap_or_else(|| exe.clone()),
                    exe,
                    guardable: true,
                    note: format!("MSIX 包 {name}：应用更新后路径会变；装了特权服务时守卫自动刷新"),
                });
            }
        }
    }

    if let Some(local) = &local {
        // 2. 旧版 Claude 桌面（Squirrel 安装到 %LOCALAPPDATA%\AnthropicClaude\app-x.y.z）
        let root = local.join("AnthropicClaude");
        let stub = root.join("claude.exe");
        for dir in subdirs(&root).into_iter().filter(|d| file_name(d).starts_with("app-")) {
            let exe = dir.join("claude.exe");
            if exists_any(&exe) {
                out.push(Found {
                    id: "claude-desktop",
                    label: "Claude 桌面版",
                    kind: Kind::Desktop,
                    launcher: if exists_any(&stub) { stub.clone() } else { exe.clone() },
                    exe,
                    guardable: true,
                    note: "Squirrel 安装：版本目录随更新变化；装了特权服务时守卫自动刷新".into(),
                });
            }
        }

        // 3. Cursor
        let cursor = local.join("Programs").join("cursor").join("Cursor.exe");
        if exists_any(&cursor) {
            out.push(Found {
                id: "cursor",
                label: "Cursor",
                kind: Kind::Desktop,
                launcher: cursor.clone(),
                exe: cursor,
                guardable: true,
                note: String::new(),
            });
        }

        // 4. Claude 桌面版内置的 Claude Code（Code 标签页使用），默认不纳入
        let mut roots = vec![local.join("Claude-Data")];
        roots.extend(r.roaming.as_ref().map(|d| d.join("Claude")));
        for root in roots {
            for exe in find_files(&root, |n| n.eq_ignore_ascii_case("claude.exe"), 4)
                .into_iter()
                .filter(|p| p.to_string_lossy().to_lowercase().contains("claude-code"))
            {
                out.push(Found {
                    id: "claude-desktop-code",
                    label: "Claude 桌面版内置的 Claude Code",
                    kind: Kind::Cli,
                    launcher: exe.clone(),
                    exe,
                    guardable: true,
                    note: "由桌面版启动，不读启动参数；需在 ~/.claude/settings.json 的 env 里设置 HTTPS_PROXY 才走通道。默认不纳入守卫".into(),
                });
            }
        }
    }

    // 5. Claude Code 原生安装
    if let Some(home) = &r.profile {
        let native = home.join(".local").join("bin").join("claude.exe");
        if exists_any(&native) {
            push_cli(&mut out, "claude", "Claude Code", native);
        }
    }
    // 6. PATH 里的 claude / codex
    for p in which_in("claude", &r.path_dirs) {
        push_cli(&mut out, "claude", "Claude Code", p);
    }
    for p in which_in("codex", &r.path_dirs) {
        push_cli(&mut out, "codex", "Codex CLI", p);
    }
    // 7. npm 安装的 Codex：node 包装器会启动随包附带的原生 codex.exe，守卫它
    if let Some(appdata) = &r.roaming {
        let pkg = appdata.join("npm").join("node_modules").join("@openai").join("codex");
        for exe in find_files(&pkg, |n| n.to_lowercase().starts_with("codex") && n.to_lowercase().ends_with(".exe"), 6) {
            push_cli(&mut out, "codex", "Codex CLI（npm 附带的原生程序）", exe);
        }
    }
    out
}

fn push_cli(out: &mut Vec<Found>, id: &'static str, label: &'static str, exe: PathBuf) {
    if out.iter().any(|f| same_path(&f.exe, &exe)) {
        return;
    }
    let (guardable, note) = classify(&exe);
    out.push(Found { id, label, kind: Kind::Cli, launcher: exe.clone(), exe, guardable, note });
}

/// 判断一个可执行文件能否按路径守卫：脚本、shim、node 进程真正联网的不是它自己。
pub fn classify(p: &Path) -> (bool, String) {
    let lower = p.to_string_lossy().to_lowercase().replace('/', "\\");
    let name = file_name(p).to_lowercase();
    if [".cmd", ".bat", ".ps1"].iter().any(|e| name.ends_with(e)) {
        return (false, "脚本包装器：真正联网的是它启动的程序（npm 安装的通常是 node），只能靠 anchor run 注入代理".into());
    }
    if lower.contains("\\shims\\") {
        return (false, "版本管理器的 shim：真正联网的是它启动的程序；改用实际安装路径，或只用 anchor run".into());
    }
    if name == "node.exe" || lower.contains("\\node_modules\\") && !name.starts_with("codex") {
        return (false, "Node 进程无法按程序区分，只能靠 anchor run 注入代理".into());
    }
    (true, String::new())
}

/// 已安装的相关 MSIX 包：(包名, 安装目录)。
fn msix_packages() -> Vec<(String, PathBuf)> {
    let script = "Get-AppxPackage | Where-Object { $_.Name -eq 'Claude' -or $_.Name -like 'OpenAI.*' } | \
                  ForEach-Object { '{0}|{1}' -f $_.Name, $_.InstallLocation }";
    let Ok(text) = ps::run_ok(script) else { return vec![] };
    parse_packages(&text)
}

const PACKAGE_REPOSITORY: &str =
    r"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages";

/// 本机 HKLM 包仓库登记的相关包（所有用户、所有仍登记的版本）：(包名, 安装目录)。
/// 读不到时退回 Get-AppxPackage -AllUsers（需要管理员）。
pub fn machine_packages() -> Vec<(String, PathBuf)> {
    let from_registry = || -> Option<Vec<(String, PathBuf)>> {
        let key = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE).open_subkey(PACKAGE_REPOSITORY).ok()?;
        let mut out = Vec::new();
        for full in key.enum_keys().flatten() {
            let name = full.split('_').next().unwrap_or_default().to_string();
            if !relevant_package(&name) {
                continue;
            }
            if let Ok(path) = key.open_subkey(&full).and_then(|k| k.get_value::<String, _>("Path")) {
                out.push((name, PathBuf::from(path)));
            }
        }
        Some(out)
    };
    if let Some(v) = from_registry() {
        return v;
    }
    let script = "Get-AppxPackage -AllUsers | Where-Object { $_.Name -eq 'Claude' -or $_.Name -like 'OpenAI.*' } | \
                  ForEach-Object { '{0}|{1}' -f $_.Name, $_.InstallLocation }";
    parse_packages(&ps::run_ok(script).unwrap_or_default())
}

/// 包仓库在 HKLM 的位置，供特权服务监视应用安装和更新。
pub fn package_repository_key() -> &'static str {
    PACKAGE_REPOSITORY
}

fn relevant_package(name: &str) -> bool {
    name == "Claude" || name.starts_with("OpenAI.")
}

fn parse_packages(text: &str) -> Vec<(String, PathBuf)> {
    text.lines()
        .filter_map(|l| l.trim().split_once('|'))
        .filter(|(n, loc)| !n.is_empty() && !loc.is_empty())
        .map(|(n, loc)| (n.to_string(), PathBuf::from(loc)))
        .collect()
}

/// 按 PATH 和 PATHEXT 查找命令，返回所有命中。
pub fn which_all(name: &str) -> Vec<PathBuf> {
    let dirs: Vec<PathBuf> = std::env::var_os("PATH").map(|p| std::env::split_paths(&p).collect()).unwrap_or_default();
    which_in(name, &dirs)
}

pub fn which_in(name: &str, dirs: &[PathBuf]) -> Vec<PathBuf> {
    let exts: Vec<String> = std::env::var("PATHEXT")
        .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into())
        .split(';')
        .filter(|e| !e.is_empty())
        .map(str::to_lowercase)
        .collect();
    let mut out: Vec<PathBuf> = Vec::new();
    for dir in dirs {
        for ext in &exts {
            let p = dir.join(format!("{name}{ext}"));
            if p.is_file() && !out.iter().any(|q| same_path(q, &p)) {
                out.push(p);
            }
        }
    }
    out
}

/// 当前是否有以该程序运行的进程。
pub fn running(exe: &Path) -> bool {
    let stem = exe.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let script = format!(
        "Get-Process -Name {} -ErrorAction SilentlyContinue | ForEach-Object {{ $_.Path }}",
        ps::quote(&stem)
    );
    ps::run_ok(&script)
        .map(|t| t.lines().any(|l| same_path(Path::new(l.trim()), exe)))
        .unwrap_or(false)
}

fn file_name(p: &Path) -> String {
    p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

fn subdirs(p: &Path) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(p) else { return vec![] };
    let mut v: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
    v.sort();
    v
}

fn find_files(root: &Path, pred: impl Fn(&str) -> bool + Copy, depth: usize) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(root) else { return out };
    for e in rd.flatten() {
        let p = e.path();
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_dir() && depth > 0 {
            out.extend(find_files(&p, pred, depth - 1));
        } else if ft.is_file() && pred(&file_name(&p)) {
            out.push(p);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_wrappers_and_natives() {
        assert!(!classify(Path::new(r"C:\Users\u\AppData\Roaming\npm\claude.cmd")).0);
        assert!(!classify(Path::new(r"C:\Users\u\AppData\Local\mise\shims\claude.exe")).0);
        assert!(!classify(Path::new(r"C:\Program Files\nodejs\node.exe")).0);
        assert!(classify(Path::new(r"C:\Users\u\.local\bin\claude.exe")).0);
        assert!(classify(Path::new(
            r"C:\Users\u\AppData\Roaming\npm\node_modules\@openai\codex\vendor\x86_64-pc-windows-msvc\codex\codex.exe"
        ))
        .0);
    }

    #[test]
    fn scan_with_finds_apps_under_a_given_profile() {
        let home = std::env::temp_dir().join(format!("anchor-scan-{}", crate::util::random_hex()));
        let touch = |rel: &str| {
            let p = home.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, b"").unwrap();
        };
        touch(r"AppData\Local\Programs\cursor\Cursor.exe");
        touch(r".local\bin\claude.exe");
        touch(r"AppData\Local\Claude-Data\x\claude-code\2.1.0\claude.exe");
        let mut roots = Roots::for_profile(&home, vec![]);
        roots.msix = MsixSource::Skip;
        let found = scan_with(&roots);
        let ids: Vec<&str> = found.iter().map(|f| f.id).collect();
        assert_eq!(ids, ["cursor", "claude-desktop-code", "claude"]);
        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn package_names_are_filtered() {
        assert!(relevant_package("Claude"));
        assert!(relevant_package("OpenAI.Codex"));
        assert!(!relevant_package("ClaudeX"));
        assert_eq!(parse_packages("Claude|C:\\p\n|x\n"), vec![("Claude".to_string(), PathBuf::from("C:\\p"))]);
    }
}
