//! 在 MSIX 应用（例如 Claude 桌面版）的终端里运行时的保护。
//!
//! 应用包里的进程写 %LOCALAPPDATA% 时，新文件会被 Windows 重定向到该应用的私有目录；
//! 从包里启动的程序也留在包里。特权服务、登录自启和普通终端都看不到这些文件，
//! 所以这类命令在包里一律拒绝，只读的命令照常运行。

use crate::config::Paths;
use crate::win::{self, Package};
use anyhow::{Context, Result};
use std::path::Path;

/// 命令行原样（用于提示用户到别的终端重新运行）。
fn shown_args() -> String {
    std::env::args()
        .skip(1)
        .filter(|a| a != "--pause")
        .map(|a| if a.contains(' ') { format!("\"{a}\"") } else { a })
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn refuse(pkg: &Package) -> anyhow::Error {
    let app = pkg.app();
    anyhow::anyhow!(
        "不能在 {app} 的终端里运行这条命令。\n\n\
         当前终端运行在 MSIX 应用 {app} 里面（应用包 {full}）。在这里：\n\
         \x20 - 写到 %LOCALAPPDATA% 的新文件会被 Windows 重定向到 {app} 的私有目录，特权服务、登录自启和普通终端都看不到；\n\
         \x20 - 启动的用户代理和 AI 程序也会留在 {app} 的环境里，读写同样被重定向。\n\n\
         请从开始菜单打开 PowerShell 或 Windows Terminal，在那里运行：\n\
         \x20 anchor {args}\n\n\
         查看类命令（status、timeline、check、guard status、agent status）在这里可以照常运行。",
        full = pkg.full_name,
        args = shown_args(),
    )
}

/// 数据目录在某个 MSIX 应用的私有目录里有副本时提醒（多半是在该应用的终端里运行过 anchor init）。
pub fn warn_private_copies(paths: &Paths) {
    let copies = win::private_copies(&paths.home);
    if copies.is_empty() {
        return;
    }
    eprintln!("注意：数据目录有一份副本在 MSIX 应用的私有目录里，特权服务和登录自启的用户代理看不到它：");
    for c in &copies {
        eprintln!("  {}", c.display());
    }
    eprintln!("这通常是在 Claude 桌面版等应用的终端里运行过 anchor init。");
    eprintln!("处理办法：在开始菜单打开的终端（cmd 或 PowerShell 都行）里运行 anchor repair，把它合并回 {}。", paths.home.display());
    eprintln!();
}

/// 副本所属的应用包目录名，如 Claude_pzs8sxrjxfjjc。
fn package_of(copy: &Path) -> String {
    let parts: Vec<String> = copy.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
    parts
        .iter()
        .position(|p| p.eq_ignore_ascii_case("Packages"))
        .and_then(|i| parts.get(i + 1).cloned())
        .unwrap_or_else(|| "副本".into())
}

fn same_content(a: &Path, b: &Path) -> bool {
    matches!((std::fs::read(a), std::fs::read(b)), (Ok(x), Ok(y)) if x == y)
}

/// anchor repair：把私有副本合并回数据目录，然后删除副本。
pub fn repair(paths: &Paths) -> Result<()> {
    let copies = win::private_copies(&paths.home);
    if copies.is_empty() {
        println!("没有发现数据目录的私有副本，不需要修复。");
        return Ok(());
    }
    for copy in &copies {
        merge_copy(copy, paths)?;
    }
    if crate::agentctl::running() {
        crate::agentctl::reload()?;
    } else {
        println!("下一步：anchor agent start");
    }
    Ok(())
}

/// 合并一份副本，不覆盖原位置已有的任何文件：
/// - anchor.toml：原位置没有就搬过来；两边相同就跳过；两边不同就保留原位置的，副本里的另存为 anchor.toml.<应用包>；
/// - bin 里的程序：原位置没有的才搬过来；
/// - 运行文件、日志、时间线不搬，原位置会重新生成。
fn merge_copy(copy: &Path, paths: &Paths) -> Result<()> {
    println!("合并 {}", copy.display());
    println!("  到 {}", paths.home.display());
    std::fs::create_dir_all(&paths.home)?;
    let src = copy.join("anchor.toml");
    if src.is_file() {
        let dst = paths.config();
        if !dst.exists() {
            std::fs::copy(&src, &dst).with_context(|| format!("复制 {} 失败", src.display()))?;
            println!("  + anchor.toml");
        } else if same_content(&src, &dst) {
            println!("  = anchor.toml（两边相同）");
        } else {
            let side = paths.home.join(format!("anchor.toml.{}", package_of(copy)));
            std::fs::copy(&src, &side)?;
            println!("  ! anchor.toml 两边不同：保留原位置的，副本里的另存为 {}，请比较后决定用哪份", side.display());
        }
    }
    if let Ok(rd) = std::fs::read_dir(copy.join("bin")) {
        std::fs::create_dir_all(paths.bin_dir())?;
        for e in rd.flatten().filter(|e| e.path().is_file()) {
            let name = e.file_name().to_string_lossy().into_owned();
            let dst = paths.bin_dir().join(&name);
            if dst.exists() {
                println!("  = bin\\{name}（原位置已有，保留原位置的）");
            } else {
                std::fs::copy(e.path(), &dst).with_context(|| format!("复制 bin\\{name} 失败"))?;
                println!("  + bin\\{name}");
            }
        }
    }
    match std::fs::remove_dir_all(copy) {
        Ok(()) => println!("  已删除私有副本（其中的运行文件、日志和时间线不保留，原位置会重新生成）"),
        Err(e) => println!("  删除私有副本失败：{e}。可能还有程序在用它，关掉后手动删除这个目录"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_copy_never_overwrites_and_removes_the_copy() {
        let root = std::env::temp_dir().join(format!("anchor-repair-{}", crate::util::random_hex()));
        let copy = root.join(r"Packages\Claude_x\LocalCache\Local\AIAnchor");
        let paths = Paths { home: root.join("AIAnchor") };
        std::fs::create_dir_all(copy.join("bin")).unwrap();
        std::fs::write(copy.join("anchor.toml"), "from copy").unwrap();
        std::fs::write(copy.join(r"bin\sing-box.exe"), "sb").unwrap();
        std::fs::write(copy.join("timeline.db"), "tl").unwrap();

        // 原位置有数据目录，但没有 anchor.toml（用户代理在外面运行过）
        std::fs::create_dir_all(paths.log_dir()).unwrap();
        merge_copy(&copy, &paths).unwrap();
        assert_eq!(std::fs::read_to_string(paths.config()).unwrap(), "from copy");
        assert_eq!(std::fs::read_to_string(paths.bin_dir().join("sing-box.exe")).unwrap(), "sb");
        assert!(!paths.home.join("timeline.db").exists(), "时间线不搬");
        assert!(!copy.exists(), "副本已删除");

        // 两边的 anchor.toml 不同：保留原位置的，副本的另存
        std::fs::create_dir_all(&copy).unwrap();
        std::fs::write(copy.join("anchor.toml"), "other").unwrap();
        merge_copy(&copy, &paths).unwrap();
        assert_eq!(std::fs::read_to_string(paths.config()).unwrap(), "from copy");
        assert_eq!(std::fs::read_to_string(paths.home.join("anchor.toml.Claude_x")).unwrap(), "other");
        let _ = std::fs::remove_dir_all(root);
    }
}
