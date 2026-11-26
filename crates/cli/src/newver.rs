//! 新版本：anchor upgrade --check 手动查一次；anchor status 显示查到的结果（不联网）。

use anchor_core::config::{Config, Paths};
use anchor_core::timeline::local_time;
use anchor_core::update::{self, State};
use anchor_core::{VERSION, win};
use anyhow::{Context, Result};

/// anchor upgrade --check：问 GitHub 最新的正式版本。只查，不下载，也不安装。
pub fn check(paths: &Paths) -> Result<()> {
    let cfg = Config::load(paths).ok();
    println!("正在查 GitHub 上最新的正式版本……");
    let r = update::check(&update::ways(cfg.as_ref()));
    let mut st = State::load(paths);
    st.record(update::now_ms(), &r);
    match &r {
        Ok(Some(rel)) if update::is_newer(&rel.version, VERSION) => {
            println!("有新版本 {}{}，现在用的是 {VERSION}。", rel.version, published(&rel.date));
            println!("下载：{}", update::release_page(&rel.version).unwrap_or_default());
            println!("下载解压后，在开始菜单打开的终端里运行解压出来的 anchor.exe upgrade。");
            // 已经告诉过用户了，用户代理不再为这个版本发通知
            st.notified = rel.version.clone();
        }
        Ok(Some(rel)) if update::is_newer(VERSION, &rel.version) => {
            println!("现在用的 {VERSION} 比最新的正式版本 {} 还新（自己编译的版本）。", rel.version)
        }
        Ok(Some(_)) => println!("已经是最新的正式版本 {VERSION}。"),
        Ok(None) => println!("GitHub 上还没有正式版本：{}", update::RELEASES_PAGE),
        Err(_) => {}
    }
    // 数据目录还没有（没运行过 anchor init）就不记；在 MSIX 应用里写入会被重定向到它的私有目录，也不记
    if paths.home.is_dir()
        && win::sandbox().is_none()
        && let Err(e) = st.save(paths)
    {
        eprintln!("（没能记下这次的结果：{e:#}）");
    }
    r.map(|_| ()).context("查新版本失败")
}

/// anchor status 里的“版本”一行：读用户代理（或上一次 --check）记下的结果。
pub fn status_line(paths: &Paths, cfg: Option<&Config>) -> String {
    let st = State::load(paths);
    let off = if cfg.is_some_and(|c| !c.update.check) { "；不自动查新版本（[update] check = false）" } else { "" };
    if let Some(v) = st.newer(VERSION) {
        let page = update::release_page(v).unwrap_or_default();
        return format!("版本  {VERSION}；有新版本 {v}{}，下载：{page}{off}", published(&st.date));
    }
    if st.checked_ms <= 0 {
        return format!("版本  {VERSION}{off}");
    }
    let when = local_time(st.checked_ms);
    if st.error.is_empty() {
        format!("版本  {VERSION}，是最新的（{when} 查过）{off}")
    } else {
        format!("版本  {VERSION}（{when} 查新版本失败：{}）{off}", st.error)
    }
}

fn published(date: &str) -> String {
    if date.is_empty() { String::new() } else { format!("（{date} 发布）") }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home(st: Option<&State>) -> Paths {
        let home = std::env::temp_dir().join(format!("anchor-test-{}", anchor_core::util::random_hex()));
        std::fs::create_dir_all(&home).unwrap();
        let paths = Paths { home };
        if let Some(st) = st {
            st.save(&paths).unwrap();
        }
        paths
    }

    #[test]
    fn status_line_reads_the_record() {
        let p = home(None);
        assert_eq!(status_line(&p, None), format!("版本  {VERSION}"));

        let newer = State { checked_ms: 1, latest: "999.0.0".into(), date: "2026-12-01".into(), ..Default::default() };
        newer.save(&p).unwrap();
        assert_eq!(
            status_line(&p, None),
            format!("版本  {VERSION}；有新版本 999.0.0（2026-12-01 发布），下载：https://github.com/JiachengWu591/anchor/releases/tag/v999.0.0")
        );

        let same = State { checked_ms: 1, latest: VERSION.into(), ..Default::default() };
        same.save(&p).unwrap();
        assert!(status_line(&p, None).starts_with(&format!("版本  {VERSION}，是最新的（")));

        // 查失败了，但之前查到过新版本：照样提示新版本
        let failed = State { checked_ms: 1, latest: "999.0.0".into(), error: "连不上 GitHub".into(), ..Default::default() };
        failed.save(&p).unwrap();
        assert!(status_line(&p, None).contains("有新版本 999.0.0，下载："));
        let failed = State { checked_ms: 1, error: "连不上 GitHub".into(), ..Default::default() };
        failed.save(&p).unwrap();
        assert!(status_line(&p, None).ends_with("查新版本失败：连不上 GitHub）"));

        let off = Config::parse("[exit]\ntype = \"socks\"\nserver = \"203.0.113.10\"\nserver_port = 1080\n[update]\ncheck = false\n").unwrap();
        assert!(status_line(&p, Some(&off)).ends_with("；不自动查新版本（[update] check = false）"));
        std::fs::remove_dir_all(&p.home).unwrap();
    }
}
