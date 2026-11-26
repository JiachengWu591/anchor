//! 新版本提醒：每天问一次 GitHub 有没有新的正式版本，有就发一次通知。只查，不下载，也不安装。
//!
//! 查到的结果记在数据目录的 update.json 里（anchor status 读它）；托盘菜单和面板用 Shared 里的那一份。

use crate::shared::{Level, Shared};
use anchor_core::update::{self, State};
use anchor_core::{VERSION, log};
use serde_json::json;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// 启动后先等一会儿再查：内核启动、出口核对先忙完。
const FIRST_DELAY: Duration = Duration::from_secs(120);
/// 多久看一次记录。anchor upgrade --check 手动查到的结果，也是这时读进来。
const TICK: Duration = Duration::from_secs(60);

pub fn run(sh: Arc<Shared>) {
    let started = Instant::now();
    let mut next = Instant::now();
    while !sh.stopping() {
        thread::sleep(Duration::from_millis(500));
        if Instant::now() < next {
            continue;
        }
        next = Instant::now() + TICK;
        let mut st = State::load(&sh.paths);
        sh.set_newer(st.newer(VERSION));
        // 配置还没读出来（或者有误）时不查：不知道用户是不是关掉了
        let Some(cfg) = sh.config() else { continue };
        if !cfg.update.check || started.elapsed() < FIRST_DELAY || !st.due(update::now_ms()) {
            continue;
        }
        let r = update::check(&update::ways(Some(&cfg)));
        match &r {
            Ok(Some(rel)) => log::line(&format!("查新版本：最新的正式版本是 {}（现在 {VERSION}）", rel.version)),
            Ok(None) => log::line("查新版本：GitHub 上还没有正式版本"),
            Err(e) => log::line(&format!("查新版本失败，3 小时后再试：{e:#}")),
        }
        st.record(update::now_ms(), &r);
        if let Some(v) = st.take_notice(VERSION) {
            sh.tl.event("update_available", json!({ "version": v, "current": VERSION }));
            sh.notify(
                Level::Info,
                &format!("AI Anchor 有新版本 {v}"),
                &format!("现在用的是 {VERSION}。右键托盘图标，点“下载新版本”打开下载页；下载解压后运行里面的 anchor.exe upgrade。"),
            );
        }
        if let Err(e) = st.save(&sh.paths) {
            log::line(&format!("记录查新版本的结果失败：{e:#}"));
        }
        sh.set_newer(st.newer(VERSION));
    }
}
