//! 每分钟向特权服务查询守卫状态：把服务做过的规则变化写进时间线，更新托盘状态。
//! 时间线只由用户代理写，服务的变化记录按“时间 + 类型”去重后同步过来。

use crate::shared::{GuardView, Level, Shared};
use anchor_core::ipc::{self, CallError};
use anchor_core::log;
use serde_json::{Value, json};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, UNIX_EPOCH};

const EVERY: Duration = Duration::from_secs(60);

pub fn run(sh: Arc<Shared>) {
    let mut next = Instant::now() + Duration::from_secs(3);
    let mut warned_missing_svc = false;
    let mut last_paused: Option<Option<String>> = None;
    while !sh.stopping() {
        thread::sleep(Duration::from_millis(200));
        if Instant::now() < next {
            continue;
        }
        next = Instant::now() + EVERY;
        let view = match ipc::call(ipc::SVC_PIPE, "guard.status", Value::Null) {
            Ok(v) => {
                sync_changes(&sh, &v);
                let paused = v["paused_until"].as_str().map(String::from);
                if let Some(prev) = &last_paused
                    && *prev != paused
                {
                    match &paused {
                        Some(until) => sh.tl.event("guard_pause", json!({ "until": until })),
                        None => sh.tl.event("guard_resume", json!({})),
                    }
                }
                last_paused = Some(paused.clone());
                let rules = v["rules"].as_array().map(Vec::len).unwrap_or(0);
                let disabled = v["rules"].as_array().map(|a| a.iter().filter(|r| r["enabled"] == false).count()).unwrap_or(0);
                GuardView {
                    svc: "running".into(),
                    rules,
                    disabled,
                    missing: v["missing"].as_array().map(Vec::len).unwrap_or(0),
                    paused_until: paused,
                    error: v["last_refresh"]["error"].as_str().map(String::from),
                }
            }
            Err(CallError::NotRunning) => {
                if !warned_missing_svc {
                    warned_missing_svc = true;
                    sh.notify(
                        Level::Warn,
                        "AI Anchor 特权服务没有运行",
                        "应用更新后守卫规则不会自动刷新。管理员终端运行 anchor service install 安装。",
                    );
                }
                GuardView { svc: "not_installed".into(), ..Default::default() }
            }
            Err(CallError::Denied) => GuardView { svc: "denied".into(), error: Some(CallError::Denied.to_string()), ..Default::default() },
            Err(e) => GuardView { svc: "error".into(), error: Some(e.to_string()), ..Default::default() },
        };
        sh.status().guard = view;
    }
}

fn sync_changes(sh: &Shared, v: &Value) {
    let Some(changes) = v["changes"].as_array() else { return };
    for c in changes {
        let Some(ts) = c["time"].as_str().and_then(|t| humantime::parse_rfc3339(t).ok()) else { continue };
        let ts = ts.duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0);
        if sh.tl.event_exists("guard_refresh", ts) {
            continue;
        }
        let detail = json!({ "added": c["added"], "removed": c["removed"], "source": c["source"] });
        log::line(&format!("守卫规则有变化：{detail}"));
        sh.tl.event_at(ts, "guard_refresh", detail);
    }
}
