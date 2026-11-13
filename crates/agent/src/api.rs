//! 用户代理的本机接口（\\.\pipe\ai-anchor-agent，只允许当前用户）。
//!
//! status：运行状态；reload：重新读取配置并重启内核；stop：退出；event：记录命令行发起的事件（目前只有 app_launch）。

use crate::shared::Shared;
use anchor_core::ipc::{Request, Response};
use anyhow::{Result, bail};
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::UNIX_EPOCH;

pub fn handle(sh: &Arc<Shared>, req: Request) -> Response {
    Response::from_result(dispatch(sh, &req))
}

fn dispatch(sh: &Arc<Shared>, req: &Request) -> Result<Value> {
    match req.method.as_str() {
        "status" => {
            let st = sh.status().clone();
            let started = sh.started.duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0);
            Ok(json!({
                "version": anchor_core::VERSION,
                "pid": std::process::id(),
                "started_ms": started,
                "home": sh.paths.home,
                "timeline": sh.paths.timeline_db(),
                "tray": sh.tray,
                "summary": sh.summary().1,
                "status": st,
            }))
        }
        "reload" => {
            sh.reload.store(true, Ordering::SeqCst);
            Ok(json!({ "reloading": true }))
        }
        "stop" => {
            sh.request_stop("命令行请求");
            crate::tray::wake();
            Ok(json!({ "stopping": true }))
        }
        "event" => {
            let kind = req.params["kind"].as_str().unwrap_or_default();
            if kind != "app_launch" {
                bail!("不接受的事件类型：{kind}");
            }
            let detail = &req.params["detail"];
            let app = detail["app"].as_str().unwrap_or_default().chars().take(64).collect::<String>();
            let exe = detail["exe"].as_str().unwrap_or_default().chars().take(512).collect::<String>();
            sh.tl.event(kind, json!({ "app": app, "exe": exe }));
            Ok(json!({ "recorded": true }))
        }
        m => bail!("未知方法 {m}"),
    }
}
