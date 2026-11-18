//! 用户代理的本机接口（\\.\pipe\ai-anchor-agent，只允许当前用户）。
//!
//! status：运行状态；reload：重新读取配置并重启内核；stop：退出；event：记录命令行发起的事件（目前只有 app_launch）；
//! exit.recheck：先锁住 AI 通道，立即核对出口（与网络变化时的处理相同）。
//! line.list：各线路的评分；line.use / line.pin / line.unpin：手动换线、固定、取消固定（交给线路控制器）。

use crate::lines::LineCmd;
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
        "exit.recheck" => {
            sh.recheck.store(true, Ordering::SeqCst);
            sh.poke();
            Ok(json!({ "rechecking": true }))
        }
        "line.list" => lines_view(sh),
        "line.use" => line_cmd(sh, LineCmd::Use(name(req)?)),
        "line.pin" => line_cmd(sh, LineCmd::Pin(name(req)?)),
        "line.unpin" => line_cmd(sh, LineCmd::Unpin),
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

fn name(req: &Request) -> Result<String> {
    match req.params["name"].as_str().map(str::trim) {
        Some(n) if !n.is_empty() => Ok(n.to_string()),
        _ => bail!("缺少线路名"),
    }
}

fn lines_view(sh: &Shared) -> Result<Value> {
    match sh.lines_view.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        Some(v) => Ok(v),
        None => bail!("没有配置线路（anchor.toml 里没有 [[lines]]），或者配置有误、内核还没运行"),
    }
}

/// 交给线路控制器线程处理，等它回话（它每 0.2 秒看一次）。
fn line_cmd(sh: &Shared, cmd: LineCmd) -> Result<Value> {
    lines_view(sh)?;
    let (tx, rx) = std::sync::mpsc::channel();
    sh.line_cmds.lock().unwrap_or_else(|e| e.into_inner()).push((cmd, tx));
    match rx.recv_timeout(std::time::Duration::from_secs(5)) {
        Ok(Ok(msg)) => Ok(json!({ "message": msg, "lines": lines_view(sh).ok() })),
        Ok(Err(e)) => bail!("{e}"),
        Err(_) => bail!("线路控制器 5 秒内没有回应"),
    }
}
