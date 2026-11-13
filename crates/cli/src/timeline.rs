//! anchor timeline：按时间顺序列出用户代理记录的事件和探测。

use crate::config::Paths;
use crate::util::pad;
use anchor_core::timeline::{Timeline, describe, local_time, now_ms};
use anyhow::Result;
use std::time::Duration;

pub struct Query {
    pub since: Duration,
    pub kinds: Vec<String>,
    pub probes: bool,
    pub limit: usize,
    pub json: bool,
}

pub fn print(paths: &Paths, q: &Query) -> Result<()> {
    let tl = Timeline::open_read_only(&paths.timeline_db())?;
    let since = now_ms() - q.since.as_millis() as i64;
    let span = humantime::format_duration(q.since);
    if q.probes {
        let probes = tl.probes_since(since, q.limit)?;
        if q.json {
            println!("{}", serde_json::to_string_pretty(&probes)?);
            return Ok(());
        }
        println!("最近 {span} 的探测（最多 {} 条）：", q.limit);
        for p in &probes {
            let r = if p.ok { p.ms.map(|m| format!("{m} ms")).unwrap_or_else(|| "成功".into()) } else { format!("失败 {}", p.note) };
            println!("{}  {} {}  {r}", local_time(p.ts), segment(&p.segment), p.target);
        }
        return Ok(());
    }

    let events = tl.events_since(since, &q.kinds, q.limit)?;
    if q.json {
        println!("{}", serde_json::to_string_pretty(&events)?);
        return Ok(());
    }
    if events.is_empty() {
        println!("最近 {span} 没有事件。");
    } else {
        println!("最近 {span} 的事件（{} 条）：", events.len());
        for e in &events {
            let (label, text) = describe(e);
            println!("{}  {}{text}", local_time(e.ts), pad(label, 10));
        }
    }
    let sum = tl.probe_summary(since)?;
    if !sum.is_empty() {
        println!("\n探测汇总：");
        for (seg, target, n, ok, avg) in sum {
            let rate = if n == 0 { 0.0 } else { ok as f64 * 100.0 / n as f64 };
            let avg = avg.map(|m| format!("，成功时平均 {m} ms")).unwrap_or_default();
            println!("  {} {}  {n} 次，成功 {rate:.1}%{avg}", segment(&seg), target);
        }
        println!("（明细：anchor timeline --probes）");
    }
    Ok(())
}

fn segment(s: &str) -> &str {
    match s {
        "line" => "线路",
        "local" => "本地网络",
        "chain" => "整条链路",
        "exit" => "出口",
        "ai" => "AI 服务",
        other => other,
    }
}
