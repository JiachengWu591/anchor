//! anchor report：一段时间内的断联次数、各段占比、“未知”占比，以及出口、线路、内核、网络的变化（P1b）。
//! 门槛 2 的一周测试直接用它的数字：每次断联都有归因，“未知”低于 10%。

use crate::config::Paths;
use crate::util::pad;
use anchor_core::disconnect::{Cause, ErrClass};
use anchor_core::report::{Summary, UNKNOWN_TARGET, lock_spans, segment_label, summarize, trigger_label};
use anchor_core::timeline::{DisconnectRow, Timeline, local_time, now_ms};
use anchor_core::util::zh_duration;
use anyhow::{Context, Result};
use std::time::Duration;

pub fn run(paths: &Paths, since: Duration, list: bool, json: bool) -> Result<()> {
    let tl = Timeline::open_read_only(&paths.timeline_db())?;
    let since_ms = now_ms() - since.as_millis() as i64;
    let rows = tl
        .disconnects_since(since_ms)
        .context("读取断联记录失败：用户代理可能还是旧版本，升级并启动后会自动建表")?;
    let events = tl.events_since(since_ms, &[], usize::MAX)?;
    let probes = tl.probe_summary(since_ms)?;
    let exit_checks = tl.probes_of("exit", since_ms)?;
    // 锁住可能开始于报告起点之前：多取一天的事件来推算锁住时段
    let spans = lock_spans(&tl.events_since(since_ms - 86_400_000, &[], usize::MAX)?, now_ms());
    let s = summarize(since_ms, &rows, &events, &probes, &exit_checks, &spans);
    if json {
        let v = serde_json::json!({ "summary": s, "disconnects": if list { serde_json::to_value(&rows)? } else { serde_json::Value::Null } });
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(());
    }
    print_text(&s, since, list);
    if list {
        print_list(&rows);
    }
    Ok(())
}

fn pct(part: usize, total: usize) -> f64 {
    if total == 0 { 0.0 } else { part as f64 * 100.0 / total as f64 }
}


fn print_text(s: &Summary, since: Duration, listing: bool) {
    println!("AI Anchor 报告 · 最近 {}（{} 起）\n", zh_duration(since.as_secs()), local_time(s.since_ms));
    if s.disconnects == 0 {
        println!("断联  0 次");
    } else {
        println!("断联  {} 次（合并了 {} 条连接错误）", s.disconnects, s.errors);
        for (cause, k) in &s.by_cause {
            let note = if cause == "unknown" {
                let ok = if s.unknown_pct < UNKNOWN_TARGET { "达标" } else { "未达标" };
                format!("  目标低于 {UNKNOWN_TARGET:.0}%，{ok}")
            } else {
                String::new()
            };
            println!("  {}{:>4}  {:>5.1}%{note}", pad(Cause::label(cause), 8), k, pct(*k, s.disconnects));
        }
        let doms: Vec<String> = s.top_domains.iter().map(|(d, k)| format!("{d} {k}")).collect();
        println!("  按域名：{}", doms.join("、"));
        let classes: Vec<String> = s.by_class.iter().map(|(c, k)| format!("{} {k}", ErrClass::label(c))).collect();
        println!("  按错误：{}", classes.join("、"));
    }
    println!();
    let triggers: Vec<String> = s.lock_triggers.iter().map(|(t, k)| format!("{} {k}", trigger_label(t))).collect();
    let triggers = if triggers.is_empty() { String::new() } else { format!("（{}）", triggers.join("、")) };
    println!("出口  IP 变化 {} 次；AI 通道锁住 {} 次，共 {}{triggers}", s.exit_ip_changes, s.locks, zh_duration(s.locked_ms / 1000));
    println!("线路  换线 {} 次，全部不可用 {} 次", s.line_switches, s.all_lines_down);
    println!("内核  意外退出 {} 次", s.kernel_restarts);
    println!("网络  变化 {} 次", s.net_changes);
    let probes: Vec<String> = s
        .probes
        .iter()
        .map(|(seg, total, ok)| format!("{} {:.1}%（{total} 次）", segment_label(seg), pct(*ok as usize, *total as usize)))
        .collect();
    if !probes.is_empty() {
        println!("探测  {}", probes.join("；"));
    }
    if s.disconnects > 0 && !listing {
        println!("\n明细：anchor report --list");
    }
}

fn print_list(rows: &[DisconnectRow]) {
    if rows.is_empty() {
        return;
    }
    println!("\n{}{}{}{}依据", pad("时间", 21), pad("域名", 34), pad("错误", 16), pad("归因", 8));
    for r in rows {
        let dom = if r.count > 1 { format!("{}（{} 条）", r.domain, r.count) } else { r.domain.clone() };
        println!(
            "{}{}{}{}{}",
            pad(&local_time(r.ts), 21),
            pad(&dom, 34),
            pad(ErrClass::label(&r.class), 16),
            pad(Cause::label(&r.cause), 8),
            r.why
        );
        if r.cause == "unknown" {
            println!("{}原始错误：{}", " ".repeat(21), r.raw);
        }
    }
}
