//! anchor report：一段时间内的断联次数、各段占比、“未知”占比，以及出口、线路、内核、网络的变化（P1b）。
//! 门槛 2 的一周测试直接用它的数字：每次断联都有归因，“未知”低于 10%。

use crate::config::Paths;
use crate::util::pad;
use anchor_core::disconnect::{Cause, ErrClass};
use anchor_core::timeline::{DisconnectRow, Event, Probe, Timeline, local_time, now_ms};
use anchor_core::util::zh_duration;
use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use std::time::Duration;

/// “未知”占比的目标上限
const UNKNOWN_TARGET: f64 = 10.0;

#[derive(Debug, Default, Serialize, PartialEq)]
pub struct Summary {
    pub since_ms: i64,
    pub disconnects: usize,
    /// 合并进断联的连接错误条数
    pub errors: u64,
    /// 归因 → 次数（按 Cause::ALL 的顺序，只含出现过的）
    pub by_cause: Vec<(String, usize)>,
    pub unknown_pct: f64,
    pub top_domains: Vec<(String, usize)>,
    pub by_class: Vec<(String, usize)>,
    pub exit_ip_changes: usize,
    /// AI 通道被出口锁定的次数和总时长（以放行事件计），按触发原因分
    pub locks: usize,
    pub locked_ms: u64,
    pub lock_triggers: Vec<(String, usize)>,
    pub line_switches: usize,
    pub all_lines_down: usize,
    pub kernel_restarts: usize,
    pub net_changes: usize,
    /// 段 → (次数, 成功次数)
    pub probes: Vec<(String, u64, u64)>,
}

/// AI 通道锁住的时间段，按事件推算：锁住、出口 IP 变化、内核启动（用户代理的内核以锁住状态启动）开始，放行结束。
fn lock_spans(events: &[Event], now: i64) -> Vec<(i64, i64)> {
    let mut spans = Vec::new();
    let mut start: Option<i64> = None;
    for e in events {
        match e.kind.as_str() {
            "exit_locked" | "exit_ip_changed" | "kernel_start" | "agent_start" => {
                start.get_or_insert(e.ts);
            }
            "exit_unlocked" => {
                if let Some(s) = start.take() {
                    spans.push((s, e.ts));
                }
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        spans.push((s, now));
    }
    spans
}

/// exit_checks：这段时间的出口核对明细；locked：AI 通道锁住的时段。出口核对只算放行期间的定时核对：
/// 锁住期间每 1～5 秒重试一次，出口或网络断着时会把成功率拉得很低，那段时间已经算在“锁住次数和时长”里。
pub fn summarize(
    since_ms: i64,
    rows: &[DisconnectRow],
    events: &[Event],
    probes: &[(String, String, u64, u64, Option<u64>)],
    exit_checks: &[Probe],
    locked: &[(i64, i64)],
) -> Summary {
    let count_by = |key: &dyn Fn(&DisconnectRow) -> String| {
        let mut m: BTreeMap<String, usize> = BTreeMap::new();
        for r in rows {
            *m.entry(key(r)).or_default() += 1;
        }
        let mut v: Vec<(String, usize)> = m.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v
    };
    let causes = count_by(&|r| r.cause.clone());
    let by_cause: Vec<(String, usize)> = Cause::ALL
        .iter()
        .filter_map(|c| causes.iter().find(|(n, _)| n == c.name()).map(|(n, k)| (n.clone(), *k)))
        .collect();
    let unknown = causes.iter().find(|(n, _)| n == "unknown").map_or(0, |(_, k)| *k);
    let n = |kind: &str| events.iter().filter(|e| e.kind == kind).count();
    let unlocks: Vec<&Event> = events.iter().filter(|e| e.kind == "exit_unlocked").collect();
    let mut triggers: BTreeMap<String, usize> = BTreeMap::new();
    for e in &unlocks {
        *triggers.entry(e.detail["trigger"].as_str().unwrap_or("").to_string()).or_default() += 1;
    }
    let mut lock_triggers: Vec<(String, usize)> = triggers.into_iter().collect();
    lock_triggers.sort_by(|a, b| b.1.cmp(&a.1));
    let mut seg: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for (s, _, total, ok, _) in probes.iter().filter(|p| p.0 != "exit") {
        let e = seg.entry(s.clone()).or_default();
        e.0 += total;
        e.1 += ok;
    }
    let open: Vec<&Probe> = exit_checks.iter().filter(|p| !locked.iter().any(|(a, b)| p.ts >= *a && p.ts <= *b)).collect();
    if !open.is_empty() {
        seg.insert("exit".into(), (open.len() as u64, open.iter().filter(|p| p.ok).count() as u64));
    }
    Summary {
        since_ms,
        disconnects: rows.len(),
        errors: rows.iter().map(|r| u64::from(r.count)).sum(),
        by_cause,
        unknown_pct: if rows.is_empty() { 0.0 } else { unknown as f64 * 100.0 / rows.len() as f64 },
        top_domains: count_by(&|r| r.domain.clone()).into_iter().take(5).collect(),
        by_class: count_by(&|r| r.class.clone()),
        exit_ip_changes: n("exit_ip_changed"),
        locks: unlocks.len(),
        locked_ms: unlocks.iter().filter_map(|e| e.detail["locked_ms"].as_u64()).sum(),
        lock_triggers,
        line_switches: n("line_switch"),
        all_lines_down: n("all_lines_down"),
        kernel_restarts: n("kernel_restart"),
        net_changes: n("net_change"),
        probes: seg.into_iter().map(|(s, (t, ok))| (s, t, ok)).collect(),
    }
}

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


fn trigger_label(t: &str) -> &str {
    match t {
        "network_change" => "网络变化",
        "kernel_start" => "内核启动",
        "exit_down" => "出口不可达",
        "recheck" => "手动核对",
        "periodic" => "定时核对",
        "" => "其他",
        other => other,
    }
}

fn segment_label(s: &str) -> &str {
    match s {
        "lan" => "连得上路由器",
        "wan" => "绕开 VPN 能上网",
        "local" => "本机能上网",
        "chain" => "整条链路可用",
        // 失败的多半是回显服务没响应；IP 真变了另算在“出口 IP 变化”里
        "exit" => "出口核对成功（放行期间）",
        "line" => "当前线路可用",
        "line_other" => "其他线路可用",
        "ai" => "AI 域名可达（突发）",
        "status" => "官方状态正常（突发）",
        other => other,
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn row(domain: &str, class: &str, cause: &str, count: u32) -> DisconnectRow {
        DisconnectRow {
            ts: 1,
            domain: domain.into(),
            phase: "open".into(),
            class: class.into(),
            outbound: "direct[exit]".into(),
            cause: cause.into(),
            why: String::new(),
            raw: String::new(),
            count,
        }
    }

    #[test]
    fn summary_counts_causes_and_changes() {
        let rows = vec![
            row("claude.ai", "unreachable", "local", 3),
            row("claude.ai", "timeout", "exit", 1),
            row("api.anthropic.com", "timeout", "local", 2),
            row("claude.ai", "reset", "unknown", 1),
        ];
        let ev = |kind: &str, detail| Event { ts: 1, kind: kind.into(), detail };
        let events = vec![
            ev("exit_unlocked", json!({ "trigger": "network_change", "locked_ms": 1500 })),
            ev("exit_unlocked", json!({ "trigger": "network_change", "locked_ms": 500 })),
            ev("exit_unlocked", json!({ "trigger": "kernel_start", "locked_ms": 1000 })),
            ev("net_change", json!({})),
            ev("kernel_restart", json!({})),
        ];
        let probes = vec![
            ("local".to_string(), "direct".to_string(), 10, 9, Some(50)),
            ("chain".to_string(), "exit".to_string(), 4, 4, Some(800)),
            ("exit".to_string(), "https://a".to_string(), 3, 1, Some(800)),
        ];
        let check = |ts, ok| Probe { ts, segment: "exit".into(), target: "https://a".into(), ok, ms: None, note: String::new() };
        // 锁住期间（10～20）那次失败的重试不算
        let exit_checks = vec![check(5, true), check(15, false), check(25, false)];
        let s = summarize(0, &rows, &events, &probes, &exit_checks, &[(10, 20)]);
        assert_eq!((s.disconnects, s.errors), (4, 7));
        assert_eq!(s.by_cause, vec![("local".into(), 2), ("exit".into(), 1), ("unknown".into(), 1)], "按 本地→…→未知 的顺序");
        assert_eq!(s.unknown_pct, 25.0);
        assert_eq!(s.top_domains[0], ("claude.ai".into(), 3));
        assert_eq!(s.by_class[0], ("timeout".into(), 2));
        assert_eq!((s.locks, s.locked_ms), (3, 3000));
        assert_eq!(s.lock_triggers[0], ("network_change".into(), 2));
        assert_eq!((s.net_changes, s.kernel_restarts, s.exit_ip_changes), (1, 1, 0));
        assert_eq!(s.probes, vec![("chain".into(), 4, 4), ("exit".into(), 2, 1), ("local".into(), 10, 9)]);
    }

    #[test]
    fn lock_spans_from_events() {
        let ev = |ts, kind: &str| Event { ts, kind: kind.into(), detail: json!({}) };
        let events = vec![
            ev(1, "agent_start"),
            ev(2, "kernel_start"),
            ev(3, "exit_unlocked"),
            ev(10, "exit_locked"),
            ev(12, "exit_ip_changed"),
            ev(20, "exit_unlocked"),
            ev(30, "exit_ip_changed"),
        ];
        assert_eq!(lock_spans(&events, 40), vec![(1, 3), (10, 20), (30, 40)]);
    }

    #[test]
    fn empty_period() {
        let s = summarize(0, &[], &[], &[], &[], &[]);
        assert_eq!((s.disconnects, s.unknown_pct), (0, 0.0));
    }
}
