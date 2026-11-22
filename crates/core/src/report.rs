//! 一段时间内的断联次数、各段占比、“未知”占比，以及出口、线路、内核、网络的变化（P1b）。
//! 命令行的 anchor report 和面板共用这份统计。

use crate::disconnect::Cause;
use crate::timeline::{DisconnectRow, Event, Probe};
use serde::Serialize;
use std::collections::BTreeMap;

/// “未知”占比的目标上限
pub const UNKNOWN_TARGET: f64 = 10.0;

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

impl Summary {
    /// 把锁住的次数和总时长换成按锁住的时段算的（`summarize` 给的是把每次放行时记下的时长加起来）。
    ///
    /// 放行时记下的时长会少算：锁着的时候用户代理重启过，只记重启之后的那一段；锁着时退出用户代理的那一次没有放行，不计。
    /// 实测 7 天按那样加是 3 小时 23 分，按时段算是 7 小时 55 分，差的主要是一次夜里 4 个多小时的断网。
    ///
    /// - spans：`lock_spans` 的结果；hours：同一段时间的 `by_hour_of_day`，里面锁住的时长已经以有探测记录的时间为上限。
    /// - horizon：还留着的最早一条探测的时间（没有探测时传 now）。比它更早的时候没有探测记录，
    ///   没法用“在运行的时间”做上限，那一段仍然用放行时记下的时长。
    /// - events：统计时段里的事件。
    pub fn set_locks(&mut self, now: i64, events: &[Event], spans: &[(i64, i64)], hours: &[HourOfDay], horizon: i64) {
        let n = spans.iter().filter(|(s, e)| *e >= self.since_ms && *s <= now).count();
        let recorded: usize = self.lock_triggers.iter().map(|t| t.1).sum();
        if n > recorded {
            // 没等到放行的：锁着时退出了用户代理，或者现在还锁着
            self.lock_triggers.push(("unfinished".into(), n - recorded));
        }
        self.locks = n.max(recorded);
        let before: u64 = events.iter().filter(|e| e.kind == "exit_unlocked" && e.ts < horizon).filter_map(|e| e.detail["locked_ms"].as_u64()).sum();
        self.locked_ms = before + hours.iter().map(|h| h.locked_ms).sum::<u64>();
    }
}

/// AI 通道锁住的时间段，按事件推算：锁住、出口 IP 变化、内核启动（用户代理的内核以锁住状态启动）开始，放行结束。
/// 用户代理退出时也结束：内核跟着停了，之后到下次启动不算“锁住”。
pub fn lock_spans(events: &[Event], now: i64) -> Vec<(i64, i64)> {
    let mut spans = Vec::new();
    let mut start: Option<i64> = None;
    for e in events {
        match e.kind.as_str() {
            "exit_locked" | "exit_ip_changed" | "kernel_start" | "agent_start" => {
                start.get_or_insert(e.ts);
            }
            "exit_unlocked" | "agent_stop" => {
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

pub const HOUR_MS: i64 = 3_600_000;
/// 某一天的某个钟点里用户代理至少运行了这么久，这一天才算“看到了这个钟点”
const SEEN_MS: i64 = 20 * 60_000;
/// 某一天的某个钟点里至少锁了这么久，才算“这一天这个钟点锁住过”（几秒的核对不算）
const LOCKED_MS: i64 = 60_000;
/// 一个钟点至少在这么多天里看到过，才拿来比较哪个钟点最容易锁住
pub const MIN_DAYS: u32 = 3;

/// 一天里的一个钟点（本机时区），几天的数据合起来看。
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct HourOfDay {
    /// 0～23
    pub hour: u8,
    /// 有几天看到了这个钟点（用户代理在运行）
    pub days: u32,
    /// 其中有几天在这个钟点锁住过
    pub days_locked: u32,
    /// 这个钟点里用户代理在运行的时间，几天合计。关机、睡眠的时间不算
    pub observed_ms: u64,
    /// 其中 AI 通道锁住的时间
    pub locked_ms: u64,
    pub disconnects: usize,
}

/// 按钟点汇总 [since, now] 里 AI 通道锁住的情况，用来看一天里什么时候最不稳。
///
/// 排名看“有几天锁住过”，不看锁住的总时长：实测有一晚 VPN 断了 4 个小时，
/// 按总时长算，那 4 个钟点会一起排到最前面，其实只是一次事故。
///
/// - offset_ms：本机时区比 UTC 快多少（期间换过夏令时的话有一小时的误差，不处理）。
/// - observed：`Timeline::observed_minutes` 的结果。锁住的时间不超过观测到的时间：电脑睡着时锁住的时段不会被放大。
/// - spans：锁住的时段；disconnects：每次断联的时间。
pub fn by_hour_of_day(since: i64, now: i64, offset_ms: i64, observed: &[(i64, u32)], spans: &[(i64, i64)], disconnects: &[i64]) -> Vec<HourOfDay> {
    let mut v: Vec<HourOfDay> = (0..24).map(|hour| HourOfDay { hour, ..Default::default() }).collect();
    for &(idx, minutes) in observed {
        let a = (idx * HOUR_MS - offset_ms).max(since);
        let b = ((idx + 1) * HOUR_MS - offset_ms).min(now);
        if b <= a {
            continue;
        }
        let seen = (i64::from(minutes.min(60)) * 60_000).min(b - a);
        let locked: i64 = spans.iter().map(|(s, e)| ((*e).min(b) - (*s).max(a)).max(0)).sum::<i64>().min(seen);
        let h = &mut v[idx.rem_euclid(24) as usize];
        h.observed_ms += seen as u64;
        h.locked_ms += locked as u64;
        if seen >= SEEN_MS {
            h.days += 1;
            h.days_locked += u32::from(locked >= LOCKED_MS);
        }
    }
    for &ts in disconnects.iter().filter(|t| **t >= since && **t <= now) {
        v[(ts + offset_ms).div_euclid(HOUR_MS).rem_euclid(24) as usize].disconnects += 1;
    }
    v
}

/// 最容易锁住的几个钟点：只比看到过足够多天的钟点，按“锁住过的天数占比”从高到低，再按锁住的时长。
/// 只在一天里锁住过的不算规律，不列。
pub fn worst_hours(hours: &[HourOfDay], n: usize) -> Vec<&HourOfDay> {
    let share = |h: &HourOfDay| f64::from(h.days_locked) / f64::from(h.days.max(1));
    let mut v: Vec<&HourOfDay> = hours.iter().filter(|h| h.days >= MIN_DAYS && h.days_locked >= 2).collect();
    v.sort_by(|a, b| share(b).total_cmp(&share(a)).then(b.locked_ms.cmp(&a.locked_ms)).then(a.hour.cmp(&b.hour)));
    v.truncate(n);
    v
}

/// 一句话说哪些钟点最容易锁住。多数日子都锁住过才叫高峰；否则照实说没有明显的高峰，只列出天数最多的。
pub fn hours_summary(hours: &[HourOfDay]) -> String {
    let worst = worst_hours(hours, 3);
    let Some(top) = worst.first() else {
        return "没有哪个钟点在两天以上锁住过，看不出高峰时段".to_string();
    };
    let list: Vec<String> = worst.iter().map(|h| hour_phrase(h)).collect();
    if top.days_locked * 2 >= top.days {
        format!("最容易锁住的钟点：{}", list.join("、"))
    } else {
        format!("没有明显的高峰时段。锁住过的天数最多的钟点：{}", list.join("、"))
    }
}

/// “19 点（6 天里有 4 天锁住过，共 42 分）”
pub fn hour_phrase(h: &HourOfDay) -> String {
    format!("{:02} 点（{} 天里有 {} 天锁住过，共 {}）", h.hour, h.days, h.days_locked, crate::util::zh_duration(h.locked_ms / 1000))
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

pub fn trigger_label(t: &str) -> &str {
    match t {
        "network_change" => "网络变化",
        "kernel_start" => "内核启动",
        "exit_down" => "出口不可达",
        "recheck" => "手动核对",
        "unfinished" => "没等到放行",
        "periodic" => "定时核对",
        "" => "其他",
        other => other,
    }
}

pub fn segment_label(s: &str) -> &str {
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
        // 锁着时用户代理退出了：算到退出为止，下次启动另起一段
        let events = vec![ev(10, "exit_locked"), ev(15, "agent_stop"), ev(100, "agent_start"), ev(103, "exit_unlocked")];
        assert_eq!(lock_spans(&events, 200), vec![(10, 15), (100, 103)]);
    }

    #[test]
    fn lock_totals_come_from_the_spans() {
        const H: i64 = HOUR_MS;
        let ev = |ts: i64, kind: &str, detail| Event { ts, kind: kind.into(), detail };
        let unlock = |ts: i64, locked_ms: i64, trigger: &str| ev(ts, "exit_unlocked", json!({ "trigger": trigger, "locked_ms": locked_ms }));
        // 第 10 小时：锁了 5 分钟后放行。
        // 第 12 小时：锁住后电脑没关好就断了电（没有“代理停止”），第 20 小时重新开机，又锁了 10 分钟才放行：
        //   放行时只记了重启后的 10 分钟，锁着运行的另外 40 分钟（第 12 小时的 20 到 60 分）没记。
        // 第 22 小时：锁着时退出了用户代理，没有放行。
        let events = vec![
            ev(10 * H, "exit_locked", json!({ "reason": "exit_down" })),
            unlock(10 * H + 300_000, 300_000, "exit_down"),
            ev(12 * H + 20 * 60_000, "exit_locked", json!({ "reason": "exit_down" })),
            ev(20 * H, "agent_start", json!({})),
            unlock(20 * H + 600_000, 600_000, "kernel_start"),
            ev(22 * H, "exit_locked", json!({ "reason": "network_change" })),
            ev(22 * H + 120_000, "agent_stop", json!({})),
        ];
        let (since, now) = (0, 24 * H);
        let spans = lock_spans(&events, now);
        assert_eq!(spans.len(), 3);
        let mut s = summarize(since, &[], &events, &[], &[], &spans);
        assert_eq!((s.locks, s.locked_ms), (2, 900_000), "放行时记下的：2 次，共 15 分钟");

        // 第 13 到 19 小时电脑关着，没有探测记录
        let observed: Vec<(i64, u32)> = [10, 11, 12, 20, 21, 22].iter().map(|h| (*h, 60)).collect();
        let hours = by_hour_of_day(since, now, 0, &observed, &spans, &[]);
        s.set_locks(now, &events, &spans, &hours, 0);
        assert_eq!(s.locks, 3, "没放行的那一次也算");
        assert_eq!(s.locked_ms, (5 + 40 + 10 + 2) * 60_000, "关机的 7 个小时不算，重启前锁着运行的 40 分钟算");
        assert_eq!(s.lock_triggers.iter().map(|t| (t.0.as_str(), t.1)).collect::<Vec<_>>(), [("exit_down", 1), ("kernel_start", 1), ("unfinished", 1)]);
        assert_eq!(trigger_label("unfinished"), "没等到放行");

        // 探测明细只留 7 天：更早的那一段没有“在运行的时间”可用，仍然用放行时记下的时长
        let mut old = summarize(since, &[], &events, &[], &[], &spans);
        let recent: Vec<(i64, u32)> = [20, 21, 22].iter().map(|h| (*h, 60)).collect();
        old.set_locks(now, &events, &spans, &by_hour_of_day(since, now, 0, &recent, &spans, &[]), 20 * H);
        assert_eq!(old.locked_ms, (5 + 10 + 2) * 60_000, "第 10 小时的 5 分钟来自放行记录，之后的来自时段");
        // 完全没有探测记录（horizon 传 now）：和原来一样
        let mut none = summarize(since, &[], &events, &[], &[], &spans);
        none.set_locks(now, &events, &spans, &by_hour_of_day(since, now, 0, &[], &spans, &[]), now);
        assert_eq!((none.locks, none.locked_ms), (3, 900_000));
    }

    #[test]
    fn hours_of_day_count_the_days_with_a_lock() {
        const H: i64 = HOUR_MS;
        let day = 24 * H;
        // 东八区。本地小时序号 = (时间戳 + 偏移) / 一小时
        let off = 8 * H;
        let idx = |d: i64, hour: i64| d * 24 + hour;
        let at = |d: i64, hour: i64, min: i64| idx(d, hour) * H - off + min * 60_000;
        let (since, now) = (at(100, 0, 0), at(104, 0, 0));
        // 四天。19 点每天都在运行，其中三天锁住过；
        // 4 点到 7 点每天都在运行，只有一晚 VPN 断了 4 个小时；3 点只运行过 30 分钟，睡着时“锁了”一小时
        let mut observed = vec![(idx(102, 3), 30)];
        for d in 100..104 {
            observed.push((idx(d, 19), 60));
            for hour in 4..8 {
                observed.push((idx(d, hour), 60));
            }
        }
        let spans = vec![
            (at(100, 19, 10), at(100, 19, 25)),
            (at(101, 19, 0), at(101, 19, 5)),
            // 跨到 20 点的那一段不在观测到的小时里，不算
            (at(102, 19, 50), at(102, 20, 30)),
            // 只锁了 20 秒的核对：不算“这一天锁住过”
            (at(103, 19, 0), at(103, 19, 0) + 20_000),
            (at(101, 4, 0), at(101, 8, 0)),
            (at(102, 3, 0), at(102, 4, 0)),
        ];
        let dcs = vec![at(100, 19, 12), at(102, 19, 51), at(101, 5, 31), since - day, now + 1];
        let v = by_hour_of_day(since, now, off, &observed, &spans, &dcs);
        assert_eq!(v.len(), 24);
        let h = |n: usize| (v[n].days, v[n].days_locked, v[n].locked_ms / 60_000, v[n].disconnects);
        assert_eq!(h(19), (4, 3, 30, 2), "15 + 5 + 10 分钟，外加 20 秒");
        assert_eq!(v[19].observed_ms, 4 * H as u64);
        assert_eq!(h(5), (4, 1, 60, 1), "那一晚的事故在这个钟点只算一天");
        assert_eq!(h(3), (1, 1, 30, 0), "最多算观测到的 30 分钟");
        assert_eq!(h(20), (0, 0, 0, 0));
        // 按总时长，4 到 7 点（各 60 分钟）会排在 19 点（30 分钟）前面；按天数，只有 19 点是规律
        let worst = worst_hours(&v, 3);
        assert_eq!(worst.iter().map(|x| x.hour).collect::<Vec<_>>(), [19]);
        assert_eq!(hour_phrase(worst[0]), "19 点（4 天里有 3 天锁住过，共 30 分 20 秒）");
        assert_eq!(hours_summary(&v), "最容易锁住的钟点：19 点（4 天里有 3 天锁住过，共 30 分 20 秒）");
        // 最多的钟点也只有不到一半的日子锁住过：照实说没有明显的高峰
        let mut mild = v.clone();
        mild[19].days = 7;
        assert!(hours_summary(&mild).starts_with("没有明显的高峰时段。锁住过的天数最多的钟点：19 点（7 天里有 3 天"), "{}", hours_summary(&mild));
        mild[19].days_locked = 1;
        assert_eq!(hours_summary(&mild), "没有哪个钟点在两天以上锁住过，看不出高峰时段");
        // 天数占比相同的，锁得久的在前
        let mut more = v.clone();
        more[5].days_locked = 3;
        assert_eq!(worst_hours(&more, 3).iter().map(|x| x.hour).collect::<Vec<_>>(), [5, 19]);
        // 统计范围以外的小时不算；别的时区落在别的钟点
        assert!(by_hour_of_day(now, now + day, off, &observed, &spans, &dcs).iter().all(|x| x.observed_ms == 0 && x.locked_ms == 0));
        let utc = by_hour_of_day(since - day, now, 0, &[(idx(100, 19) - 8, 60)], &[(at(100, 19, 10), at(100, 19, 25))], &[at(100, 19, 12)]);
        assert_eq!((utc[11].days, utc[11].days_locked, utc[11].locked_ms / 60_000, utc[11].disconnects), (1, 1, 15, 1));
    }

    #[test]
    fn empty_period() {
        let s = summarize(0, &[], &[], &[], &[], &[]);
        assert_eq!((s.disconnects, s.unknown_pct), (0, 0.0));
    }
}
