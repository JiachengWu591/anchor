//! 面板显示的数据。文字都在这里拼好，网页只管摆放。
//!
//! - `state`：现在的情况（网页每 2 秒取一次）：AI 通道放行还是锁住、从本机到 AI 服务每一段通不通、卡在哪一段。
//! - `history`：最近 24 小时和 7 天的统计（每 30 秒取一次），数字和 anchor report 用的是同一份。

use crate::shared::{GuardView, KernelState, Status};
use anchor_core::disconnect::{Cause, ErrClass};
use anchor_core::report::{self, Summary};
use anchor_core::stall::{self, NoticeCtx, Stuck};
use anchor_core::timeline::{DisconnectRow, Event, Probe, Timeline, describe, local_offset_ms, local_time};
use anchor_core::util::zh_duration;
use anyhow::Result;
use serde::Serialize;
use serde_json::{Value, json};
use std::time::Duration;

/// 本机网络三段每 10 秒测一次；断网时一轮要十几秒。超过这么久没有新结果就当作不知道。
const LOCAL_FRESH_MS: i64 = 45_000;
/// 整条链路每 30 秒测一次，一次最多 10 秒。
const CHAIN_FRESH_MS: i64 = 90_000;

/// 从本机到 AI 服务的一段。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Seg {
    pub id: &'static str,
    pub name: &'static str,
    /// 名字后面的小字：Wi-Fi、网卡名、出口 IP
    pub sub: String,
    /// ok / fail / off（没有连接）/ warn / unknown / blocked（被 AI Anchor 拦住）
    pub state: &'static str,
    pub text: String,
}

pub struct PathIn<'a> {
    pub now_ms: i64,
    /// 每一段最近的一次探测
    pub last: &'a [Probe],
    /// 有没有连着 Wi-Fi 或网线；None 表示还没看过
    pub has_uplink: Option<bool>,
    pub via_vpn: bool,
    pub vpn_seen: bool,
    /// 出口绑定的网卡（一般是 VPN 的虚拟网卡）
    pub bind_if: Option<&'a str>,
    pub bind_if_down: bool,
    pub st: &'a Status,
}

fn uplink_name(kind: &str) -> String {
    match kind {
        "wifi" => "Wi-Fi".into(),
        "ethernet" => "网线".into(),
        _ => String::new(),
    }
}

fn took(p: &Probe) -> String {
    p.ms.map_or_else(|| "正常".to_string(), |m| format!("{m} ms"))
}

/// 本机 → 路由器 → 宽带 →（VPN）→（线路）→ 出口 → AI 服务。没有用到的段不出现。
pub fn path(i: &PathIn) -> Vec<Seg> {
    let p = |seg: &str, max_age: i64| i.last.iter().find(|p| p.segment == seg && i.now_ms - p.ts <= max_age);
    let (lan, wan, local, chain) = (p("lan", LOCAL_FRESH_MS), p("wan", LOCAL_FRESH_MS), p("local", LOCAL_FRESH_MS), p("chain", CHAIN_FRESH_MS));
    let seg = |id, name, sub: String, (state, text): (&'static str, String)| Seg { id, name, sub, state, text };
    let nothing = || ("unknown", "暂无探测结果".to_string());
    let has_vpn = i.via_vpn || i.vpn_seen || i.bind_if.is_some();
    let mut v = vec![seg("device", "这台电脑", String::new(), ("ok", String::new()))];

    let no_link = || ("fail", "没有连上 Wi-Fi 或网线".to_string());
    v.push(match lan {
        Some(p) if p.target == "none" => seg("lan", "路由器", String::new(), no_link()),
        Some(p) if p.ok => seg("lan", "路由器", uplink_name(&p.target), ("ok", took(p))),
        Some(p) => seg("lan", "路由器", uplink_name(&p.target), ("fail", "连不上".into())),
        None if i.has_uplink == Some(false) => seg("lan", "路由器", String::new(), no_link()),
        None => seg("lan", "路由器", String::new(), nothing()),
    });

    // 没有 VPN 时，“本机上网”那一项测的就是宽带
    let wan = wan.or(if has_vpn { None } else { local });
    v.push(seg(
        "wan",
        "宽带",
        String::new(),
        match wan {
            Some(p) if p.ok => ("ok", took(p)),
            Some(_) => ("fail", "外网不通".into()),
            None => nothing(),
        },
    ));

    if has_vpn {
        let through = local.filter(|p| p.target == "vpn");
        let state = if i.bind_if_down {
            ("off", "没有连接".to_string())
        } else if i.vpn_seen && !i.via_vpn {
            ("off", "没有连接：默认流量没有经过它".to_string())
        } else if !i.via_vpn {
            // 只有出口绑定在这块网卡上，别的流量不走它
            ("ok", "已连接".to_string())
        } else {
            match through {
                Some(p) if p.ok => ("ok", took(p)),
                Some(_) => ("fail", "连着，但经它上不了网".to_string()),
                None => nothing(),
            }
        };
        v.push(seg("vpn", "VPN", i.bind_if.unwrap_or_default().to_string(), state));
    }

    let st = i.st;
    if st.lines > 0 {
        let state = if st.lines_down { ("fail", "不可用".to_string()) } else { ("ok", "可用".to_string()) };
        v.push(seg("line", "线路", st.line.clone().unwrap_or_default(), state));
    }

    let e = &st.exit;
    let running = st.kernel == KernelState::Running && st.config_error.is_none();
    let exit = if !running {
        ("unknown", "内核没有运行".to_string())
    } else {
        match e.state.as_str() {
            "open" => ("ok", "与基线一致".to_string()),
            "changed" => ("fail", format!("IP 已变化：现在 {}", e.actual.as_deref().unwrap_or("未知"))),
            "unverifiable" => ("warn", "连得上，但核对不了 IP".to_string()),
            "no_baseline" => ("warn", "还没有登记基线".to_string()),
            "" => ("unknown", "还没有核对".to_string()),
            _ if e.exit_down => ("fail", "连不上".to_string()),
            _ => ("warn", "正在核对".to_string()),
        }
    };
    v.push(seg("exit", "出口", e.baseline.clone(), exit));

    let ai = if !running || e.locked || st.lines_down {
        ("blocked", "已拦住，不会直连".to_string())
    } else {
        match chain {
            Some(p) if p.ok => ("ok", format!("整条链路 {}", took(p))),
            // 刚放行时，最近的一次可能还是锁住期间测的：写明是多久以前
            Some(p) => ("warn", format!("{} 秒前整条链路探测失败", ((i.now_ms - p.ts).max(0) + 500) / 1000)),
            None => ("unknown", "等待探测".to_string()),
        }
    };
    v.push(seg("ai", "AI 服务", String::new(), ai));
    v
}

/// 卡在哪一段（网页把这一段标出来）。AI 通道放行着就不标。
/// stuck：用户代理的判断（出口连不上时才有）；没有时取路上第一段不通的。
pub fn culprit(segs: &[Seg], open: bool, stuck: Option<Stuck>) -> Option<&'static str> {
    if open {
        return None;
    }
    let has = |id: &str| segs.iter().any(|s| s.id == id);
    let vpn_or_wan = || if has("vpn") { "vpn" } else { "wan" };
    match stuck {
        Some(Stuck::Link) => Some("lan"),
        Some(Stuck::Broadband) => Some("wan"),
        Some(Stuck::VpnStuck | Stuck::VpnOff | Stuck::Local) => Some(vpn_or_wan()),
        Some(Stuck::Exit) => Some("exit"),
        None => segs.iter().find(|s| matches!(s.state, "fail" | "off")).map(|s| s.id),
    }
}

/// 面板最上面那一块：AI 通道现在怎样、为什么、该做什么。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Channel {
    /// open / locked / verifying / starting / stopped / error
    pub state: &'static str,
    pub title: String,
    pub detail: String,
    pub advice: String,
    pub locked_ms: Option<u64>,
}

fn first_line(s: &str) -> &str {
    s.lines().next().unwrap_or(s)
}

fn lock_reason(r: &str) -> &str {
    match r {
        "network_change" => "网络刚变化过",
        "kernel_start" => "内核刚启动",
        "exit_down" => "出口刚才连不上",
        "recheck" => "手动核对",
        "periodic" => "定时核对",
        _ => "",
    }
}

pub fn channel(st: &Status, stuck: Option<Stuck>, ctx: &NoticeCtx) -> Channel {
    let ch = |state, title: &str, detail: String, advice: &str| Channel {
        state,
        title: title.to_string(),
        detail,
        advice: advice.to_string(),
        locked_ms: None,
    };
    const SAFE: &str = "AI 程序此时没有网络，不会直连。";
    if let Some(e) = &st.config_error {
        return ch("error", "配置有误", first_line(e).to_string(), &format!("改好 anchor.toml 后点“重新加载配置”。{SAFE}"));
    }
    match st.kernel {
        KernelState::Starting => return ch("starting", "内核启动中", "几秒内就绪".into(), ""),
        KernelState::Restarting => return ch("starting", "内核重启中", "内核意外退出，正在自动恢复".into(), SAFE),
        KernelState::Stopped => return ch("stopped", "内核已停止", String::new(), SAFE),
        KernelState::Error => {
            return ch("error", "内核出错", first_line(st.kernel_error.as_deref().unwrap_or("")).to_string(), SAFE);
        }
        KernelState::Running => {}
    }
    if st.lines_down {
        return ch("locked", "线路不可用", "AI 的新连接会失败，不会直连".into(), "线路恢复后自动继续；也可以用 anchor line use 换一条。");
    }
    let e = &st.exit;
    let mut c = match e.state.as_str() {
        "open" => ch("open", "AI 通道已放行", format!("出口 {} 与基线一致", e.baseline), ""),
        "changed" => ch(
            "locked",
            "AI 通道已锁住",
            format!("出口 IP 已变化：基线 {}，现在 {}", e.baseline, e.actual.as_deref().unwrap_or("未知")),
            "切回原来的出口会自动恢复；确认要换成新 IP，点下面的“登记现在的出口为基线”（或运行 anchor baseline）。",
        ),
        "unverifiable" => ch(
            "locked",
            "AI 通道已锁住",
            "出口能连通，但 IP 回显服务都连不上，无法核对".into(),
            "回显服务恢复后自动核对并放行；一直不行，可以在 [check] ip_echo 换成别的服务。",
        ),
        "no_baseline" => ch("locked", "AI 通道已锁住", "还没有登记出口基线".into(), "确认现在的出口是你要的，然后点下面的“登记现在的出口为基线”（或运行 anchor baseline）。"),
        "" => ch("verifying", "等待核对出口", String::new(), ""),
        _ if e.exit_down => match stuck {
            Some(s) => {
                let locked = Duration::from_millis(e.locked_ms.unwrap_or(0));
                ch("locked", "AI 通道已锁住", Stuck::label(s.name()).to_string(), &stall::notice(s, locked, ctx).1)
            }
            None => ch("locked", "AI 通道已锁住", "出口连不上".into(), "恢复后自动核对出口并放行。"),
        },
        _ => ch("verifying", "正在核对出口", lock_reason(&e.reason).to_string(), "与基线一致就放行，通常只要一两秒。"),
    };
    if c.state != "open" {
        c.locked_ms = e.locked_ms;
    }
    c
}

/// 面板上能直接做的几件事要用到的数据。没有配置线路、没有备用出口时，对应的那一栏不出现。
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Controls {
    /// AI 通道因为“出口 IP 变了”或“还没有基线”锁着：这时给一个登记基线的按钮
    pub baseline_needed: bool,
    pub lines: Option<Lines>,
    /// 主出口和备用出口；只有一个出口时是空的
    pub exits: Vec<ExitRow>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Lines {
    /// 自动换线 / 固定在某条 / 手动
    pub mode: String,
    pub pinned: bool,
    pub rows: Vec<LineRow>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct LineRow {
    pub name: String,
    pub current: bool,
    pub pinned: bool,
    /// ok / fail / unknown：最近一次探测
    pub state: &'static str,
    pub text: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ExitRow {
    pub name: String,
    pub label: String,
    /// 登记的基线 IP；还没登记时为空
    pub baseline: String,
    pub active: bool,
    pub primary: bool,
}

/// 登记基线的按钮只在它能解决问题时出现：内核在运行、配置没错，而通道是因为出口 IP 对不上或没有基线才锁着。
pub fn baseline_needed(st: &Status) -> bool {
    st.config_error.is_none() && st.kernel == KernelState::Running && !st.lines_down && matches!(st.exit.state.as_str(), "changed" | "no_baseline")
}

/// 线路控制器公布的内容（和 anchor line list 是同一份）整理成面板的一栏。
pub fn lines(v: Option<&Value>) -> Option<Lines> {
    let v = v?;
    let rows: Vec<LineRow> = v["lines"]
        .as_array()?
        .iter()
        .filter_map(|l| {
            let name = l["name"].as_str()?.to_string();
            let n = l["samples"].as_u64().unwrap_or(0);
            let mut bits = Vec::new();
            let state = match (l["last_ok"].as_bool(), l["last_ms"].as_u64()) {
                (Some(true), Some(ms)) => {
                    bits.push(format!("通，{ms} ms"));
                    "ok"
                }
                (Some(true), None) => {
                    bits.push("通".to_string());
                    "ok"
                }
                (Some(false), _) => {
                    bits.push("不通".to_string());
                    "fail"
                }
                _ => {
                    bits.push("还没测".to_string());
                    "unknown"
                }
            };
            if let Some(r) = l["rate"].as_f64() {
                bits.push(format!("5 分钟成功率 {:.0}%（{n} 次）", r * 100.0));
            }
            if let Some(m) = l["median_ms"].as_u64() {
                bits.push(format!("中位数 {m} ms"));
            }
            Some(LineRow {
                name,
                current: l["current"].as_bool().unwrap_or(false),
                pinned: l["pinned"].as_bool().unwrap_or(false),
                state,
                text: bits.join(" · "),
            })
        })
        .collect();
    if rows.is_empty() {
        return None;
    }
    let pinned = v["mode"].as_str() == Some("pinned");
    let mode = match v["mode"].as_str().unwrap_or("") {
        "pinned" => format!("固定在 {}，不自动换线", v["pinned"].as_str().unwrap_or("?")),
        "manual" => "手动模式，不自动换线".to_string(),
        _ => "自动换线".to_string(),
    };
    let mode = if v["all_down"].as_bool().unwrap_or(false) { format!("{mode}；所有线路都不可用") } else { mode };
    Some(Lines { mode, pinned, rows })
}

/// 有备用出口时列出所有出口；只有一个出口就没有什么可换的。
pub fn exits(all: &[anchor_core::config::ExitEntry]) -> Vec<ExitRow> {
    if all.len() < 2 {
        return Vec::new();
    }
    all.iter()
        .map(|e| ExitRow {
            name: e.name.clone(),
            // 配置给的说明是“名字（类型 地址）”：名字已经单独显示了，这里只留括号里的
            label: e
                .label
                .strip_prefix(e.name.as_str())
                .map(|rest| rest.trim().trim_start_matches('（').trim_end_matches('）').to_string())
                .filter(|rest| !rest.is_empty())
                .unwrap_or_else(|| e.label.clone()),
            baseline: e.baseline_ip.clone(),
            active: e.active,
            primary: e.primary,
        })
        .collect()
}

fn kernel_label(k: KernelState) -> &'static str {
    match k {
        KernelState::Starting => "启动中",
        KernelState::Running => "运行中",
        KernelState::Restarting => "重启中",
        KernelState::Stopped => "已停止",
        KernelState::Error => "出错",
    }
}

fn guard_text(g: &GuardView) -> String {
    match g.svc.as_str() {
        "running" => match &g.paused_until {
            Some(until) => format!("已暂停，到 {until} 自动恢复"),
            None if g.missing > 0 => format!("运行中，{} 条规则；有 {} 个程序没有覆盖", g.rules, g.missing),
            None => format!("运行中，{} 条规则", g.rules),
        },
        "not_installed" => "没有安装特权服务：应用更新后规则不会自动刷新".into(),
        "unknown" => "正在查询".into(),
        "denied" => "无权访问特权服务".into(),
        _ => format!("状态未知{}", g.error.as_deref().map(|e| format!("：{}", first_line(e))).unwrap_or_default()),
    }
}

pub struct About<'a> {
    pub version: &'a str,
    pub pid: u32,
    pub started_ms: i64,
    pub home: String,
}

/// 面板底部的几行说明：(名称, 内容)。
pub fn facts(st: &Status, a: &About) -> Vec<(&'static str, String)> {
    let mut v = Vec::new();
    let exit = match (st.exit_name.is_empty(), st.exit.baseline.is_empty()) {
        (false, false) => format!("{} · {}", st.exit_name, st.exit.baseline),
        (false, true) => st.exit_name.clone(),
        (true, _) => st.exit.baseline.clone(),
    };
    if !exit.is_empty() {
        v.push(("出口", exit));
    }
    if st.lines > 0 {
        let mode = match st.line_mode.as_str() {
            "auto" => "自动选线",
            "manual" => "手动",
            "pinned" => "已固定",
            other => other,
        };
        v.push(("线路", format!("{}（{mode}，共 {} 条）", st.line.as_deref().unwrap_or("—"), st.lines)));
    }
    let kernel = match st.kernel_pid {
        Some(pid) => format!("{}（pid {pid}，意外退出 {} 次）", kernel_label(st.kernel), st.kernel_restarts),
        None => kernel_label(st.kernel).to_string(),
    };
    v.push(("内核", kernel));
    v.push(("守卫", guard_text(&st.guard)));
    if !st.listen.is_empty() {
        v.push(("AI 入口", st.listen.clone()));
    }
    v.push(("用户代理", format!("{} · pid {} · {} 启动", a.version, a.pid, local_time(a.started_ms))));
    v.push(("数据目录", a.home.clone()));
    v
}

fn pct(part: usize, total: usize) -> f64 {
    if total == 0 { 0.0 } else { (part as f64 * 1000.0 / total as f64).round() / 10.0 }
}

fn summary_json(s: &Summary) -> Value {
    let causes: Vec<Value> =
        s.by_cause.iter().map(|(c, n)| json!({ "id": c, "label": Cause::label(c), "n": n, "pct": pct(*n, s.disconnects) })).collect();
    let triggers: Vec<Value> = s.lock_triggers.iter().map(|(t, n)| json!({ "label": report::trigger_label(t), "n": n })).collect();
    let probes: Vec<Value> = s
        .probes
        .iter()
        .map(|(seg, total, ok)| json!({ "label": report::segment_label(seg), "n": total, "pct": pct(*ok as usize, *total as usize) }))
        .collect();
    json!({
        "disconnects": s.disconnects,
        "errors": s.errors,
        "causes": causes,
        "unknown_pct": (s.unknown_pct * 10.0).round() / 10.0,
        "unknown_target": report::UNKNOWN_TARGET,
        "unknown_ok": s.unknown_pct < report::UNKNOWN_TARGET,
        "locks": s.locks,
        "locked": if s.locked_ms < 1000 { "不到 1 秒".to_string() } else { zh_duration(s.locked_ms / 1000) },
        "lock_triggers": triggers,
        "exit_ip_changes": s.exit_ip_changes,
        "kernel_restarts": s.kernel_restarts,
        "net_changes": s.net_changes,
        "line_switches": s.line_switches,
        "probes": probes,
    })
}

/// 一个小时里 AI 通道锁了多久、断联了几次（最近 24 小时的条形图）。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Hour {
    pub start_ms: i64,
    /// 这一小时开始的钟点，如 "14"
    pub label: String,
    pub locked_s: u64,
    pub disconnects: usize,
}

const HOUR_MS: i64 = 3_600_000;

/// 到当前这个钟点为止的 24 个小时（按本机时区的整点分）。spans：AI 通道锁住的时段。
///
/// 和“按钟点看”同一个口径：一小时里锁住的时间不超过这一小时里有探测记录的时间（observed），
/// 电脑睡着、关机的时候不算锁住。horizon 是还留着的最早一条探测的时间：比它更早的小时没有探测记录可比，不设上限。
pub fn hours(now: i64, offset_ms: i64, observed: &[(i64, u32)], horizon: i64, spans: &[(i64, i64)], rows: &[DisconnectRow]) -> Vec<Hour> {
    let last = (now + offset_ms).div_euclid(HOUR_MS);
    (0..24)
        .map(|k| {
            let idx = last - 23 + k;
            let a = idx * HOUR_MS - offset_ms;
            let b = (a + HOUR_MS).min(now);
            let mut locked: i64 = spans.iter().map(|(s, e)| ((*e).min(b) - (*s).max(a)).max(0)).sum();
            if b > horizon {
                let seen = observed.iter().find(|o| o.0 == idx).map_or(0, |o| i64::from(o.1.min(60)) * 60_000);
                locked = locked.min(seen);
            }
            Hour {
                start_ms: a,
                label: local_time(a).get(11..13).unwrap_or("").to_string(),
                locked_s: (locked.max(0) as u64 + 500) / 1000,
                disconnects: rows.iter().filter(|r| r.ts >= a && r.ts < a + HOUR_MS).count(),
            }
        })
        .collect()
}

/// 按钟点的条形图：每个钟点一根，高度是“看到的天数里有几成锁住过”。
fn by_hour_json(hours: &[report::HourOfDay]) -> Value {
    let bars: Vec<Value> = hours
        .iter()
        .map(|h| {
            let tip = if h.days == 0 {
                format!("{:02} 点：这 7 天里用户代理没有在这个钟点运行过", h.hour)
            } else {
                format!(
                    "{:02} 点：{} 天里有 {} 天锁住过，共锁住 {}，断联 {} 次",
                    h.hour,
                    h.days,
                    h.days_locked,
                    zh_duration(h.locked_ms / 1000),
                    h.disconnects
                )
            };
            json!({
                "label": format!("{:02}", h.hour),
                "days": h.days,
                "days_locked": h.days_locked,
                "share": if h.days == 0 { 0.0 } else { f64::from(h.days_locked) / f64::from(h.days) },
                "tip": tip,
            })
        })
        .collect();
    json!({ "hours": bars, "text": report::hours_summary(hours) })
}

fn disconnect_json(r: &DisconnectRow) -> Value {
    json!({
        "time": local_time(r.ts),
        "domain": r.domain,
        "count": r.count,
        "error": ErrClass::label(&r.class),
        "cause": r.cause,
        "cause_label": Cause::label(&r.cause),
        "why": r.why,
        "raw": if r.cause == "unknown" { r.raw.as_str() } else { "" },
    })
}

/// 列表里最多放多少条断联和事件
const LIST_MAX: usize = 40;

pub fn history(tl: &Timeline, now: i64) -> Result<Value> {
    let day = 24 * HOUR_MS;
    let rows7 = tl.disconnects_since(now - 7 * day)?;
    // 锁住可能开始于统计起点之前：多取一天的事件来推算锁住时段
    let events8 = tl.events_since(now - 8 * day, &[], usize::MAX)?;
    let spans = report::lock_spans(&events8, now);
    let offset = local_offset_ms();
    let observed = tl.observed_minutes(now - 7 * day, offset)?;
    let horizon = tl.oldest_probe()?.unwrap_or(now);
    let times: Vec<i64> = rows7.iter().map(|r| r.ts).collect();
    let period = |span: i64| -> Result<(Value, Vec<report::HourOfDay>)> {
        let since = now - span;
        let rows: Vec<DisconnectRow> = rows7.iter().filter(|r| r.ts >= since).cloned().collect();
        let events: Vec<Event> = events8.iter().filter(|e| e.ts >= since).cloned().collect();
        let mut s = report::summarize(since, &rows, &events, &tl.probe_summary(since)?, &tl.probes_of("exit", since)?, &spans);
        // 锁住的次数和总时长按锁住的时段算，以用户代理在运行的时间为上限
        let by_hour = report::by_hour_of_day(since, now, offset, &observed, &spans, &times);
        s.set_locks(now, &events, &spans, &by_hour, horizon);
        Ok((summary_json(&s), by_hour))
    };
    let recent: Vec<Value> = rows7.iter().rev().take(LIST_MAX).map(disconnect_json).collect();
    let events: Vec<Value> = events8
        .iter()
        .rev()
        .filter(|e| e.ts >= now - day)
        .take(LIST_MAX)
        .map(|e| {
            let (label, text) = describe(e);
            json!({ "time": local_time(e.ts), "label": label, "text": text })
        })
        .collect();
    // 7 天那一份按钟点的汇总，同时用来画“按钟点看”
    let (week, by_hour) = period(7 * day)?;
    Ok(json!({
        "day": period(day)?.0,
        "week": week,
        "hours": hours(now, offset, &observed, horizon, &spans, &rows7),
        "by_hour": by_hour_json(&by_hour),
        "disconnects": recent,
        "events": events,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_core::exitlock::View as ExitView;

    const NOW: i64 = 1_000_000_000;

    fn probe(seg: &str, target: &str, ok: bool, age_s: i64) -> Probe {
        Probe { ts: NOW - age_s * 1000, segment: seg.into(), target: target.into(), ok, ms: ok.then_some(12), note: String::new() }
    }

    fn open_status() -> Status {
        let mut st = Status { kernel: KernelState::Running, exit_name: "main".into(), ..Default::default() };
        st.exit = ExitView { state: "open".into(), baseline: "203.0.113.10".into(), ..Default::default() };
        st
    }

    fn states(v: &[Seg]) -> Vec<(&str, &str)> {
        v.iter().map(|s| (s.id, s.state)).collect()
    }

    fn input<'a>(last: &'a [Probe], st: &'a Status) -> PathIn<'a> {
        PathIn { now_ms: NOW, last, has_uplink: Some(true), via_vpn: true, vpn_seen: true, bind_if: Some("vpn0"), bind_if_down: false, st }
    }

    #[test]
    fn the_baseline_button_only_when_it_would_help() {
        let mut st = open_status();
        assert!(!baseline_needed(&st), "放行着");
        st.exit.state = "changed".into();
        assert!(baseline_needed(&st), "出口 IP 变了");
        st.exit.state = "no_baseline".into();
        assert!(baseline_needed(&st), "还没有基线");
        // 这些情况登记基线解决不了问题，或者现在测不了出口
        st.exit.state = "unverifiable".into();
        assert!(!baseline_needed(&st));
        st.exit.state = "changed".into();
        st.kernel = KernelState::Restarting;
        assert!(!baseline_needed(&st), "内核没在运行");
        st.kernel = KernelState::Running;
        st.config_error = Some("第 3 行".into());
        assert!(!baseline_needed(&st), "配置有误");
        st.config_error = None;
        st.lines_down = true;
        assert!(!baseline_needed(&st), "线路都不通");
        // 两种情况下的建议里都提到了按钮，也留着命令
        st.lines_down = false;
        for state in ["changed", "no_baseline"] {
            st.exit.state = state.into();
            let c = channel(&st, None, &NoticeCtx { bind_if: None, has_backup: false });
            assert!(c.advice.contains("登记现在的出口为基线") && c.advice.contains("anchor baseline"), "{}", c.advice);
        }
    }

    #[test]
    fn lines_as_the_panel_shows_them() {
        assert_eq!(lines(None), None, "没有配置线路");
        assert_eq!(lines(Some(&json!({ "mode": "auto", "lines": [] }))), None);
        let v = json!({
            "mode": "auto", "current": "hk", "pinned": null, "all_down": false,
            "lines": [
                { "name": "hk", "current": true, "pinned": false, "samples": 30, "rate": 0.967, "median_ms": 88, "last_ok": true, "last_ms": 91 },
                { "name": "jp", "current": false, "pinned": false, "samples": 30, "rate": 0.5, "median_ms": null, "last_ok": false, "last_ms": null },
                { "name": "sg", "current": false, "pinned": false, "samples": 0, "rate": null, "median_ms": null, "last_ok": null, "last_ms": null },
            ],
        });
        let l = lines(Some(&v)).unwrap();
        assert_eq!((l.mode.as_str(), l.pinned), ("自动换线", false));
        let rows: Vec<(&str, bool, &str, &str)> = l.rows.iter().map(|r| (r.name.as_str(), r.current, r.state, r.text.as_str())).collect();
        assert_eq!(
            rows,
            [
                ("hk", true, "ok", "通，91 ms · 5 分钟成功率 97%（30 次） · 中位数 88 ms"),
                ("jp", false, "fail", "不通 · 5 分钟成功率 50%（30 次）"),
                ("sg", false, "unknown", "还没测"),
            ]
        );

        let mut v = v;
        v["mode"] = json!("pinned");
        v["pinned"] = json!("jp");
        v["all_down"] = json!(true);
        v["lines"][1]["pinned"] = json!(true);
        let l = lines(Some(&v)).unwrap();
        assert_eq!((l.mode.as_str(), l.pinned), ("固定在 jp，不自动换线；所有线路都不可用", true));
        assert!(l.rows[1].pinned && !l.rows[0].pinned);
    }

    #[test]
    fn exits_are_listed_only_when_there_is_a_choice() {
        use anchor_core::config::ExitEntry;
        let e = |name: &str, ip: &str, active: bool, primary: bool| ExitEntry {
            name: name.into(),
            label: format!("{name}（socks 203.0.113.11:1080）"),
            baseline_ip: ip.into(),
            active,
            primary,
        };
        assert_eq!(exits(&[]), []);
        assert_eq!(exits(&[e("home", "203.0.113.10", true, true)]), [], "只有一个出口，没有什么可换的");
        let rows = exits(&[e("home", "203.0.113.10", false, true), e("backup", "", true, false)]);
        let got: Vec<(&str, &str, bool, bool)> = rows.iter().map(|r| (r.name.as_str(), r.baseline.as_str(), r.active, r.primary)).collect();
        assert_eq!(got, [("home", "203.0.113.10", false, true), ("backup", "", true, false)]);
        assert_eq!(rows[0].label, "socks 203.0.113.11:1080", "名字不重复写");
        let odd = exits(&[e("home", "", true, true), ExitEntry { name: "b".into(), label: "别的写法".into(), baseline_ip: String::new(), active: false, primary: false }]);
        assert_eq!(odd[1].label, "别的写法", "不是那种格式就原样显示");
    }

    #[test]
    fn path_when_everything_works() {
        let st = open_status();
        let last = [probe("lan", "wifi", true, 3), probe("wan", "wifi", true, 3), probe("local", "vpn", true, 2), probe("chain", "exit", true, 20)];
        let v = path(&input(&last, &st));
        assert_eq!(states(&v), [("device", "ok"), ("lan", "ok"), ("wan", "ok"), ("vpn", "ok"), ("exit", "ok"), ("ai", "ok")]);
        assert_eq!((v[1].sub.as_str(), v[1].text.as_str()), ("Wi-Fi", "12 ms"));
        assert_eq!((v[3].sub.as_str(), v[4].sub.as_str()), ("vpn0", "203.0.113.10"));
        assert_eq!(culprit(&v, true, None), None, "放行着就不标");
        // 刚放行，最近一次整条链路探测还是锁住期间的那次失败：写明是多久以前
        let last = [probe("chain", "exit", false, 20)];
        let v = path(&input(&last, &st));
        assert_eq!((v[5].state, v[5].text.as_str()), ("warn", "20 秒前整条链路探测失败"));
    }

    #[test]
    fn path_when_the_vpn_is_stuck_or_off() {
        let mut st = open_status();
        st.exit = ExitView { state: "verifying".into(), locked: true, exit_down: true, baseline: "203.0.113.10".into(), ..Default::default() };
        let last = [probe("lan", "wifi", true, 3), probe("wan", "wifi", true, 3), probe("local", "vpn", false, 2), probe("chain", "exit", false, 20)];
        let v = path(&input(&last, &st));
        assert_eq!(states(&v), [("device", "ok"), ("lan", "ok"), ("wan", "ok"), ("vpn", "fail"), ("exit", "fail"), ("ai", "blocked")]);
        assert_eq!(culprit(&v, false, Some(Stuck::VpnStuck)), Some("vpn"));
        assert_eq!(culprit(&v, false, None), Some("vpn"), "用户代理还没判断时，取路上第一段不通的");

        // VPN 断开：出口绑定的网卡没有连接
        let mut i = input(&last, &st);
        i.bind_if_down = true;
        i.via_vpn = false;
        let v = path(&i);
        assert_eq!((v[3].state, v[3].text.as_str()), ("off", "没有连接"));
        // 没有绑定网卡，但默认流量不再经 VPN
        let mut i = input(&last, &st);
        i.bind_if = None;
        i.via_vpn = false;
        assert_eq!(path(&i)[3].state, "off");
    }

    #[test]
    fn path_when_wifi_is_off() {
        let mut st = open_status();
        st.exit = ExitView { state: "verifying".into(), locked: true, exit_down: true, ..Default::default() };
        // 断开那一刻记了一条；之后不再有路由器和宽带的探测
        let last = [probe("lan", "none", false, 5), probe("wan", "wifi", true, 70), probe("local", "direct", false, 4)];
        let mut i = input(&last, &st);
        i.has_uplink = Some(false);
        i.via_vpn = false;
        let v = path(&i);
        assert_eq!((v[1].state, v[1].text.as_str()), ("fail", "没有连上 Wi-Fi 或网线"));
        assert_eq!(v[2].state, "unknown", "太旧的探测结果不算");
        assert_eq!(culprit(&v, false, Some(Stuck::Link)), Some("lan"));
        // 那条记录也过期之后，靠“没有上行网卡”判断
        let i = PathIn { last: &[], ..i };
        assert_eq!(path(&i)[1].state, "fail");
    }

    #[test]
    fn path_without_a_vpn_and_with_lines() {
        let mut st = open_status();
        st.lines = 2;
        st.line = Some("line-a".into());
        // 没有 VPN：“本机上网”测的就是宽带
        let last = [probe("lan", "ethernet", true, 3), probe("local", "direct", true, 2)];
        fn plain<'a>(last: &'a [Probe], st: &'a Status) -> PathIn<'a> {
            PathIn { now_ms: NOW, last, has_uplink: Some(true), via_vpn: false, vpn_seen: false, bind_if: None, bind_if_down: false, st }
        }
        let v = path(&plain(&last, &st));
        assert_eq!(states(&v), [("device", "ok"), ("lan", "ok"), ("wan", "ok"), ("line", "ok"), ("exit", "ok"), ("ai", "unknown")]);
        assert_eq!((v[1].sub.as_str(), v[3].sub.as_str()), ("网线", "line-a"));
        assert_eq!(culprit(&v, false, Some(Stuck::Local)), Some("wan"), "没有 VPN 这一段时，标在宽带上");

        st.exit.state = "changed".into();
        st.exit.locked = true;
        st.exit.actual = Some("198.51.100.9".into());
        let v = path(&plain(&last, &st));
        assert_eq!(v[4].text, "IP 已变化：现在 198.51.100.9");
        assert_eq!(culprit(&v, false, None), Some("exit"));
    }

    #[test]
    fn channel_says_what_is_going_on() {
        let ctx = NoticeCtx { bind_if: Some("vpn0"), has_backup: false };
        let mut st = open_status();
        let c = channel(&st, None, &ctx);
        assert_eq!((c.state, c.title.as_str(), c.detail.as_str()), ("open", "AI 通道已放行", "出口 203.0.113.10 与基线一致"));
        assert_eq!(c.locked_ms, None);

        st.exit = ExitView { state: "verifying".into(), locked: true, reason: "network_change".into(), locked_ms: Some(900), ..Default::default() };
        let c = channel(&st, None, &ctx);
        assert_eq!((c.state, c.title.as_str(), c.detail.as_str(), c.locked_ms), ("verifying", "正在核对出口", "网络刚变化过", Some(900)));

        st.exit.exit_down = true;
        st.exit.locked_ms = Some(41_000);
        let c = channel(&st, Some(Stuck::VpnStuck), &ctx);
        assert_eq!((c.state, c.detail.as_str()), ("locked", "VPN 卡住了"));
        assert!(c.advice.contains("断开再重新连接") && c.advice.contains("41 秒"), "{}", c.advice);
        assert_eq!(channel(&st, None, &ctx).detail, "出口连不上");

        st.exit.state = "changed".into();
        st.exit.baseline = "203.0.113.10".into();
        st.exit.actual = Some("198.51.100.9".into());
        let c = channel(&st, None, &ctx);
        assert!(c.detail.contains("203.0.113.10") && c.detail.contains("198.51.100.9") && c.advice.contains("anchor baseline"));

        // 内核和配置的问题排在出口前面
        st.kernel = KernelState::Restarting;
        assert_eq!(channel(&st, None, &ctx).state, "starting");
        st.config_error = Some("第 3 行有误\n详情".into());
        let c = channel(&st, None, &ctx);
        assert_eq!((c.state, c.detail.as_str()), ("error", "第 3 行有误"));
    }

    #[test]
    fn facts_cover_exit_kernel_and_guard() {
        let mut st = open_status();
        st.kernel_pid = Some(42);
        st.guard = GuardView { svc: "running".into(), rules: 6, missing: 1, ..Default::default() };
        let a = About { version: "0.2.0", pid: 7, started_ms: 0, home: "C:\\data".into() };
        let f = facts(&st, &a);
        let get = |k: &str| f.iter().find(|(n, _)| *n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("出口"), Some("main · 203.0.113.10"));
        assert_eq!(get("内核"), Some("运行中（pid 42，意外退出 0 次）"));
        assert_eq!(get("守卫"), Some("运行中，6 条规则；有 1 个程序没有覆盖"));
        assert_eq!(get("线路"), None, "没有配置线路就不显示");
        st.guard.svc = "not_installed".into();
        assert!(facts(&st, &a).iter().any(|(_, v)| v.contains("没有安装特权服务")));
    }

    #[test]
    fn hours_split_locks_and_count_disconnects() {
        let now = 100 * HOUR_MS + 30 * 60_000; // 某个钟点过了 30 分
        let row = |ts| DisconnectRow {
            ts,
            domain: "claude.ai".into(),
            phase: "open".into(),
            class: "timeout".into(),
            outbound: String::new(),
            cause: "vpn".into(),
            why: String::new(),
            raw: String::new(),
            count: 1,
        };
        // 一次锁住跨了两个小时：前一小时的最后 10 分钟，加这一小时的头 5 分钟
        let spans = [(100 * HOUR_MS - 600_000, 100 * HOUR_MS + 300_000), (50 * HOUR_MS, 50 * HOUR_MS + 1000)];
        let rows = [row(100 * HOUR_MS + 1), row(100 * HOUR_MS + 2), row(99 * HOUR_MS + 5), row(10 * HOUR_MS)];
        // 没有探测记录可比时（horizon 传 now）：锁了多久就是多久
        let h = hours(now, 0, &[], now, &spans, &rows);
        assert_eq!(h.len(), 24);
        assert_eq!((h[23].start_ms, h[23].locked_s, h[23].disconnects), (100 * HOUR_MS, 300, 2));
        assert_eq!((h[22].locked_s, h[22].disconnects), (600, 1));
        assert_eq!(h.iter().map(|x| x.locked_s).sum::<u64>(), 900, "24 小时以外的不算");
        // 还锁着：只算到现在
        let h = hours(now, 0, &[], now, &[(100 * HOUR_MS + 20 * 60_000, i64::MAX)], &[]);
        assert_eq!(h[23].locked_s, 600);

        // 有探测记录时：一小时里锁住的时间不超过用户代理在运行的时间。
        // 第 97 小时锁住后电脑睡了，第 99 小时醒来：睡着的第 98 小时不算，第 97 小时只运行了 20 分钟
        let asleep = [(97 * HOUR_MS + 10 * 60_000, 99 * HOUR_MS + 5 * 60_000)];
        let observed = [(97, 20), (99, 60), (100, 30)];
        let h = hours(now, 0, &observed, 0, &asleep, &[]);
        assert_eq!((h[20].locked_s, h[21].locked_s, h[22].locked_s), (20 * 60, 0, 5 * 60));
        // 探测明细留不到那么早的小时（horizon 之前）不设上限
        let h = hours(now, 0, &observed, 99 * HOUR_MS, &asleep, &[]);
        assert_eq!((h[20].locked_s, h[21].locked_s, h[22].locked_s), (50 * 60, 60 * 60, 5 * 60));
        // 小时按本机时区的整点分：东 5 区半，整点落在 UTC 的半点上
        let off = 5 * HOUR_MS + 30 * 60_000;
        let h = hours(now, off, &[], now, &[], &[]);
        assert_eq!((h[23].start_ms + off) % HOUR_MS, 0);
        assert!(h[23].start_ms <= now && now - h[23].start_ms < HOUR_MS);
    }

    /// 手动跑：对着一份真实的时间线（只读）算一遍统计，看要多久。
    /// `ANCHOR_TIMELINE=<timeline.db> cargo test -p anchor-agent real_timeline -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn history_on_a_real_timeline() {
        let Some(path) = std::env::var_os("ANCHOR_TIMELINE") else { return };
        let tl = Timeline::open_read_only(std::path::Path::new(&path)).unwrap();
        let t = std::time::Instant::now();
        let h = history(&tl, anchor_core::timeline::now_ms()).unwrap();
        let took = t.elapsed();
        let last = tl.last_probes(anchor_core::timeline::now_ms() - 120_000).unwrap();
        println!(
            "history: {took:?}; week: {} disconnects, {} locks, unknown {}%; day: {} disconnects; list {}; events {}; last probes {} in {:?}",
            h["week"]["disconnects"],
            h["week"]["locks"],
            h["week"]["unknown_pct"],
            h["day"]["disconnects"],
            h["disconnects"].as_array().unwrap().len(),
            h["events"].as_array().unwrap().len(),
            last.len(),
            t.elapsed() - took
        );
    }

    #[test]
    fn history_from_a_timeline() {
        let tl = Timeline::memory().unwrap();
        let now = 200 * 24 * HOUR_MS;
        let row = |ts, cause: &str| DisconnectRow {
            ts,
            domain: "api.anthropic.com".into(),
            phase: "open".into(),
            class: "timeout".into(),
            outbound: String::new(),
            cause: cause.into(),
            why: "依据".into(),
            raw: "dial tcp: i/o timeout".into(),
            count: 2,
        };
        tl.disconnect(&row(now - HOUR_MS, "vpn"));
        tl.disconnect(&row(now - 2 * HOUR_MS, "unknown"));
        tl.disconnect(&row(now - 3 * 24 * HOUR_MS, "vpn"));
        tl.event_at(now - 2 * HOUR_MS, "exit_locked", json!({ "reason": "exit_down" }));
        tl.event_at(now - 2 * HOUR_MS + 90_000, "exit_unlocked", json!({ "trigger": "exit_down", "locked_ms": 90_000, "ip": "203.0.113.10" }));
        let h = history(&tl, now).unwrap();
        assert_eq!((h["day"]["disconnects"].as_u64(), h["week"]["disconnects"].as_u64()), (Some(2), Some(3)));
        assert_eq!(h["day"]["unknown_pct"], json!(50.0));
        assert_eq!(h["day"]["unknown_ok"], json!(false));
        assert_eq!(h["week"]["causes"][0], json!({ "id": "vpn", "label": "VPN", "n": 2, "pct": 66.7 }));
        assert_eq!((h["day"]["locks"].as_u64(), h["day"]["locked"].as_str()), (Some(1), Some("1 分 30 秒")));
        assert_eq!(h["hours"].as_array().unwrap().iter().map(|x| x["locked_s"].as_u64().unwrap()).sum::<u64>(), 90);
        // 最近的在前；只有“未知”带原始错误
        let d = h["disconnects"].as_array().unwrap();
        assert_eq!((d.len(), d[0]["cause_label"].as_str(), d[0]["raw"].as_str()), (3, Some("VPN"), Some("")));
        assert_eq!(d[1]["raw"].as_str(), Some("dial tcp: i/o timeout"));
        let e = h["events"].as_array().unwrap();
        assert_eq!((e.len(), e[0]["label"].as_str()), (2, Some("出口放行")));
        // 按钟点：这份时间线里没有探测记录，所以哪个钟点都没看到
        let bars = h["by_hour"]["hours"].as_array().unwrap();
        assert_eq!((bars.len(), bars[7]["label"].as_str(), bars[7]["days"].as_u64()), (24, Some("07"), Some(0)));
        assert_eq!(h["by_hour"]["text"].as_str(), Some("没有哪个钟点在两天以上锁住过，看不出高峰时段"));
    }

    #[test]
    fn by_hour_bars_say_how_many_days_were_locked() {
        let mut hours: Vec<report::HourOfDay> = (0..24).map(|hour| report::HourOfDay { hour, ..Default::default() }).collect();
        hours[19] = report::HourOfDay { hour: 19, days: 6, days_locked: 4, observed_ms: 6 * 3_600_000, locked_ms: 42 * 60_000, disconnects: 31 };
        let v = by_hour_json(&hours);
        assert_eq!(v["hours"][19]["tip"].as_str(), Some("19 点：6 天里有 4 天锁住过，共锁住 42 分，断联 31 次"));
        assert_eq!(v["hours"][19]["share"].as_f64().map(|x| (x * 100.0).round()), Some(67.0));
        assert_eq!(v["hours"][3]["tip"].as_str(), Some("03 点：这 7 天里用户代理没有在这个钟点运行过"));
        assert_eq!(v["text"].as_str(), Some("最容易锁住的钟点：19 点（6 天里有 4 天锁住过，共 42 分）"));
    }
}
