//! 断联采集与归因（P1b；设计见 P1 详细设计“断联采集与归因”一节）。
//!
//! 用户代理实时读 sing-box 日志：AI 程序经 AI 入站访问 AI 域名的连接出错，就记一次断联，
//! 同一域名 5 秒内的多条错误合并成一次。断联发生后补一轮探测，再用断联前后的探测和事件判断故障在哪一段。
//!
//! 日志格式不是 sing-box 的公开接口：解析按 1.14 实测的格式写，认不出的行跳过，原始错误文本原样保存。
//! 实测的几类错误：DNS 解析超时（lookup … deadline exceeded）、网络不可达（隧道刚断或刚恢复）、
//! 连接超时（dial tcp … i/o timeout）、上游代理拒绝（socks5: request rejected）。
//!
//! AI 通道锁住期间，内核按规则直接拒绝 AI 入站的连接，不记错误。这些连接从日志里的模式切换
//! （`clash-mode: updated mode: Lock/Open`，内核启动时是锁住的）和入站连接认出来：
//! 一次锁住期间拦下的 AI 域名连接合并成一次断联，按锁住的原因归因。

use crate::rules;
use crate::singbox::{MODE_LOCK, MODE_OPEN, TAG_IN};
use crate::timeline::{Event, Probe};
use serde::Serialize;
use std::collections::HashMap;

/// 同一域名这么久之内的错误合并成一次断联（从第一条算）
pub const MERGE_MS: i64 = 5_000;
/// 归因窗口：断联前 30 秒到断联后 15 秒。突发探测在断联后几秒内完成，所以等窗口结束再归因。
/// 网络变化、内核重启这类一次性的事件看整个窗口（余波会持续一阵）；
/// 探测失败只看断联前 10 秒到之后 15 秒，要反映断联那一刻的状态，免得前一次故障算到这一次头上。
pub const WINDOW_BEFORE_MS: i64 = 30_000;
pub const WINDOW_AFTER_MS: i64 = 15_000;
const PROBE_BEFORE_MS: i64 = 10_000;

/// 一行 sing-box 日志。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogLine<'a> {
    /// 毫秒时间戳
    pub ts: i64,
    pub level: &'a str,
    /// 连接编号（行首 [编号 耗时] 里的编号）
    pub conn: Option<u64>,
    pub msg: &'a str,
}

/// 解析 `-0800 2026-11-14 10:07:11 ERROR [2781160631 0ms] connection: …`。不是这个格式就返回 None。
pub fn parse_line(line: &str) -> Option<LogLine<'_>> {
    let line = line.trim_end_matches(['\r', '\n']);
    let mut it = line.splitn(5, ' ');
    let (tz, date, time, level, rest) = (it.next()?, it.next()?, it.next()?, it.next()?, it.next()?);
    let ts = chrono::DateTime::parse_from_str(&format!("{date} {time} {tz}"), "%Y-%m-%d %H:%M:%S %z").ok()?.timestamp_millis();
    let (conn, msg) = match rest.strip_prefix('[') {
        Some(r) => {
            let end = r.find(']')?;
            (r[..end].split(' ').next().and_then(|id| id.parse().ok()), r[end + 1..].trim_start())
        }
        None => (None, rest),
    };
    Some(LogLine { ts, level, conn, msg })
}

/// 错误文本的类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrClass {
    Dns,
    Unreachable,
    Timeout,
    Refused,
    /// 上游代理（出口或线路服务器）拒绝了请求
    Rejected,
    Reset,
    Tls,
    Other,
    /// AI 通道锁住期间被拦下：内核不记错误，按日志里的模式切换和入站连接认出来
    Locked,
}

impl ErrClass {
    pub fn name(self) -> &'static str {
        match self {
            ErrClass::Dns => "dns",
            ErrClass::Unreachable => "unreachable",
            ErrClass::Timeout => "timeout",
            ErrClass::Refused => "refused",
            ErrClass::Rejected => "rejected",
            ErrClass::Reset => "reset",
            ErrClass::Tls => "tls",
            ErrClass::Other => "other",
            ErrClass::Locked => "locked",
        }
    }

    pub fn label(name: &str) -> &'static str {
        match name {
            "dns" => "DNS 解析失败",
            "unreachable" => "网络不可达",
            "timeout" => "连接超时",
            "refused" => "连接被拒绝",
            "rejected" => "上游代理拒绝",
            "reset" => "连接被重置",
            "tls" => "TLS 失败",
            "locked" => "锁住拦下",
            _ => "其他错误",
        }
    }
}

/// 按错误文本分类。顺序有讲究：DNS 超时的文本里也有 deadline exceeded，要先认 lookup。
pub fn classify(reason: &str) -> ErrClass {
    let r = reason.to_ascii_lowercase();
    let has = |s: &str| r.contains(s);
    if has("lookup ") {
        ErrClass::Dns
    } else if has("unreachable network") || has("unreachable host") || has("network is unreachable") || has("no route to host") {
        ErrClass::Unreachable
    } else if has("request rejected") {
        ErrClass::Rejected
    } else if has("refused") {
        ErrClass::Refused
    } else if has("i/o timeout") || has("timed out") || has("deadline exceeded") {
        ErrClass::Timeout
    } else if has("tls") || has("x509") || has("certificate") {
        ErrClass::Tls
    } else if has("reset") || has("forcibly closed") || has("aborted") || has("broken pipe") || has("eof") {
        ErrClass::Reset
    } else {
        ErrClass::Other
    }
}

/// 一次断联（还没归因）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disconnect {
    pub ts: i64,
    pub domain: String,
    /// open：连接建不起来；relay：建立后出错
    pub phase: &'static str,
    pub class: ErrClass,
    /// 出错的出站，如 direct[exit]、shadowsocks[line-a]
    pub outbound: String,
    /// 原始错误文本（截断）
    pub raw: String,
    /// 合并进来的错误条数（锁住拦下的：拦下的连接数）
    pub count: u32,
    /// 锁住拦下的：这次锁住从什么时候到什么时候（还锁着时 until 为 None）
    pub lock: Option<LockSpan>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockSpan {
    pub since: i64,
    pub until: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Feed {
    /// 新的一次断联
    New(Disconnect),
    /// 并入 domain 上 ts 开始的那次断联；locked：并入的是锁住拦下的那种
    Merged { domain: String, first_ts: i64, locked: bool },
    /// 锁住拦下的那次断联所在的锁住结束了（at：放行时间）
    LockEnded { domain: String, first_ts: i64, at: i64 },
}

struct Conn {
    inbound: String,
    host: String,
    ts: i64,
    /// 锁住时被拦下的（内核按理不会再给它记错误；万一记了也不重复算）
    intercepted: bool,
}

/// 按连接编号把入站目标和错误串起来；按模式切换行跟踪 AI 通道是否锁住。
#[derive(Default)]
pub struct Tracker {
    conns: HashMap<u64, Conn>,
    /// 域名 → 当前这次断联的开始时间
    open: HashMap<String, i64>,
    latest: i64,
    /// AI 通道锁住的开始时间（放行时为 None）
    locked_since: Option<i64>,
    /// 这次锁住期间已经记下的断联：(域名, 开始时间)
    lock_dc: Option<(String, i64)>,
}

impl Tracker {
    pub fn feed(&mut self, l: &LogLine) -> Option<Feed> {
        self.latest = self.latest.max(l.ts);
        let Some(id) = l.conn else { return self.mode_line(l) };
        if let Some((inbound, host)) = inbound_target(l.msg) {
            let intercepted = self.locked_since.is_some() && inbound == TAG_IN && rules::is_ai_domain(&host);
            self.conns.insert(id, Conn { inbound, host: host.clone(), ts: l.ts, intercepted });
            if self.conns.len() > 20_000 {
                let cutoff = self.latest - 10 * 60_000;
                self.conns.retain(|_, c| c.ts >= cutoff);
            }
            return if intercepted { Some(self.intercept(host, l.ts)) } else { None };
        }
        if l.level != "ERROR" {
            return None;
        }
        let c = self.conns.get(&id)?;
        if c.intercepted || c.inbound != TAG_IN || !rules::is_ai_domain(&c.host) {
            return None;
        }
        let host = c.host.clone();
        if let Some(first) = self.open.get(&host)
            && l.ts - *first < MERGE_MS
        {
            return Some(Feed::Merged { domain: host, first_ts: *first, locked: false });
        }
        let (phase, outbound, reason) = parse_error(l.msg);
        self.open.insert(host.clone(), l.ts);
        Some(Feed::New(Disconnect {
            ts: l.ts,
            domain: host,
            phase,
            class: classify(reason),
            outbound,
            raw: reason.chars().take(500).collect(),
            count: 1,
            lock: None,
        }))
    }

    /// 没有连接编号的行：模式切换、内核启动（用户代理生成的配置里 AI 通道以锁住状态启动）。
    fn mode_line(&mut self, l: &LogLine) -> Option<Feed> {
        let mode = l.msg.strip_prefix("clash-mode: updated mode: ");
        if mode == Some(MODE_LOCK) || l.msg.starts_with("sing-box started") {
            // 已经锁着时内核重启：还是同一次锁住
            self.locked_since.get_or_insert(l.ts);
        } else if mode == Some(MODE_OPEN) {
            self.locked_since = None;
            return self.lock_dc.take().map(|(domain, first_ts)| Feed::LockEnded { domain, first_ts, at: l.ts });
        }
        None
    }

    /// 锁住时 AI 程序连 AI 域名：一次锁住期间的合并成一次断联。
    fn intercept(&mut self, host: String, ts: i64) -> Feed {
        if let Some((domain, first_ts)) = &self.lock_dc {
            return Feed::Merged { domain: domain.clone(), first_ts: *first_ts, locked: true };
        }
        let since = self.locked_since.unwrap_or(ts);
        self.lock_dc = Some((host.clone(), ts));
        Feed::New(Disconnect {
            ts,
            domain: host,
            phase: "locked",
            class: ErrClass::Locked,
            outbound: String::new(),
            raw: "AI 通道锁住，连接被拦下".into(),
            count: 1,
            lock: Some(LockSpan { since, until: None }),
        })
    }
}

/// `inbound/mixed[ai-in]: inbound connection to claude.ai:443`（探测入站多一段 `[用户名] `）→ (入站, 主机)
fn inbound_target(msg: &str) -> Option<(String, String)> {
    let rest = msg.strip_prefix("inbound/")?;
    let (lb, rb) = (rest.find('[')?, rest.find(']')?);
    let tag = rest.get(lb + 1..rb)?;
    let after = rest[rb + 1..].trim_start_matches(':').trim_start();
    let after = if after.starts_with('[') { after.split_once("] ")?.1 } else { after };
    let target = after.strip_prefix("inbound connection to ")?;
    Some((tag.to_string(), host_of(target)))
}

fn host_of(target: &str) -> String {
    let t = target.trim();
    let host = match t.strip_prefix('[') {
        Some(r) => r.split(']').next().unwrap_or(r),
        None => t.rsplit_once(':').map_or(t, |(h, _)| h),
    };
    host.to_ascii_lowercase()
}

/// `connection: open connection to HOST:PORT using outbound/TYPE[TAG]: REASON` → (open, TYPE[TAG], REASON)；
/// 其他 `connection: REASON` 视为建立后出错。
fn parse_error(msg: &str) -> (&'static str, String, &str) {
    if let Some(r) = msg.strip_prefix("connection: open connection to ") {
        if let Some((_, after)) = r.split_once(" using outbound/")
            && let Some((ob, reason)) = after.split_once("]: ")
        {
            return ("open", format!("{ob}]"), reason);
        }
        return ("open", String::new(), r);
    }
    ("relay", String::new(), msg.strip_prefix("connection: ").unwrap_or(msg))
}

/// 故障所在的一段。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Cause {
    /// 本机网络：Wi-Fi 或网线、宽带
    Local,
    /// 本机网络正常，VPN 隧道断了或卡住
    Vpn,
    Kernel,
    Line,
    Exit,
    Service,
    Unknown,
}

impl Cause {
    pub fn name(self) -> &'static str {
        match self {
            Cause::Local => "local",
            Cause::Vpn => "vpn",
            Cause::Kernel => "kernel",
            Cause::Line => "line",
            Cause::Exit => "exit",
            Cause::Service => "service",
            Cause::Unknown => "unknown",
        }
    }

    pub fn label(name: &str) -> &'static str {
        match name {
            "local" => "本地",
            "vpn" => "VPN",
            "kernel" => "内核",
            "line" => "线路",
            "exit" => "出口",
            "service" => "服务端",
            _ => "未知",
        }
    }

    pub const ALL: [Cause; 7] = [Cause::Local, Cause::Vpn, Cause::Kernel, Cause::Line, Cause::Exit, Cause::Service, Cause::Unknown];
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub cause: Cause,
    /// 归因依据，一句话
    pub why: String,
}

/// 按设计的顺序归因：内核 → 本地（Wi-Fi、宽带）或 VPN → 线路 → 出口 → 服务端 → 未知。
/// probes、events 取断联前后窗口内的（多给了也会按窗口筛）；has_lines：配置了线路。
pub fn attribute(d: &Disconnect, probes: &[Probe], events: &[Event], has_lines: bool) -> Verdict {
    // 锁住拦下的：窗口从锁住那一刻算起（第一条被拦下的连接可能在锁住好几分钟之后）
    let from = window_start(d);
    let in_win = |ts: i64| ts >= from - WINDOW_BEFORE_MS && ts <= d.ts + WINDOW_AFTER_MS;
    let near = |ts: i64| ts >= from - PROBE_BEFORE_MS && ts <= d.ts + WINDOW_AFTER_MS;
    let failed = |seg: &str| probes.iter().filter(|p| near(p.ts) && p.segment == seg && !p.ok).count();
    let event = |kinds: &[&str]| events.iter().find(|e| in_win(e.ts) && kinds.contains(&e.kind.as_str()));
    let v = |cause, why: String| Verdict { cause, why };

    // 1. 内核意外退出：经它的连接全部中断
    if event(&["kernel_restart", "kernel_error"]).is_some() {
        return v(Cause::Kernel, "前后 30 秒内内核意外退出或出错".into());
    }
    // 2. 本机网络，由近到远：电脑到路由器（lan）→ 绕开 VPN 上网（wan）→ 经 VPN 上网（local 的目标是 vpn）。
    // 绕开 VPN 能上网、本机上网又是经 VPN 的，问题才定在 VPN 上；没有这些数据时按原来的笼统说法归“本地”
    let ok_near = |seg: &str| probes.iter().any(|p| near(p.ts) && p.segment == seg && p.ok);
    let has_vpn = probes.iter().any(|p| near(p.ts) && p.segment == "local" && p.target == "vpn");
    let vpn_suspect = has_vpn && ok_near("wan");
    let n = failed("lan");
    if n > 0 {
        return v(Cause::Local, format!("连不上路由器 {n} 次：Wi-Fi 或网线断了"));
    }
    if event(&["uplink_change"]).is_some() {
        return v(Cause::Local, "前后 30 秒内换了网络（Wi-Fi 或网线）".into());
    }
    let n = failed("wan");
    if n > 0 {
        return v(Cause::Local, format!("路由器通，绕开 VPN 也上不了网 {n} 次：宽带、热点或路由器的上游断了"));
    }
    let n = failed("local");
    if n > 0 {
        if vpn_suspect {
            return v(Cause::Vpn, format!("Wi-Fi 和宽带正常（绕开 VPN 能上网），经 VPN 上网失败 {n} 次：VPN 隧道断了或卡住"));
        }
        return v(Cause::Local, format!("本地网络探测失败 {n} 次"));
    }
    if event(&["net_change"]).is_some() {
        if vpn_suspect {
            return v(Cause::Vpn, "前后 30 秒内网卡地址或路由有变化，Wi-Fi 和宽带正常：多半是 VPN 断开或重连".into());
        }
        return v(Cause::Local, "前后 30 秒内网络有变化（VPN 断开、重连或换网络）".into());
    }
    if d.class == ErrClass::Unreachable {
        if vpn_suspect {
            return v(Cause::Vpn, "系统报告网络不可达，Wi-Fi 和宽带正常：VPN 隧道当时不可用".into());
        }
        return v(Cause::Local, "系统报告网络不可达：隧道或路由当时不可用".into());
    }
    // 3. 线路
    if has_lines {
        let n = failed("line");
        if n > 0 {
            return v(Cause::Line, format!("线路探测失败 {n} 次"));
        }
        if event(&["line_down", "all_lines_down"]).is_some() {
            return v(Cause::Line, "前后 30 秒内线路故障".into());
        }
    }
    // 4. 出口。锁住拦下的：本地、内核、线路都没问题，就看是什么锁住的
    if d.class == ErrClass::Locked {
        return locked_verdict(d, events);
    }
    if event(&["exit_ip_changed"]).is_some() {
        return v(Cause::Exit, "前后 30 秒内出口 IP 变化".into());
    }
    if exit_down_at(d.ts, events) {
        return v(Cause::Exit, "出口不可达，AI 通道锁住".into());
    }
    let n = failed("chain");
    if n > 0 {
        return v(Cause::Exit, format!("整条链路探测失败 {n} 次"));
    }
    // 5. 服务端：其余各段正常，偏偏这个域名经出口访问不了，或官方报告严重故障
    if probes.iter().any(|p| in_win(p.ts) && p.segment == "ai" && p.target == d.domain && !p.ok) {
        return v(Cause::Service, format!("其余各段正常，经出口访问 {} 失败", d.domain));
    }
    if let Some(p) = probes.iter().find(|p| in_win(p.ts) && p.segment == "status" && !p.ok) {
        return v(Cause::Service, format!("{} 官方状态页报告故障：{}", p.target, p.note));
    }
    // 6. 探测都没指出问题时，按错误本身判断：这两类是出口一侧报的错
    if d.class == ErrClass::Rejected {
        return v(Cause::Exit, "出口（或上游代理）拒绝了这次连接，各段探测正常：多半是一时的".into());
    }
    if d.class == ErrClass::Dns {
        return v(Cause::Exit, "经出口的 DNS 解析失败，各段探测正常：多半是一时的".into());
    }
    v(Cause::Unknown, "各段探测都正常".into())
}

/// 归因窗口的起点：一般是断联时间，锁住拦下的是锁住时间。settle 按它取探测和事件。
pub fn window_start(d: &Disconnect) -> i64 {
    d.lock.map_or(d.ts, |l| l.since.min(d.ts))
}

/// 锁住拦下的断联补在归因依据后面的一句：锁了多久、拦下几次，锁住期间本地网络和整条链路的探测结果。
/// now：还锁着时算到这一刻。
pub fn lock_summary(d: &Disconnect, probes: &[Probe], now: i64) -> Option<String> {
    let l = d.lock?;
    let until = l.until.unwrap_or(now);
    let mut s = match l.until {
        Some(u) => format!("锁住 {}，拦下 {} 次 AI 连接", crate::util::zh_duration(((u - l.since).max(0) / 1000) as u64), d.count),
        None => format!("拦下 {} 次 AI 连接（记录时仍锁着）", d.count),
    };
    let seg = |name: &str| {
        let v: Vec<&Probe> = probes.iter().filter(|p| p.segment == name && p.ts >= l.since && p.ts <= until).collect();
        (v.iter().filter(|p| !p.ok).count(), v.len())
    };
    let parts: Vec<String> = [("lan", "路由器"), ("wan", "绕开 VPN 上网"), ("local", "本机上网"), ("chain", "整条链路")]
        .iter()
        .filter_map(|(name, label)| match seg(name) {
            (_, 0) => None,
            (bad, n) => Some(format!("{label}探测 {n} 次失败 {bad} 次")),
        })
        .collect();
    if !parts.is_empty() {
        s.push_str(&format!("；锁住期间{}", parts.join("、")));
    }
    Some(s)
}

/// 锁住事件和日志里的模式切换相差不超过这么久，就是同一次（日志时间只到秒）
const LOCK_SLACK_MS: i64 = 5_000;

/// 锁住期间拦下的连接按锁住的原因归因：出口 IP 变化、无法核对、锁住事件记的原因、刚启动。
fn locked_verdict(d: &Disconnect, events: &[Event]) -> Verdict {
    let since = d.lock.map_or(d.ts, |l| l.since);
    let during = |e: &&Event| e.ts >= since - LOCK_SLACK_MS && e.ts <= d.ts + WINDOW_AFTER_MS;
    let at_lock = |e: &&Event| (e.ts - since).abs() <= LOCK_SLACK_MS;
    let v = |cause, why: &str| Verdict { cause, why: why.to_string() };
    if events.iter().filter(during).any(|e| e.kind == "exit_ip_changed") {
        return v(Cause::Exit, "出口 IP 变了，AI 通道锁住");
    }
    if events.iter().filter(during).any(|e| e.kind == "exit_unverifiable") {
        return v(Cause::Exit, "IP 回显服务都连不上，无法核对出口，AI 通道锁住");
    }
    let reason = events.iter().filter(at_lock).filter(|e| e.kind == "exit_locked").last().map(|e| e.detail["reason"].as_str().unwrap_or(""));
    match reason {
        Some("exit_down") => return v(Cause::Exit, "出口不可达，AI 通道锁住"),
        Some("network_change") => return v(Cause::Local, "网络变化后核对出口，AI 通道锁住"),
        Some("kernel_start") => return v(Cause::Kernel, "内核重新启动后核对出口，AI 通道锁住"),
        Some("recheck") => return v(Cause::Exit, "手动核对出口，AI 通道暂时锁住"),
        Some("no_baseline") => return v(Cause::Exit, "没有出口基线，AI 通道锁住（运行 anchor baseline）"),
        _ => {}
    }
    if events.iter().filter(at_lock).any(|e| e.kind == "kernel_start" || e.kind == "agent_start") {
        return v(Cause::Kernel, "AI Anchor 刚启动，核对出口之前 AI 通道锁住");
    }
    v(Cause::Unknown, "AI 通道锁住，时间线里找不到锁住的原因")
}

/// 断联那一刻，AI 通道是否因“出口不可达”锁着：锁住发生在断联后几秒内也算（断联往往先于核对发现），
/// 断联前已经放行的不算。
fn exit_down_at(ts: i64, events: &[Event]) -> bool {
    const SLACK_MS: i64 = 5_000;
    let Some(lock) = events
        .iter()
        .filter(|e| e.kind == "exit_locked" && e.detail["reason"] == "exit_down")
        .filter(|e| e.ts <= ts + SLACK_MS && e.ts >= ts - WINDOW_BEFORE_MS)
        .last()
    else {
        return false;
    };
    // 这次锁住之后的第一次放行
    match events.iter().find(|e| e.kind == "exit_unlocked" && e.ts >= lock.ts) {
        Some(unlock) => unlock.ts >= ts - SLACK_MS,
        None => true,
    }
}

/// AI 域名所属服务商的状态页（突发探测用）。
pub fn status_page(domain: &str) -> Option<(&'static str, &'static str)> {
    let d = domain.to_ascii_lowercase();
    let under = |s: &str| d == s || d.ends_with(&format!(".{s}"));
    if ["anthropic.com", "claude.ai", "claude.com", "claudeusercontent.com"].iter().any(|s| under(s)) {
        Some(("Anthropic", "https://status.anthropic.com/api/v2/status.json"))
    } else if ["openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com", "sora.com"].iter().any(|s| under(s)) {
        Some(("OpenAI", "https://status.openai.com/api/v2/status.json"))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const T0: &str = "-0800 2026-11-14 10:07:11";

    fn line(level: &str, conn: u64, msg: &str) -> String {
        format!("{T0} {level} [{conn} 0ms] {msg}")
    }

    #[test]
    fn parses_real_log_lines() {
        let raw = line("ERROR", 2781160631, "connection: open connection to ifconfig.me:443 using outbound/direct[exit]: dial tcp 34.160.111.145:443: connectex: A socket operation was attempted to an unreachable network.");
        let l = parse_line(&raw).unwrap();
        assert_eq!(l.level, "ERROR");
        assert_eq!(l.conn, Some(2781160631));
        assert!(l.msg.starts_with("connection: open connection"));
        assert_eq!(l.ts, chrono::DateTime::parse_from_rfc3339("2026-11-14T18:07:11Z").unwrap().timestamp_millis());
        let s = parse_line("-0800 2026-11-14 10:07:11 INFO inbound/mixed[probe-in]: tcp server started at 127.0.0.1:17892").unwrap();
        assert_eq!(s.conn, None);
        assert!(parse_line("garbage").is_none());
        assert!(parse_line("").is_none());
    }

    #[test]
    fn classifies_the_errors_seen_in_real_logs() {
        let c = |s: &str| classify(s);
        assert_eq!(c("lookup claude.ai: (exchange4: claude.ai.: context deadline exceeded | exchange6: …)"), ErrClass::Dns);
        assert_eq!(c("dial tcp 1.2.3.4:443: connectex: A socket operation was attempted to an unreachable network."), ErrClass::Unreachable);
        assert_eq!(c("dial tcp 1.2.3.4:443: i/o timeout"), ErrClass::Timeout);
        assert_eq!(c("socks5: request rejected, code=1"), ErrClass::Rejected);
        assert_eq!(c("dial tcp 127.0.0.1:28090: connectex: No connection could be made because the target machine actively refused it."), ErrClass::Refused);
        assert_eq!(c("read tcp: wsarecv: An existing connection was forcibly closed by the remote host."), ErrClass::Reset);
        assert_eq!(c("tls: handshake failure"), ErrClass::Tls);
        assert_eq!(c("something new"), ErrClass::Other);
    }

    fn feed(t: &mut Tracker, s: &str) -> Option<Feed> {
        t.feed(&parse_line(s).unwrap())
    }

    #[test]
    fn tracks_ai_connections_and_merges_bursts() {
        let mut t = Tracker::default();
        assert_eq!(feed(&mut t, &line("INFO", 1, "inbound/mixed[ai-in]: inbound connection to claude.ai:443")), None);
        let Some(Feed::New(d)) = feed(&mut t, &line("ERROR", 1, "connection: open connection to claude.ai:443 using outbound/direct[exit]: lookup claude.ai: exchange4: claude.ai.: context deadline exceeded")) else {
            panic!("应记一次断联")
        };
        assert_eq!((d.domain.as_str(), d.phase, d.class, d.outbound.as_str()), ("claude.ai", "open", ErrClass::Dns, "direct[exit]"));
        assert!(d.raw.starts_with("lookup claude.ai"));

        // 同一域名 5 秒内再出错：合并
        feed(&mut t, &line("INFO", 2, "inbound/mixed[ai-in]: inbound connection to claude.ai:443"));
        assert_eq!(
            feed(&mut t, &line("ERROR", 2, "connection: open connection to claude.ai:443 using outbound/direct[exit]: dial tcp 1.2.3.4:443: i/o timeout")),
            Some(Feed::Merged { domain: "claude.ai".into(), first_ts: d.ts, locked: false })
        );
        // 5 秒以后：新的一次
        let later = "-0800 2026-11-14 10:07:17";
        feed(&mut t, &format!("{later} INFO [3 0ms] inbound/mixed[ai-in]: inbound connection to claude.ai:443"));
        assert!(matches!(
            feed(&mut t, &format!("{later} ERROR [3 0ms] connection: open connection to claude.ai:443 using outbound/direct[exit]: dial tcp 1.2.3.4:443: i/o timeout")),
            Some(Feed::New(_))
        ));
    }

    #[test]
    fn ignores_probe_inbound_non_ai_domains_and_unknown_connections() {
        let mut t = Tracker::default();
        feed(&mut t, &line("INFO", 1, "inbound/mixed[probe-in]: [anchor] inbound connection to api.ipify.org:443"));
        assert_eq!(feed(&mut t, &line("ERROR", 1, "connection: open connection to api.ipify.org:443 using outbound/direct[exit]: i/o timeout")), None);
        feed(&mut t, &line("INFO", 2, "inbound/mixed[ai-in]: inbound connection to data.chc.ucsb.edu:443"));
        assert_eq!(feed(&mut t, &line("ERROR", 2, "connection: open connection to data.chc.ucsb.edu:443 using outbound/direct[exit]: i/o timeout")), None, "AI 程序访问的普通网站");
        assert_eq!(feed(&mut t, &line("ERROR", 9, "connection: open connection to claude.ai:443 using outbound/direct[exit]: x")), None, "不知道入站的连接");
        // 建立后出错
        feed(&mut t, &line("INFO", 4, "inbound/mixed[ai-in]: inbound connection to [2606:4700::1]:443"));
        feed(&mut t, &line("INFO", 5, "inbound/mixed[ai-in]: inbound connection to api.anthropic.com:443"));
        let Some(Feed::New(d)) = feed(&mut t, &line("ERROR", 5, "connection: download closed: wsarecv: An existing connection was forcibly closed by the remote host.")) else {
            panic!()
        };
        assert_eq!((d.phase, d.class), ("relay", ErrClass::Reset));
    }

    fn dc(class: ErrClass) -> Disconnect {
        Disconnect { ts: 100_000, domain: "claude.ai".into(), phase: "open", class, outbound: "direct[exit]".into(), raw: String::new(), count: 1, lock: None }
    }

    fn probe(ts: i64, seg: &str, target: &str, ok: bool) -> Probe {
        Probe { ts, segment: seg.into(), target: target.into(), ok, ms: None, note: String::new() }
    }

    fn ev(ts: i64, kind: &str, detail: serde_json::Value) -> Event {
        Event { ts, kind: kind.into(), detail }
    }

    #[test]
    fn attribution_follows_the_designed_order() {
        let d = dc(ErrClass::Timeout);
        let ok = vec![probe(95_000, "local", "direct", true), probe(101_000, "chain", "exit", true)];
        assert_eq!(attribute(&d, &ok, &[], false).cause, Cause::Unknown);

        // 内核优先于一切
        let k = vec![ev(103_000, "kernel_restart", json!({}))];
        let bad_local = vec![probe(99_000, "local", "direct", false)];
        assert_eq!(attribute(&d, &bad_local, &k, false).cause, Cause::Kernel);
        // 本地：探测失败、网络变化、网络不可达
        assert_eq!(attribute(&d, &bad_local, &[], false).cause, Cause::Local);
        assert_eq!(attribute(&d, &ok, &[ev(80_000, "net_change", json!({}))], false).cause, Cause::Local);
        assert_eq!(attribute(&dc(ErrClass::Unreachable), &ok, &[], false).cause, Cause::Local);
        // 窗口外的不算
        assert_eq!(attribute(&d, &[probe(60_000, "local", "direct", false)], &[], false).cause, Cause::Unknown);
        // 线路只在配置了线路时看
        let bad_line = vec![probe(99_000, "line", "line-a", false)];
        assert_eq!(attribute(&d, &bad_line, &[], true).cause, Cause::Line);
        assert_eq!(attribute(&d, &bad_line, &[], false).cause, Cause::Unknown);
        // 出口
        assert_eq!(attribute(&d, &[probe(101_000, "chain", "exit", false)], &[], false).cause, Cause::Exit);
        assert_eq!(attribute(&d, &ok, &[ev(99_000, "exit_locked", json!({ "reason": "exit_down" }))], false).cause, Cause::Exit);
        assert_eq!(attribute(&d, &ok, &[ev(103_000, "exit_locked", json!({ "reason": "exit_down" }))], false).cause, Cause::Exit, "断联先于核对发现");
        assert_eq!(attribute(&d, &ok, &[ev(99_000, "exit_locked", json!({ "reason": "recheck" }))], false).cause, Cause::Unknown);
        // 实测：前一次出口故障 20 秒前已经恢复，不能算到这一次头上
        let earlier = vec![
            ev(78_000, "exit_locked", json!({ "reason": "exit_down" })),
            ev(84_000, "exit_unlocked", json!({ "reason": "verified" })),
        ];
        assert_eq!(attribute(&d, &ok, &earlier, false).cause, Cause::Unknown);
        // 探测失败只看断联前 10 秒起：25 秒前的链路失败不算
        assert_eq!(attribute(&d, &[probe(75_000, "chain", "exit", false)], &[], false).cause, Cause::Unknown);
        // 服务端：其余正常，经出口访问该域名失败，或状态页报故障
        let mut svc = ok.clone();
        svc.push(probe(102_000, "ai", "claude.ai", false));
        assert_eq!(attribute(&d, &svc, &[], false).cause, Cause::Service);
        assert_eq!(attribute(&dc(ErrClass::Rejected), &svc, &[], false).cause, Cause::Service, "域名本身访问不了：不怪出口");
        // 探测都正常时，出口一侧报的错归出口
        assert_eq!(attribute(&dc(ErrClass::Rejected), &ok, &[], false).cause, Cause::Exit);
        assert_eq!(attribute(&dc(ErrClass::Dns), &ok, &[], false).cause, Cause::Exit);
        let mut status = ok.clone();
        status.push(Probe { note: "Major Outage".into(), ..probe(102_000, "status", "Anthropic", false) });
        let v = attribute(&d, &status, &[], false);
        assert_eq!(v.cause, Cause::Service);
        assert!(v.why.contains("Major Outage"));
    }

    #[test]
    fn local_failures_are_split_into_wifi_broadband_and_vpn() {
        let d = dc(ErrClass::Timeout);
        let cause = |probes: &[Probe], events: &[Event]| attribute(&d, probes, events, false);
        let lan = |ok| probe(98_000, "lan", "wifi", ok);
        let wan = |ok| probe(98_500, "wan", "wifi", ok);
        let local = |via: &str, ok| probe(99_000, "local", via, ok);

        // 连不上路由器：Wi-Fi
        let v = cause(&[lan(false), local("vpn", false)], &[]);
        assert_eq!(v.cause, Cause::Local);
        assert!(v.why.contains("路由器"));
        // 换了网络
        assert_eq!(cause(&[lan(true)], &[ev(95_000, "uplink_change", json!({ "from": "wifi", "to": "wifi" }))]).cause, Cause::Local);
        // 路由器通、绕开 VPN 也不通：宽带
        let v = cause(&[lan(true), wan(false), local("vpn", false)], &[]);
        assert_eq!(v.cause, Cause::Local);
        assert!(v.why.contains("宽带"));
        // 路由器通、绕开 VPN 能上网，经 VPN 不通：VPN
        assert_eq!(cause(&[lan(true), wan(true), local("vpn", false)], &[]).cause, Cause::Vpn);
        // 没有 VPN（本机上网不经 VPN）或没有绕开 VPN 的数据：分不清，归本地
        assert_eq!(cause(&[lan(true), wan(true), local("direct", false)], &[]).cause, Cause::Local);
        assert_eq!(cause(&[lan(true), local("vpn", false)], &[]).cause, Cause::Local);
        // 网络变化、网络不可达：Wi-Fi 和宽带都正常时归 VPN
        let fine = [lan(true), wan(true), local("vpn", true)];
        assert_eq!(cause(&fine, &[ev(90_000, "net_change", json!({}))]).cause, Cause::Vpn);
        assert_eq!(cause(&fine[..1], &[ev(90_000, "net_change", json!({}))]).cause, Cause::Local);
        assert_eq!(attribute(&dc(ErrClass::Unreachable), &fine, &[], false).cause, Cause::Vpn);
        // 锁住拦下的同样适用
        assert_eq!(attribute(&locked_dc(90_000, 100_000), &[lan(true), wan(true), local("vpn", false)], &[], false).cause, Cause::Vpn);
    }

    fn at(sec: &str, rest: &str) -> String {
        format!("-0800 2026-11-15 18:{sec} {rest}")
    }

    #[test]
    fn connections_during_a_lock_become_one_disconnect() {
        let mut t = Tracker::default();
        // 内核启动时锁住；用户代理核对后放行
        assert_eq!(feed(&mut t, &at("19:00", "INFO sing-box started (0.12s)")), None);
        assert!(matches!(feed(&mut t, &at("19:01", "INFO [1 0ms] inbound/mixed[ai-in]: inbound connection to claude.ai:443")), Some(Feed::New(_))), "启动核对期间拦下");
        assert!(matches!(feed(&mut t, &at("19:02", "INFO clash-mode: updated mode: Open")), Some(Feed::LockEnded { .. })));
        assert_eq!(feed(&mut t, &at("19:03", "INFO [2 0ms] inbound/mixed[ai-in]: inbound connection to claude.ai:443")), None, "放行后正常");

        // 实测（18:19 断网）：锁住后 AI 程序反复重连，内核只记入站，不记错误
        assert_eq!(feed(&mut t, &at("19:54", "INFO clash-mode: updated mode: Lock")), None);
        let lock_ts = parse_line(&at("19:54", "INFO x")).unwrap().ts;
        let Some(Feed::New(d)) = feed(&mut t, &at("20:01", "INFO [3 0ms] inbound/mixed[ai-in]: inbound connection to claude.ai:443")) else {
            panic!("锁住期间第一条 AI 连接：新的一次断联")
        };
        assert_eq!((d.class, d.phase, d.domain.as_str()), (ErrClass::Locked, "locked", "claude.ai"));
        assert_eq!(d.lock, Some(LockSpan { since: lock_ts, until: None }));
        let merged = Some(Feed::Merged { domain: "claude.ai".into(), first_ts: d.ts, locked: true });
        assert_eq!(feed(&mut t, &at("20:02", "INFO [4 0ms] inbound/mixed[ai-in]: inbound connection to bridge.claudeusercontent.com:443")), merged, "别的 AI 域名也并进同一次");
        assert_eq!(feed(&mut t, &at("21:30", "INFO [5 0ms] inbound/mixed[ai-in]: inbound connection to claude.ai:443")), merged, "几分钟后仍是同一次锁住");
        assert_eq!(feed(&mut t, &at("20:03", "INFO [6 0ms] inbound/mixed[ai-in]: inbound connection to data.chc.ucsb.edu:443")), None, "普通网站不算");
        assert_eq!(feed(&mut t, &at("20:03", "INFO [7 0ms] inbound/mixed[probe-in]: [anchor] inbound connection to api.ipify.org:443")), None, "探测入站不算");
        assert_eq!(feed(&mut t, &at("20:04", "ERROR [3 3.0s] connection: open connection to claude.ai:443 using outbound/direct[exit]: x")), None, "拦下的连接再报错不重复算");
        // 锁着时内核重启：还是同一次
        assert_eq!(feed(&mut t, &at("22:00", "INFO sing-box started (0.12s)")), None);
        assert_eq!(feed(&mut t, &at("22:01", "INFO [8 0ms] inbound/mixed[ai-in]: inbound connection to claude.ai:443")), merged);
        assert_eq!(
            feed(&mut t, &at("23:37", "INFO clash-mode: updated mode: Open")),
            Some(Feed::LockEnded { domain: "claude.ai".into(), first_ts: d.ts, at: parse_line(&at("23:37", "INFO x")).unwrap().ts })
        );
        // 下一次锁住是新的一次
        feed(&mut t, &at("30:00", "INFO clash-mode: updated mode: Lock"));
        assert!(matches!(feed(&mut t, &at("30:01", "INFO [9 0ms] inbound/mixed[ai-in]: inbound connection to claude.ai:443")), Some(Feed::New(_))));
    }

    fn locked_dc(since: i64, ts: i64) -> Disconnect {
        Disconnect { lock: Some(LockSpan { since, until: None }), phase: "locked", ts, ..dc(ErrClass::Locked) }
    }

    #[test]
    fn locked_disconnects_are_attributed_by_why_the_channel_locked() {
        let ok = vec![probe(95_000, "local", "direct", true), probe(101_000, "chain", "exit", true)];
        let locked = |reason: &str| ev(90_000, "exit_locked", json!({ "reason": reason }));
        let d = locked_dc(90_000, 100_000);
        assert_eq!(attribute(&d, &ok, &[locked("exit_down")], false).cause, Cause::Exit);
        assert_eq!(attribute(&d, &ok, &[locked("recheck")], false).cause, Cause::Exit);
        assert_eq!(attribute(&d, &ok, &[locked("kernel_start")], false).cause, Cause::Kernel);
        assert_eq!(attribute(&d, &ok, &[ev(88_000, "agent_start", json!({})), ev(89_500, "kernel_start", json!({}))], false).cause, Cause::Kernel);
        assert_eq!(attribute(&d, &ok, &[ev(95_000, "exit_ip_changed", json!({}))], false).cause, Cause::Exit);
        assert_eq!(attribute(&d, &ok, &[locked("network_change"), ev(90_000, "net_change", json!({}))], false).cause, Cause::Local);
        assert_eq!(attribute(&d, &ok, &[], false).cause, Cause::Unknown);
        // 实测（18:19）：出口核对发现不可达而锁住，但本地网络探测也失败：本地优先
        let bad_local = vec![probe(97_000, "local", "direct", false)];
        assert_eq!(attribute(&d, &bad_local, &[locked("exit_down")], false).cause, Cause::Local);
        // 第一条被拦下的连接在锁住 3 分钟后：仍按锁住那一刻找原因和探测
        let late = locked_dc(90_000, 270_000);
        assert_eq!(window_start(&late), 90_000);
        assert_eq!(attribute(&late, &[], &[locked("exit_down")], false).cause, Cause::Exit);
        assert_eq!(attribute(&late, &bad_local, &[locked("exit_down")], false).cause, Cause::Local);
    }

    #[test]
    fn lock_summary_counts_probes_during_the_lock() {
        let mut d = locked_dc(90_000, 100_000);
        d.count = 55;
        let probes = vec![
            probe(80_000, "local", "direct", false), // 锁住之前，不算
            probe(95_000, "local", "direct", false),
            probe(105_000, "local", "direct", true),
            probe(110_000, "chain", "exit", false),
        ];
        assert_eq!(lock_summary(&d, &probes, 120_000).unwrap(), "拦下 55 次 AI 连接（记录时仍锁着）；锁住期间本机上网探测 2 次失败 1 次、整条链路探测 1 次失败 1 次");
        d.lock = Some(LockSpan { since: 90_000, until: Some(313_000) });
        assert!(lock_summary(&d, &[], 0).unwrap().starts_with("锁住 3 分 43 秒，拦下 55 次 AI 连接"));
        assert_eq!(lock_summary(&dc(ErrClass::Timeout), &probes, 0), None);
    }

    #[test]
    fn status_pages_by_vendor() {
        assert_eq!(status_page("bridge.claudeusercontent.com").unwrap().0, "Anthropic");
        assert_eq!(status_page("chatgpt.com").unwrap().0, "OpenAI");
        assert!(status_page("cursor.com").is_none());
    }
}
