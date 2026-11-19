//! AI 通道因为出口连不上而锁住、迟迟不恢复时：判断卡在哪一段，决定什么时候提醒（P1c）。
//!
//! 只有逻辑，不做探测：用户代理把本机网络各段探测的最新结果（`LocalHealth`）交进来。
//!
//! - `diagnose`：由近到远看是哪一段不通，顺序和断联归因一致（路由器 → 宽带 → VPN → 出口）。
//! - `StallWatch`：VPN 短暂重连几秒就好，不打扰；锁住超过设定的时间（默认 30 秒）才提醒。
//!   同一类问题在一次锁住里只提醒一次；问题换了一类（Wi-Fi 回来了、VPN 却没连回来）再提醒一次；
//!   提醒过的锁住，恢复时再通知一次。
//!
//! 起因是一次真机测试：Wi-Fi 断了 12 秒，恢复后 VPN 卡在“显示连着、实际不通”79 秒，要手动重连才好。
//! 用户代理在锁住后 25 秒就测出“Wi-Fi 和宽带正常，只有经 VPN 不通”，但当时没有任何通知。

use crate::util::zh_duration;
use std::time::{Duration, Instant};

/// 一段探测最近一次的结果。at 是这次探测**开始**的时间：开始得比锁住还早的探测，说明不了现在的情况。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reading {
    pub ok: bool,
    pub at: Instant,
}

/// 本机网络各段的最新情况。None 表示没测过，或者测不了（这个网关从没回过 ping、绕开 VPN 从没连上过）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LocalHealth {
    /// 有没有上行网卡（Wi-Fi 或网线上的默认网关）
    pub uplink: Option<Reading>,
    /// 路由器 ping 得通吗
    pub lan: Option<Reading>,
    /// 绕开 VPN 能上网吗
    pub wan: Option<Reading>,
    /// 走系统路由能上网吗（开着全量 VPN 时经 VPN）
    pub local: Option<Reading>,
    /// 此刻默认流量是不是经 VPN
    pub via_vpn: bool,
    /// 这次运行里见过默认流量经 VPN
    pub vpn_seen: bool,
    /// 出口绑定了网卡（[exit] bind_interface），那块网卡此刻没有连接
    pub exit_if_down: bool,
}

/// 出口连不上时，卡在哪一段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stuck {
    /// Wi-Fi 或网线没有连上，或者连不上路由器
    Link,
    /// 路由器连得上，外网不通
    Broadband,
    /// Wi-Fi 和宽带正常，VPN 连着但不通
    VpnStuck,
    /// Wi-Fi 和宽带正常，VPN 没有连接
    VpnOff,
    /// 本机上不了网，分不出是 VPN 还是宽带（绕开 VPN 那一段测不了）
    Local,
    /// 本机上网正常，只有出口连不上
    Exit,
}

impl Stuck {
    /// 写进时间线和状态里的名字
    pub fn name(self) -> &'static str {
        match self {
            Stuck::Link => "link",
            Stuck::Broadband => "broadband",
            Stuck::VpnStuck => "vpn_stuck",
            Stuck::VpnOff => "vpn_off",
            Stuck::Local => "local",
            Stuck::Exit => "exit",
        }
    }

    /// 一句话说明（时间线、托盘提示、anchor agent status 共用）
    pub fn label(name: &str) -> &'static str {
        match name {
            "link" => "Wi-Fi 或网线没有连上",
            "broadband" => "宽带不通",
            "vpn_stuck" => "VPN 卡住了",
            "vpn_off" => "VPN 没有连接",
            "local" => "本机上不了网",
            "exit" => "本机上网正常，出口连不上",
            _ => "原因不明",
        }
    }

    /// 要用户做的事相同的算一类：同一类不重复提醒。
    fn group(self) -> u8 {
        match self {
            Stuck::Link => 0,
            Stuck::Broadband => 1,
            Stuck::VpnStuck | Stuck::VpnOff => 2,
            Stuck::Local => 3,
            Stuck::Exit => 4,
        }
    }
}

/// 出口连不上时，问题在哪一段。结果不够新、下不了结论时返回 None（等下一轮探测）。
///
/// - fresh_after：只认这个时刻之后开始的探测（一般是锁住的时刻）；None 表示手头有什么用什么。
/// - exit_on_route：出口从本机按系统路由直接出去（direct 出口、没有线路）。这时“出口连不上”本身
///   就说明这条路不通，不用等“本机上网”那一项：VPN 卡住时它要解析域名，常常十几秒才有结果。
pub fn diagnose(h: &LocalHealth, fresh_after: Option<Instant>, exit_on_route: bool) -> Option<Stuck> {
    let fresh = |r: Option<Reading>| r.filter(|r| fresh_after.is_none_or(|t| r.at >= t));
    let (uplink, lan, wan, local) = (fresh(h.uplink), fresh(h.lan), fresh(h.wan), fresh(h.local));
    if uplink.is_some_and(|r| !r.ok) || lan.is_some_and(|r| !r.ok) {
        return Some(Stuck::Link);
    }
    if wan.is_some_and(|r| !r.ok) {
        return Some(Stuck::Broadband);
    }
    // 近处两段没有测出问题。绕开 VPN 能上网，才能把问题定在 VPN 上
    let lower_ok = wan.is_some_and(|r| r.ok);
    let link_ok = uplink.is_some_and(|r| r.ok);
    if h.exit_if_down && (lower_ok || (h.wan.is_none() && link_ok)) {
        return Some(Stuck::VpnOff);
    }
    if lower_ok {
        if h.vpn_seen && !h.via_vpn {
            return Some(Stuck::VpnOff);
        }
        if h.via_vpn && exit_on_route {
            return Some(Stuck::VpnStuck);
        }
    }
    // 其余要看“本机上网”那一项。绕开 VPN 那一段测得了、只是还没有新结果：再等一轮
    if !lower_ok && h.wan.is_some() {
        return None;
    }
    match local {
        Some(r) if r.ok => Some(Stuck::Exit),
        Some(_) if lower_ok && h.via_vpn => Some(Stuck::VpnStuck),
        Some(_) => Some(Stuck::Local),
        None => None,
    }
}

/// 写提醒时要用到的配置。
#[derive(Debug, Clone, Copy, Default)]
pub struct NoticeCtx<'a> {
    /// 出口绑定的网卡名（[exit] bind_interface）
    pub bind_if: Option<&'a str>,
    /// 配了备用出口
    pub has_backup: bool,
}

/// 提醒的标题和正文：哪一段不通、已经锁了多久、该怎么做。
pub fn notice(s: Stuck, locked: Duration, ctx: &NoticeCtx) -> (String, String) {
    let dur = zh_duration(whole_secs(locked));
    let title = format!("{}，AI 通道已锁住", Stuck::label(s.name()));
    let body = match s {
        Stuck::Link => format!("连不上路由器，已经 {dur}。连上网络后会自动核对出口并放行，AI Anchor 这边不需要操作。"),
        Stuck::Broadband => format!("路由器连得上，但外网不通，已经 {dur}。检查宽带或路由器的上游；恢复后自动放行。"),
        Stuck::VpnStuck => {
            format!("Wi-Fi 和宽带正常，但经 VPN 上不了网，已经 {dur}。在 VPN 客户端里断开再重新连接；恢复后自动核对出口并放行。")
        }
        Stuck::VpnOff => {
            let which = match ctx.bind_if {
                Some(name) => format!("出口走的网卡“{name}”没有连接"),
                None => "现在没有经 VPN 上网".to_string(),
            };
            // 真机上 Wi-Fi 断开再回来后，VPN 客户端有时过一分钟自己连回来，有时一直不回来；
            // 提醒发出时分不出是哪一种，所以先说可能在自动重连，再说等不到就手动连。
            format!("Wi-Fi 和宽带正常，但{which}，出口连不上，已经 {dur}。VPN 客户端可能正在自动重连；一两分钟后还没恢复，就在客户端里手动重新连接。恢复后自动核对出口并放行。")
        }
        Stuck::Local => format!("已经 {dur}。可能是 VPN 卡住了，也可能是宽带不通：先在 VPN 客户端里断开再重新连接，不行再检查宽带。"),
        Stuck::Exit => {
            let backup = if ctx.has_backup { "配了备用出口，可以用 anchor exit use 切换。" } else { "" };
            format!("出口已经 {dur}连不上。运行 anchor check 查看是哪一段；恢复后自动放行。{backup}")
        }
    };
    (title, body)
}

/// 恢复时的通知。
pub fn recovered_notice(baseline: &str, locked: Duration) -> (String, String) {
    ("AI 通道已恢复".into(), format!("出口 IP {baseline}，与基线一致。这次锁住了 {}。", zh_duration(whole_secs(locked))))
}

/// 四舍五入到整秒（19.9 秒说成 20 秒）。
fn whole_secs(d: Duration) -> u64 {
    (d.as_millis() as u64 + 500) / 1000
}

/// AI 通道此刻的状态（从出口锁定状态机的显示信息得来）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lock {
    /// 放行
    Open,
    /// 锁着，正在核对，最近一次核对时出口连不上
    ExitDown,
    /// 锁着，正在核对，出口这一刻是通的（在等回显服务），或者线路控制器已经在提醒
    Verifying,
    /// 锁着，原因有自己的通知：出口 IP 变了、无法核对、没有基线
    Other,
}

impl Lock {
    pub fn of(locked: bool, state: &str, exit_down: bool) -> Self {
        match (locked, state) {
            (false, _) => Lock::Open,
            (true, "verifying") if exit_down => Lock::ExitDown,
            (true, "verifying") => Lock::Verifying,
            (true, _) => Lock::Other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StallNote {
    /// 卡在这一段，已经锁了这么久
    Stuck(Stuck, Duration),
    /// 提醒过的那次锁住结束了，一共锁了这么久
    Recovered(Duration),
}

/// 判断要保持这么久不变才提醒：网络还在变化时（Wi-Fi 刚回来、VPN 正在重连）先不说。
pub const HOLD: Duration = Duration::from_secs(10);
/// 到了提醒时间、探测结果却还不够新时，最多再等这么久，之后用手头的结果。
pub const GRACE: Duration = Duration::from_secs(30);

pub struct StallWatch {
    after: Option<Duration>,
    /// 现在的判断，和它从什么时候开始没变过
    cur: Option<(Stuck, Instant)>,
    /// 这次锁住里最近一次提醒的是什么
    notified: Option<Stuck>,
    last_locked: Duration,
}

impl StallWatch {
    /// after：锁住多久之后提醒；None 表示不提醒。
    pub fn new(after: Option<Duration>) -> Self {
        Self { after, cur: None, notified: None, last_locked: Duration::ZERO }
    }

    /// 这次锁住里提醒过的原因（给状态显示用）。
    pub fn notified(&self) -> Option<Stuck> {
        self.notified
    }

    /// 快到提醒时间了，该去看各段的情况了。平时不必每个循环都读路由表。
    pub fn wants_diagnosis(&self, lock: Lock, locked_for: Duration) -> bool {
        self.after.is_some_and(|a| lock == Lock::ExitDown && locked_for + HOLD + Duration::from_secs(5) >= a)
    }

    /// 每个循环调用一次。diag：按够新的探测结果得出的判断；fallback：手头有什么用什么得出的判断。
    pub fn tick(&mut self, now: Instant, lock: Lock, locked_for: Duration, diag: Option<Stuck>, fallback: Stuck) -> Option<StallNote> {
        let after = self.after?;
        match lock {
            Lock::Open => {
                self.cur = None;
                let locked = std::mem::take(&mut self.last_locked);
                return self.notified.take().map(|_| StallNote::Recovered(locked));
            }
            // 状态机接手了通知（出口 IP 已变化、无法核对），恢复时也由它通知
            Lock::Other => {
                self.cur = None;
                self.notified = None;
                self.last_locked = locked_for;
                return None;
            }
            Lock::Verifying => {
                self.last_locked = locked_for;
                return None;
            }
            Lock::ExitDown => {}
        }
        self.last_locked = locked_for;
        let d = match diag {
            Some(d) => d,
            None if locked_for >= after + GRACE => fallback,
            // 结果还不够新：这一轮不判断，已有的判断和计时保持不动
            None => return None,
        };
        let since = match self.cur {
            Some((c, t)) if c == d => t,
            _ => {
                self.cur = Some((d, now));
                now
            }
        };
        let held = now.saturating_duration_since(since);
        if locked_for >= after && held >= HOLD && self.notified.map(Stuck::group) != Some(d.group()) {
            self.notified = Some(d);
            return Some(StallNote::Stuck(d, locked_for));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: Duration = Duration::from_secs(1);

    fn at(t0: Instant, secs: u64, ok: bool) -> Option<Reading> {
        Some(Reading { ok, at: t0 + S * secs as u32 })
    }

    /// 全量 VPN 正常工作时的样子：各段都通，默认流量经 VPN。
    fn healthy(t0: Instant, secs: u64) -> LocalHealth {
        LocalHealth {
            uplink: at(t0, secs, true),
            lan: at(t0, secs, true),
            wan: at(t0, secs, true),
            local: at(t0, secs, true),
            via_vpn: true,
            vpn_seen: true,
            exit_if_down: false,
        }
    }

    #[test]
    fn nearest_broken_segment_wins() {
        let t0 = Instant::now();
        let lock = Some(t0);
        // Wi-Fi 关了：找不到上行网卡
        let mut h = healthy(t0, 1);
        h.uplink = at(t0, 1, false);
        h.lan = None;
        h.wan = None;
        h.local = at(t0, 1, false);
        assert_eq!(diagnose(&h, lock, true), Some(Stuck::Link));
        // 路由器 ping 不通
        let mut h = healthy(t0, 1);
        h.lan = at(t0, 1, false);
        h.wan = at(t0, 1, false);
        assert_eq!(diagnose(&h, lock, true), Some(Stuck::Link));
        // 路由器通，绕开 VPN 也上不了网
        let mut h = healthy(t0, 1);
        h.wan = at(t0, 1, false);
        h.local = at(t0, 1, false);
        assert_eq!(diagnose(&h, lock, true), Some(Stuck::Broadband));
    }

    #[test]
    fn vpn_is_blamed_only_when_wifi_and_broadband_are_known_good() {
        let t0 = Instant::now();
        let lock = Some(t0);
        // direct 出口：Wi-Fi 和宽带正常、默认流量经 VPN、出口连不上，就是 VPN 卡住。不用等“本机上网”
        let mut h = healthy(t0, 2);
        h.local = Some(Reading { ok: true, at: t0 - S }); // 还是锁住之前开始的那次探测
        assert_eq!(diagnose(&h, lock, true), Some(Stuck::VpnStuck));
        // 代理型出口：要等“本机上网”有新结果
        assert_eq!(diagnose(&h, lock, false), None);
        h.local = at(t0, 9, false);
        assert_eq!(diagnose(&h, lock, false), Some(Stuck::VpnStuck));
        // 经 VPN 上网是好的：问题在出口
        h.local = at(t0, 9, true);
        assert_eq!(diagnose(&h, lock, false), Some(Stuck::Exit));

        // VPN 断开了：之前经 VPN，现在不经
        let mut h = healthy(t0, 2);
        h.via_vpn = false;
        assert_eq!(diagnose(&h, lock, true), Some(Stuck::VpnOff));
        // 开机后 VPN 还没连：没见过经 VPN，但出口绑定的网卡没有连接
        let mut h = healthy(t0, 2);
        h.via_vpn = false;
        h.vpn_seen = false;
        assert_eq!(diagnose(&h, lock, true), Some(Stuck::Exit), "本机上网正常，看不出和 VPN 有关");
        h.exit_if_down = true;
        assert_eq!(diagnose(&h, lock, true), Some(Stuck::VpnOff));
    }

    #[test]
    fn untestable_bypass_gives_a_general_answer() {
        let t0 = Instant::now();
        // 有的 VPN 不许绕开它：绕开 VPN 那一段从没连上过，分不出 VPN 和宽带
        let mut h = healthy(t0, 2);
        h.wan = None;
        h.local = at(t0, 2, false);
        assert_eq!(diagnose(&h, Some(t0), true), Some(Stuck::Local));
        h.local = at(t0, 2, true);
        assert_eq!(diagnose(&h, Some(t0), true), Some(Stuck::Exit));
        // 网卡没连接是眼前的事实，上行网卡在就能下结论
        h.exit_if_down = true;
        assert_eq!(diagnose(&h, Some(t0), true), Some(Stuck::VpnOff));
    }

    #[test]
    fn readings_from_before_the_lock_do_not_count() {
        let t0 = Instant::now();
        let lock = t0 + S * 60;
        // 全是锁住之前测的：什么都说明不了
        let h = healthy(t0, 50);
        assert_eq!(diagnose(&h, Some(lock), true), None);
        // 手头有什么用什么：各段都好，只能说是出口
        assert_eq!(diagnose(&h, None, false), Some(Stuck::Exit));
        // 锁住之后只有路由器和宽带有新结果：direct 出口已经可以下结论
        let mut h = healthy(t0, 50);
        h.uplink = at(t0, 65, true);
        h.wan = at(t0, 65, true);
        assert_eq!(diagnose(&h, Some(lock), true), Some(Stuck::VpnStuck));
        // 什么探测结果都没有
        assert_eq!(diagnose(&LocalHealth::default(), None, true), None);
    }

    fn secs(n: u64) -> Duration {
        S * n as u32
    }

    #[test]
    fn short_locks_stay_silent() {
        let t0 = Instant::now();
        let mut w = StallWatch::new(Some(secs(30)));
        // VPN 重连：锁住 8 秒就放行
        for s in 0..8 {
            assert_eq!(w.tick(t0 + secs(s), Lock::ExitDown, secs(s), Some(Stuck::VpnStuck), Stuck::Exit), None);
        }
        assert_eq!(w.tick(t0 + secs(8), Lock::Open, Duration::ZERO, None, Stuck::Exit), None, "没提醒过，恢复时也不通知");
    }

    #[test]
    fn notifies_once_after_the_threshold_and_again_on_recovery() {
        let t0 = Instant::now();
        let mut w = StallWatch::new(Some(secs(30)));
        let mut notes = Vec::new();
        for s in 0..120 {
            notes.extend(w.tick(t0 + secs(s), Lock::ExitDown, secs(s), Some(Stuck::VpnStuck), Stuck::Exit).map(|n| (s, n)));
        }
        assert_eq!(notes, [(30, StallNote::Stuck(Stuck::VpnStuck, secs(30)))], "锁住满 30 秒提醒一次，之后不重复");
        assert_eq!(w.notified(), Some(Stuck::VpnStuck));
        assert_eq!(w.tick(t0 + secs(120), Lock::Open, Duration::ZERO, None, Stuck::Exit), Some(StallNote::Recovered(secs(119))));
        assert_eq!(w.notified(), None);
        assert_eq!(w.tick(t0 + secs(121), Lock::Open, Duration::ZERO, None, Stuck::Exit), None);
    }

    /// 真机上那次的经过：Wi-Fi 断 12 秒，恢复后 VPN 的路由过了十来秒才回来，然后一直不通，
    /// 用户手动断开 VPN 再连上才好。
    #[test]
    fn wifi_blip_then_stuck_vpn_gets_one_vpn_notice() {
        let t0 = Instant::now();
        let mut w = StallWatch::new(Some(secs(30)));
        let diag = |s: u64| match s {
            0..=3 => None,                    // 还没有新的探测结果
            4..=12 => Some(Stuck::Link),      // Wi-Fi 关着
            13..=23 => Some(Stuck::VpnOff),   // Wi-Fi 回来了，VPN 的路由还没回来
            24..=91 => Some(Stuck::VpnStuck), // 路由回来了，不通
            _ => Some(Stuck::VpnOff),         // 用户手动断开 VPN
        };
        let mut notes = Vec::new();
        for s in 0..105 {
            notes.extend(w.tick(t0 + secs(s), Lock::ExitDown, secs(s), diag(s), Stuck::Exit).map(|n| (s, n)));
        }
        assert_eq!(notes, [(34, StallNote::Stuck(Stuck::VpnStuck, secs(34)))], "只提醒一次，说的是 VPN；断开重连属于同一类，不再提醒");
        assert_eq!(w.tick(t0 + secs(105), Lock::Open, Duration::ZERO, None, Stuck::Exit), Some(StallNote::Recovered(secs(104))));
    }

    #[test]
    fn a_different_kind_of_problem_is_announced_again() {
        let t0 = Instant::now();
        let mut w = StallWatch::new(Some(secs(30)));
        let mut notes = Vec::new();
        // Wi-Fi 关了一分钟，回来之后 VPN 卡住
        for s in 0..120 {
            let d = if s < 60 { Stuck::Link } else { Stuck::VpnStuck };
            notes.extend(w.tick(t0 + secs(s), Lock::ExitDown, secs(s), Some(d), Stuck::Exit).map(|n| (s, n)));
        }
        assert_eq!(notes, [(30, StallNote::Stuck(Stuck::Link, secs(30))), (70, StallNote::Stuck(Stuck::VpnStuck, secs(70)))]);
    }

    #[test]
    fn waits_for_fresh_readings_but_not_forever() {
        let t0 = Instant::now();
        let mut w = StallWatch::new(Some(secs(30)));
        let mut notes = Vec::new();
        for s in 0..90 {
            notes.extend(w.tick(t0 + secs(s), Lock::ExitDown, secs(s), None, Stuck::Local).map(|n| (s, n)));
        }
        // 60 秒起用手头的结果，再保持 10 秒不变
        assert_eq!(notes, [(70, StallNote::Stuck(Stuck::Local, secs(70)))]);

        // 中间偶尔拿不到新结果，不打断已经在计时的判断
        let mut w = StallWatch::new(Some(secs(30)));
        let mut notes = Vec::new();
        for s in 0..40 {
            let d = if s % 3 == 0 { None } else { Some(Stuck::Exit) };
            notes.extend(w.tick(t0 + secs(s), Lock::ExitDown, secs(s), d, Stuck::Exit).map(|n| (s, n)));
        }
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].0, 31, "30 秒那一轮正好没有新结果，下一轮提醒");
    }

    #[test]
    fn other_lock_reasons_have_their_own_notifications() {
        let t0 = Instant::now();
        let mut w = StallWatch::new(Some(secs(30)));
        for s in 0..40 {
            w.tick(t0 + secs(s), Lock::ExitDown, secs(s), Some(Stuck::VpnStuck), Stuck::Exit);
        }
        assert!(w.notified().is_some());
        // 出口一时是通的（在等回显服务）：不提醒，也不忘记提醒过
        assert_eq!(w.tick(t0 + secs(40), Lock::Verifying, secs(40), None, Stuck::Exit), None);
        assert!(w.notified().is_some());
        // VPN 连回来却到了另一台服务器：状态机会通知“出口 IP 已变化”，恢复时也由它通知
        assert_eq!(w.tick(t0 + secs(41), Lock::Other, secs(41), None, Stuck::Exit), None);
        assert_eq!(w.tick(t0 + secs(50), Lock::Open, Duration::ZERO, None, Stuck::Exit), None);

        // 关掉提醒
        let mut off = StallWatch::new(None);
        assert!(!off.wants_diagnosis(Lock::ExitDown, secs(600)));
        assert_eq!(off.tick(t0, Lock::ExitDown, secs(600), Some(Stuck::VpnStuck), Stuck::Exit), None);
    }

    #[test]
    fn diagnosis_starts_shortly_before_the_threshold() {
        let w = StallWatch::new(Some(secs(30)));
        assert!(!w.wants_diagnosis(Lock::ExitDown, secs(5)));
        assert!(w.wants_diagnosis(Lock::ExitDown, secs(15)), "提前 15 秒开始看，判断才来得及稳定 10 秒");
        assert!(!w.wants_diagnosis(Lock::Verifying, secs(60)));
        assert!(!w.wants_diagnosis(Lock::Open, secs(0)));
    }

    #[test]
    fn lock_state_from_the_exit_view() {
        assert_eq!(Lock::of(false, "open", false), Lock::Open);
        assert_eq!(Lock::of(true, "verifying", true), Lock::ExitDown);
        assert_eq!(Lock::of(true, "verifying", false), Lock::Verifying);
        assert_eq!(Lock::of(true, "changed", true), Lock::Other);
        assert_eq!(Lock::of(true, "no_baseline", false), Lock::Other);
    }

    #[test]
    fn notices_say_what_is_broken_and_what_to_do() {
        let ctx = NoticeCtx::default();
        let (title, body) = notice(Stuck::VpnStuck, secs(34), &ctx);
        assert_eq!(title, "VPN 卡住了，AI 通道已锁住");
        assert!(body.contains("Wi-Fi 和宽带正常") && body.contains("34 秒") && body.contains("断开再重新连接"), "{body}");
        let (title, body) = notice(Stuck::VpnOff, secs(95), &NoticeCtx { bind_if: Some("vpn0"), has_backup: false });
        assert_eq!(title, "VPN 没有连接，AI 通道已锁住");
        assert!(body.contains("“vpn0”没有连接") && body.contains("1 分 35 秒"), "{body}");
        // VPN 客户端可能自己连回来：先说等一等，再说手动重连
        assert!(body.contains("可能正在自动重连") && body.contains("还没恢复，就在客户端里手动重新连接"), "{body}");
        assert!(notice(Stuck::VpnOff, secs(95), &ctx).1.contains("没有经 VPN 上网"));
        assert!(notice(Stuck::Link, secs(30), &ctx).0.starts_with("Wi-Fi 或网线没有连上"));
        assert!(notice(Stuck::Broadband, secs(30), &ctx).1.contains("路由器连得上"));
        let (_, body) = notice(Stuck::Exit, secs(30), &NoticeCtx { bind_if: None, has_backup: true });
        assert!(body.starts_with("出口已经 30 秒连不上。") && body.contains("anchor check") && body.contains("anchor exit use"), "{body}");
        assert!(notice(Stuck::Exit, Duration::from_millis(19_900), &ctx).1.starts_with("出口已经 20 秒连不上"), "四舍五入到整秒");
        assert!(!notice(Stuck::Exit, secs(30), &ctx).1.contains("anchor exit use"));
        // 托盘气泡的正文最多 255 个字符
        for s in [Stuck::Link, Stuck::Broadband, Stuck::VpnStuck, Stuck::VpnOff, Stuck::Local, Stuck::Exit] {
            let (t, b) = notice(s, secs(3 * 3600 + 59 * 60 + 59), &NoticeCtx { bind_if: Some("一块名字比较长的虚拟网卡"), has_backup: true });
            assert!(t.encode_utf16().count() < 64 && b.encode_utf16().count() < 255, "{t}：{b}");
            assert_ne!(Stuck::label(s.name()), "原因不明");
        }
        let (title, body) = recovered_notice("203.0.113.10", secs(105));
        assert_eq!(title, "AI 通道已恢复");
        assert!(body.contains("203.0.113.10") && body.contains("1 分 45 秒"), "{body}");
    }
}
