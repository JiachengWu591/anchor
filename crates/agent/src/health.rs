//! 持续探测（P1b）：本机网络每 10 秒、整条链路每 30 秒，结果写进时间线，供断联归因使用。
//! 线路由看门狗探测，出口 IP 由出口核对探测，这里不重复。
//!
//! 本机网络分三段测，用来把“本地”断联分成 Wi-Fi、宽带、VPN：
//! - 路由器（lan）：ping 上行网卡（Wi-Fi 或网线）的默认网关；
//! - 绕开 VPN 上网（wan）：绑定上行网卡，和连通性检测地址（[check] local_url 的主机）握一次 TCP；
//! - 本机上网（local）：不经代理访问连通性检测地址，走系统路由。开着全量 VPN 时经过 VPN（目标记 vpn）。
//!
//! 整条链路（chain）：经内核从出口请求测速地址（[switch] probe_url）。

use crate::shared::{KernelState, Shared};
use anchor_core::config::Config;
use anchor_core::net::{self, ClashApi};
use anchor_core::singbox::TAG_EXIT;
use anchor_core::stall::Reading;
use anchor_core::uplink::{self, Uplink};
use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const LOCAL_EVERY: Duration = Duration::from_secs(10);
const CHAIN_EVERY: Duration = Duration::from_secs(30);
pub const CHAIN_TIMEOUT_MS: u32 = 5000;
const PING_TIMEOUT: Duration = Duration::from_secs(1);
const BYPASS_TIMEOUT: Duration = Duration::from_secs(2);
/// 连通性检测地址的 IP 多久重新解析一次（只在本机上网正常时解析，免得断网时卡在 DNS 上）
const RESOLVE_EVERY: Duration = Duration::from_secs(600);

pub fn spawn(sh: Arc<Shared>, cfg: &Config, stop: Arc<AtomicBool>) -> JoinHandle<()> {
    let local_url = cfg.check.local_url.clone();
    let probe_url = cfg.switch.probe_url.clone();
    let api = ClashApi::new(cfg);
    thread::spawn(move || {
        // 本机网络三段一个线程，整条链路一个线程：断网时探测会变慢，互不拖累
        let local = {
            let (sh, stop) = (sh.clone(), stop.clone());
            thread::spawn(move || {
                let mut lp = LocalProbes::new(&local_url);
                let mut next = Instant::now() + Duration::from_secs(5);
                while !stop.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_millis(250));
                    if Instant::now() >= next {
                        next = Instant::now() + LOCAL_EVERY;
                        lp.run(&sh);
                    }
                }
            })
        };
        let mut next_chain = Instant::now() + Duration::from_secs(10);
        while !stop.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(250));
            let now = Instant::now();
            if now >= next_chain && sh.status().kernel == KernelState::Running {
                next_chain = now + CHAIN_EVERY;
                let (ok, ms, note) = chain_probe(&api, &probe_url);
                // 内核在探测中途停了：不算链路故障
                if !stop.load(Ordering::SeqCst) {
                    sh.tl.probe("chain", TAG_EXIT, ok, ms, &note);
                }
            }
        }
        let _ = local.join();
    })
}

/// 本机网络三段探测，带记忆。某个网关在这次运行里从没回过 ping、或者绕开 VPN 的连接从没连上过，
/// 它们的失败就不记：有的网络不回 ping，有的 VPN 不许绕开它，这些是“测不了”，不是故障。
struct LocalProbes {
    direct: ureq::Agent,
    url: String,
    host_port: Option<(String, u16)>,
    addrs: Vec<SocketAddrV4>,
    resolved_at: Option<Instant>,
    answered: HashSet<Ipv4Addr>,
    bypass_ok: HashSet<Ipv4Addr>,
    /// 上一次看到的上行网卡（外层 None：还没看过）
    last: Option<Option<Uplink>>,
    /// 这次运行里有过上行网卡
    ever_uplink: bool,
}

impl LocalProbes {
    fn new(url: &str) -> Self {
        Self {
            direct: net::agent_direct(Duration::from_secs(3)),
            url: url.to_string(),
            host_port: host_port(url),
            addrs: Vec::new(),
            resolved_at: None,
            answered: HashSet::new(),
            bypass_ok: HashSet::new(),
            last: None,
            ever_uplink: false,
        }
    }

    fn run(&mut self, sh: &Shared) {
        let up = uplink::find();
        if let Some(prev) = self.last
            && !same_uplink(prev, up)
        {
            let kind = |u: Option<Uplink>| u.map_or("none", |u| u.kind());
            sh.tl.event("uplink_change", serde_json::json!({ "from": kind(prev), "to": kind(up) }));
        }
        let had_uplink = self.last.is_some_and(|u| u.is_some());
        self.last = Some(up);
        self.ever_uplink |= up.is_some();

        // 各段的最新结果也留一份在内存里（出口迟迟连不上时，用它判断卡在哪一段）。
        // 时间记的是这一段探测开始的时刻；测不了的段记 None
        let started = Instant::now();
        let dst = self.addrs.first().map(|a| *a.ip());
        {
            let mut h = sh.local_health();
            h.uplink = (self.ever_uplink || up.is_some()).then_some(Reading { ok: up.is_some(), at: started });
            h.via_vpn = via_label(up, dst) == "vpn";
            h.vpn_seen |= h.via_vpn;
            if up.is_none() {
                h.lan = None;
                h.wan = None;
            }
        }

        match up {
            Some(u) => {
                let at = Instant::now();
                let (ok, ms, note) = twice(|| match uplink::ping(u.gateway, PING_TIMEOUT) {
                    Ok(ms) => (true, Some(u64::from(ms)), String::new()),
                    Err(e) => (false, None, format!("{e:#}")),
                });
                if ok {
                    self.answered.insert(u.gateway);
                }
                let known = ok || self.answered.contains(&u.gateway);
                if known {
                    sh.tl.probe("lan", u.kind(), ok, ms, &note);
                }
                sh.local_health().lan = known.then_some(Reading { ok, at });
                let mut wan = None;
                if let Some(addr) = self.addrs.first().copied() {
                    let at = Instant::now();
                    let (ok, ms, note) = twice(|| match uplink::tcp_via(u.if_index, addr, BYPASS_TIMEOUT) {
                        Ok(d) => (true, Some(d.as_millis() as u64), String::new()),
                        Err(e) => (false, None, format!("{e:#}")),
                    });
                    if ok {
                        self.bypass_ok.insert(u.gateway);
                    }
                    if ok || self.bypass_ok.contains(&u.gateway) {
                        sh.tl.probe("wan", u.kind(), ok, ms, &note);
                        wan = Some(Reading { ok, at });
                    }
                }
                sh.local_health().wan = wan;
            }
            // 刚才还连着，现在找不到默认网关：Wi-Fi 断了或网线拔了
            None if had_uplink => sh.tl.probe("lan", "none", false, None, "没有连上 Wi-Fi 或网线（找不到默认网关）"),
            None => {}
        }

        let at = Instant::now();
        let (ok, ms, note) = local_probe(&self.direct, &self.url);
        let target = via_label(up, dst);
        sh.tl.probe("local", target, ok, ms, &note);
        {
            let mut h = sh.local_health();
            h.local = Some(Reading { ok, at });
            h.via_vpn = target == "vpn";
            h.vpn_seen |= h.via_vpn;
        }
        if ok && self.resolved_at.is_none_or(|t| t.elapsed() >= RESOLVE_EVERY) {
            self.resolve();
        }
    }

    fn resolve(&mut self) {
        let Some((host, port)) = &self.host_port else { return };
        self.resolved_at = Some(Instant::now());
        if let Ok(it) = (host.as_str(), *port).to_socket_addrs() {
            let v: Vec<SocketAddrV4> = it
                .filter_map(|a| match a {
                    SocketAddr::V4(v) => Some(v),
                    SocketAddr::V6(_) => None,
                })
                .collect();
            if !v.is_empty() {
                self.addrs = v;
            }
        }
    }
}

fn same_uplink(a: Option<Uplink>, b: Option<Uplink>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a.if_index == b.if_index && a.gateway == b.gateway,
        (None, None) => true,
        _ => false,
    }
}

/// 本机上网探测走的路：去往连通性检测地址（不知道时用一个公网地址代替）的路由不在上行网卡上，就是经 VPN。
fn via_label(up: Option<Uplink>, dst: Option<Ipv4Addr>) -> &'static str {
    let dst = dst.unwrap_or(Ipv4Addr::new(1, 1, 1, 1));
    match (up, uplink::route_if(dst)) {
        (Some(u), Some(idx)) if idx != u.if_index => "vpn",
        _ => "direct",
    }
}

/// 断联后的突发探测用：此刻本机上网是不是经 VPN。
pub fn local_via() -> &'static str {
    via_label(uplink::find(), None)
}

/// `http://host[:port]/path` → (host, port)
fn host_port(url: &str) -> Option<(String, u16)> {
    let (scheme, rest) = url.split_once("://")?;
    let auth = rest.split(['/', '?', '#']).next()?;
    let default = if scheme.eq_ignore_ascii_case("https") { 443 } else { 80 };
    match auth.rsplit_once(':') {
        Some((h, p)) if !h.contains(']') || h.ends_with(']') => Some((h.trim_matches(['[', ']']).to_string(), p.parse().ok()?)),
        _ => Some((auth.to_string(), default)),
    }
}

/// 一次探测最多试两次：第一次失败隔 0.5 秒再试，两次都失败才算失败。
/// 实测：本地网络正常时，偶尔有一次请求读响应超时；只试一次的话，这一次就会把同时发生的断联错算成“本地”。
fn twice(mut f: impl FnMut() -> (bool, Option<u64>, String)) -> (bool, Option<u64>, String) {
    let first = f();
    if first.0 {
        return first;
    }
    thread::sleep(Duration::from_millis(500));
    let second = f();
    if second.0 { (true, second.1, format!("重试后成功；第一次：{}", first.2)) } else { second }
}

/// 不经代理访问连通性检测地址：(成功, 毫秒, 说明)。
pub fn local_probe(direct: &ureq::Agent, url: &str) -> (bool, Option<u64>, String) {
    twice(|| match net::get(direct, url) {
        Ok(r) if (200..400).contains(&r.code) => (true, Some(r.elapsed.as_millis() as u64), String::new()),
        Ok(r) => (false, None, format!("HTTP {}", r.code)),
        Err(e) => (false, None, format!("{e:#}").chars().take(200).collect()),
    })
}

/// 经内核从出口请求测速地址：(成功, 毫秒, 说明)。
pub fn chain_probe(api: &ClashApi, probe_url: &str) -> (bool, Option<u64>, String) {
    twice(|| match api.delay(TAG_EXIT, probe_url, CHAIN_TIMEOUT_MS) {
        Ok(ms) => (true, Some(ms), String::new()),
        Err(e) => (false, None, format!("{e:#}").chars().take(200).collect()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_and_port_from_url() {
        assert_eq!(host_port("http://www.msftconnecttest.com/connecttest.txt"), Some(("www.msftconnecttest.com".into(), 80)));
        assert_eq!(host_port("https://example.com"), Some(("example.com".into(), 443)));
        assert_eq!(host_port("http://127.0.0.1:28080/a.txt"), Some(("127.0.0.1".into(), 28080)));
        assert_eq!(host_port("nonsense"), None);
    }

    #[test]
    fn uplink_identity() {
        let u = |idx, gw: [u8; 4]| Some(Uplink { if_index: idx, wifi: true, gateway: Ipv4Addr::from(gw) });
        assert!(same_uplink(u(25, [192, 168, 1, 1]), u(25, [192, 168, 1, 1])));
        assert!(!same_uplink(u(25, [192, 168, 1, 1]), u(25, [10, 0, 0, 1])), "换了 Wi-Fi 网络");
        assert!(!same_uplink(u(25, [192, 168, 1, 1]), None));
        assert!(same_uplink(None, None));
    }
}
