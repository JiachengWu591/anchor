//! 一次性体检：本地网络、内核、线路、出口、AI 服务、一致性、守卫，并按设计文档的顺序归因。
//! P0 只做一次性；P1 改为后台定时探测并存入 SQLite 时间线。

use crate::config::{Config, Paths, host_port};
use crate::net::{self, ClashApi, ExitInfo};
use crate::netenv;
use crate::util::{now_rfc3339, pad};
use anyhow::Result;
use serde::Serialize;
use serde_json::Value;
use std::io::Write;
use std::time::Duration;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum St {
    Pass,
    Info,
    Warn,
    Fail,
    Skip,
}

impl St {
    fn tag(self) -> &'static str {
        match self {
            St::Pass => "OK",
            St::Info => "INFO",
            St::Warn => "WARN",
            St::Fail => "FAIL",
            St::Skip => "SKIP",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Probe {
    pub segment: &'static str,
    pub name: String,
    pub status: St,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub time: String,
    pub verdict: String,
    pub healthy: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit: Option<ExitInfo>,
    pub probes: Vec<Probe>,
}

const LOCAL: &str = "本地网络";
const CORE: &str = "内核";
const LINE: &str = "线路";
const EXIT: &str = "出口";
const AI: &str = "AI 服务";
const CONS: &str = "一致性";
const GUARD: &str = "守卫";

const STATUS_PAGES: &[(&str, &str)] = &[
    ("Anthropic 状态页", "https://status.anthropic.com/api/v2/status.json"),
    ("OpenAI 状态页", "https://status.openai.com/api/v2/status.json"),
];
const ENDPOINTS: &[(&str, &str)] = &[
    ("api.anthropic.com", "https://api.anthropic.com/v1/models"),
    ("claude.ai", "https://claude.ai/"),
    ("api.openai.com", "https://api.openai.com/v1/models"),
    ("chatgpt.com", "https://chatgpt.com/"),
];

fn probe(segment: &'static str, name: impl Into<String>, status: St, latency: Option<Duration>, detail: impl Into<String>) -> Probe {
    Probe { segment, name: name.into(), status, latency_ms: latency.map(|d| d.as_millis() as u64), detail: detail.into() }
}

pub fn run(cfg: &Config) -> Report {
    let mut p = Vec::new();

    // 1. 本地网络：不经代理访问连通性检测地址
    let direct = net::agent_direct(Duration::from_secs(6));
    match net::get(&direct, &cfg.check.local_url) {
        Ok(r) if (200..400).contains(&r.code) => p.push(probe(LOCAL, "直连连通性", St::Pass, Some(r.elapsed), format!("HTTP {}", r.code))),
        Ok(r) => p.push(probe(LOCAL, "直连连通性", St::Fail, Some(r.elapsed), format!("HTTP {}", r.code))),
        Err(e) => p.push(probe(LOCAL, "直连连通性", St::Fail, None, format!("{e:#}"))),
    }
    // 默认流量是否进 VPN / TUN：线路流量都会经过它，它断开时所有线路会同时失败
    let tunnel = netenv::default_route().filter(|d| d.is_tunnel());
    if let Some(t) = &tunnel {
        let how = if t.split_default { "全量隧道" } else { "默认路由" };
        let (st, state) = if t.up { (St::Info, "已连接") } else { (St::Warn, "未连接") };
        p.push(probe(
            LOCAL,
            "VPN / 隧道",
            st,
            None,
            format!("{state}：{how}经 {}。线路流量都走这个隧道；它断开或重连时所有线路会同时失败", t.describe()),
        ));
    }

    // 2. 内核
    let core_up = net::port_open(&cfg.proxy.listen, cfg.proxy.port);
    let listen = host_port(&cfg.proxy.listen, cfg.proxy.port);
    p.push(if core_up {
        probe(CORE, "AI 代理端口", St::Pass, None, format!("{listen} 在监听"))
    } else {
        probe(CORE, "AI 代理端口", St::Fail, None, format!("{listen} 没有监听：先运行 anchor up"))
    });
    let api = ClashApi::new(cfg);

    // 3. 线路：内核在运行时测协议握手 + 请求，否则只测 TCP
    let current = if core_up { api.current_line() } else { None };
    if cfg.lines.is_empty() {
        p.push(probe(LINE, "（未配置）", St::Info, None, "直接连接出口"));
    }
    for l in &cfg.lines {
        let name = l.name.as_deref().unwrap_or_default();
        let tcp = match (l.server(), l.port()) {
            (Some(h), Some(port)) => Some(net::tcp_probe(h, port, Duration::from_secs(3))),
            _ => None,
        };
        let tcp_text = match &tcp {
            Some(Ok(d)) => format!("TCP {} ms", d.as_millis()),
            Some(Err(e)) => format!("TCP 失败：{e:#}"),
            None => "没有 server/server_port，跳过 TCP".into(),
        };
        let shown = if current.as_deref() == Some(name) { format!("{name}（当前）") } else { name.to_string() };
        if core_up {
            match api.delay(name, &cfg.switch.probe_url, 5000) {
                Ok(ms) => p.push(Probe { latency_ms: Some(ms), ..probe(LINE, shown, St::Pass, None, format!("协议握手 + 请求；{tcp_text}")) }),
                Err(e) => p.push(probe(LINE, shown, St::Fail, None, format!("协议探测失败：{e:#}；{tcp_text}"))),
            }
        } else {
            // 只有 TCP 能连上不代表线路协议可用；经 VPN / TUN 时，握手还可能由隧道客户端在本地先应答。
            let (st, lat) = match &tcp {
                Some(Ok(d)) => (St::Info, Some(*d)),
                Some(Err(_)) => (St::Fail, None),
                None => (St::Skip, None),
            };
            let why = if tunnel.is_some() { "内核未运行，只测 TCP；经 VPN 时握手可能是本地应答" } else { "内核未运行，只测 TCP，不代表线路可用" };
            p.push(probe(LINE, shown, st, lat, format!("{tcp_text}（{why}）")));
        }
    }

    // 4. 出口：经通道访问 IP 回显服务，与基线比对
    let mut exit_info = None;
    if core_up {
        if let Ok(ms) = api.delay("exit", &cfg.switch.probe_url, 8000) {
            p.push(Probe { latency_ms: Some(ms), ..probe(EXIT, "整条链路", St::Pass, None, "线路 → 出口 → 目标") });
        }
        match net::agent_via_proxy(cfg, Duration::from_secs(10)).and_then(|a| net::fetch_exit(&a, &cfg.check)) {
            Ok(info) => {
                let (st, detail) = if cfg.expect.ip.trim().is_empty() {
                    (St::Warn, format!("实际 {}；还没有登记基线（anchor baseline）", info.ip))
                } else if net::same_ip(&cfg.expect.ip, &info.ip) {
                    (St::Pass, format!("{}，与基线一致", info.ip))
                } else {
                    (St::Fail, format!("实际 {}，基线 {}：出口 IP 已变化", info.ip, cfg.expect.ip))
                };
                p.push(probe(EXIT, "出口 IP", st, None, detail));
                p.push(probe(EXIT, "出口位置", St::Info, None, format!("{}；{}", info.place(), info.org.as_deref().unwrap_or("网络归属未知"))));
                exit_info = Some(info);
            }
            Err(e) => p.push(probe(EXIT, "出口 IP", St::Fail, None, format!("经通道访问失败：{e:#}"))),
        }
    } else {
        p.push(probe(EXIT, "出口 IP", St::Skip, None, "内核未运行"));
    }

    // 5. AI 服务：官方状态页 + 关键域名可达性
    match (core_up, net::agent_via_proxy(cfg, Duration::from_secs(10))) {
        (true, Ok(agent)) => {
            for (name, url) in STATUS_PAGES {
                p.push(status_page(&agent, name, url));
            }
            for (name, url) in ENDPOINTS {
                p.push(match net::get(&agent, url) {
                    Ok(r) if region_blocked(&r) => probe(AI, *name, St::Warn, Some(r.elapsed), format!("HTTP {}：服务提示出口所在地区不受支持", r.code)),
                    Ok(r) => probe(AI, *name, St::Pass, Some(r.elapsed), format!("可达（HTTP {}）", r.code)),
                    Err(e) => probe(AI, *name, St::Fail, None, format!("{e:#}")),
                });
            }
        }
        _ => p.push(probe(AI, "全部", St::Skip, None, "内核未运行")),
    }

    // 6. 一致性
    consistency(cfg, exit_info.as_ref(), &mut p);

    // 7. 守卫
    p.push(match crate::guard::status(cfg) {
        Ok(st) if st.rules.is_empty() => probe(GUARD, "防火墙规则", St::Warn, None, "未安装：通道断开时 AI 程序可能直连（管理员运行 anchor guard install）"),
        Ok(st) if st.disabled() > 0 => probe(GUARD, "防火墙规则", St::Warn, None, format!("{} 条规则已暂停（anchor guard resume）", st.disabled())),
        Ok(st) if !st.missing.is_empty() => {
            let names: Vec<&str> = st.missing.iter().map(|t| t.label.as_str()).collect();
            probe(GUARD, "防火墙规则", St::Warn, None, format!("未覆盖：{}（应用更新后路径会变，重新运行 anchor guard install）", names.join("、")))
        }
        Ok(st) => probe(GUARD, "防火墙规则", St::Pass, None, format!("{} 条规则，覆盖配置里的 {} 个程序", st.rules.len(), st.expected.len())),
        Err(e) => probe(GUARD, "防火墙规则", St::Warn, None, format!("无法读取：{e:#}")),
    });

    let verdict = attribute(&p, !cfg.lines.is_empty(), tunnel.as_ref().map(|t| t.name.as_str()));
    Report { time: now_rfc3339(), healthy: !p.iter().any(|x| x.status == St::Fail), verdict, exit: exit_info, probes: p }
}

fn status_page(agent: &ureq::Agent, name: &str, url: &str) -> Probe {
    let r = match net::get(agent, url) {
        Ok(r) => r,
        Err(e) => return probe(AI, name, St::Warn, None, format!("状态页打不开：{e:#}")),
    };
    let v: Option<Value> = serde_json::from_str(&r.body).ok();
    let indicator = v.as_ref().and_then(|v| v["status"]["indicator"].as_str()).map(str::to_string);
    let desc = v.as_ref().and_then(|v| v["status"]["description"].as_str()).unwrap_or("").to_string();
    match indicator.as_deref() {
        Some("none") => probe(AI, name, St::Pass, Some(r.elapsed), desc),
        Some("minor") | Some("maintenance") => probe(AI, name, St::Warn, Some(r.elapsed), desc),
        Some(_) => probe(AI, name, St::Fail, Some(r.elapsed), format!("服务端故障：{desc}")),
        None => probe(AI, name, St::Warn, Some(r.elapsed), format!("HTTP {}，无法解析状态", r.code)),
    }
}

fn region_blocked(r: &net::HttpResult) -> bool {
    let u = r.final_url.to_lowercase();
    let b = r.body.to_lowercase();
    u.contains("unavailable-in-region") || b.contains("unsupported_country") || b.contains("unavailable in your region")
}

fn consistency(cfg: &Config, exit: Option<&ExitInfo>, p: &mut Vec<Probe>) {
    match exit {
        Some(info) => {
            let tz = info.timezone.as_deref().unwrap_or("");
            p.push(if tz.is_empty() {
                probe(CONS, "时区", St::Skip, None, "回显服务没有返回时区")
            } else if cfg.expect.timezone.is_empty() {
                probe(CONS, "时区", St::Warn, None, format!("出口时区 {tz}；还没有登记期望时区（anchor baseline 会填写）"))
            } else if cfg.expect.timezone == tz {
                probe(CONS, "时区", St::Pass, None, format!("出口时区 {tz}，与配置一致"))
            } else {
                probe(CONS, "时区", St::Warn, None, format!("出口时区 {tz}，配置期望 {}", cfg.expect.timezone))
            });
            let region = cfg.expect.language.rsplit(['-', '_']).next().unwrap_or("").to_uppercase();
            let country = info.country.as_deref().unwrap_or("").to_uppercase();
            p.push(if country.is_empty() {
                probe(CONS, "语言", St::Skip, None, "回显服务没有返回国家")
            } else if region == country {
                probe(CONS, "语言", St::Pass, None, format!("{} 与出口国家 {country} 一致", cfg.expect.language))
            } else {
                probe(CONS, "语言", St::Warn, None, format!("浏览器语言 {} 与出口国家 {country} 不一致（改 [expect] language）", cfg.expect.language))
            });
        }
        None => p.push(probe(CONS, "时区 / 语言", St::Skip, None, "没有拿到出口信息")),
    }
    let sys_tz = std::process::Command::new("tzutil")
        .arg("/g")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    p.push(probe(CONS, "系统时区", St::Info, None, format!("{sys_tz}（网页和桌面客户端读取的是系统时区）")));
    p.push(probe(CONS, "DNS / WebRTC 泄露", St::Skip, None, "P1：在 AI 专用浏览器内检测"));
}

/// 按设计文档的归因顺序：本地 → 内核 → 线路 → 出口 → 服务端。
/// vpn 是承载默认流量的隧道网卡名：线路同时失败时，它是最常见的共同原因。
fn attribute(p: &[Probe], has_lines: bool, vpn: Option<&str>) -> String {
    let failed = |seg: &str| p.iter().any(|x| x.segment == seg && x.status == St::Fail);
    let vpn_down = p.iter().any(|x| x.segment == LOCAL && x.name == "VPN / 隧道" && x.status == St::Warn);
    let lines: Vec<&Probe> = p.iter().filter(|x| x.segment == LINE && x.status != St::Info).collect();
    let all_lines_down = has_lines && !lines.is_empty() && lines.iter().all(|x| x.status == St::Fail);
    if failed(LOCAL) || vpn_down {
        match vpn {
            Some(v) => format!("故障在本地网络：本机出网失败，流量经 VPN“{v}”，先检查 VPN 是否已连接，再检查 Wi-Fi / 网线"),
            None => "故障在本地网络：本机直连外网失败，先检查 Wi-Fi / 网线".into(),
        }
    } else if failed(CORE) {
        "内核没有运行：运行 anchor up".into()
    } else if all_lines_down {
        match vpn {
            Some(v) => format!("故障在线路，或底层 VPN“{v}”：所有线路同时失败，先确认 VPN 没有在重连"),
            None => "故障在线路：所有线路都不可用".into(),
        }
    } else if failed(EXIT) {
        "故障在出口：出口不可达，或出口 IP 已变化".into()
    } else if failed(AI) {
        "故障在服务端，或出口到 AI 服务的路径".into()
    } else if failed(LINE) {
        "通道可用：部分线路不可用，自动切换会避开它们".into()
    } else if p.iter().any(|x| x.status == St::Warn) {
        "通道可用，有需要注意的项（见 WARN）".into()
    } else {
        "全部正常".into()
    }
}

pub fn print(r: &Report) {
    println!("AI Anchor 体检  {}\n", r.time);
    for x in &r.probes {
        let lat = x.latency_ms.map(|m| format!("{m} ms")).unwrap_or_default();
        println!("{}  {}  {}  {}  {}", pad(x.segment, 8), pad(x.status.tag(), 4), pad(&x.name, 24), pad(&lat, 7), x.detail);
    }
    println!("\n结论：{}", r.verdict);
}

pub fn save(paths: &Paths, r: &Report) -> Result<std::path::PathBuf> {
    std::fs::create_dir_all(paths.log_dir())?;
    let file = paths.log_dir().join("checks.jsonl");
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&file)?;
    writeln!(f, "{}", serde_json::to_string(r)?)?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pr(seg: &'static str, st: St) -> Probe {
        probe(seg, "x", st, None, "")
    }

    #[test]
    fn attribution_order_follows_design() {
        let p = vec![pr(LOCAL, St::Fail), pr(CORE, St::Fail), pr(EXIT, St::Fail)];
        assert!(attribute(&p, true, None).contains("本地网络"));
        let p = vec![pr(LOCAL, St::Pass), pr(CORE, St::Pass), pr(LINE, St::Fail), pr(LINE, St::Fail), pr(EXIT, St::Fail)];
        assert!(attribute(&p, true, None).contains("线路"));
        let p = vec![pr(LOCAL, St::Pass), pr(CORE, St::Pass), pr(LINE, St::Fail), pr(LINE, St::Pass), pr(EXIT, St::Pass)];
        assert!(attribute(&p, true, None).contains("部分线路"));
        let p = vec![pr(LOCAL, St::Pass), pr(CORE, St::Pass), pr(LINE, St::Pass), pr(EXIT, St::Fail)];
        assert!(attribute(&p, true, None).contains("出口"));
        let p = vec![pr(LOCAL, St::Pass), pr(CORE, St::Pass), pr(EXIT, St::Pass), pr(AI, St::Fail)];
        assert!(attribute(&p, false, None).contains("服务端"));
        let p = vec![pr(LOCAL, St::Pass), pr(CORE, St::Pass), pr(EXIT, St::Pass)];
        assert_eq!(attribute(&p, false, None), "全部正常");
    }

    #[test]
    fn attribution_points_at_vpn_when_tunneled() {
        let p = vec![pr(LOCAL, St::Pass), pr(CORE, St::Pass), pr(LINE, St::Fail), pr(LINE, St::Fail)];
        assert!(attribute(&p, true, Some("本地连接")).contains("VPN“本地连接”"));
        let p = vec![pr(LOCAL, St::Pass), probe(LOCAL, "VPN / 隧道", St::Warn, None, ""), pr(CORE, St::Pass)];
        assert!(attribute(&p, true, Some("本地连接")).contains("先检查 VPN 是否已连接"));
        // 隧道正常时，信息项不影响“全部正常”
        let p = vec![pr(LOCAL, St::Pass), probe(LOCAL, "VPN / 隧道", St::Info, None, ""), pr(CORE, St::Pass), pr(EXIT, St::Pass)];
        assert_eq!(attribute(&p, false, Some("本地连接")), "全部正常");
    }
}
