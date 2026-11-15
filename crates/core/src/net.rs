//! 网络探测工具：直连 / 经通道的 HTTP、TCP 握手、出口信息、sing-box 的 Clash API。

use crate::config::{CheckCfg, Config, host_port};
use anyhow::{Context, Result, anyhow, bail};
use serde::Serialize;
use serde_json::Value;
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

const UA: &str = concat!("ai-anchor/", env!("CARGO_PKG_VERSION"));

/// 不走任何代理（不读 HTTP_PROXY 环境变量，也不读系统代理）。
pub fn agent_direct(timeout: Duration) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(timeout.min(Duration::from_secs(5)))
        .timeout(timeout)
        .user_agent(UA)
        .build()
}

/// 经本机 AI 通道（AI 程序用的端口；出口锁住时连不上）。
pub fn agent_via_proxy(cfg: &Config, timeout: Duration) -> Result<ureq::Agent> {
    proxied(&cfg.proxy_url(), timeout)
}

/// 经探测专用入站：与 AI 通道走同一个出口，但不受出口锁定影响。核对出口、体检用它。
pub fn agent_via_probe(cfg: &Config, timeout: Duration) -> Result<ureq::Agent> {
    proxied(&cfg.probe_proxy_url(), timeout)
}

/// 命令行核对出口用：探测入站在监听就用它，否则（内核是旧版本启动的）退回 AI 端口。
pub fn agent_for_checks(cfg: &Config, timeout: Duration) -> Result<ureq::Agent> {
    if port_open("127.0.0.1", cfg.probe_port()) { agent_via_probe(cfg, timeout) } else { agent_via_proxy(cfg, timeout) }
}

fn proxied(url: &str, timeout: Duration) -> Result<ureq::Agent> {
    let proxy = ureq::Proxy::new(url).context("代理地址格式错误")?;
    Ok(ureq::AgentBuilder::new()
        .proxy(proxy)
        .timeout_connect(Duration::from_secs(5).min(timeout))
        .timeout(timeout)
        .user_agent(UA)
        .build())
}

/// 从一个回显服务取出口 IP：纯文本 IP，或带 "ip" 字段的 JSON（如 ipinfo）。
pub fn echo_ip(agent: &ureq::Agent, url: &str) -> Result<String> {
    parse_echo(&get(agent, url)?)
}

/// 解析回显服务的响应。能走到这一步说明经出口拿到了响应，出错只是回显服务本身的问题。
pub fn parse_echo(r: &HttpResult) -> Result<String> {
    if r.code != 200 {
        bail!("HTTP {}", r.code);
    }
    let body = r.body.trim();
    let ip = match serde_json::from_str::<Value>(body) {
        Ok(v) => v.get("ip").and_then(Value::as_str).unwrap_or_default().to_string(),
        Err(_) => body.to_string(),
    };
    match ip.parse::<IpAddr>() {
        Ok(a) => Ok(a.to_string()),
        Err(_) => bail!("返回内容不是 IP 地址"),
    }
}

pub struct HttpResult {
    pub code: u16,
    pub body: String,
    pub final_url: String,
    pub elapsed: Duration,
    /// Cloudflare 的 cf-mitigated 响应头（"challenge" 表示要求人机验证）
    pub cf_mitigated: Option<String>,
}

/// GET；4xx/5xx 也算拿到了响应（说明网络可达），只有传输层失败才返回错误。
pub fn get(agent: &ureq::Agent, url: &str) -> Result<HttpResult> {
    let t = Instant::now();
    let resp = match agent.get(url).call() {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(e) => return Err(anyhow::Error::new(e)),
    };
    let code = resp.status();
    let final_url = resp.get_url().to_string();
    let cf_mitigated = resp.header("cf-mitigated").map(|v| v.trim().to_ascii_lowercase());
    let body = resp.into_string().unwrap_or_default();
    Ok(HttpResult { code, body, final_url, elapsed: t.elapsed(), cf_mitigated })
}

#[derive(Debug, Clone, Serialize)]
pub struct ExitInfo {
    pub ip: String,
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub timezone: Option<String>,
    pub org: Option<String>,
    pub source: String,
}

impl ExitInfo {
    pub fn place(&self) -> String {
        let parts: Vec<&str> = [&self.country, &self.region, &self.city].iter().filter_map(|x| x.as_deref()).collect();
        if parts.is_empty() { "未知".into() } else { parts.join(" / ") }
    }
}

/// 先用带地理信息的服务，失败再退回纯 IP 回显服务。
pub fn fetch_exit(agent: &ureq::Agent, cc: &CheckCfg) -> Result<ExitInfo> {
    let mut errs = Vec::new();
    if !cc.ip_info.is_empty() {
        match get(agent, &cc.ip_info) {
            Ok(r) if r.code == 200 => match serde_json::from_str::<Value>(&r.body) {
                Ok(v) if v.get("ip").and_then(Value::as_str).is_some_and(|s| s.parse::<IpAddr>().is_ok()) => {
                    let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
                    return Ok(ExitInfo {
                        ip: s("ip").unwrap_or_default(),
                        country: s("country"),
                        region: s("region"),
                        city: s("city"),
                        timezone: s("timezone"),
                        org: s("org"),
                        source: cc.ip_info.clone(),
                    });
                }
                _ => errs.push(format!("{}：返回内容无法解析", cc.ip_info)),
            },
            Ok(r) => errs.push(format!("{}：HTTP {}", cc.ip_info, r.code)),
            Err(e) => errs.push(format!("{}：{e}", cc.ip_info)),
        }
    }
    for url in &cc.ip_echo {
        match get(agent, url) {
            Ok(r) if r.code == 200 && r.body.trim().parse::<IpAddr>().is_ok() => {
                return Ok(ExitInfo {
                    ip: r.body.trim().to_string(),
                    country: None,
                    region: None,
                    city: None,
                    timezone: None,
                    org: None,
                    source: url.clone(),
                });
            }
            Ok(r) => errs.push(format!("{url}：HTTP {}", r.code)),
            Err(e) => errs.push(format!("{url}：{e}")),
        }
    }
    bail!("所有 IP 回显服务都失败：{}", errs.join("；"))
}

pub fn same_ip(a: &str, b: &str) -> bool {
    match (a.trim().parse::<IpAddr>(), b.trim().parse::<IpAddr>()) {
        (Ok(x), Ok(y)) => x == y,
        _ => a.trim().eq_ignore_ascii_case(b.trim()),
    }
}

/// TCP 握手耗时（直连，不经代理）。
pub fn tcp_probe(host: &str, port: u16, timeout: Duration) -> Result<Duration> {
    let addrs: Vec<_> = (host, port).to_socket_addrs().with_context(|| format!("解析 {host} 失败"))?.collect();
    let mut last = None;
    for a in addrs {
        let t = Instant::now();
        match TcpStream::connect_timeout(&a, timeout) {
            Ok(_) => return Ok(t.elapsed()),
            Err(e) => last = Some(e),
        }
    }
    Err(match last {
        Some(e) => anyhow::Error::new(e).context(format!("连接 {} 失败", host_port(host, port))),
        None => anyhow!("{host} 没有可用地址"),
    })
}

pub fn port_open(host: &str, port: u16) -> bool {
    tcp_probe(host, port, Duration::from_millis(800)).is_ok()
}

/// sing-box 内置的 Clash API（只监听 127.0.0.1）。
pub struct ClashApi {
    base: String,
    secret: String,
    agent: ureq::Agent,
}

impl ClashApi {
    pub fn new(cfg: &Config) -> Self {
        Self {
            base: format!("http://127.0.0.1:{}", cfg.api_port()),
            secret: cfg.core.api_secret.clone(),
            agent: agent_direct(Duration::from_secs(8)),
        }
    }

    pub fn get(&self, path: &str) -> Result<Value> {
        let url = format!("{}{}", self.base, path);
        let mut req = self.agent.get(&url);
        if !self.secret.is_empty() {
            req = req.set("Authorization", &format!("Bearer {}", self.secret));
        }
        let resp = match req.call() {
            Ok(r) => r,
            Err(ureq::Error::Status(code, r)) => {
                let body = r.into_string().unwrap_or_default();
                bail!("Clash API 返回 {code}：{}", body.trim());
            }
            Err(e) => return Err(e.into()),
        };
        Ok(serde_json::from_str(&resp.into_string()?)?)
    }

    /// 经指定出站请求 url 的耗时（毫秒）。对线路测的是“线路握手 + 请求”，对 exit 测的是整条链。
    pub fn delay(&self, outbound: &str, url: &str, timeout_ms: u32) -> Result<u64> {
        let v = self.get(&format!("/proxies/{}/delay?timeout={timeout_ms}&url={}", enc(outbound), enc(url)))?;
        v.get("delay").and_then(Value::as_u64).context("返回内容缺少 delay")
    }

    /// 让整组重新测速；urltest 组会据此立即重新选线。返回成功线路的延迟。
    pub fn group_delay(&self, group: &str, url: &str, timeout_ms: u32) -> Result<serde_json::Map<String, Value>> {
        let v = self.get(&format!("/group/{}/delay?timeout={timeout_ms}&url={}", enc(group), enc(url)))?;
        Ok(v.as_object().cloned().unwrap_or_default())
    }

    /// 线路组当前选中的线路。
    pub fn current_line(&self) -> Option<String> {
        self.get("/proxies/lines").ok()?.get("now")?.as_str().map(str::to_string)
    }

    /// 当前 Clash 模式（出口锁定用 Lock / Open）。
    pub fn mode(&self) -> Option<String> {
        self.get("/configs").ok()?.get("mode")?.as_str().map(str::to_string)
    }

    /// 切换 Clash 模式，并读回确认已生效（不认识的模式会被内核忽略）。
    pub fn set_mode(&self, mode: &str) -> Result<()> {
        let url = format!("{}/configs", self.base);
        let mut req = self.agent.request("PATCH", &url).set("Content-Type", "application/json");
        if !self.secret.is_empty() {
            req = req.set("Authorization", &format!("Bearer {}", self.secret));
        }
        match req.send_string(&serde_json::json!({ "mode": mode }).to_string()) {
            Ok(_) => {}
            Err(ureq::Error::Status(code, r)) => bail!("Clash API 返回 {code}：{}", r.into_string().unwrap_or_default().trim()),
            Err(e) => return Err(e.into()),
        }
        match self.mode() {
            Some(m) if m.eq_ignore_ascii_case(mode) => Ok(()),
            other => bail!("切换到 {mode} 后读回的模式是 {}", other.as_deref().unwrap_or("未知")),
        }
    }
}

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_ip_normalizes() {
        assert!(same_ip("203.0.113.10", " 203.0.113.10\n"));
        assert!(same_ip("2001:db8::1", "2001:0db8:0:0:0:0:0:1"));
        assert!(!same_ip("203.0.113.10", "203.0.113.11"));
    }

    #[test]
    fn percent_encoding() {
        assert_eq!(enc("line-a"), "line-a");
        assert_eq!(enc("https://x/y?z=1"), "https%3A%2F%2Fx%2Fy%3Fz%3D1");
        assert_eq!(enc("线路"), "%E7%BA%BF%E8%B7%AF");
    }
}
