//! 一致性检测（P1c）。三样都要联网或启动浏览器，所以只在 anchor check 里跑，不进用户代理的定时探测：
//!
//! - 出口 IP 的类型：问几个公开数据库，把各家的说法并排列出来，不只信一家。
//! - DNS 泄露：经通道访问检测服务的一次性域名，看是哪些解析服务器去查的。
//! - AI 专用浏览器：用同一套启动参数无头打开一个本机页面，看 WebRTC 暴露了什么地址、网页读到的时区和语言。
//!
//! 取数和判断分开：判断都是纯函数，按实测的返回内容测。

use crate::check::St;
use crate::net;
use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

// ---------- 出口 IP 的类型 ----------

/// 一个数据库对出口 IP 的说法。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpType {
    /// 这个库把它标成了什么：代理、VPN、机房、Tor。空表示没有标记
    pub flags: Vec<&'static str>,
    /// 库自己的分类（Business、移动网络……），只用来展示
    pub kind: Option<String>,
    /// 出口所在时区此刻比 UTC 快多少秒（只有 ip-api 给）
    pub offset_secs: Option<i64>,
}

/// (数据库名, 结果或失败原因)
pub type Typed = (String, Result<IpType, String>);

fn ip_type_url(source: &str, ip: &str) -> Option<String> {
    Some(match source {
        // 免费接口只有 HTTP；查询里只有出口 IP，本来就是经出口发出的
        "ip-api" => format!("http://ip-api.com/json/{ip}?fields=status,message,offset,mobile,proxy,hosting"),
        "ipquery" => format!("https://api.ipquery.io/{ip}?format=json"),
        "proxycheck" => format!("https://proxycheck.io/v2/{ip}?vpn=1&asn=1"),
        _ => return None,
    })
}

/// 按实测的返回格式解析（2026-11）。
pub fn parse_ip_type(source: &str, body: &str, ip: &str) -> Result<IpType> {
    let v: Value = serde_json::from_str(body).context("返回内容不是 JSON")?;
    let yes = |x: &Value| x.as_bool() == Some(true);
    let mut t = IpType::default();
    match source {
        "ip-api" => {
            if v["status"].as_str() != Some("success") {
                bail!("查询失败：{}", v["message"].as_str().unwrap_or("没有说明"));
            }
            // ip-api 的 proxy 一项包含代理、VPN 和 Tor 出口，不细分
            if yes(&v["proxy"]) {
                t.flags.push("代理或 VPN");
            }
            if yes(&v["hosting"]) {
                t.flags.push("机房");
            }
            if yes(&v["mobile"]) {
                t.kind = Some("移动网络".into());
            }
            t.offset_secs = v["offset"].as_i64();
        }
        "ipquery" => {
            let r = v.get("risk").filter(|r| r.is_object()).context("返回内容里没有 risk")?;
            for (key, label) in [("is_vpn", "VPN"), ("is_proxy", "代理"), ("is_tor", "Tor"), ("is_datacenter", "机房")] {
                if yes(&r[key]) {
                    t.flags.push(label);
                }
            }
            if yes(&r["is_mobile"]) {
                t.kind = Some("移动网络".into());
            }
        }
        "proxycheck" => {
            let e = match v.get(ip).filter(|e| e.is_object()) {
                Some(e) => e,
                None => bail!("查询失败：{}", v["message"].as_str().or(v["status"].as_str()).unwrap_or("返回内容里没有这个 IP")),
            };
            let kind = e["type"].as_str().unwrap_or("").trim();
            let lower = kind.to_ascii_lowercase();
            if e["proxy"].as_str() == Some("yes") {
                t.flags.push(match lower.as_str() {
                    "vpn" => "VPN",
                    "tor" => "Tor",
                    _ => "代理",
                });
            }
            if lower == "hosting" {
                t.flags.push("机房");
            }
            if !kind.is_empty() && !matches!(lower.as_str(), "vpn" | "tor" | "hosting") {
                t.kind = Some(kind.to_string());
            }
        }
        _ => bail!("不认识的数据库（可用：ip-api、ipquery、proxycheck）"),
    }
    Ok(t)
}

/// 同时问配置里的几个数据库。agent 经通道发请求。
pub fn fetch_ip_types(agent: &ureq::Agent, sources: &[String], ip: &str) -> Vec<Typed> {
    std::thread::scope(|s| {
        let jobs: Vec<_> = sources
            .iter()
            .map(|src| {
                s.spawn(move || {
                    let res = (|| {
                        let url = ip_type_url(src, ip).context("不认识的数据库（可用：ip-api、ipquery、proxycheck）")?;
                        let r = net::get(agent, &url)?;
                        if r.code != 200 {
                            bail!("HTTP {}", r.code);
                        }
                        parse_ip_type(src, &r.body, ip)
                    })();
                    res.map_err(|e| format!("{e:#}"))
                })
            })
            .collect();
        sources
            .iter()
            .zip(jobs)
            .map(|(src, j)| (src.clone(), j.join().unwrap_or_else(|_| Err("检测线程出错".into()))))
            .collect()
    })
}

/// 几个库的说法汇成一项。多数库标成代理或机房才算 WARN：这是出口本身的性质，不是通道的故障。
pub fn ip_type_summary(results: &[Typed]) -> (St, String) {
    let answered: Vec<(&str, &IpType)> = results.iter().filter_map(|(s, r)| r.as_ref().ok().map(|t| (s.as_str(), t))).collect();
    let parts: Vec<String> = results
        .iter()
        .map(|(src, r)| match r {
            Ok(t) => {
                let said = if t.flags.is_empty() { "没有标记".to_string() } else { t.flags.join("、") };
                match &t.kind {
                    Some(k) => format!("{src}：{said}（{k}）"),
                    None => format!("{src}：{said}"),
                }
            }
            Err(e) => format!("{src}：没查到（{e}）"),
        })
        .collect();
    let detail = parts.join("；");
    if answered.is_empty() {
        return (St::Skip, format!("数据库都没查到。{detail}"));
    }
    let flagged = answered.iter().filter(|(_, t)| !t.flags.is_empty()).count();
    let n = answered.len();
    if flagged == 0 {
        (St::Info, format!("{n} 个库都没有把它标成代理或机房。{detail}"))
    } else if flagged * 2 > n {
        (St::Warn, format!("{n} 个库里 {flagged} 个把它标成代理或机房：AI 服务可能更常要求验证。{detail}"))
    } else {
        (St::Info, format!("{n} 个库里 {flagged} 个把它标成代理或机房，各库说法不一。{detail}"))
    }
}

/// 出口时区此刻比 UTC 快多少秒（哪个库给了就用哪个）。
pub fn exit_offset_secs(results: &[Typed]) -> Option<i64> {
    results.iter().find_map(|(_, r)| r.as_ref().ok()?.offset_secs)
}

// ---------- DNS 泄露 ----------

/// 替我们去查一次性域名的解析服务器（检测服务从它的权威服务器上看到的）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolver {
    pub ip: String,
    /// 两位国家代码，大写
    pub country: String,
    pub org: String,
}

const DNS_LOOKUPS: u32 = 6;

/// 用 bash.ws 实测：领一个编号，经通道访问几个带编号的一次性域名，再问它看到了哪些解析服务器。
/// 这些域名没有缓存，谁替通道解析，谁就会被看到。
pub fn dns_leak_test(agent: &ureq::Agent) -> Result<Vec<Resolver>> {
    let r = net::get(agent, "https://bash.ws/id").context("领不到检测编号")?;
    let id = r.body.trim().to_string();
    if r.code != 200 || id.is_empty() || id.len() > 40 || !id.bytes().all(|b| b.is_ascii_alphanumeric()) {
        bail!("检测服务没有给出编号（HTTP {}）", r.code);
    }
    // 只要域名被解析就够了，请求本身成不成功无所谓
    std::thread::scope(|s| {
        for i in 1..=DNS_LOOKUPS {
            let url = format!("https://{i}.{id}.bash.ws/");
            s.spawn(move || {
                let _ = net::get(agent, &url);
            });
        }
    });
    let r = net::get(agent, &format!("https://bash.ws/dnsleak/test/{id}?json")).context("取不到检测结果")?;
    if r.code != 200 {
        bail!("取检测结果时 HTTP {}", r.code);
    }
    parse_bashws(&r.body)
}

/// bash.ws 的结果是一个数组：type 为 dns 的是解析服务器，ip 是本机出口，conclusion 是它自己的结论。
/// 它的结论只看“解析服务器是不是出口本身”，对经出口发 DoH 的做法总说可能泄露，不用。
pub fn parse_bashws(body: &str) -> Result<Vec<Resolver>> {
    let v: Value = serde_json::from_str(body).context("检测结果不是 JSON")?;
    let list = v.as_array().context("检测结果的格式不认识")?;
    Ok(list
        .iter()
        .filter(|e| e["type"].as_str() == Some("dns"))
        .filter_map(|e| {
            Some(Resolver {
                ip: e["ip"].as_str()?.to_string(),
                country: e["country"].as_str().unwrap_or("").to_ascii_uppercase(),
                org: e["org"].as_str().or(e["asn"].as_str()).unwrap_or("").trim().to_string(),
            })
        })
        .collect())
}

/// 解析服务器都在出口所在的国家就算通过。不在同一个国家不一定是泄露（出口用的公共 DNS 可能就近
/// 落在邻国），所以只标 WARN，把是谁列出来让人判断。
pub fn dns_leak_summary(resolvers: &[Resolver], exit_country: Option<&str>) -> (St, String) {
    if resolvers.is_empty() {
        return (St::Skip, "检测服务没有看到解析请求，这次测不出".into());
    }
    // 同一家、同一个国家的合成一项
    let mut groups: Vec<(String, usize)> = Vec::new();
    for r in resolvers {
        let key = if r.org.is_empty() { r.country.clone() } else { format!("{} {}", r.country, r.org) };
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, n)) => *n += 1,
            None => groups.push((key, 1)),
        }
    }
    let who = groups.iter().map(|(k, n)| if *n > 1 { format!("{k} ×{n}") } else { k.clone() }).collect::<Vec<_>>().join("、");
    let Some(exit) = exit_country.map(str::trim).filter(|c| !c.is_empty()) else {
        return (St::Info, format!("替通道解析域名的是：{who}。不知道出口在哪个国家，没法比较"));
    };
    let exit = exit.to_ascii_uppercase();
    if resolvers.iter().all(|r| r.country == exit) {
        (St::Pass, format!("替通道解析域名的服务器都在出口所在的 {exit}：{who}"))
    } else {
        (St::Warn, format!("有解析服务器不在出口所在的 {exit}：{who}。如果其中有你本地网络的运营商，域名查询没有经出口"))
    }
}

// ---------- AI 专用浏览器 ----------

/// 检测页在浏览器里看到的。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BrowserSeen {
    /// 网页读到的时区（IANA 名称）
    pub timezone: Option<String>,
    /// 网页读到的时间比 UTC 快多少分钟
    pub offset_min: Option<i64>,
    /// navigator.languages
    pub languages: Vec<String>,
    /// 请求头里的 Accept-Language
    pub accept_language: Option<String>,
    /// WebRTC 收集到的候选（原始的 candidate 行）
    pub candidates: Vec<String>,
    pub webrtc_error: Option<String>,
}

/// 检测页：向两个 STUN 服务器收集 WebRTC 候选（最多等 5 秒），连同时区和语言交回本机。
const PAGE: &str = r#"<!doctype html><meta charset="utf-8"><title>AI Anchor</title><script>
(async () => {
  const out = { tz: null, offset: null, langs: navigator.languages, cands: [], err: null };
  try { out.tz = Intl.DateTimeFormat().resolvedOptions().timeZone; out.offset = -new Date().getTimezoneOffset(); } catch (e) {}
  try {
    const pc = new RTCPeerConnection({ iceServers: [{ urls: ['stun:stun.l.google.com:19302', 'stun:stun.cloudflare.com:3478'] }] });
    pc.createDataChannel('x');
    const done = new Promise(res => {
      pc.onicecandidate = e => { if (!e.candidate) return res(); out.cands.push(e.candidate.candidate); };
      setTimeout(res, 5000);
    });
    await pc.setLocalDescription(await pc.createOffer());
    await done;
    pc.close();
  } catch (e) { out.err = String(e); }
  await fetch('/result', { method: 'POST', body: JSON.stringify(out) });
})();
</script>"#;

const BROWSER_TIMEOUT: Duration = Duration::from_secs(20);

/// 无头启动浏览器打开本机的检测页，等它把结果交回来。
/// args(临时配置目录, 检测页地址) 给出启动参数：调用方用和 AI 专用浏览器同一套参数，测的就是那套参数的效果。
/// 浏览器对 127.0.0.1 不走代理，所以通道锁着、内核没起来时也能测。
pub fn browser_check(exe: &Path, args: impl FnOnce(&Path, &str) -> Vec<String>) -> Result<BrowserSeen> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).context("开不了本机检测端口")?;
    let port = listener.local_addr()?.port();
    listener.set_nonblocking(true)?;
    let profile = std::env::temp_dir().join(format!("ai-anchor-browser-check-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&profile);
    std::fs::create_dir_all(&profile).context("建不了临时配置目录")?;
    let url = format!("http://127.0.0.1:{port}/");
    let spawned = Command::new(exe)
        .args(args(&profile, &url))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("无法启动 {}", exe.display()));
    let res = match spawned {
        Ok(mut child) => {
            let res = serve(&listener, Instant::now() + BROWSER_TIMEOUT);
            kill_tree(child.id());
            let _ = child.wait();
            res
        }
        Err(e) => Err(e),
    };
    // 浏览器的子进程退出要一点时间，目录一时删不掉就多试几次
    for _ in 0..15 {
        if std::fs::remove_dir_all(&profile).is_ok() || !profile.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let (body, accept_language) = res?;
    parse_seen(&body, accept_language)
}

fn kill_tree(pid: u32) {
    let _ = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// 只服务检测页和它交回的结果。返回 (结果 JSON, 打开检测页时的 Accept-Language)。
fn serve(listener: &TcpListener, deadline: Instant) -> Result<(String, Option<String>)> {
    let mut accept_language = None;
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let _ = stream.set_nonblocking(false);
                let Ok(req) = read_request(&mut stream) else { continue };
                match (req.method.as_str(), req.path.as_str()) {
                    ("GET", "/") => {
                        accept_language = req.header("accept-language").map(str::to_string);
                        respond(&mut stream, "200 OK", PAGE.as_bytes());
                    }
                    ("POST", "/result") => {
                        respond(&mut stream, "204 No Content", b"");
                        return Ok((String::from_utf8_lossy(&req.body).into_owned(), accept_language));
                    }
                    _ => respond(&mut stream, "404 Not Found", b""),
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    bail!("浏览器 {} 秒内没有交回结果", BROWSER_TIMEOUT.as_secs());
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(e).context("本机检测端口出错"),
        }
    }
}

struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
}

fn read_request(stream: &mut TcpStream) -> Result<Request> {
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > 64 * 1024 {
            bail!("请求头太长");
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            bail!("连接提前关闭");
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or("").split_whitespace();
    let method = first.next().unwrap_or("").to_string();
    let path = first.next().unwrap_or("").to_string();
    let headers: Vec<(String, String)> =
        lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())).collect();
    let len = headers.iter().find(|(k, _)| k == "content-length").and_then(|(_, v)| v.parse::<usize>().ok()).unwrap_or(0).min(1 << 20);
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < len {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(len);
    Ok(Request { method, path, headers, body })
}

fn respond(stream: &mut TcpStream, status: &str, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

pub fn parse_seen(body: &str, accept_language: Option<String>) -> Result<BrowserSeen> {
    let v: Value = serde_json::from_str(body).context("浏览器交回的结果不是 JSON")?;
    let strings = |x: &Value| x.as_array().map(|a| a.iter().filter_map(|s| s.as_str().map(str::to_string)).collect()).unwrap_or_default();
    Ok(BrowserSeen {
        timezone: v["tz"].as_str().filter(|s| !s.is_empty()).map(str::to_string),
        offset_min: v["offset"].as_i64(),
        languages: strings(&v["langs"]),
        accept_language,
        candidates: strings(&v["cands"]),
        webrtc_error: v["err"].as_str().map(str::to_string),
    })
}

/// 候选行里的地址：candidate:<编号> <分量> <协议> <优先级> <地址> <端口> typ <类型> …
/// 地址可能是 IP，也可能是浏览器用来遮住内网地址的 xxxx.local。
fn candidate_addr(line: &str) -> Option<&str> {
    line.split_whitespace().nth(4)
}

/// 互联网上能路由到的地址。内网、回环、链路本地、运营商级 NAT（100.64/10）、
/// 测试网段（198.18/15，一些 VPN 用它做隧道内部地址）都不算。
fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            !(a.is_private()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_unspecified()
                || a.is_broadcast()
                || (o[0] == 100 && o[1] & 0xC0 == 64)
                || (o[0] == 198 && o[1] & 0xFE == 18))
        }
        IpAddr::V6(a) => {
            let s = a.segments()[0];
            !(a.is_loopback() || a.is_unspecified() || s & 0xFFC0 == 0xFE80 || s & 0xFE00 == 0xFC00)
        }
    }
}

/// 网页能不能靠 WebRTC 拿到代理之外的地址。
pub fn webrtc_summary(seen: &BrowserSeen, exit_ip: Option<&str>) -> (St, String) {
    if let Some(e) = &seen.webrtc_error {
        return (St::Skip, format!("检测页里建不了 WebRTC 连接，测不出：{e}"));
    }
    let mut public: Vec<IpAddr> = Vec::new();
    let mut private: Vec<IpAddr> = Vec::new();
    for ip in seen.candidates.iter().filter_map(|c| candidate_addr(c)?.parse::<IpAddr>().ok()) {
        if ip.is_loopback() || ip.is_unspecified() {
            continue;
        }
        let list = if is_public(ip) { &mut public } else { &mut private };
        if !list.contains(&ip) {
            list.push(ip);
        }
    }
    let show = |l: &[IpAddr]| l.iter().map(IpAddr::to_string).collect::<Vec<_>>().join("、");
    let exit = exit_ip.and_then(|s| s.trim().parse::<IpAddr>().ok());
    let other: Vec<IpAddr> = public.iter().copied().filter(|ip| Some(*ip) != exit).collect();
    if !other.is_empty() {
        return match exit {
            Some(e) => (St::Fail, format!("网页经 WebRTC 看到了公网地址 {}，不是出口 IP {e}：这个地址绕过了代理", show(&other))),
            None => (St::Warn, format!("网页经 WebRTC 看到了公网地址 {}；没有拿到出口 IP，没法判断是不是出口", show(&other))),
        };
    }
    if !public.is_empty() {
        return (
            St::Warn,
            "WebRTC 绕过代理发了 UDP，网页看到的正好是出口 IP：现在没有暴露别的地址，但承载流量的 VPN 一断开，看到的就是本机的真实地址".into(),
        );
    }
    if !private.is_empty() {
        return (St::Warn, format!("网页经 WebRTC 看到了内网地址 {}", show(&private)));
    }
    (St::Pass, format!("网页经 WebRTC 拿不到代理之外的地址（收集到 {} 个候选，里面没有 IP 地址）", seen.candidates.len()))
}

/// 网页读到的时区和出口所在的时区对不对得上。名称不同但此刻时间相同也算一致。
pub fn timezone_summary(seen: &BrowserSeen, exit_tz: Option<&str>, exit_offset_secs: Option<i64>) -> (St, String) {
    let Some(tz) = seen.timezone.as_deref() else {
        return (St::Skip, "检测页没有读到时区".into());
    };
    let Some(exit) = exit_tz.map(str::trim).filter(|s| !s.is_empty()) else {
        return (St::Info, format!("网页读到的时区是 {tz}（就是系统时区）；没有拿到出口时区，没法比较"));
    };
    if tz.eq_ignore_ascii_case(exit) {
        return (St::Pass, format!("网页读到的时区 {tz} 与出口一致"));
    }
    match (seen.offset_min, exit_offset_secs) {
        (Some(m), Some(s)) if m * 60 == s => (St::Pass, format!("网页读到的时区 {tz} 与出口时区 {exit} 名称不同，此刻时间相同")),
        _ => (St::Warn, format!("网页读到的时区是 {tz}（就是系统时区），出口在 {exit}：和出口位置对不上，改系统时区可以一致")),
    }
}

/// 网页和服务器读到的首选语言是不是配置里期望的那个。
pub fn language_summary(seen: &BrowserSeen, expect: &str) -> (St, String) {
    let js = seen.languages.first().map(String::as_str);
    let header = seen.accept_language.as_deref().and_then(|h| h.split(',').next()).map(|s| s.split(';').next().unwrap_or(s).trim());
    let (Some(js), Some(header)) = (js, header) else {
        return (St::Skip, "检测页没有读到语言".into());
    };
    if js.eq_ignore_ascii_case(expect) && header.eq_ignore_ascii_case(expect) {
        (St::Pass, format!("网页读到的首选语言和 Accept-Language 都是 {expect}"))
    } else {
        (St::Warn, format!("网页读到的首选语言是 {js}，Accept-Language 以 {header} 开头，配置期望 {expect}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IP: &str = "203.0.113.10";

    #[test]
    fn ip_type_is_parsed_from_each_database() {
        let t = parse_ip_type("ip-api", r#"{"status":"success","offset":-28800,"mobile":false,"proxy":true,"hosting":false}"#, IP).unwrap();
        assert_eq!(t.flags, ["代理或 VPN"]);
        assert_eq!(t.offset_secs, Some(-28800));
        let t = parse_ip_type("ip-api", r#"{"status":"success","offset":3600,"mobile":true,"proxy":false,"hosting":true}"#, IP).unwrap();
        assert_eq!(t.flags, ["机房"]);
        assert_eq!(t.kind.as_deref(), Some("移动网络"));
        let e = parse_ip_type("ip-api", r#"{"status":"fail","message":"reserved range"}"#, IP).unwrap_err();
        assert!(e.to_string().contains("reserved range"));

        let body = r#"{"ip":"203.0.113.10","isp":{"asn":"AS64500","org":"Example Transit"},"location":{"country_code":"US"},
            "risk":{"is_mobile":false,"is_vpn":false,"is_tor":false,"is_proxy":false,"is_datacenter":false,"risk_score":0}}"#;
        assert_eq!(parse_ip_type("ipquery", body, IP).unwrap(), IpType::default());
        let body = r#"{"risk":{"is_mobile":false,"is_vpn":true,"is_tor":false,"is_proxy":false,"is_datacenter":true,"risk_score":60}}"#;
        assert_eq!(parse_ip_type("ipquery", body, IP).unwrap().flags, ["VPN", "机房"]);
        assert!(parse_ip_type("ipquery", r#"{"ip":"203.0.113.10"}"#, IP).is_err());

        let body = r#"{"status":"ok","203.0.113.10":{"asn":"AS64500","provider":"Example Transit","isocode":"US","proxy":"no","type":"Business"}}"#;
        let t = parse_ip_type("proxycheck", body, IP).unwrap();
        assert!(t.flags.is_empty());
        assert_eq!(t.kind.as_deref(), Some("Business"));
        let body = r#"{"status":"ok","203.0.113.10":{"proxy":"yes","type":"VPN"}}"#;
        assert_eq!(parse_ip_type("proxycheck", body, IP).unwrap().flags, ["VPN"]);
        let body = r#"{"status":"ok","203.0.113.10":{"proxy":"no","type":"Hosting"}}"#;
        assert_eq!(parse_ip_type("proxycheck", body, IP).unwrap().flags, ["机房"]);
        let e = parse_ip_type("proxycheck", r#"{"status":"denied","message":"1,000 queries exceeded"}"#, IP).unwrap_err();
        assert!(e.to_string().contains("exceeded"));

        assert!(parse_ip_type("nope", "{}", IP).is_err());
    }

    fn typed(src: &str, flags: &[&'static str], kind: Option<&str>) -> Typed {
        (src.into(), Ok(IpType { flags: flags.to_vec(), kind: kind.map(str::to_string), offset_secs: None }))
    }

    #[test]
    fn ip_type_warns_only_when_most_databases_agree() {
        // 实测的情况：三个库里一个标成代理，说法不一，只作提示
        let r = [typed("ip-api", &["代理或 VPN"], None), typed("ipquery", &[], None), typed("proxycheck", &[], Some("Business"))];
        let (st, d) = ip_type_summary(&r);
        assert_eq!(st, St::Info);
        assert!(d.starts_with("3 个库里 1 个") && d.contains("ip-api：代理或 VPN") && d.contains("proxycheck：没有标记（Business）"), "{d}");

        let r = [typed("ip-api", &["机房"], None), typed("ipquery", &["VPN", "机房"], None), typed("proxycheck", &[], None)];
        assert_eq!(ip_type_summary(&r).0, St::Warn);

        let r = [typed("ip-api", &[], None), typed("ipquery", &[], None)];
        let (st, d) = ip_type_summary(&r);
        assert_eq!(st, St::Info);
        assert!(d.starts_with("2 个库都没有"), "{d}");

        // 没查到的库不算数；只剩一个库回答并且标了，就是多数
        let r = [typed("ip-api", &["机房"], None), ("ipquery".to_string(), Err("HTTP 429".to_string()))];
        let (st, d) = ip_type_summary(&r);
        assert_eq!(st, St::Warn);
        assert!(d.contains("ipquery：没查到（HTTP 429）"), "{d}");

        let r = [("ip-api".to_string(), Err("timeout".to_string()))];
        assert_eq!(ip_type_summary(&r).0, St::Skip);
    }

    #[test]
    fn exit_offset_comes_from_whichever_database_has_it() {
        let mut a = typed("ipquery", &[], None);
        assert_eq!(exit_offset_secs(&[a.clone()]), None);
        a.1.as_mut().unwrap().offset_secs = Some(-28800);
        assert_eq!(exit_offset_secs(&[("x".into(), Err("e".into())), a]), Some(-28800));
    }

    const BASHWS: &str = r#"[{"ip":"203.0.113.10","country":"us","country_name":"USA","asn":"AS64500 Example Transit","org":"Example Transit","type":"ip"},
        {"ip":"198.51.100.48","country":"us","country_name":"USA","asn":"AS64501 Example DNS Inc","org":"Example DNS Inc","type":"dns"},
        {"ip":"198.51.100.49","country":"us","country_name":"USA","asn":"AS64501 Example DNS Inc","org":"Example DNS Inc","type":"dns"},
        {"ip":"DNS may be leaking.","country":"","country_name":"","asn":"","org":"","type":"conclusion"}]"#;

    #[test]
    fn dns_leak_result_keeps_only_resolvers() {
        let r = parse_bashws(BASHWS).unwrap();
        assert_eq!(r.len(), 2, "出口自己和服务的结论不算解析服务器");
        assert_eq!(r[0], Resolver { ip: "198.51.100.48".into(), country: "US".into(), org: "Example DNS Inc".into() });
        assert!(parse_bashws("<html>").is_err());
        assert!(parse_bashws("[]").unwrap().is_empty());
    }

    #[test]
    fn dns_leak_is_judged_by_where_the_resolvers_are() {
        let r = parse_bashws(BASHWS).unwrap();
        let (st, d) = dns_leak_summary(&r, Some("us"));
        assert_eq!(st, St::Pass);
        assert!(d.contains("US Example DNS Inc ×2"), "{d}");

        // 出口在别的国家：列出来，标 WARN
        let (st, d) = dns_leak_summary(&r, Some("JP"));
        assert_eq!(st, St::Warn);
        assert!(d.contains("不在出口所在的 JP"), "{d}");

        // 本地运营商的解析服务器混在里面
        let mut leak = r.clone();
        leak.push(Resolver { ip: "192.0.2.5".into(), country: "CN".into(), org: "Example Broadband".into() });
        let (st, d) = dns_leak_summary(&leak, Some("US"));
        assert_eq!(st, St::Warn);
        assert!(d.contains("CN Example Broadband"), "{d}");

        assert_eq!(dns_leak_summary(&r, None).0, St::Info);
        assert_eq!(dns_leak_summary(&[], Some("US")).0, St::Skip);
    }

    fn seen(cands: &[&str]) -> BrowserSeen {
        BrowserSeen { candidates: cands.iter().map(|s| s.to_string()).collect(), ..Default::default() }
    }

    const HOST_MDNS: &str = "candidate:1883835080 1 udp 2113937151 0b3543c8-5776-4013-ae58-683c285a3c33.local 50247 typ host generation 0 ufrag qg+2 network-cost 999";

    fn srflx(ip: &str) -> String {
        format!("candidate:3817175137 1 udp 1677729535 {ip} 50247 typ srflx raddr 0.0.0.0 rport 0 generation 0 ufrag qg+2 network-cost 999")
    }

    #[test]
    fn browser_result_is_parsed() {
        let body = r#"{"tz":"America/Los_Angeles","offset":-480,"langs":["en-US","en"],"cands":["a","b"],"err":null}"#;
        let s = parse_seen(body, Some("en-US,en;q=0.9".into())).unwrap();
        assert_eq!(s.timezone.as_deref(), Some("America/Los_Angeles"));
        assert_eq!(s.offset_min, Some(-480));
        assert_eq!(s.languages, ["en-US", "en"]);
        assert_eq!(s.candidates.len(), 2);
        assert_eq!(s.webrtc_error, None);
        assert!(parse_seen("not json", None).is_err());
    }

    #[test]
    fn webrtc_verdicts() {
        // 策略生效：没有候选，或者只有遮住的 .local 地址
        assert_eq!(webrtc_summary(&seen(&[]), Some(IP)).0, St::Pass);
        assert_eq!(webrtc_summary(&seen(&[HOST_MDNS]), Some(IP)).0, St::Pass);

        // 实测到的情况（策略没生效，全量 VPN）：看到的公网地址正好是出口
        let (st, d) = webrtc_summary(&seen(&[HOST_MDNS, &srflx(IP)]), Some(IP));
        assert_eq!(st, St::Warn);
        assert!(d.contains("绕过代理"), "{d}");

        // 看到了不是出口的公网地址：泄露
        let (st, d) = webrtc_summary(&seen(&[&srflx("198.51.100.7")]), Some(IP));
        assert_eq!(st, St::Fail);
        assert!(d.contains("198.51.100.7") && d.contains(IP), "{d}");
        let (st, _) = webrtc_summary(&seen(&[&srflx("2001:db8::7")]), Some(IP));
        assert_eq!(st, St::Fail);
        assert_eq!(webrtc_summary(&seen(&[&srflx("198.51.100.7")]), None).0, St::Warn, "没有出口 IP 可比");

        // 内网地址、VPN 隧道的内部地址：提示，不算公网泄露
        let (st, d) = webrtc_summary(&seen(&[&srflx("192.168.1.20")]), Some(IP));
        assert_eq!(st, St::Warn);
        assert!(d.contains("内网地址 192.168.1.20"), "{d}");
        assert_eq!(webrtc_summary(&seen(&[&srflx("198.18.0.60"), &srflx("100.64.3.2")]), Some(IP)).0, St::Warn);

        let broken = BrowserSeen { webrtc_error: Some("NotSupportedError".into()), ..Default::default() };
        assert_eq!(webrtc_summary(&broken, Some(IP)).0, St::Skip);
    }

    #[test]
    fn browser_timezone_is_compared_with_the_exit() {
        let s = BrowserSeen { timezone: Some("America/Los_Angeles".into()), offset_min: Some(-480), ..Default::default() };
        assert_eq!(timezone_summary(&s, Some("America/Los_Angeles"), None).0, St::Pass);
        // 名称不同、此刻时间相同
        let (st, d) = timezone_summary(&s, Some("America/Vancouver"), Some(-28800));
        assert_eq!(st, St::Pass);
        assert!(d.contains("名称不同"), "{d}");
        // 对不上
        assert_eq!(timezone_summary(&s, Some("Asia/Tokyo"), Some(32400)).0, St::Warn);
        assert_eq!(timezone_summary(&s, Some("Asia/Tokyo"), None).0, St::Warn, "没有偏移可比时按名称判断");
        assert_eq!(timezone_summary(&s, None, None).0, St::Info);
        assert_eq!(timezone_summary(&BrowserSeen::default(), Some("Asia/Tokyo"), None).0, St::Skip);
    }

    #[test]
    fn browser_language_is_compared_with_the_config() {
        let s = BrowserSeen { languages: vec!["en-US".into(), "en".into()], accept_language: Some("en-US,en;q=0.9".into()), ..Default::default() };
        assert_eq!(language_summary(&s, "en-US").0, St::Pass);
        let (st, d) = language_summary(&s, "ja-JP");
        assert_eq!(st, St::Warn);
        assert!(d.contains("en-US") && d.contains("ja-JP"), "{d}");
        let s = BrowserSeen { languages: vec!["en-US".into()], accept_language: Some("zh-CN,zh;q=0.9".into()), ..Default::default() };
        assert_eq!(language_summary(&s, "en-US").0, St::Warn, "请求头和网页读到的不一样");
        assert_eq!(language_summary(&BrowserSeen::default(), "en-US").0, St::Skip);
    }

    #[test]
    fn the_check_page_server_returns_what_the_page_posts() {
        use std::io::{Read, Write};
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let client = std::thread::spawn(move || {
            let send = |req: &str| {
                let mut s = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
                s.write_all(req.as_bytes()).unwrap();
                let mut out = String::new();
                let _ = s.read_to_string(&mut out);
                out
            };
            let page = send("GET / HTTP/1.1\r\nHost: x\r\nAccept-Language: en-US,en;q=0.9\r\n\r\n");
            assert!(page.starts_with("HTTP/1.1 200") && page.contains("RTCPeerConnection"));
            assert!(send("GET /favicon.ico HTTP/1.1\r\nHost: x\r\n\r\n").starts_with("HTTP/1.1 404"));
            let body = r#"{"tz":"UTC","offset":0,"langs":["en-US"],"cands":[],"err":null}"#;
            send(&format!("POST /result HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}", body.len()));
        });
        let (body, al) = serve(&listener, Instant::now() + Duration::from_secs(10)).unwrap();
        client.join().unwrap();
        assert_eq!(al.as_deref(), Some("en-US,en;q=0.9"));
        assert_eq!(parse_seen(&body, al).unwrap().timezone.as_deref(), Some("UTC"));

        // 没人交结果：到点报错，不一直等
        let e = serve(&listener, Instant::now()).unwrap_err();
        assert!(e.to_string().contains("没有交回结果"));
    }
}
