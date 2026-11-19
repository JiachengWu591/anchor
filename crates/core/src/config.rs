//! 配置模型（anchor.toml）与数据目录。

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::path::PathBuf;

use crate::net::ExitInfo;

/// 数据目录布局。
pub struct Paths {
    pub home: PathBuf,
}

impl Paths {
    pub fn resolve(cli: Option<PathBuf>) -> Result<Self> {
        let home = match cli.or_else(|| std::env::var_os("ANCHOR_HOME").map(PathBuf::from)) {
            Some(p) => p,
            None => {
                let base = std::env::var_os("LOCALAPPDATA").context("找不到 LOCALAPPDATA 环境变量")?;
                PathBuf::from(base).join("AIAnchor")
            }
        };
        let home = if home.is_relative() { std::env::current_dir()?.join(home) } else { home };
        Ok(Self { home })
    }
    pub fn config(&self) -> PathBuf { self.home.join("anchor.toml") }
    pub fn run_dir(&self) -> PathBuf { self.home.join("run") }
    pub fn singbox_json(&self) -> PathBuf { self.run_dir().join("sing-box.json") }
    pub fn pid_file(&self) -> PathBuf { self.run_dir().join("core.pid") }
    pub fn log_dir(&self) -> PathBuf { self.home.join("logs") }
    pub fn bin_dir(&self) -> PathBuf { self.home.join("bin") }
    pub fn browser_profile(&self, name: &str) -> PathBuf { self.home.join("browser").join(name) }
    pub fn timeline_db(&self) -> PathBuf { self.home.join("timeline.db") }
    /// anchor exit use 选用的备用出口名；用主出口时没有这个文件
    pub fn active_exit(&self) -> PathBuf { self.home.join("exit.active") }
    /// anchor line pin 固定的线路名（重启后仍然有效）
    pub fn line_pin(&self) -> PathBuf { self.home.join("line.pin") }
    pub fn agent_log(&self) -> PathBuf { self.log_dir().join("agent.log") }
}

/// 一个 sing-box 出站：除 name 外的字段原样透传给 sing-box。
#[derive(Debug, Clone, Deserialize)]
pub struct Node {
    #[serde(default)]
    pub name: Option<String>,
    /// 只对线路有意义：评分接近时优先用数字小的（例如按流量成本排）。不传给 sing-box。
    #[serde(default)]
    pub priority: Option<u32>,
    /// 只对备用出口有意义：这个出口自己的基线（anchor baseline 在用它时填写）。主出口的基线在 [expect]。不传给 sing-box。
    #[serde(default)]
    pub expect: Option<Expect>,
    #[serde(flatten)]
    pub outbound: Map<String, Value>,
}

impl Node {
    pub fn kind(&self) -> Option<&str> { self.outbound.get("type").and_then(Value::as_str) }
    pub fn server(&self) -> Option<&str> { self.outbound.get("server").and_then(Value::as_str) }
    pub fn port(&self) -> Option<u16> {
        self.outbound.get("server_port").and_then(Value::as_u64).and_then(|p| u16::try_from(p).ok())
    }
    pub fn label(&self) -> String {
        let name = self.name.as_deref().unwrap_or("未命名");
        match (self.kind(), self.server(), self.port()) {
            (Some(k), Some(s), Some(p)) => format!("{name}（{k} {}）", host_port(s, p)),
            (Some(k), _, _) => format!("{name}（{k}）"),
            _ => name.to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LineMode { Auto, Manual }

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyCfg { pub listen: String, pub port: u16 }
impl Default for ProxyCfg {
    fn default() -> Self { Self { listen: "127.0.0.1".into(), port: 17890 } }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Expect { pub ip: String, pub language: String, pub timezone: String, pub country: String }
impl Default for Expect {
    fn default() -> Self { Self { ip: String::new(), language: "en-US".into(), timezone: String::new(), country: String::new() } }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SwitchCfg {
    pub lines: LineMode,
    pub keep_existing_conns: bool,
    pub probe_url: String,
    pub probe_interval: String,
    pub tolerance_ms: u32,
    /// 线路看门狗的探测间隔；"0s" 或空表示关闭
    pub watch_interval: String,
    /// 出口 IP 定时核对的间隔（网络变化、内核启动时另外立即核对）
    pub exit_check_interval: String,
}
impl Default for SwitchCfg {
    fn default() -> Self {
        Self {
            lines: LineMode::Auto,
            keep_existing_conns: true,
            probe_url: "https://www.gstatic.com/generate_204".into(),
            probe_interval: "30s".into(),
            tolerance_ms: 50,
            watch_interval: "3s".into(),
            exit_check_interval: "60s".into(),
        }
    }
}
impl SwitchCfg {
    /// 出口定时核对间隔，至少 5 秒。
    pub fn exit_check_every(&self) -> std::time::Duration {
        humantime::parse_duration(self.exit_check_interval.trim())
            .unwrap_or(std::time::Duration::from_secs(60))
            .max(std::time::Duration::from_secs(5))
    }

    /// 看门狗间隔；None 表示关闭。
    pub fn watch_every(&self) -> Option<std::time::Duration> {
        let s = self.watch_interval.trim();
        if s.is_empty() {
            return None;
        }
        humantime::parse_duration(s).ok().filter(|d| !d.is_zero())
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AppsCfg { pub desktop: Vec<String>, pub cli: Vec<String> }
impl Default for AppsCfg {
    fn default() -> Self {
        Self {
            desktop: vec!["claude-desktop".into(), "chatgpt-desktop".into(), "cursor".into()],
            cli: vec!["claude".into(), "codex".into()],
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BrowserCfg { pub engine: String, pub path: String, pub profile: String, pub start_url: String }
impl Default for BrowserCfg {
    fn default() -> Self {
        Self { engine: "edge".into(), path: String::new(), profile: "ai-anchor".into(), start_url: "https://claude.ai".into() }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GuardCfg { pub allow_fakeip: bool, pub fakeip_range: String, pub extra_programs: Vec<String> }
impl Default for GuardCfg {
    fn default() -> Self { Self { allow_fakeip: false, fakeip_range: "198.18.0.0/15".into(), extra_programs: vec![] } }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CoreCfg { pub path: String, pub log_level: String, pub api_port: u16, pub api_secret: String, pub probe_port: u16 }
impl Default for CoreCfg {
    fn default() -> Self {
        Self { path: String::new(), log_level: "info".into(), api_port: 0, api_secret: String::new(), probe_port: 0 }
    }
}

/// 域名解析。只对 type = "direct" 的出口起作用：这种出口由 sing-box 在本机解析目标域名，
/// 默认的“系统 DNS”可能取到别的网卡的 DNS，让 AI 域名的查询绕过 VPN、明文发到本地网络。
/// 代理型出口（socks、shadowsocks……）把域名交给出口服务器解析，不经本机 DNS。
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsCfg {
    /// 经出口发出的加密 DNS（DoH）服务器 IP。用 IP 免得为了找 DNS 服务器先查一次 DNS
    pub exit_doh: String,
}
impl Default for DnsCfg {
    fn default() -> Self { Self { exit_doh: "1.1.1.1".into() } }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CheckCfg {
    pub local_url: String,
    pub ip_info: String,
    pub ip_echo: Vec<String>,
    /// 判断出口 IP 类型时问哪些数据库（ip-api、ipquery、proxycheck）；空列表表示不问
    pub ip_type: Vec<String>,
    /// anchor check 是否实测 DNS 泄露（经通道解析检测服务的一次性域名）
    pub dns_leak: bool,
    /// anchor check 是否在无头的 AI 专用浏览器里检测 WebRTC、时区和语言
    pub browser: bool,
}
impl Default for CheckCfg {
    fn default() -> Self {
        Self {
            local_url: "http://www.msftconnecttest.com/connecttest.txt".into(),
            ip_info: "https://ipinfo.io/json".into(),
            ip_echo: vec!["https://api.ipify.org".into(), "https://ifconfig.me/ip".into()],
            ip_type: vec!["ip-api".into(), "ipquery".into(), "proxycheck".into()],
            dns_leak: true,
            browser: true,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub proxy: ProxyCfg,
    pub exit: Node,
    #[serde(default)]
    pub backup_exits: Vec<Node>,
    #[serde(default)]
    pub lines: Vec<Node>,
    #[serde(default)]
    pub expect: Expect,
    #[serde(default)]
    pub switch: SwitchCfg,
    #[serde(default)]
    pub apps: AppsCfg,
    #[serde(default)]
    pub browser: BrowserCfg,
    #[serde(default)]
    pub guard: GuardCfg,
    #[serde(default)]
    pub core: CoreCfg,
    #[serde(default)]
    pub check: CheckCfg,
    #[serde(default)]
    pub dns: DnsCfg,
    /// 配置里的所有出口（主出口在前），以及现在用的是哪个。由 select_exit 填写
    #[serde(skip)]
    pub exits: Vec<ExitEntry>,
    /// 现在用的是第几个备用出口（从 0 数）；用主出口时为 None
    #[serde(skip)]
    pub active_backup: Option<usize>,
}

/// anchor exit list 的一行。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitEntry {
    pub name: String,
    pub label: String,
    /// 登记的基线 IP；还没登记时为空
    pub baseline_ip: String,
    pub active: bool,
    pub primary: bool,
}

/// 主出口没写 name 时的称呼
pub const MAIN_EXIT: &str = "main";

/// sing-box 配置里由 AI Anchor 占用的出站名。
const RESERVED: &[&str] = &["exit", "lines", "direct", "ai-in", "probe-in"];

impl Config {
    /// 读取配置，并按 anchor exit use 的选择决定用哪个出口。
    pub fn load(paths: &Paths) -> Result<Self> {
        let p = paths.config();
        let text = std::fs::read_to_string(&p)
            .with_context(|| format!("读取配置失败：{}（还没有配置？先运行 anchor init）", p.display()))?;
        let mut cfg = Self::parse(&text).with_context(|| format!("配置有误：{}", p.display()))?;
        if let Ok(want) = std::fs::read_to_string(paths.active_exit()) {
            cfg.select_exit(Some(want.trim()))?;
        }
        Ok(cfg)
    }

    pub fn parse(text: &str) -> Result<Self> {
        // 记事本“UTF-8 带 BOM”、PowerShell 5 的 Set-Content -Encoding utf8 都会在开头写 BOM
        let mut cfg: Config = toml::from_str(text.trim_start_matches('\u{feff}'))?;
        cfg.validate()?;
        cfg.select_exit(None)?;
        Ok(cfg)
    }

    /// 主出口的名字（没写 name 时叫 main）
    pub fn main_exit_name(&self) -> String {
        match self.active_backup {
            None => self.exit.name.clone(),
            Some(_) => self.exits.first().map(|e| e.name.clone()),
        }
        .filter(|n| !n.trim().is_empty())
        .unwrap_or_else(|| MAIN_EXIT.to_string())
    }

    /// 现在用的出口的名字
    pub fn exit_name(&self) -> String {
        self.exits.iter().find(|e| e.active).map(|e| e.name.clone()).unwrap_or_else(|| MAIN_EXIT.to_string())
    }

    /// 选用名为 want 的出口（None、空或主出口的名字：用主出口）。选了备用出口后，exit 和 expect
    /// 就是它的出站和它自己的基线，其余代码不用区分。只能在刚解析完的配置上调用。
    pub fn select_exit(&mut self, want: Option<&str>) -> Result<()> {
        let main = self.main_exit_name();
        let want = want.map(str::trim).filter(|w| !w.is_empty() && *w != main);
        let mut entries = vec![ExitEntry {
            name: main,
            label: self.exit.label(),
            baseline_ip: self.expect.ip.trim().to_string(),
            active: want.is_none(),
            primary: true,
        }];
        for b in &self.backup_exits {
            let name = b.name.clone().unwrap_or_default();
            entries.push(ExitEntry {
                active: want == Some(name.as_str()),
                label: b.label(),
                baseline_ip: b.expect.as_ref().map(|e| e.ip.trim().to_string()).unwrap_or_default(),
                primary: false,
                name,
            });
        }
        if let Some(w) = want {
            let Some(i) = self.backup_exits.iter().position(|b| b.name.as_deref() == Some(w)) else {
                let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
                bail!("现在选用的出口 {w} 不在 anchor.toml 里（有：{}）。运行 anchor exit use <名称> 重新选一个", names.join("、"));
            };
            let b = self.backup_exits[i].clone();
            // 语言跟主出口一致，除非这个出口自己写了
            self.expect = b.expect.clone().unwrap_or_else(|| Expect { language: self.expect.language.clone(), ..Expect::default() });
            self.exit = Node { expect: None, ..b };
            self.active_backup = Some(i);
        }
        self.exits = entries;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        check_node("[exit]", &self.exit)?;
        let main = self.exit.name.as_deref().map(str::trim).filter(|n| !n.is_empty()).unwrap_or(MAIN_EXIT);
        let mut exit_names = HashSet::from([main.to_string()]);
        for (i, b) in self.backup_exits.iter().enumerate() {
            check_node(&format!("第 {} 个备用出口", i + 1), b)?;
            let name = b.name.as_deref().unwrap_or("").trim();
            if name.is_empty() {
                bail!("第 {} 个备用出口缺少 name（anchor exit use 按名字选出口）", i + 1);
            }
            if !exit_names.insert(name.to_string()) {
                bail!("出口名重复：{name}");
            }
        }
        let mut seen = HashSet::new();
        for (i, l) in self.lines.iter().enumerate() {
            let name = l.name.as_deref().unwrap_or("").trim();
            if name.is_empty() {
                bail!("第 {} 条线路缺少 name", i + 1);
            }
            if RESERVED.contains(&name) {
                bail!("线路名 {name} 是保留名，请换一个");
            }
            if !seen.insert(name.to_string()) {
                bail!("线路名重复：{name}");
            }
            check_node(&format!("线路 {name}"), l)?;
        }
        if self.proxy.port == 0 {
            bail!("[proxy] port 不能为 0");
        }
        let (ai, api, probe) = (self.proxy.port, self.api_port(), self.probe_port());
        if ai == api || ai == probe || api == probe {
            bail!("AI 代理端口 {ai}、Clash API 端口 {api}、探测端口 {probe} 不能相同（[proxy] port、[core] api_port、[core] probe_port）");
        }
        // http:// 也可以（省掉 TLS 握手）：发给内核时由 net::ClashApi 处理它对 http:// 的特殊对待
        let probe = self.switch.probe_url.trim();
        if !(probe.starts_with("https://") || probe.starts_with("http://")) {
            bail!("[switch] probe_url 必须是 http:// 或 https:// 地址：{}", self.switch.probe_url);
        }
        if self.dns.exit_doh.trim().parse::<std::net::IpAddr>().is_err() {
            bail!("[dns] exit_doh 必须是 IP 地址（例如 \"1.1.1.1\"）：{}", self.dns.exit_doh);
        }
        let e = self.switch.exit_check_interval.trim();
        humantime::parse_duration(e).with_context(|| format!("[switch] exit_check_interval 格式错误：{e}（例如 \"60s\"）"))?;
        let w = self.switch.watch_interval.trim();
        if !w.is_empty() {
            let d = humantime::parse_duration(w).with_context(|| format!("[switch] watch_interval 格式错误：{w}（例如 \"3s\"，\"0s\" 表示关闭）"))?;
            if !d.is_zero() && d < std::time::Duration::from_secs(1) {
                bail!("[switch] watch_interval 至少 1s（\"0s\" 表示关闭）");
            }
        }
        if !matches!(self.browser.engine.as_str(), "edge" | "chrome") {
            bail!("[browser] engine 只能是 edge 或 chrome");
        }
        crate::guard::parse_cidr(&self.guard.fakeip_range).context("[guard] fakeip_range 格式错误")?;
        Ok(())
    }

    pub fn api_port(&self) -> u16 {
        if self.core.api_port != 0 { self.core.api_port } else { self.proxy.port.wrapping_add(1) }
    }

    /// 探测专用入站的端口：用户代理和命令行核对出口走它，AI 通道锁住时也能用。
    pub fn probe_port(&self) -> u16 {
        if self.core.probe_port != 0 { self.core.probe_port } else { self.proxy.port.wrapping_add(2) }
    }

    /// 探测入站的账号密码。密码由 api_secret 派生，只含十六进制字符，可直接放进代理地址。
    pub fn probe_auth(&self) -> (String, String) {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in "ai-anchor-probe:".bytes().chain(self.core.api_secret.bytes()) {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        ("anchor".into(), format!("{h:016x}"))
    }

    /// 经探测入站联网的代理地址（带认证）。用 SOCKS5：ureq 经 HTTP 代理访问 http:// 地址时
    /// 不发 Proxy-Authorization（只有 CONNECT 才带），SOCKS5 对两种地址都会先认证。
    pub fn probe_proxy_url(&self) -> String {
        let (user, pass) = self.probe_auth();
        format!("socks5://{user}:{pass}@{}", host_port("127.0.0.1", self.probe_port()))
    }

    /// AI 程序使用的代理地址（HTTP CONNECT，同端口也接受 SOCKS5）。
    pub fn proxy_url(&self) -> String {
        format!("http://{}", host_port(&self.proxy.listen, self.proxy.port))
    }

    pub fn line_names(&self) -> Vec<&str> {
        self.lines.iter().map(|l| l.name.as_deref().unwrap_or_default()).collect()
    }
}

fn check_node(what: &str, n: &Node) -> Result<()> {
    if n.kind().is_none() {
        bail!("{what} 缺少 type 字段（sing-box 出站类型，如 socks、shadowsocks、vless、trojan）");
    }
    for k in ["tag", "detour"] {
        if n.outbound.contains_key(k) {
            bail!("{what} 里不要写 {k}，由 AI Anchor 自动填写");
        }
    }
    Ok(())
}

pub fn host_port(host: &str, port: u16) -> String {
    if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") }
}

/// 把测得的出口信息登记为现在所用出口的基线，保留文件里的注释和格式。
/// 用主出口时写 [expect]；用备用出口时写它那一项 [[backup_exits]] 里的 expect。
pub fn set_expect(paths: &Paths, info: &ExitInfo) -> Result<()> {
    let active_backup = Config::load(paths)?.active_backup;
    let p = paths.config();
    let text = std::fs::read_to_string(&p)?;
    let mut doc: toml_edit::DocumentMut = text.trim_start_matches('\u{feff}').parse().context("解析 anchor.toml 失败")?;
    let mut fields = vec![("ip", info.ip.clone())];
    if let Some(tz) = &info.timezone {
        fields.push(("timezone", tz.clone()));
    }
    if let Some(c) = &info.country {
        fields.push(("country", c.clone()));
    }
    match active_backup {
        None => {
            for (k, v) in fields {
                doc["expect"][k] = toml_edit::value(v);
            }
        }
        Some(i) => {
            let table = doc
                .get_mut("backup_exits")
                .and_then(|x| x.as_array_of_tables_mut())
                .and_then(|a| a.get_mut(i))
                .context("anchor.toml 里的备用出口要写成 [[backup_exits]] 的形式，才能登记它的基线")?;
            match table.get_mut("expect").and_then(|e| e.as_table_like_mut()) {
                Some(t) => {
                    for (k, v) in fields {
                        t.insert(k, toml_edit::value(v));
                    }
                }
                None => {
                    let mut t = toml_edit::InlineTable::new();
                    for (k, v) in fields {
                        t.insert(k, v.into());
                    }
                    table.insert("expect", toml_edit::Item::Value(toml_edit::Value::InlineTable(t)));
                }
            }
        }
    }
    std::fs::write(&p, doc.to_string())?;
    Ok(())
}

pub fn example(secret: &str) -> String {
    EXAMPLE.replace("__SECRET__", secret)
}

const EXAMPLE: &str = r#"# AI Anchor 配置（P0 原型）
# 修改后运行 `anchor gen` 检查，再重启 `anchor up` 生效。

[proxy]
# AI 程序连接的本机代理端口（同一端口支持 HTTP 和 SOCKS5），只监听回环地址。
listen = "127.0.0.1"
port = 17890

# 固定出口：AI 服务看到的就是它的 IP。
# 字段与 sing-box 出站配置一致，原样透传；tag 和 detour 由 AI Anchor 填写。
# 下面是占位示例，请换成你自己的出口。
[exit]
name = "my-exit"
type = "socks"
server = "203.0.113.10"
server_port = 1080
version = "5"
# username = "user"
# password = "pass"

# 线路层：只负责把流量送到出口。可以写多条，切换线路不会改变出口 IP。
# 一条线路都不写时，直接连接出口（经系统路由，开着 VPN 时就是经 VPN）。
# 如果本机 VPN 本身就能稳定出境，可以不写线路，少一层故障点。
[[lines]]
name = "line-a"
# 评分接近时优先用数字小的线路（例如按流量成本排）；不写的排在写了的后面
# priority = 1
type = "shadowsocks"
server = "198.51.100.20"
server_port = 8388
method = "2022-blake3-aes-128-gcm"
# 换成线路提供方给的密钥。2022 系列方法要求 16 字节的 base64 密钥（sing-box generate rand 16 --base64）
password = "AAAAAAAAAAAAAAAAAAAAAA=="

# [[lines]]
# name = "line-b"
# type = "trojan"
# server = "line-b.example.com"
# server_port = 443
# password = "请替换"
# tls = { enabled = true, server_name = "line-b.example.com" }

# 备用出口：只在你运行 anchor exit use <名称> 时启用，不会自动切换（换出口就是换 IP）。
# 每个出口有自己的基线：切过去后运行 anchor baseline，会登记在这一项的 expect 里。
# [[backup_exits]]
# name = "backup"
# type = "socks"
# server = "203.0.113.11"
# server_port = 1080

[expect]
# 出口基线。`anchor baseline` 会自动填写 ip、timezone、country。
ip = ""
language = "en-US"
timezone = ""
country = ""

[switch]
lines = "auto"               # auto：线路控制器按规则换线；manual：不自动换，用 anchor line use 手动换
keep_existing_conns = true   # 切换线路时不打断已建立的连接
# 测速地址：线路探测和整条链路探测都请求它。http:// 地址也可以（省掉 TLS 握手）
probe_url = "https://www.gstatic.com/generate_204"
probe_interval = "30s"       # 当前线路以外的线路多久探测一次
tolerance_ms = 50            # 只在前台调试的 anchor up 里起作用（urltest 的容差）
# 当前线路的探测间隔（有 AI 连接时；空闲时 15 秒一次）。探测失败就立刻把所有线路测一遍并换线。"0s" 关闭定时探测
watch_interval = "3s"
# 出口 IP 定时核对（至少 5 秒）。网络变化、内核启动时会先锁住 AI 通道并立即核对，与基线一致才放行
exit_check_interval = "60s"

[apps]
# 纳入 AI Anchor 的程序，名称见 `anchor scan`。
desktop = ["claude-desktop", "chatgpt-desktop", "cursor"]
cli = ["claude", "codex"]

[browser]
engine = "edge"              # edge 或 chrome
path = ""                    # 留空自动查找
profile = "ai-anchor"
start_url = "https://claude.ai"

[guard]
# 守卫只放行本机回环地址（127.0.0.0/8、::1）：AI 程序只能连 AI Anchor 的本机端口。
# allow_fakeip 只在启用 AI Anchor 自己的 TUN 兜底（P1）时打开。
# 本机的 VPN 或其他代理的 TUN 常占用 198.18.0.0/15 一带；重叠时 anchor guard 会拒绝执行。
allow_fakeip = false
fakeip_range = "198.18.0.0/15"
# 额外需要守卫的程序完整路径，例如 'C:\Tools\some-ai-cli.exe'
extra_programs = []

[dns]
# 只对 type = "direct" 的出口起作用：目标域名经出口用加密 DNS（DoH）解析，查询不经本地网络。
# 代理型出口（socks、shadowsocks……）由出口服务器解析域名，不受这项影响。
exit_doh = "1.1.1.1"

[core]
# sing-box.exe 路径；留空时依次查找 <数据目录>\bin、anchor.exe 同目录、PATH。
path = ""
log_level = "info"
api_port = 0                 # 0 表示代理端口 + 1
api_secret = "__SECRET__"
probe_port = 0               # 探测专用入站（带认证，核对出口用）；0 表示代理端口 + 2
"#;

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: &str = "[exit]\ntype = \"socks\"\nserver = \"203.0.113.10\"\nserver_port = 1080\n";

    #[test]
    fn example_config_is_valid() {
        let cfg = Config::parse(&example("abc")).unwrap();
        assert_eq!(cfg.proxy.port, 17890);
        assert_eq!(cfg.api_port(), 17891);
        assert_eq!(cfg.lines.len(), 1);
        assert_eq!(cfg.exit.kind(), Some("socks"));
        assert!(!cfg.exit.outbound.contains_key("name"));
        assert_eq!(cfg.core.api_secret, "abc");
        assert!(!cfg.guard.allow_fakeip, "FakeIP 段默认不放行");
    }

    #[test]
    fn minimal_config_uses_defaults() {
        let cfg = Config::parse(MIN).unwrap();
        assert_eq!(cfg.proxy_url(), "http://127.0.0.1:17890");
        assert_eq!(cfg.switch.lines, LineMode::Auto);
        assert!(cfg.lines.is_empty());
    }

    #[test]
    fn rejects_reserved_and_duplicate_line_names() {
        let reserved = format!("{MIN}[[lines]]\nname = \"exit\"\ntype = \"socks\"\n");
        assert!(Config::parse(&reserved).is_err());
        let dup = format!("{MIN}[[lines]]\nname = \"a\"\ntype = \"socks\"\n[[lines]]\nname = \"a\"\ntype = \"socks\"\n");
        assert!(Config::parse(&dup).is_err());
    }

    #[test]
    fn rejects_tag_and_detour_in_nodes() {
        assert!(Config::parse(&format!("{MIN}detour = \"x\"\n")).is_err());
        assert!(Config::parse("[exit]\nserver = \"1.2.3.4\"\n").is_err());
    }

    #[test]
    fn set_expect_keeps_comments_and_fills_baseline() {
        let home = std::env::temp_dir().join(format!("anchor-test-{}", crate::util::random_hex()));
        std::fs::create_dir_all(&home).unwrap();
        let paths = Paths { home: home.clone() };
        std::fs::write(paths.config(), example("s")).unwrap();
        let info = ExitInfo {
            ip: "203.0.113.10".into(),
            country: Some("US".into()),
            region: None,
            city: None,
            timezone: Some("America/Los_Angeles".into()),
            org: None,
            source: "test".into(),
        };
        set_expect(&paths, &info).unwrap();
        let text = std::fs::read_to_string(paths.config()).unwrap();
        let cfg = Config::parse(&text).unwrap();
        assert_eq!(cfg.expect.ip, "203.0.113.10");
        assert_eq!(cfg.expect.timezone, "America/Los_Angeles");
        assert_eq!(cfg.expect.country, "US");
        assert!(text.contains("# 固定出口：AI 服务看到的就是它的 IP。"));
        std::fs::remove_dir_all(home).unwrap();
    }

    const WITH_BACKUPS: &str = "[exit]\nname = \"home\"\ntype = \"socks\"\nserver = \"203.0.113.10\"\nserver_port = 1080\n\n\
        [expect]\nip = \"203.0.113.10\"\nlanguage = \"en-GB\"\n\n\
        # 第一个备用\n[[backup_exits]]\nname = \"b1\"\ntype = \"socks\"\nserver = \"203.0.113.11\"\nserver_port = 1080\n\n\
        [[backup_exits]]\nname = \"b2\"\ntype = \"socks\"\nserver = \"203.0.113.12\"\nserver_port = 1080\nexpect = { ip = \"203.0.113.12\" }\n";

    #[test]
    fn backup_exit_is_used_only_when_selected_and_has_its_own_baseline() {
        let cfg = Config::parse(WITH_BACKUPS).unwrap();
        assert_eq!((cfg.exit_name().as_str(), cfg.active_backup), ("home", None));
        assert_eq!(cfg.exits.iter().map(|e| (e.name.as_str(), e.baseline_ip.as_str(), e.active)).collect::<Vec<_>>(), [
            ("home", "203.0.113.10", true),
            ("b1", "", false),
            ("b2", "203.0.113.12", false),
        ]);

        let mut b2 = Config::parse(WITH_BACKUPS).unwrap();
        b2.select_exit(Some("b2")).unwrap();
        assert_eq!(b2.exit.server(), Some("203.0.113.12"));
        assert_eq!(b2.expect.ip, "203.0.113.12", "按这个出口自己的基线核对");
        assert_eq!((b2.exit_name().as_str(), b2.main_exit_name().as_str(), b2.active_backup), ("b2", "home", Some(1)));
        assert!(b2.exit.expect.is_none() && !b2.exit.outbound.contains_key("expect"), "expect 不传给内核");

        // 还没登记基线的备用出口：基线为空（AI 通道保持锁住，直到 anchor baseline），语言沿用主出口
        let mut b1 = Config::parse(WITH_BACKUPS).unwrap();
        b1.select_exit(Some("b1")).unwrap();
        assert_eq!((b1.expect.ip.as_str(), b1.expect.language.as_str()), ("", "en-GB"));

        // 选主出口的名字、空：都是主出口；选不存在的：报错，不悄悄换回主出口
        let mut main = Config::parse(WITH_BACKUPS).unwrap();
        main.select_exit(Some("home")).unwrap();
        assert_eq!(main.active_backup, None);
        assert!(Config::parse(WITH_BACKUPS).unwrap().select_exit(Some("gone")).is_err());
    }

    #[test]
    fn backup_exits_need_unique_names() {
        let unnamed = format!("{MIN}[[backup_exits]]\ntype = \"socks\"\n");
        assert!(Config::parse(&unnamed).is_err());
        let dup = format!("{MIN}[[backup_exits]]\nname = \"main\"\ntype = \"socks\"\n");
        assert!(Config::parse(&dup).is_err(), "和主出口（没写名字时叫 main）重名");
    }

    #[test]
    fn baseline_is_registered_on_the_exit_in_use() {
        let home = std::env::temp_dir().join(format!("anchor-test-{}", crate::util::random_hex()));
        std::fs::create_dir_all(&home).unwrap();
        let paths = Paths { home: home.clone() };
        std::fs::write(paths.config(), WITH_BACKUPS).unwrap();
        std::fs::write(paths.active_exit(), "b1\n").unwrap();
        let info = |ip: &str| ExitInfo { ip: ip.into(), country: Some("JP".into()), region: None, city: None, timezone: None, org: None, source: "test".into() };
        set_expect(&paths, &info("198.51.100.5")).unwrap();
        let text = std::fs::read_to_string(paths.config()).unwrap();
        assert!(text.contains("# 第一个备用"), "注释保留");
        let cfg = Config::load(&paths).unwrap();
        assert_eq!((cfg.exit_name().as_str(), cfg.expect.ip.as_str(), cfg.expect.country.as_str()), ("b1", "198.51.100.5", "JP"));
        assert_eq!(cfg.exits[0].baseline_ip, "203.0.113.10", "主出口的基线没动");
        assert_eq!(cfg.exits[2].baseline_ip, "203.0.113.12", "另一个备用出口的基线没动");
        // 已经有 expect 的那一项：改它里面的字段
        std::fs::write(paths.active_exit(), "b2").unwrap();
        set_expect(&paths, &info("198.51.100.6")).unwrap();
        assert_eq!(Config::load(&paths).unwrap().expect.ip, "198.51.100.6");
        // 回到主出口：写 [expect]
        std::fs::remove_file(paths.active_exit()).unwrap();
        set_expect(&paths, &info("198.51.100.7")).unwrap();
        let cfg = Config::load(&paths).unwrap();
        assert_eq!((cfg.expect.ip.as_str(), cfg.exits[1].baseline_ip.as_str()), ("198.51.100.7", "198.51.100.5"));
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn watch_interval_parsing() {
        let cfg = Config::parse(MIN).unwrap();
        assert_eq!(cfg.switch.watch_every(), Some(std::time::Duration::from_secs(3)));
        let off = Config::parse(&format!("{MIN}[switch]\nwatch_interval = \"0s\"\n")).unwrap();
        assert_eq!(off.switch.watch_every(), None);
        assert!(Config::parse(&format!("{MIN}[switch]\nwatch_interval = \"500ms\"\n")).is_err());
        assert!(Config::parse(&format!("{MIN}[switch]\nwatch_interval = \"fast\"\n")).is_err());
    }

    #[test]
    fn accepts_utf8_bom() {
        assert!(Config::parse(&format!("\u{feff}{MIN}")).is_ok());
    }

    #[test]
    fn probe_port_and_auth() {
        let cfg = Config::parse(&format!("{MIN}[core]\napi_secret = \"x\"\n")).unwrap();
        assert_eq!(cfg.probe_port(), 17892);
        let url = cfg.probe_proxy_url();
        assert!(url.starts_with("socks5://anchor:") && url.ends_with("@127.0.0.1:17892"), "{url}");
        let other = Config::parse(&format!("{MIN}[core]\napi_secret = \"y\"\n")).unwrap();
        assert_ne!(cfg.probe_auth().1, other.probe_auth().1, "密码随 api_secret 变化");
        assert!(Config::parse(&format!("{MIN}[core]\nprobe_port = 17890\n")).is_err(), "与 AI 端口冲突");
        assert!(Config::parse(&format!("{MIN}[switch]\nexit_check_interval = \"soon\"\n")).is_err());
        assert!(Config::parse(&format!("{MIN}[switch]\nprobe_url = \"http://x/204\"\n")).is_ok(), "http 测速地址也可以");
        assert!(Config::parse(&format!("{MIN}[switch]\nprobe_url = \"x/204\"\n")).is_err(), "测速地址要带协议");
        assert!(Config::parse(&format!("{MIN}[dns]\nexit_doh = \"dns.google\"\n")).is_err(), "DoH 服务器要写 IP");
        assert_eq!(Config::parse(MIN).unwrap().dns.exit_doh, "1.1.1.1");
    }

    #[test]
    fn rejects_unknown_sections() {
        assert!(Config::parse(&format!("{MIN}[typo]\na = 1\n")).is_err());
    }
}
