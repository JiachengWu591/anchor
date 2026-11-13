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
}

/// 一个 sing-box 出站：除 name 外的字段原样透传给 sing-box。
#[derive(Debug, Clone, Deserialize)]
pub struct Node {
    #[serde(default)]
    pub name: Option<String>,
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

#[derive(Debug, Deserialize)]
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
        }
    }
}
impl SwitchCfg {
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
pub struct CoreCfg { pub path: String, pub log_level: String, pub api_port: u16, pub api_secret: String }
impl Default for CoreCfg {
    fn default() -> Self { Self { path: String::new(), log_level: "info".into(), api_port: 0, api_secret: String::new() } }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CheckCfg { pub local_url: String, pub ip_info: String, pub ip_echo: Vec<String> }
impl Default for CheckCfg {
    fn default() -> Self {
        Self {
            local_url: "http://www.msftconnecttest.com/connecttest.txt".into(),
            ip_info: "https://ipinfo.io/json".into(),
            ip_echo: vec!["https://api.ipify.org".into(), "https://ifconfig.me/ip".into()],
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
}

/// sing-box 配置里由 AI Anchor 占用的出站名。
const RESERVED: &[&str] = &["exit", "lines", "direct", "ai-in"];

impl Config {
    pub fn load(paths: &Paths) -> Result<Self> {
        let p = paths.config();
        let text = std::fs::read_to_string(&p)
            .with_context(|| format!("读取配置失败：{}（还没有配置？先运行 anchor init）", p.display()))?;
        Self::parse(&text).with_context(|| format!("配置有误：{}", p.display()))
    }

    pub fn parse(text: &str) -> Result<Self> {
        let cfg: Config = toml::from_str(text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        check_node("[exit]", &self.exit)?;
        for (i, b) in self.backup_exits.iter().enumerate() {
            check_node(&format!("第 {} 个备用出口", i + 1), b)?;
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

/// 把测得的出口信息写回 [expect]，保留文件里的注释和格式。
pub fn set_expect(paths: &Paths, info: &ExitInfo) -> Result<()> {
    let p = paths.config();
    let text = std::fs::read_to_string(&p)?;
    let mut doc: toml_edit::DocumentMut = text.parse().context("解析 anchor.toml 失败")?;
    doc["expect"]["ip"] = toml_edit::value(info.ip.clone());
    if let Some(tz) = &info.timezone {
        doc["expect"]["timezone"] = toml_edit::value(tz.clone());
    }
    if let Some(c) = &info.country {
        doc["expect"]["country"] = toml_edit::value(c.clone());
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

# 备用出口：P0 只做记录，P1 起在用户确认后从下一次会话开始启用。
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
lines = "auto"               # auto：线路自动切换；manual：固定用第一条
keep_existing_conns = true   # 切换线路时不打断已建立的连接
probe_url = "https://www.gstatic.com/generate_204"
probe_interval = "30s"
tolerance_ms = 50
# 线路看门狗：每隔这么久探测当前线路，失败时立即重新选线，不必等 probe_interval。"0s" 关闭
watch_interval = "3s"

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

[core]
# sing-box.exe 路径；留空时依次查找 <数据目录>\bin、anchor.exe 同目录、PATH。
path = ""
log_level = "info"
api_port = 0                 # 0 表示代理端口 + 1
api_secret = "__SECRET__"
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
    fn rejects_unknown_sections() {
        assert!(Config::parse(&format!("{MIN}[typo]\na = 1\n")).is_err());
    }
}
