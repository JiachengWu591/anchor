//! 新版本提醒：问 GitHub 最新的正式版本，和自己的版本比。只查，不下载，也不安装。
//!
//! 结果记在数据目录的 update.json 里。用户代理每天查一次，有新版本时发一次通知；
//! anchor status 和面板只读这份记录；anchor upgrade --check 随时手动查一次。

use crate::config::{Config, Paths};
use crate::net;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 发布版本的仓库。
pub const REPO: &str = "JiachengWu591/anchor";
/// 最新的正式版本（GitHub 不把草稿和预发布版本算在内）。
const LATEST_API: &str = "https://api.github.com/repos/JiachengWu591/anchor/releases/latest";
/// 所有版本的列表页。
pub const RELEASES_PAGE: &str = "https://github.com/JiachengWu591/anchor/releases";

/// 查成功后，隔多久再查。
pub const EVERY_OK: Duration = Duration::from_secs(24 * 3600);
/// 查失败后，隔多久再试。
pub const EVERY_FAILED: Duration = Duration::from_secs(3 * 3600);
/// 每条路最多等多久。
pub const TIMEOUT: Duration = Duration::from_secs(15);

/// 版本号的三段数字（主、次、修订），可以带开头的 v。别的写法（如 0.4.0-rc1）认不出。
pub fn parse_version(s: &str) -> Option<[u64; 3]> {
    let s = s.strip_prefix('v').unwrap_or(s);
    let mut parts = s.split('.');
    let mut v = [0u64; 3];
    for slot in &mut v {
        let p = parts.next()?;
        if p.is_empty() || p.len() > 9 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        *slot = p.parse().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(v)
}

/// a 比 b 新。认不出的版本号不算新。
pub fn is_newer(a: &str, b: &str) -> bool {
    matches!((parse_version(a), parse_version(b)), (Some(x), Some(y)) if x > y)
}

/// 某个版本的发布页。地址由核对过的版本号拼出来，只含数字和点。
pub fn release_page(version: &str) -> Option<String> {
    let [a, b, c] = parse_version(version)?;
    Some(format!("https://github.com/{REPO}/releases/tag/v{a}.{b}.{c}"))
}

/// GitHub 上的一个正式版本。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    /// 不带 v，如 0.4.0
    pub version: String,
    /// 发布日期（UTC），如 2026-12-01；没有时为空
    pub date: String,
}

/// 解析 GitHub 的 releases/latest 响应。
pub fn parse_release(body: &str) -> Result<Release> {
    let v: Value = serde_json::from_str(body).context("GitHub 返回的不是 JSON")?;
    if v["draft"] == true || v["prerelease"] == true {
        bail!("GitHub 返回的不是正式版本");
    }
    let tag = v["tag_name"].as_str().context("GitHub 返回的内容里没有版本标签")?;
    let Some([a, b, c]) = parse_version(tag) else {
        bail!("认不出版本标签 {}", tag.chars().take(40).collect::<String>());
    };
    let date = v["published_at"]
        .as_str()
        .and_then(|d| d.get(..10))
        .filter(|d| d.bytes().all(|b| b.is_ascii_digit() || b == b'-'))
        .unwrap_or_default()
        .to_string();
    Ok(Release { version: format!("{a}.{b}.{c}"), date })
}

/// 经一条路问一次。还没有发布过正式版本时返回 None。
pub fn fetch(agent: &ureq::Agent) -> Result<Option<Release>> {
    let resp = match agent.get(LATEST_API).set("Accept", "application/vnd.github+json").set("X-GitHub-Api-Version", "2022-11-28").call() {
        Ok(r) => r,
        Err(ureq::Error::Status(404, _)) => return Ok(None),
        Err(ureq::Error::Status(code @ (403 | 429), _)) => bail!("GitHub 暂时限制了查询（HTTP {code}）"),
        Err(ureq::Error::Status(code, _)) => bail!("GitHub 返回 HTTP {code}"),
        Err(ureq::Error::Transport(t)) => bail!("连不上 GitHub（{}）", transport(&t)),
    };
    let body = resp.into_string().context("读取 GitHub 的响应失败")?;
    parse_release(&body).map(Some)
}

/// 传输层错误的简短说明（不带地址）。
fn transport(t: &ureq::Transport) -> String {
    let kind = t.kind().to_string();
    match (t.message(), std::error::Error::source(t)) {
        (Some(m), _) => format!("{kind}：{m}"),
        (None, Some(src)) => format!("{kind}：{src}"),
        (None, None) => kind,
    }
}

/// 查询走哪几条路：先直连；内核的探测入站在监听时，再经出口试一次。
pub fn ways(cfg: Option<&Config>) -> Vec<(&'static str, ureq::Agent)> {
    let mut v = vec![("直连", net::agent_direct(TIMEOUT))];
    if let Some(cfg) = cfg
        && net::port_open("127.0.0.1", cfg.probe_port())
        && let Ok(a) = net::agent_via_probe(cfg, TIMEOUT)
    {
        v.push(("经出口", a));
    }
    v
}

/// 依次经各条路查，第一条成功的为准；都失败时，各条路的原因都写上。
pub fn check(ways: &[(&str, ureq::Agent)]) -> Result<Option<Release>> {
    let mut errs = Vec::new();
    for (name, agent) in ways {
        match fetch(agent) {
            Ok(r) => return Ok(r),
            Err(e) => errs.push(format!("{name}：{e:#}")),
        }
    }
    if errs.is_empty() {
        bail!("没有可用的网络");
    }
    bail!("{}", errs.join("；"))
}

pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// 数据目录里的 update.json。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// 上次去查的时间（毫秒时间戳），不论成败
    pub checked_ms: i64,
    /// 查到的最新正式版本；还没查到过、或者还没有发布过时为空
    pub latest: String,
    /// 它的发布日期（UTC）
    pub date: String,
    /// 上次查询失败的原因；成功时为空
    pub error: String,
    /// 已经为哪个版本发过通知（或者在命令行里告诉过用户）
    pub notified: String,
}

impl State {
    /// 读不到、格式不对，都当作还没查过。
    pub fn load(paths: &Paths) -> Self {
        std::fs::read_to_string(paths.update_state()).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
    }

    /// 先写临时文件再改名：用户代理和命令行都会写，读的一方不会读到半个文件。
    pub fn save(&self, paths: &Paths) -> Result<()> {
        let p = paths.update_state();
        let tmp = p.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(self)?).with_context(|| format!("无法写入 {}", tmp.display()))?;
        std::fs::rename(&tmp, &p).with_context(|| format!("无法写入 {}", p.display()))
    }

    /// 记下一次查询的结果。失败时保留上次查到的版本。
    pub fn record(&mut self, now_ms: i64, r: &Result<Option<Release>>) {
        self.checked_ms = now_ms;
        match r {
            Ok(Some(rel)) => {
                self.latest = rel.version.clone();
                self.date = rel.date.clone();
                self.error.clear();
            }
            Ok(None) => {
                self.latest.clear();
                self.date.clear();
                self.error.clear();
            }
            Err(e) => self.error = format!("{e:#}"),
        }
    }

    /// 比 current 新的那个版本（有的话）。
    pub fn newer(&self, current: &str) -> Option<&str> {
        is_newer(&self.latest, current).then_some(self.latest.as_str())
    }

    /// 该不该去查了：没查过、到了间隔，或者系统时间往回调过。
    pub fn due(&self, now_ms: i64) -> bool {
        let every = if self.error.is_empty() { EVERY_OK } else { EVERY_FAILED };
        self.checked_ms <= 0 || now_ms < self.checked_ms || now_ms - self.checked_ms >= every.as_millis() as i64
    }

    /// 有新版本、还没为它发过通知：返回这个版本，并记为已通知。
    pub fn take_notice(&mut self, current: &str) -> Option<String> {
        let v = self.newer(current)?.to_string();
        if self.notified == v {
            return None;
        }
        self.notified = v.clone();
        Some(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare_by_number() {
        assert_eq!(parse_version("v0.3.0"), Some([0, 3, 0]));
        assert_eq!(parse_version("1.10.2"), Some([1, 10, 2]));
        for bad in ["", "v", "0.3", "0.3.0.1", "0.4.0-rc1", "0.x.0", "v 0.3.0", "0..1", "1234567890.0.0"] {
            assert_eq!(parse_version(bad), None, "{bad}");
        }
        assert!(is_newer("0.10.0", "0.9.9"), "按数字比，不按字符");
        assert!(is_newer("v1.0.0", "0.3.0"));
        assert!(!is_newer("0.3.0", "0.3.0"));
        assert!(!is_newer("0.2.9", "0.3.0"));
        assert!(!is_newer("", "0.3.0"));
        assert!(!is_newer("0.4.0-rc1", "0.3.0"), "认不出的不算新");
    }

    #[test]
    fn release_page_is_built_from_the_number() {
        assert_eq!(release_page("0.4.0").as_deref(), Some("https://github.com/JiachengWu591/anchor/releases/tag/v0.4.0"));
        assert_eq!(release_page("v0.4.0").as_deref(), Some("https://github.com/JiachengWu591/anchor/releases/tag/v0.4.0"));
        assert_eq!(release_page("0.4.0/../../x"), None);
        assert!(LATEST_API.contains(REPO) && RELEASES_PAGE.contains(REPO));
    }

    #[test]
    fn parses_the_latest_release() {
        let body = r#"{"tag_name":"v0.4.0","name":"AI Anchor v0.4.0","draft":false,"prerelease":false,
                       "published_at":"2026-12-01T08:32:36Z","assets":[]}"#;
        assert_eq!(parse_release(body).unwrap(), Release { version: "0.4.0".into(), date: "2026-12-01".into() });
        let no_date = r#"{"tag_name":"v0.4.0","published_at":null}"#;
        assert_eq!(parse_release(no_date).unwrap().date, "");
        assert!(parse_release(r#"{"tag_name":"v0.4.0","prerelease":true}"#).is_err());
        assert!(parse_release(r#"{"tag_name":"nightly"}"#).is_err());
        assert!(parse_release(r#"{"message":"Not Found"}"#).is_err());
        assert!(parse_release("<html>").is_err());
    }

    #[test]
    fn check_names_every_way_that_failed() {
        // 本机 1 号端口上没有代理：两条路都立刻连不上，不会真的联网
        let dead = || ureq::AgentBuilder::new().proxy(ureq::Proxy::new("socks5://127.0.0.1:1").unwrap()).timeout(TIMEOUT).build();
        let e = check(&[("甲", dead()), ("乙", dead())]).unwrap_err().to_string();
        assert!(e.starts_with("甲：连不上 GitHub（") && e.contains("）；乙：连不上 GitHub（"), "{e}");
        assert_eq!(check(&[]).unwrap_err().to_string(), "没有可用的网络");
    }

    #[test]
    fn state_records_results_and_notices_once() {
        let mut st = State::default();
        assert!(st.due(1_000));
        let found = Ok(Some(Release { version: "0.4.0".into(), date: "2026-12-01".into() }));
        st.record(1_000, &found);
        assert_eq!(st.newer("0.3.0"), Some("0.4.0"));
        assert_eq!(st.newer("0.4.0"), None, "升级之后不再提醒");
        assert_eq!(st.take_notice("0.3.0").as_deref(), Some("0.4.0"));
        assert_eq!(st.take_notice("0.3.0"), None, "同一个版本只通知一次");

        // 查失败：保留上次查到的版本，3 小时后再试
        st.record(2_000, &Err(anyhow::anyhow!("连不上")));
        assert_eq!((st.latest.as_str(), st.error.as_str()), ("0.4.0", "连不上"));
        assert!(!st.due(2_000 + EVERY_FAILED.as_millis() as i64 - 1));
        assert!(st.due(2_000 + EVERY_FAILED.as_millis() as i64));

        // 又出了新版本：再通知一次
        st.record(3_000, &Ok(Some(Release { version: "0.5.0".into(), date: String::new() })));
        assert!(st.error.is_empty());
        assert!(!st.due(3_000 + EVERY_OK.as_millis() as i64 - 1));
        assert!(st.due(3_000 + EVERY_OK.as_millis() as i64));
        assert!(st.due(2_999), "系统时间往回调过");
        assert_eq!(st.take_notice("0.3.0").as_deref(), Some("0.5.0"));

        // GitHub 上没有正式版本了（都撤下了）
        st.record(4_000, &Ok(None));
        assert_eq!(st.newer("0.3.0"), None);
    }

    #[test]
    fn state_file_round_trips() {
        let home = std::env::temp_dir().join(format!("anchor-test-{}", crate::util::random_hex()));
        std::fs::create_dir_all(&home).unwrap();
        let paths = Paths { home: home.clone() };
        assert_eq!(State::load(&paths), State::default(), "没有文件时当作没查过");
        let st = State { checked_ms: 5, latest: "0.4.0".into(), date: "2026-12-01".into(), error: String::new(), notified: "0.4.0".into() };
        st.save(&paths).unwrap();
        assert_eq!(State::load(&paths), st);
        assert!(!paths.update_state().with_extension("json.tmp").exists());
        std::fs::write(paths.update_state(), "{broken").unwrap();
        assert_eq!(State::load(&paths), State::default(), "坏文件当作没查过");
        std::fs::remove_dir_all(home).unwrap();
    }
}
