//! 本机时间线（SQLite，WAL 模式）。只有用户代理写，命令行只读。
//!
//! events：一次状态变化；probes：一次探测；disconnects：一次断联（P1b，版本 2）。

use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags, params};
use serde::Serialize;
use serde_json::Value;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SCHEMA_VERSION: i64 = 2;
/// 探测明细保留天数
pub const PROBE_DAYS: i64 = 7;
/// 事件保留天数
pub const EVENT_DAYS: i64 = 90;

pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub ts: i64,
    pub kind: String,
    pub detail: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct Probe {
    pub ts: i64,
    pub segment: String,
    pub target: String,
    pub ok: bool,
    pub ms: Option<u64>,
    pub note: String,
}

/// 一次断联及其归因。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DisconnectRow {
    pub ts: i64,
    pub domain: String,
    /// open / relay
    pub phase: String,
    /// 错误类别（disconnect::ErrClass 的名字）
    pub class: String,
    pub outbound: String,
    /// 归因（disconnect::Cause 的名字）
    pub cause: String,
    /// 归因依据
    pub why: String,
    /// 原始错误文本
    pub raw: String,
    /// 合并进来的错误条数
    pub count: u32,
}

pub struct Timeline {
    conn: Mutex<Connection>,
}

impl Timeline {
    /// 打开（不存在则创建）时间线，供用户代理写入。
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let conn = Connection::open(path).with_context(|| format!("打开时间线失败：{}", path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        Self::init(conn)
    }

    /// 只读打开，供命令行查询；不存在时报错。
    pub fn open_read_only(path: &Path) -> Result<Self> {
        if !path.exists() {
            anyhow::bail!("还没有时间线：{}（用户代理 anchor-agent 还没运行过）", path.display());
        }
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)
            .with_context(|| format!("打开时间线失败：{}", path.display()))?;
        conn.busy_timeout(Duration::from_secs(5))?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    pub fn memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.busy_timeout(Duration::from_secs(5))?;
        let v: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if v < 1 {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS events (
                     id INTEGER PRIMARY KEY,
                     ts INTEGER NOT NULL,
                     kind TEXT NOT NULL,
                     detail TEXT NOT NULL DEFAULT '{}'
                 );
                 CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
                 CREATE TABLE IF NOT EXISTS probes (
                     id INTEGER PRIMARY KEY,
                     ts INTEGER NOT NULL,
                     segment TEXT NOT NULL,
                     target TEXT NOT NULL,
                     ok INTEGER NOT NULL,
                     ms INTEGER,
                     note TEXT NOT NULL DEFAULT ''
                 );
                 CREATE INDEX IF NOT EXISTS probes_ts ON probes(ts);",
            )?;
        }
        if v < 2 {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS disconnects (
                     id INTEGER PRIMARY KEY,
                     ts INTEGER NOT NULL,
                     domain TEXT NOT NULL,
                     phase TEXT NOT NULL,
                     class TEXT NOT NULL,
                     outbound TEXT NOT NULL DEFAULT '',
                     cause TEXT NOT NULL,
                     why TEXT NOT NULL DEFAULT '',
                     raw TEXT NOT NULL DEFAULT '',
                     count INTEGER NOT NULL DEFAULT 1
                 );
                 CREATE INDEX IF NOT EXISTS disconnects_ts ON disconnects(ts);",
            )?;
        }
        if v > SCHEMA_VERSION {
            anyhow::bail!("时间线由更新版本的 AI Anchor 创建（版本 {v}），请升级");
        }
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    fn with<T>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> Result<T> {
        let c = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        Ok(f(&c)?)
    }

    /// 记一条事件。写入失败只打印，不影响调用方。
    pub fn event(&self, kind: &str, detail: Value) {
        self.event_at(now_ms(), kind, detail);
    }

    pub fn event_at(&self, ts: i64, kind: &str, detail: Value) {
        let r = self.with(|c| {
            c.execute("INSERT INTO events (ts, kind, detail) VALUES (?1, ?2, ?3)", params![ts, kind, detail.to_string()])
        });
        if let Err(e) = r {
            eprintln!("写时间线失败（{kind}）：{e:#}");
        }
    }

    pub fn probe(&self, segment: &str, target: &str, ok: bool, ms: Option<u64>, note: &str) {
        let r = self.with(|c| {
            c.execute(
                "INSERT INTO probes (ts, segment, target, ok, ms, note) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![now_ms(), segment, target, ok, ms.map(|m| m as i64), note],
            )
        });
        if let Err(e) = r {
            eprintln!("写时间线失败（探测）：{e:#}");
        }
    }

    /// 同一时刻同类事件是否已记录（从别处同步来的事件去重用）。
    pub fn event_exists(&self, kind: &str, ts: i64) -> bool {
        self.with(|c| {
            c.query_row("SELECT COUNT(*) FROM events WHERE kind = ?1 AND ts = ?2", params![kind, ts], |r| r.get::<_, i64>(0))
        })
        .map(|n| n > 0)
        .unwrap_or(false)
    }

    /// since 之后的事件，按时间正序；kinds 为空表示全部类型。
    pub fn events_since(&self, since: i64, kinds: &[String], limit: usize) -> Result<Vec<Event>> {
        self.with(|c| {
            let mut st = c.prepare(
                "SELECT ts, kind, detail FROM (SELECT ts, kind, detail, id FROM events WHERE ts >= ?1 ORDER BY ts DESC, id DESC) \
                 ORDER BY ts, id",
            )?;
            let rows = st.query_map(params![since], |r| {
                let detail: String = r.get(2)?;
                Ok(Event { ts: r.get(0)?, kind: r.get(1)?, detail: serde_json::from_str(&detail).unwrap_or(Value::Null) })
            })?;
            let mut out: Vec<Event> = rows.filter_map(|r| r.ok()).filter(|e| kinds.is_empty() || kinds.contains(&e.kind)).collect();
            if out.len() > limit {
                out.drain(..out.len() - limit);
            }
            Ok(out)
        })
    }

    pub fn probes_since(&self, since: i64, limit: usize) -> Result<Vec<Probe>> {
        self.with(|c| {
            let mut st = c.prepare(
                "SELECT ts, segment, target, ok, ms, note FROM \
                 (SELECT * FROM probes WHERE ts >= ?1 ORDER BY ts DESC, id DESC LIMIT ?2) ORDER BY ts, id",
            )?;
            let rows = st.query_map(params![since, limit as i64], |r| {
                Ok(Probe {
                    ts: r.get(0)?,
                    segment: r.get(1)?,
                    target: r.get(2)?,
                    ok: r.get(3)?,
                    ms: r.get::<_, Option<i64>>(4)?.map(|m| m as u64),
                    note: r.get(5)?,
                })
            })?;
            Ok(rows.filter_map(|r| r.ok()).collect())
        })
    }

    /// 每段每个目标的探测汇总：(段, 目标, 次数, 成功次数, 平均延迟)。
    pub fn probe_summary(&self, since: i64) -> Result<Vec<(String, String, u64, u64, Option<u64>)>> {
        self.with(|c| {
            let mut st = c.prepare(
                "SELECT segment, target, COUNT(*), SUM(ok), AVG(CASE WHEN ok THEN ms END) FROM probes \
                 WHERE ts >= ?1 GROUP BY segment, target ORDER BY segment, target",
            )?;
            let rows = st.query_map(params![since], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get::<_, i64>(2)? as u64,
                    r.get::<_, i64>(3)? as u64,
                    r.get::<_, Option<f64>>(4)?.map(|m| m.round() as u64),
                ))
            })?;
            Ok(rows.filter_map(|r| r.ok()).collect())
        })
    }

    /// [from, to] 之间的探测，按时间正序（归因用）。
    pub fn probes_between(&self, from: i64, to: i64) -> Result<Vec<Probe>> {
        self.with(|c| {
            let mut st = c.prepare("SELECT ts, segment, target, ok, ms, note FROM probes WHERE ts BETWEEN ?1 AND ?2 ORDER BY ts, id")?;
            let rows = st.query_map(params![from, to], |r| {
                Ok(Probe {
                    ts: r.get(0)?,
                    segment: r.get(1)?,
                    target: r.get(2)?,
                    ok: r.get(3)?,
                    ms: r.get::<_, Option<i64>>(4)?.map(|m| m as u64),
                    note: r.get(5)?,
                })
            })?;
            Ok(rows.filter_map(|r| r.ok()).collect())
        })
    }

    /// 某一段 from 以来的探测，按时间正序。
    pub fn probes_of(&self, segment: &str, from: i64) -> Result<Vec<Probe>> {
        self.with(|c| {
            let mut st = c.prepare("SELECT ts, segment, target, ok, ms, note FROM probes WHERE segment = ?1 AND ts >= ?2 ORDER BY ts, id")?;
            let rows = st.query_map(params![segment, from], |r| {
                Ok(Probe {
                    ts: r.get(0)?,
                    segment: r.get(1)?,
                    target: r.get(2)?,
                    ok: r.get(3)?,
                    ms: r.get::<_, Option<i64>>(4)?.map(|m| m as u64),
                    note: r.get(5)?,
                })
            })?;
            Ok(rows.filter_map(|r| r.ok()).collect())
        })
    }

    /// [from, to] 之间的事件，按时间正序（归因用）。
    pub fn events_between(&self, from: i64, to: i64) -> Result<Vec<Event>> {
        self.with(|c| {
            let mut st = c.prepare("SELECT ts, kind, detail FROM events WHERE ts BETWEEN ?1 AND ?2 ORDER BY ts, id")?;
            let rows = st.query_map(params![from, to], |r| {
                let detail: String = r.get(2)?;
                Ok(Event { ts: r.get(0)?, kind: r.get(1)?, detail: serde_json::from_str(&detail).unwrap_or(Value::Null) })
            })?;
            Ok(rows.filter_map(|r| r.ok()).collect())
        })
    }

    pub fn disconnect(&self, d: &DisconnectRow) {
        let r = self.with(|c| {
            c.execute(
                "INSERT INTO disconnects (ts, domain, phase, class, outbound, cause, why, raw, count) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![d.ts, d.domain, d.phase, d.class, d.outbound, d.cause, d.why, d.raw, d.count],
            )
        });
        if let Err(e) = r {
            eprintln!("写时间线失败（断联）：{e:#}");
        }
    }

    /// since 之后的断联，按时间正序。时间线还是旧版本（用户代理没升级）时返回错误。
    pub fn disconnects_since(&self, since: i64) -> Result<Vec<DisconnectRow>> {
        self.with(|c| {
            let mut st = c.prepare(
                "SELECT ts, domain, phase, class, outbound, cause, why, raw, count FROM disconnects WHERE ts >= ?1 ORDER BY ts, id",
            )?;
            let rows = st.query_map(params![since], |r| {
                Ok(DisconnectRow {
                    ts: r.get(0)?,
                    domain: r.get(1)?,
                    phase: r.get(2)?,
                    class: r.get(3)?,
                    outbound: r.get(4)?,
                    cause: r.get(5)?,
                    why: r.get(6)?,
                    raw: r.get(7)?,
                    count: r.get::<_, i64>(8)? as u32,
                })
            })?;
            Ok(rows.filter_map(|r| r.ok()).collect())
        })
    }

    /// 删除超出保留期的数据，返回 (删除的探测数, 删除的事件和断联数)。
    pub fn prune(&self, now: i64) -> Result<(usize, usize)> {
        let day = 86_400_000i64;
        self.with(|c| {
            let p = c.execute("DELETE FROM probes WHERE ts < ?1", params![now - PROBE_DAYS * day])?;
            let e = c.execute("DELETE FROM events WHERE ts < ?1", params![now - EVENT_DAYS * day])?;
            let d = c.execute("DELETE FROM disconnects WHERE ts < ?1", params![now - EVENT_DAYS * day])?;
            Ok((p, e + d))
        })
    }
}

/// 本地时间，如 2026-11-12 10:31:02。
pub fn local_time(ts: i64) -> String {
    use chrono::TimeZone;
    match chrono::Local.timestamp_millis_opt(ts) {
        chrono::LocalResult::Single(t) | chrono::LocalResult::Ambiguous(t, _) => t.format("%Y-%m-%d %H:%M:%S").to_string(),
        chrono::LocalResult::None => ts.to_string(),
    }
}

fn s<'a>(d: &'a Value, k: &str) -> &'a str {
    d.get(k).and_then(Value::as_str).unwrap_or("?")
}

fn secs(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms} 毫秒")
    } else if ms < 60_000 {
        format!("{:.1} 秒", ms as f64 / 1000.0)
    } else {
        crate::util::zh_duration(ms / 1000)
    }
}

fn uplink_name(kind: &str) -> &str {
    match kind {
        "wifi" => "Wi-Fi",
        "ethernet" => "网线",
        "none" => "没有网络",
        other => other,
    }
}

/// 事件的中文名称和一句话说明（命令行时间线和托盘通知共用）。
pub fn describe(e: &Event) -> (&'static str, String) {
    let d = &e.detail;
    let n = |k: &str| d.get(k).and_then(Value::as_u64);
    match e.kind.as_str() {
        "agent_start" => ("代理启动", format!("anchor-agent {} 启动", s(d, "version"))),
        "agent_stop" => ("代理停止", format!("anchor-agent 停止（{}）", s(d, "reason"))),
        "kernel_start" => ("内核启动", format!("sing-box 已启动（pid {}）", n("pid").unwrap_or(0))),
        "kernel_restart" => {
            let code = d.get("exit_code").and_then(Value::as_i64).map(|c| format!("退出码 {c}")).unwrap_or_else(|| "被结束".into());
            let up = n("uptime_ms").map(|m| format!("，运行了 {}", secs(m))).unwrap_or_default();
            match n("down_ms") {
                Some(m) => ("内核重启", format!("sing-box 意外退出（{code}{up}），{}后恢复", secs(m))),
                None => ("内核重启", format!("sing-box 意外退出（{code}{up}），正在重启")),
            }
        }
        "kernel_error" => ("内核错误", s(d, "message").to_string()),
        "line_switch" => {
            let why = match s(d, "reason") {
                "down" => "当前线路探测失败",
                "manual" => "手动切换",
                "flaky" => "当前线路不稳定",
                "slow" => "当前线路持续偏慢",
                other => other,
            };
            let ms = n("ms").map(|m| format!("，{m} ms")).unwrap_or_default();
            ("线路切换", format!("{} → {}（{why}{ms}）；出口 IP 不变", s(d, "from"), s(d, "to")))
        }
        "line_down" => {
            let why = if s(d, "why") == "pinned" { "线路已固定，不自动切换" } else { "手动模式不自动切换" };
            ("线路故障", format!("线路 {} 探测失败；{why}", s(d, "line")))
        }
        "line_recovered" => ("线路恢复", format!("线路已恢复，当前 {}", s(d, "line"))),
        "all_lines_down" => ("线路全断", format!("所有线路都不可用（当前 {}）；AI 新连接会失败，不会直连", s(d, "line"))),
        "guard_refresh" => {
            let list = |k: &str| -> Vec<String> {
                d.get(k).and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default()
            };
            let (add, rm) = (list("added"), list("removed"));
            let mut parts = Vec::new();
            if !add.is_empty() {
                parts.push(format!("新增 {}", add.join("、")));
            }
            if !rm.is_empty() {
                parts.push(format!("移除 {}", rm.join("、")));
            }
            if parts.is_empty() {
                parts.push("规则无变化".into());
            }
            ("守卫刷新", format!("{}（{}）", parts.join("；"), s(d, "source")))
        }
        "guard_pause" => ("守卫暂停", format!("守卫已暂停，到 {} 自动恢复", s(d, "until"))),
        "guard_resume" => ("守卫恢复", "守卫已恢复".into()),
        "app_launch" => ("启动应用", format!("{}（{}）", s(d, "app"), s(d, "exe"))),
        "exit_locked" => {
            let why = match s(d, "reason") {
                "network_change" => "网络变化",
                "kernel_start" => "内核启动",
                "exit_down" => "出口不可达",
                "recheck" => "手动核对",
                "no_baseline" => "还没有登记出口基线",
                other => other,
            };
            ("出口锁定", format!("AI 通道已锁住，核对出口后再放行（{why}）"))
        }
        "exit_unlocked" => {
            let locked = n("locked_ms").map(|m| format!("，锁住 {}", secs(m))).unwrap_or_default();
            match s(d, "reason") {
                "back_to_baseline" => ("出口恢复", format!("出口回到基线 {}，AI 通道已放行{locked}", s(d, "ip"))),
                _ => ("出口放行", format!("出口 {} 与基线一致，AI 通道已放行{locked}", s(d, "ip"))),
            }
        }
        "exit_ip_changed" => (
            "出口变化",
            format!("出口 IP 已变化：基线 {}，现在 {}；AI 通道已锁住", s(d, "baseline"), s(d, "actual")),
        ),
        "exit_unverifiable" => ("无法核对", "出口能连通，但 IP 回显服务都连不上；AI 通道保持锁住".into()),
        "net_change" => ("网络变化", "网卡地址或默认路由变化（VPN 连接、断开、重连，或换网络）".into()),
        "exit_switch" => ("出口切换", format!("出口 {} → {}（手动切换）；AI 服务看到的 IP 随之改变", s(d, "from"), s(d, "to"))),
        "uplink_change" => ("换网络", format!("上行网卡变了：{} → {}", uplink_name(s(d, "from")), uplink_name(s(d, "to")))),
        "config_error" => ("配置错误", s(d, "message").to_string()),
        _ => ("其他", format!("{} {}", e.kind, e.detail)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn events_round_trip_in_order_with_filter_and_limit() {
        let t = Timeline::memory().unwrap();
        t.event_at(1000, "agent_start", json!({"version": "0.2.0"}));
        t.event_at(2000, "kernel_restart", json!({"exit_code": 1, "uptime_ms": 5000, "down_ms": 2400}));
        t.event_at(3000, "line_switch", json!({"from": "a", "to": "b", "reason": "down", "ms": 800}));
        let all = t.events_since(0, &[], 100).unwrap();
        assert_eq!(all.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>(), ["agent_start", "kernel_restart", "line_switch"]);
        let last = t.events_since(0, &[], 2).unwrap();
        assert_eq!(last[0].kind, "kernel_restart", "limit 保留最近的几条");
        let only = t.events_since(1500, &["line_switch".to_string()], 100).unwrap();
        assert_eq!(only.len(), 1);
        assert_eq!(describe(&only[0]).1, "a → b（当前线路探测失败，800 ms）；出口 IP 不变");
        assert_eq!(describe(&all[1]).1, "sing-box 意外退出（退出码 1，运行了 5.0 秒），2.4 秒后恢复");
    }

    #[test]
    fn disconnects_and_windows() {
        let t = Timeline::memory().unwrap();
        let row = DisconnectRow {
            ts: 10_000,
            domain: "claude.ai".into(),
            phase: "open".into(),
            class: "dns".into(),
            outbound: "direct[exit]".into(),
            cause: "exit".into(),
            why: "w".into(),
            raw: "lookup …".into(),
            count: 3,
        };
        t.disconnect(&row);
        assert_eq!(t.disconnects_since(0).unwrap(), vec![row]);
        assert!(t.disconnects_since(20_000).unwrap().is_empty());

        t.event_at(5_000, "net_change", serde_json::json!({}));
        t.event_at(50_000, "net_change", serde_json::json!({}));
        assert_eq!(t.events_between(0, 10_000).unwrap().len(), 1);
        t.probe("local", "direct", true, Some(10), "");
        let now = now_ms();
        assert_eq!(t.probes_between(now - 60_000, now + 1_000).unwrap().len(), 1);
        assert!(t.probes_between(0, 1_000).unwrap().is_empty());

        // 断联和事件一样保留 90 天
        let (_, e) = t.prune(10_000 + (EVENT_DAYS + 1) * 86_400_000).unwrap();
        assert_eq!(e, 3);
    }

    #[test]
    fn upgrades_a_version_1_timeline() {
        let path = std::env::temp_dir().join(format!("anchor-tl-{}.db", crate::util::random_hex()));
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch(
                "CREATE TABLE events (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, kind TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '{}');
                 CREATE TABLE probes (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, segment TEXT NOT NULL, target TEXT NOT NULL, ok INTEGER NOT NULL, ms INTEGER, note TEXT NOT NULL DEFAULT '');
                 INSERT INTO events (ts, kind) VALUES (1, 'agent_start');
                 PRAGMA user_version = 1;",
            )
            .unwrap();
        }
        let t = Timeline::open(&path).unwrap();
        assert_eq!(t.events_since(0, &[], 10).unwrap().len(), 1, "旧数据保留");
        assert!(t.disconnects_since(0).unwrap().is_empty(), "新表已建");
        drop(t);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[test]
    fn describes_exit_lock_events() {
        let ev = |kind: &str, detail: Value| Event { ts: 0, kind: kind.into(), detail };
        assert_eq!(
            describe(&ev("exit_locked", json!({ "reason": "network_change" }))),
            ("出口锁定", "AI 通道已锁住，核对出口后再放行（网络变化）".to_string())
        );
        assert_eq!(
            describe(&ev("exit_unlocked", json!({ "reason": "verified", "ip": "1.1.1.1", "locked_ms": 900 }))).1,
            "出口 1.1.1.1 与基线一致，AI 通道已放行，锁住 900 毫秒"
        );
        assert_eq!(describe(&ev("exit_unlocked", json!({ "reason": "back_to_baseline", "ip": "1.1.1.1" }))).0, "出口恢复");
        assert_eq!(
            describe(&ev("exit_ip_changed", json!({ "baseline": "1.1.1.1", "actual": "2.2.2.2" }))).1,
            "出口 IP 已变化：基线 1.1.1.1，现在 2.2.2.2；AI 通道已锁住"
        );
    }

    #[test]
    fn probes_summary_and_prune() {
        let t = Timeline::memory().unwrap();
        t.probe("line", "a", true, Some(100), "");
        t.probe("line", "a", true, Some(300), "");
        t.probe("line", "a", false, None, "timeout");
        let sum = t.probe_summary(0).unwrap();
        assert_eq!(sum, vec![("line".to_string(), "a".to_string(), 3, 2, Some(200))]);
        assert_eq!(t.probes_since(0, 2).unwrap().len(), 2);
        let (p, e) = t.prune(now_ms() + (PROBE_DAYS + 1) * 86_400_000).unwrap();
        assert_eq!((p, e), (3, 0));
    }

    #[test]
    fn reopening_keeps_data_and_read_only_works() {
        let dir = std::env::temp_dir().join(format!("anchor-tl-{}", crate::util::random_hex()));
        let db = dir.join("timeline.db");
        {
            let t = Timeline::open(&db).unwrap();
            t.event("agent_start", json!({"version": "x"}));
        }
        let t = Timeline::open(&db).unwrap();
        t.event("agent_stop", json!({"reason": "test"}));
        let ro = Timeline::open_read_only(&db).unwrap();
        assert_eq!(ro.events_since(0, &[], 10).unwrap().len(), 2);
        drop((t, ro));
        let _ = std::fs::remove_dir_all(dir);
    }
}
