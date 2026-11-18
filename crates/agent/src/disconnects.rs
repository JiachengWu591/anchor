//! 断联采集（P1b）：实时读 sing-box 日志，把 AI 程序访问 AI 域名时的连接错误记成断联，
//! 立刻补一轮探测，等归因窗口结束（断联后 15 秒）再按前后的探测和事件归因，写进时间线。
//!
//! 逻辑在 anchor_core::disconnect（解析、分类、合并、归因），这里负责读文件、突发探测和落盘。
//! AI 通道锁住期间拦下的连接（内核不记错误）按一次锁住记一次断联，等锁住结束再归因落盘。
//! 只看用户代理启动之后新写的日志；日志被轮转（变小）时从头读新文件。

use crate::health;
use crate::shared::Shared;
use anchor_core::config::Config;
use anchor_core::disconnect::{self, Disconnect, ErrClass, Feed, Tracker, WINDOW_AFTER_MS, WINDOW_BEFORE_MS};
use anchor_core::log;
use anchor_core::net::{self, ClashApi};
use anchor_core::timeline::{DisconnectRow, now_ms};
use serde_json::Value;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// 两轮突发探测至少隔这么久（一次故障常带来一连串断联）
const BURST_EVERY: Duration = Duration::from_secs(10);
/// 锁住拦下的断联等锁住结束再写（拦下的连接数才全），但最多等这么久
const LOCK_SETTLE_MAX_MS: i64 = 10 * 60_000;

pub fn run(sh: Arc<Shared>) {
    let path = sh.paths.log_dir().join("sing-box.log");
    let mut tail = Tail::new(path);
    let mut tracker = Tracker::default();
    let mut pending: Vec<Disconnect> = Vec::new();
    let mut last_burst: Option<Instant> = None;
    while !sh.stopping() {
        thread::sleep(Duration::from_millis(500));
        for line in tail.read_lines() {
            let Some(l) = disconnect::parse_line(&line) else { continue };
            match tracker.feed(&l) {
                Some(Feed::New(d)) => {
                    sh.line_kick.store(true, std::sync::atomic::Ordering::SeqCst);
                    if last_burst.is_none_or(|t| t.elapsed() >= BURST_EVERY)
                        && let Some(cfg) = sh.config()
                    {
                        last_burst = Some(Instant::now());
                        burst(sh.clone(), cfg, d.domain.clone());
                    }
                    pending.push(d);
                }
                Some(Feed::Merged { domain, first_ts, locked }) => {
                    if let Some(p) = pending.iter_mut().find(|p| p.domain == domain && p.ts == first_ts && p.lock.is_some() == locked) {
                        p.count += 1;
                    }
                }
                Some(Feed::LockEnded { domain, first_ts, at }) => {
                    if let Some(l) = pending.iter_mut().find(|p| p.domain == domain && p.ts == first_ts).and_then(|p| p.lock.as_mut()) {
                        l.until = Some(at);
                    }
                }
                None => {}
            }
        }
        let now = now_ms();
        pending.retain(|d| {
            let due = match d.lock {
                Some(l) => (l.until.is_some() && now >= d.ts + WINDOW_AFTER_MS) || now >= d.ts + LOCK_SETTLE_MAX_MS,
                None => now >= d.ts + WINDOW_AFTER_MS,
            };
            if due {
                settle(&sh, d);
            }
            !due
        });
    }
    // 退出前把等着的也归因掉（窗口不全，按已有的数据）
    for d in &pending {
        settle(&sh, d);
    }
}

/// 归因并写进时间线。
fn settle(sh: &Shared, d: &Disconnect) {
    let has_lines = sh.config().is_some_and(|c| !c.lines.is_empty());
    let from = disconnect::window_start(d) - WINDOW_BEFORE_MS;
    // 锁住拦下的：探测取到锁住结束，补充锁住期间各段的情况
    let to = d.lock.and_then(|l| l.until).unwrap_or(d.ts).max(d.ts) + WINDOW_AFTER_MS;
    let probes = sh.tl.probes_between(from, to).unwrap_or_default();
    let events = sh.tl.events_between(from, d.ts + WINDOW_AFTER_MS).unwrap_or_default();
    let mut v = disconnect::attribute(d, &probes, &events, has_lines);
    if let Some(more) = disconnect::lock_summary(d, &probes, now_ms()) {
        v.why = format!("{}；{more}", v.why);
    }
    log::line(&format!(
        "断联：{}（{}，{} 条）→ {}：{}",
        d.domain,
        ErrClass::label(d.class.name()),
        d.count,
        disconnect::Cause::label(v.cause.name()),
        v.why
    ));
    sh.tl.disconnect(&DisconnectRow {
        ts: d.ts,
        domain: d.domain.clone(),
        phase: d.phase.into(),
        class: d.class.name().into(),
        outbound: d.outbound.clone(),
        cause: v.cause.name().into(),
        why: v.why,
        raw: d.raw.clone(),
        count: d.count,
    });
}

/// 断联后立刻把各段测一遍，保证归因窗口里有数据，不靠碰巧赶上定时探测。
fn burst(sh: Arc<Shared>, cfg: Arc<Config>, domain: String) {
    thread::spawn(move || {
        const NOTE: &str = "突发";
        let note = |n: &str| if n.is_empty() { NOTE.to_string() } else { format!("{NOTE}：{n}") };
        let (ok, ms, n) = health::local_probe(&net::agent_direct(Duration::from_secs(3)), &cfg.check.local_url);
        sh.tl.probe("local", health::local_via(), ok, ms, &note(&n));

        let api = ClashApi::new(&cfg);
        let (ok, ms, n) = health::chain_probe(&api, &cfg.switch.probe_url);
        sh.tl.probe("chain", anchor_core::singbox::TAG_EXIT, ok, ms, &note(&n));

        if !cfg.lines.is_empty()
            && let Some(cur) = api.current_line()
        {
            match api.delay(&cur, &cfg.switch.probe_url, 3000) {
                Ok(ms) => sh.tl.probe("line", &cur, true, Some(ms), NOTE),
                Err(e) => sh.tl.probe("line", &cur, false, None, &note(&format!("{e:#}"))),
            }
        }

        // 经出口访问出事的 AI 域名（探测入站，锁住时也能测）：拿到任何 HTTP 响应都算通
        let Ok(agent) = net::agent_via_probe(&cfg, Duration::from_secs(8)) else { return };
        let started = Instant::now();
        match net::get(&agent, &format!("https://{domain}/")) {
            Ok(r) => sh.tl.probe("ai", &domain, true, Some(started.elapsed().as_millis() as u64), &note(&format!("HTTP {}", r.code))),
            Err(e) => sh.tl.probe("ai", &domain, false, None, &note(&format!("{e:#}"))),
        }
        if let Some((vendor, url)) = disconnect::status_page(&domain)
            && let Ok(r) = net::get(&agent, url)
        {
            let v: Value = serde_json::from_str(&r.body).unwrap_or(Value::Null);
            let indicator = v["status"]["indicator"].as_str().unwrap_or("");
            let desc = v["status"]["description"].as_str().unwrap_or("");
            // 只有严重故障才算服务端出事；minor、维护只是提示
            let ok = !matches!(indicator, "major" | "critical");
            sh.tl.probe("status", vendor, ok, None, &note(desc));
        }
    });
}

/// 跟读一个只追加的文本文件。
struct Tail {
    path: PathBuf,
    offset: u64,
    partial: Vec<u8>,
}

impl Tail {
    /// 从文件当前末尾开始：只看之后新写的。
    fn new(path: PathBuf) -> Self {
        let offset = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        Self { path, offset, partial: Vec::new() }
    }

    fn read_lines(&mut self) -> Vec<String> {
        let Ok(len) = std::fs::metadata(&self.path).map(|m| m.len()) else { return vec![] };
        if len < self.offset {
            // 日志被轮转或截断了：从新文件开头读
            self.offset = 0;
            self.partial.clear();
        }
        if len == self.offset {
            return vec![];
        }
        let mut buf = Vec::new();
        if read_range(&self.path, self.offset, &mut buf).is_err() {
            return vec![];
        }
        self.offset += buf.len() as u64;
        self.partial.extend_from_slice(&buf);
        let Some(last_nl) = self.partial.iter().rposition(|b| *b == b'\n') else { return vec![] };
        let rest = self.partial.split_off(last_nl + 1);
        let complete = std::mem::replace(&mut self.partial, rest);
        complete.split(|b| *b == b'\n').filter(|l| !l.is_empty()).map(|l| String::from_utf8_lossy(l).into_owned()).collect()
    }
}

fn read_range(path: &Path, offset: u64, buf: &mut Vec<u8>) -> std::io::Result<()> {
    let mut f = std::fs::File::open(path)?;
    f.seek(SeekFrom::Start(offset))?;
    // 一次最多读 8 MB，剩下的下一轮再读
    f.take(8 << 20).read_to_end(buf)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tail_reads_only_new_complete_lines_and_survives_rotation() {
        let p = std::env::temp_dir().join(format!("anchor-tail-{}.log", anchor_core::util::random_hex()));
        std::fs::write(&p, "old line\n").unwrap();
        let mut t = Tail::new(p.clone());
        assert!(t.read_lines().is_empty(), "启动前的内容不读");
        let append = |s: &str| {
            use std::io::Write;
            std::fs::OpenOptions::new().append(true).open(&p).unwrap().write_all(s.as_bytes()).unwrap();
        };
        append("a\nb\npart");
        assert_eq!(t.read_lines(), ["a", "b"]);
        append("ial 中文\n");
        assert_eq!(t.read_lines(), ["partial 中文"], "跨两次读取的行拼起来");
        // 轮转：文件变小，从头读
        std::fs::write(&p, "new\n").unwrap();
        assert_eq!(t.read_lines(), ["new"]);
        let _ = std::fs::remove_file(&p);
    }
}
