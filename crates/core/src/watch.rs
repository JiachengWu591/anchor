//! 线路看门狗：每隔 watch_interval 探测当前线路，失败时立即让 sing-box 重新选线。
//!
//! sing-box 的 urltest 只在定时检测时换线（默认 30 秒一次），连接失败不会立刻触发，
//! 当前线路断开后新连接会持续失败到下一轮检测。实测调用一次 Clash API 的组测速
//! （GET /group/lines/delay）就会重新选线，约 1 秒恢复。只动线路层，出口不变。

use crate::config::{Config, LineMode};
use crate::net::ClashApi;
use serde_json::{Map, Value};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const PROBE_TIMEOUT_MS: u32 = 2500;

/// 当前线路探测失败、做完组测速后的判断结果。
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// 重新选线后换到了另一条线路
    Switched { from: String, to: String, ms: Option<u64> },
    /// 复测后仍是当前线路且可用：偶发失败
    Retested,
    /// 所有线路都测不通
    AllDown,
}

/// 看门狗报告的事件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchEvent {
    /// 一次协议级探测
    Probe { line: String, ok: bool, ms: Option<u64>, note: String },
    /// 当前线路失败，已换到另一条
    Switched { from: String, to: String, ms: Option<u64> },
    /// 手动模式下当前线路探测失败（不自动切换）
    LineDown { line: String },
    /// 所有线路都不可用（恢复前只报告一次）
    AllDown { line: String },
    /// 报告过故障之后，线路恢复可用
    Recovered { line: String },
}

/// group：组测速结果（线路名 → 延迟，只含成功的）；now：组测速后的当前线路。
pub fn after_failure(current: &str, group: Option<&Map<String, Value>>, now: Option<&str>) -> Outcome {
    match group {
        Some(g) if !g.is_empty() => match now {
            Some(n) if n != current => Outcome::Switched {
                from: current.to_string(),
                to: n.to_string(),
                ms: g.get(n).and_then(Value::as_u64),
            },
            _ => Outcome::Retested,
        },
        _ => Outcome::AllDown,
    }
}

/// 有线路且没关闭看门狗时，启动后台线程；stop 置位后 200 毫秒内退出。
pub fn spawn<F>(cfg: &Config, stop: Arc<AtomicBool>, on: F) -> Option<(Duration, JoinHandle<()>)>
where
    F: FnMut(WatchEvent) + Send + 'static,
{
    if cfg.lines.is_empty() {
        return None;
    }
    let every = cfg.switch.watch_every()?;
    let api = ClashApi::new(cfg);
    let url = cfg.switch.probe_url.clone();
    let manual = cfg.switch.lines == LineMode::Manual;
    let lines: Vec<String> = cfg.line_names().into_iter().map(String::from).collect();
    let h = thread::spawn(move || run(&api, &url, &lines, every, manual, &stop, on));
    Some((every, h))
}

fn run(
    api: &ClashApi,
    url: &str,
    lines: &[String],
    every: Duration,
    manual: bool,
    stop: &AtomicBool,
    mut on: impl FnMut(WatchEvent),
) {
    // 已经报告过故障，恢复前不再重复报告
    let mut reported_down = false;
    let mut next = Instant::now() + every;
    while !stop.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(200));
        if Instant::now() < next {
            continue;
        }
        next = Instant::now() + every;
        // 内核正在启动或重启时 API 不可用，跳过这一轮
        let Some(current) = api.current_line() else { continue };
        match api.delay(&current, url, PROBE_TIMEOUT_MS) {
            Ok(ms) => {
                on(WatchEvent::Probe { line: current.clone(), ok: true, ms: Some(ms), note: String::new() });
                if reported_down {
                    on(WatchEvent::Recovered { line: current });
                    reported_down = false;
                }
                continue;
            }
            Err(e) => {
                // 正在停止，或内核这时退出了（API 也不通）：不算线路故障，内核由守护进程处理
                if stop.load(Ordering::SeqCst) || api.current_line().is_none() {
                    continue;
                }
                on(WatchEvent::Probe { line: current.clone(), ok: false, ms: None, note: format!("{e:#}") })
            }
        }
        if manual {
            if !reported_down {
                on(WatchEvent::LineDown { line: current });
                reported_down = true;
            }
            continue;
        }
        let group = api.group_delay("lines", url, PROBE_TIMEOUT_MS).ok();
        let now = api.current_line();
        if stop.load(Ordering::SeqCst) || now.is_none() {
            continue;
        }
        if let Some(g) = &group {
            for l in lines {
                let ms = g.get(l).and_then(Value::as_u64);
                on(WatchEvent::Probe { line: l.clone(), ok: ms.is_some(), ms, note: "组测速".into() });
            }
        }
        match after_failure(&current, group.as_ref(), now.as_deref()) {
            Outcome::Switched { from, to, ms } => {
                on(WatchEvent::Switched { from, to: to.clone(), ms });
                // 之前报告过全部不可用：换到的线路可用，也就是恢复了
                if reported_down {
                    on(WatchEvent::Recovered { line: to });
                }
                reported_down = false;
            }
            Outcome::Retested => {}
            Outcome::AllDown => {
                if !reported_down {
                    on(WatchEvent::AllDown { line: current });
                    reported_down = true;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn map(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn switch_when_group_picks_another_line() {
        let g = map(json!({ "line-b": 821 }));
        assert_eq!(
            after_failure("line-a", Some(&g), Some("line-b")),
            Outcome::Switched { from: "line-a".into(), to: "line-b".into(), ms: Some(821) }
        );
    }

    #[test]
    fn transient_failure_keeps_line() {
        let g = map(json!({ "line-a": 300, "line-b": 900 }));
        assert_eq!(after_failure("line-a", Some(&g), Some("line-a")), Outcome::Retested);
    }

    #[test]
    fn empty_or_failed_group_test_means_all_down() {
        assert_eq!(after_failure("line-a", Some(&Map::new()), Some("line-a")), Outcome::AllDown);
        assert_eq!(after_failure("line-a", None, None), Outcome::AllDown);
    }
}
