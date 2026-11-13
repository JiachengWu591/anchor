//! 线路看门狗：每隔 watch_interval 探测当前线路，失败时立即让 sing-box 重新选线。
//!
//! sing-box 的 urltest 只在定时检测时换线（默认 30 秒一次），连接失败不会立刻触发，
//! 当前线路断开后新连接会持续失败到下一轮检测。实测调用一次 Clash API 的组测速
//! （GET /group/lines/delay）就会重新选线，约 1 秒恢复。只动线路层，出口不变。

use crate::config::{Config, LineMode};
use crate::net::ClashApi;
use crate::util::now_rfc3339;
use serde_json::{Map, Value};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const PROBE_TIMEOUT_MS: u32 = 2500;

#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    /// 重新选线后换到了另一条线路
    Switched { from: String, to: String, ms: Option<u64> },
    /// 复测后仍是当前线路且可用：偶发失败
    Retested,
    /// 所有线路都测不通
    AllDown,
}

/// 当前线路探测失败、做完组测速后，判断发生了什么。
/// group：组测速结果（线路名 → 延迟，只含成功的）；now：组测速后的当前线路。
pub fn after_failure(current: &str, group: Option<&Map<String, Value>>, now: Option<&str>) -> Event {
    match group {
        Some(g) if !g.is_empty() => match now {
            Some(n) if n != current => Event::Switched {
                from: current.to_string(),
                to: n.to_string(),
                ms: g.get(n).and_then(Value::as_u64),
            },
            _ => Event::Retested,
        },
        _ => Event::AllDown,
    }
}

/// 有线路且没关闭看门狗时，启动后台线程；stop 置位后 200 毫秒内退出。
pub fn spawn(cfg: &Config, stop: Arc<AtomicBool>) -> Option<Duration> {
    if cfg.lines.is_empty() {
        return None;
    }
    let every = cfg.switch.watch_every()?;
    let api = ClashApi::new(cfg);
    let url = cfg.switch.probe_url.clone();
    let manual = cfg.switch.lines == LineMode::Manual;
    thread::spawn(move || run(&api, &url, every, manual, &stop));
    Some(every)
}

fn run(api: &ClashApi, url: &str, every: Duration, manual: bool, stop: &AtomicBool) {
    // 已经报告过“不可用”，恢复前不再重复报告
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
        if api.delay(&current, url, PROBE_TIMEOUT_MS).is_ok() {
            if reported_down {
                println!("[{}] 线路已恢复，当前 {current}", now_rfc3339());
                reported_down = false;
            }
            continue;
        }
        if manual {
            if !reported_down {
                eprintln!(
                    "[{}] 线路 {current} 探测失败。手动模式不会自动切换；出口 IP 不变，新连接会失败，直到线路恢复或手动切换",
                    now_rfc3339()
                );
                reported_down = true;
            }
            continue;
        }
        let group = api.group_delay("lines", url, PROBE_TIMEOUT_MS).ok();
        let now = api.current_line();
        match after_failure(&current, group.as_ref(), now.as_deref()) {
            Event::Switched { from, to, ms } => {
                let ms = ms.map(|m| format!("，{m} ms")).unwrap_or_default();
                println!("[{}] 线路 {from} 探测失败，已切换到 {to}{ms}；出口 IP 不变", now_rfc3339());
                reported_down = false;
            }
            Event::Retested => {}
            Event::AllDown => {
                if !reported_down {
                    eprintln!(
                        "[{}] 所有线路都不可用（当前 {current} 探测失败）。出口 IP 不会因此改变；新连接会失败，直到有线路恢复",
                        now_rfc3339()
                    );
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
            Event::Switched { from: "line-a".into(), to: "line-b".into(), ms: Some(821) }
        );
    }

    #[test]
    fn transient_failure_keeps_line() {
        let g = map(json!({ "line-a": 300, "line-b": 900 }));
        assert_eq!(after_failure("line-a", Some(&g), Some("line-a")), Event::Retested);
    }

    #[test]
    fn empty_or_failed_group_test_means_all_down() {
        assert_eq!(after_failure("line-a", Some(&Map::new()), Some("line-a")), Event::AllDown);
        assert_eq!(after_failure("line-a", None, None), Event::AllDown);
    }
}
