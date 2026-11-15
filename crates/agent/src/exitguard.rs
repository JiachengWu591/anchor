//! 出口核对与锁定的执行者（每次会话一个线程）。
//!
//! 状态机在 anchor_core::exitlock：它决定什么时候问哪个 IP 回显服务、结果意味着什么。这里负责：
//! - 经探测入站去问回显服务（另起线程，主循环不被网络请求卡住，网络一变化就能立刻锁住）；
//! - 经 Clash API 把 AI 入站切到 Lock / Open，并在内核重启后重新应用；
//! - 记时间线、发通知、更新托盘和 anchor status 看到的状态。

use crate::shared::{KernelState, Level, Shared};
use anchor_core::config::Config;
use anchor_core::exitlock::{self, Action, Check, Machine, Severity, Timing, Trigger};
use anchor_core::log;
use anchor_core::net::{self, ClashApi};
use anchor_core::singbox::{MODE_LOCK, MODE_OPEN, TAG_EXIT};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// 回显服务一次请求的超时；出口本身通不通的测试超时。
const ECHO_TIMEOUT: Duration = Duration::from_secs(4);
const EXIT_PROBE_TIMEOUT_MS: u32 = 3000;
/// 一次网络变化通常带来一串通知（地址、路由先删后加）：最后一条之后静默这么久再核对，
/// 免得在隧道切换到一半时核对，也免得反复丢弃进行中的核对。
const NET_SETTLE: Duration = Duration::from_millis(500);
/// 回显连接失败后，最多再等“出口通不通”的结果这么久。隧道刚恢复时连接会立即失败，
/// 出口测试却要等到它自己的超时；为它干等会把每次重试拖慢 3 秒。
const EXIT_PROBE_GRACE: Duration = Duration::from_secs(1);
/// 锁着时，进行中的核对超过这么久没结果，就换一个来源再并发一个，最多 MAX_INFLIGHT 个。
/// 实测：隧道路由回来后的头几秒，连接要么立即失败、要么卡到超时（4 秒）；
/// 只跑一个的话，卡住的那个会把下一次尝试推迟到隧道早已可用之后。
const HEDGE_AFTER: Duration = Duration::from_secs(1);
const MAX_INFLIGHT: usize = 3;

/// 核对用的来源：纯 IP 回显服务在前（高频核对用它们），带地理信息的服务在后。
pub fn sources(cfg: &Config) -> Vec<String> {
    let mut v: Vec<String> = cfg.check.ip_echo.iter().filter(|u| !u.trim().is_empty()).cloned().collect();
    if !cfg.check.ip_info.trim().is_empty() {
        v.push(cfg.check.ip_info.clone());
    }
    v
}

pub fn spawn(sh: Arc<Shared>, cfg: &Config, stop: Arc<AtomicBool>, kernel_gen: Arc<AtomicU64>) -> JoinHandle<()> {
    let ctx = Ctx {
        api: Arc::new(ClashApi::new(cfg)),
        probe: net::agent_via_probe(cfg, ECHO_TIMEOUT).ok().map(Arc::new),
        probe_url: cfg.switch.probe_url.clone(),
        sources: sources(cfg),
        baseline: cfg.expect.ip.trim().to_string(),
        timing: Timing::new(cfg.switch.exit_check_every()),
    };
    thread::spawn(move || run(&sh, &ctx, &stop, &kernel_gen))
}

struct Ctx {
    api: Arc<ClashApi>,
    probe: Option<Arc<ureq::Agent>>,
    probe_url: String,
    sources: Vec<String>,
    baseline: String,
    timing: Timing,
}

/// 正在进行的一次核对：结果通道（结果和耗时）、来源、发起时间，以及发起时的内核代数和网络代数。
struct Inflight {
    rx: Receiver<(Check, Duration)>,
    source: usize,
    started: Instant,
    kernel_gen: u64,
    net_gen: u64,
    /// 已经结束：Some(Some(结果)) 拿到结果，Some(None) 线程没给结果就退出了
    done: Option<Option<(Check, Duration)>>,
}

/// 现在该不该再发起一个核对，用哪个来源。due：状态机想要核对时给出的来源。
/// 没有进行中的就直接用它；锁着、最新的一个也超过 HEDGE_AFTER 还没结果，就换一个没在用的来源并发。
fn next_check(due: Option<usize>, locked: bool, inflight: &[(usize, Duration)], sources: usize) -> Option<usize> {
    let due = due?;
    if inflight.is_empty() {
        return Some(due);
    }
    let limit = MAX_INFLIGHT.min(sources);
    if !locked || inflight.len() >= limit || inflight.iter().any(|(_, age)| *age < HEDGE_AFTER) {
        return None;
    }
    (0..sources).map(|i| (due + i) % sources).find(|s| !inflight.iter().any(|(busy, _)| busy == s))
}

fn run(sh: &Arc<Shared>, ctx: &Ctx, stop: &AtomicBool, kernel_gen: &AtomicU64) {
    let n = if ctx.probe.is_some() { ctx.sources.len() } else { 0 };
    let (mut m, actions) = Machine::new(&ctx.baseline, n, ctx.timing, Instant::now());
    let mut locked = true;
    apply(sh, actions, &mut locked);
    if n == 0 && !ctx.baseline.is_empty() {
        log::line("出口核对：没有可用的 IP 回显服务（[check] ip_echo / ip_info），AI 通道保持锁住");
    }

    let mut seen_kernel = kernel_gen.load(Ordering::SeqCst);
    let mut seen_net = sh.net_gen.load(Ordering::SeqCst);
    let mut seen_poke = sh.pokes();
    // 已经让哪一代内核处于什么模式；内核重启后要重新设置
    let mut applied: Option<(u64, bool)> = None;
    let mut last_err = String::new();
    let mut inflight: Vec<Inflight> = Vec::new();
    let mut settle_until = Instant::now();

    // 每次触发都丢掉进行中的核对：它走的可能是旧路径，等它超时只会拖慢放行
    while !stop.load(Ordering::SeqCst) {
        let now = Instant::now();
        let kg = kernel_gen.load(Ordering::SeqCst);
        if kg != seen_kernel {
            seen_kernel = kg;
            inflight.clear();
            apply(sh, m.trigger(now, Trigger::KernelStart), &mut locked);
        }
        let ng = sh.net_gen.load(Ordering::SeqCst);
        if ng != seen_net {
            log::line(if m.state().locked() {
                "网络变化（AI 通道已锁住，平息后重新核对）"
            } else {
                "网络变化：先锁住 AI 通道，核对出口后再放行"
            });
            seen_net = ng;
            inflight.clear();
            settle_until = now + NET_SETTLE;
            apply(sh, m.trigger(now, Trigger::NetworkChange), &mut locked);
        }
        if sh.recheck.swap(false, Ordering::SeqCst) {
            inflight.clear();
            apply(sh, m.trigger(now, Trigger::Recheck), &mut locked);
        }

        let running = sh.status().kernel == KernelState::Running;
        if running && applied != Some((seen_kernel, locked)) {
            let mode = if locked { MODE_LOCK } else { MODE_OPEN };
            match ctx.api.set_mode(mode) {
                Ok(()) => {
                    applied = Some((seen_kernel, locked));
                    last_err.clear();
                    log::line(&format!("AI 通道已{}", if locked { "锁住" } else { "放行" }));
                }
                Err(e) => {
                    let msg = format!("{e:#}");
                    if msg != last_err {
                        log::line(&format!("切换 AI 通道到 {mode} 失败，稍后重试：{msg}"));
                        last_err = msg;
                    }
                }
            }
        }

        // 收核对结果，一次处理一个。发起之后内核重启或网络变化过，结果可能是旧路径的，丢掉
        for f in inflight.iter_mut().filter(|f| f.done.is_none()) {
            match f.rx.try_recv() {
                Ok(r) => f.done = Some(Some(r)),
                Err(TryRecvError::Disconnected) => f.done = Some(None),
                Err(TryRecvError::Empty) => {}
            }
        }
        if let Some(i) = inflight.iter().position(|f| f.done.is_some()) {
            let f = inflight.swap_remove(i);
            if let Some(Some((check, took))) = f.done
                && f.kernel_gen == seen_kernel
                && f.net_gen == seen_net
                && !stop.load(Ordering::SeqCst)
            {
                // 锁着时每次都记，放行时只记不一致和失败，便于事后看清放行慢在哪里
                if m.state().locked() || check != Check::Match {
                    log::line(&format!("出口核对：{} → {}（{} ms）", ctx.sources[f.source], describe(&check), took.as_millis()));
                }
                let before = m.state();
                apply(sh, m.on_check(Instant::now(), f.source, check), &mut locked);
                // 状态变了（放行、确认已变化……）：其余并发的核对是按旧状态发起的，
                // 迟到的失败不能再把刚放行的通道锁上，全部丢掉
                if m.state() != before {
                    inflight.clear();
                }
            }
            continue;
        }
        // 内核在运行、模式已经设好、网络变化已经平息，才发起新的核对
        if running
            && now >= settle_until
            && applied == Some((seen_kernel, locked))
            && let Some(probe) = &ctx.probe
        {
            let busy: Vec<(usize, Duration)> = inflight.iter().map(|f| (f.source, now.saturating_duration_since(f.started))).collect();
            if let Some(src) = next_check(m.due(now), m.state().locked(), &busy, ctx.sources.len()) {
                inflight.push(start_check(sh, ctx, probe.clone(), src, m.state().locked(), seen_kernel, seen_net));
            }
        }

        sh.status().exit = m.view(Instant::now());
        seen_poke = sh.wait_poke(seen_poke, Duration::from_millis(250));
    }
}

/// locked：锁着时同时测出口本身通不通，回显失败时不必再等一轮；放行时只在回显失败后才测。
fn start_check(
    sh: &Arc<Shared>,
    ctx: &Ctx,
    probe: Arc<ureq::Agent>,
    source: usize,
    locked: bool,
    kernel_gen: u64,
    net_gen: u64,
) -> Inflight {
    let (tx, rx) = mpsc::channel();
    let url = ctx.sources[source].clone();
    let baseline = ctx.baseline.clone();
    let probe_url = ctx.probe_url.clone();
    let api = ctx.api.clone();
    let sh = sh.clone();
    thread::spawn(move || {
        let started = Instant::now();
        let exit_probe = |api: Arc<ClashApi>, url: String| move || api.delay(TAG_EXIT, &url, EXIT_PROBE_TIMEOUT_MS).is_ok();
        let parallel = locked.then(|| {
            let (ptx, prx) = mpsc::channel();
            let f = exit_probe(api.clone(), probe_url.clone());
            thread::spawn(move || {
                let _ = ptx.send(f());
            });
            prx
        });
        let check = match net::get(&probe, &url) {
            // 拿到了响应：出口肯定通，只是回显服务出了问题（状态码、内容不对）
            Ok(r) => match net::parse_echo(&r) {
                Ok(ip) => exitlock::classify(&baseline, &ip),
                Err(e) => Check::Failed { exit_up: true, reason: format!("{url}：{e:#}") },
            },
            // 连接没建立：看出口本身通不通（经内核测整条链路）
            Err(e) => {
                let exit_up = match parallel {
                    Some(rx) => rx.recv_timeout(EXIT_PROBE_GRACE).unwrap_or(false),
                    None => exit_probe(api, probe_url)(),
                };
                Check::Failed { exit_up, reason: format!("{e:#}") }
            }
        };
        let _ = tx.send((check, started.elapsed()));
        sh.poke();
    });
    Inflight { rx, source, started: Instant::now(), kernel_gen, net_gen, done: None }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: Duration = Duration::from_secs(1);

    #[test]
    fn hedges_only_while_locked_and_after_the_newest_check_stalls() {
        assert_eq!(next_check(Some(0), true, &[], 3), Some(0), "没有进行中的：按状态机给的来源");
        assert_eq!(next_check(None, true, &[], 3), None, "状态机不要求核对");
        // 锁着，进行中的已经 1 秒没结果：换一个没在用的来源并发
        assert_eq!(next_check(Some(0), true, &[(0, S)], 3), Some(1));
        assert_eq!(next_check(Some(0), true, &[(0, 2 * S), (1, S)], 3), Some(2));
        // 最新的一个还不到 1 秒：等等
        assert_eq!(next_check(Some(0), true, &[(0, 2 * S), (1, S / 2)], 3), None);
        // 放行时不并发；最多 3 个；不超过来源个数
        assert_eq!(next_check(Some(0), false, &[(0, 5 * S)], 3), None);
        assert_eq!(next_check(Some(0), true, &[(0, 3 * S), (1, 2 * S), (2, S)], 3), None);
        assert_eq!(next_check(Some(0), true, &[(0, 5 * S)], 1), None);
    }
}

fn describe(c: &Check) -> String {
    match c {
        Check::Match => "与基线一致".into(),
        Check::Mismatch(ip) => format!("不一致，回显 {ip}"),
        Check::Failed { exit_up, reason } => format!("失败（出口{}）：{reason}", if *exit_up { "可达" } else { "不可达" }),
    }
}

fn apply(sh: &Shared, actions: Vec<Action>, locked: &mut bool) {
    for a in actions {
        match a {
            Action::Lock => *locked = true,
            Action::Unlock => *locked = false,
            Action::Event(kind, detail) => {
                log::line(&format!("出口：{kind} {detail}"));
                sh.tl.event(kind, detail);
            }
            Action::Notify(sev, title, body) => {
                let level = match sev {
                    Severity::Info => Level::Info,
                    Severity::Warn => Level::Warn,
                    Severity::Error => Level::Error,
                };
                sh.notify(level, &title, &body);
            }
        }
    }
}
