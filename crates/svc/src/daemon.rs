//! 守卫维护：让防火墙守卫规则始终覆盖当前安装的 AI 程序版本。
//!
//! 触发：服务启动时、HKLM 应用包仓库变化时（应用安装或更新）、每 5 分钟轮询、收到 guard.refresh 请求时。
//! 要守卫的程序由服务自己按登记用户的配置文件目录和本机包仓库查找，不执行任何来自配置的路径；
//! 用户配置只用来决定守卫哪些程序（[apps]、[guard]），配置有误时沿用上一次有效的配置。

use anchor_core::apps::{self, Roots};
use anchor_core::config::{Config, Paths};
use anchor_core::guard::{self, Plan, RuleInfo};
use anchor_core::util::{exists_any, now_rfc3339};
use anchor_core::{ipc, log, ps, win};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

const MAX_CHANGES: usize = 50;
const MAX_PAUSE_MIN: u64 = 24 * 60;

pub struct Ctx {
    /// 安装时登记的用户
    pub user_sid: String,
    /// 该用户的 AI Anchor 数据目录（读取 anchor.toml）
    pub home: PathBuf,
    /// 该用户的配置文件目录（扫描按用户安装的程序）
    pub profile: PathBuf,
    /// 只计算不改规则（调试用，不需要管理员）
    pub dry_run: bool,
    pub poll: Duration,
}

#[derive(Debug, Clone, Serialize)]
pub struct Change {
    pub seq: u64,
    pub time: String,
    pub source: String,
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub time: String,
    pub source: String,
    pub ok: bool,
    pub error: Option<String>,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub dry_run: bool,
}

#[derive(Default)]
struct State {
    paused_until: Option<SystemTime>,
    last: Option<Report>,
    changes: VecDeque<Change>,
    seq: u64,
    plan: Option<Plan>,
    rules: Vec<RuleInfo>,
    config_error: Option<String>,
    /// 上一次能解析的配置文本
    good_config: Option<String>,
    /// 演练模式不写规则，每次算出的差异相同；只在差异变化时记一次
    last_dry: Option<(Vec<String>, Vec<String>)>,
}

pub struct Daemon {
    ctx: Ctx,
    st: Mutex<State>,
    /// 同一时间只做一次刷新
    busy: Mutex<()>,
}

impl Daemon {
    pub fn new(ctx: Ctx) -> Self {
        Self { ctx, st: Mutex::new(State::default()), busy: Mutex::new(()) }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// 读取用户配置。读不了或有误时沿用本次运行中上一次有效的配置；
    /// 一次都没读成功过就返回错误，调用方不改任何规则（不会因为配置写错而突然断掉用户没打算守卫的程序）。
    fn load_config(&self) -> Result<Config> {
        let paths = Paths { home: self.ctx.home.clone() };
        let read = std::fs::read_to_string(paths.config()).with_context(|| format!("读取 {} 失败", paths.config().display()));
        let parsed = read.and_then(|t| Config::parse(&t).map(|c| (c, t)));
        let mut st = self.state();
        match parsed {
            Ok((cfg, text)) => {
                st.config_error = None;
                st.good_config = Some(text);
                Ok(cfg)
            }
            Err(e) => {
                st.config_error = Some(format!("{e:#}"));
                match st.good_config.as_deref().and_then(|t| Config::parse(t).ok()) {
                    Some(cfg) => Ok(cfg),
                    None => bail!("配置不可用，守卫规则保持不变：{e:#}"),
                }
            }
        }
    }

    fn roots(&self) -> Roots {
        Roots::for_profile(&self.ctx.profile, user_path_dirs(&self.ctx.user_sid, &self.ctx.profile))
    }

    fn paused(&self) -> bool {
        self.state().paused_until.is_some_and(|t| t > SystemTime::now())
    }

    /// 刷新守卫规则。prune 为 true 时也删除期望之外的规则（anchor guard install 使用）。
    pub fn refresh(&self, source: &str, prune: bool) -> Result<Report> {
        let _busy = self.busy.lock().unwrap_or_else(|e| e.into_inner());
        let r = self.refresh_inner(source, prune);
        let report = match &r {
            Ok(rep) => rep.clone(),
            Err(e) => Report {
                time: now_rfc3339(),
                source: source.to_string(),
                ok: false,
                error: Some(format!("{e:#}")),
                added: vec![],
                removed: vec![],
                dry_run: self.ctx.dry_run,
            },
        };
        self.state().last = Some(report);
        r
    }

    fn refresh_inner(&self, source: &str, prune: bool) -> Result<Report> {
        let cfg = self.load_config()?;
        let plan = guard::plan_with(&cfg, &self.roots())?;
        let mut rules = guard::read_rules()?;
        let fp = guard::fingerprint(&plan.remote);
        let d = guard::diff(&plan.targets, &rules, &fp, prune, exists_any);
        let paused = self.paused();
        let added: Vec<String> = d.add.iter().map(|t| t.path.display().to_string()).collect();
        let removed: Vec<String> = d.remove.iter().map(|r| r.program.display().to_string()).collect();

        if !self.ctx.dry_run {
            if !d.is_empty() {
                ps::run_ok(&guard::apply_script(&d, &plan.remote, !paused)).context("写入守卫规则失败")?;
            }
            // 没在暂停却有停用的规则（被手动停用，或暂停期间服务重启）：恢复，保证失败即阻断
            let disabled = rules.iter().any(|r| !r.enabled);
            if !paused && disabled {
                ps::run_ok(&guard::set_enabled_script(true)).context("启用守卫规则失败")?;
                log::line("发现停用的守卫规则，已重新启用");
            }
            if !d.is_empty() || (!paused && disabled) {
                rules = guard::read_rules()?;
            }
        }

        let mut st = self.state();
        let repeated_dry = self.ctx.dry_run && st.last_dry.as_ref() == Some(&(added.clone(), removed.clone()));
        if self.ctx.dry_run {
            st.last_dry = Some((added.clone(), removed.clone()));
        }
        if !d.is_empty() && !repeated_dry {
            st.seq += 1;
            let change = Change { seq: st.seq, time: now_rfc3339(), source: source.to_string(), added: added.clone(), removed: removed.clone() };
            st.changes.push_back(change);
            while st.changes.len() > MAX_CHANGES {
                st.changes.pop_front();
            }
            let verb = if self.ctx.dry_run { "（演练，未写入）" } else { "" };
            log::line(&format!("守卫刷新{verb}（{source}）：新增 {added:?}，移除 {removed:?}"));
        }
        st.plan = Some(plan);
        st.rules = rules;
        Ok(Report { time: now_rfc3339(), source: source.to_string(), ok: true, error: None, added, removed, dry_run: self.ctx.dry_run })
    }

    pub fn pause(&self, minutes: u64) -> Result<Value> {
        if minutes == 0 || minutes > MAX_PAUSE_MIN {
            bail!("暂停时长需在 1 到 {MAX_PAUSE_MIN} 分钟之间");
        }
        let _busy = self.busy.lock().unwrap_or_else(|e| e.into_inner());
        if !self.ctx.dry_run {
            let out = ps::run_ok(&guard::set_enabled_script(false))?;
            if out.trim() == "NONE" {
                bail!("还没有守卫规则");
            }
        }
        let until = SystemTime::now() + Duration::from_secs(minutes * 60);
        self.state().paused_until = Some(until);
        let until = humantime::format_rfc3339_seconds(until).to_string();
        log::line(&format!("守卫已暂停，到 {until} 自动恢复"));
        Ok(json!({ "paused_until": until }))
    }

    pub fn resume(&self, why: &str) -> Result<Value> {
        let _busy = self.busy.lock().unwrap_or_else(|e| e.into_inner());
        if !self.ctx.dry_run {
            ps::run_ok(&guard::set_enabled_script(true))?;
        }
        self.state().paused_until = None;
        log::line(&format!("守卫已恢复（{why}）"));
        Ok(json!({ "resumed": true }))
    }

    pub fn status(&self) -> Value {
        let st = self.state();
        let (expected, skipped, missing, stale) = match &st.plan {
            Some(p) => {
                let gs = guard::status_from(st.rules.clone(), p.targets.clone());
                let t = |v: &[guard::Target]| v.iter().map(|t| json!({ "label": t.label, "path": t.path })).collect::<Vec<_>>();
                let sk: Vec<Value> = p.skipped.iter().map(|(l, path, why)| json!({ "label": l, "path": path, "why": why })).collect();
                let stale: Vec<Value> = gs.stale.iter().map(|r| json!(r.program)).collect();
                (t(&gs.expected), sk, t(&gs.missing), stale)
            }
            None => (vec![], vec![], vec![], vec![]),
        };
        let rules: Vec<Value> =
            st.rules.iter().map(|r| json!({ "name": r.name, "program": r.program, "enabled": r.enabled })).collect();
        json!({
            "version": anchor_core::VERSION,
            "user_sid": self.ctx.user_sid,
            "home": self.ctx.home,
            "dry_run": self.ctx.dry_run,
            "paused_until": st.paused_until.filter(|t| *t > SystemTime::now()).map(|t| humantime::format_rfc3339_seconds(t).to_string()),
            "rules": rules,
            "expected": expected,
            "missing": missing,
            "skipped": skipped,
            "stale": stale,
            "last_refresh": st.last,
            "changes": st.changes,
            "seq": st.seq,
            "config_error": st.config_error,
        })
    }

    fn handle(&self, req: ipc::Request) -> ipc::Response {
        let p = &req.params;
        let r = match req.method.as_str() {
            "guard.status" => {
                if p["fresh"].as_bool().unwrap_or(false) {
                    let _ = self.refresh("状态查询", false);
                }
                Ok(self.status())
            }
            "guard.refresh" => {
                let source = p["source"].as_str().unwrap_or("手动请求").chars().take(40).collect::<String>();
                self.refresh(&source, p["prune"].as_bool().unwrap_or(false)).map(|r| json!(r))
            }
            "guard.pause" => self.pause(p["minutes"].as_u64().unwrap_or(10)),
            "guard.resume" => self.resume("用户请求"),
            m => Err(anyhow::anyhow!("未知方法 {m}")),
        };
        ipc::Response::from_result(r)
    }
}

/// 登记用户的 PATH（用户环境变量 + 系统环境变量），用于查找命令行 AI 工具。
fn user_path_dirs(sid: &str, profile: &std::path::Path) -> Vec<PathBuf> {
    use winreg::RegKey;
    use winreg::enums::{HKEY_LOCAL_MACHINE, HKEY_USERS};
    let local = profile.join("AppData").join("Local");
    let roaming = profile.join("AppData").join("Roaming");
    let vars: [(&str, &std::path::Path); 3] = [("USERPROFILE", profile), ("LOCALAPPDATA", &local), ("APPDATA", &roaming)];
    let mut raw = Vec::new();
    if let Ok(k) = RegKey::predef(HKEY_USERS).open_subkey(format!(r"{sid}\Environment")) {
        raw.extend(k.get_value::<String, _>("Path").ok());
    }
    if let Ok(k) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment") {
        raw.extend(k.get_value::<String, _>("Path").ok());
    }
    raw.iter()
        .flat_map(|p| p.split(';'))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| PathBuf::from(win::expand_env(s, &vars)))
        .collect()
}

/// 运行守卫维护和管道服务，直到 stop 置位。
pub fn run(ctx: Ctx, stop: Arc<AtomicBool>, pipe_sddl: &str) -> Result<()> {
    let poll = ctx.poll;
    let daemon = Arc::new(Daemon::new(ctx));
    let listener = ipc::Listener::bind(ipc::SVC_PIPE, pipe_sddl)?;
    {
        let d = daemon.clone();
        let s = stop.clone();
        std::thread::spawn(move || listener.run(s, move |req| d.handle(req)));
    }
    log::line(&format!("anchor-svc {} 已启动；数据目录 {}", anchor_core::VERSION, daemon.ctx.home.display()));

    let watch = match win::RegWatch::hklm(apps::package_repository_key()) {
        Ok(w) => Some(w),
        Err(e) => {
            log::line(&format!("无法监视应用包仓库，只靠定时检查：{e:#}"));
            None
        }
    };
    // 服务启动：之前若处于暂停（暂停不跨重启），refresh 会把停用的规则恢复
    refresh_logged(&daemon, "服务启动");
    let mut next_poll = Instant::now() + poll;
    while !stop.load(Ordering::SeqCst) {
        let expired = daemon.state().paused_until.is_some_and(|t| t <= SystemTime::now());
        if expired && let Err(e) = daemon.resume("暂停到期") {
            log::line(&format!("恢复守卫失败：{e:#}"));
        }
        let changed = match &watch {
            Some(w) => w.wait(Duration::from_secs(1)),
            None => {
                std::thread::sleep(Duration::from_secs(1));
                false
            }
        };
        if changed {
            // 安装过程会连续改动登记表，等它稳定下来
            let settle = Instant::now() + Duration::from_secs(3);
            while Instant::now() < settle && !stop.load(Ordering::SeqCst) {
                if let Some(w) = &watch {
                    w.wait(Duration::from_millis(500));
                }
            }
            refresh_logged(&daemon, "应用安装或更新");
            next_poll = Instant::now() + poll;
        } else if Instant::now() >= next_poll {
            refresh_logged(&daemon, "定时检查");
            next_poll = Instant::now() + poll;
        }
    }
    ipc::wake(ipc::SVC_PIPE);
    log::line("anchor-svc 已停止");
    Ok(())
}

fn refresh_logged(d: &Daemon, source: &str) {
    if let Err(e) = d.refresh(source, false) {
        log::line(&format!("守卫刷新失败（{source}）：{e:#}"));
    }
}
