//! 面板（P2）：点托盘图标打开的一个小窗口，显示 AI 通道的状态、卡在哪一段、最近的断联。
//!
//! 做法：用户代理在 127.0.0.1 的一个随机端口上提供网页，用 Edge 的应用窗口打开。
//!
//! - **用到时才监听**：第一次打开面板时才开端口；10 分钟没有请求就关掉，下次打开换一个端口。
//! - **只认本机、只认自己打开的窗口**：
//!   - 只监听 127.0.0.1；请求的 Host 必须是这个地址（防 DNS 重绑定）。
//!   - 打开面板的地址里带一次性的入场券（60 秒内有效，用一次就作废），网页拿它换一个会话令牌，
//!     之后每个请求都要带令牌。浏览器历史里留下的只是作废的入场券。
//!   - 改状态的请求（核对出口、重新加载配置等）还要求是 JSON 请求、来源是面板自己，别的网页发不出来。
//! - 面板能做的事：托盘菜单里已有的那几样，加上换线路、固定线路（和 anchor line 一样，直接生效）。
//!   换出口、登记基线只是替人打开命令窗口：要不要做，在那个窗口里看清楚再确认，网页自己完成不了。
//!   退出用户代理仍然只在托盘菜单里。
//! - 面板窗口已经开着时，再点托盘图标只把它切到前面，不再开一个。

mod http;
mod view;

use crate::actions;
use crate::lines::LineCmd;
use crate::shared::{Level, Shared};
use anchor_core::config::ExitEntry;
use anchor_core::log;
use anchor_core::stall::{self, NoticeCtx, Stuck};
use anchor_core::timeline::{Timeline, now_ms};
use anchor_core::uplink;
use anyhow::{Context, Result, bail};
use http::{ReadError, Request, Response};
use serde_json::{Value, json};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, UNIX_EPOCH};
use windows_sys::Win32::Foundation::{BOOL, HWND, LPARAM};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetClassNameW, GetWindowTextW, IsIconic, IsWindowVisible, SW_RESTORE, SetForegroundWindow, ShowWindow,
};

const INDEX_HTML: &str = include_str!("assets/index.html");
const APP_CSS: &str = include_str!("assets/app.css");
const APP_JS: &str = include_str!("assets/app.js");
const ICON_SVG: &str = include_str!("assets/icon.svg");

/// 这么久没有请求就停止监听
const IDLE_STOP: Duration = Duration::from_secs(600);
const TICKET_TTL: Duration = Duration::from_secs(60);
const MAX_SESSIONS: usize = 8;
const MAX_TICKETS: usize = 8;
const MAX_CONNS: usize = 16;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// 统计要查 7 天的数据，结果留这么久
const HISTORY_TTL: Duration = Duration::from_secs(20);
/// 各段最近一次探测只看这么久以内的
const LAST_PROBES_MS: i64 = 120_000;
/// 面板读到状态之后，窗口标题以这个开头（app.js 里拼的）。没读到状态、会话失效时标题只是“AI Anchor”。
const PANEL_TITLE: &str = "AI Anchor · ";
/// Edge 的窗口类名
const EDGE_CLASS: &str = "Chrome_WidgetWin_1";
const MAX_NAME: usize = 64;

/// 入场券和会话令牌。
#[derive(Default)]
struct Auth {
    tickets: Vec<(String, Instant)>,
    sessions: Vec<String>,
}

impl Auth {
    fn issue(&mut self, ticket: String, now: Instant) {
        self.tickets.retain(|(_, t)| now.duration_since(*t) < TICKET_TTL);
        if self.tickets.len() >= MAX_TICKETS {
            self.tickets.remove(0);
        }
        self.tickets.push((ticket, now));
    }

    /// 入场券有效就作废它，记下新的会话令牌。
    fn redeem(&mut self, ticket: &str, token: String, now: Instant) -> bool {
        self.tickets.retain(|(_, t)| now.duration_since(*t) < TICKET_TTL);
        let Some(i) = self.tickets.iter().position(|(t, _)| same(t, ticket)) else { return false };
        self.tickets.remove(i);
        if self.sessions.len() >= MAX_SESSIONS {
            self.sessions.remove(0);
        }
        self.sessions.push(token);
        true
    }

    fn allows(&self, token: &str) -> bool {
        self.sessions.iter().any(|s| same(s, token))
    }

    fn has_sessions(&self) -> bool {
        !self.sessions.is_empty()
    }
}

/// 比较两个令牌，用时不随内容变化。
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// 32 个十六进制字符，来自系统的随机数发生器。
fn random_token() -> Result<String> {
    use windows_sys::Win32::Security::Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom};
    let mut buf = [0u8; 16];
    let status = unsafe { BCryptGenRandom(std::ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
    if status != 0 {
        bail!("取不到随机数（BCryptGenRandom 0x{status:08x}）");
    }
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

struct Server {
    port: u16,
    auth: Mutex<Auth>,
    last_seen: Mutex<Instant>,
    /// 只读打开的时间线：统计查询不占用户代理写时间线的连接
    tl: Option<Timeline>,
    history: Mutex<Option<(Instant, Value)>>,
}

impl Server {
    fn touch(&self) {
        *self.last_seen.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
    }

    fn idle(&self) -> bool {
        self.last_seen.lock().unwrap_or_else(|e| e.into_inner()).elapsed() >= IDLE_STOP
    }
}

/// 面板服务的开关（放在 Shared 里）。没人用时里面是空的，不监听任何端口。
#[derive(Default)]
pub struct Panel {
    running: Mutex<Option<Arc<Server>>>,
}

impl Panel {
    /// 打开面板用的地址（带一张新的入场券）。服务没在运行就先启动。
    pub fn url(&self, sh: &Arc<Shared>) -> Result<String> {
        let mut g = self.running.lock().unwrap_or_else(|e| e.into_inner());
        let srv = match g.as_ref() {
            Some(s) => s.clone(),
            None => {
                let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).context("面板端口监听失败")?;
                let port = listener.local_addr()?.port();
                let srv = Arc::new(Server {
                    port,
                    auth: Mutex::new(Auth::default()),
                    last_seen: Mutex::new(Instant::now()),
                    tl: Timeline::open_read_only(&sh.paths.timeline_db()).ok(),
                    history: Mutex::new(None),
                });
                let (s, server) = (sh.clone(), srv.clone());
                std::thread::spawn(move || serve(s, server, listener));
                log::line(&format!("面板服务已启动：127.0.0.1:{port}"));
                *g = Some(srv.clone());
                srv
            }
        };
        srv.touch();
        let ticket = random_token()?;
        srv.auth.lock().unwrap_or_else(|e| e.into_inner()).issue(ticket.clone(), Instant::now());
        Ok(format!("http://127.0.0.1:{}/#k={ticket}", srv.port))
    }

    /// 这一次运行里有没有窗口换到过会话令牌。没有的话，桌面上即使有面板窗口也是上一次运行留下的，已经失效。
    fn has_session(&self) -> bool {
        let g = self.running.lock().unwrap_or_else(|e| e.into_inner());
        g.as_ref().is_some_and(|s| s.auth.lock().unwrap_or_else(|e| e.into_inner()).has_sessions())
    }

    /// 打开面板窗口；已经开着就把它切到前面。失败时发一条通知。
    pub fn open(&self, sh: &Arc<Shared>) -> Result<()> {
        if self.has_session() && focus_existing() {
            log::line("面板窗口已经开着，切到前面");
            return Ok(());
        }
        let r = self.url(sh).and_then(|url| launch(&url));
        if let Err(e) = &r {
            sh.notify(Level::Error, "无法打开面板", &format!("{e:#}"));
        }
        r
    }
}

/// 是不是开着的面板窗口：Edge 的应用窗口，标题就是网页标题。
/// 普通浏览器标签页的标题后面带“ - 浏览器名”，不算：那种窗口切到前面也不一定停在面板那一页。
fn is_panel_window(class: &str, title: &str) -> bool {
    class == EDGE_CLASS && title.starts_with(PANEL_TITLE) && !title.contains(" - ")
}

unsafe extern "system" fn find_panel(hwnd: HWND, out: LPARAM) -> BOOL {
    unsafe {
        if IsWindowVisible(hwnd) == 0 {
            return 1;
        }
        let (mut class, mut title) = ([0u16; 64], [0u16; 256]);
        let c = GetClassNameW(hwnd, class.as_mut_ptr(), class.len() as i32).max(0) as usize;
        let t = GetWindowTextW(hwnd, title.as_mut_ptr(), title.len() as i32).max(0) as usize;
        if is_panel_window(&String::from_utf16_lossy(&class[..c]), &String::from_utf16_lossy(&title[..t])) {
            *(out as *mut HWND) = hwnd;
            return 0;
        }
        1
    }
}

/// 把已经开着的面板窗口切到前面（最小化的先还原）。没有这样的窗口返回 false。
fn focus_existing() -> bool {
    let mut found: HWND = std::ptr::null_mut();
    unsafe {
        EnumWindows(Some(find_panel), &mut found as *mut HWND as LPARAM);
        if found.is_null() {
            return false;
        }
        if IsIconic(found) != 0 {
            ShowWindow(found, SW_RESTORE);
        }
        SetForegroundWindow(found);
    }
    true
}

fn edge_exe() -> Option<PathBuf> {
    ["ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"]
        .iter()
        .filter_map(|k| std::env::var_os(k).map(PathBuf::from))
        .map(|base| base.join("Microsoft").join("Edge").join("Application").join("msedge.exe"))
        .find(|p| p.is_file())
}

/// 用 Edge 的应用窗口（没有地址栏和标签页）打开；找不到 Edge 就交给默认浏览器。
fn launch(url: &str) -> Result<()> {
    if let Some(edge) = edge_exe() {
        let r = std::process::Command::new(&edge).arg(format!("--app={url}")).arg("--window-size=460,860").spawn();
        match r {
            Ok(_) => return Ok(()),
            Err(e) => log::line(&format!("用 Edge 打开面板失败，改用默认浏览器：{e}")),
        }
    }
    actions::open_url(url)
}

fn serve(sh: Arc<Shared>, srv: Arc<Server>, listener: TcpListener) {
    let _ = listener.set_nonblocking(true);
    let active = Arc::new(AtomicUsize::new(0));
    loop {
        if sh.stopping() {
            break;
        }
        {
            // 判断空闲和摘掉服务在同一把锁里做：url() 不会拿到一个马上要停的端口
            let mut g = sh.panel.running.lock().unwrap_or_else(|e| e.into_inner());
            if srv.idle() {
                *g = None;
                log::line("面板服务空闲 10 分钟，已停止监听");
                break;
            }
        }
        match listener.accept() {
            Ok((stream, peer)) => {
                if !peer.ip().is_loopback() || active.load(Ordering::SeqCst) >= MAX_CONNS {
                    continue;
                }
                active.fetch_add(1, Ordering::SeqCst);
                let (sh, srv, active) = (sh.clone(), srv.clone(), active.clone());
                std::thread::spawn(move || {
                    handle(&sh, &srv, stream);
                    active.fetch_sub(1, Ordering::SeqCst);
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(40)),
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    }
}

fn handle(sh: &Arc<Shared>, srv: &Server, mut stream: TcpStream) {
    // Windows 上 accept 出来的连接沿用监听端口的非阻塞设置
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let resp = match http::read_request(&mut stream) {
        Ok(req) => route(sh, srv, &req),
        Err(ReadError::TooLarge) => Response::error(413, "请求太大"),
        Err(ReadError::Bad) => Response::error(400, "看不懂的请求"),
        Err(ReadError::Io) => return,
    };
    http::write_response(&mut stream, &resp);
}

/// Host 必须是面板自己的地址：别的域名即使解析到 127.0.0.1 也不认。
fn host_ok(host: Option<&str>, port: u16) -> bool {
    host.is_some_and(|h| h == format!("127.0.0.1:{port}") || h == format!("localhost:{port}"))
}

/// 改状态的请求：浏览器带了 Origin 的话必须是面板自己，而且必须是 JSON（普通表单发不出 JSON）。
fn post_ok(req: &Request, port: u16) -> Result<(), Response> {
    if let Some(o) = req.header("origin")
        && o != format!("http://127.0.0.1:{port}")
        && o != format!("http://localhost:{port}")
    {
        return Err(Response::error(403, "来源不对"));
    }
    if !req.header("content-type").is_some_and(|c| c.to_ascii_lowercase().starts_with("application/json")) {
        return Err(Response::error(415, "只接受 JSON"));
    }
    Ok(())
}

fn authed(req: &Request, srv: &Server) -> bool {
    let token = req.header("authorization").and_then(|a| a.strip_prefix("Bearer ")).unwrap_or("");
    !token.is_empty() && srv.auth.lock().unwrap_or_else(|e| e.into_inner()).allows(token)
}

fn route(sh: &Arc<Shared>, srv: &Server, req: &Request) -> Response {
    if !host_ok(req.header("host"), srv.port) {
        return Response::error(403, "只能从本机用 127.0.0.1 访问");
    }
    let api = req.path.starts_with("/api/");
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/" | "/index.html") => Response::asset("text/html; charset=utf-8", INDEX_HTML),
        ("GET", "/app.css") => Response::asset("text/css; charset=utf-8", APP_CSS),
        ("GET", "/app.js") => Response::asset("text/javascript; charset=utf-8", APP_JS),
        ("GET", "/icon.svg") => Response::asset("image/svg+xml", ICON_SVG),
        ("POST", "/api/session") => match post_ok(req, srv.port) {
            Err(r) => r,
            Ok(()) => session(srv, &req.body),
        },
        (_, _) if api && !authed(req, srv) => Response::error(401, "面板会话已失效，请从托盘图标重新打开"),
        ("GET", "/api/state") => {
            srv.touch();
            Response::json(200, &state(sh, srv))
        }
        ("GET", "/api/history") => {
            srv.touch();
            match history(sh, srv) {
                Ok(v) => Response::json(200, &v),
                Err(e) => Response::error(503, &format!("{e:#}")),
            }
        }
        ("POST", "/api/action") => match post_ok(req, srv.port) {
            Err(r) => r,
            Ok(()) => {
                srv.touch();
                action(sh, &req.body)
            }
        },
        ("GET" | "POST", _) => Response::error(404, "没有这个地址"),
        _ => Response::error(405, "不支持的方法"),
    }
}

fn session(srv: &Server, body: &[u8]) -> Response {
    let ticket = serde_json::from_slice::<Value>(body).ok().and_then(|v| v["ticket"].as_str().map(str::to_string)).unwrap_or_default();
    let Ok(token) = random_token() else { return Response::error(503, "取不到随机数") };
    if ticket.is_empty() || !srv.auth.lock().unwrap_or_else(|e| e.into_inner()).redeem(&ticket, token.clone(), Instant::now()) {
        return Response::error(403, "入场券无效或已经用过，请从托盘图标重新打开面板");
    }
    srv.touch();
    Response::json(200, &json!({ "token": token }))
}

fn state(sh: &Arc<Shared>, srv: &Server) -> Value {
    let now = now_ms();
    let st = sh.status().clone();
    let (level, summary) = crate::shared::summarize(&st);
    let health = *sh.local_health();
    let cfg = sh.config();
    let bind_if = cfg
        .as_ref()
        .and_then(|c| c.exit.outbound.get("bind_interface").and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string));
    let bind_if_down = bind_if.as_deref().is_some_and(|name| !uplink::iface_connected(name));
    let exit_on_route = cfg.as_ref().is_some_and(|c| anchor_core::singbox::is_direct_exit(c) && c.lines.is_empty());
    let has_backup = cfg.as_ref().is_some_and(|c| c.exits.len() > 1);

    // 卡在哪一段：用户代理提醒过就用它的判断，否则按手头的探测结果现算一个
    let exit = &st.exit;
    let exit_down = exit.locked && exit.exit_down && !matches!(exit.state.as_str(), "open" | "changed" | "unverifiable" | "no_baseline" | "");
    let stuck = if exit_down {
        let mut h = health;
        h.exit_if_down = bind_if_down;
        exit.stuck.as_deref().and_then(Stuck::from_name).or_else(|| stall::diagnose(&h, None, exit_on_route))
    } else {
        None
    };

    let last = srv.tl.as_ref().and_then(|t| t.last_probes(now - LAST_PROBES_MS).ok()).unwrap_or_default();
    let segs = view::path(&view::PathIn {
        now_ms: now,
        last: &last,
        has_uplink: health.uplink.map(|r| r.ok),
        via_vpn: health.via_vpn,
        vpn_seen: health.vpn_seen,
        bind_if: bind_if.as_deref(),
        bind_if_down,
        st: &st,
    });
    let ch = view::channel(&st, stuck, &NoticeCtx { bind_if: bind_if.as_deref(), has_backup });
    let culprit = view::culprit(&segs, ch.state == "open", stuck);
    let about = view::About {
        version: anchor_core::VERSION,
        pid: std::process::id(),
        started_ms: sh.started.duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0),
        home: sh.paths.home.display().to_string(),
    };
    let facts: Vec<Value> = view::facts(&st, &about).into_iter().map(|(k, v)| json!({ "k": k, "v": v })).collect();
    let controls = view::Controls {
        baseline_needed: view::baseline_needed(&st),
        lines: view::lines(sh.lines_view.lock().unwrap_or_else(|e| e.into_inner()).as_ref()),
        exits: cfg.as_ref().map(|c| view::exits(&c.exits)).unwrap_or_default(),
    };
    json!({
        "now_ms": now,
        "level": match level { Level::Info => "info", Level::Warn => "warn", Level::Error => "error" },
        "summary": summary,
        "channel": ch,
        "path": segs,
        "culprit": culprit,
        "facts": facts,
        "controls": controls,
    })
}

fn history(sh: &Arc<Shared>, srv: &Server) -> Result<Value> {
    let mut cache = srv.history.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((at, v)) = cache.as_ref()
        && at.elapsed() < HISTORY_TTL
    {
        return Ok(v.clone());
    }
    let v = match &srv.tl {
        Some(tl) => view::history(tl, now_ms())?,
        None => view::history(&sh.tl, now_ms())?,
    };
    *cache = Some((Instant::now(), v.clone()));
    Ok(v)
}

fn action(sh: &Arc<Shared>, body: &[u8]) -> Response {
    let v = serde_json::from_slice::<Value>(body).unwrap_or(Value::Null);
    let name = v["action"].as_str().unwrap_or_default();
    // 线路名、出口名
    let arg = v["name"].as_str().map(str::trim).unwrap_or_default();
    let done = |text: &str| Response::json(200, &json!({ "message": text }));
    match name {
        "recheck" => {
            actions::recheck(sh);
            done("已请求立即核对出口：AI 通道先锁住，与基线一致后放行")
        }
        "reload" => {
            actions::reload(sh);
            done("正在重新加载配置，内核会按新配置重启，几秒内恢复")
        }
        "check" => run(sh, &["check"], "已在新窗口里运行体检"),
        "report" => run(sh, &["report", "--since", "7d", "--list"], "已在新窗口里打开 7 天的断联报告"),
        "timeline" => run(sh, &["timeline", "--since", "24h"], "已在新窗口里打开最近 24 小时的时间线"),
        "folder" => match actions::open_folder(sh) {
            Ok(()) => done("已打开数据目录"),
            Err(e) => Response::error(503, &format!("{e:#}")),
        },
        "line.use" => line(sh, arg, LineCmd::Use),
        "line.pin" => line(sh, arg, LineCmd::Pin),
        "line.unpin" => line_reply(crate::api::line_cmd(sh, LineCmd::Unpin)),
        "exit.use" => exit_use(sh, arg),
        "baseline" => run(sh, &["baseline"], "已在新窗口里测量现在的出口。看清测到的 IP，在那个窗口里确认之后才会登记为基线"),
        _ => Response::error(400, "没有这个操作"),
    }
}

/// 换线、固定线路：和 anchor line use / pin 走同一条路，交给线路控制器，认不认识这个名字由它判断。
fn line(sh: &Arc<Shared>, arg: &str, make: fn(String) -> LineCmd) -> Response {
    if arg.is_empty() || arg.chars().count() > MAX_NAME {
        return Response::error(400, "缺少线路名");
    }
    line_reply(crate::api::line_cmd(sh, make(arg.to_string())))
}

fn line_reply(r: Result<Value>) -> Response {
    match r {
        Ok(v) => Response::json(200, &json!({ "message": v["message"].as_str().unwrap_or("完成") })),
        Err(e) => Response::error(409, &format!("{e:#}")),
    }
}

/// 只接受配置里有、而且不是正在用的出口名。
fn pick_exit(exits: &[ExitEntry], arg: &str) -> Result<String, String> {
    match exits.iter().find(|e| e.name == arg) {
        None => Err("没有这个出口".into()),
        Some(e) if e.active => Err(format!("已经在用出口 {}", e.name)),
        // 名字会作为命令行参数交给 anchor exit use：以 - 开头的会被当成选项
        Some(e) if e.name.starts_with('-') => Err(format!("出口名 {} 以 - 开头，面板里换不了", e.name)),
        Some(e) => Ok(e.name.clone()),
    }
}

/// 换出口要先关掉正在运行的 AI 程序，还要人确认：面板只负责打开命令窗口，问答都在那个窗口里。
fn exit_use(sh: &Arc<Shared>, arg: &str) -> Response {
    let Some(cfg) = sh.config() else { return Response::error(409, "配置还没有读出来") };
    match pick_exit(&cfg.exits, arg) {
        Err(msg) => Response::error(400, &msg),
        Ok(name) => run(
            sh,
            &["exit", "use", &name],
            &format!("已在新窗口里开始切换到出口 {name}：要关闭哪些 AI 程序、是否继续，在那个窗口里确认"),
        ),
    }
}

fn run(sh: &Arc<Shared>, args: &[&str], ok: &str) -> Response {
    match actions::run_cli(sh, args) {
        Ok(()) => Response::json(200, &json!({ "message": ok })),
        Err(e) => Response::error(503, &format!("{e:#}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(method: &str, path: &str, headers: &[(&str, &str)]) -> Request {
        Request {
            method: method.into(),
            path: path.into(),
            headers: headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            body: Vec::new(),
        }
    }

    #[test]
    fn tickets_work_once_and_expire() {
        let t0 = Instant::now();
        let mut a = Auth::default();
        a.issue("ticket-1".into(), t0);
        assert!(!a.redeem("wrong", "tok".into(), t0));
        assert!(a.redeem("ticket-1", "tok-1".into(), t0));
        assert!(!a.redeem("ticket-1", "tok-2".into(), t0), "入场券只能用一次");
        assert!(a.allows("tok-1") && !a.allows("tok-2") && !a.allows(""));

        a.issue("ticket-2".into(), t0);
        assert!(!a.redeem("ticket-2", "tok-3".into(), t0 + TICKET_TTL), "过期的入场券不认");

        // 会话多了，最早的作废
        for i in 0..MAX_SESSIONS {
            a.issue(format!("t{i}"), t0);
            assert!(a.redeem(&format!("t{i}"), format!("s{i}"), t0));
        }
        assert!(!a.allows("tok-1") && a.allows("s0"));
    }

    #[test]
    fn tokens_are_random_hex() {
        let (a, b) = (random_token().unwrap(), random_token().unwrap());
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
        assert!(same("abc", "abc") && !same("abc", "abd") && !same("abc", "ab"));
    }

    #[test]
    fn only_the_panels_own_address_is_accepted() {
        assert!(host_ok(Some("127.0.0.1:5000"), 5000));
        assert!(host_ok(Some("localhost:5000"), 5000));
        assert!(!host_ok(Some("127.0.0.1:5001"), 5000));
        assert!(!host_ok(Some("evil.example:5000"), 5000), "解析到本机的别的域名（DNS 重绑定）");
        assert!(!host_ok(Some("127.0.0.1"), 5000));
        assert!(!host_ok(None, 5000));
    }

    #[test]
    fn state_changing_requests_must_come_from_the_panel() {
        let json = ("content-type", "application/json");
        assert!(post_ok(&req("POST", "/api/action", &[json]), 5000).is_ok(), "不带 Origin 的本机请求");
        assert!(post_ok(&req("POST", "/api/action", &[json, ("origin", "http://127.0.0.1:5000")]), 5000).is_ok());
        let other = post_ok(&req("POST", "/api/action", &[json, ("origin", "https://evil.example")]), 5000);
        assert_eq!(other.err().map(|r| r.status), Some(403));
        let form = post_ok(&req("POST", "/api/action", &[("content-type", "text/plain"), ("origin", "http://127.0.0.1:5000")]), 5000);
        assert_eq!(form.err().map(|r| r.status), Some(415), "网页表单发不出 JSON");
    }

    #[test]
    fn only_an_open_panel_window_is_brought_forward() {
        assert!(is_panel_window(EDGE_CLASS, "AI Anchor · 已放行"));
        assert!(is_panel_window(EDGE_CLASS, "AI Anchor · 已锁住"));
        assert!(!is_panel_window(EDGE_CLASS, "AI Anchor"), "还没读到状态，或者会话已失效的窗口");
        assert!(!is_panel_window(EDGE_CLASS, "AI Anchor · 已放行 - 个人 - Microsoft Edge"), "普通浏览器里的一个标签页");
        assert!(!is_panel_window("CabinetWClass", "AI Anchor · 已放行"), "不是浏览器窗口");
        assert!(!is_panel_window(EDGE_CLASS, "别的网页"));
        // 网页标题是这么拼的
        assert!(APP_JS.contains("document.title = 'AI Anchor · '"));
        assert!(APP_JS.contains("document.title = 'AI Anchor';"), "会话失效时标题改回去，不会再被当成开着的面板");
    }

    #[test]
    fn only_a_configured_exit_that_is_not_in_use_can_be_switched_to() {
        let e = |name: &str, active: bool| ExitEntry { name: name.into(), label: String::new(), baseline_ip: String::new(), active, primary: active };
        let exits = [e("home", true), e("backup", false), e("-y", false)];
        assert_eq!(pick_exit(&exits, "backup"), Ok("backup".to_string()));
        assert!(pick_exit(&exits, "home").unwrap_err().contains("已经在用"));
        assert!(pick_exit(&exits, "nope").unwrap_err().contains("没有这个出口"));
        assert!(pick_exit(&exits, "").is_err());
        assert!(pick_exit(&exits, "backup --yes").is_err(), "名字要和配置里的一模一样");
        assert!(pick_exit(&exits, "-y").unwrap_err().contains("以 - 开头"), "不会被当成命令行选项传出去");
    }

    #[test]
    fn the_page_loads_only_its_own_files() {
        // 内容安全策略不许内联脚本和样式：页面里不能有
        assert!(!INDEX_HTML.contains("<script>") && !INDEX_HTML.contains("<style") && !INDEX_HTML.contains(" style="));
        assert!(!INDEX_HTML.contains(" onclick=") && !INDEX_HTML.contains("javascript:"));
        assert!(INDEX_HTML.contains("src=\"/app.js\"") && INDEX_HTML.contains("href=\"/app.css\""));
        // 数据一律当文字放进页面，不拼 HTML
        assert!(!APP_JS.contains("innerHTML") && !APP_JS.contains("document.write") && !APP_JS.contains("eval("));
        assert!(!INDEX_HTML.contains("http://") && !INDEX_HTML.contains("https://"), "不引用外部资源");
        assert!(!APP_CSS.contains("url(http"));
    }
}
