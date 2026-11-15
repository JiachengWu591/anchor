//! 把 anchor.toml 翻译成 sing-box 配置（面向 sing-box 1.12+ 的新格式：新 DNS 服务器写法、路由动作）。
//!
//! 结构：本机 mixed 入站 → exit（固定出口）→ detour 到 lines 组（urltest/selector）→ 各条线路。
//! 线路组切换只影响线路层，出口始终是同一个出站，所以 AI 服务看到的 IP 不变。
//!
//! 出口锁定（exit_lock）：AI 入站在 Clash 模式为 Lock 时拒绝新连接，内核以 Lock 模式启动，
//! 由用户代理核对出口 IP 与基线一致后经 Clash API 切到 Open。探测入站（带认证）不受锁定影响，
//! 用户代理和命令行经它核对出口。

use crate::config::{Config, LineMode, Paths};
use anyhow::Result;
use serde_json::{Value, json};

pub const TAG_IN: &str = "ai-in";
pub const TAG_PROBE: &str = "probe-in";
pub const TAG_EXIT: &str = "exit";
pub const TAG_LINES: &str = "lines";
pub const TAG_DIRECT: &str = "direct";
/// Clash 模式：AI 入站拒绝新连接
pub const MODE_LOCK: &str = "Lock";
/// Clash 模式：AI 入站放行
pub const MODE_OPEN: &str = "Open";

/// exit_lock：AI 通道以锁住状态启动，等用户代理核对出口后放行。
/// 只有用户代理守护内核时才打开；前台调试的 anchor up 没有人核对，不锁。
pub fn generate(cfg: &Config, paths: &Paths, exit_lock: bool) -> Result<Value> {
    let mut outbounds = Vec::new();

    let mut exit = cfg.exit.outbound.clone();
    exit.insert("tag".into(), json!(TAG_EXIT));
    if !cfg.lines.is_empty() {
        exit.insert("detour".into(), json!(TAG_LINES));
    }
    outbounds.push(Value::Object(exit));

    if !cfg.lines.is_empty() {
        let names = cfg.line_names();
        // keep_existing_conns：线路切换时不打断已有连接，回答到一半不会断。
        let interrupt = !cfg.switch.keep_existing_conns;
        outbounds.push(match cfg.switch.lines {
            LineMode::Auto => json!({
                "type": "urltest",
                "tag": TAG_LINES,
                "outbounds": names,
                "url": cfg.switch.probe_url,
                "interval": cfg.switch.probe_interval,
                "tolerance": cfg.switch.tolerance_ms,
                "interrupt_exist_connections": interrupt,
            }),
            LineMode::Manual => json!({
                "type": "selector",
                "tag": TAG_LINES,
                "outbounds": names,
                "default": names[0],
                "interrupt_exist_connections": interrupt,
            }),
        });
        for l in &cfg.lines {
            let mut o = l.outbound.clone();
            o.insert("tag".into(), json!(l.name.as_deref().unwrap_or_default()));
            outbounds.push(Value::Object(o));
        }
    }
    outbounds.push(json!({ "type": "direct", "tag": TAG_DIRECT }));

    let log_file = paths.log_dir().join("sing-box.log");
    let (user, pass) = cfg.probe_auth();

    let mut rules = vec![
        // 禁用 QUIC/HTTP3：强制走 TCP，连接行为稳定、可识别。
        json!({ "network": ["udp"], "port": [443], "action": "reject" }),
    ];
    let mut clash_api = json!({
        "external_controller": format!("127.0.0.1:{}", cfg.api_port()),
        "secret": cfg.core.api_secret,
    });
    if exit_lock {
        rules.push(json!({ "inbound": [TAG_IN], "clash_mode": MODE_LOCK, "action": "reject" }));
        // 这条与 final 等价；有它 Open 才会出现在 Clash API 的模式列表里，才能切过去
        rules.push(json!({ "inbound": [TAG_IN], "clash_mode": MODE_OPEN, "action": "route", "outbound": TAG_EXIT }));
        clash_api["default_mode"] = json!(MODE_LOCK);
    }

    Ok(json!({
        "log": {
            "level": cfg.core.log_level,
            "timestamp": true,
            "output": log_file.to_string_lossy(),
        },
        "dns": {
            // 只用于解析线路服务器的域名；AI 程序走 HTTP CONNECT，目标域名交给出口解析。
            "servers": [ { "type": "local", "tag": "local" } ],
            "final": "local",
        },
        "inbounds": [
            {
                "type": "mixed",
                "tag": TAG_IN,
                "listen": cfg.proxy.listen,
                "listen_port": cfg.proxy.port,
            },
            {
                "type": "mixed",
                "tag": TAG_PROBE,
                "listen": "127.0.0.1",
                "listen_port": cfg.probe_port(),
                "users": [ { "username": user, "password": pass } ],
            },
        ],
        "outbounds": outbounds,
        "route": {
            "rules": rules,
            // 进入本机端口的流量全部走固定出口，没有直连分支。
            "final": TAG_EXIT,
            "default_domain_resolver": "local",
        },
        // 不开 cache_file：它会记住上次的 Clash 模式，内核重启后就不再以 Lock 启动。
        "experimental": { "clash_api": clash_api },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXIT: &str = "[exit]\nname = \"e\"\ntype = \"socks\"\nserver = \"203.0.113.10\"\nserver_port = 1080\n";
    const TWO_LINES: &str = "[[lines]]\nname = \"a\"\ntype = \"socks\"\nserver = \"198.51.100.1\"\nserver_port = 1080\n\
                             [[lines]]\nname = \"b\"\ntype = \"socks\"\nserver = \"198.51.100.2\"\nserver_port = 1080\n";

    fn build(extra: &str) -> Value {
        build_with(extra, false)
    }

    fn build_with(extra: &str, lock: bool) -> Value {
        let cfg = Config::parse(&format!("{EXIT}{extra}")).unwrap();
        generate(&cfg, &Paths { home: r"C:\anchor-test".into() }, lock).unwrap()
    }

    fn tags(v: &Value) -> Vec<String> {
        v["outbounds"].as_array().unwrap().iter().map(|o| o["tag"].as_str().unwrap().to_string()).collect()
    }

    #[test]
    fn exit_is_chained_through_line_group() {
        let v = build(TWO_LINES);
        assert_eq!(tags(&v), ["exit", "lines", "a", "b", "direct"]);
        let ob = &v["outbounds"];
        assert_eq!(ob[0]["detour"], "lines");
        assert_eq!(ob[0]["server"], "203.0.113.10");
        assert!(ob[0].get("name").is_none(), "name 不应传给 sing-box");
        assert_eq!(ob[1]["type"], "urltest");
        assert_eq!(ob[1]["outbounds"], json!(["a", "b"]));
        assert_eq!(ob[1]["interrupt_exist_connections"], false);
        assert_eq!(v["route"]["final"], "exit");
        assert_eq!(v["inbounds"][0]["listen"], "127.0.0.1");
    }

    #[test]
    fn without_lines_exit_dials_directly() {
        let v = build("");
        assert_eq!(tags(&v), ["exit", "direct"]);
        assert!(v["outbounds"][0].get("detour").is_none());
    }

    #[test]
    fn manual_mode_uses_selector_with_first_line_default() {
        let v = build(&format!("{TWO_LINES}[switch]\nlines = \"manual\"\nkeep_existing_conns = false\n"));
        let g = &v["outbounds"][1];
        assert_eq!(g["type"], "selector");
        assert_eq!(g["default"], "a");
        assert_eq!(g["interrupt_exist_connections"], true);
    }

    #[test]
    fn quic_is_rejected() {
        let v = build("");
        let r = &v["route"]["rules"][0];
        assert_eq!(r["action"], "reject");
        assert_eq!(r["port"], json!([443]));
    }

    #[test]
    fn exit_lock_starts_locked_and_only_blocks_the_ai_inbound() {
        let v = build_with("[core]\napi_secret = \"s\"\n", true);
        let rules = v["route"]["rules"].as_array().unwrap();
        let lock = rules.iter().find(|r| r["clash_mode"] == MODE_LOCK).expect("锁定规则");
        assert_eq!(lock["action"], "reject");
        assert_eq!(lock["inbound"], json!([TAG_IN]), "探测入站不受锁定影响");
        assert!(rules.iter().any(|r| r["clash_mode"] == MODE_OPEN), "Open 要出现在模式列表里");
        assert_eq!(v["experimental"]["clash_api"]["default_mode"], MODE_LOCK);
        assert!(v["experimental"].get("cache_file").is_none(), "cache_file 会记住模式，不能开");

        // 不锁（anchor up）：没有模式规则，也不设默认模式
        let v = build("");
        assert!(v["route"]["rules"].as_array().unwrap().iter().all(|r| r.get("clash_mode").is_none()));
        assert!(v["experimental"]["clash_api"].get("default_mode").is_none());
    }

    #[test]
    fn probe_inbound_requires_auth() {
        let v = build("[core]\napi_secret = \"s\"\n");
        let probe = &v["inbounds"][1];
        assert_eq!(probe["tag"], TAG_PROBE);
        assert_eq!(probe["listen"], "127.0.0.1");
        assert_eq!(probe["listen_port"], 17892);
        let u = &probe["users"][0];
        assert_eq!(u["username"], "anchor");
        let pass = u["password"].as_str().unwrap();
        assert_eq!(pass.len(), 16);
        assert!(pass.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
