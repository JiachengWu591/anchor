//! 把 anchor.toml 翻译成 sing-box 配置（面向 sing-box 1.12+ 的新格式：新 DNS 服务器写法、路由动作）。
//!
//! 结构：本机 mixed 入站 → exit（固定出口）→ detour 到 lines 组（urltest/selector）→ 各条线路。
//! 线路组切换只影响线路层，出口始终是同一个出站，所以 AI 服务看到的 IP 不变。

use crate::config::{Config, LineMode, Paths};
use anyhow::Result;
use serde_json::{Value, json};

pub const TAG_IN: &str = "ai-in";
pub const TAG_EXIT: &str = "exit";
pub const TAG_LINES: &str = "lines";
pub const TAG_DIRECT: &str = "direct";

pub fn generate(cfg: &Config, paths: &Paths) -> Result<Value> {
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
    let cache_file = paths.run_dir().join("cache.db");

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
        "inbounds": [ {
            "type": "mixed",
            "tag": TAG_IN,
            "listen": cfg.proxy.listen,
            "listen_port": cfg.proxy.port,
        } ],
        "outbounds": outbounds,
        "route": {
            "rules": [
                // 禁用 QUIC/HTTP3：强制走 TCP，连接行为稳定、可识别。
                { "network": ["udp"], "port": [443], "action": "reject" },
            ],
            // 进入本机 AI 端口的流量全部走固定出口，没有直连分支。
            "final": TAG_EXIT,
            "default_domain_resolver": "local",
        },
        "experimental": {
            "cache_file": { "enabled": true, "path": cache_file.to_string_lossy() },
            "clash_api": {
                "external_controller": format!("127.0.0.1:{}", cfg.api_port()),
                "secret": cfg.core.api_secret,
            },
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXIT: &str = "[exit]\nname = \"e\"\ntype = \"socks\"\nserver = \"203.0.113.10\"\nserver_port = 1080\n";
    const TWO_LINES: &str = "[[lines]]\nname = \"a\"\ntype = \"socks\"\nserver = \"198.51.100.1\"\nserver_port = 1080\n\
                             [[lines]]\nname = \"b\"\ntype = \"socks\"\nserver = \"198.51.100.2\"\nserver_port = 1080\n";

    fn build(extra: &str) -> Value {
        let cfg = Config::parse(&format!("{EXIT}{extra}")).unwrap();
        generate(&cfg, &Paths { home: r"C:\anchor-test".into() }).unwrap()
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
}
