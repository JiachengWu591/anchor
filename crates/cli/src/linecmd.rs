//! anchor line：看各线路的评分，手动换线，固定线路。都交给用户代理里的线路控制器（P1b）。

use crate::agentctl;
use crate::util::pad;
use anyhow::{Result, anyhow};
use serde_json::{Value, json};

fn call(method: &str, params: Value) -> Result<Value> {
    agentctl::call(method, params).map_err(|e| anyhow!("anchor-agent {e}"))
}

pub fn list(as_json: bool) -> Result<()> {
    let v = call("line.list", Value::Null)?;
    if as_json {
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        print(&v);
    }
    Ok(())
}

pub fn use_line(name: &str) -> Result<()> {
    done(call("line.use", json!({ "name": name }))?)
}

pub fn pin(name: &str) -> Result<()> {
    done(call("line.pin", json!({ "name": name }))?)
}

pub fn unpin() -> Result<()> {
    done(call("line.unpin", Value::Null)?)
}

fn done(v: Value) -> Result<()> {
    println!("{}", v["message"].as_str().unwrap_or("完成"));
    Ok(())
}

fn mode_text(v: &Value) -> String {
    match v["mode"].as_str().unwrap_or("") {
        "pinned" => format!("固定在 {}，不自动换线", v["pinned"].as_str().unwrap_or("?")),
        "manual" => "手动模式，不自动换线".into(),
        _ => "自动换线".into(),
    }
}

/// 一条线路一行：标记、名称、优先级、5 分钟成功率、延迟中位数、最近一次探测。
pub fn rows(v: &Value) -> Vec<[String; 6]> {
    let empty = Vec::new();
    v["lines"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .map(|l| {
            let mark = match (l["current"].as_bool().unwrap_or(false), l["pinned"].as_bool().unwrap_or(false)) {
                (true, true) => "当前·固定",
                (true, false) => "当前",
                (false, true) => "固定",
                _ => "",
            };
            let n = l["samples"].as_u64().unwrap_or(0);
            let rate = l["rate"].as_f64().map(|r| format!("{:.0}%（{n} 次）", r * 100.0)).unwrap_or_else(|| "—".into());
            let median = l["median_ms"].as_u64().map(|m| format!("{m} ms")).unwrap_or_else(|| "—".into());
            let last = match (l["last_ok"].as_bool(), l["last_ms"].as_u64()) {
                (Some(true), Some(ms)) => format!("通，{ms} ms"),
                (Some(true), None) => "通".into(),
                (Some(false), _) => "不通".into(),
                _ => "还没测".into(),
            };
            let prio = l["priority"].as_u64().map(|p| p.to_string()).unwrap_or_else(|| "—".into());
            [mark.to_string(), l["name"].as_str().unwrap_or("?").to_string(), prio, rate, median, last]
        })
        .collect()
}

fn print(v: &Value) {
    println!("线路  {}{}\n", mode_text(v), if v["all_down"].as_bool().unwrap_or(false) { "；所有线路都不可用" } else { "" });
    let w = [12, 18, 8, 16, 12];
    println!("{}{}{}{}{}最近一次", pad("", w[0]), pad("名称", w[1]), pad("优先级", w[2]), pad("5 分钟成功率", w[3]), pad("延迟中位数", w[4]));
    for r in rows(v) {
        println!("{}{}{}{}{}{}", pad(&r[0], w[0]), pad(&r[1], w[1]), pad(&r[2], w[2]), pad(&r[3], w[3]), pad(&r[4], w[4]), r[5]);
    }
    println!("\n换线：anchor line use <名称>；固定：anchor line pin <名称>，取消：anchor line unpin");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_from_the_agent_view() {
        let v = json!({
            "mode": "pinned", "pinned": "b", "current": "b", "all_down": false,
            "lines": [
                { "name": "a", "priority": 1, "current": false, "pinned": false, "samples": 10, "rate": 0.8, "median_ms": 120, "last_ok": false, "last_ms": null },
                { "name": "b", "priority": null, "current": true, "pinned": true, "samples": 0, "rate": null, "median_ms": null, "last_ok": null, "last_ms": null },
            ]
        });
        let r = rows(&v);
        assert_eq!(r[0], ["", "a", "1", "80%（10 次）", "120 ms", "不通"].map(String::from));
        assert_eq!(r[1], ["当前·固定", "b", "—", "—", "—", "还没测"].map(String::from));
        assert!(mode_text(&v).contains("固定在 b"));
    }
}
