//! AI 规则集：AI 服务的域名清单。
//! 独立模式下 AI 程序整体走通道，用不到它；它给插件模式（mihomo / Clash Verge Rev）和 P1 的 TUN 兜底使用。
//! 只收 AI 服务自有域名，不收 Cloudflare、Sentry 这类通用域名，以免改变其他程序的出口。

use anyhow::{Result, bail};
use serde_json::json;

pub const AI_DOMAINS: &[&str] = &[
    // OpenAI / ChatGPT
    "openai.com",
    "chatgpt.com",
    "oaistatic.com",
    "oaiusercontent.com",
    "sora.com",
    // Anthropic / Claude
    "anthropic.com",
    "claude.ai",
    "claude.com",
    "claudeusercontent.com",
    // Cursor
    "cursor.com",
    "cursor.sh",
];

pub fn print(format: &str) -> Result<()> {
    match format {
        "singbox" => println!(
            "{}",
            serde_json::to_string_pretty(&json!({ "version": 2, "rules": [ { "domain_suffix": AI_DOMAINS } ] }))?
        ),
        "mihomo" => {
            println!("# mihomo rule-provider（behavior: domain, format: yaml）");
            println!("payload:");
            for d in AI_DOMAINS {
                println!("  - '+.{d}'");
            }
        }
        "list" => AI_DOMAINS.iter().for_each(|d| println!("{d}")),
        _ => bail!("未知格式 {format}：可选 singbox、mihomo、list"),
    }
    Ok(())
}
