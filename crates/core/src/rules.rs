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

/// 是否 AI 服务自有的域名（本身或子域名）。断联只统计这些：AI 程序也会访问别的网站，那些站点出错不算通道的问题。
pub fn is_ai_domain(host: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    AI_DOMAINS.iter().any(|d| h == *d || h.ends_with(&format!(".{d}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ai_domain_matching() {
        assert!(is_ai_domain("claude.ai"));
        assert!(is_ai_domain("API.Anthropic.com."));
        assert!(is_ai_domain("bridge.claudeusercontent.com"));
        assert!(!is_ai_domain("notclaude.ai"), "后缀要按标签匹配");
        assert!(!is_ai_domain("http-intake.logs.us5.datadoghq.com"));
        assert!(!is_ai_domain("api.github.com"));
    }
}

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
