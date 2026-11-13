//! 调用 Windows PowerShell 5.1。脚本以 -EncodedCommand 传入，避免中文和引号转义问题。

use anyhow::{Context, Result, bail};
use base64::Engine;
use std::process::{Command, Output};

/// PowerShell 单引号字符串字面量。
pub fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

pub fn run(script: &str) -> Result<Output> {
    let full = format!(
        "$ProgressPreference = 'SilentlyContinue'\n\
         [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false\n\
         {script}"
    );
    let utf16: Vec<u8> = full.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let b64 = base64::engine::general_purpose::STANDARD.encode(utf16);
    Command::new("powershell.exe")
        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", &b64])
        .output()
        .context("无法启动 powershell.exe")
}

/// 运行脚本，失败时把 stderr 作为错误返回。
pub fn run_ok(script: &str) -> Result<String> {
    let out = run(script)?;
    let stdout = String::from_utf8_lossy(&out.stdout).trim_start_matches('\u{feff}').to_string();
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let err = if err.trim().is_empty() { format!("退出码 {}", out.status.code().unwrap_or(-1)) } else { err.trim().to_string() };
        bail!("PowerShell 执行失败：{err}");
    }
    Ok(stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_escapes_single_quotes() {
        assert_eq!(quote(r"C:\it's\a.exe"), r"'C:\it''s\a.exe'");
    }
}
