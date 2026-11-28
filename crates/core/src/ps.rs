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
    // 绝对路径：特权服务以 SYSTEM 运行，不能被 PATH 里的同名程序替换
    let mut cmd = Command::new(crate::win::system32(r"WindowsPowerShell\v1.0\powershell.exe"));
    cmd.args(["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", &b64]);
    // 后台进程（用户代理、服务）调用时不弹出控制台窗口
    std::os::windows::process::CommandExt::creation_flags(&mut cmd, 0x0800_0000);
    cmd.output().context("无法启动 powershell.exe")
}

/// 在后台启动脚本，不等它结束：不开窗口，不接标准输入输出，脱离调用方所在的作业对象（终端关掉也继续运行）。
pub fn spawn_detached(script: &str) -> Result<()> {
    use std::os::windows::process::CommandExt;
    use std::process::Stdio;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
    let utf16: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let b64 = base64::engine::general_purpose::STANDARD.encode(utf16);
    let spawn = |flags: u32| {
        Command::new(crate::win::system32(r"WindowsPowerShell\v1.0\powershell.exe"))
            .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", &b64])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(flags)
            .spawn()
    };
    spawn(CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB).or_else(|_| spawn(CREATE_NO_WINDOW)).context("无法启动 powershell.exe")?;
    Ok(())
}

/// 运行脚本，失败时把 stderr（为空时用退出码和 stdout 末尾）作为错误返回。
pub fn run_ok(script: &str) -> Result<String> {
    let out = run(script)?;
    let stdout = String::from_utf8_lossy(&out.stdout).trim_start_matches('\u{feff}').to_string();
    if !out.status.success() {
        bail!("PowerShell 执行失败：{}", failure_message(out.status.code(), &out.stdout, &out.stderr));
    }
    Ok(stdout)
}

/// 失败时 stdout 最多附带的行数和字符数
const TAIL_LINES: usize = 20;
const TAIL_CHARS: usize = 2000;

/// 失败原因：优先用 stderr；stderr 为空时给出退出码，再附上 stdout 的最后几行。
fn failure_message(code: Option<i32>, stdout: &[u8], stderr: &[u8]) -> String {
    let err = decode_output(stderr);
    if !err.trim().is_empty() {
        return err.trim().to_string();
    }
    let code = match code {
        // 负数和大于 255 的退出码多是 NTSTATUS / HRESULT，十六进制才查得到
        Some(c) if !(0..=255).contains(&c) => format!("退出码 {c}（0x{:08X}）", c as u32),
        Some(c) => format!("退出码 {c}"),
        None => "退出码未知".to_string(),
    };
    let out = decode_output(stdout);
    let lines: Vec<&str> = out.trim().lines().collect();
    let tail = lines[lines.len().saturating_sub(TAIL_LINES)..].join("\n");
    let skip = tail.chars().count().saturating_sub(TAIL_CHARS);
    let tail: String = tail.chars().skip(skip).collect();
    if tail.trim().is_empty() { code } else { format!("{code}；stdout 末尾：\n{}", tail.trim()) }
}

/// 把 PowerShell 写出的字节解成文字。
///
/// 脚本开头把输出设成 UTF-8，但在它生效之前出的错（PowerShell 自身启动失败、命令行参数不对）
/// 由宿主直接写出：有的是不带 BOM 的 UTF-16LE，有的是控制台代码页（中文 Windows 上是 GBK）。
/// 依次判断：UTF-16LE BOM 或 NUL 字节分布 → UTF-16LE；合法 UTF-8 → UTF-8；否则按 ANSI 代码页解码。
pub fn decode_output(bytes: &[u8]) -> String {
    decode_with_codepage(bytes, windows_sys::Win32::Globalization::CP_ACP)
}

fn decode_with_codepage(bytes: &[u8], codepage: u32) -> String {
    let text = if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        utf16le(rest)
    } else if looks_utf16le(bytes) {
        utf16le(bytes)
    } else {
        let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
        match std::str::from_utf8(bytes) {
            Ok(s) => s.to_string(),
            Err(_) => ansi(bytes, codepage).unwrap_or_else(|| String::from_utf8_lossy(bytes).into_owned()),
        }
    };
    text.trim_start_matches('\u{feff}').to_string()
}

/// UTF-8 和 GBK 文字里不会有 NUL；UTF-16LE 里的 ASCII 字符高字节是 0，落在奇数位置上。
fn looks_utf16le(bytes: &[u8]) -> bool {
    let odd = bytes.iter().skip(1).step_by(2).filter(|&&b| b == 0).count();
    let even = bytes.iter().step_by(2).filter(|&&b| b == 0).count();
    odd > 0 && odd > even
}

fn utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    String::from_utf16_lossy(&units)
}

/// 按指定代码页解码，失败返回 None。
fn ansi(bytes: &[u8], codepage: u32) -> Option<String> {
    use windows_sys::Win32::Globalization::MultiByteToWideChar;
    let len = i32::try_from(bytes.len()).ok()?;
    if len == 0 {
        return Some(String::new());
    }
    // SAFETY: 输入指针和长度来自同一个切片；第一次调用只求所需长度，第二次写入按该长度分配的缓冲区
    let n = unsafe { MultiByteToWideChar(codepage, 0, bytes.as_ptr(), len, std::ptr::null_mut(), 0) };
    if n <= 0 {
        return None;
    }
    let mut wide = vec![0u16; n as usize];
    let n = unsafe { MultiByteToWideChar(codepage, 0, bytes.as_ptr(), len, wide.as_mut_ptr(), n) };
    if n <= 0 {
        return None;
    }
    wide.truncate(n as usize);
    Some(String::from_utf16_lossy(&wide))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_escapes_single_quotes() {
        assert_eq!(quote(r"C:\it's\a.exe"), r"'C:\it''s\a.exe'");
    }

    /// 和服务日志里那条乱码同类的消息：PowerShell 启动失败，宿主直接写出 UTF-16LE
    const STARTUP_ERROR: &str =
        "Windows PowerShell 已终止，返回以下错误: \r\n    “System.Management.Automation.Utils”的类型初始值设定项引发异常。\r\n";

    fn utf16le_bytes(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    /// GBK 编码的“无法将"-File"参数”。不是合法 UTF-8（编译器的 invalid_from_utf8 检查也这么说），解码会走到代码页
    const GBK: &[u8] = &[
        0xce, 0xde, 0xb7, 0xa8, 0xbd, 0xab, 0x22, 0x2d, 0x46, 0x69, 0x6c, 0x65, 0x22, 0xb2, 0xce, 0xca, 0xfd,
    ];

    #[test]
    fn decodes_utf16le_with_bom() {
        let mut bytes = vec![0xFF, 0xFE];
        bytes.extend(utf16le_bytes(STARTUP_ERROR));
        assert_eq!(decode_with_codepage(&bytes, 936), STARTUP_ERROR);
    }

    #[test]
    fn decodes_utf16le_without_bom() {
        assert_eq!(decode_with_codepage(&utf16le_bytes(STARTUP_ERROR), 936), STARTUP_ERROR);
        // 低字节为 0 的汉字（“一”是 00 4E）不影响判断
        assert_eq!(decode_with_codepage(&utf16le_bytes("Get-NetFirewallRule 一条也没有"), 936), "Get-NetFirewallRule 一条也没有");
    }

    #[test]
    fn decodes_utf8_with_and_without_bom() {
        let s = "找不到规则组“AI Anchor”";
        assert_eq!(decode_with_codepage(s.as_bytes(), 936), s);
        let mut bom = vec![0xEF, 0xBB, 0xBF];
        bom.extend_from_slice(s.as_bytes());
        assert_eq!(decode_with_codepage(&bom, 936), s);
        assert_eq!(decode_with_codepage(b"", 936), "");
    }

    #[test]
    fn decodes_gbk_through_the_ansi_codepage() {
        // 指定 936 而不是 CP_ACP：测试结果不随运行机器的系统区域变化
        assert_eq!(decode_with_codepage(GBK, 936), "无法将\"-File\"参数");
    }

    #[test]
    fn failure_prefers_stderr() {
        let msg = failure_message(Some(1), b"ignored", &utf16le_bytes(STARTUP_ERROR));
        assert!(msg.starts_with("Windows PowerShell 已终止"), "{msg}");
        assert!(msg.ends_with("引发异常。"), "{msg}");
    }

    #[test]
    fn failure_without_stderr_shows_exit_code_and_stdout_tail() {
        assert_eq!(failure_message(Some(2), b"", b"  \r\n"), "退出码 2");
        assert_eq!(failure_message(Some(2), b"\xEF\xBB\xBFNONE\r\n", b""), "退出码 2；stdout 末尾：\nNONE");
        assert_eq!(failure_message(Some(-196608), b"", b""), "退出码 -196608（0xFFFD0000）");
        assert_eq!(failure_message(None, b"", b""), "退出码未知");

        let long: String = (1..=50).map(|i| format!("line {i}\r\n")).collect();
        let msg = failure_message(Some(1), long.as_bytes(), b"");
        let tail = msg.split_once('\n').unwrap().1;
        assert_eq!(tail.lines().count(), TAIL_LINES);
        assert!(tail.starts_with("line 31") && tail.ends_with("line 50"), "{tail}");

        let huge = "长".repeat(TAIL_CHARS * 2);
        let msg = failure_message(Some(1), huge.as_bytes(), b"");
        assert_eq!(msg.split_once('\n').unwrap().1.chars().count(), TAIL_CHARS);
    }
}
