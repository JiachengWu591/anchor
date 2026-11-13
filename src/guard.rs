//! 防火墙守卫：按程序路径写入持久化的 Windows 防火墙出站规则。
//!
//! Windows 防火墙里阻断规则优先于放行规则，所以不能写“放行回环 + 阻断全部”。
//! 做法是一条阻断规则，远程地址取“允许范围”的补集：程序只能连 127.0.0.0/8 和 ::1，
//! 连不了任何其他地址。内核没运行时，AI 程序因此没有网络，而不是直连。
//! FakeIP 段默认不放行：它只给 AI Anchor 自己的 TUN 兜底（P1）使用，而且常与 VPN 网段重叠。

use crate::apps::{self, Kind};
use crate::config::Config;
use crate::{netenv, ps};
use crate::util::{confirm, exists_any, same_path};
use anyhow::{Context, Result, bail};
use std::collections::HashSet;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::process::{Command, Stdio};

pub const GROUP: &str = "AI Anchor Guard";

/// 这些程序不只被 AI 使用，守卫会断掉它们的日常联网，拒绝加入。
const FORBIDDEN: &[&str] = &[
    "msedge.exe", "chrome.exe", "firefox.exe", "node.exe", "bun.exe", "deno.exe", "python.exe",
    "pythonw.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "svchost.exe", "explorer.exe", "git.exe",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix: u8,
}

pub fn parse_cidr(s: &str) -> Result<Cidr> {
    let (a, p) = s.trim().split_once('/').context("缺少 /前缀长度")?;
    let addr: IpAddr = a.parse().context("IP 地址格式错误")?;
    let prefix: u8 = p.parse().context("前缀长度格式错误")?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        bail!("前缀长度超出范围");
    }
    Ok(Cidr { addr, prefix })
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

pub fn overlaps(a: &Cidr, b: &Cidr) -> bool {
    if a.addr.is_ipv4() != b.addr.is_ipv4() {
        return false;
    }
    let ((s1, e1), (s2, e2)) = (range_of(a), range_of(b));
    s1 <= e2 && s2 <= e1
}

fn range_of(c: &Cidr) -> (u128, u128) {
    let (base, bits) = match c.addr {
        IpAddr::V4(a) => (u32::from(a) as u128, 32u32),
        IpAddr::V6(a) => (u128::from(a), 128u32),
    };
    let host_bits = bits - c.prefix as u32;
    let mask: u128 = if host_bits >= 128 { u128::MAX } else { (1u128 << host_bits) - 1 };
    let start = base & !mask;
    (start, start | mask)
}

/// [0, max] 去掉 allowed 后剩下的区间。
pub fn complement(mut allowed: Vec<(u128, u128)>, max: u128) -> Vec<(u128, u128)> {
    allowed.sort();
    let mut out = Vec::new();
    let mut next: Option<u128> = Some(0);
    for (s, e) in allowed {
        let Some(n) = next else { break };
        if s > n {
            out.push((n, s - 1));
        }
        if e >= n {
            next = if e >= max { None } else { Some(e + 1) };
        }
    }
    if let Some(n) = next {
        out.push((n, max));
    }
    out
}

/// 守卫规则要阻断的远程地址（Windows 防火墙的地址区间写法）。
/// fakeip 为 Some 时额外放行该段，仅供 AI Anchor 自己的 TUN 使用。
pub fn blocked_remote(fakeip: Option<&str>) -> Result<Vec<String>> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    let mut allowed = vec!["127.0.0.0/8", "::1/128"];
    allowed.extend(fakeip);
    for a in allowed {
        let c = parse_cidr(a)?;
        if c.addr.is_ipv4() { v4.push(range_of(&c)) } else { v6.push(range_of(&c)) }
    }
    let f4 = |x: u128| Ipv4Addr::from(x as u32).to_string();
    let f6 = |x: u128| Ipv6Addr::from(x).to_string();
    let mut out = Vec::new();
    for (s, e) in complement(v4, u32::MAX as u128) {
        out.push(if s == e { f4(s) } else { format!("{}-{}", f4(s), f4(e)) });
    }
    for (s, e) in complement(v6, u128::MAX) {
        // 单独的 "::"（未指定地址）不可能是连接目标，部分系统不接受它作为规则地址，跳过。
        if s == 0 && e == 0 {
            continue;
        }
        out.push(if s == e { f6(s) } else { format!("{}-{}", f6(s), f6(e)) });
    }
    Ok(out)
}

#[derive(Debug, Clone)]
pub struct Target {
    pub label: String,
    pub path: PathBuf,
}

pub struct Plan {
    pub targets: Vec<Target>,
    /// (名称, 路径, 原因)
    pub skipped: Vec<(String, PathBuf, String)>,
    pub allowed: Vec<String>,
    pub remote: Vec<String>,
}

/// 开启 allow_fakeip 时，FakeIP 段不能与本机任何网卡的网段重叠（VPN、其他 TUN 常用 198.18.0.0/15 一带）。
fn fakeip_allowance(cfg: &Config) -> Result<Option<&str>> {
    if !cfg.guard.allow_fakeip {
        return Ok(None);
    }
    let range = parse_cidr(&cfg.guard.fakeip_range)?;
    if let Some((alias, net)) = netenv::local_subnets().into_iter().find(|(_, n)| overlaps(n, &range)) {
        bail!(
            "[guard] fakeip_range {range} 与本机网卡“{alias}”的网段 {net} 重叠（通常是 VPN 或其他代理的 TUN）。\
             放行它会让 AI 程序能绕过通道直接访问该网段。请把 allow_fakeip 设为 false，或换一个不重叠的 fakeip_range"
        );
    }
    Ok(Some(cfg.guard.fakeip_range.as_str()))
}

pub fn plan(cfg: &Config) -> Result<Plan> {
    let enabled: HashSet<&str> = cfg.apps.desktop.iter().chain(cfg.apps.cli.iter()).map(String::as_str).collect();
    let mut targets: Vec<Target> = Vec::new();
    let mut skipped = Vec::new();
    for f in apps::scan() {
        if !enabled.contains(f.id) {
            continue;
        }
        if !f.guardable {
            skipped.push((f.label.to_string(), f.exe.clone(), f.note.clone()));
            continue;
        }
        if !targets.iter().any(|t| same_path(&t.path, &f.exe)) {
            let kind = if f.kind == Kind::Desktop { "桌面" } else { "命令行" };
            targets.push(Target { label: format!("{}（{kind}，{}）", f.label, f.id), path: f.exe });
        }
    }
    for p in &cfg.guard.extra_programs {
        let path = PathBuf::from(p);
        let file = path.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
        if FORBIDDEN.contains(&file.as_str()) {
            bail!("[guard] extra_programs 不能包含 {file}：它不只被 AI 使用，守卫会断掉它的日常联网");
        }
        if !targets.iter().any(|t| same_path(&t.path, &path)) {
            targets.push(Target { label: format!("自定义：{file}"), path });
        }
    }
    let fakeip = fakeip_allowance(cfg)?;
    let mut allowed = vec!["127.0.0.0/8".to_string(), "::1".to_string()];
    allowed.extend(fakeip.map(|f| format!("{f}（FakeIP）")));
    Ok(Plan { targets, skipped, allowed, remote: blocked_remote(fakeip)? })
}

pub fn print_plan(plan: &Plan) {
    println!("将守卫 {} 个程序（只允许连接本机 AI 通道）：", plan.targets.len());
    for t in &plan.targets {
        let flag = if exists_any(&t.path) { "" } else { "  [文件不存在]" };
        println!("  - {}\n    {}{flag}", t.label, t.path.display());
    }
    if !plan.skipped.is_empty() {
        println!("无法按程序守卫（已跳过）：");
        for (label, path, why) in &plan.skipped {
            println!("  - {label}：{}\n    {why}", path.display());
        }
    }
    println!("只放行：{}", plan.allowed.join("、"));
    println!("阻断的远程地址：{}", plan.remote.join(", "));
}

/// 取出本组规则到 $rules；组不存在时得到空数组，其他错误（如权限）照常抛出。
fn load_rules_ps() -> String {
    format!(
        "try {{ $rules = @(Get-NetFirewallRule -Group {} -ErrorAction Stop) }} \
         catch {{ if ($_.CategoryInfo.Category -eq 'ObjectNotFound') {{ $rules = @() }} else {{ throw }} }}",
        ps::quote(GROUP)
    )
}

pub fn install_script(plan: &Plan) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "$ErrorActionPreference = 'Stop'");
    let _ = writeln!(s, "$group = {}", ps::quote(GROUP));
    let _ = writeln!(s, "{}", load_rules_ps());
    let _ = writeln!(s, "if ($rules.Count) {{ $rules | Remove-NetFirewallRule }}");
    let remote: Vec<String> = plan.remote.iter().map(|r| ps::quote(r)).collect();
    let _ = writeln!(s, "$remote = @({})", remote.join(", "));
    let desc = ps::quote("只允许经本机 AI 通道联网。由 AI Anchor 管理，用 anchor guard remove 移除。");
    for t in &plan.targets {
        let _ = writeln!(
            s,
            "New-NetFirewallRule -DisplayName {} -Group $group -Direction Outbound -Action Block -Program {} \
             -RemoteAddress $remote -Profile Any -Description {desc} | Out-Null",
            ps::quote(&format!("AI Anchor Guard: {}", t.label)),
            ps::quote(&t.path.to_string_lossy()),
        );
    }
    s
}

fn require_admin() -> Result<()> {
    let ok = Command::new("net")
        .arg("session")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        bail!("需要管理员权限：请在“以管理员身份运行”的终端里执行这条命令");
    }
    Ok(())
}

pub fn install(cfg: &Config) -> Result<()> {
    let plan = plan(cfg)?;
    print_plan(&plan);
    if plan.targets.is_empty() {
        bail!("没有可守卫的程序：检查 anchor.toml 的 [apps]，或运行 anchor scan 查看本机程序");
    }
    require_admin()?;
    ps::run_ok(&install_script(&plan))?;
    println!("\n已写入 {} 条守卫规则（防火墙规则组“{GROUP}”），重启后仍然有效。", plan.targets.len());
    println!("提醒：MSIX / Squirrel 安装的应用更新后路径会变，更新后请重新运行 anchor guard install；anchor check 会提示未覆盖的程序。");
    Ok(())
}

pub fn remove(yes: bool) -> Result<()> {
    if !yes && !confirm(&format!("将删除防火墙规则组“{GROUP}”中的全部规则，AI 程序恢复为可直连。继续？[y/N] "))? {
        println!("未修改。");
        return Ok(());
    }
    require_admin()?;
    let n = ps::run_ok(&format!("{}\nif ($rules.Count) {{ $rules | Remove-NetFirewallRule }}\n$rules.Count", load_rules_ps()))?;
    println!("已移除 {} 条守卫规则。", n.trim());
    Ok(())
}

pub fn set_enabled(enabled: bool, yes: bool) -> Result<()> {
    if !enabled
        && !yes
        && !confirm("暂停守卫后，通道断开时 AI 程序可能直连，直到运行 anchor guard resume。继续？[y/N] ")?
    {
        println!("未修改。");
        return Ok(());
    }
    require_admin()?;
    let verb = if enabled { "Enable-NetFirewallRule" } else { "Disable-NetFirewallRule" };
    let out = ps::run_ok(&format!("{}\nif (-not $rules.Count) {{ 'NONE'; exit 0 }}\n$rules | {verb}", load_rules_ps()))?;
    if out.trim() == "NONE" {
        bail!("还没有守卫规则：先运行 anchor guard install");
    }
    println!("{}", if enabled { "守卫已恢复。" } else { "守卫已暂停。" });
    Ok(())
}

#[derive(Debug, Clone)]
pub struct RuleInfo {
    pub enabled: bool,
    pub name: String,
    pub program: PathBuf,
}

pub struct GuardStatus {
    pub rules: Vec<RuleInfo>,
    pub expected: Vec<Target>,
    pub missing: Vec<Target>,
    pub stale: Vec<RuleInfo>,
}

impl GuardStatus {
    pub fn covers(&self, exe: &std::path::Path) -> bool {
        self.rules.iter().any(|r| r.enabled && same_path(&r.program, exe))
    }
    pub fn disabled(&self) -> usize {
        self.rules.iter().filter(|r| !r.enabled).count()
    }
}

pub fn read_rules() -> Result<Vec<RuleInfo>> {
    let script = format!(
        "{}\nforeach ($r in $rules) {{ \
           $p = ($r | Get-NetFirewallApplicationFilter).Program; '{{0}}|{{1}}|{{2}}' -f $r.Enabled, $p, $r.DisplayName }}",
        load_rules_ps()
    );
    let text = ps::run_ok(&script)?;
    Ok(text
        .lines()
        .filter_map(|l| {
            let mut it = l.trim().splitn(3, '|');
            let enabled = it.next()?.eq_ignore_ascii_case("true");
            let program = PathBuf::from(it.next()?);
            let name = it.next().unwrap_or_default().to_string();
            Some(RuleInfo { enabled, name, program })
        })
        .collect())
}

pub fn status(cfg: &Config) -> Result<GuardStatus> {
    let rules = read_rules()?;
    let expected = plan(cfg)?.targets;
    let missing = expected
        .iter()
        .filter(|t| !rules.iter().any(|r| r.enabled && same_path(&r.program, &t.path)))
        .cloned()
        .collect();
    let stale = rules.iter().filter(|r| !exists_any(&r.program)).cloned().collect();
    Ok(GuardStatus { rules, expected, missing, stale })
}

pub fn print_status(st: &GuardStatus) {
    println!("守卫规则：{} 条（停用 {} 条）", st.rules.len(), st.disabled());
    for r in &st.rules {
        let flag = if r.enabled { "启用" } else { "停用" };
        println!("  [{flag}] {}\n         {}", r.name, r.program.display());
    }
    if st.missing.is_empty() {
        println!("配置里的 {} 个程序都已受守卫。", st.expected.len());
    } else {
        println!("未受守卫的程序（运行 anchor guard install 补上）：");
        for t in &st.missing {
            println!("  - {}：{}", t.label, t.path.display());
        }
    }
    if !st.stale.is_empty() {
        println!("指向已不存在文件的旧规则（应用可能已更新）：{} 条，重新运行 anchor guard install 会清理。", st.stale.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(r: &[String]) -> Vec<&str> {
        r.iter().filter(|s| !s.contains(':')).map(String::as_str).collect()
    }

    fn blocked(r: &[String], ip: &str) -> bool {
        let x = u32::from(ip.parse::<Ipv4Addr>().unwrap());
        v4(r).into_iter().any(|s| {
            let (a, b) = s.split_once('-').unwrap_or((s, s));
            let (a, b) = (u32::from(a.parse::<Ipv4Addr>().unwrap()), u32::from(b.parse::<Ipv4Addr>().unwrap()));
            a <= x && x <= b
        })
    }

    #[test]
    fn default_allows_only_loopback() {
        let r = blocked_remote(None).unwrap();
        assert_eq!(v4(&r), ["0.0.0.0-126.255.255.255", "128.0.0.0-255.255.255.255"]);
        // VPN 网段（例如 198.18.0.0/20）也被阻断，AI 程序不能绕过通道访问它
        assert!(blocked(&r, "198.18.0.1"));
        assert!(!blocked(&r, "127.0.0.1"));
    }

    #[test]
    fn ipv4_complement_with_fakeip() {
        let r = blocked_remote(Some("198.18.0.0/15")).unwrap();
        assert_eq!(v4(&r), ["0.0.0.0-126.255.255.255", "128.0.0.0-198.17.255.255", "198.20.0.0-255.255.255.255"]);
    }

    #[test]
    fn ipv6_complement_of_loopback() {
        let r = blocked_remote(None).unwrap();
        let v6: Vec<&String> = r.iter().filter(|s| s.contains(':')).collect();
        assert_eq!(v6, ["::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]);
    }

    #[test]
    fn overlap_detects_vpn_subnet() {
        let fake = parse_cidr("198.18.0.0/15").unwrap();
        assert!(overlaps(&fake, &parse_cidr("198.18.0.60/20").unwrap()));
        assert!(!overlaps(&fake, &parse_cidr("192.168.1.5/24").unwrap()));
        assert!(!overlaps(&fake, &parse_cidr("fc00::1/64").unwrap()));
        assert_eq!(parse_cidr("198.18.0.60/20").unwrap().to_string(), "198.18.0.60/20");
    }

    #[test]
    fn complement_handles_overlap_and_edges() {
        assert_eq!(complement(vec![(0, 10), (5, 20)], 100), vec![(21, 100)]);
        assert_eq!(complement(vec![(90, 100)], 100), vec![(0, 89)]);
        assert_eq!(complement(vec![(0, 100)], 100), vec![]);
        assert_eq!(complement(vec![], 100), vec![(0, 100)]);
    }

    #[test]
    fn allowed_addresses_are_not_blocked() {
        let r = blocked_remote(Some("198.18.0.0/15")).unwrap();
        assert!(!blocked(&r, "127.0.0.1"));
        assert!(!blocked(&r, "198.18.0.5"));
        assert!(!blocked(&r, "198.19.255.255"));
        assert!(blocked(&r, "198.20.0.0"));
        assert!(blocked(&r, "8.8.8.8"));
        assert!(blocked(&r, "192.168.1.1"));
    }

    #[test]
    fn rejects_bad_cidr() {
        assert!(parse_cidr("198.18.0.0").is_err());
        assert!(parse_cidr("198.18.0.0/33").is_err());
        assert!(parse_cidr("fc00::/18").is_ok());
    }
}
