//! 防火墙守卫：按程序路径写入持久化的 Windows 防火墙出站规则。
//!
//! Windows 防火墙里阻断规则优先于放行规则，所以不能写“放行回环 + 阻断全部”。
//! 做法是一条阻断规则，远程地址取“允许范围”的补集：程序只能连 127.0.0.0/8 和 ::1，
//! 连不了任何其他地址。内核没运行时，AI 程序因此没有网络，而不是直连。
//! FakeIP 段默认不放行：它只给 AI Anchor 自己的 TUN 兜底（P1）使用，而且常与 VPN 网段重叠。

use crate::apps::{self, Kind, Roots};
use crate::config::Config;
use crate::util::{confirm, exists_any, same_path};
use crate::{netenv, ps, win};
use anyhow::{Context, Result, bail};
use std::collections::HashSet;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub label: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone)]
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
    plan_with(cfg, &Roots::current())
}

/// extra_programs 里不能守卫的路径和原因。
fn refuse_extra(path: &Path) -> Option<String> {
    let file = path.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
    if !path.is_absolute() {
        return Some("必须写完整路径".into());
    }
    if FORBIDDEN.contains(&file.as_str()) {
        return Some(format!("{file} 不只被 AI 使用，守卫会断掉它的日常联网"));
    }
    let sysroot = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    if path.to_string_lossy().to_lowercase().starts_with(&sysroot.to_string_lossy().to_lowercase()) {
        return Some("不能守卫 Windows 目录里的系统程序".into());
    }
    None
}

pub fn plan_with(cfg: &Config, roots: &Roots) -> Result<Plan> {
    let enabled: HashSet<&str> = cfg.apps.desktop.iter().chain(cfg.apps.cli.iter()).map(String::as_str).collect();
    let mut targets: Vec<Target> = Vec::new();
    let mut skipped = Vec::new();
    for f in apps::scan_with(roots) {
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
        if let Some(why) = refuse_extra(&path) {
            skipped.push((format!("自定义：{file}"), path, format!("[guard] extra_programs：{why}")));
            continue;
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

/// 阻断地址集合的指纹，写进规则说明。地址集合变了（例如改了 allow_fakeip），旧规则会被识别出来重建。
pub fn fingerprint(remote: &[String]) -> String {
    // FNV-1a 64：跨版本稳定，不依赖标准库哈希的实现
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in remote.join(",").bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{:08x}", (h >> 32) as u32 ^ h as u32)
}

fn fp_tag(fp: &str) -> String {
    format!("[fp:{fp}]")
}

fn rule_description(fp: &str) -> String {
    format!("只允许经本机 AI 通道联网。由 AI Anchor 管理，用 anchor guard remove 移除。{}", fp_tag(fp))
}

fn new_rule_ps(t: &Target, fp: &str, enabled: bool) -> String {
    format!(
        "New-NetFirewallRule -DisplayName {} -Group $group -Direction Outbound -Action Block -Program {} \
         -RemoteAddress $remote -Profile Any -Enabled {} -Description {} | Out-Null",
        ps::quote(&format!("AI Anchor Guard: {}", t.label)),
        ps::quote(&t.path.to_string_lossy()),
        if enabled { "True" } else { "False" },
        ps::quote(&rule_description(fp)),
    )
}

fn script_header(remote: &[String]) -> String {
    let remote: Vec<String> = remote.iter().map(|r| ps::quote(r)).collect();
    format!("$ErrorActionPreference = 'Stop'\n$group = {}\n$remote = @({})\n", ps::quote(GROUP), remote.join(", "))
}

pub fn install_script(plan: &Plan) -> String {
    let fp = fingerprint(&plan.remote);
    let mut s = script_header(&plan.remote);
    let _ = writeln!(s, "{}", load_rules_ps());
    let _ = writeln!(s, "if ($rules.Count) {{ $rules | Remove-NetFirewallRule }}");
    for t in &plan.targets {
        let _ = writeln!(s, "{}", new_rule_ps(t, &fp, true));
    }
    s
}

/// 现有规则与期望的差异。
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Diff {
    pub add: Vec<Target>,
    pub remove: Vec<RuleInfo>,
}

impl Diff {
    pub fn is_empty(&self) -> bool {
        self.add.is_empty() && self.remove.is_empty()
    }
}

/// 计算增量刷新：
/// - 程序文件已不存在的规则删掉（应用更新后的旧版本路径）；
/// - 阻断地址集合已变的规则删掉重建（指纹不符，含 P0 写的没有指纹的规则）；
/// - prune 为 true 时，期望之外的规则也删掉（用户从 [apps] 去掉了某个程序）；
/// - 期望的程序没有有效规则的，补上。
///
/// 不带 prune 的刷新只会删“文件已不存在”或“需要重建”的规则：即使某次扫描漏了程序，
/// 也不会因此删掉仍然有效的规则。
pub fn diff(desired: &[Target], rules: &[RuleInfo], fp: &str, prune: bool, exists: impl Fn(&Path) -> bool) -> Diff {
    let tag = fp_tag(fp);
    let mut d = Diff::default();
    let mut kept: Vec<&RuleInfo> = Vec::new();
    for r in rules {
        let wanted = desired.iter().any(|t| same_path(&t.path, &r.program));
        let duplicate = kept.iter().any(|k| same_path(&k.program, &r.program));
        if !exists(&r.program) || !r.description.contains(&tag) || (prune && !wanted) || duplicate {
            d.remove.push(r.clone());
        } else {
            kept.push(r);
        }
    }
    for t in desired {
        if !kept.iter().any(|k| same_path(&k.program, &t.path)) && !d.add.iter().any(|a| same_path(&a.path, &t.path)) {
            d.add.push(t.clone());
        }
    }
    d
}

/// 执行增量刷新的 PowerShell。enabled 为 false（守卫暂停中）时，新规则以停用状态写入。
pub fn apply_script(d: &Diff, remote: &[String], enabled: bool) -> String {
    let fp = fingerprint(remote);
    let mut s = script_header(remote);
    // 先加新规则再删旧规则：同一程序在替换过程中始终有规则，不会有一瞬间可以直连
    for t in &d.add {
        let _ = writeln!(s, "{}", new_rule_ps(t, &fp, enabled));
    }
    if !d.remove.is_empty() {
        let ids: Vec<String> = d.remove.iter().map(|r| ps::quote(&r.id)).collect();
        let _ = writeln!(s, "Remove-NetFirewallRule -Name @({})", ids.join(", "));
    }
    s
}

/// 启用或停用本组全部规则。返回脚本，输出 NONE 表示还没有规则。
pub fn set_enabled_script(enabled: bool) -> String {
    let verb = if enabled { "Enable-NetFirewallRule" } else { "Disable-NetFirewallRule" };
    format!("{}\nif (-not $rules.Count) {{ 'NONE'; exit 0 }}\n$rules | {verb}", load_rules_ps())
}

pub fn require_admin() -> Result<()> {
    win::require_admin()
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
    let out = ps::run_ok(&set_enabled_script(enabled))?;
    if out.trim() == "NONE" {
        bail!("还没有守卫规则：先运行 anchor guard install");
    }
    println!("{}", if enabled { "守卫已恢复。" } else { "守卫已暂停。" });
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleInfo {
    /// 规则的唯一名称（Name，删除时用）
    pub id: String,
    pub enabled: bool,
    /// 显示名
    pub name: String,
    pub program: PathBuf,
    pub description: String,
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
           $p = ($r | Get-NetFirewallApplicationFilter).Program; \
           '{{0}}|{{1}}|{{2}}|{{3}}|{{4}}' -f $r.Enabled, $r.Name, $p, ($r.DisplayName -replace '\\|', '/'), ($r.Description -replace '[\\r\\n]', ' ') }}",
        load_rules_ps()
    );
    Ok(parse_rules(&ps::run_ok(&script)?))
}

fn parse_rules(text: &str) -> Vec<RuleInfo> {
    text.lines()
        .filter_map(|l| {
            let mut it = l.trim().splitn(5, '|');
            let enabled = it.next()?.eq_ignore_ascii_case("true");
            let id = it.next()?.to_string();
            let program = PathBuf::from(it.next()?);
            let name = it.next().unwrap_or_default().to_string();
            let description = it.next().unwrap_or_default().to_string();
            Some(RuleInfo { id, enabled, name, program, description })
        })
        .collect()
}

pub fn status(cfg: &Config) -> Result<GuardStatus> {
    let rules = read_rules()?;
    let expected = plan(cfg)?.targets;
    Ok(status_from(rules, expected))
}

pub fn status_from(rules: Vec<RuleInfo>, expected: Vec<Target>) -> GuardStatus {
    let missing = expected
        .iter()
        .filter(|t| !rules.iter().any(|r| r.enabled && same_path(&r.program, &t.path)))
        .cloned()
        .collect();
    let stale = rules.iter().filter(|r| !exists_any(&r.program)).cloned().collect();
    GuardStatus { rules, expected, missing, stale }
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
        println!("未受守卫的程序（运行 anchor guard install 补上；装了特权服务时会自动补上）：");
        for t in &st.missing {
            println!("  - {}：{}", t.label, t.path.display());
        }
    }
    if !st.stale.is_empty() {
        println!("指向已不存在文件的旧规则（应用可能已更新）：{} 条，下次刷新会清理。", st.stale.len());
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

    fn rule(id: &str, program: &str, desc: &str) -> RuleInfo {
        RuleInfo { id: id.into(), enabled: true, name: id.into(), program: program.into(), description: desc.into() }
    }

    fn target(path: &str) -> Target {
        Target { label: path.into(), path: path.into() }
    }

    #[test]
    fn diff_adds_new_versions_and_drops_vanished_files() {
        let fp = "abcd1234";
        let ok = rule_description(fp);
        let rules = vec![rule("old", r"C:\WA\Claude_1\app\Claude.exe", &ok), rule("cur", r"C:\c\Cursor.exe", &ok)];
        let desired = vec![target(r"C:\WA\Claude_2\app\Claude.exe"), target(r"c:\C\cursor.exe")];
        let exists = |p: &Path| !p.to_string_lossy().contains("Claude_1");
        let d = diff(&desired, &rules, fp, false, exists);
        assert_eq!(d.add, vec![target(r"C:\WA\Claude_2\app\Claude.exe")]);
        assert_eq!(d.remove.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), ["old"]);
    }

    #[test]
    fn diff_rebuilds_rules_with_other_fingerprint_and_prunes_only_on_request() {
        let rules = vec![
            rule("p0", r"C:\a.exe", "P0 写的规则，没有指纹"),
            rule("extra", r"C:\b.exe", &rule_description("f1")),
            rule("dup", r"C:\b.exe", &rule_description("f1")),
        ];
        let desired = vec![target(r"C:\a.exe")];
        let d = diff(&desired, &rules, "f1", false, |_| true);
        assert_eq!(d.remove.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), ["p0", "dup"]);
        assert_eq!(d.add, vec![target(r"C:\a.exe")]);
        let pruned = diff(&desired, &rules, "f1", true, |_| true);
        assert_eq!(pruned.remove.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), ["p0", "extra", "dup"]);
        assert!(diff(&[], &[], "f1", true, |_| true).is_empty());
    }

    #[test]
    fn fingerprint_is_stable_and_sensitive() {
        let a = blocked_remote(None).unwrap();
        let b = blocked_remote(Some("198.18.0.0/15")).unwrap();
        assert_eq!(fingerprint(&a), fingerprint(&a.clone()));
        assert_ne!(fingerprint(&a), fingerprint(&b));
        assert_eq!(fingerprint(&a).len(), 8);
    }

    #[test]
    fn apply_script_removes_by_id_and_adds_disabled_when_paused() {
        let d = Diff { add: vec![target(r"C:\it's.exe")], remove: vec![rule("{1}", r"C:\x.exe", "")] };
        let s = apply_script(&d, &["0.0.0.0-126.255.255.255".to_string()], false);
        assert!(s.contains("Remove-NetFirewallRule -Name @('{1}')"));
        assert!(s.contains(r"-Program 'C:\it''s.exe'"));
        assert!(s.contains("-Enabled False"));
        assert!(s.find("New-NetFirewallRule").unwrap() < s.find("Remove-NetFirewallRule").unwrap(), "先加后删");
    }

    #[test]
    fn parse_rules_reads_all_fields() {
        let r = parse_rules("True|{abc}|C:\\x.exe|AI Anchor Guard: x|说明 [fp:1]\nFalse|{d}|C:\\y.exe|y|\n");
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].id, "{abc}");
        assert!(r[0].enabled && !r[1].enabled);
        assert_eq!(r[0].description, "说明 [fp:1]");
    }

    #[test]
    fn extra_programs_refuse_system_and_relative_paths() {
        assert!(refuse_extra(Path::new(r"C:\Windows\System32\curl.exe")).is_some());
        assert!(refuse_extra(Path::new("tool.exe")).is_some());
        assert!(refuse_extra(Path::new(r"D:\Tools\node.exe")).is_some());
        assert!(refuse_extra(Path::new(r"D:\Tools\ai.exe")).is_none());
    }

    #[test]
    fn rejects_bad_cidr() {
        assert!(parse_cidr("198.18.0.0").is_err());
        assert!(parse_cidr("198.18.0.0/33").is_err());
        assert!(parse_cidr("fc00::/18").is_ok());
    }
}
