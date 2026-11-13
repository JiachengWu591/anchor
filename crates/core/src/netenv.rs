//! 本机网络环境：默认路由走哪块网卡、是否经 VPN / TUN 全量隧道、各网卡的网段。
//!
//! AI Anchor 本身不建 TUN、不改路由，可以和公司 VPN 或其他 TUN 共存：sing-box 连线路时照常走系统路由，
//! 也就是进入 VPN 隧道。这里只负责把这个事实告诉体检和归因。

use crate::guard::{Cidr, parse_cidr};
use crate::ps;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultIface {
    pub name: String,
    pub description: String,
    pub up: bool,
    /// 例如 198.18.0.60/20
    pub addr: Option<String>,
    /// 由 0.0.0.0/1 + 128.0.0.0/1 两条路由接管默认流量（VPN 全量隧道的典型写法）
    pub split_default: bool,
}

impl DefaultIface {
    pub fn is_tunnel(&self) -> bool {
        self.split_default || looks_like_tunnel(&self.description)
    }

    pub fn describe(&self) -> String {
        let addr = self.addr.as_deref().map(|a| format!("，{a}")).unwrap_or_default();
        format!("“{}”（{}{addr}）", self.name, self.description)
    }
}

/// 按网卡描述判断是不是 VPN / TUN 虚拟网卡。Hyper-V 虚拟交换机承载的是真实网络，不算。
pub fn looks_like_tunnel(desc: &str) -> bool {
    let d = desc.to_lowercase();
    if d.contains("hyper-v") {
        return false;
    }
    [
        "wintun", "tap-windows", "tap-", "tunnel", "wireguard", "vpn", "openvpn", "anyconnect", "fortinet",
        "globalprotect", "pangp", "zerotier", "tailscale", "sangfor", "atrust", "easyconnect", "juniper",
        "pulse secure", "sonicwall",
    ]
    .iter()
    .any(|k| d.contains(k))
}

/// 当前承载默认 IPv4 流量的网卡。
pub fn default_route() -> Option<DefaultIface> {
    let script = r#"
$r = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue)
$halves = @($r | Where-Object { $_.DestinationPrefix -in '0.0.0.0/1','128.0.0.0/1' } |
  Group-Object InterfaceIndex | Where-Object { $_.Count -ge 2 } | ForEach-Object { [int]$_.Name })
if ($halves.Count) { $idx = $halves[0]; $mode = 'split' } else {
  $best = $r | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' } | ForEach-Object {
    $i = Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
    [pscustomobject]@{ Idx = $_.InterfaceIndex; M = $_.RouteMetric + $i.InterfaceMetric } } |
    Sort-Object M | Select-Object -First 1
  if (-not $best) { 'NONE'; exit 0 }
  $idx = $best.Idx; $mode = 'default'
}
$a = Get-NetAdapter -InterfaceIndex $idx -IncludeHidden -ErrorAction SilentlyContinue
$ip = Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
$addr = if ($ip) { '{0}/{1}' -f $ip.IPAddress, $ip.PrefixLength } else { '' }
'{0}|{1}|{2}|{3}|{4}' -f $a.Name, $a.InterfaceDescription, $a.Status, $addr, $mode
"#;
    let out = ps::run_ok(script).ok()?;
    parse_default(out.lines().map(str::trim).find(|l| !l.is_empty())?)
}

fn parse_default(line: &str) -> Option<DefaultIface> {
    if line == "NONE" {
        return None;
    }
    let f: Vec<&str> = line.split('|').collect();
    if f.len() != 5 {
        return None;
    }
    Some(DefaultIface {
        name: f[0].to_string(),
        description: f[1].to_string(),
        up: f[2].eq_ignore_ascii_case("up"),
        addr: (!f[3].is_empty()).then(|| f[3].to_string()),
        split_default: f[4] == "split",
    })
}

/// 本机各网卡的 IPv4 网段：(网卡名, 网段)。
pub fn local_subnets() -> Vec<(String, Cidr)> {
    let script = "Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | \
                  ForEach-Object { '{0}|{1}/{2}' -f $_.InterfaceAlias, $_.IPAddress, $_.PrefixLength }";
    let Ok(text) = ps::run_ok(script) else { return vec![] };
    text.lines()
        .filter_map(|l| {
            let (alias, net) = l.trim().rsplit_once('|')?;
            Some((alias.to_string(), parse_cidr(net).ok()?))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_split_tunnel_line() {
        let d = parse_default("本地连接|Wintun Userspace Tunnel|Up|198.18.0.60/20|split").unwrap();
        assert!(d.is_tunnel() && d.up && d.split_default);
        assert_eq!(d.addr.as_deref(), Some("198.18.0.60/20"));
        assert!(parse_default("NONE").is_none());
        assert!(parse_default("garbage").is_none());
    }

    #[test]
    fn physical_nic_is_not_tunnel() {
        let d = parse_default("WLAN|Intel(R) Wi-Fi 6E AX211 160MHz|Up|192.168.1.23/24|default").unwrap();
        assert!(!d.is_tunnel());
        assert!(!looks_like_tunnel("Hyper-V Virtual Ethernet Adapter"));
        assert!(looks_like_tunnel("WireGuard Tunnel"));
        assert!(looks_like_tunnel("TAP-Windows Adapter V9"));
    }
}
