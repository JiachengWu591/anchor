//! 本机的上行网卡（Wi-Fi 或有线）和绕开 VPN 的探测，用来把“本地”断联分成 Wi-Fi、宽带、VPN（P1b）。
//!
//! 全量 VPN 用 0.0.0.0/1 + 128.0.0.0/1（或跃点更小的 0.0.0.0/0）接管默认流量，但原来那条经路由器的
//! 0.0.0.0/0 还在。这里从路由表里找出它：物理网卡（以太网、Wi-Fi）上、有下一跳的默认路由，取跃点最小的。
//! - 网关 ping 得通：电脑到路由器这一段是好的。
//! - 绑定这块网卡连外网（IP_UNICAST_IF，不走 VPN 的路由）连得上：路由器之外的宽带也是好的。
//! - 这两段都好、经 VPN 却上不了网：问题在 VPN。
//!
//! 都只用普通用户权限：读路由表、ICMP、带选项的 TCP 连接。

use anyhow::{Result, bail};
use std::ffi::c_void;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{INVALID_HANDLE_VALUE, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, FreeMibTable, GetBestInterface, GetIpForwardTable2, GetIpInterfaceEntry, ICMP_ECHO_REPLY,
    IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho, InitializeIpInterfaceEntry, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, FD_SET, FIONBIO, IN_ADDR, IN_ADDR_0, INVALID_SOCKET, IP_UNICAST_IF, IPPROTO_IP, IPPROTO_TCP, SO_ERROR, SOCK_STREAM, SOCKADDR,
    SOCKADDR_IN, SOL_SOCKET, TIMEVAL, WSACleanup, WSADATA, WSAEWOULDBLOCK, WSAGetLastError, WSAStartup, closesocket, connect,
    getsockopt, ioctlsocket, select, setsockopt, socket,
};

/// 网卡类型（NET_LUID 里的 IfType）：以太网、Wi-Fi。VPN 的虚拟网卡（Wintun 是 53）不算。
const IF_TYPE_ETHERNET: u16 = 6;
const IF_TYPE_WIFI: u16 = 71;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Uplink {
    pub if_index: u32,
    pub wifi: bool,
    pub gateway: Ipv4Addr,
}

impl Uplink {
    /// 写进时间线的名字
    pub fn kind(&self) -> &'static str {
        if self.wifi { "wifi" } else { "ethernet" }
    }
}

/// 一条默认路由候选：(接口序号, 接口类型, 下一跳, 路由跃点)
type Candidate = (u32, u16, Ipv4Addr, u32);

/// 从候选里挑上行网卡：物理网卡、有下一跳，跃点（路由跃点 + 接口跃点）最小。
fn pick(candidates: &[Candidate], if_metric: impl Fn(u32) -> u32) -> Option<Uplink> {
    candidates
        .iter()
        .filter(|(_, t, hop, _)| (*t == IF_TYPE_ETHERNET || *t == IF_TYPE_WIFI) && !hop.is_unspecified())
        .min_by_key(|(idx, _, _, m)| m.saturating_add(if_metric(*idx)))
        .map(|(idx, t, hop, _)| Uplink { if_index: *idx, wifi: *t == IF_TYPE_WIFI, gateway: *hop })
}

/// 此刻的上行网卡；没连 Wi-Fi 也没插网线时为 None。
pub fn find() -> Option<Uplink> {
    let mut candidates: Vec<Candidate> = Vec::new();
    // SAFETY: GetIpForwardTable2 成功后表一直有效，直到 FreeMibTable；按 NumEntries 读行
    unsafe {
        let mut t: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        if GetIpForwardTable2(AF_INET, &mut t) != NO_ERROR || t.is_null() {
            return None;
        }
        let rows = std::slice::from_raw_parts((*t).Table.as_ptr(), (*t).NumEntries as usize);
        for r in rows.iter().filter(|r| r.DestinationPrefix.PrefixLength == 0) {
            let hop = Ipv4Addr::from(r.NextHop.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes());
            let if_type = (r.InterfaceLuid.Value >> 48) as u16;
            candidates.push((r.InterfaceIndex, if_type, hop, r.Metric));
        }
        FreeMibTable(t as *const c_void);
    }
    pick(&candidates, interface_metric)
}

fn interface_metric(if_index: u32) -> u32 {
    // SAFETY: 行由 InitializeIpInterfaceEntry 初始化，只读出参
    unsafe {
        let mut row: MIB_IPINTERFACE_ROW = std::mem::zeroed();
        InitializeIpInterfaceEntry(&mut row);
        row.Family = AF_INET;
        row.InterfaceIndex = if_index;
        if GetIpInterfaceEntry(&mut row) == NO_ERROR { row.Metric } else { u32::MAX / 2 }
    }
}

/// 名字（别名）是 alias 的网卡此刻有没有连接。没有这块网卡也算没连接：
/// VPN 的虚拟网卡在断开时常常整个消失。
pub fn iface_connected(alias: &str) -> bool {
    let wide: Vec<u16> = alias.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: 别名是以 0 结尾的 UTF-16 串；出参和行都是本地变量，行先由系统初始化
    unsafe {
        let mut row: MIB_IPINTERFACE_ROW = std::mem::zeroed();
        InitializeIpInterfaceEntry(&mut row);
        row.Family = AF_INET;
        if ConvertInterfaceAliasToLuid(wide.as_ptr(), &mut row.InterfaceLuid) != NO_ERROR {
            return false;
        }
        GetIpInterfaceEntry(&mut row) == NO_ERROR && row.Connected as u8 != 0
    }
}

/// 去往 dst 的流量此刻走哪块网卡（只查路由，不发包）。
pub fn route_if(dst: Ipv4Addr) -> Option<u32> {
    let mut idx = 0u32;
    // SAFETY: 地址按网络字节序传入，出参是普通整数
    let r = unsafe { GetBestInterface(u32::from_ne_bytes(dst.octets()), &mut idx) };
    (r == NO_ERROR).then_some(idx)
}

/// ping 一次：往返毫秒。
pub fn ping(ip: Ipv4Addr, timeout: Duration) -> Result<u32> {
    let data = [0x61u8; 32];
    let mut buf = vec![0u8; std::mem::size_of::<ICMP_ECHO_REPLY>() + data.len() + 8 + 64];
    // SAFETY: 句柄用完即关；应答缓冲区足够大，按非对齐方式读出应答头
    unsafe {
        let h = IcmpCreateFile();
        if h == INVALID_HANDLE_VALUE || h.is_null() {
            bail!("无法发 ping");
        }
        let n = IcmpSendEcho(
            h,
            u32::from_ne_bytes(ip.octets()),
            data.as_ptr() as *const c_void,
            data.len() as u16,
            std::ptr::null(),
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u32,
            timeout.as_millis() as u32,
        );
        IcmpCloseHandle(h);
        if n == 0 {
            bail!("{} 毫秒内没有应答", timeout.as_millis());
        }
        let reply: ICMP_ECHO_REPLY = std::ptr::read_unaligned(buf.as_ptr() as *const ICMP_ECHO_REPLY);
        if reply.Status != 0 {
            bail!("应答状态 {}", reply.Status);
        }
        Ok(reply.RoundTripTime)
    }
}

/// 绑定网卡发起 TCP 连接，只握手，连上就关：耗时。用来绕开 VPN 的路由测外网。
pub fn tcp_via(if_index: u32, addr: SocketAddrV4, timeout: Duration) -> Result<Duration> {
    let started = Instant::now();
    // SAFETY: 套接字在所有路径上都会关闭；结构体按 WinSock 的定义填写
    unsafe {
        let mut wsa: WSADATA = std::mem::zeroed();
        if WSAStartup(0x202, &mut wsa) != 0 {
            bail!("WinSock 初始化失败");
        }
        let s = socket(AF_INET as i32, SOCK_STREAM, IPPROTO_TCP);
        let result = (|| {
            if s == INVALID_SOCKET {
                bail!("创建套接字失败（{}）", WSAGetLastError());
            }
            let idx = if_index.to_be();
            if setsockopt(s, IPPROTO_IP, IP_UNICAST_IF, &idx as *const u32 as *const u8, 4) != 0 {
                bail!("绑定网卡失败（{}）", WSAGetLastError());
            }
            let mut nonblocking = 1u32;
            ioctlsocket(s, FIONBIO, &mut nonblocking);
            let sa = SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: addr.port().to_be(),
                sin_addr: IN_ADDR { S_un: IN_ADDR_0 { S_addr: u32::from_ne_bytes(addr.ip().octets()) } },
                sin_zero: [0; 8],
            };
            if connect(s, &sa as *const SOCKADDR_IN as *const SOCKADDR, std::mem::size_of::<SOCKADDR_IN>() as i32) != 0 {
                let e = WSAGetLastError();
                if e != WSAEWOULDBLOCK {
                    bail!("连接失败（{e}）");
                }
            }
            let mut w: FD_SET = std::mem::zeroed();
            w.fd_count = 1;
            w.fd_array[0] = s;
            let mut x = w;
            let tv = TIMEVAL { tv_sec: timeout.as_secs() as i32, tv_usec: timeout.subsec_micros() as i32 };
            match select(0, std::ptr::null_mut(), &mut w, &mut x, &tv) {
                0 => bail!("{} 毫秒内没连上", timeout.as_millis()),
                n if n < 0 => bail!("等待连接出错（{}）", WSAGetLastError()),
                _ => {}
            }
            if x.fd_count > 0 {
                let mut err = 0i32;
                let mut len = 4i32;
                getsockopt(s, SOL_SOCKET, SO_ERROR, &mut err as *mut i32 as *mut u8, &mut len);
                bail!("连接失败（{err}）");
            }
            Ok(started.elapsed())
        })();
        if s != INVALID_SOCKET {
            closesocket(s);
        }
        WSACleanup();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GW: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);

    #[test]
    fn picks_the_physical_default_route_under_a_full_tunnel_vpn() {
        // 实测路由表的形状：VPN 网卡（Wintun，类型 53）上有一条跃点 9999 的 0.0.0.0/0，Wi-Fi 上有经路由器的一条
        let routes = [(22, 53, Ipv4Addr::new(10, 0, 0, 1), 9999), (25, IF_TYPE_WIFI, GW, 0)];
        assert_eq!(pick(&routes, |_| 25), Some(Uplink { if_index: 25, wifi: true, gateway: GW }));
        // 只有 VPN、没有物理网卡：没有上行
        assert_eq!(pick(&routes[..1], |_| 25), None);
        // 没有下一跳的（点对点）不算
        assert_eq!(pick(&[(7, IF_TYPE_ETHERNET, Ipv4Addr::UNSPECIFIED, 0)], |_| 0), None);
        // Wi-Fi 和网线都连着：按路由跃点 + 接口跃点取小的
        let both = [(25, IF_TYPE_WIFI, GW, 0), (9, IF_TYPE_ETHERNET, Ipv4Addr::new(10, 1, 1, 1), 0)];
        let metric = |i| if i == 9 { 5 } else { 40 };
        assert_eq!(pick(&both, metric).unwrap().kind(), "ethernet");
    }

    #[test]
    fn reads_the_real_routing_table() {
        // 有没有上行取决于测试机，这里只确认读路由表、查路由不出错
        if let Some(u) = find() {
            assert!(!u.gateway.is_unspecified());
        }
        let _ = route_if(Ipv4Addr::new(192, 0, 2, 1));
    }

    #[test]
    fn ping_loopback() {
        assert!(ping(Ipv4Addr::LOCALHOST, Duration::from_secs(1)).is_ok(), "回环地址应能 ping 通");
    }

    #[test]
    fn tcp_via_reports_refused_or_timeout() {
        // 回环网卡上没人监听的端口：连接被拒，迅速失败
        let lo = route_if(Ipv4Addr::LOCALHOST).unwrap_or(1);
        let r = tcp_via(lo, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9), Duration::from_millis(500));
        assert!(r.is_err());
    }

    #[test]
    fn a_missing_adapter_counts_as_not_connected() {
        assert!(!iface_connected("ai-anchor-没有这块网卡"));
        assert!(!iface_connected(""));
    }

    /// 看本机某几块网卡此刻算不算连接着：
    /// `ANCHOR_IFACES=WLAN,名字2 cargo test -p anchor-core --features timeline iface_states -- --ignored --nocapture`
    #[test]
    #[ignore = "要给出本机的网卡名"]
    fn iface_states() {
        for name in std::env::var("ANCHOR_IFACES").unwrap_or_default().split(',').filter(|s| !s.is_empty()) {
            println!("{name}: connected = {}", iface_connected(name));
        }
    }
}
