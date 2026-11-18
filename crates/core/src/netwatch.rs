//! 网络变化通知：网卡地址增删、默认路由增删（VPN 连上 / 断开 / 重连、换网络）。
//!
//! 用 Windows 的 NotifyUnicastIpAddressChange 和 NotifyRouteChange2，普通用户就能订阅；
//! 回调在系统线程池里执行，只调用调用方给的钩子。只看“增加 / 删除”，不看参数变化
//! （地址生存期刷新这类变化很频繁，又不影响出口）。

use anyhow::{Result, bail};
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use windows_sys::Win32::Foundation::{HANDLE, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, MIB_IPFORWARD_ROW2, MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW, MibAddInstance,
    MibDeleteInstance, NotifyRouteChange2, NotifyUnicastIpAddressChange,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_INET};

type Hook = Box<dyn Fn() + Send + Sync>;

/// 订阅期间一直有效；丢弃时取消订阅。
pub struct NetWatch {
    handles: Vec<HANDLE>,
    hook: *mut Hook,
}

// 句柄和钩子指针只在 Drop 里使用；钩子本身是 Send + Sync
unsafe impl Send for NetWatch {}

impl NetWatch {
    pub fn start(on_change: impl Fn() + Send + Sync + 'static) -> Result<Self> {
        let hook: *mut Hook = Box::into_raw(Box::new(Box::new(on_change) as Hook));
        let mut w = NetWatch { handles: Vec::new(), hook };
        let ctx = hook as *const c_void;
        // SAFETY: 回调签名与 windows-sys 声明一致；ctx 在取消订阅之前一直有效（Drop 里先取消再释放）
        unsafe {
            let mut h: HANDLE = std::ptr::null_mut();
            let r = NotifyUnicastIpAddressChange(AF_UNSPEC, Some(on_addr), ctx, 0, &mut h);
            if r != NO_ERROR {
                bail!("订阅网卡地址变化失败（错误码 {r}）");
            }
            w.handles.push(h);
            let mut h: HANDLE = std::ptr::null_mut();
            let r = NotifyRouteChange2(AF_UNSPEC, Some(on_route), ctx, 0, &mut h);
            if r != NO_ERROR {
                bail!("订阅路由变化失败（错误码 {r}）");
            }
            w.handles.push(h);
        }
        Ok(w)
    }
}

impl Drop for NetWatch {
    fn drop(&mut self) {
        // SAFETY: CancelMibChangeNotify2 返回后不会再有回调，之后才释放钩子
        unsafe {
            for h in self.handles.drain(..) {
                CancelMibChangeNotify2(h);
            }
            drop(Box::from_raw(self.hook));
        }
    }
}

fn is_add_or_delete(kind: MIB_NOTIFICATION_TYPE) -> bool {
    kind == MibAddInstance || kind == MibDeleteInstance
}

unsafe extern "system" fn on_addr(ctx: *const c_void, row: *const MIB_UNICASTIPADDRESS_ROW, kind: MIB_NOTIFICATION_TYPE) {
    if row.is_null() || !is_add_or_delete(kind) {
        return;
    }
    // SAFETY: 系统保证回调期间 row 有效
    let ip = unsafe { sockaddr_ip(&(*row).Address) };
    if ip.is_some_and(relevant_addr) {
        unsafe { fire(ctx) };
    }
}

unsafe extern "system" fn on_route(ctx: *const c_void, row: *const MIB_IPFORWARD_ROW2, kind: MIB_NOTIFICATION_TYPE) {
    if row.is_null() || !is_add_or_delete(kind) {
        return;
    }
    // SAFETY: 同上
    let prefix = unsafe { (*row).DestinationPrefix.PrefixLength };
    if default_like(prefix) {
        unsafe { fire(ctx) };
    }
}

unsafe fn fire(ctx: *const c_void) {
    if ctx.is_null() {
        return;
    }
    // SAFETY: ctx 是 start 里放进去的 *mut Hook
    let hook = unsafe { &*(ctx as *const Hook) };
    // 回调跨越 FFI 边界，不能让 panic 传出去
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(hook));
}

unsafe fn sockaddr_ip(a: &SOCKADDR_INET) -> Option<IpAddr> {
    // SAFETY: 按 si_family 读对应的联合体成员
    unsafe {
        match a.si_family {
            f if f == AF_INET => Some(IpAddr::V4(Ipv4Addr::from(a.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()))),
            f if f == AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(a.Ipv6.sin6_addr.u.Byte))),
            _ => None,
        }
    }
}

/// 会影响出口的地址：不是回环、链路本地或未指定地址。
pub fn relevant_addr(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => !(v.is_loopback() || v.is_link_local() || v.is_unspecified()),
        IpAddr::V6(v) => !(v.is_loopback() || v.is_unspecified() || (v.segments()[0] & 0xffc0) == 0xfe80),
    }
}

/// 默认路由及 VPN 常用的半边默认路由（0.0.0.0/1、128.0.0.0/1）。
pub fn default_like(prefix_len: u8) -> bool {
    prefix_len <= 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_addresses_that_do_not_affect_the_exit() {
        assert!(relevant_addr("198.18.0.60".parse().unwrap()), "VPN 隧道地址");
        assert!(relevant_addr("10.176.3.4".parse().unwrap()));
        assert!(relevant_addr("2409:8a00::1".parse().unwrap()));
        assert!(!relevant_addr("127.0.0.1".parse().unwrap()));
        assert!(!relevant_addr("169.254.10.1".parse().unwrap()));
        assert!(!relevant_addr("fe80::1c2:3".parse().unwrap()));
        assert!(!relevant_addr("::1".parse().unwrap()));
    }

    #[test]
    fn only_default_and_half_default_routes_count() {
        assert!(default_like(0));
        assert!(default_like(1));
        assert!(!default_like(8));
        assert!(!default_like(32));
    }

    #[test]
    fn subscribe_and_cancel() {
        let w = NetWatch::start(|| {}).expect("普通用户也能订阅网络变化");
        drop(w);
    }
}
