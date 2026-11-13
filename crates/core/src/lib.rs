//! AI Anchor 公共库。命令行 anchor、用户代理 anchor-agent、特权服务 anchor-svc 共用。
//!
//! 让 AI 程序走固定出口；通道不可用时阻断，而不是直连。本机其他程序的网络不受影响。

pub mod apps;
pub mod config;
pub mod guard;
pub mod ipc;
pub mod kernel;
pub mod log;
pub mod net;
pub mod netenv;
pub mod ps;
pub mod rules;
pub mod singbox;
#[cfg(feature = "timeline")]
pub mod timeline;
pub mod util;
pub mod watch;
pub mod win;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
