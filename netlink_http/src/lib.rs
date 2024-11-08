pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub mod service;
pub mod web_server;

pub use netlink_core::config::*;
