pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub mod service;
pub mod web_server;

pub use netlink_core::config::*;
use std::net::SocketAddr;

pub struct HttpConfiguration {
    pub addr: SocketAddr,
    pub user_info: Option<HttpUserInfo>,
}

pub struct HttpUserInfo {
    pub username: String,
    pub password: String,
}
