use crate::ipc::service::ApiService;
use std::net::SocketAddr;
pub mod common;

#[cfg(feature = "web")]
pub mod http;
pub mod service;
pub mod udp;

pub async fn server_start(addr: SocketAddr, api_service: ApiService) -> anyhow::Result<()> {
    udp::server::start(addr, api_service.clone()).await?;
    #[cfg(feature = "web")]
    http::server::start(addr, api_service).await?;
    Ok(())
}
