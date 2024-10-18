use crate::ipc::service::ApiService;
pub mod common;

#[cfg(feature = "web")]
pub mod http;
pub mod service;
pub mod udp;

pub async fn server_start(addr: String, api_service: ApiService) -> anyhow::Result<()> {
    udp::server::start(addr.clone(), api_service.clone()).await?;
    #[cfg(feature = "web")]
    http::server::start(addr, api_service).await?;
    Ok(())
}
