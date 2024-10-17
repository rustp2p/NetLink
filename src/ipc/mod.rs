use crate::ipc::service::ApiService;
use rustp2p::pipe::PipeWriter;

pub mod common;

pub mod http;
pub mod service;
pub mod udp;

pub async fn server_start(port: u16, pipe_writer: PipeWriter) -> anyhow::Result<()> {
    let api_service = ApiService::new(pipe_writer);
    udp::server::start(port, api_service.clone()).await?;
    http::server::start(port, api_service).await
}
