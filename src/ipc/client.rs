use crate::ipc::common::{GroupItem, RouteItem};
use std::io;
use std::time::Duration;
use tabled::Table;
use tokio::net::UdpSocket;
async fn recv(cmd: &str, port: u16, buf: &mut [u8]) -> io::Result<usize> {
    let udp = UdpSocket::bind("127.0.0.1:0").await?;
    udp.connect(format!("127.0.0.1:{port}")).await?;
    udp.send(cmd.as_bytes()).await?;
    let len = match tokio::time::timeout(Duration::from_secs(2), udp.recv(buf)).await {
        Ok(rs) => rs?,
        Err(_) => return Err(io::Error::from(io::ErrorKind::TimedOut)),
    };
    Ok(len)
}
pub async fn nodes(port: u16) -> io::Result<()> {
    let mut buf = [0; 4096];
    let len = recv("list", port, &mut buf).await?;
    match serde_json::from_slice::<Vec<RouteItem>>(&buf[..len]) {
        Ok(rs) => {
            let table = Table::new(rs).to_string();
            println!("{table}");
        }
        Err(e) => {
            log::warn!("nodes error {e}");
        }
    }
    Ok(())
}

pub async fn groups(port: u16) -> io::Result<()> {
    let mut buf = [0; 4096];
    let len = recv("all_group_code", port, &mut buf).await?;
    match serde_json::from_slice::<Vec<GroupItem>>(&buf[..len]) {
        Ok(rs) => {
            let table = Table::new(rs).to_string();
            println!("{table}");
        }
        Err(e) => {
            log::warn!("groups error {e}");
        }
    }
    Ok(())
}
