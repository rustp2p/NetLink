use crate::ipc::common::{GroupItem, NetworkNatInfo, RouteItem};
use std::io;
use std::time::Duration;
use tabled::Table;
use tokio::net::UdpSocket;
async fn recv(cmd: &str, addr: String, buf: &mut [u8]) -> io::Result<usize> {
    let udp = UdpSocket::bind("[::]:0").await?;
    udp.connect(addr).await?;
    udp.send(cmd.as_bytes()).await?;
    let len = match tokio::time::timeout(Duration::from_secs(2), udp.recv(buf)).await {
        Ok(rs) => rs?,
        Err(_) => return Err(io::Error::from(io::ErrorKind::TimedOut)),
    };
    Ok(len)
}
const BUF_SIZE: usize = 1024 * 1024;
pub async fn current_info(addr: String) -> io::Result<()> {
    let mut buf = vec![0; BUF_SIZE];
    let len = recv("info", addr, &mut buf).await?;
    match serde_json::from_slice::<NetworkNatInfo>(&buf[..len]) {
        Ok(mut rs) => {
            println!("         node ip: {}", rs.node_ip);
            println!("      local ipv4: {}", rs.local_ipv4);
            println!("            ipv6: {:?}", rs.ipv6);
            println!("  local tcp port: {:?}", rs.local_tcp_port);
            println!(" local udp ports: {:?}", rs.local_udp_ports);
            println!("        nat type: {:?}", rs.nat_type);
            println!("      public ips: {:?}", rs.public_ips);
            if rs.public_tcp_port != 0 {
                if rs.public_ips.len() == 1 {
                    println!(
                        "      public tcp: {:?}:{}",
                        rs.public_ips[0], rs.public_tcp_port
                    );
                } else {
                    println!(" public tcp port: {}", rs.public_tcp_port);
                }
            }
            rs.public_udp_ports.retain(|v| *v != 0);
            if !rs.public_udp_ports.is_empty() {
                if rs.public_ips.len() == 1 {
                    for port in rs.public_udp_ports {
                        println!("      public udp: {:?}:{}", rs.public_ips[0], port);
                    }
                } else {
                    println!("public udp ports: {:?}", rs.public_udp_ports);
                }
            }
        }
        Err(e) => {
            log::warn!("nodes error {e}");
        }
    }
    Ok(())
}

pub async fn nodes(addr: String) -> io::Result<()> {
    let mut buf = vec![0; BUF_SIZE];
    let len = recv("nodes", addr, &mut buf).await?;
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

pub async fn other_nodes(addr: String, group_code: String) -> io::Result<()> {
    let mut buf = vec![0; BUF_SIZE];
    let len = recv(&format!("other_nodes_{group_code}"), addr, &mut buf).await?;
    match serde_json::from_slice::<Vec<RouteItem>>(&buf[..len]) {
        Ok(rs) => {
            let table = Table::new(rs).to_string();
            println!("{table}");
        }
        Err(e) => {
            log::warn!("other_nodes error {e}");
        }
    }
    Ok(())
}

pub async fn groups(addr: String) -> io::Result<()> {
    let mut buf = vec![0; BUF_SIZE];
    let len = recv("groups", addr, &mut buf).await?;
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
