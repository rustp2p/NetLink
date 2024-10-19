use std::net::{Ipv4Addr, Ipv6Addr};

use rustp2p::config::NatType;
use serde::{Deserialize, Serialize};
use tabled::Tabled;

#[derive(Serialize, Deserialize, Debug, Tabled)]
pub struct RouteItem {
    pub node_id: String,
    pub next_hop: String,
    pub protocol: String,
    pub metric: u8,
    pub rtt: u32,
    pub interface: String,
}
#[derive(Serialize, Deserialize, Debug, Tabled)]
pub struct GroupItem {
    pub group_code: String,
    pub node_num: usize,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NetworkNatInfo {
    pub node_ip: Ipv4Addr,
    pub local_ipv4: Ipv4Addr,
    pub ipv6: Option<Ipv6Addr>,
    pub nat_type: NatType,
    pub public_ips: Vec<Ipv4Addr>,
    pub public_udp_ports: Vec<u16>,
    pub public_tcp_port: u16,
    pub local_udp_ports: Vec<u16>,
    pub local_tcp_port: u16,
}
