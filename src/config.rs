use crate::cipher::Cipher;
use rustp2p::config::LocalInterface;
use rustp2p::pipe::PeerNodeAddress;
use rustp2p::protocol::node_id::GroupCode;
use std::net::Ipv4Addr;

#[derive(Clone)]
pub struct Config {
    pub self_id: Ipv4Addr,
    pub prefix: u8,
    pub tun_name: Option<String>,
    pub cipher: Option<Cipher>,
    pub port: u16,
    pub group_code: GroupCode,
    pub addrs: Vec<PeerNodeAddress>,
    pub iface_option: Option<LocalInterface>,
    pub exit_node: Option<Ipv4Addr>,
}
