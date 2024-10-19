use anyhow::anyhow;
use std::net::{Ipv4Addr, Ipv6Addr};

use rustp2p::config::LocalInterface;
use rustp2p::pipe::PeerNodeAddress;
use rustp2p::protocol::node_id::GroupCode;
use serde::{Deserialize, Serialize};

use crate::cipher::Cipher;
use crate::{CMD_HOST, CMD_PORT, LISTEN_PORT};

const UDP_STUN: [&str; 6] = [
    "stun.miwifi.com",
    "stun.chat.bilibili.com",
    "stun.hitv.com",
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun2.l.google.com:19302",
];
const TCP_STUN: [&str; 3] = [
    "stun.flashdance.cx",
    "stun.sipnet.net",
    "stun.nextcloud.com:443",
];

#[derive(Clone)]
pub struct Config {
    pub node_ipv4: Ipv4Addr,
    pub node_ipv6: Option<Ipv6Addr>,
    pub prefix: u8,
    pub prefix_v6: u8,
    pub tun_name: Option<String>,
    pub cipher: Option<Cipher>,
    pub encrypt: Option<String>,
    pub algorithm: Option<String>,
    pub port: u16,
    pub group_code: GroupCode,
    pub peer_addrs: Option<Vec<PeerNodeAddress>>,
    pub bind_dev_name: Option<String>,
    pub iface_option: Option<LocalInterface>,
    pub exit_node: Option<Ipv4Addr>,

    pub udp_stun: Vec<String>,
    pub tcp_stun: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConfigView {
    pub group_code: String,
    pub node_ipv4: String,
    pub prefix: u8,
    pub node_ipv6: Option<String>,
    pub prefix_v6: u8,
    pub tun_name: Option<String>,
    pub encrypt: Option<String>,
    pub algorithm: Option<String>,
    pub port: u16,
    pub peer: Option<Vec<String>>,
    pub bind_dev_name: Option<String>,
    pub exit_node: Option<String>,

    pub udp_stun: Vec<String>,
    pub tcp_stun: Vec<String>,
}

impl Default for ConfigView {
    fn default() -> Self {
        Self {
            group_code: "".to_string(),
            node_ipv4: "".to_string(),
            prefix: 24,
            node_ipv6: None,
            prefix_v6: 96,
            tun_name: None,
            encrypt: None,
            algorithm: None,
            port: LISTEN_PORT,
            peer: None,
            bind_dev_name: None,
            exit_node: None,
            udp_stun: UDP_STUN.iter().map(|v| v.to_string()).collect(),
            tcp_stun: TCP_STUN.iter().map(|v| v.to_string()).collect(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(default)]
pub struct FileConfigView {
    pub cmd_host: String,
    pub cmd_port: u16,
    pub threads: usize,

    pub group_code: String,
    pub node_ipv4: String,
    pub prefix: u8,
    pub node_ipv6: Option<String>,
    pub prefix_v6: u8,
    pub tun_name: Option<String>,
    pub encrypt: Option<String>,
    pub algorithm: Option<String>,
    pub port: u16,
    pub peer: Option<Vec<String>>,
    pub bind_dev_name: Option<String>,
    pub exit_node: Option<String>,

    pub udp_stun: Vec<String>,
    pub tcp_stun: Vec<String>,
}

impl FileConfigView {
    pub fn read_file(file_path: &str) -> anyhow::Result<Self> {
        let conf = std::fs::read_to_string(file_path)?;
        let file_conf = serde_yaml::from_str::<FileConfigView>(&conf)?;
        file_conf.check()?;
        Ok(file_conf)
    }
    pub fn check(&self) -> anyhow::Result<()> {
        if self.group_code.trim().is_empty() {
            Err(anyhow!("group_code cannot be empty"))?
        }
        if self.node_ipv4.trim().is_empty() {
            Err(anyhow!("node_ipv4 cannot be empty"))?
        }
        Ok(())
    }
}

impl From<FileConfigView> for ConfigView {
    fn from(value: FileConfigView) -> Self {
        Self {
            group_code: value.group_code,
            node_ipv4: value.node_ipv4,
            prefix: value.prefix,
            node_ipv6: value.node_ipv6,
            prefix_v6: value.prefix_v6,
            tun_name: value.tun_name,
            encrypt: value.encrypt,
            algorithm: value.algorithm,
            port: value.port,
            peer: value.peer,
            bind_dev_name: value.bind_dev_name,
            exit_node: value.exit_node,
            udp_stun: value.udp_stun,
            tcp_stun: value.tcp_stun,
        }
    }
}

impl Default for FileConfigView {
    fn default() -> Self {
        Self {
            cmd_host: CMD_HOST.to_string(),
            cmd_port: CMD_PORT,
            threads: 2,
            group_code: "".to_string(),
            node_ipv4: "".to_string(),
            prefix: 24,
            node_ipv6: None,
            prefix_v6: 96,
            tun_name: None,
            encrypt: None,
            algorithm: Some("chacha20-poly1305".to_string()),
            port: LISTEN_PORT,
            peer: None,
            bind_dev_name: None,
            exit_node: None,
            udp_stun: UDP_STUN.iter().map(|v| v.to_string()).collect(),
            tcp_stun: TCP_STUN.iter().map(|v| v.to_string()).collect(),
        }
    }
}

impl Config {
    pub fn to_config_view(&self) -> ConfigView {
        ConfigView {
            group_code: group_code_to_string(&self.group_code),
            node_ipv4: format!("{}", self.node_ipv4),
            prefix: self.prefix,
            node_ipv6: self.node_ipv6.map(|v| format!("{v}")),
            prefix_v6: self.prefix_v6,
            tun_name: self.tun_name.clone(),
            encrypt: self.encrypt.clone(),
            algorithm: self.algorithm.clone(),
            port: self.port,
            peer: self
                .peer_addrs
                .clone()
                .map(|v| v.iter().map(|v| v.to_string()).collect()),
            bind_dev_name: self.bind_dev_name.clone(),
            exit_node: self.exit_node.map(|v| format!("{v}")),
            udp_stun: self.udp_stun.clone(),
            tcp_stun: self.tcp_stun.clone(),
        }
    }
}

impl ConfigView {
    pub fn into_config(self) -> anyhow::Result<Config> {
        let group_code = string_to_group_code(&self.group_code)?;
        let node_ipv4: Ipv4Addr = self
            .node_ipv4
            .parse()
            .map_err(|e| anyhow::anyhow!("node_ipv4 error: {e}"))?;
        let node_ipv6 = if let Some(node_ipv6) = self.node_ipv6 {
            let node_ipv6: Ipv6Addr = node_ipv6
                .parse()
                .map_err(|e| anyhow::anyhow!("node_ipv6 error: {e}"))?;
            let mut octets = node_ipv6.octets();
            octets[12..].copy_from_slice(&node_ipv4.octets());

            let node_ipv6 = Ipv6Addr::from(octets);
            if self.prefix_v6 > 96 {
                Err(anyhow::anyhow!("prefix_v6 cannot be greater than 96"))?
            }
            Some(node_ipv6)
        } else {
            let mut v6: [u8; 16] = [
                0xfd, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0, 0, 0, 0,
            ];
            v6[12..].copy_from_slice(&node_ipv4.octets());
            let v6 = Ipv6Addr::from(v6);

            Some(v6)
        };
        let encrypt = self.encrypt.clone();
        let algorithm = self.algorithm.clone();
        let cipher = if let Some(v) = self.algorithm {
            match v.to_lowercase().as_str() {
                "aes-gcm" => self.encrypt.map(Cipher::new_aes_gcm),
                "chacha20-poly1305" => self.encrypt.map(Cipher::new_chacha20_poly1305),
                "xor" => self.encrypt.map(Cipher::new_xor),
                t => Err(anyhow::anyhow!("algorithm error: {t}"))?,
            }
        } else {
            self.encrypt.map(Cipher::new_chacha20_poly1305)
        };
        let mut peer_addrs = None;
        if let Some(peers) = self.peer {
            let mut list = Vec::new();
            for addr in peers {
                list.push(
                    addr.parse::<PeerNodeAddress>()
                        .map_err(|e| anyhow::anyhow!("peer error: {e}"))?,
                )
            }
            peer_addrs.replace(list);
        }

        let mut iface_option = None;
        if let Some(bind_dev_name) = self.bind_dev_name.clone() {
            let _bind_dev_index = match crate::platform::dev_name_to_index(&bind_dev_name) {
                Ok(index) => index,
                Err(e) => Err(anyhow::anyhow!("bind_dev_name error: {e}"))?,
            };
            let iface;
            #[cfg(not(target_os = "linux"))]
            {
                iface = LocalInterface::new(_bind_dev_index);
            }
            #[cfg(target_os = "linux")]
            {
                iface = LocalInterface::new(bind_dev_name.clone());
            }
            iface_option.replace(iface);
        }
        let exit_node = if let Some(exit_node) = self.exit_node {
            let exit_node: Ipv4Addr = exit_node
                .parse()
                .map_err(|e| anyhow::anyhow!("exit_node error: {e}"))?;
            Some(exit_node)
        } else {
            None
        };
        Ok(Config {
            node_ipv4,
            node_ipv6,
            prefix: self.prefix,
            prefix_v6: self.prefix_v6,
            tun_name: self.tun_name,
            cipher,
            encrypt,
            algorithm,
            port: self.port,
            group_code,
            peer_addrs,
            bind_dev_name: self.bind_dev_name,
            iface_option,
            exit_node,
            udp_stun: self.udp_stun,
            tcp_stun: self.tcp_stun,
        })
    }
}

pub(crate) fn string_to_group_code(input: &str) -> anyhow::Result<GroupCode> {
    let mut array = [0u8; 16];
    let bytes = input.as_bytes();
    if bytes.len() > 16 {
        return Err(anyhow::anyhow!("group_code is too long"));
    }
    let len = bytes.len();
    array[..len].copy_from_slice(&bytes[..len]);
    Ok(array.into())
}

pub(crate) fn group_code_to_string(group_code: &GroupCode) -> String {
    let mut vec = group_code.as_ref().to_vec();
    if let Some(pos) = vec.iter().rposition(|&x| x != 0) {
        vec.truncate(pos + 1);
    }
    match String::from_utf8(vec) {
        Ok(group_code) => group_code,
        Err(_) => format!("{:?}", group_code.as_ref()),
    }
}
