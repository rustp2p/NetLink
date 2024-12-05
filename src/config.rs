use std::fmt::Debug;

use anyhow::{anyhow, Context};
use regex::Regex;
use serde::{Deserialize, Serialize};

use netlink_http::{Config, ConfigBuilder};

use crate::{DEFAULT_ALGORITHM, LISTEN_PORT};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(default)]
pub struct FileConfigView {
    #[cfg(feature = "web")]
    pub api_addr: std::net::SocketAddr,
    #[cfg(feature = "web")]
    pub api_disable: bool,
    pub threads: usize,

    pub group_code: String,
    pub node_ipv4: String,
    pub prefix: u8,
    pub node_ipv6: Option<String>,
    pub prefix_v6: Option<u8>,
    pub tun_name: Option<String>,
    pub encrypt: Option<String>,
    pub algorithm: String,
    pub port: u16,
    pub peer: Option<Vec<String>>,
    pub bind_dev_name: Option<String>,
    pub exit_node: Option<String>,
    pub mtu: Option<u16>,
    pub udp_stun: Option<Vec<String>>,
    pub tcp_stun: Option<Vec<String>>,
    pub group_code_filter: Option<Vec<String>>,
    #[cfg(feature = "web")]
    pub username: Option<String>,
    #[cfg(feature = "web")]
    pub password: Option<String>,
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
pub fn convert_group_filter(src: Option<Vec<String>>) -> anyhow::Result<Option<Vec<String>>> {
    let mut group_code_filter_regex = Vec::new();
    if let Some(v) = src {
        for x in v {
            if let Err(e) = Regex::new(&x) {
                Err(anyhow::anyhow!("{e}"))?;
            } else {
                group_code_filter_regex.push(x);
            }
        }
    }

    if group_code_filter_regex.is_empty() {
        Ok(None)
    } else {
        Ok(Some(group_code_filter_regex))
    }
}
impl TryFrom<FileConfigView> for Config {
    type Error = anyhow::Error;

    fn try_from(value: FileConfigView) -> Result<Self, Self::Error> {
        let node_ipv6 = if let Some(node_ipv6) = value.node_ipv6 {
            Some(node_ipv6.parse().context("node_ipv6 format error")?)
        } else {
            None
        };
        let group_code_filter_regex = convert_group_filter(value.group_code_filter)?;
        let mut builder = ConfigBuilder::new()
            .udp_stun(value.udp_stun)
            .tcp_stun(value.tcp_stun)
            .node_ipv4(value.node_ipv4.parse().context("node_ipv4 format error")?)
            .node_ipv6(node_ipv6)
            .prefix(value.prefix)
            .prefix_v6(value.prefix_v6)
            .group_code(value.group_code.try_into()?)
            .port(value.port)
            .algorithm(Some(value.algorithm))
            .encrypt(value.encrypt)
            .config_name(Some("file_config".to_string()))
            .tun_name(value.tun_name)
            .bind_dev_name(value.bind_dev_name)
            .mtu(value.mtu)
            .group_code_filter_regex(group_code_filter_regex)
            .peer_str(value.peer)?;

        if let Some(exit_node) = value.exit_node {
            builder = builder.exit_node(Some(exit_node.parse().context("node_ipv6 format error")?))
        }

        builder.build()
    }
}

impl Default for FileConfigView {
    fn default() -> Self {
        Self {
            #[cfg(feature = "web")]
            api_addr: crate::CMD_ADDRESS,
            #[cfg(feature = "web")]
            api_disable: false,
            threads: 2,
            group_code: "".to_string(),
            node_ipv4: "".to_string(),
            prefix: 24,
            node_ipv6: None,
            prefix_v6: None,
            tun_name: None,
            encrypt: None,
            algorithm: DEFAULT_ALGORITHM.to_string(),
            port: LISTEN_PORT,
            peer: None,
            bind_dev_name: None,
            exit_node: None,
            mtu: None,
            udp_stun: None,
            tcp_stun: None,
            group_code_filter: None,
            username: None,
            password: None,
        }
    }
}
