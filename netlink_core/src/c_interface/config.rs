use crate::config::{Config, ConfigBuilder, PeerAddress};
use libc::{c_char, c_uchar, c_uint, c_ushort};
use std::ffi::CStr;
use std::str::FromStr;
#[repr(C)]
pub struct CConfig {
    listen_route: bool,
    config_name: *mut c_char,
    node_ipv4: c_uint,
    node_ipv6: *mut u8, // len = 16
    prefix: c_uchar,
    prefix_v6: c_uchar,
    tun_name: *mut c_char,
    encrypt: *mut c_char,
    algorithm: *mut c_char,
    port: c_ushort,
    group_code: *mut c_char,
    peer: *mut *mut c_char,
    peer_count: c_uint,
    bind_dev_name: *mut c_char,
    exit_node: c_uint,
    udp_stun: *mut *mut c_char,
    udp_stun_count: c_uint,
    tcp_stun: *mut *mut c_char,
    tcp_stun_count: c_uint,
}
impl Drop for CConfig {
    fn drop(&mut self) {
        unsafe {
            // Free `config_name` string
            if !self.config_name.is_null() {
                libc::free(self.config_name as *mut libc::c_void);
            }

            // Free `tun_name` string
            if !self.tun_name.is_null() {
                libc::free(self.tun_name as *mut libc::c_void);
            }

            // Free `encrypt` string
            if !self.encrypt.is_null() {
                libc::free(self.encrypt as *mut libc::c_void);
            }

            // Free `algorithm` string
            if !self.algorithm.is_null() {
                libc::free(self.algorithm as *mut libc::c_void);
            }

            // Free `group_code` string
            if !self.group_code.is_null() {
                libc::free(self.group_code as *mut libc::c_void);
            }

            // Free `peer` array of strings
            if !self.peer.is_null() {
                for i in 0..self.peer_count {
                    let peer_ptr = *self.peer.offset(i as isize);
                    if !peer_ptr.is_null() {
                        libc::free(peer_ptr as *mut libc::c_void);
                    }
                }
                libc::free(self.peer as *mut libc::c_void);
            }

            // Free `udp_stun` array of strings
            if !self.udp_stun.is_null() {
                for i in 0..self.udp_stun_count {
                    let udp_stun_ptr = *self.udp_stun.offset(i as isize);
                    if !udp_stun_ptr.is_null() {
                        libc::free(udp_stun_ptr as *mut libc::c_void);
                    }
                }
                libc::free(self.udp_stun as *mut libc::c_void);
            }

            // Free `tcp_stun` array of strings
            if !self.tcp_stun.is_null() {
                for i in 0..self.tcp_stun_count {
                    let tcp_stun_ptr = *self.tcp_stun.offset(i as isize);
                    if !tcp_stun_ptr.is_null() {
                        libc::free(tcp_stun_ptr as *mut libc::c_void);
                    }
                }
                libc::free(self.tcp_stun as *mut libc::c_void);
            }

            // Free `node_ipv6` array (assuming it's dynamically allocated)
            if !self.node_ipv6.is_null() {
                libc::free(self.node_ipv6 as *mut libc::c_void);
            }
        }
    }
}

pub(crate) unsafe fn to_config(c_config: &CConfig) -> anyhow::Result<Config> {
    let config_name = if !c_config.config_name.is_null() {
        Some(
            CStr::from_ptr(c_config.config_name)
                .to_string_lossy()
                .into_owned(),
        )
    } else {
        None
    };
    if c_config.group_code.is_null() {
        Err(anyhow::anyhow!(
            "Received null pointer for CConfig group_code"
        ))?;
    }
    let group_code = CStr::from_ptr(c_config.group_code)
        .to_string_lossy()
        .into_owned();
    let tun_name = if !c_config.tun_name.is_null() {
        Some(
            CStr::from_ptr(c_config.tun_name)
                .to_string_lossy()
                .into_owned(),
        )
    } else {
        None
    };

    let encrypt = if !c_config.encrypt.is_null() {
        Some(
            CStr::from_ptr(c_config.encrypt)
                .to_string_lossy()
                .into_owned(),
        )
    } else {
        None
    };

    let algorithm = if !c_config.algorithm.is_null() {
        Some(
            CStr::from_ptr(c_config.algorithm)
                .to_string_lossy()
                .into_owned(),
        )
    } else {
        None
    };
    let bind_dev_name = if !c_config.bind_dev_name.is_null() {
        Some(
            CStr::from_ptr(c_config.bind_dev_name)
                .to_string_lossy()
                .into_owned(),
        )
    } else {
        None
    };

    let peer = if !c_config.peer.is_null() {
        let mut peers = Vec::new();
        for i in 0..c_config.peer_count {
            let peer_ptr = *c_config.peer.offset(i as isize);
            if !peer_ptr.is_null() {
                peers.push(CStr::from_ptr(peer_ptr).to_string_lossy().into_owned());
            }
        }
        Some(peers)
    } else {
        None
    };

    let udp_stun = if !c_config.udp_stun.is_null() {
        let mut stuns = Vec::new();
        for i in 0..c_config.udp_stun_count {
            let stun_ptr = *c_config.udp_stun.offset(i as isize);
            if !stun_ptr.is_null() {
                stuns.push(CStr::from_ptr(stun_ptr).to_string_lossy().into_owned());
            }
        }
        stuns
    } else {
        Vec::new()
    };

    let tcp_stun = if !c_config.tcp_stun.is_null() {
        let mut stuns = Vec::new();
        for i in 0..c_config.tcp_stun_count {
            let stun_ptr = *c_config.tcp_stun.offset(i as isize);
            if !stun_ptr.is_null() {
                stuns.push(CStr::from_ptr(stun_ptr).to_string_lossy().into_owned());
            }
        }
        stuns
    } else {
        Vec::new()
    };
    let peer = if let Some(peer) = peer {
        let mut list = Vec::new();
        for addr in peer {
            list.push(PeerAddress::from_str(&addr)?)
        }
        Some(list)
    } else {
        None
    };
    let exit_node = if c_config.exit_node == 0 {
        None
    } else {
        Some(c_config.exit_node.into())
    };
    let node_ipv6 = if c_config.node_ipv6.is_null() {
        None
    } else {
        unsafe {
            let node_ipv6 = std::slice::from_raw_parts_mut(c_config.node_ipv6, 16);
            let node_ipv6: [u8; 16] = node_ipv6.try_into().unwrap();
            Some(node_ipv6.into())
        }
    };
    let mut builder = ConfigBuilder::new()
        .listen_route(c_config.listen_route)
        .udp_stun(udp_stun)
        .tcp_stun(tcp_stun)
        .node_ipv4(c_config.node_ipv4.into())
        .exit_node(exit_node)
        .prefix(c_config.prefix)
        .prefix_v6(c_config.prefix_v6)
        .group_code(group_code.try_into()?)
        .port(c_config.port)
        .algorithm(algorithm)
        .encrypt(encrypt)
        .config_name(config_name)
        .tun_name(tun_name)
        .bind_dev_name(bind_dev_name)
        .peer(peer);
    if let Some(node_ipv6) = node_ipv6 {
        builder = builder.node_ipv6(node_ipv6);
    }
    builder.build()
}
