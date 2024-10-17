use std::net::Ipv4Addr;

use rustp2p::pipe::PipeWriter;
use rustp2p::protocol::node_id::GroupCode;

use crate::ipc::common::{GroupItem, NetworkNatInfo, RouteItem};

#[derive(Clone)]
pub struct ApiService {
    pipe_writer: PipeWriter,
}

impl ApiService {
    pub fn new(pipe_writer: PipeWriter) -> ApiService {
        Self { pipe_writer }
    }
}

impl ApiService {
    pub fn current_info(&self) -> anyhow::Result<NetworkNatInfo> {
        let punch_info = self.pipe_writer.pipe_context().punch_info().read().clone();
        let info = NetworkNatInfo {
            local_ipv4: punch_info.local_ipv4,
            ipv6: punch_info.ipv6,
            nat_type: punch_info.nat_type,
            public_ips: punch_info.public_ips,
            public_udp_ports: punch_info.public_udp_ports,
            public_tcp_port: punch_info.public_tcp_port,
            local_udp_ports: punch_info.local_udp_ports,
            local_tcp_port: punch_info.local_tcp_port,
        };
        Ok(info)
    }
    pub fn current_nodes(&self) -> anyhow::Result<Vec<RouteItem>> {
        let mut list = Vec::new();
        for node_id in self.pipe_writer.nodes() {
            if let Some(routes) = self.pipe_writer.lookup_route(&node_id) {
                let not_empty = !routes.is_empty();
                for route in routes {
                    let next_hop = if route.is_relay() {
                        self.pipe_writer
                            .route_to_node_id(&route.route_key())
                            .map(|v| format!("{}", Ipv4Addr::from(v)))
                    } else {
                        Some("Direct-Connection".to_string())
                    };

                    list.push(RouteItem {
                        node_id: format!("{}", Ipv4Addr::from(node_id)),
                        next_hop: next_hop.unwrap_or_default(),
                        protocol: format!("{:?}", route.route_key().protocol()),
                        metric: route.metric(),
                        rtt: route.rtt(),
                    })
                }
                if not_empty {
                    continue;
                }
            }
            list.push(RouteItem {
                node_id: format!("{}", Ipv4Addr::from(node_id)),
                next_hop: String::new(),
                protocol: "Not linked".to_string(),
                metric: 0,
                rtt: 0,
            })
        }
        Ok(list)
    }
    pub fn nodes_by_group(&self, group_code: &str) -> anyhow::Result<Vec<RouteItem>> {
        if let Some(group_code) = crate::string_to_group_code(group_code) {
            let current_group_code = self.pipe_writer.current_group_code();
            if group_code == current_group_code {
                return self.current_nodes();
            }
            return self.other_nodes(&group_code);
        }
        Err(anyhow::anyhow!("group_code error"))
    }
    pub fn other_nodes(&self, group_code: &GroupCode) -> anyhow::Result<Vec<RouteItem>> {
        let mut list = Vec::new();
        let nodes = if let Some(nodes) = self.pipe_writer.other_group_nodes(group_code) {
            nodes
        } else {
            return Ok(list);
        };
        for node_id in nodes {
            if let Some(routes) = self.pipe_writer.other_group_route(group_code, &node_id) {
                let not_empty = !routes.is_empty();
                for route in routes {
                    let next_hop = if route.is_relay() {
                        self.pipe_writer
                            .other_route_to_node_id(group_code, &route.route_key())
                            .map(|v| format!("{}", Ipv4Addr::from(v)))
                    } else {
                        Some("Direct-Connection".to_string())
                    };

                    list.push(RouteItem {
                        node_id: format!("{}", Ipv4Addr::from(node_id)),
                        next_hop: next_hop.unwrap_or_default(),
                        protocol: format!("{:?}", route.route_key().protocol()),
                        metric: route.metric(),
                        rtt: route.rtt(),
                    })
                }
                if not_empty {
                    continue;
                }
            }
            list.push(RouteItem {
                node_id: format!("{}", Ipv4Addr::from(node_id)),
                next_hop: String::new(),
                protocol: "Not linked".to_string(),
                metric: 0,
                rtt: 0,
            })
        }
        Ok(list)
    }
    pub fn groups(&self) -> anyhow::Result<Vec<GroupItem>> {
        let mut group_codes = Vec::new();
        let current_group_code = self.pipe_writer.current_group_code();
        let current_node_num = self.pipe_writer.nodes().len();
        match String::from_utf8(current_group_code.as_ref().to_vec()) {
            Ok(group_code) => group_codes.push(GroupItem {
                group_code,
                node_num: current_node_num,
            }),
            Err(_) => group_codes.push(GroupItem {
                group_code: format!("{:?}", current_group_code.as_ref()),
                node_num: current_node_num,
            }),
        }
        let vec = self.pipe_writer.other_group_codes();
        for code in vec {
            let node_num = self
                .pipe_writer
                .other_group_nodes(&code)
                .map(|v| v.len())
                .unwrap_or_default();
            let group_code = group_code_to_string(&code);
            group_codes.push(GroupItem {
                group_code,
                node_num,
            });
        }
        Ok(group_codes)
    }
}

fn group_code_to_string(group_code: &GroupCode) -> String {
    let mut vec = group_code.as_ref().to_vec();
    if let Some(pos) = vec.iter().rposition(|&x| x != 0) {
        vec.truncate(pos + 1);
    }
    match String::from_utf8(vec) {
        Ok(group_code) => group_code,
        Err(_) => format!("{:?}", group_code.as_ref()),
    }
}
