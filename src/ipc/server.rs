use crate::ipc::common::{GroupItem, NetworkNatInfo, RouteItem};
use rustp2p::pipe::PipeWriter;
use rustp2p::protocol::node_id::GroupCode;
use std::io;
use std::net::Ipv4Addr;
use tokio::net::UdpSocket;
pub async fn start(port: u16, pipe_writer: PipeWriter) -> io::Result<()> {
    let addr = format!("127.0.0.1:{port}");
    let udp = UdpSocket::bind(&addr).await?;
    log::info!("start backend command server udp://{addr}");
    tokio::spawn(async move {
        if let Err(e) = start0(udp, pipe_writer).await {
            log::warn!("{e:?}");
        }
    });
    Ok(())
}
async fn start0(udp: UdpSocket, pipe_writer: PipeWriter) -> io::Result<()> {
    let mut buf = [0; 128];
    loop {
        let (len, addr) = udp.recv_from(&mut buf).await?;
        match std::str::from_utf8(&buf[..len]) {
            Ok(cmd) => match handle(cmd, &pipe_writer).await {
                Ok(rs) => {
                    let _ = udp.send_to(rs.as_bytes(), addr).await;
                }
                Err(e) => {
                    log::warn!("ipc error {e:?},addr={addr}");
                }
            },
            Err(e) => {
                log::warn!("{:?}", e);
            }
        }
    }
}
async fn handle(cmd: &str, pipe_writer: &PipeWriter) -> io::Result<String> {
    let cmd = cmd.trim();
    match cmd {
        "info" => {
            return current_info(pipe_writer).await;
        }
        "nodes" => {
            return current_nodes(pipe_writer).await;
        }
        "groups" => {
            let mut group_codes = Vec::new();
            let current_group_code = pipe_writer.current_group_code();
            let current_node_num = pipe_writer.nodes().len();
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
            let vec = pipe_writer.other_group_codes();
            for code in vec {
                let node_num = pipe_writer
                    .other_group_nodes(&code)
                    .map(|v| v.len())
                    .unwrap_or_default();
                let group_code = group_code_to_string(&code);
                group_codes.push(GroupItem {
                    group_code,
                    node_num,
                });
            }
            match serde_json::to_string(&group_codes) {
                Ok(rs) => return Ok(rs),
                Err(e) => {
                    log::debug!("cmd=groups,err={e:?}");
                }
            }
        }
        _ => {
            if let Some(group_code) = cmd.strip_prefix("other_nodes_") {
                if let Some(group_code) = crate::string_to_group_code(group_code) {
                    let current_group_code = pipe_writer.current_group_code();
                    if group_code == current_group_code {
                        return current_nodes(pipe_writer).await;
                    }
                    return other_nodes(pipe_writer, &group_code).await;
                }
            }
        }
    }
    Ok("error".to_string())
}
async fn current_info(pipe_writer: &PipeWriter) -> io::Result<String> {
    let punch_info = pipe_writer.pipe_context().punch_info().read().clone();
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
    match serde_json::to_string(&info) {
        Ok(rs) => Ok(rs),
        Err(e) => {
            log::debug!("cmd=current_info,err={e:?}");
            Ok("error".to_string())
        }
    }
}
async fn current_nodes(pipe_writer: &PipeWriter) -> io::Result<String> {
    let mut list = Vec::new();
    for node_id in pipe_writer.nodes() {
        if let Some(routes) = pipe_writer.lookup_route(&node_id) {
            let not_empty = !routes.is_empty();
            for route in routes {
                let next_hop = if route.is_relay() {
                    pipe_writer
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
    match serde_json::to_string(&list) {
        Ok(rs) => Ok(rs),
        Err(e) => {
            log::debug!("cmd=nodes,err={e:?}");
            Ok("error".to_string())
        }
    }
}

async fn other_nodes(pipe_writer: &PipeWriter, group_code: &GroupCode) -> io::Result<String> {
    let mut list = Vec::new();
    let nodes = if let Some(nodes) = pipe_writer.other_group_nodes(group_code) {
        nodes
    } else {
        return Ok(String::new());
    };
    for node_id in nodes {
        if let Some(routes) = pipe_writer.other_group_route(group_code, &node_id) {
            let not_empty = !routes.is_empty();
            for route in routes {
                let next_hop = if route.is_relay() {
                    pipe_writer
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
    match serde_json::to_string(&list) {
        Ok(rs) => Ok(rs),
        Err(e) => {
            log::debug!("cmd=nodes,err={e:?}");
            Ok("error".to_string())
        }
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
