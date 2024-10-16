use crate::ipc::common::{GroupItem, RouteItem};
use rustp2p::pipe::PipeWriter;
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
    match cmd.trim() {
        "nodes" => {
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
                Ok(rs) => return Ok(rs),
                Err(e) => {
                    log::debug!("cmd=nodes,err={e:?}");
                }
            }
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
                if let Ok(group_code) = String::from_utf8(code.as_ref().to_vec()) {
                    group_codes.push(GroupItem {
                        group_code,
                        node_num,
                    });
                } else {
                    group_codes.push(GroupItem {
                        group_code: format!("{:?}", code.as_ref()),
                        node_num,
                    })
                }
            }
            match serde_json::to_string(&group_codes) {
                Ok(rs) => return Ok(rs),
                Err(e) => {
                    log::debug!("cmd=groups,err={e:?}");
                }
            }
        }
        _ => {}
    }
    Ok("error".to_string())
}
