use std::io;

use tokio::net::UdpSocket;

use crate::ipc::service::ApiService;

pub async fn start(addr: String, api_service: ApiService) -> io::Result<()> {
    let udp = UdpSocket::bind(&addr).await?;
    log::info!("start backend command server udp://{addr}");
    tokio::spawn(async move {
        if let Err(e) = start0(udp, api_service).await {
            log::warn!("{e:?}");
        }
    });
    Ok(())
}

async fn start0(udp: UdpSocket, api_service: ApiService) -> io::Result<()> {
    let mut buf = [0; 128];
    loop {
        let (len, addr) = udp.recv_from(&mut buf).await?;
        match std::str::from_utf8(&buf[..len]) {
            Ok(cmd) => match handle(cmd, &api_service).await {
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

async fn handle(cmd: &str, api_service: &ApiService) -> io::Result<String> {
    let cmd = cmd.trim();
    match cmd {
        "info" => {
            return match api_service.current_info() {
                Ok(rs) => match serde_json::to_string(&rs) {
                    Ok(rs) => Ok(rs),
                    Err(e) => {
                        log::debug!("cmd=current_info,err={e:?}");
                        Ok("error".to_string())
                    }
                },
                Err(e) => {
                    log::debug!("cmd=current_info,err={e:?}");
                    Ok("error".to_string())
                }
            };
        }
        "nodes" => {
            return match api_service.current_nodes() {
                Ok(rs) => match serde_json::to_string(&rs) {
                    Ok(rs) => Ok(rs),
                    Err(e) => {
                        log::debug!("cmd=current_nodes,err={e:?}");
                        Ok("error".to_string())
                    }
                },
                Err(e) => {
                    log::debug!("cmd=current_nodes,err={e:?}");
                    Ok("error".to_string())
                }
            };
        }
        "groups" => {
            return match api_service.groups() {
                Ok(rs) => match serde_json::to_string(&rs) {
                    Ok(rs) => return Ok(rs),
                    Err(e) => {
                        log::debug!("cmd=groups,err={e:?}");
                        Ok("error".to_string())
                    }
                },
                Err(e) => {
                    log::debug!("cmd=current_nodes,err={e:?}");
                    Ok("error".to_string())
                }
            };
        }
        _ => {
            if let Some(group_code) = cmd.strip_prefix("other_nodes_") {
                return match api_service.nodes_by_group(group_code) {
                    Ok(rs) => match serde_json::to_string(&rs) {
                        Ok(rs) => return Ok(rs),
                        Err(e) => {
                            log::debug!("cmd=nodes_by_group,err={e:?}");
                            Ok("error".to_string())
                        }
                    },
                    Err(e) => {
                        log::debug!("cmd=nodes_by_group,err={e:?}");
                        Ok("error".to_string())
                    }
                };
            }
        }
    }
    Ok("error".to_string())
}
