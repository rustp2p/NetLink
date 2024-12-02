use crate::route::{prefix_to_mask, ExternalRoute};
use async_shutdown::ShutdownManager;
use futures::StreamExt;
use net_route::{Handle, Route, RouteChange};
use std::net::{IpAddr, Ipv4Addr};

pub async fn route_listen(
    shutdown_manager: ShutdownManager<()>,
    if_index: u32,
    external_route: ExternalRoute,
) -> std::io::Result<()> {
    let handle = Handle::new()?;
    let stream = handle.route_listen_stream();

    tokio::spawn(async move {
        futures::pin_mut!(stream);
        loop {
            if shutdown_manager.is_shutdown_triggered() {
                return;
            }
            let value = if let Ok(rs) = shutdown_manager.wrap_cancel(stream.next()).await {
                if let Some(rs) = rs {
                    rs
                } else {
                    log::warn!("route_listen exit");
                    return;
                }
            } else {
                return;
            };
            let (action, route) = match value {
                RouteChange::Add(route) => ("add", route),
                RouteChange::Delete(route) => ("delete", route),
                RouteChange::Change(route) => ("change", route),
            };
            if let Some((dest, mask, next)) = route_warp(route, if_index) {
                log::info!(
                    "{action} subnet route {}/{} -> {next}",
                    Ipv4Addr::from(dest),
                    mask.count_ones()
                )
            } else {
                continue;
            }
            match handle.list().await {
                Ok(list) => {
                    let mut routes: Vec<(u32, u32, Ipv4Addr)> = Vec::new();
                    for route in list {
                        if let Some(route) = route_warp(route, if_index) {
                            routes.push(route);
                        }
                    }
                    external_route.update(routes);
                }
                Err(e) => {
                    log::warn!("route list error {:?}", e);
                }
            };
        }
    });
    Ok(())
}

fn route_warp(route: Route, if_index: u32) -> Option<(u32, u32, Ipv4Addr)> {
    if let Some(index) = route.ifindex {
        if index == if_index {
            match route.destination {
                IpAddr::V4(dest) => {
                    if let Some(gateway) = route.gateway {
                        match gateway {
                            IpAddr::V4(gateway) => {
                                if !gateway.is_unspecified() {
                                    let mask = prefix_to_mask(route.prefix);
                                    let dest: u32 = dest.into();
                                    return Some((dest, mask, gateway));
                                }
                            }
                            IpAddr::V6(_) => {}
                        }
                    }
                }
                IpAddr::V6(_) => {}
            }
        }
    }
    None
}
