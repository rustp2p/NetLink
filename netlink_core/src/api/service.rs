use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;

use async_shutdown::ShutdownManager;
use rustp2p::pipe::PipeWriter;

use crate::api::entity::{GroupItem, NetworkNatInfo, RouteItem};
use crate::config::{Config, GroupCode};
use crate::netlink_task::start_netlink;
use crate::route::ExternalRoute;

pub struct NetLinkCoreApi {
    config: Config,
    pipe: Arc<PipeWriter>,
    shutdown_manager: ShutdownManager<()>,
    external_route: Option<ExternalRoute>,
}

impl NetLinkCoreApi {
    pub async fn open(config: Config) -> anyhow::Result<Self> {
        let (pipe, external_route, shutdown_manager) = start_netlink(
            config.clone(),
            #[cfg(unix)]
            None,
        )
        .await?;
        Ok(Self {
            config,
            pipe,
            shutdown_manager,
            external_route,
        })
    }
    /// # Safety
    /// This method is safe if the provided fd is valid.
    /// Construct a TUN from an existing file descriptor
    #[cfg(unix)]
    pub async unsafe fn open_with_tun_fd(config: Config, tun_fd: u32) -> anyhow::Result<Self> {
        let (pipe, external_route, shutdown_manager) =
            start_netlink(config.clone(), Some(tun_fd)).await?;
        Ok(Self {
            config,
            pipe,
            shutdown_manager,
            external_route,
        })
    }
    pub fn close(self) {
        self.shutdown();
    }
    pub fn shutdown(&self) {
        _ = self.pipe.shutdown();
        _ = self.shutdown_manager.trigger_shutdown(());
    }
    pub async fn wait_shutdown_triggered(&self) {
        self.shutdown_manager.wait_shutdown_triggered().await
    }
    pub async fn wait_shutdown_complete(&self) {
        self.shutdown_manager.wait_shutdown_complete().await
    }
    pub fn is_shutdown_triggered(&self) -> bool {
        self.shutdown_manager.is_shutdown_triggered()
    }
    pub fn is_shutdown_completed(&self) -> bool {
        self.shutdown_manager.is_shutdown_completed()
    }
    pub fn current_config(&self) -> &Config {
        &self.config
    }
    pub(crate) fn pipe_writer(&self) -> &PipeWriter {
        &self.pipe
    }
    pub fn current_info(&self) -> anyhow::Result<NetworkNatInfo> {
        let pipe_writer = self.pipe_writer();
        let punch_info = pipe_writer.pipe_context().punch_info().read().clone();
        let info = NetworkNatInfo {
            node_ip: pipe_writer
                .pipe_context()
                .load_id()
                .map(|v| v.into())
                .unwrap_or(Ipv4Addr::UNSPECIFIED),
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
        let pipe_writer = self.pipe_writer();
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
                        node_id: Ipv4Addr::from(node_id),
                        next_hop: next_hop.unwrap_or_default(),
                        protocol: format!("{:?}", route.route_key().protocol()),
                        metric: route.metric(),
                        rtt: route.rtt(),
                        interface: route.route_key().addr().to_string(),
                    })
                }
                if not_empty {
                    continue;
                }
            }
            list.push(RouteItem {
                node_id: Ipv4Addr::from(node_id),
                next_hop: String::new(),
                protocol: "Not linked".to_string(),
                metric: 0,
                rtt: 0,
                interface: "".to_string(),
            })
        }
        Ok(list)
    }
    pub fn nodes_by_group(&self, group_code: &str) -> anyhow::Result<Vec<RouteItem>> {
        let pipe_writer = self.pipe_writer();
        let group_code = GroupCode::from_str(group_code)?;
        let current_group_code = pipe_writer.current_group_code();
        if group_code.0 == current_group_code {
            return self.current_nodes();
        }
        self.other_nodes(&group_code)
    }
    pub fn other_nodes(&self, group_code: &GroupCode) -> anyhow::Result<Vec<RouteItem>> {
        let pipe_writer = self.pipe_writer();
        let mut list = Vec::new();
        let nodes = if let Some(nodes) = pipe_writer.other_group_nodes(&group_code.0) {
            nodes
        } else {
            return Ok(list);
        };
        for node_id in nodes {
            if let Some(routes) = pipe_writer.other_group_route(&group_code.0, &node_id) {
                let not_empty = !routes.is_empty();
                for route in routes {
                    let next_hop = if route.is_relay() {
                        pipe_writer
                            .other_route_to_node_id(&group_code.0, &route.route_key())
                            .map(|v| format!("{}", Ipv4Addr::from(v)))
                    } else {
                        Some("Direct-Connection".to_string())
                    };

                    list.push(RouteItem {
                        node_id: Ipv4Addr::from(node_id),
                        next_hop: next_hop.unwrap_or_default(),
                        protocol: format!("{:?}", route.route_key().protocol()),
                        metric: route.metric(),
                        rtt: route.rtt(),
                        interface: route.route_key().addr().to_string(),
                    })
                }
                if not_empty {
                    continue;
                }
            }
            list.push(RouteItem {
                node_id: Ipv4Addr::from(node_id),
                next_hop: String::new(),
                protocol: "Not linked".to_string(),
                metric: 0,
                rtt: 0,
                interface: "".to_string(),
            })
        }
        Ok(list)
    }
    pub fn groups(&self) -> anyhow::Result<Vec<GroupItem>> {
        let pipe_writer = self.pipe_writer();
        let mut group_codes = Vec::new();
        let current_group_code = pipe_writer.current_group_code();
        let current_node_num = pipe_writer.nodes().len();
        group_codes.push(GroupItem {
            group_code: GroupCode(current_group_code).to_string(),
            node_num: current_node_num,
        });
        let vec = pipe_writer.other_group_codes();
        for code in vec {
            let node_num = pipe_writer
                .other_group_nodes(&code)
                .map(|v| v.len())
                .unwrap_or_default();
            group_codes.push(GroupItem {
                group_code: GroupCode(code).to_string(),
                node_num,
            });
        }
        Ok(group_codes)
    }
    pub fn update_external_route(
        &self,
        route_table: Vec<(u32, u32, Ipv4Addr)>,
    ) -> anyhow::Result<()> {
        if let Some(external_route) = self.external_route.as_ref() {
            external_route.update(route_table);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Does not support routing"))
        }
    }
}
impl Drop for NetLinkCoreApi {
    fn drop(&mut self) {
        let _ = self.pipe.shutdown();
        let _ = self.shutdown_manager.trigger_shutdown(());
    }
}
