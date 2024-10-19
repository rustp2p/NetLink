use crate::config::{group_code_to_string, Config, ConfigView};
use crate::ipc::common::{GroupItem, NetworkNatInfo, RouteItem};
use async_shutdown::ShutdownManager;
use parking_lot::Mutex;
use rustp2p::pipe::PipeWriter;
use rustp2p::protocol::node_id::GroupCode;
use std::net::Ipv4Addr;
use std::sync::Arc;

type PipeInfo = Arc<Mutex<Option<(PipeWriter, ShutdownManager<()>)>>>;
#[derive(Clone)]
pub struct ApiService {
    config: Arc<Mutex<Config>>,
    pipe: PipeInfo,
}

impl ApiService {
    pub fn new(config: Config) -> ApiService {
        Self {
            pipe: Default::default(),
            config: Arc::new(Mutex::new(config)),
        }
    }
    pub fn load_config(&self) -> Config {
        self.config.lock().clone()
    }
    pub fn save_config(&self, config: Config) {
        *self.config.lock() = config;
    }
    pub fn set_pipe(&self, pipe_writer: PipeWriter, shutdown_manager: ShutdownManager<()>) {
        if let Some((v1, v2)) = self.pipe.lock().replace((pipe_writer, shutdown_manager)) {
            if let Err(e) = v1.shutdown() {
                log::error!("shutdown failed {e:?}");
            }
            if let Err(e) = v2.trigger_shutdown(()) {
                log::error!("shutdown failed {e:?}");
            }
        }
    }
}

impl ApiService {
    pub fn pipe_writer(&self) -> Option<PipeWriter> {
        self.pipe.lock().as_ref().map(|(v1, _)| v1.clone())
    }
    pub fn is_close(&self) -> bool {
        self.pipe.lock().is_none()
    }
    pub fn close(&self) -> anyhow::Result<()> {
        let pipe = self.pipe.lock().take();
        if let Some((pipe_writer, shutdown_manager)) = pipe {
            let rs1 = shutdown_manager.trigger_shutdown(());
            let rs2 = pipe_writer.shutdown();
            rs1?;
            rs2?;
        } else {
            Err(anyhow::anyhow!("Not Started"))?
        }

        Ok(())
    }
    pub async fn open(&self) -> anyhow::Result<()> {
        if self.pipe.lock().is_some() {
            Err(anyhow::anyhow!("Started"))?
        }
        crate::start(self.clone()).await?;
        Ok(())
    }
    pub fn current_config(&self) -> anyhow::Result<ConfigView> {
        Ok(self.config.lock().to_config_view())
    }
    pub fn update_config(&self, config_view: ConfigView) -> anyhow::Result<()> {
        let config = config_view.into_config()?;
        self.save_config(config);
        Ok(())
    }
    pub fn current_info(&self) -> anyhow::Result<NetworkNatInfo> {
        let pipe_writer = if let Some(pipe_writer) = self.pipe_writer() {
            pipe_writer
        } else {
            Err(anyhow::anyhow!("Not Started"))?
        };
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
        let pipe_writer = if let Some(pipe_writer) = self.pipe_writer() {
            pipe_writer
        } else {
            Err(anyhow::anyhow!("Not Started"))?
        };
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
                        interface: route.route_key().addr().to_string(),
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
                interface: "".to_string(),
            })
        }
        Ok(list)
    }
    pub fn nodes_by_group(&self, group_code: &str) -> anyhow::Result<Vec<RouteItem>> {
        let pipe_writer = if let Some(pipe_writer) = self.pipe_writer() {
            pipe_writer
        } else {
            Err(anyhow::anyhow!("Not Started"))?
        };
        if let Some(group_code) = crate::string_to_group_code(group_code) {
            let current_group_code = pipe_writer.current_group_code();
            if group_code == current_group_code {
                return self.current_nodes();
            }
            return self.other_nodes(&group_code);
        }
        Err(anyhow::anyhow!("group_code error"))
    }
    pub fn other_nodes(&self, group_code: &GroupCode) -> anyhow::Result<Vec<RouteItem>> {
        let pipe_writer = if let Some(pipe_writer) = self.pipe_writer() {
            pipe_writer
        } else {
            Err(anyhow::anyhow!("Not Started"))?
        };
        let mut list = Vec::new();
        let nodes = if let Some(nodes) = pipe_writer.other_group_nodes(group_code) {
            nodes
        } else {
            return Ok(list);
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
                        interface: route.route_key().addr().to_string(),
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
                interface: "".to_string(),
            })
        }
        Ok(list)
    }
    pub fn groups(&self) -> anyhow::Result<Vec<GroupItem>> {
        let pipe_writer = if let Some(pipe_writer) = self.pipe_writer() {
            pipe_writer
        } else {
            Err(anyhow::anyhow!("Not Started"))?
        };
        let mut group_codes = Vec::new();
        let current_group_code = pipe_writer.current_group_code();
        let current_node_num = pipe_writer.nodes().len();
        group_codes.push(GroupItem {
            group_code: group_code_to_string(&current_group_code),
            node_num: current_node_num,
        });
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
        Ok(group_codes)
    }
}
