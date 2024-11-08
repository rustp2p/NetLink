use std::sync::Arc;

use parking_lot::Mutex;

use netlink_core::api::entity::{GroupItem, NetworkNatInfo, RouteItem};
use netlink_core::api::NetLinkCoreApi;
use netlink_core::config::Config;

#[derive(Clone)]
pub struct ApiService {
    lock: Arc<tokio::sync::Mutex<()>>,
    config: Arc<Mutex<Option<(Config, usize)>>>,
    api: Arc<Mutex<Option<(NetLinkCoreApi, usize)>>>,
}

impl ApiService {
    pub fn new() -> Self {
        Self {
            lock: Arc::new(Default::default()),
            config: Arc::new(Default::default()),
            api: Arc::new(Default::default()),
        }
    }
    pub fn load_config(&self) -> Option<Config> {
        self.api
            .lock()
            .as_ref()
            .map(|(v, _)| v.current_config().clone())
    }
    pub async fn update_config(&self, config_view: Config) -> anyhow::Result<()> {
        let mut guard = self.config.lock();
        if let Some((config, epoch)) = guard.as_mut() {
            *config = config_view;
            *epoch += *epoch;
        } else {
            guard.replace((config_view, 1));
        }
        Ok(())
    }
    pub fn is_close(&self) -> bool {
        self.api.lock().is_none()
    }
    pub fn close(&self) -> anyhow::Result<()> {
        if let Some((v, _)) = self.api.lock().take() {
            v.close();
        }
        Ok(())
    }
    pub async fn open(&self) -> anyhow::Result<()> {
        let guard = self.lock.lock().await;
        let config = self.config.lock().clone();
        if !self.is_close() {
            Err(anyhow::anyhow!("Started"))?
        }
        if let Some((config, epoch)) = config {
            let api = NetLinkCoreApi::open(config).await?;
            self.api.lock().replace((api, epoch));
            drop(guard);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Notfound config"))?
        }
    }
}
impl ApiService {
    pub fn started_config(&self) -> Option<Config> {
        self.api
            .lock()
            .as_ref()
            .map(|(v, _)| v.current_config().clone())
    }
    pub fn current_config(&self) -> anyhow::Result<Option<Config>> {
        let config = if let Some((config, _)) = self.config.lock().clone() {
            Some(config)
        } else {
            None
        };
        Ok(config)
    }
    pub fn current_config_check(&self) -> Option<(Config, bool)> {
        if let Some((config, epoch)) = self.config.lock().clone() {
            if let Some((_, v)) = self.api.lock().as_ref() {
                Some((config, epoch == *v))
            } else {
                Some((config, false))
            }
        } else {
            None
        }
    }
    pub fn current_info(&self) -> anyhow::Result<NetworkNatInfo> {
        if let Some((v, _)) = self.api.lock().as_ref() {
            v.current_info()
        } else {
            Err(anyhow::anyhow!("Not Started"))?
        }
    }
    pub fn current_nodes(&self) -> anyhow::Result<Vec<RouteItem>> {
        if let Some((v, _)) = self.api.lock().as_ref() {
            v.current_nodes()
        } else {
            Err(anyhow::anyhow!("Not Started"))?
        }
    }
    pub fn nodes_by_group(&self, group_code: &str) -> anyhow::Result<Vec<RouteItem>> {
        if let Some((v, _)) = self.api.lock().as_ref() {
            v.nodes_by_group(group_code)
        } else {
            Err(anyhow::anyhow!("Not Started"))?
        }
    }
    pub fn groups(&self) -> anyhow::Result<Vec<GroupItem>> {
        if let Some((v, _)) = self.api.lock().as_ref() {
            v.groups()
        } else {
            Err(anyhow::anyhow!("Not Started"))?
        }
    }
}
