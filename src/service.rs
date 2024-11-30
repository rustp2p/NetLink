use netlink_http::service::ApiService as Api;
use netlink_http::Config;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const CONFIG_FILE: &str = "config.json";

#[derive(Clone, Default)]
pub struct ApiService {
    path: PathBuf,
    api: Api,
}

impl Deref for ApiService {
    type Target = Api;

    fn deref(&self) -> &Self::Target {
        &self.api
    }
}

impl ApiService {
    pub async fn new(config: Option<Config>) -> anyhow::Result<ApiService> {
        let fall_back = PathBuf::from("./");
        let exe_in_path = std::env::current_exe()
            .map(|path| path.parent().unwrap_or(fall_back.as_path()).to_owned())
            .unwrap_or(fall_back);
        let config = if config.is_none() {
            Self::load_config_by_file(&exe_in_path).await.ok()
        } else {
            config
        };
        let api_service = Self {
            path: exe_in_path,
            api: Default::default(),
        };
        if let Some(config) = config {
            api_service.update_config(config.clone()).await?;
            if let Err(e) = api_service.save_config_to_file(config).await {
                log::debug!("{e}");
            }
        }
        Ok(api_service)
    }
    #[allow(dead_code)]
    pub fn inner_api(&self) -> Api {
        self.api.clone()
    }
    pub async fn update_config(&self, config: Config) -> anyhow::Result<()> {
        self.api.update_config(config.clone())?;
        if let Err(e) = self.save_config_to_file(config).await {
            log::debug!("save config to file failed {e}");
        }
        Ok(())
    }
    #[allow(dead_code)]
    pub async fn save_config(&self) -> anyhow::Result<()> {
        if let Some(config) = self.load_config() {
            self.save_config_to_file(config).await?;
        }
        Ok(())
    }
    pub async fn save_config_to_file(&self, config: Config) -> anyhow::Result<()> {
        let json_str = serde_json::to_string(&config)?;
        let path_buf = self.path.join(CONFIG_FILE);
        let mut file = File::create(path_buf).await?;
        file.write_all(json_str.as_bytes()).await?;
        Ok(())
    }
    pub async fn load_config_by_file(path: &Path) -> anyhow::Result<Config> {
        let path_buf = path.join(CONFIG_FILE);
        let mut file = File::open(path_buf).await?;
        let mut rs = String::new();
        file.read_to_string(&mut rs).await?;
        let config = serde_json::from_str::<Config>(&rs)?;
        Ok(config)
    }
}
