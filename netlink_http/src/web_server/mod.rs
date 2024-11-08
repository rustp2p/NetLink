use mime_guess::Mime;
use salvo::http::Method;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{net::SocketAddr, path::PathBuf};

#[handler]
async fn application_info(res: &mut Response) -> anyhow::Result<()> {
    res.render(Text::Json(
        json!({
            "code":200,
            "data":ApplicationInfo::default()
        })
        .to_string(),
    ));
    Ok(())
}

struct Open(ApiService);
#[async_trait]
impl Handler for Open {
    async fn handle(
        &self,
        _req: &mut Request,
        _depot: &mut Depot,
        res: &mut Response,
        _ctrl: &mut FlowCtrl,
    ) {
        if self.0.load_config().is_none() {
            res.render(Text::Json(
                json!({
                    "code":400,
                    "data":"没有可用配置进行启动"
                })
                .to_string(),
            ));
            return;
        }
        match self.0.open().await {
            Ok(_) => {
                res.render(Text::Json(
                    json!({
                        "code":200,
                        "data":"success"
                    })
                    .to_string(),
                ));
            }
            Err(e) => {
                res.render(Text::Json(
                    json!({
                        "code":400,
                        "data":format!("{e}")
                    })
                    .to_string(),
                ));
            }
        }
    }
}

struct ApiQueryHandler<R>(ApiService, fn(&ApiService) -> anyhow::Result<R>, bool);
#[async_trait]
impl<R: 'static + Send + Sync + Serialize> Handler for ApiQueryHandler<R> {
    async fn handle(
        &self,
        _req: &mut Request,
        _depot: &mut Depot,
        res: &mut Response,
        _ctrl: &mut FlowCtrl,
    ) {
        if self.2 && self.0.is_close() {
            res.render(Text::Json(
                json!({
                    "code":503,
                    "data":"Not Started"
                })
                .to_string(),
            ));
            return;
        }
        match (self.1)(&self.0) {
            Ok(rs) => {
                res.render(Text::Json(
                    json!({
                        "code":200,
                        "data":rs
                    })
                    .to_string(),
                ));
            }
            Err(e) => {
                res.render(Text::Json(
                    json!({
                        "code":400,
                        "data":format!("{e}")
                    })
                    .to_string(),
                ));
            }
        }
    }
}

struct UpdateConfig(ApiService);
#[async_trait]
impl Handler for UpdateConfig {
    async fn handle(
        &self,
        req: &mut Request,
        _depot: &mut Depot,
        res: &mut Response,
        _ctrl: &mut FlowCtrl,
    ) {
        match req.parse_json::<Config>().await {
            Ok(config_view) => match self.0.update_config(config_view).await {
                Ok(_) => {
                    res.render(Text::Json(
                        json!({
                            "code":200,
                            "data":"success"
                        })
                        .to_string(),
                    ));
                }
                Err(e) => {
                    res.render(Text::Json(
                        json!({
                            "code":400,
                            "data":format!("{e}")
                        })
                        .to_string(),
                    ));
                }
            },
            Err(e) => {
                res.render(Text::Json(
                    json!({
                        "code":400,
                        "data":format!("{e}")
                    })
                    .to_string(),
                ));
                return;
            }
        };
    }
}

struct NodesByGroup(ApiService);
#[async_trait]
impl Handler for NodesByGroup {
    async fn handle(
        &self,
        req: &mut Request,
        _depot: &mut Depot,
        res: &mut Response,
        _ctrl: &mut FlowCtrl,
    ) {
        if self.0.is_close() {
            res.render(Text::Json(
                json!({
                    "code":503,
                    "data":"Not Started"
                })
                .to_string(),
            ));
            return;
        }
        match req.param::<String>("group") {
            Some(group_code) => match self.0.nodes_by_group(&group_code) {
                Ok(rs) => {
                    res.render(Text::Json(
                        json!({
                            "code":200,
                            "data":rs
                        })
                        .to_string(),
                    ));
                }
                Err(e) => {
                    res.render(Text::Json(
                        json!({
                            "code":400,
                            "data":format!("{e}")
                        })
                        .to_string(),
                    ));
                }
            },
            None => {
                res.render(Text::Json(
                    json!({
                        "code":400,
                        "data":"group-code is required"
                    })
                    .to_string(),
                ));
                return;
            }
        };
    }
}

use crate::service::ApiService;
use netlink_core::config::Config;
use salvo::cors::{Cors, CorsHandler};

fn allow_cors() -> CorsHandler {
    Cors::new()
        .allow_origin("*")
        .allow_methods(vec![
            Method::GET,
            Method::POST,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers("*")
        .into_handler()
}

pub async fn start(addr: SocketAddr, api_service: ApiService) -> anyhow::Result<()> {
    let acceptor = TcpListener::new(addr).bind().await;
    let router = Router::with_path("api").hoop(allow_cors());
    let router = router.push(
        Router::with_path("application-info")
            .get(application_info)
            .options(handler::empty()),
    );
    let router = router.push(
        Router::with_path("open")
            .get(Open(api_service.clone()))
            .options(handler::empty()),
    );
    let router = router.push(
        Router::with_path("close")
            .get(ApiQueryHandler(
                api_service.clone(),
                ApiService::close as _,
                true,
            ))
            .options(handler::empty()),
    );
    let router = router.push(
        Router::with_path("current-config")
            .get(ApiQueryHandler(
                api_service.clone(),
                ApiService::current_config as _,
                false,
            ))
            .options(handler::empty()),
    );
    let router = router.push(
        Router::with_path("current-info")
            .get(ApiQueryHandler(
                api_service.clone(),
                ApiService::current_info as _,
                true,
            ))
            .options(handler::empty()),
    );
    let router = router.push(
        Router::with_path("current-nodes")
            .get(ApiQueryHandler(
                api_service.clone(),
                ApiService::current_nodes as _,
                true,
            ))
            .options(handler::empty()),
    );
    let router = router.push(
        Router::with_path("groups")
            .get(ApiQueryHandler(
                api_service.clone(),
                ApiService::groups as _,
                true,
            ))
            .options(handler::empty()),
    );
    let router = router.push(
        Router::with_path("update-config")
            .post(UpdateConfig(api_service.clone()))
            .options(handler::empty()),
    );
    let router = router.push(
        Router::with_path("nodes-by-group/<group>")
            .get(NodesByGroup(api_service.clone()))
            .options(handler::empty()),
    );

    let root_router = Router::new();
    let root_router = root_router.push(router);
    let root_router = root_router.push(Router::new().get(static_file));
    let root_router = root_router.push(Router::with_path("<**path>").get(static_file));
    tokio::spawn(async move {
        log::info!("http service has served on http://{addr}");
        Server::new(acceptor).serve(root_router).await;
    });
    Ok(())
}

async fn read_file(path: &str) -> Option<(Vec<u8>, Mime)> {
    let fall_back = PathBuf::from("./");
    let exe_in_path = std::env::current_exe()
        .map(|path| path.parent().unwrap_or(fall_back.as_path()).to_owned())
        .unwrap_or(fall_back);
    let current_path = exe_in_path.join("static").join(path);
    if current_path.exists() {
        if let Ok(content) = tokio::fs::read(current_path).await {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            return Some((content, mime));
        }
        return None;
    }
    if let Some(content) = StaticAssets::get(path) {
        let mime = mime_guess::from_path(path).first_or_octet_stream();
        return Some((content.data.into_owned(), mime));
    }
    None
}

#[handler]
async fn static_file(req: &mut Request, res: &mut Response) {
    // salvo 0.63 must use "**path" while higher version uses "path" index
    let mut path = req
        .param::<String>("**path")
        .unwrap_or("index.html".to_string());
    if path.is_empty() {
        path = "index.html".to_string();
    }
    match read_file(&path).await {
        Some((body, mime)) => {
            _ = res
                .body(body.into())
                .add_header("Content-Type", mime.as_ref(), true);
        }
        None => {
            if path == "index.html" {
                res.status_code(StatusCode::NOT_FOUND);
                return;
            }
            if let Some((body, mime)) = read_file("index.html").await {
                _ = res
                    .body(body.into())
                    .add_header("Content-Type", mime.as_ref(), true);
            } else {
                res.status_code(StatusCode::NOT_FOUND);
            }
        }
    }
}

#[derive(rust_embed::Embed)]
#[folder = "static/"]
#[exclude = "README.md"]
struct StaticAssets;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ApplicationInfo {
    version: String,
    algorithm_list: Vec<String>,
}

impl Default for ApplicationInfo {
    fn default() -> Self {
        Self {
            version: crate::VERSION.to_string(),
            algorithm_list: vec![
                "aes-gcm".to_string(),
                "chacha20-poly1305".to_string(),
                "xor".to_string(),
            ],
        }
    }
}
