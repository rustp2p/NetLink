use crate::config::ConfigView;
use crate::ipc::service::ApiService;
use salvo::http::Method;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use std::path::Path;

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

struct ApiQueryHandler<R>(ApiService, fn(&ApiService) -> anyhow::Result<R>);
#[async_trait]
impl<R: 'static + Send + Sync + Serialize> Handler for ApiQueryHandler<R> {
    async fn handle(
        &self,
        _req: &mut Request,
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
        match req.parse_json::<ConfigView>().await {
            Ok(config_view) => match self.0.update_config(config_view) {
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

use salvo::cors::{Cors, CorsHandler};
fn allow_cors() -> CorsHandler {
    Cors::new()
        .allow_origin("*")
        .allow_methods(vec![Method::GET, Method::POST, Method::DELETE])
        .into_handler()
}

pub async fn start(addr: SocketAddr, api_service: ApiService) -> anyhow::Result<()> {
    let acceptor = TcpListener::new(addr).bind().await;
    let router = Router::with_path("api").hoop(allow_cors());
    let router = router.push(Router::with_path("application-info").get(application_info));
    let router = router.push(Router::with_path("open").get(Open(api_service.clone())));
    let router = router.push(
        Router::with_path("close")
            .get(ApiQueryHandler(api_service.clone(), ApiService::close as _)),
    );
    let router = router.push(Router::with_path("current-config").get(ApiQueryHandler(
        api_service.clone(),
        ApiService::current_config as _,
    )));
    let router = router.push(Router::with_path("current-info").get(ApiQueryHandler(
        api_service.clone(),
        ApiService::current_info as _,
    )));
    let router = router.push(Router::with_path("current-nodes").get(ApiQueryHandler(
        api_service.clone(),
        ApiService::current_nodes as _,
    )));
    let router = router.push(Router::with_path("groups").get(ApiQueryHandler(
        api_service.clone(),
        ApiService::groups as _,
    )));
    let router =
        router.push(Router::with_path("update-config").get(UpdateConfig(api_service.clone())));
    let router = router
        .push(Router::with_path("nodes-by-group/<group>").get(NodesByGroup(api_service.clone())));

    let root_router = Router::new();
    //root_router.push(Router::with_path("/<**path>").get(goal))
    let root_router = root_router.push(router);
    tokio::spawn(async move {
        Server::new(acceptor).serve(root_router).await;
    });
    Ok(())
}

#[derive(rust_embed::Embed)]
#[folder = "static/"]
#[exclude = "README.md"]
struct StaticAssets;

async fn serve_static(path: warp::path::Tail) -> Result<impl warp::Reply, warp::Rejection> {
    let mut path = path.as_str();
    if path.is_empty() {
        path = "index.html"
    }
    let mut first = true;
    loop {
        // Attempt to read files from the current directory
        let current_path = Path::new(".").join("static").join(path);
        if current_path.exists() {
            if let Ok(content) = tokio::fs::read(current_path).await {
                let mime = mime_guess::from_path(path).first_or_octet_stream();
                return Ok(warp::http::Response::builder()
                    .header("Content-Type", mime.as_ref())
                    .body(content));
            }
        }

        // If the file does not exist in the current directory, try reading from the packaged static file
        return if let Some(content) = StaticAssets::get(path) {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            Ok(warp::http::Response::builder()
                .header("Content-Type", mime.as_ref())
                .body(content.data.into_owned()))
        } else {
            if first {
                first = false;
                path = "index.html";
                continue;
            }
            Err(warp::reject::not_found())
        };
    }
}

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
