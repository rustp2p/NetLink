use jsonwebtoken::{self, Algorithm, DecodingKey, EncodingKey, Validation};
use salvo::http::Method;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    username: String,
    exp: i64,
}

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

use crate::service::ApiService;
use netlink_core::config::Config;
use salvo::cors::{Cors, CorsHandler};
use sha2::Digest;

fn allow_cors() -> CorsHandler {
    Cors::new()
        .allow_origin("*")
        .allow_methods(vec![
            Method::GET,
            Method::POST,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            "*".to_string().try_into().unwrap(),
            "Authorization".to_string().try_into().unwrap(),
        ])
        .into_handler()
}
pub async fn start_api(
    http_config: crate::HttpConfiguration,
    api_service: ApiService,
) -> anyhow::Result<()> {
    start(
        http_config,
        api_service,
        Option::<DefaultApiInterceptor>::None,
        DefaultStaticFileAssets,
    )
    .await
}
use time::{Duration, OffsetDateTime};
struct Validator {
    secret: Vec<u8>,
    username: String,
    password: String,
}
#[async_trait]
impl Handler for Validator {
    async fn handle(
        &self,
        req: &mut Request,
        _depot: &mut Depot,
        res: &mut Response,
        _ctrl: &mut FlowCtrl,
    ) {
        let username = req
            .form::<String>("user_name")
            .await
            .unwrap_or("".to_string());
        let password = req
            .form::<String>("password")
            .await
            .unwrap_or("".to_string());
        if username == self.username && password == self.password {
            let exp = OffsetDateTime::now_utc() + Duration::days(1);
            let claim = JwtClaims {
                username,
                exp: exp.unix_timestamp(),
            };
            match jsonwebtoken::encode(
                &jsonwebtoken::Header::default(),
                &claim,
                &EncodingKey::from_secret(&self.secret),
            ) {
                Ok(token) => {
                    res.render(Text::Json(
                        json!({
                            "code":200,
                            "data":{
                                "token":token
                            }
                        })
                        .to_string(),
                    ));
                }
                Err(e) => {
                    res.render(Text::Json(
                        json!({
                            "code":400,
                            "data":e.to_string()
                        })
                        .to_string(),
                    ));
                }
            }
        } else {
            res.render(Text::Json(
                json!({
                    "code":400,
                    "data":"账号或密码错误"
                })
                .to_string(),
            ));
        }
    }
}
struct Authorized {
    secret: Vec<u8>,
}
#[async_trait]
impl Handler for Authorized {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        if let Some(authorization) = req.header::<String>("Authorization") {
            if let Some(token) = authorization.strip_prefix("Bearer ") {
                match jsonwebtoken::decode::<JwtClaims>(
                    token,
                    &DecodingKey::from_secret(&self.secret),
                    &Validation::new(Algorithm::HS256),
                ) {
                    Ok(_rs) => {
                        ctrl.call_next(req, depot, res).await;
                        return;
                    }
                    Err(e) => {
                        log::error!("token check:{e:?} remote_addr={:?}", req.remote_addr())
                    }
                }
            }
        }
        res.render(Text::Json(
            json!({
                "code":401,
                "data":"Unauthorized"
            })
            .to_string(),
        ));
        ctrl.skip_rest();
    }
}

#[handler]
pub async fn check_me(res: &mut Response) {
    res.render(Text::Json(
        json!({
            "code":200,
            "data":"OK"
        })
        .to_string(),
    ));
}

pub async fn start<A: StaticFileAssets, I: Handler>(
    http_config: crate::HttpConfiguration,
    api_service: ApiService,
    api_interceptor: Option<I>,
    static_assets: A,
) -> anyhow::Result<()> {
    let acceptor = TcpListener::new(http_config.addr).bind().await;
    let router = Router::with_path("api").hoop(allow_cors());
    let mut router = if let Some(i) = api_interceptor {
        router.hoop(i)
    } else {
        router
    };
    if let Some(user_info) = http_config.user_info {
        let mut hasher = sha2::Sha256::new();
        hasher.update(user_info.username.as_bytes());
        hasher.update(user_info.password.as_bytes());
        let secret: [u8; 32] = hasher.finalize().into();
        let secret = secret.to_vec();
        let validator = Validator {
            secret: secret.clone(),
            username: user_info.username,
            password: user_info.password,
        };

        router = router.push(
            Router::with_path("login")
                .post(validator)
                .options(handler::empty()),
        );
        router = router.hoop_when(Authorized { secret }, |req, _| {
            req.uri().path() != "/api/login"
        });
    }
    let router = router.push(
        Router::with_path("check")
            .get(check_me)
            .options(handler::empty()),
    );
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
        Router::with_path("started-config")
            .get(ApiQueryHandler(
                api_service.clone(),
                ApiService::started_config as _,
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
    let root_router = root_router.push(Router::new().get(StaticFileHandler(static_assets.clone())));
    let root_router = root_router
        .push(Router::with_path("<**path>").get(StaticFileHandler(static_assets.clone())));
    tokio::spawn(async move {
        log::info!("http service has served on http://{}", http_config.addr);
        Server::new(acceptor).serve(root_router).await;
    });
    Ok(())
}

async fn read_file<A: StaticFileAssets>(file_assets: &A, path: &str) -> Option<(Vec<u8>, String)> {
    let fall_back = PathBuf::from("./");
    let exe_in_path = std::env::current_exe()
        .map(|path| path.parent().unwrap_or(fall_back.as_path()).to_owned())
        .unwrap_or(fall_back);
    let current_path = exe_in_path.join("static").join(path);
    if current_path.exists() {
        if let Ok(content) = tokio::fs::read(current_path).await {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            return Some((content, mime.as_ref().to_string()));
        }
        return None;
    }
    if let Some((content, mime)) = file_assets.get_file(path) {
        return Some((content, mime));
    }
    None
}
pub trait StaticFileAssets: Clone + Send + Sync + 'static {
    /// return file data,file mime
    fn get_file(&self, path: &str) -> Option<(Vec<u8>, String)>;
}
#[derive(Copy, Clone)]
struct DefaultStaticFileAssets;
impl StaticFileAssets for DefaultStaticFileAssets {
    fn get_file(&self, _path: &str) -> Option<(Vec<u8>, String)> {
        None
    }
}
struct StaticFileHandler<A: StaticFileAssets>(A);
#[async_trait]
impl<A: StaticFileAssets> Handler for StaticFileHandler<A> {
    async fn handle(
        &self,
        req: &mut Request,
        _depot: &mut Depot,
        res: &mut Response,
        _ctrl: &mut FlowCtrl,
    ) {
        // salvo 0.63 must use "**path" while higher version uses "path" index
        let mut path = req
            .param::<String>("**path")
            .unwrap_or("index.html".to_string());
        if path.is_empty() {
            path = "index.html".to_string();
        }
        match read_file(&self.0, &path).await {
            Some((body, mime)) => {
                _ = res.body(body.into()).add_header("Content-Type", mime, true);
            }
            None => {
                if path == "index.html" {
                    res.status_code(StatusCode::NOT_FOUND);
                    return;
                }
                if let Some((body, mime)) = read_file(&self.0, "index.html").await {
                    _ = res.body(body.into()).add_header("Content-Type", mime, true);
                } else {
                    res.status_code(StatusCode::NOT_FOUND);
                }
            }
        }
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
#[derive(Copy, Clone)]
struct DefaultApiInterceptor;
#[async_trait]
impl Handler for DefaultApiInterceptor {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        ctrl.call_next(req, depot, res).await;
    }
}
