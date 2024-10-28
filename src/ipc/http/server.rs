use crate::config::ConfigView;
use crate::ipc::http::entity::ApiResponse;
use crate::ipc::service::ApiService;
use salvo::http::Method;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use std::path::Path;
use warp::Filter;
use salvo::prelude::*;


#[handler]
async fn application_info(res:& mut Response) -> anyhow::Result<()> {
    res.render(Text::Json(json!({
        "code":200,
        "data":ApplicationInfo::default()
    }).to_string()));
    Ok(())
}

struct Open(ApiService);
#[async_trait]
impl Handler for Open {
    async fn handle(&self, _req: &mut Request, _depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl){
        match self.0.open().await {
            Ok(_) =>{
                res.render(Text::Json(json!({
                    "code":200,
                    "data":"success"
                }).to_string()));
            }
            Err(e) => {
                res.render(Text::Json(json!({
                    "code":400,
                    "data":format!("{e}")
                }).to_string())); 
            }
        }
    }
}

struct ApiHandler<R>(ApiService,fn(&ApiService)->anyhow::Result<R>);
#[async_trait]
impl<R:'static+Send+Sync+Serialize> Handler for ApiHandler<R> {
    async fn handle(&self, req: &mut Request, _depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl){
        if self.0.is_close() {
            res.render(Text::Json(json!({
                "code":503,
                "data":"Not Started"
            }).to_string()));
            return;
        }
        match (self.1)(&self.0) {
            Ok(rs) =>{
                res.render(Text::Json(json!({
                    "code":200,
                    "data":rs
                }).to_string()));
            }
            Err(e) => {
                res.render(Text::Json(json!({
                    "code":400,
                    "data":format!("{e}")
                }).to_string())); 
            }
        }
    }
}





async fn update_config(
    config_view: ConfigView,
    api_service: ApiService,
) -> Result<impl warp::Reply, warp::Rejection> {
    match api_service.update_config(config_view) {
        Ok(_) => Ok(warp::reply::json(&ApiResponse::success("success"))),
        Err(e) => Ok(warp::reply::json(&ApiResponse::failed(format!("{e}")))),
    }
}



async fn groups(api_service: ApiService) -> Result<impl warp::Reply, warp::Rejection> {
    if api_service.is_close() {
        return Ok(warp::reply::json(&ApiResponse::not_started()));
    }
    match api_service.groups() {
        Ok(rs) => Ok(warp::reply::json(&ApiResponse::success(rs))),
        Err(e) => Ok(warp::reply::json(&ApiResponse::failed(format!("{e}")))),
    }
}


async fn nodes_by_group(
    group_code: String,
    api_service: ApiService,
) -> Result<impl warp::Reply, warp::Rejection> {
    if api_service.is_close() {
        return Ok(warp::reply::json(&ApiResponse::not_started()));
    }
    match api_service.nodes_by_group(&group_code) {
        Ok(rs) => Ok(warp::reply::json(&ApiResponse::success(rs))),
        Err(e) => Ok(warp::reply::json(&ApiResponse::failed(format!("{e}")))),
    }
}

// pub async fn start(addr: SocketAddr, api_service: ApiService) -> anyhow::Result<()> {
//     let state_filter = warp::any().map(move || api_service.clone());
//     let application_info_api = warp::path!("api" / "application-info")
//         .and_then(application_info)
//         .boxed();

//     let close_api = warp::path!("api" / "close")
//         .and(warp::get())
//         .and(state_filter.clone())
//         .and_then(close)
//         .boxed();
//     let open_api = warp::path!("api" / "open")
//         .and(warp::get())
//         .and(state_filter.clone())
//         .and_then(open)
//         .boxed();
//     let current_info_api = warp::path!("api" / "current-info")
//         .and(warp::get())
//         .and(state_filter.clone())
//         .and_then(current_info)
//         .boxed();
//     let groups_api = warp::path!("api" / "groups")
//         .and(warp::get())
//         .and(state_filter.clone())
//         .and_then(groups)
//         .boxed();
//     let current_nodes_api = warp::path!("api" / "current-nodes")
//         .and(warp::get())
//         .and(state_filter.clone())
//         .and_then(current_nodes)
//         .boxed();
//     let nodes_by_group_api = warp::path!("api" / "nodes-by-group" / String)
//         .and(warp::get())
//         .and(state_filter.clone())
//         .and_then(nodes_by_group)
//         .boxed();
//     let current_config_api = warp::path!("api" / "current-config")
//         .and(warp::get())
//         .and(state_filter.clone())
//         .and_then(current_config)
//         .boxed();
//     let update_config_api = warp::path!("api" / "update-config")
//         .and(warp::post())
//         .and(warp::body::json())
//         .and(state_filter.clone())
//         .and_then(update_config)
//         .boxed();
//     let static_files = warp::path::tail().and_then(serve_static);

//     let routes = application_info_api
//         .or(close_api)
//         .or(open_api)
//         .or(current_info_api)
//         .or(groups_api)
//         .or(current_nodes_api)
//         .or(nodes_by_group_api)
//         .or(current_config_api)
//         .or(update_config_api)
//         .or(static_files)
//         .with(
//             warp::cors()
//                 .allow_any_origin()
//                 .allow_headers(vec!["content-type"])
//                 .allow_methods(vec!["GET", "POST"]),
//         );
//     let (_addr, server) = warp::serve(routes).try_bind_ephemeral(addr)?;
//     log::info!("start backend command server http://{addr}");
//     tokio::spawn(server);
//     Ok(())
// }
use salvo::cors::{Cors,CorsHandler};
fn allow_cors()->CorsHandler{
    Cors::new()
        .allow_origin("*")
        .allow_methods(vec![Method::GET, Method::POST, Method::DELETE])
        .into_handler()
}

pub async fn start(addr: SocketAddr, api_service: ApiService) -> anyhow::Result<()>{
    let acceptor = TcpListener::new(addr).bind().await;
    let router = Router::with_path("api").hoop(allow_cors());
    let router = router.push(Router::with_path("application-info").get(application_info)) ;
    let router = router.push(Router::with_path("open").get(Open(api_service.clone()))) ;
    let router = router.push(Router::with_path("close").get(ApiHandler(api_service.clone(),ApiService::close as _))) ;
    let router = router.push(Router::with_path("current-config").get(ApiHandler(api_service.clone(),ApiService::current_config as _))) ;
    let router = router.push(Router::with_path("current-info").get(ApiHandler(api_service.clone(),ApiService::current_info as _))) ;
    let router = router.push(Router::with_path("current-nodes").get(ApiHandler(api_service.clone(),ApiService::current_nodes as _))) ;
    tokio::spawn(async move{
        Server::new(acceptor).serve(router).await;
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
