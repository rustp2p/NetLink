use crate::config::ConfigView;
use crate::ipc::http::entity::ApiResponse;
use crate::ipc::service::ApiService;
use std::net::SocketAddr;
use std::path::Path;
use warp::Filter;

async fn close(api_service: ApiService) -> Result<impl warp::Reply, warp::Rejection> {
    if api_service.is_close() {
        return Ok(warp::reply::json(&ApiResponse::not_started()));
    }
    match api_service.close() {
        Ok(_) => Ok(warp::reply::json(&ApiResponse::success("success"))),
        Err(e) => Ok(warp::reply::json(&ApiResponse::failed(format!("{e}")))),
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

async fn open(api_service: ApiService) -> Result<impl warp::Reply, warp::Rejection> {
    match api_service.open().await {
        Ok(_) => Ok(warp::reply::json(&ApiResponse::success("success"))),
        Err(e) => Ok(warp::reply::json(&ApiResponse::failed(format!("{e}")))),
    }
}

async fn current_config(api_service: ApiService) -> Result<impl warp::Reply, warp::Rejection> {
    match api_service.current_config() {
        Ok(rs) => Ok(warp::reply::json(&ApiResponse::success(rs))),
        Err(e) => Ok(warp::reply::json(&ApiResponse::failed(format!("{e}")))),
    }
}

async fn current_info(api_service: ApiService) -> Result<impl warp::Reply, warp::Rejection> {
    if api_service.is_close() {
        return Ok(warp::reply::json(&ApiResponse::not_started()));
    }
    match api_service.current_info() {
        Ok(rs) => Ok(warp::reply::json(&ApiResponse::success(rs))),
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

async fn current_nodes(api_service: ApiService) -> Result<impl warp::Reply, warp::Rejection> {
    if api_service.is_close() {
        return Ok(warp::reply::json(&ApiResponse::not_started()));
    }
    match api_service.current_nodes() {
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

pub async fn start(addr: String, api_service: ApiService) -> anyhow::Result<()> {
    let state_filter = warp::any().map(move || api_service.clone());
    let close_api = warp::path!("api" / "close")
        .and(warp::get())
        .and(state_filter.clone())
        .and_then(close)
        .boxed();
    let open_api = warp::path!("api" / "open")
        .and(warp::get())
        .and(state_filter.clone())
        .and_then(open)
        .boxed();
    let current_info_api = warp::path!("api" / "current-info")
        .and(warp::get())
        .and(state_filter.clone())
        .and_then(current_info)
        .boxed();
    let groups_api = warp::path!("api" / "groups")
        .and(warp::get())
        .and(state_filter.clone())
        .and_then(groups)
        .boxed();
    let current_nodes_api = warp::path!("api" / "current-nodes")
        .and(warp::get())
        .and(state_filter.clone())
        .and_then(current_nodes)
        .boxed();
    let nodes_by_group_api = warp::path!("api" / "nodes-by-group" / String)
        .and(warp::get())
        .and(state_filter.clone())
        .and_then(nodes_by_group)
        .boxed();
    let current_config_api = warp::path!("api" / "current-config")
        .and(warp::get())
        .and(state_filter.clone())
        .and_then(current_config)
        .boxed();
    let update_config_api = warp::path!("api" / "update-config")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(update_config)
        .boxed();
    let static_files = warp::path::tail().and_then(serve_static);

    let routes = close_api
        .or(open_api)
        .or(current_info_api)
        .or(groups_api)
        .or(current_nodes_api)
        .or(nodes_by_group_api)
        .or(current_config_api)
        .or(update_config_api)
        .or(static_files)
        .with(
            warp::cors()
                .allow_any_origin()
                .allow_headers(vec!["content-type"])
                .allow_methods(vec!["GET", "POST"]),
        );
    let addr: SocketAddr = addr.parse()?;
    let (_addr, server) = warp::serve(routes).try_bind_ephemeral(addr)?;
    log::info!("start backend command server http://{addr}");
    tokio::spawn(server);
    Ok(())
}

#[derive(rust_embed::Embed)]
#[folder = "static/"]
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
