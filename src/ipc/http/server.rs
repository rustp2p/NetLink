use crate::ipc::http::entity::ApiResponse;
use crate::ipc::service::ApiService;
use std::net::SocketAddr;
use warp::Filter;

async fn close(api_service: ApiService) -> Result<impl warp::Reply, warp::Rejection> {
    match api_service.close() {
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
async fn current_info(api_service: ApiService) -> Result<impl warp::Reply, warp::Rejection> {
    match api_service.current_info() {
        Ok(rs) => Ok(warp::reply::json(&ApiResponse::success(rs))),
        Err(e) => Ok(warp::reply::json(&ApiResponse::failed(format!("{e}")))),
    }
}
async fn groups(api_service: ApiService) -> Result<impl warp::Reply, warp::Rejection> {
    match api_service.groups() {
        Ok(rs) => Ok(warp::reply::json(&ApiResponse::success(rs))),
        Err(e) => Ok(warp::reply::json(&ApiResponse::failed(format!("{e}")))),
    }
}
async fn current_nodes(api_service: ApiService) -> Result<impl warp::Reply, warp::Rejection> {
    match api_service.current_nodes() {
        Ok(rs) => Ok(warp::reply::json(&ApiResponse::success(rs))),
        Err(e) => Ok(warp::reply::json(&ApiResponse::failed(format!("{e}")))),
    }
}
async fn nodes_by_group(
    group_code: String,
    api_service: ApiService,
) -> Result<impl warp::Reply, warp::Rejection> {
    match api_service.nodes_by_group(&group_code) {
        Ok(rs) => Ok(warp::reply::json(&ApiResponse::success(rs))),
        Err(e) => Ok(warp::reply::json(&ApiResponse::failed(format!("{e}")))),
    }
}

pub async fn start(port: u16, api_service: ApiService) -> anyhow::Result<()> {
    let state_filter = warp::any().map(move || api_service.clone());
    let close_api = warp::path!("api" / "close")
        .and(warp::get())
        .and(state_filter.clone())
        .and_then(close);
    let open_api = warp::path!("api" / "open")
        .and(warp::get())
        .and(state_filter.clone())
        .and_then(open);
    let current_info_api = warp::path!("api" / "current-info")
        .and(warp::get())
        .and(state_filter.clone())
        .and_then(current_info);
    let groups_api = warp::path!("api" / "groups")
        .and(warp::get())
        .and(state_filter.clone())
        .and_then(groups);
    let current_nodes_api = warp::path!("api" / "current-nodes")
        .and(warp::get())
        .and(state_filter.clone())
        .and_then(current_nodes);
    let nodes_by_group_api = warp::path!("api" / "nodes-by-group" / String)
        .and(warp::get())
        .and(state_filter.clone())
        .and_then(nodes_by_group);
    let routes = close_api
        .or(open_api)
        .or(current_info_api)
        .or(groups_api)
        .or(current_nodes_api)
        .or(nodes_by_group_api)
        .with(
            warp::cors()
                .allow_any_origin()
                .allow_headers(vec!["content-type"])
                .allow_methods(vec!["GET", "POST"]),
        );
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let (_addr, server) = warp::serve(routes).try_bind_ephemeral(addr)?;
    tokio::spawn(server);
    Ok(())
}
