use crate::ipc::http::entity::ApiResponse;
use crate::ipc::service::ApiService;
use actix_web::web::Data;
use actix_web::{web, App, HttpResponse, HttpServer};
use actix_cors::Cors;
use std::{net, thread};

#[actix_web::get("/api/close")]
async fn close(service: Data<ApiService>) -> HttpResponse {
    match service.close() {
        Ok(_) => HttpResponse::Ok().json(ApiResponse::success("success")),
        Err(e) => HttpResponse::Ok().json(ApiResponse::failed(format!("{e}"))),
    }
}
#[actix_web::get("/api/open")]
async fn open(service: Data<ApiService>) -> HttpResponse {
    match service.open().await {
        Ok(_) => HttpResponse::Ok().json(ApiResponse::success("success")),
        Err(e) => HttpResponse::Ok().json(ApiResponse::failed(format!("{e}"))),
    }
}

#[actix_web::get("/api/current-info")]
async fn current_info(service: Data<ApiService>) -> HttpResponse {
    match service.current_info() {
        Ok(rs) => HttpResponse::Ok().json(ApiResponse::success(rs)),
        Err(e) => HttpResponse::Ok().json(ApiResponse::failed(format!("{e}"))),
    }
}

#[actix_web::get("/api/groups")]
async fn groups(service: Data<ApiService>) -> HttpResponse {
    match service.groups() {
        Ok(rs) => HttpResponse::Ok().json(ApiResponse::success(rs)),
        Err(e) => HttpResponse::Ok().json(ApiResponse::failed(format!("{e}"))),
    }
}

#[actix_web::get("/api/current-nodes")]
async fn current_nodes(service: Data<ApiService>) -> HttpResponse {
    match service.current_nodes() {
        Ok(rs) => HttpResponse::Ok().json(ApiResponse::success(rs)),
        Err(e) => HttpResponse::Ok().json(ApiResponse::failed(format!("{e}"))),
    }
}

#[actix_web::get("/api/nodes-by-group/{group}")]
async fn nodes_by_group(service: Data<ApiService>, group: web::Path<String>) -> HttpResponse {
    match service.nodes_by_group(group.as_str()) {
        Ok(rs) => HttpResponse::Ok().json(ApiResponse::success(rs)),
        Err(e) => HttpResponse::Ok().json(ApiResponse::failed(format!("{e}"))),
    }
}

pub async fn start(port: u16, api_service: ApiService) -> anyhow::Result<()> {
    let listener = net::TcpListener::bind(format!("[::]:{port}"))?;
    thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                if let Err(e) = start0(listener, api_service).await {
                    log::warn!("web api {e:?}")
                }
            });
    });
    Ok(())
}

async fn start0(listener: net::TcpListener, api_service: ApiService) -> anyhow::Result<()> {
    HttpServer::new(move || {
        App::new().wrap(Cors::permissive())
            .app_data(Data::new(api_service.clone()))
            .service(current_info)
            .service(groups)
            .service(current_nodes)
            .service(nodes_by_group)
            .service(open)
            .service(close)
    })
    .listen(listener)?
    .run()
    .await?;
    Ok(())
}
