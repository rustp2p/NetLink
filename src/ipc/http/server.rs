use crate::ipc::http::entity::ApiResponse;
use crate::ipc::server::current_info;
use rustp2p::pipe::PipeWriter;
use warp::Filter;

pub async fn start(port: u16, pipe_writer: &PipeWriter) {
    let info_ = pipe_writer.clone();
    // let hello = warp::path!("info" / String).map(|name| match current_info(&info_) {
    //     Ok(rs) => ApiResponse::success(rs).to_json(),
    //     Err(e) => ApiResponse::failed(format!("{e:?}")).to_json(),
    // });
    // warp::serve(hello).run(([127, 0, 0, 1], port)).await;
}
