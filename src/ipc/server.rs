use std::io;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

pub async fn start(port: u16) -> io::Result<()> {
    let listener = TcpListener::bind(format!("127.0.0.1:{port}")).await?;
    loop {
        let (tcp, addr) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle(tcp).await {
                log::warn!("ipc error {e:?},addr={addr}");
            }
        })
    }
}
async fn handle(mut tcp: TcpStream) -> io::Result<()> {
    let mut cmd = String::new();
    let _len = tcp.read_to_string(&mut cmd).await?;
    match cmd.as_str() {
        "all_group_code" => {
            todo!()
        }
        _ => {
            if let Some(group_code) = cmd.strip_prefix("list_") {
                todo!()
            }
        }
    }
    Ok(())
}
