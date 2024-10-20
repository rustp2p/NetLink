use clap::Parser;
use env_logger::Env;
use std::future::Future;

use anyhow::anyhow;
use async_shutdown::ShutdownManager;
use clap::error::ErrorKind;
use futures::FutureExt;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use tun_rs::{AbstractDevice, AsyncDevice};

use crate::config::{ConfigView, FileConfigView};
use crate::ipc::service::ApiService;
use crate::route_listen::ExternalRoute;
use rustp2p::config::{PipeConfig, TcpPipeConfig, UdpPipeConfig};
use rustp2p::pipe::{Pipe, PipeLine, PipeWriter, RecvError, RecvUserData};
use rustp2p::protocol::node_id::{GroupCode, NodeID};
use tokio::sync::mpsc::Sender;

mod cipher;
mod config;
mod exit_route;
mod ipc;
mod platform;
mod route_listen;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Peer node address.
    /// e.g.: -p tcp://192.168.10.13:23333 -p udp://192.168.10.23:23333
    #[arg(short, long)]
    peer: Option<Vec<String>>,
    /// Local node IP and prefix.If there is no 'prefix', Will not enable Tun.
    /// e.g.: -l 10.26.0.2/24
    #[arg(short, long, value_name = "LOCAL IP")]
    local: String,
    /// Nodes with the same group_code can form a network (Maximum length 16).
    #[arg(short, long, value_name = "GROUP CODE")]
    group_code: String,
    /// Listen local port, default is 23333
    #[arg(short = 'P', long)]
    port: Option<u16>,
    /// Bind the outgoing network interface (using the interface name).
    /// e.g.: -b eth0
    #[arg(short, long, value_name = "DEVICE NAME")]
    bind_dev: Option<String>,
    /// Set the number of threads, default is 2
    #[arg(long)]
    threads: Option<usize>,
    /// Enable data encryption.
    /// e.g.: -e "password"
    #[arg(short, long, value_name = "PASSWORD")]
    encrypt: Option<String>,
    /// Set encryption algorithm. Optional aes-gcm/chacha20-poly1305/xor, default is chacha20-poly1305
    #[arg(short, long)]
    algorithm: Option<String>,
    /// Global exit node,please use it together with '--bind-dev'
    #[arg(long)]
    exit_node: Option<String>,
    /// Set tun name
    #[arg(long)]
    tun_name: Option<String>,
    /// Start using configuration file
    #[arg(short = 'f', long)]
    config: Option<String>,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Parser, Debug)]
struct ArgsConfig {
    #[arg(short = 'f', long)]
    config: String,
}

#[derive(Parser, Debug)]
struct ArgsBack {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Backend command
    Cmd {
        /// set backend server host. default 127.0.0.1
        #[arg(long)]
        cmd_host: Option<String>,
        /// When opening multiple programs, this port needs to be set. default 23336
        #[arg(long)]
        cmd_port: Option<u16>,
        /// View information about the current program
        #[arg(long)]
        info: bool,
        /// View all nodes in the current group
        #[arg(long)]
        nodes: bool,
        /// View all group codes
        #[arg(long)]
        groups: bool,
        /// View all nodes in the group code
        #[arg(long)]
        others: Option<String>,
    },
}

const CMD_HOST: &str = "127.0.0.1";
const CMD_PORT: u16 = 23336;
const LISTEN_PORT: u16 = 23333;

pub fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let args = match Args::try_parse() {
        Ok(arg) => arg,
        Err(e) => {
            if e.kind() == ErrorKind::DisplayHelp {
                println!("{e}");
                return Ok(());
            }
            if let Ok(args) = ArgsBack::try_parse() {
                return client_cmd(args);
            }
            if let Ok(args) = ArgsConfig::try_parse() {
                let file_config = FileConfigView::read_file(&args.config)?;
                let worker_threads = file_config.threads;
                return block_on(worker_threads, async move {
                    main_by_config_file(file_config).boxed().await
                });
            }
            println!("{e}");
            return Ok(());
        }
    };
    let worker_threads = args.threads.unwrap_or(2);
    block_on(
        worker_threads,
        async move { main_by_cmd(args).boxed().await },
    )
}

fn block_on<F: Future>(worker_threads: usize, f: F) -> F::Output {
    if worker_threads <= 1 {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    } else {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(worker_threads)
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }
}

#[tokio::main(flavor = "current_thread")]
async fn client_cmd(args: ArgsBack) -> anyhow::Result<()> {
    let Commands::Cmd {
        cmd_host,
        cmd_port,
        info,
        nodes,
        groups,
        others,
    } = args.command;
    let host = cmd_host.unwrap_or(CMD_HOST.to_string());
    let port = cmd_port.unwrap_or(CMD_PORT);
    let addr = format!("{host}:{port}");
    if nodes {
        if let Err(e) = ipc::udp::client::nodes(addr).await {
            Err(anyhow!("Perhaps the backend service has not been started. Use '--cmd-port' to change the port. error={e}"))?;
        }
    } else if groups {
        if let Err(e) = ipc::udp::client::groups(addr).await {
            Err(anyhow!("Perhaps the backend service has not been started. Use '--cmd-port' to change the port. error={e}"))?;
        }
    } else if let Some(group_code) = others {
        if let Err(e) = ipc::udp::client::other_nodes(addr, group_code).await {
            Err(anyhow!("Perhaps the backend service has not been started. Use '--cmd-port' to change the port. error={e}"))?;
        }
    } else if info {
        if let Err(e) = ipc::udp::client::current_info(addr).await {
            Err(anyhow!("Perhaps the backend service has not been started. Use '--cmd-port' to change the port. error={e}"))?;
        }
    } else {
        Err(anyhow!("Use specific commands to view data"))?;
    }
    Ok(())
}

async fn main_by_cmd(args: Args) -> anyhow::Result<()> {
    let Args {
        peer,
        local,
        group_code,
        port,
        bind_dev,
        encrypt,
        algorithm,
        exit_node,
        tun_name,
        command,
        ..
    } = args;
    let mut split = local.split('/');
    let self_id = Ipv4Addr::from_str(split.next().expect("--local error")).expect("--local error");
    let prefix = if let Some(mask) = split.next() {
        u8::from_str(mask).expect("--local error")
    } else {
        0
    };
    let config_view = ConfigView {
        group_code,
        node_ipv4: format!("{self_id}"),
        prefix,
        node_ipv6: None,
        tun_name,
        encrypt,
        algorithm,
        port: port.unwrap_or(LISTEN_PORT),
        peer,
        bind_dev_name: bind_dev,
        exit_node,
        ..ConfigView::default()
    };
    let addr = if let Some(Commands::Cmd {
        cmd_host, cmd_port, ..
    }) = command
    {
        format!(
            "{}:{}",
            cmd_host.unwrap_or(CMD_HOST.to_string()),
            cmd_port.unwrap_or(CMD_PORT)
        )
    } else {
        format!("{CMD_HOST}:{CMD_PORT}")
    };
    start_by_config(config_view, addr).await?;
    Ok(())
}

async fn main_by_config_file(file_config: FileConfigView) -> anyhow::Result<()> {
    let addr = format!("{}:{}", file_config.cmd_host, file_config.cmd_port);
    let config_view = ConfigView::from(file_config);
    start_by_config(config_view, addr).await
}

async fn start_by_config(config_view: ConfigView, cmd_server_addr: String) -> anyhow::Result<()> {
    let config = config_view.into_config()?;

    let api_service = ApiService::new(config);
    if let Err(e) = ipc::server_start(cmd_server_addr, api_service.clone()).await {
        return Err(anyhow!("The backend command port has already been used. Please use '--cmd-port' to change the port, err={e}"));
    }
    let (tx, mut quit) = tokio::sync::mpsc::channel::<()>(1);

    ctrlc2::set_async_handler(async move {
        let _ = tx.send(()).await;
    })
    .await;

    start(api_service.clone()).await?;
    _ = quit.recv().await;
    _ = api_service.close();
    log::info!("exit!!!!");
    Ok(())
}

async fn start(api_service: ApiService) -> anyhow::Result<()> {
    let config = api_service.load_config();

    let udp_config = UdpPipeConfig::default().set_simple_udp_port(config.port);
    let tcp_config = TcpPipeConfig::default().set_tcp_port(config.port);
    let mut pipe_config = PipeConfig::empty()
        .set_udp_pipe_config(udp_config)
        .set_tcp_pipe_config(tcp_config)
        .set_direct_addrs(config.peer_addrs.unwrap_or_default())
        .set_group_code(config.group_code)
        .set_node_id(config.node_ipv4.into())
        .set_udp_stun_servers(config.udp_stun)
        .set_tcp_stun_servers(config.tcp_stun);
    if let Some(iface) = config.iface_option {
        pipe_config = pipe_config.set_default_interface(iface);
    }

    let mut pipe = Pipe::new(pipe_config).await?;
    let shutdown_manager = ShutdownManager::<()>::new();

    api_service.set_pipe(pipe.writer().clone(), shutdown_manager.clone());

    let (sender, mut receiver) = tokio::sync::mpsc::channel::<RecvUserData>(256);
    if config.prefix > 0 {
        let mut dev_config = tun_rs::Configuration::default();
        dev_config
            .address_with_prefix(config.node_ipv4, config.prefix)
            .platform_config(|_v| {
                #[cfg(windows)]
                {
                    _v.ring_capacity(4 * 1024 * 1024);
                    _v.metric(0);
                }
            })
            .mtu(1400)
            .up();
        if let Some(name) = config.tun_name {
            dev_config.name(name);
        }
        let device = tun_rs::create_as_async(&dev_config)?;
        #[cfg(target_os = "linux")]
        if let Err(e) = device.set_tx_queue_len(1000) {
            log::warn!("set tx_queue_len failed. {e:?}");
        }
        let if_index = device.if_index().unwrap();
        let name = device.name().unwrap();
        log::info!("device index={if_index},name={name}",);
        if let Some(v6) = config.node_ipv6 {
            if let Err(e) = device.add_address_v6(v6.into(), config.prefix_v6) {
                log::warn!("add ipv6 failed. {e:?},v6={v6}");
            } else {
                log::info!("mapped ipv6 addr={v6}");
            }
        }

        let external_route = ExternalRoute::new(config.node_ipv4, config.prefix);

        route_listen::route_listen(shutdown_manager.clone(), if_index, external_route.clone())
            .await?;
        if let Some(exit_node) = config.exit_node {
            exit_route::exit_route(exit_node, if_index).await?;
        }
        #[cfg(target_os = "macos")]
        {
            use tun_rs::AbstractDevice;
            device.set_ignore_packet_info(true);
        }
        let device = Arc::new(device);
        let device_r = device.clone();
        let cipher = config.cipher.clone();
        let writer = pipe.writer();
        tokio::spawn(async move {
            if let Err(e) = tun_recv(
                shutdown_manager,
                writer,
                device_r,
                config.node_ipv4,
                external_route,
                cipher,
            )
            .await
            {
                log::warn!("device.recv {e:?}")
            }
        });
        let cipher = config.cipher.clone();
        tokio::spawn(async move {
            while let Some(mut buf) = receiver.recv().await {
                if let Some(cipher) = cipher.as_ref() {
                    match cipher.decrypt(gen_salt(&buf.src_id(), &buf.dest_id()), buf.payload_mut())
                    {
                        Ok(len) => {
                            if let Err(e) = device.send(&buf.payload()[..len]).await {
                                log::warn!("device.send {e:?}")
                            }
                        }
                        Err(e) => {
                            log::warn!("decrypt {e:?},{:?}->{:?}", buf.src_id(), buf.dest_id())
                        }
                    }
                } else if let Err(e) = device.send(buf.payload()).await {
                    log::warn!("device.send {e:?}")
                }
            }
        });
    }
    log::info!("listen local port: {}", config.port);

    tokio::spawn(async move {
        loop {
            match pipe.accept().await {
                Ok(line) => {
                    tokio::spawn(recv(line, sender.clone()));
                }
                Err(e) => {
                    log::error!("pipe.accept {e:?}");
                    break;
                }
            }
        }
        drop(pipe)
    });
    Ok(())
}

fn string_to_group_code(input: &str) -> Option<GroupCode> {
    let mut array = [0u8; 16];
    let bytes = input.as_bytes();
    if bytes.len() > 16 {
        return None;
    }
    let len = bytes.len();
    array[..len].copy_from_slice(&bytes[..len]);
    Some(array.into())
}

fn gen_salt(src_id: &NodeID, dest_id: &NodeID) -> [u8; 12] {
    let mut res = [0u8; 12];
    res[..4].copy_from_slice(src_id.as_ref());
    res[4..8].copy_from_slice(dest_id.as_ref());
    res
}

async fn recv(mut line: PipeLine, sender: Sender<RecvUserData>) {
    loop {
        let rs = match line.next().await {
            Ok(rs) => rs,
            Err(e) => {
                if let RecvError::Io(e) = e {
                    log::warn!("recv_from {e:?}");
                }
                drop(line);
                return;
            }
        };
        let handle_rs = match rs {
            Ok(handle_rs) => handle_rs,
            Err(e) => {
                log::warn!("recv_data_handle {e:?}");
                continue;
            }
        };
        if sender.send(handle_rs).await.is_err() {
            log::warn!("discard UserData ")
        }
    }
}

async fn tun_recv(
    shutdown_manager: ShutdownManager<()>,
    pipe_writer: PipeWriter,
    device: Arc<AsyncDevice>,
    self_ip: Ipv4Addr,
    external_route: ExternalRoute,
    cipher: Option<cipher::Cipher>,
) -> anyhow::Result<()> {
    let self_id: NodeID = self_ip.into();
    loop {
        let mut send_packet = pipe_writer.allocate_send_packet();
        unsafe { send_packet.set_payload_len(send_packet.capacity()) };
        let payload_len = if let Ok(rs) = shutdown_manager
            .wrap_cancel(device.recv(&mut send_packet))
            .await
        {
            rs?
        } else {
            return Ok(());
        };
        unsafe { send_packet.set_payload_len(payload_len) };
        let buf: &mut [u8] = &mut send_packet;
        if buf.len() < 20 {
            continue;
        }
        let mut v6 = false;
        let mut dest_ip = if buf[0] >> 4 != 4 {
            if let Some(ipv6_packet) = pnet_packet::ipv6::Ipv6Packet::new(buf) {
                let last: [u8; 4] = ipv6_packet.get_destination().octets()[12..]
                    .try_into()
                    .unwrap();
                v6 = true;
                Ipv4Addr::from(last)
            } else {
                continue;
            }
        } else {
            Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19])
        };
        if dest_ip.is_unspecified() {
            continue;
        }
        if dest_ip.is_broadcast() || dest_ip.is_multicast() || buf[19] == 255 {
            if v6 {
                continue;
            }
            dest_ip = Ipv4Addr::BROADCAST;
        }
        #[cfg(target_os = "macos")]
        {
            if dest_ip == self_ip {
                if let Err(err) = process_myself(&buf[..payload_len], &device).await {
                    log::error!("process myself err: {err:?}");
                }
                continue;
            }
        }
        let dest_id = if v6 {
            dest_ip.into()
        } else if let Some(next_hop) = external_route.route(&dest_ip) {
            next_hop.into()
        } else {
            dest_ip.into()
        };
        if let Some(cipher) = cipher.as_ref() {
            send_packet.resize(payload_len + cipher.reserved_len(), 0);
            if let Err(e) = cipher.encrypt(gen_salt(&self_id, &dest_id), &mut send_packet) {
                log::warn!("encrypt,{dest_ip:?} {e:?}");
                continue;
            }
        }
        if let Err(e) = pipe_writer.send_packet_to(send_packet, &dest_id).await {
            log::debug!("discard,{dest_ip:?}:{:?} {e:?}", dest_id.as_ref())
        }
    }
}

#[cfg(target_os = "macos")]
async fn process_myself(payload: &[u8], device: &Arc<AsyncDevice>) -> anyhow::Result<()> {
    use pnet_packet::icmp::IcmpTypes;
    use pnet_packet::ip::IpNextHeaderProtocols;
    use pnet_packet::Packet;
    if let Some(ip_packet) = pnet_packet::ipv4::Ipv4Packet::new(payload) {
        match ip_packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Icmp => {
                let icmp_pkt = pnet_packet::icmp::IcmpPacket::new(ip_packet.payload()).ok_or(
                    std::io::Error::new(std::io::ErrorKind::Other, "invalid icmp packet"),
                )?;
                if IcmpTypes::EchoRequest == icmp_pkt.get_icmp_type() {
                    let mut v = ip_packet.payload().to_owned();
                    let mut icmp_new =
                        pnet_packet::icmp::MutableIcmpPacket::new(&mut v[..]).unwrap();
                    icmp_new.set_icmp_type(IcmpTypes::EchoReply);
                    icmp_new.set_checksum(pnet_packet::icmp::checksum(&icmp_new.to_immutable()));
                    let len = ip_packet.packet().len();
                    let mut buf = vec![0u8; len];
                    let mut res = pnet_packet::ipv4::MutableIpv4Packet::new(&mut buf).unwrap();
                    res.set_total_length(ip_packet.get_total_length());
                    res.set_header_length(ip_packet.get_header_length());
                    res.set_destination(ip_packet.get_source());
                    res.set_source(ip_packet.get_destination());
                    res.set_identification(0x42);
                    res.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
                    res.set_payload(&v);
                    res.set_ttl(64);
                    res.set_version(ip_packet.get_version());
                    res.set_checksum(pnet_packet::ipv4::checksum(&res.to_immutable()));
                    device.send(&buf).await?;
                }
            }
            IpNextHeaderProtocols::Tcp => {
                device.send(payload).await?;
            }
            IpNextHeaderProtocols::Udp => {
                device.send(payload).await?;
            }
            other => {
                log::warn!("{other:?} is not processed by myself");
            }
        }
    };
    Ok(())
}
