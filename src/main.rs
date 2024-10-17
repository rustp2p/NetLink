use clap::Parser;
use env_logger::Env;
use std::io;

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;
use tun_rs::{AbstractDevice, AsyncDevice};

use crate::route_listen::ExternalRoute;
use rustp2p::config::{LocalInterface, PipeConfig, TcpPipeConfig, UdpPipeConfig};
use rustp2p::error::*;
use rustp2p::pipe::{PeerNodeAddress, Pipe, PipeLine, PipeWriter, RecvError, RecvUserData};
use rustp2p::protocol::node_id::{GroupCode, NodeID};
use tokio::sync::mpsc::Sender;

mod cipher;
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
    exit_node: Option<Ipv4Addr>,
    /// Set tun name
    #[arg(long)]
    tun_name: Option<String>,
    #[command(subcommand)]
    command: Option<Commands>,
}
#[derive(Parser, Debug)]
struct ArgsBack {
    #[arg(long)]
    cmd_port: Option<u16>,
    #[command(subcommand)]
    command: Commands,
}
#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Backend command
    Cmd {
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
const CMD_PORT: u16 = 23336;
const LISTEN_PORT: u16 = 23333;

pub fn main() -> Result<()> {
    let args = match Args::try_parse() {
        Ok(arg) => arg,
        Err(e) => {
            match ArgsBack::try_parse() {
                Ok(args) => {
                    client_cmd(args);
                }
                Err(_) => {
                    println!("{e}");
                }
            }
            return Ok(());
        }
    };
    let worker_threads = args.threads.unwrap_or(2);
    if worker_threads <= 1 {
        main_current_thread(args)
    } else {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(worker_threads)
            .enable_all()
            .build()
            .unwrap()
            .block_on(run(args))
    }
}
#[tokio::main(flavor = "current_thread")]
async fn client_cmd(args: ArgsBack) {
    let Commands::Cmd {
        cmd_port,
        info,
        nodes,
        groups,
        others,
    } = args.command;
    if nodes {
        if let Err(e) = ipc::client::nodes(cmd_port.unwrap_or(CMD_PORT)).await {
            println!("Perhaps the backend service has not been started. Use '--cmd-port' to change the port. error={e}");
        }
    } else if groups {
        if let Err(e) = ipc::client::groups(cmd_port.unwrap_or(CMD_PORT)).await {
            println!("Perhaps the backend service has not been started. Use '--cmd-port' to change the port. error={e}");
        }
    } else if let Some(group_code) = others {
        if let Err(e) = ipc::client::other_nodes(cmd_port.unwrap_or(CMD_PORT), group_code).await {
            println!("Perhaps the backend service has not been started. Use '--cmd-port' to change the port. error={e}");
        }
    } else if info {
        if let Err(e) = ipc::client::current_info(cmd_port.unwrap_or(CMD_PORT)).await {
            println!("Perhaps the backend service has not been started. Use '--cmd-port' to change the port. error={e}");
        }
    } else {
        println!("Use specific commands to view data");
    }
}
#[tokio::main(flavor = "current_thread")]
async fn main_current_thread(args: Args) -> Result<()> {
    run(args).await
}

async fn run(args: Args) -> Result<()> {
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
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let mut split = local.split('/');
    let self_id = Ipv4Addr::from_str(split.next().expect("--local error")).expect("--local error");
    let prefix = if let Some(mask) = split.next() {
        u8::from_str(mask).expect("--local error")
    } else {
        0
    };
    let mut addrs = Vec::new();
    if let Some(peers) = peer {
        for addr in peers {
            addrs.push(addr.parse::<PeerNodeAddress>().expect("--peer"))
        }
    }
    let (tx, mut quit) = tokio::sync::mpsc::channel::<()>(1);

    ctrlc2::set_async_handler(async move {
        tx.send(()).await.expect("Signal error");
    })
    .await;

    let port = port.unwrap_or(LISTEN_PORT);
    let udp_config = UdpPipeConfig::default().set_simple_udp_port(port);
    let tcp_config = TcpPipeConfig::default().set_tcp_port(port);
    let group_code = if let Some(group_code) = string_to_group_code(&group_code) {
        group_code
    } else {
        println!("--group-code is too long");
        return Ok(());
    };
    let mut config = PipeConfig::empty()
        .set_udp_pipe_config(udp_config)
        .set_tcp_pipe_config(tcp_config)
        .set_direct_addrs(addrs)
        .set_group_code(group_code)
        .set_node_id(self_id.into());
    if let Some(bind_dev_name) = bind_dev {
        let _bind_dev_index = match platform::dev_name_to_index(&bind_dev_name) {
            Ok(index) => index,
            Err(e) => {
                log::error!("--bind-dev error: {e:?}");
                return Ok(());
            }
        };
        let iface;
        #[cfg(not(target_os = "linux"))]
        {
            log::info!("bind_dev_name={bind_dev_name:?},bind_dev_index={_bind_dev_index}");
            iface = LocalInterface::new(_bind_dev_index);
        }
        #[cfg(target_os = "linux")]
        {
            log::info!("bind_dev_name={bind_dev_name:?}");
            iface = LocalInterface::new(bind_dev_name.clone());
        }
        config = config.set_default_interface(iface);
    }

    let cipher = if let Some(v) = algorithm {
        match v.to_lowercase().as_str() {
            "aes-gcm" => encrypt.map(cipher::Cipher::new_aes_gcm),
            "chacha20-poly1305" => encrypt.map(cipher::Cipher::new_chacha20_poly1305),
            "xor" => encrypt.map(cipher::Cipher::new_xor),
            _ => {
                println!("--algorithm error");
                return Ok(());
            }
        }
    } else {
        encrypt.map(cipher::Cipher::new_chacha20_poly1305)
    };

    let mut pipe = Pipe::new(config).await?;
    let writer = pipe.writer();
    let cmd_port = if let Some(Commands::Cmd { cmd_port, .. }) = command {
        cmd_port.unwrap_or(CMD_PORT)
    } else {
        CMD_PORT
    };
    if let Err(e) = ipc::server::start(cmd_port, writer.clone()).await {
        if e.kind() == io::ErrorKind::AddrInUse {
            println!("The backend command port has already been used. Please use '--cmd-port' to change the port");
        }
        println!("The backend command port has already been used. Please use '--cmd-port' to change the port, err={e}");
        return Ok(());
    }
    let shutdown_writer = writer.clone();
    let (sender, mut receiver) = tokio::sync::mpsc::channel::<RecvUserData>(256);
    if prefix > 0 {
        let mut config = tun_rs::Configuration::default();
        config
            .address_with_prefix(self_id, prefix)
            .platform_config(|_v| {
                #[cfg(windows)]
                {
                    _v.ring_capacity(4 * 1024 * 1024);
                    _v.metric(0);
                }
            })
            .mtu(1400)
            .up();
        if let Some(name) = tun_name {
            config.name(name);
        }
        let device = tun_rs::create_as_async(&config).unwrap();
        #[cfg(target_os = "linux")]
        if let Err(e) = device.set_tx_queue_len(1000) {
            log::warn!("set tx_queue_len failed. {e:?}");
        }
        let if_index = device.if_index().unwrap();
        let name = device.name().unwrap();
        log::info!("device index={if_index},name={name}",);
        let mut v6: [u8; 16] = [
            0xfd, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0, 0, 0, 0,
        ];
        v6[12..].copy_from_slice(&self_id.octets());
        let v6 = Ipv6Addr::from(v6);
        if let Err(e) = device.add_address_v6(v6.into(), 96) {
            log::warn!("add ipv6 failed. {e:?},v6={v6}");
        } else {
            log::info!("mapped ipv6 addr={v6}");
        }
        let external_route = ExternalRoute::new(self_id, prefix);
        route_listen::route_listen(if_index, external_route.clone()).await?;
        if let Some(exit_node) = exit_node {
            exit_route::exit_route(exit_node, if_index).await?;
        }
        #[cfg(target_os = "macos")]
        {
            use tun_rs::AbstractDevice;
            device.set_ignore_packet_info(true);
        }
        let device = Arc::new(device);
        let device_r = device.clone();
        let cipher_ = cipher.clone();
        tokio::spawn(async move {
            if let Err(e) = tun_recv(writer, device_r, self_id, external_route, cipher_).await {
                log::warn!("device.recv {e:?}")
            }
        });
        let cipher = cipher.clone();
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
    log::info!("listen local port: {port}");

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
    });

    quit.recv().await.expect("quit error");
    _ = shutdown_writer.shutdown();
    log::info!("exit!!!!");
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
    pipe_writer: PipeWriter,
    device: Arc<AsyncDevice>,
    self_ip: Ipv4Addr,
    external_route: ExternalRoute,
    cipher: Option<cipher::Cipher>,
) -> Result<()> {
    let self_id: NodeID = self_ip.into();
    loop {
        let mut send_packet = pipe_writer.allocate_send_packet();
        unsafe { send_packet.set_payload_len(send_packet.capacity()) };
        let payload_len = device.recv(&mut send_packet).await?;
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
async fn process_myself(payload: &[u8], device: &Arc<AsyncDevice>) -> Result<()> {
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
