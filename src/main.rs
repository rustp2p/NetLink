use clap::Parser;
use env_logger::Env;

use rustp2p::cipher::aes_gcm::{AesGcmCipher, AES_GCM_ENCRYPTION_RESERVED};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use tun_rs::{AbstractDevice, AsyncDevice};

use crate::route_listen::ExternalRoute;
use rustp2p::config::{LocalInterface, PipeConfig, TcpPipeConfig, UdpPipeConfig};
use rustp2p::error::*;
use rustp2p::pipe::{PeerNodeAddress, Pipe, PipeLine, PipeWriter, RecvError, RecvUserData};
use rustp2p::protocol::node_id::{GroupCode, NodeID};
use tokio::sync::mpsc::Sender;

mod platform;
mod route_listen;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Peer node address.
    /// e.g.: -p tcp://192.168.10.13:23333 -p udp://192.168.10.23:23333
    #[arg(short, long)]
    peer: Option<Vec<String>>,
    /// Local node IP and mask.
    /// e.g.: -l 10.26.0.2/24
    #[arg(short, long, value_name = "LOCAL IP")]
    local: String,
    /// Nodes with the same group_code can form a network (Maximum length 16).
    #[arg(short, long, value_name = "GROUP CODE")]
    group_code: String,
    /// Listen local port
    #[arg(short = 'P', long)]
    port: Option<u16>,
    /// Bind the outgoing network interface (using the interface name).
    /// e.g.: -b eth0
    #[arg(short, long, value_name = "DEVICE NAME")]
    bind_dev: Option<String>,
    /// Enable data encryption.
    /// e.g.: -e "password"
    #[arg(short, long, value_name = "PASSWORD")]
    encrypt: Option<String>,
    /// Set the number of threads, default to 2
    #[arg(long)]
    threads: Option<usize>,
    /// This is a test. Parallel encryption and decryption.
    /// Enabling this parameter may reduce performance
    #[arg(long)]
    pcrypt: bool,
}
pub fn main() -> Result<()> {
    let args = Args::parse();
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
        pcrypt,
        ..
    } = args;
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let mut split = local.split('/');
    let self_id = Ipv4Addr::from_str(split.next().expect("--local error")).expect("--local error");
    let mask = if let Some(mask) = split.next() {
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

    let port = port.unwrap_or(23333);
    let mut udp_config = UdpPipeConfig::default().set_udp_ports(vec![port]);
    let mut tcp_config = TcpPipeConfig::default().set_tcp_port(port);
    if let Some(bind_dev_name) = bind_dev {
        let _bind_dev_index = match platform::dev_name_to_index(&bind_dev_name) {
            Ok(index) => index,
            Err(e) => {
                log::error!("--bind-dev error: {e:?}");
                return Ok(());
            }
        };
        #[cfg(not(target_os = "linux"))]
        {
            log::info!("bind_dev_name={bind_dev_name:?},bind_dev_index={_bind_dev_index}");
            udp_config = udp_config.set_default_interface(LocalInterface::new(_bind_dev_index));
            tcp_config = tcp_config.set_default_interface(LocalInterface::new(_bind_dev_index));
        }
        #[cfg(target_os = "linux")]
        {
            log::info!("bind_dev_name={bind_dev_name:?}");
            udp_config =
                udp_config.set_default_interface(LocalInterface::new(bind_dev_name.clone()));
            tcp_config = tcp_config.set_default_interface(LocalInterface::new(bind_dev_name));
        }
    }
    let config = PipeConfig::empty()
        .set_udp_pipe_config(udp_config)
        .set_tcp_pipe_config(tcp_config)
        .set_direct_addrs(addrs)
        .set_group_code(string_to_group_code(&group_code))
        .set_node_id(self_id.into());
    let cipher = encrypt.map(rustp2p::cipher::aes_gcm::cipher);

    let mut pipe = Pipe::new(config).await?;
    let writer = pipe.writer();
    let shutdown_writer = writer.clone();
    let (sender, mut receiver) = tokio::sync::mpsc::channel::<RecvUserData>(256);
    if mask > 0 {
        let device = tun_rs::create_as_async(
            tun_rs::Configuration::default()
                .address_with_prefix(self_id, mask)
                .platform_config(|_v| {
                    #[cfg(windows)]
                    _v.ring_capacity(4 * 1024 * 1024);
                    #[cfg(target_os = "linux")]
                    _v.tx_queue_len(1000);
                })
                .mtu(1400)
                .up(),
        )
        .unwrap();
        let if_index = device.if_index().unwrap();
        let name = device.name().unwrap();
        log::info!("device index={if_index},name={name}",);
        let external_route = ExternalRoute::new();
        route_listen::route_listen(if_index, external_route.clone()).await?;

        #[cfg(target_os = "macos")]
        {
            use tun_rs::AbstractDevice;
            device.set_ignore_packet_info(true);
        }
        let device = Arc::new(device);
        let device_r = device.clone();
        let cipher_ = cipher.clone();
        tokio::spawn(async move {
            if let Err(e) =
                tun_recv(writer, device_r, self_id, external_route, cipher_, pcrypt).await
            {
                log::warn!("device.recv {e:?}")
            }
        });
        let cipher = cipher.clone();
        tokio::spawn(async move {
            while let Some(mut buf) = receiver.recv().await {
                if let Some(cipher) = cipher.as_ref() {
                    if pcrypt {
                        let cipher = cipher.clone();
                        let device = device.clone();
                        tokio::spawn(async move {
                            match cipher
                                .decrypt(gen_salt(&buf.src_id(), &buf.dest_id()), buf.payload_mut())
                            {
                                Ok(len) => {
                                    if let Err(e) = device.send(&buf.payload()[..len]).await {
                                        log::warn!("device.send {e:?}")
                                    }
                                }
                                Err(e) => {
                                    log::warn!(
                                        "decrypt {e:?},{:?}->{:?}",
                                        buf.src_id(),
                                        buf.dest_id()
                                    )
                                }
                            }
                        });
                    } else {
                        match cipher
                            .decrypt(gen_salt(&buf.src_id(), &buf.dest_id()), buf.payload_mut())
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

fn string_to_group_code(input: &str) -> GroupCode {
    let mut array = [0u8; 16];
    let bytes = input.as_bytes();
    let len = bytes.len().min(16);
    array[..len].copy_from_slice(&bytes[..len]);
    array.into()
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
    cipher: Option<AesGcmCipher>,
    pcrypt: bool,
) -> Result<()> {
    let self_id: NodeID = self_ip.into();
    loop {
        let mut send_packet = pipe_writer.allocate_send_packet();
        unsafe { send_packet.set_payload_len(send_packet.capacity()) };
        let payload_len = device.recv(&mut send_packet).await?;
        unsafe { send_packet.set_payload_len(payload_len) };
        let buf: &mut [u8] = &mut send_packet;
        if buf[0] >> 4 != 4 {
            // log::warn!("payload[0] >> 4 != 4");
            continue;
        }
        let mut dest_ip = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
        if dest_ip.is_unspecified() {
            continue;
        }
        if dest_ip.is_broadcast() || dest_ip.is_multicast() || buf[19] == 255 {
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
        let dest_id = if let Some(next_hop) = external_route.route(&dest_ip) {
            next_hop.into()
        } else {
            dest_ip.into()
        };
        if let Some(cipher) = cipher.as_ref() {
            if pcrypt {
                let cipher = cipher.clone();
                let pipe_writer = pipe_writer.clone();
                tokio::spawn(async move {
                    send_packet.resize(payload_len + AES_GCM_ENCRYPTION_RESERVED, 0);
                    if let Err(e) = cipher.encrypt(gen_salt(&self_id, &dest_id), &mut send_packet) {
                        log::warn!("encrypt,{dest_ip:?} {e:?}")
                    } else if let Err(e) = pipe_writer.send_packet_to(send_packet, &dest_id).await {
                        log::warn!("discard,{dest_ip:?} {e:?}")
                    }
                });
            } else {
                send_packet.resize(payload_len + AES_GCM_ENCRYPTION_RESERVED, 0);
                if let Err(e) = cipher.encrypt(gen_salt(&self_id, &dest_id), &mut send_packet) {
                    log::warn!("encrypt,{dest_ip:?} {e:?}")
                } else if let Err(e) = pipe_writer.send_packet_to(send_packet, &dest_id).await {
                    log::warn!("discard,{dest_ip:?} {e:?}")
                }
            }
        } else if let Err(e) = pipe_writer.send_packet_to(send_packet, &dest_id).await {
            log::warn!("discard,{dest_ip:?} {e:?}")
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
