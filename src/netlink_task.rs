use std::{net::Ipv4Addr, sync::Arc};

use async_shutdown::ShutdownManager;
use futures::FutureExt;
use rustp2p::{
    config::{PipeConfig, TcpPipeConfig, UdpPipeConfig},
    pipe::{Pipe, PipeLine, PipeWriter, RecvError, RecvUserData},
    protocol::node_id::NodeID,
};
use tun_rs::{AbstractDevice, AsyncDevice};

use crate::config::Config;
use crate::route::ExternalRoute;
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
use crate::route::{exit_route, route_listen};
use crate::{cipher, ipc::service::ApiService};
use tachyonix::{channel, Sender};

pub async fn start_netlink(api_service: &ApiService) -> anyhow::Result<()> {
    let shutdown_manager = ShutdownManager::<()>::new();
    let Some(config) = api_service.load_config() else {
        return Ok(());
    };
    match start_netlink0(shutdown_manager.clone(), config).await {
        Ok(writer) => {
            api_service.set_pipe(writer, shutdown_manager);
            Ok(())
        }
        Err(e) => {
            _ = shutdown_manager.trigger_shutdown(());
            Err(e)
        }
    }
}
async fn start_netlink0(
    shutdown_manager: ShutdownManager<()>,
    config: Config,
) -> anyhow::Result<Arc<PipeWriter>> {
    let udp_config = UdpPipeConfig::default().set_simple_udp_port(config.port);
    let tcp_config = TcpPipeConfig::default().set_tcp_port(config.port);
    let mut pipe_config = PipeConfig::empty()
        .set_udp_pipe_config(udp_config)
        .set_tcp_pipe_config(tcp_config)
        .set_direct_addrs(config.peer.into_iter().map(|v| v.0).collect())
        .set_group_code(config.group_code)
        .set_node_id(config.node_ipv4.into())
        .set_udp_stun_servers(config.udp_stun)
        .set_tcp_stun_servers(config.tcp_stun);
    if let Some(iface) = config.iface_option {
        pipe_config = pipe_config.set_default_interface(iface);
    }

    let mut pipe = Pipe::new(pipe_config).boxed().await?;
    let writer = Arc::new(pipe.writer());

    let (sender, mut receiver) = channel::<RecvUserData>(256);
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

        #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
        {
            route_listen::route_listen(shutdown_manager.clone(), if_index, external_route.clone())
                .await?;
            if let Some(exit_node) = config.exit_node {
                exit_route::exit_route(exit_node, if_index).await?;
            }
        }

        #[cfg(target_os = "macos")]
        {
            use tun_rs::AbstractDevice;
            device.set_ignore_packet_info(true);
        }
        let device = Arc::new(device);
        let device_r = device.clone();
        let cipher = config.cipher.clone();
        let pipe_writer = writer.clone();
        tokio::spawn(shutdown_manager.wrap_cancel(async move {
            if let Err(e) = tun_recv(
                pipe_writer,
                device_r,
                config.node_ipv4,
                external_route,
                cipher,
            )
            .await
            {
                log::warn!("device.recv {e:?}")
            }
        }));
        let cipher = config.cipher.clone();
        tokio::spawn(shutdown_manager.wrap_cancel(async move {
            while let Ok(mut buf) = receiver.recv().await {
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
        }));
    }
    log::info!("listen local port: {}", config.port);

    tokio::spawn(shutdown_manager.wrap_cancel(async move {
        loop {
            match pipe.accept().await {
                Ok(line) => {
                    tokio::spawn(line_recv(line, sender.clone()));
                }
                Err(e) => {
                    log::error!("pipe.accept {e:?}");
                    break;
                }
            }
        }
    }));
    Ok(writer)
}

fn gen_salt(src_id: &NodeID, dest_id: &NodeID) -> [u8; 12] {
    let mut res = [0u8; 12];
    res[..4].copy_from_slice(src_id.as_ref());
    res[4..8].copy_from_slice(dest_id.as_ref());
    res
}

async fn line_recv(mut line: PipeLine, sender: Sender<RecvUserData>) {
    loop {
        let rs = match line.next().await {
            Ok(rs) => rs,
            Err(e) => {
                if let RecvError::Io(e) = e {
                    log::warn!("recv_from {e:?} {:?}", line.remote_addr());
                }
                return;
            }
        };
        let handle_rs = match rs {
            Ok(handle_rs) => handle_rs,
            Err(e) => {
                log::warn!("recv_data_handle {e:?} {:?}", line.remote_addr());
                continue;
            }
        };
        if sender.send(handle_rs).await.is_err() {
            log::warn!("discard UserData ")
        }
    }
}

async fn tun_recv(
    pipe_writer: Arc<PipeWriter>,
    device: Arc<AsyncDevice>,
    self_ip: Ipv4Addr,

    external_route: ExternalRoute,
    cipher: Option<cipher::Cipher>,
) -> anyhow::Result<()> {
    let self_id: NodeID = self_ip.into();
    loop {
        let mut send_packet = pipe_writer.allocate_send_packet();
        unsafe { send_packet.set_payload_len(send_packet.capacity()) };
        let Ok(payload_len) = device.recv(&mut send_packet).await else {
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
