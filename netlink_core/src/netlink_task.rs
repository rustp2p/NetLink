use async_shutdown::ShutdownManager;
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use regex::Regex;
use rustp2p::{
    node_id::NodeID, Config as RustP2pConfig, DataInterceptor, EndPoint, KcpListener, KcpStream,
    RecvResult, TcpTunnelConfig, UdpTunnelConfig,
};
use std::{net::Ipv4Addr, sync::Arc};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tun_rs::{AsyncDevice};

use crate::cipher;
use crate::config::{default_tcp_stun, default_udp_stun, Config, GroupCode};
use crate::route::ExternalRoute;
use crate::route::{exit_route, route_listen};

pub async fn start_netlink(
    config: Config,
    #[cfg(unix)] tun_fd: Option<u32>,
) -> anyhow::Result<(Arc<EndPoint>, Option<ExternalRoute>, ShutdownManager<()>)> {
    let shutdown_manager = ShutdownManager::<()>::new();

    match start_netlink0(
        shutdown_manager.clone(),
        config,
        #[cfg(unix)]
        tun_fd,
    )
    .await
    {
        Ok((writer, external_route)) => Ok((writer, external_route, shutdown_manager)),
        Err(e) => {
            _ = shutdown_manager.trigger_shutdown(());
            Err(e)
        }
    }
}
async fn start_netlink0(
    shutdown_manager: ShutdownManager<()>,
    config: Config,
    #[cfg(unix)] tun_fd: Option<u32>,
) -> anyhow::Result<(Arc<EndPoint>, Option<ExternalRoute>)> {
    let config_attach = config.generate()?;

    let group_code_filter = config.group_code_filter.unwrap_or_default();
    let group_code_filter_regex = config.group_code_filter_regex.unwrap_or_default();
    let interceptor = GroupCodeInterceptor::new(
        config.group_code,
        group_code_filter,
        group_code_filter_regex,
    )?;
    let mtu = config.mtu.unwrap_or(crate::config::MTU);
    let udp_config = UdpTunnelConfig::default().set_simple_udp_port(config.port);
    let tcp_config = TcpTunnelConfig::default().set_tcp_port(config.port);
    let mut endpoint_config = RustP2pConfig::empty()
        .set_udp_tunnel_config(udp_config)
        .set_tcp_tunnel_config(tcp_config)
        .set_recycle_buf_cap(0)
        .set_direct_addrs(
            config
                .peer
                .unwrap_or_default()
                .into_iter()
                .map(|v| v.0)
                .collect(),
        )
        .set_recv_buffer_size(65536)
        .set_send_buffer_size(mtu as usize + 1024)
        .set_group_code(config.group_code.0)
        .set_node_id(config.node_ipv4.into())
        .set_udp_stun_servers(config.udp_stun.unwrap_or(default_udp_stun()))
        .set_tcp_stun_servers(config.tcp_stun.unwrap_or(default_tcp_stun()));
    if let Some(iface) = config_attach.iface_option {
        endpoint_config = endpoint_config.set_default_interface(iface);
    }

    let endpoint = Arc::new(if let Some(interceptor) = interceptor {
        EndPoint::with_interceptor(endpoint_config, interceptor).await?
    } else {
        EndPoint::new(endpoint_config).await?
    });

    let mut external_route_op = None;
    #[cfg(unix)]
    assert!(tun_fd.is_none() || config.prefix > 0, "configuration error");
    if config.prefix > 0 {
        let external_route = ExternalRoute::new(config.node_ipv4, config.prefix);
        external_route_op.replace(external_route.clone());
        #[cfg(unix)]
        let mut device = Option::<AsyncDevice>::None;
        #[cfg(not(unix))]
        let device = Option::<AsyncDevice>::None;
        #[cfg(unix)]
        if let Some(tun_fd) = tun_fd {
            device = Some(unsafe { AsyncDevice::from_fd(tun_fd as _)? })
        }
        let device = if let Some(device) = device {
            device
        } else {
            let mut device_builder = tun_rs::DeviceBuilder::default();
            device_builder = device_builder
                .ipv4(config.node_ipv4, config.prefix, None)
                .mtu(mtu);
            if let Some(name) = &config.tun_name {
                device_builder = device_builder.name(name);
            }
            #[cfg(windows)]
            {
                device_builder = device_builder
                    .ring_capacity(8 * 1024 * 1024)
                    .metric(0)
                    .device_guid(
                        config
                            .tun_name
                            .map(hash_str_to_u128)
                            .unwrap_or(184891423852740613562132735076188020489),
                    );
            }
            #[cfg(target_os = "linux")]
            {
                device_builder = device_builder.offload(true);
            }
            let device = device_builder.build_async()?;
            if let Some(v6) = config.node_ipv6 {
                if let Err(e) =
                    device.add_address_v6(v6, config.prefix_v6.unwrap_or(crate::config::NODE_IPV6))
                {
                    log::warn!("add ipv6 failed. {e:?},v6={v6}");
                } else {
                    log::info!("mapped ipv6 addr={v6}");
                }
            }
            device
        };
        #[cfg(any(
            target_os = "windows",
            target_os = "linux",
            target_os = "macos",
            target_os = "freebsd"
        ))]
        {
            #[cfg(target_os = "linux")]
            if let Err(e) = device.set_tx_queue_len(1000) {
                log::warn!("set tx_queue_len failed. {e:?}");
            }
            let if_index = device.if_index().unwrap();
            let name = device.name().unwrap();
            log::info!("device index={if_index},name={name}",);
            if config.listen_route.unwrap_or(true) {
                route_listen::route_listen(
                    shutdown_manager.clone(),
                    if_index,
                    external_route.clone(),
                )
                .await?;
                if let Some(exit_node) = config.exit_node {
                    exit_route::exit_route(exit_node, if_index).await?;
                }
            }
        }
        let device = Arc::new(device);
        let device_r = device.clone();
        let device_s = device.clone();
        let cipher = config_attach.cipher.clone();
        let shutdown_manager_ = shutdown_manager.clone();
        let endpoint_clone = endpoint.clone();
        let listener = endpoint.kcp_listener();
        let map = Arc::new(DashMap::new());
        let map1 = map.clone();
        tokio::spawn(shutdown_manager.wrap_cancel(async move {
            if let Err(e) = start_kcp_listener(listener, device_s, map1).await {
                log::warn!("start kcp listener failed. {e:?}");
            }
        }));
        tokio::spawn(shutdown_manager.wrap_cancel(async move {
            if let Err(e) = tun_recv(
                &endpoint_clone,
                map,
                device_r,
                config.node_ipv4,
                external_route,
                cipher,
                mtu,
            )
            .await
            {
                log::warn!("device.recv {e:?}")
            }
            _ = endpoint_clone.shutdown();
            _ = shutdown_manager_.trigger_shutdown(());
        }));
        let cipher = config_attach.cipher.clone();
        let endpoint_clone = endpoint.clone();
        tokio::spawn(shutdown_manager.wrap_cancel(async move {
            tun_send(endpoint_clone, cipher, device, mtu).await;
        }));
    }
    log::info!("listen local port: {}", config.port);
    Ok((endpoint, external_route_op))
}

fn gen_salt(src_id: &NodeID, dest_id: &NodeID) -> [u8; 12] {
    let mut res = [0u8; 12];
    res[..4].copy_from_slice(src_id.as_ref());
    res[4..8].copy_from_slice(dest_id.as_ref());
    res
}
#[derive(Clone)]
struct GroupCodeInterceptor {
    current_group_code: GroupCode,
    group_code_filter: Vec<GroupCode>,
    group_code_filter_regex: Vec<Regex>,
}
impl GroupCodeInterceptor {
    pub fn new(
        current_group_code: GroupCode,
        group_code_filter: Vec<GroupCode>,
        group_code_filter_regex: Vec<String>,
    ) -> anyhow::Result<Option<Self>> {
        if group_code_filter.is_empty() && group_code_filter_regex.is_empty() {
            return Ok(None);
        }

        let mut filter_regex = Vec::with_capacity(group_code_filter_regex.len());
        for x in group_code_filter_regex {
            filter_regex.push(Regex::new(&x)?);
        }
        Ok(Some(Self {
            current_group_code,
            group_code_filter,
            group_code_filter_regex: filter_regex,
        }))
    }
}
#[async_trait::async_trait]
impl DataInterceptor for GroupCodeInterceptor {
    async fn pre_handle(&self, data: &mut RecvResult) -> bool {
        if let Ok(packet) = data.net_packet() {
            let group_code = packet.group_code();
            if group_code == self.current_group_code.0.as_ref() {
                return true;
            }
            let group_code = match GroupCode::try_from(group_code) {
                Ok(group_code) => group_code,
                Err(e) => {
                    log::warn!("group code error {e:?} {}", data.remote_addr());
                    return false;
                }
            };
            for x in &self.group_code_filter {
                if x == &group_code {
                    return true;
                }
            }
            if let Ok(str) = group_code.as_str() {
                for x in &self.group_code_filter_regex {
                    if x.is_match(str) {
                        return true;
                    }
                }
            }
        }
        // intercept
        false
    }
}
#[cfg(windows)]
fn hash_str_to_u128(opt: String) -> u128 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher1 = DefaultHasher::new();
    let mut hasher2 = DefaultHasher::new();

    opt.hash(&mut hasher1);
    217086439.hash(&mut hasher1);
    opt.hash(&mut hasher2);
    506273941.hash(&mut hasher2);

    let high = hasher1.finish();
    let low = hasher2.finish();

    ((high as u128) << 64) | (low as u128)
}

#[cfg(target_os = "linux")]
struct Buffer(rustp2p::RecvUserData);
#[cfg(target_os = "linux")]
impl AsRef<[u8]> for Buffer {
    fn as_ref(&self) -> &[u8] {
        self.0.original_bytes()
    }
}
#[cfg(target_os = "linux")]
impl AsMut<[u8]> for Buffer {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.original_bytes_mut()
    }
}
#[cfg(target_os = "linux")]
impl tun_rs::ExpandBuffer for Buffer {
    fn buf_capacity(&self) -> usize {
        self.0.original_bytes().capacity()
    }

    fn buf_resize(&mut self, new_len: usize, value: u8) {
        self.0.original_bytes_mut().resize(new_len, value)
    }

    fn buf_extend_from_slice(&mut self, extend: &[u8]) {
        self.0.original_bytes_mut().extend_from_slice(extend)
    }
}
#[cfg(target_os = "linux")]
async fn tun_send(
    endpoint: Arc<EndPoint>,
    cipher: Option<cipher::Cipher>,
    device: Arc<AsyncDevice>,
    mtu: u16,
) {
    log::info!("vnet_hdr={},udp_gso={}", device.tcp_gso(), device.udp_gso());
    if !device.tcp_gso() {
        tun_send0(endpoint, cipher, device, mtu).await;
        return;
    }
    let mut table = tun_rs::GROTable::default();
    let mut bufs = Vec::with_capacity(tun_rs::IDEAL_BATCH_SIZE);

    while let Ok((data, meta)) = endpoint.recv_from().await {
        let first_offset = data.offset();
        let mut op = Some((data, meta));
        let mut next_data = None;
        loop {
            let (mut data, meta) = op.take().unwrap();
            if let Some(cipher) = cipher.as_ref() {
                let current_offset = data.offset();
                match cipher.decrypt(
                    gen_salt(&meta.src_id(), &meta.dest_id()),
                    data.payload_mut(),
                ) {
                    Ok(len) => {
                        data.original_bytes_mut().truncate(current_offset + len);
                    }
                    Err(e) => {
                        log::warn!(
                            "decrypt {e:?},{:?},{:?}->{:?}",
                            meta.route_key(),
                            meta.src_id(),
                            meta.dest_id()
                        );
                        break;
                    }
                }
            }
            if first_offset != data.offset() {
                next_data.replace(data);
                break;
            }
            let buffer = Buffer(data);
            bufs.push(buffer);
            if bufs.len() == bufs.capacity() {
                break;
            }
            match endpoint.try_recv_from() {
                Ok((recv_data, recv_meta)) => _ = op.replace((recv_data, recv_meta)),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_e) => return,
            }
        }
        if !bufs.is_empty() {
            if let Err(e) = device
                .send_multiple(&mut table, &mut bufs, first_offset)
                .await
            {
                log::warn!("device.send_multiple {e:?}")
            }
            bufs.clear();
        }
        if let Some(next_data) = next_data {
            let offset = next_data.offset();
            if let Err(e) = device
                .send_multiple(&mut table, &mut [Buffer(next_data)], offset)
                .await
            {
                log::warn!("device.send_multiple {e:?}")
            }
        }
    }
}

#[cfg(target_os = "linux")]
async fn tun_recv(
    pipe_writer: &Arc<EndPoint>,
    map: Arc<DashMap<Ipv4Addr, Sender<Vec<u8>>>>,
    device: Arc<AsyncDevice>,
    self_ip: Ipv4Addr,
    external_route: ExternalRoute,
    cipher: Option<cipher::Cipher>,
    mtu: u16,
) -> anyhow::Result<()> {
    if !device.tcp_gso() {
        return tun_recv0(
            pipe_writer,
            map,
            device,
            self_ip,
            external_route,
            cipher,
            mtu,
        )
        .await;
    }
    let self_id: NodeID = self_ip.into();
    let mut original_buffer = vec![0; tun_rs::VIRTIO_NET_HDR_LEN + 65535];
    use tun_rs::IDEAL_BATCH_SIZE;
    let mut bufs = Vec::with_capacity(IDEAL_BATCH_SIZE);
    let mut sizes = vec![0; IDEAL_BATCH_SIZE];
    while bufs.len() < IDEAL_BATCH_SIZE {
        let buf = vec![0u8; u16::MAX as usize];
        bufs.push(buf);
    }
    loop {
        let num = device
            .recv_multiple(&mut original_buffer, &mut bufs, &mut sizes, 0)
            .await;
        let num = match num {
            Ok(num) => num,
            Err(e) => {
                if let Some(code) = e.raw_os_error() {
                    if libc::EBADFD == code {
                        return Err(e)?;
                    }
                }
                log::warn!("tun_recv {e:?}");
                continue;
            }
        };

        for i in 0..num {
            let payload_len = sizes[i];
            let buf = &mut bufs[i];
            tun_recv_handle(
                &device,
                &map,
                &cipher,
                pipe_writer,
                &self_id,
                buf,
                payload_len,
                &external_route,
            )
            .await
        }
    }
}
#[cfg(not(target_os = "linux"))]
async fn tun_send(
    endpoint: Arc<EndPoint>,
    cipher: Option<cipher::Cipher>,
    device: Arc<AsyncDevice>,
    mtu: u16,
) {
    tun_send0(endpoint, cipher, device, mtu).await;
}
async fn tun_send0(
    endpoint: Arc<EndPoint>,
    cipher: Option<cipher::Cipher>,
    device: Arc<AsyncDevice>,
    _mtu: u16,
) {
    while let Ok((mut recv_data, recv_meta)) = endpoint.recv_from().await {
        if let Some(cipher) = cipher.as_ref() {
            match cipher.decrypt(
                gen_salt(&recv_meta.src_id(), &recv_meta.dest_id()),
                recv_data.payload_mut(),
            ) {
                Ok(len) => {
                    if let Err(e) = device.send(&recv_data.payload()[..len]).await {
                        log::warn!("device.send {e:?}")
                    }
                }
                Err(e) => {
                    log::warn!(
                        "decrypt {e:?},{:?}->{:?}",
                        recv_meta.src_id(),
                        recv_meta.dest_id()
                    )
                }
            }
        } else if let Err(e) = device.send(recv_data.payload()).await {
            log::warn!("device.send {e:?}")
        }
    }
}
#[cfg(not(target_os = "linux"))]
async fn tun_recv(
    endpoint: &Arc<EndPoint>,
    map: Arc<DashMap<Ipv4Addr, Sender<Vec<u8>>>>,
    device: Arc<AsyncDevice>,
    self_ip: Ipv4Addr,
    external_route: ExternalRoute,
    cipher: Option<cipher::Cipher>,
    mtu: u16,
) -> anyhow::Result<()> {
    tun_recv0(endpoint, map, device, self_ip, external_route, cipher, mtu).await
}
async fn tun_recv0(
    endpoint: &Arc<EndPoint>,
    map: Arc<DashMap<Ipv4Addr, Sender<Vec<u8>>>>,
    device: Arc<AsyncDevice>,
    self_ip: Ipv4Addr,
    external_route: ExternalRoute,
    cipher: Option<cipher::Cipher>,
    _mtu: u16,
) -> anyhow::Result<()> {
    let self_id: NodeID = self_ip.into();
    let mut buf = [0u8; u16::MAX as usize];
    loop {
        let payload_len = device.recv(&mut buf).await?;
        tun_recv_handle(
            &device,
            &map,
            &cipher,
            endpoint,
            &self_id,
            &mut buf,
            payload_len,
            &external_route,
        )
        .await;
    }
}
async fn tun_recv_handle(
    device: &Arc<AsyncDevice>,
    map: &DashMap<Ipv4Addr, Sender<Vec<u8>>>,
    cipher: &Option<cipher::Cipher>,
    endpoint: &Arc<EndPoint>,
    self_id: &NodeID,
    buf: &mut [u8],
    payload_len: usize,
    external_route: &ExternalRoute,
) {
    let mut v6 = false;
    let mut dest_ip = if buf[0] >> 4 != 4 {
        if let Some(ipv6_packet) = pnet_packet::ipv6::Ipv6Packet::new(buf) {
            let last: [u8; 4] = ipv6_packet.get_destination().octets()[12..]
                .try_into()
                .unwrap();
            v6 = true;
            Ipv4Addr::from(last)
        } else {
            return;
        }
    } else {
        Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19])
    };
    if dest_ip.is_unspecified() {
        return;
    }

    if dest_ip.is_broadcast() || dest_ip.is_multicast() {
        if v6 {
            return;
        }
        dest_ip = Ipv4Addr::BROADCAST;
    }
    if !v6 && buf[19] == 255 {
        dest_ip = Ipv4Addr::BROADCAST;
    }
    #[cfg(target_os = "macos")]
    {
        let self_ip = Ipv4Addr::from(*self_id);
        if dest_ip == self_ip {
            if let Err(err) = process_myself(&buf[..payload_len], &device).await {
                log::error!("process myself err: {err:?}");
            }
            return;
        }
    }
    let dest_id = if v6 {
        dest_ip.into()
    } else if let Some(next_hop) = external_route.route(&dest_ip) {
        next_hop.into()
    } else {
        dest_ip.into()
    };
    let total_len = if let Some(cipher) = cipher.as_ref() {
        let total_len = payload_len + cipher.reserved_len();
        if let Err(e) = cipher.encrypt(gen_salt(self_id, &dest_id), &mut buf[..total_len]) {
            log::warn!("encrypt,{dest_ip:?} {e:?}");
            return;
        }
        total_len
    } else {
        payload_len
    };
    if let Some(sender) = map.get(&dest_ip) {
        if sender.send(buf[..total_len].to_vec()).await.is_ok() {
            return;
        }
        drop(sender);
        map.remove(&dest_ip);
    } else if endpoint.lookup_route_one(&dest_id).is_some() && false {
        let (s, r) = tokio::sync::mpsc::channel(1024);
        _ = s.send(buf[..total_len].to_vec()).await;
        map.insert(dest_ip, s);
        let  stream = endpoint.open_kcp_stream(dest_id).unwrap();
        let device = device.clone();
        log::info!("open kcp stream {dest_ip}");
        tokio::spawn(async move {
            if let Err(e) = start_kcp_handle(stream, r, device).await {
                log::warn!("start_kcp_handle,{e:?}");
            }
        });
    } else if let Err(e) = endpoint.send_to(&buf[..total_len], dest_id).await {
        log::debug!("discard,{dest_ip:?}:{:?} {e:?}", dest_id.as_ref())
    }
}
async fn start_kcp_listener(
    listener: KcpListener,
    device: Arc<AsyncDevice>,
    map: Arc<DashMap<Ipv4Addr, Sender<Vec<u8>>>>,
) -> std::io::Result<()> {
    loop {
        let (stream, node_id) = listener.accept().await?;
        let node_ip = node_id.into();
        log::info!("accept kcp connection from {node_ip}");
        let device = device.clone();
        let (s, r) = tokio::sync::mpsc::channel(1024);
        map.insert(node_ip, s);
        let device = device.clone();
        tokio::spawn(async move {
            if let Err(e) = start_kcp_handle(stream, r, device).await {
                log::warn!("start_kcp_handle,{e:?}");
            }
        });
    }
}
async fn start_kcp_handle(
    stream: KcpStream,
    mut r: Receiver<Vec<u8>>,
    device: Arc<AsyncDevice>,
) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    let mut table = tun_rs::GROTable::default();
    let mut framed = Framed::new(stream, LengthDelimitedCodec::new());
    
    loop {
        tokio::select! {
            next = framed.next() => {
                if let Some(next) = next {
                    let buf = next?;
                    #[cfg(target_os = "linux")]
                    device_send(&device,&mut table,buf).await?;
                    #[cfg(not(target_os = "linux"))]
                    device.send(&buf).await?;
                }else{
                    break;
                }
            }
            recv = r.recv() => {
                if let Some(buf) = recv {
                    framed.send(buf.into()).await?;
                }else{
                    break;
                }
            }
        }
    }
    Ok(())
}
#[cfg(target_os = "linux")]
async fn device_send(device: &AsyncDevice,table: &mut tun_rs::GROTable, buf: bytes::BytesMut) -> std::io::Result<()> {
    let mut bytes_mut = bytes::BytesMut::with_capacity(tun_rs::VIRTIO_NET_HDR_LEN + buf.len());
    bytes_mut.resize(tun_rs::VIRTIO_NET_HDR_LEN , 0);
    bytes_mut.extend_from_slice(&buf);
    device.send_multiple(table, &mut [bytes_mut], tun_rs::VIRTIO_NET_HDR_LEN)
        .await?;
    Ok(())
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
