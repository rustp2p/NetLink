use net_route::Route;
use std::io;
use std::net::{IpAddr, Ipv4Addr};

pub async fn exit_route(exit_node_id: Ipv4Addr, tun_index: u32) -> io::Result<()> {
    let exit_node_id = exit_node_id.into();
    let routes = [
        // Route::new(IpAddr::from([0, 0, 0, 0]), 1).with_ifindex(tun_index),  // does not work on macOS for bind_device
        Route::new(IpAddr::from([1, 0, 0, 0]), 8)
            .with_gateway(exit_node_id)
            .with_ifindex(tun_index),
        Route::new(IpAddr::from([2, 0, 0, 0]), 7)
            .with_gateway(exit_node_id)
            .with_ifindex(tun_index),
        Route::new(IpAddr::from([4, 0, 0, 0]), 6)
            .with_gateway(exit_node_id)
            .with_ifindex(tun_index),
        Route::new(IpAddr::from([8, 0, 0, 0]), 5)
            .with_gateway(exit_node_id)
            .with_ifindex(tun_index),
        Route::new(IpAddr::from([16, 0, 0, 0]), 4)
            .with_gateway(exit_node_id)
            .with_ifindex(tun_index),
        Route::new(IpAddr::from([32, 0, 0, 0]), 3)
            .with_gateway(exit_node_id)
            .with_ifindex(tun_index),
        Route::new(IpAddr::from([64, 0, 0, 0]), 2)
            .with_gateway(exit_node_id)
            .with_ifindex(tun_index),
        Route::new(IpAddr::from([128, 0, 0, 0]), 1)
            .with_gateway(exit_node_id)
            .with_ifindex(tun_index),
    ];
    let handle = net_route::Handle::new()?;
    for r in &routes {
        handle.add(r).await?;
    }
    Ok(())
}
