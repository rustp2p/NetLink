use parking_lot::Mutex;
use std::net::Ipv4Addr;
use std::sync::Arc;

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
pub mod exit_route;
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
pub mod route_listen;
fn prefix_to_mask(prefix: u8) -> u32 {
    let mask: u32 = if prefix == 0 {
        0
    } else {
        (!0u32) << (32 - prefix)
    };
    mask
}

#[derive(Clone)]
pub struct ExternalRoute {
    network: u32,
    mask: u32,
    route_table: Arc<Mutex<Vec<(u32, u32, Ipv4Addr)>>>,
}

impl ExternalRoute {
    pub fn new(ip: Ipv4Addr, prefix: u8) -> Self {
        let mask = prefix_to_mask(prefix);
        Self {
            network: u32::from(ip) & mask,
            mask,
            route_table: Arc::new(Mutex::new(vec![])),
        }
    }
    #[allow(dead_code)]
    pub fn update(&self, mut route_table: Vec<(u32, u32, Ipv4Addr)>) {
        for (dest, mask, _) in &mut route_table {
            *dest &= *mask
        }
        route_table.sort_by(|(dest1, _, _), (dest2, _, _)| dest2.cmp(dest1));

        let mut guard = self.route_table.lock();
        *guard = route_table;
    }

    pub fn route(&self, ip: &Ipv4Addr) -> Option<Ipv4Addr> {
        if ip.is_broadcast() {
            return None;
        }
        let ip: u32 = (*ip).into();

        if self.mask & ip == self.network {
            return None;
        }
        let route_table = self.route_table.lock();
        if route_table.is_empty() {
            return None;
        }
        for (dest, mask, gateway) in route_table.iter() {
            if *mask & ip == *dest {
                return Some(*gateway);
            }
        }
        None
    }
}
