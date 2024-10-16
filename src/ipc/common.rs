use serde::{Deserialize, Serialize};
use tabled::Tabled;

#[derive(Serialize, Deserialize, Debug, Tabled)]
pub struct RouteItem {
    pub node_id: String,
    pub next_hop: String,
    pub protocol:String,
    pub metric: u8,
    pub rtt: u32,
}
#[derive(Serialize, Deserialize, Debug, Tabled)]
pub struct GroupItem {
    pub group_code: String,
}
