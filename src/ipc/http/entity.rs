use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiResponse<T> {
    pub code: u32,
    pub data: T,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> ApiResponse<T> {
        Self { code: 200, data }
    }
    pub fn failed(data: T) -> ApiResponse<T> {
        Self { code: 400, data }
    }
}
impl<T: Serialize> ApiResponse<T> {
    pub fn to_json(&self) -> String {
        serde_json::to_string(&self).unwrap_or_else(|_e| {
            let json_str = r#"{"code": 400, "data": "failed"}"#;
            json_str.to_string()
        })
    }
}
