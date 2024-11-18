use netlink_http::web_server::StaticFileAssets;

#[derive(rust_embed::Embed)]
#[folder = "static/"]
struct StaticAssetsInner;

#[derive(Copy, Clone)]
pub struct StaticAssets;

impl StaticFileAssets for StaticAssets {
    fn get_file(&self, path: &str) -> Option<(Vec<u8>, String)> {
        StaticAssetsInner::get(path).map(|v| (v.data.to_vec(), v.metadata.mimetype().to_string()))
    }
}
