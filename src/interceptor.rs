use crate::service::ApiService;
use salvo::{async_trait, Depot, FlowCtrl, Handler, Request, Response};

pub struct ApiInterceptor(ApiService);
impl ApiInterceptor {
    pub fn new(api: ApiService) -> Self {
        ApiInterceptor(api)
    }
}

#[async_trait]
impl Handler for ApiInterceptor {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        ctrl.call_next(req, depot, res).await;
        if req.uri().path() == "/api/update-config" {
            if let Err(e) = self.0.save_config().await {
                log::warn!("save_config {e:?}")
            }
        }
    }
}
