use crate::client::OktaClient;
pub struct SystemLogApi<'c>(pub(crate) &'c OktaClient);
