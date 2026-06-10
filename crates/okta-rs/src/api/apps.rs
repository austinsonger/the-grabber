use crate::client::OktaClient;
pub struct AppsApi<'c>(pub(crate) &'c OktaClient);
