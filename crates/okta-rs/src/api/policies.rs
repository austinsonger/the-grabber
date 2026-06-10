use crate::client::OktaClient;
pub struct PoliciesApi<'c>(pub(crate) &'c OktaClient);
