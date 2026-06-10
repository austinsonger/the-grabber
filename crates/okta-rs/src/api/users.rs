use crate::client::OktaClient;
pub struct UsersApi<'c>(pub(crate) &'c OktaClient);
