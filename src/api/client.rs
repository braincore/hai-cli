use reqwest::{
    Client, Error as ReqwestError,
    header::{self, HeaderValue},
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::fmt;

use super::types::{account, asset, messaging, task};

#[derive(Debug, Clone)]
pub struct HaiClient {
    base_url: String,
    client: Client,
    token: Option<String>,
}

#[derive(Debug)]
pub enum RequestError<T> {
    Http(ReqwestError),
    Route(T),
    BadRequest(String),
    Unexpected(String),
}

impl<T: fmt::Display> fmt::Display for RequestError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RequestError::Http(e) => write!(f, "HTTP Error: {}", e),
            RequestError::Route(msg) => write!(f, "API Route Error: {}", msg),
            RequestError::BadRequest(msg) => write!(f, "Bad Request Error: {}", msg),
            RequestError::Unexpected(msg) => write!(f, "Unexpected Error: {}", msg),
        }
    }
}

impl<T: fmt::Debug + fmt::Display> std::error::Error for RequestError<T> {}

impl<T> From<ReqwestError> for RequestError<T> {
    fn from(error: ReqwestError) -> Self {
        RequestError::Http(error)
    }
}

impl HaiClient {
    /// Initializes a new HaiClient with the given base URL
    pub fn new(base_url: &str) -> Self {
        HaiClient {
            base_url: base_url.to_string(),
            client: Client::new(),
            token: None,
        }
    }

    /// Generic API request function for HaiClient
    pub async fn mk_api_request<ArgType, ResultType, ErrorType>(
        &self,
        endpoint: &str,
        arg: &ArgType,
    ) -> Result<ResultType, RequestError<ErrorType>>
    where
        ArgType: Serialize,
        ResultType: DeserializeOwned,
        ErrorType: DeserializeOwned,
    {
        // Construct the full URL based on `base_url` and `endpoint`
        let url = format!("{}{}", self.base_url, endpoint);

        // Create a new request builder and set the Authorization header if the token exists
        let mut request = self.client.post(&url).json(arg).header(
            header::USER_AGENT,
            HeaderValue::from_str(&format!("hai/{}", env!("CARGO_PKG_VERSION"))).map_err(|_| {
                RequestError::Unexpected("Failed to construct User-Agent header".into())
            })?,
        );

        if let Some(ref token) = self.token {
            // Add the authorization header: "Bearer {token}"
            let auth_value = format!("Bearer {}", token);
            request = request.header(
                header::AUTHORIZATION,
                HeaderValue::from_str(&auth_value).map_err(|_| {
                    RequestError::Unexpected("Failed to construct Authorization header".into())
                })?,
            );
        }

        // Send the request
        let response = request.send().await.map_err(RequestError::Http)?; // Map `reqwest::Error` to `RequestError::HttpError`

        // Determine what to do based on the HTTP status code
        if response.status().is_success() {
            // If successful, deserialize the response into the success type
            let result = response
                .json::<ResultType>()
                .await
                .map_err(RequestError::Http)?;
            Ok(result)
        } else if response.status().as_u16() == 418 {
            // If status is `418`, deserialize the response into the error type
            let error = response
                .json::<ErrorType>()
                .await
                .map_err(RequestError::Http)?;
            Err(RequestError::Route(error))
        } else if response.status().as_u16() == 422 {
            // If status is `422`, show body
            Err(RequestError::BadRequest(
                response.text().await.unwrap_or("".to_string()),
            ))
        } else {
            // Handle unexpected status codes
            Err(RequestError::Unexpected(format!(
                "Unexpected HTTP status: {}",
                response.status()
            )))
        }
    }

    /// Sets the account credentials (token) to authenticate the client
    pub fn set_token(&mut self, token: &str) {
        self.token = Some(token.to_string());
    }

    /// Authenticates with a username and password, returning a token
    pub async fn account_token_from_login(
        &self,
        arg: account::AccountTokenFromLoginArg,
    ) -> Result<
        account::AccountTokenFromLoginResult,
        RequestError<account::AccountTokenFromLoginError>,
    > {
        self.mk_api_request::<_, account::AccountTokenFromLoginResult, account::AccountTokenFromLoginError>(
            "/account/token_from_login",
            &arg,
        )
        .await
    }

    /// Authenticates with a username and password, returning a token
    pub async fn account_register(
        &self,
        arg: account::AccountRegisterArg,
    ) -> Result<account::AccountRegisterResult, RequestError<account::AccountRegisterError>> {
        self.mk_api_request::<_, account::AccountRegisterResult, account::AccountRegisterError>(
            "/account/register",
            &arg,
        )
        .await
    }

    pub async fn account_check_client_version(
        &self,
        arg: (),
    ) -> Result<account::AccountCheckClientVersionResult, RequestError<()>> {
        self.mk_api_request::<_, account::AccountCheckClientVersionResult, ()>(
            "/account/check_client_version",
            &arg,
        )
        .await
    }

    pub async fn account_whois(
        &self,
        arg: account::AccountWhoisArg,
    ) -> Result<account::AccountWhoisResult, RequestError<account::AccountWhoisError>> {
        self.mk_api_request::<_, account::AccountWhoisResult, account::AccountWhoisError>(
            "/account/whois",
            &arg,
        )
        .await
    }

    pub async fn account_get_balance(
        &self,
        arg: (),
    ) -> Result<account::AccountGetBalanceResult, RequestError<()>> {
        self.mk_api_request::<_, _, _>("/account/get_balance", &arg)
            .await
    }

    pub async fn account_get_subscribe_link(
        &self,
        arg: (),
    ) -> Result<
        account::AccountGetSubscribeLinkResult,
        RequestError<account::AccountGetSubscribeLinkError>,
    > {
        self.mk_api_request::<_, _, _>("/account/get_subscribe_link", &arg)
            .await
    }

    /// Puts a task to the repository
    pub async fn task_put(
        &self,
        arg: task::TaskPutArg,
    ) -> Result<(), RequestError<task::TaskPutError>> {
        self.mk_api_request::<_, (), task::TaskPutError>("/task/put", &arg)
            .await
    }

    pub async fn task_get(
        &self,
        arg: task::TaskGetArg,
    ) -> Result<task::TaskGetResult, RequestError<task::TaskGetError>> {
        self.mk_api_request::<_, task::TaskGetResult, task::TaskGetError>("/task/get", &arg)
            .await
    }

    pub async fn task_list_versions(
        &self,
        arg: task::TaskListVersionsArg,
    ) -> Result<task::TaskListVersionsResult, RequestError<task::TaskListVersionsError>> {
        self.mk_api_request::<_, task::TaskListVersionsResult, task::TaskListVersionsError>(
            "/task/list_versions",
            &arg,
        )
        .await
    }

    pub async fn task_search(
        &self,
        arg: task::TaskSearchArg,
    ) -> Result<task::TaskSearchResult, RequestError<task::TaskSearchError>> {
        self.mk_api_request::<_, task::TaskSearchResult, task::TaskSearchError>(
            "/task/search",
            &arg,
        )
        .await
    }

    pub async fn asset_put(
        &self,
        arg: asset::AssetPutArg,
    ) -> Result<asset::AssetPutResult, RequestError<asset::AssetPutError>> {
        self.mk_api_request::<_, _, _>("/asset/put", &arg).await
    }

    pub async fn asset_put_text(
        &self,
        arg: asset::AssetPutTextArg,
    ) -> Result<asset::AssetPutResult, RequestError<asset::AssetPutError>> {
        self.mk_api_request::<_, _, _>("/asset/put_text", &arg)
            .await
    }

    #[allow(dead_code)]
    pub async fn asset_replace(
        &self,
        arg: asset::AssetReplaceArg,
    ) -> Result<asset::AssetReplaceResult, RequestError<asset::AssetReplaceError>> {
        self.mk_api_request::<_, _, _>("/asset/replace", &arg).await
    }

    #[allow(dead_code)]
    pub async fn asset_replace_text(
        &self,
        arg: asset::AssetReplaceTextArg,
    ) -> Result<asset::AssetReplaceResult, RequestError<asset::AssetReplaceError>> {
        self.mk_api_request::<_, _, _>("/asset/replace_text", &arg)
            .await
    }

    pub async fn asset_push(
        &self,
        arg: asset::AssetPushArg,
    ) -> Result<asset::AssetPushResult, RequestError<asset::AssetPushError>> {
        self.mk_api_request::<_, _, _>("/asset/push", &arg).await
    }

    pub async fn asset_get(
        &self,
        arg: asset::AssetGetArg,
    ) -> Result<asset::AssetGetResult, RequestError<asset::AssetGetError>> {
        self.mk_api_request::<_, _, _>("/asset/get", &arg).await
    }

    pub async fn asset_remove(
        &self,
        arg: asset::AssetRemoveArg,
    ) -> Result<asset::AssetRemoveResult, RequestError<asset::AssetRemoveError>> {
        self.mk_api_request::<_, _, _>("/asset/remove", &arg).await
    }

    pub async fn asset_move(
        &self,
        arg: asset::AssetMoveArg,
    ) -> Result<asset::AssetMoveResult, RequestError<asset::AssetMoveError>> {
        self.mk_api_request::<_, _, _>("/asset/move", &arg).await
    }

    pub async fn asset_metadata_put(
        &self,
        arg: asset::AssetMetadataPutArg,
    ) -> Result<asset::AssetPutResult, RequestError<asset::AssetMetadataPutError>> {
        self.mk_api_request::<_, _, _>("/asset/metadata/put", &arg)
            .await
    }

    pub async fn asset_entry_acl_set(
        &self,
        arg: asset::AssetEntryAclSetArg,
    ) -> Result<asset::AssetEntryAcl, RequestError<asset::AssetEntryAclSetError>> {
        self.mk_api_request::<_, _, _>("/asset/entry/acl/set", &arg)
            .await
    }

    #[allow(dead_code)]
    pub async fn asset_entry_acl_get(
        &self,
        arg: asset::AssetEntryAclGetArg,
    ) -> Result<asset::AssetEntryAcl, RequestError<asset::AssetEntryAclGetError>> {
        self.mk_api_request::<_, _, _>("/asset/entry/acl/get", &arg)
            .await
    }

    pub async fn asset_entry_list(
        &self,
        arg: asset::AssetEntryListArg,
    ) -> Result<asset::AssetEntryListResult, RequestError<asset::AssetEntryListError>> {
        self.mk_api_request::<_, _, _>("/asset/entry/list", &arg)
            .await
    }

    pub async fn asset_entry_list_next(
        &self,
        arg: asset::AssetEntryListNextArg,
    ) -> Result<asset::AssetEntryListResult, RequestError<asset::AssetEntryListNextError>> {
        self.mk_api_request::<_, _, _>("/asset/entry/list/next", &arg)
            .await
    }

    pub async fn asset_entry_iter(
        &self,
        arg: asset::AssetEntryIterArg,
    ) -> Result<asset::AssetEntryIterResult, RequestError<asset::AssetEntryIterError>> {
        self.mk_api_request::<_, _, _>("/asset/entry/iter", &arg)
            .await
    }

    pub async fn asset_entry_iter_next(
        &self,
        arg: asset::AssetEntryIterNextArg,
    ) -> Result<asset::AssetEntryIterResult, RequestError<asset::AssetEntryIterNextError>> {
        self.mk_api_request::<_, _, _>("/asset/entry/iter/next", &arg)
            .await
    }

    pub async fn asset_entry_search(
        &self,
        arg: asset::AssetEntrySearchArg,
    ) -> Result<asset::AssetEntrySearchResult, RequestError<asset::AssetEntrySearchError>> {
        self.mk_api_request::<_, _, _>("/asset/entry/search", &arg)
            .await
    }

    pub async fn asset_folder_collapse(
        &self,
        arg: asset::AssetPoolFolderCollapseArg,
    ) -> Result<(), RequestError<asset::AssetPoolFolderCollapseError>> {
        self.mk_api_request::<_, _, _>("/asset/folder/collapse", &arg)
            .await
    }

    pub async fn asset_folder_expand(
        &self,
        arg: asset::AssetPoolFolderExpandArg,
    ) -> Result<(), RequestError<asset::AssetPoolFolderExpandError>> {
        self.mk_api_request::<_, _, _>("/asset/folder/expand", &arg)
            .await
    }

    pub async fn asset_folder_list(
        &self,
        arg: asset::AssetPoolFolderListArg,
    ) -> Result<asset::AssetPoolFolderListResult, RequestError<asset::AssetPoolFolderListError>>
    {
        self.mk_api_request::<_, _, _>("/asset/folder/list", &arg)
            .await
    }

    pub async fn asset_revision_iter(
        &self,
        arg: asset::AssetRevisionIterArg,
    ) -> Result<asset::AssetRevisionIterResult, RequestError<asset::AssetRevisionIterError>> {
        self.mk_api_request::<_, _, _>("/asset/revision/iter", &arg)
            .await
    }

    pub async fn asset_revision_iter_next(
        &self,
        arg: asset::AssetRevisionIterNextArg,
    ) -> Result<asset::AssetRevisionIterResult, RequestError<asset::AssetRevisionIterNextError>>
    {
        self.mk_api_request::<_, _, _>("/asset/revision/iter/next", &arg)
            .await
    }

    pub async fn asset_revision_get(
        &self,
        arg: asset::AssetRevisionGetArg,
    ) -> Result<asset::AssetRevisionGetResult, RequestError<asset::AssetRevisionGetError>> {
        self.mk_api_request::<_, _, _>("/asset/revision/get", &arg)
            .await
    }

    pub async fn messaging_email_recipient_send(
        &self,
        arg: messaging::EmailRecipientSendArg,
    ) -> Result<(), RequestError<messaging::EmailRecipientSendError>> {
        self.mk_api_request::<_, _, _>("/messaging/email_recipient/send", &arg)
            .await
    }
}
