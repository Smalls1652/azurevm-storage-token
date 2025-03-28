use serde::{Deserialize, Serialize};

use crate::error::Error;

/// The endpoint for an Azure Managed Identity to get an access token from.
static MANAGED_IDENTITY_TOKEN_ENDPOINT: &str =
    "http://169.254.169.254/metadata/identity/oauth2/token";

/// The access token response from the Azure Managed Identity token endpoint.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct AccessTokenResponse {
    /// The access token string that can be used to authenticate requests.
    #[serde(rename = "access_token")]
    pub access_token: String,

    /// The client ID of the application that is requesting an access token.
    #[serde(rename = "client_id")]
    pub client_id: String,

    /// The time when the access token expires.
    #[serde(rename = "expires_in")]
    pub expires_in: String,

    /// The datetime the access token expires.
    #[serde(rename = "expires_on")]
    pub expires_on: String,

    #[serde(rename = "ext_expires_in")]
    pub ext_expires_in: String,

    /// The time when the access token can be used.
    #[serde(rename = "not_before")]
    pub not_before: String,

    /// The resource(s) that the access token is for.
    #[serde(rename = "resource")]
    pub resource: String,

    /// The type of token that is being requested.
    #[serde(rename = "token_type")]
    pub token_type: String,
}

/// Get an access token for a managed identity.
///
/// ## Arguments
///
/// * `resource` - The resource(s) that the access token is for.
pub async fn get_managed_identity_token(resource: &str) -> Result<AccessTokenResponse, Error> {
    let http_client = reqwest::Client::builder()
        .user_agent("AzTokenRetriever")
        .use_rustls_tls()
        .build()
        .map_err(|_| Error::HttpClientCreationError)?;

    let encoded_resource =
        percent_encoding::utf8_percent_encode(resource, percent_encoding::CONTROLS).to_string();

    let url = format!(
        "{}?api-version=2018-02-01&resource={}",
        MANAGED_IDENTITY_TOKEN_ENDPOINT, encoded_resource
    );

    let token_response = http_client
        .get(url)
        .header("Metadata", "true")
        .send()
        .await
        .map_err(|e| Error::HttpRequestError(e))?
        .json::<AccessTokenResponse>()
        .await
        .map_err(|e| Error::HttpRequestError(e))?;

    Ok(token_response)
}
