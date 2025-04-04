use base64::{Engine, engine::general_purpose};
use chrono::{Duration, Utc};
use hmac::{Hmac, KeyInit, Mac};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::error::Error;

use super::auth::AccessTokenResponse;

const SERVICE_VERSION: &'static str = "2022-11-02";

/// The request body for getting the user delegation key.
#[derive(Serialize, Debug, Clone)]
#[serde(rename = "KeyInfo")]
struct UserDelegationKeyRequest {
    /// The start time for the key.
    #[serde(rename = "Start")]
    pub start: String,

    /// The expiry time for the key.
    #[serde(rename = "Expiry")]
    pub expiry: String,
}

impl UserDelegationKeyRequest {
    /// Create a new `UserDelegationKeyRequest`.
    ///
    /// ## Arguments
    ///
    /// * `expires_in_hours` - The number of hours until the key expires.
    pub fn new(expires_in_hours: i64) -> Result<Self, Error> {
        let current_utc_time = Utc::now();
        let expires_utc_time = Utc::now() + Duration::hours(expires_in_hours);

        let start = current_utc_time.format("%FT%TZ").to_string();
        let expiry = expires_utc_time.format("%FT%TZ").to_string();

        Ok(Self { start, expiry })
    }
}

/// The user delegation key for a storage account.
#[derive(Deserialize, Debug, Clone)]
#[serde(rename = "UserDelegationKey")]
pub struct UserDelegationKey {
    #[serde(rename = "SignedOid")]
    pub signed_oid: String,

    #[serde(rename = "SignedTid")]
    pub signed_tid: String,

    #[serde(rename = "SignedStart")]
    pub signed_start: String,

    #[serde(rename = "SignedExpiry")]
    pub signed_expiry: String,

    #[serde(rename = "SignedService")]
    pub signed_service: String,

    #[serde(rename = "SignedVersion")]
    pub signed_version: String,

    #[serde(rename = "Value")]
    pub value: String,
}

impl UserDelegationKey {
    /// Generate a SAS signature token with the user delegation key.
    ///
    /// ## Arguments
    ///
    /// * `storage_account_name` - The name of the storage account.
    /// * `container_name` - The name of the container in the storage account.
    pub fn to_sas_token(
        &self,
        storage_account_name: &str,
        container_name: &str,
    ) -> Result<String, Error> {
        let sas_signature = self.generate_sas_signature(storage_account_name, container_name)?;
        let sas_signature = utf8_percent_encode(&sas_signature, NON_ALPHANUMERIC).to_string();

        let sas_token = format!(
            "sp=r&st={SignedStart}&se={SignedExpiry}&skoid={SignedOid}&sktid={SignedTid}&skt={SignedStart}&ske={SignedExpiry}&sks={SignedService}&skv={SignedVersion}&spr=https&sv={SignedVersion}&sr=c&sig={SignedSignature}",
            SignedStart = self.signed_start,
            SignedExpiry = self.signed_expiry,
            SignedOid = self.signed_oid,
            SignedTid = self.signed_tid,
            SignedService = self.signed_service,
            SignedVersion = self.signed_version,
            SignedSignature = sas_signature
        );

        Ok(sas_token)
    }

    /// Generate a SAS signature with the user delegation key.
    ///
    /// ## Arguments
    ///
    /// * `storage_account_name` - The name of the storage account.
    /// * `container_name` - The name of the container in the storage account.
    fn generate_sas_signature(
        &self,
        storage_account_name: &str,
        container_name: &str,
    ) -> Result<String, Error> {
        let value_bytes = general_purpose::STANDARD
            .decode(&self.value)
            .map_err(|e| Error::Base64DecodeError(e))?;

        let mut hmac_signer =
            Hmac::<Sha256>::new_from_slice(&value_bytes).map_err(|_| Error::UnknownError)?;

        let string_to_sign = format!(
            r#"r
{SignedStart}
{SignedExpiry}
/blob/{StorageAccountName}/{ContainerName}
{SignedOid}
{SignedTid}
{SignedStart}
{SignedExpiry}
{SignedService}
{SignedVersion}




https
{SignedVersion}
c






"#,
            SignedStart = self.signed_start,
            SignedExpiry = self.signed_expiry,
            SignedOid = self.signed_oid,
            SignedTid = self.signed_tid,
            SignedService = self.signed_service,
            SignedVersion = self.signed_version,
            StorageAccountName = storage_account_name,
            ContainerName = container_name
        );

        hmac_signer.update(string_to_sign.as_bytes());

        let signature_bytes_result = hmac_signer.finalize();

        let signature_bytes = signature_bytes_result.into_bytes();

        let signature = general_purpose::STANDARD.encode(&signature_bytes);

        Ok(signature)
    }
}

/// Get the user delegation key.
///
/// ## Arguments
///
/// * `access_token` - The access token for the request.
/// * `storage_account_name` - The name of the storage account.
pub fn get_user_delegation_key(
    access_token: &AccessTokenResponse,
    storage_account_name: &str,
) -> Result<UserDelegationKey, Error> {
    let mut default_http_headers = HeaderMap::new();
    default_http_headers.insert(
        "Authorization",
        format!("Bearer {}", access_token.access_token)
            .parse()
            .unwrap(),
    );
    default_http_headers.insert("x-ms-version", SERVICE_VERSION.parse().unwrap());

    let http_client = reqwest::blocking::Client::builder()
        .user_agent("AzTokenRetriever")
        .use_rustls_tls()
        .default_headers(default_http_headers)
        .build()
        .map_err(|_| Error::HttpClientCreationError)?;

    let user_delegation_request_body = UserDelegationKeyRequest::new(2)?;
    let user_delegation_request_body =
        quick_xml::se::to_string::<UserDelegationKeyRequest>(&user_delegation_request_body)
            .map_err(|e| Error::XmlSerializationError(e))?;

    let request_url = format!(
        "https://{}.blob.core.windows.net/?restype=service&comp=userdelegationkey",
        storage_account_name
    );

    let user_delegation_response = http_client
        .post(request_url)
        .header("Content-Type", "application/xml")
        .body(user_delegation_request_body)
        .send()
        .map_err(|e| Error::HttpRequestError(e))?
        .text()
        .map_err(|e| Error::HttpRequestError(e))?;

    let user_delegation_response =
        quick_xml::de::from_str::<UserDelegationKey>(&user_delegation_response)
            .map_err(|e| Error::XmlDeserializationError(e))?;

    Ok(user_delegation_response)
}
