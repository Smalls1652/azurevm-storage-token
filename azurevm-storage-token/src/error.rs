use std::string::FromUtf8Error;

use thiserror::Error;

/// Errors for the application.
#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum Error {
    /// Error when parsing CLI arguments.
    #[error("Failed to parse CLI arguments: {0}")]
    ArgParseError(clap_builder::Error),

    /// Error when decoding a Base64 string.
    #[error("An error occurred while decode Base64 string: {0}")]
    Base64DecodeError(base64::DecodeError),

    /// Error when creating an HTTP client.
    #[error("Failed to create HTTP client")]
    HttpClientCreationError,

    /// Error when a HTTP request fails.
    #[error("An error occurred with the HTTP request: {0}")]
    HttpRequestError(reqwest::Error),

    /// Error that occurs when a managed identity token cannot be retrieved.
    #[error("An error occurred while getting an access token")]
    ManagedIdentityAccessTokenError,

    /// Error when a time is invalid.
    #[error("An invalid time was provided")]
    InvalidTimeError,

    /// Error when a XML could not be serialized.
    #[error("An error occurred while serializing XML: {0}")]
    XmlSerializationError(quick_xml::se::SeError),

    /// Error when a XML could not be deserialized.
    #[error("An error occurred while deserializing XML: {0}")]
    XmlDeserializationError(quick_xml::de::DeError),

    /// Error when an UTF8 string could not be decoded.
    #[error("An error occurred while decoding UTF8 string: {0}")]
    UTF8DecodeError(FromUtf8Error),

    /// A generic unknown error.
    #[error("An unknown error occurred")]
    UnknownError,
}
