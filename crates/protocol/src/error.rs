use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable error codes exchanged between the provider and broker.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidRequest,
    UnsupportedVersion,
    NotFound,
    AlreadyExists,
    InvalidCollection,
    SecretTooLarge,
    MetadataTooLarge,
    PermissionDenied,
    BackendUnavailable,
    Conflict,
    CorruptState,
    Internal,
}

/// A sanitized broker error safe to return over the wire.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BrokerError {
    pub code: ErrorCode,
    pub message: String,
}

impl BrokerError {
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// Errors produced while reading, writing, or validating protocol frames.
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("frame length {actual} exceeds the maximum {maximum}")]
    FrameTooLarge { actual: usize, maximum: usize },

    #[error("zero-length frames are invalid")]
    EmptyFrame,

    #[error("CBOR encoding failed: {0}")]
    Encode(String),

    #[error("CBOR decoding failed: {0}")]
    Decode(String),

    #[error("frame contains {0} trailing bytes")]
    TrailingBytes(usize),

    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u16),

    #[error("no mutually supported protocol version")]
    NoCommonVersion,

    #[error("invalid metadata: {0}")]
    InvalidMetadata(String),
}
