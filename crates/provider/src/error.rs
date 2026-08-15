use thiserror::Error;
use wincred_libsecret_protocol::{BrokerError, ErrorCode, ProtocolError};
use zbus::DBusError;

pub type Result<T> = std::result::Result<T, ProviderError>;

/// Errors deliberately contain metadata only; secret material must never enter
/// a D-Bus error or tracing event.
#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("broker error: {0:?}")]
    Broker(BrokerError),
    #[error("broker transport unavailable")]
    Transport,
    #[error("broker request timed out")]
    Timeout,
    #[error("broker operation outcome is indeterminate")]
    Indeterminate,
    #[error("invalid Secret Service request: {0}")]
    InvalidRequest(String),
    #[error("unknown or expired session")]
    InvalidSession,
    #[error("secret exceeds the 2560-byte Windows Credential Manager limit")]
    SecretTooLarge,
    #[error("protocol error: {0}")]
    Protocol(ProtocolError),
}

impl From<ProviderError> for SecretServiceError {
    fn from(error: ProviderError) -> Self {
        match error {
            ProviderError::Broker(broker) => match broker.code {
                ErrorCode::NotFound | ErrorCode::InvalidCollection => {
                    Self::NoSuchObject(broker.message)
                }
                ErrorCode::AlreadyExists | ErrorCode::Conflict => {
                    Self::AlreadyExists(broker.message)
                }
                ErrorCode::SecretTooLarge | ErrorCode::MetadataTooLarge => {
                    Self::LimitsExceeded(broker.message)
                }
                ErrorCode::PermissionDenied => Self::AccessDenied(broker.message),
                ErrorCode::BackendUnavailable => Self::BackendUnavailable(broker.message),
                _ => Self::Failed(broker.message),
            },
            ProviderError::SecretTooLarge => Self::LimitsExceeded(
                "secret exceeds the 2560-byte Windows Credential Manager limit".to_owned(),
            ),
            ProviderError::InvalidSession => {
                Self::NoSuchSession("unknown or expired session".to_owned())
            }
            ProviderError::InvalidRequest(message) => Self::Failed(message),
            ProviderError::Transport | ProviderError::Timeout | ProviderError::Indeterminate => {
                Self::BackendUnavailable(
                    "Windows Credential Manager broker is unavailable".to_owned(),
                )
            }
            ProviderError::Protocol(error) => Self::Failed(error.to_string()),
        }
    }
}

/// The names and categories expected by libsecret clients.
#[derive(Debug, DBusError)]
#[zbus(prefix = "org.freedesktop.Secret.Error")]
pub enum SecretServiceError {
    Failed(String),
    NoSuchObject(String),
    NoSuchSession(String),
    AlreadyExists(String),
    IsLocked(String),
    AccessDenied(String),
    LimitsExceeded(String),
    BackendUnavailable(String),
}

impl From<SecretServiceError> for zbus::fdo::Error {
    fn from(error: SecretServiceError) -> Self {
        zbus::fdo::Error::Failed(error.to_string())
    }
}

impl From<ProtocolError> for ProviderError {
    fn from(error: ProtocolError) -> Self {
        if matches!(error, ProtocolError::InvalidMetadata(_)) {
            Self::InvalidRequest(error.to_string())
        } else {
            Self::Protocol(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_limit_errors_without_leaking_data() {
        let mapped: SecretServiceError = ProviderError::SecretTooLarge.into();
        assert_eq!(
            mapped.name().as_str(),
            "org.freedesktop.Secret.Error.LimitsExceeded"
        );
    }

    #[test]
    fn maps_broker_not_found_to_secret_service_name() {
        let mapped: SecretServiceError =
            ProviderError::Broker(BrokerError::new(ErrorCode::NotFound, "not found")).into();
        assert_eq!(
            mapped.name().as_str(),
            "org.freedesktop.Secret.Error.NoSuchObject"
        );
    }

    #[test]
    fn maps_all_broker_error_categories_to_stable_dbus_names() {
        for (code, expected) in [
            (ErrorCode::InvalidCollection, "NoSuchObject"),
            (ErrorCode::AlreadyExists, "AlreadyExists"),
            (ErrorCode::Conflict, "AlreadyExists"),
            (ErrorCode::SecretTooLarge, "LimitsExceeded"),
            (ErrorCode::MetadataTooLarge, "LimitsExceeded"),
            (ErrorCode::PermissionDenied, "AccessDenied"),
            (ErrorCode::BackendUnavailable, "BackendUnavailable"),
            (ErrorCode::CorruptState, "Failed"),
        ] {
            let mapped: SecretServiceError =
                ProviderError::Broker(BrokerError::new(code, "sanitized")).into();
            assert!(
                mapped.name().as_str().ends_with(expected),
                "unexpected D-Bus error for {code:?}"
            );
        }
        let timeout: SecretServiceError = ProviderError::Timeout.into();
        assert_eq!(
            timeout.name().as_str(),
            "org.freedesktop.Secret.Error.BackendUnavailable"
        );
    }
}
