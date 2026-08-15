use std::{fmt, str::FromStr};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use thiserror::Error;
use uuid::Uuid;

use crate::MAX_ALIAS_BYTES;

/// Prefix used for every credential owned by this project.
pub const CREDENTIAL_PREFIX: &str = "WinCredLibSecret/v1/";

/// A strongly typed `WinCred` target name.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TargetName {
    Collection(Uuid),
    Alias(String),
    ItemMetadata(Uuid),
    ItemSecret { item_id: Uuid, generation: Uuid },
}

impl fmt::Display for TargetName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Collection(id) => {
                write!(formatter, "{CREDENTIAL_PREFIX}collection/{id}")
            }
            Self::Alias(alias) => {
                let encoded = URL_SAFE_NO_PAD.encode(alias.as_bytes());
                write!(formatter, "{CREDENTIAL_PREFIX}alias/{encoded}")
            }
            Self::ItemMetadata(id) => {
                write!(formatter, "{CREDENTIAL_PREFIX}item/{id}/meta")
            }
            Self::ItemSecret {
                item_id,
                generation,
            } => write!(
                formatter,
                "{CREDENTIAL_PREFIX}item/{item_id}/secret/{generation}"
            ),
        }
    }
}

impl FromStr for TargetName {
    type Err = TargetParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let suffix = value
            .strip_prefix(CREDENTIAL_PREFIX)
            .ok_or(TargetParseError::ForeignPrefix)?;
        let parts: Vec<_> = suffix.split('/').collect();
        match parts.as_slice() {
            ["collection", id] => Ok(Self::Collection(parse_uuid(id)?)),
            ["alias", encoded] => {
                let bytes = URL_SAFE_NO_PAD
                    .decode(encoded)
                    .map_err(|_| TargetParseError::InvalidAliasEncoding)?;
                if bytes.len() > MAX_ALIAS_BYTES {
                    return Err(TargetParseError::AliasTooLong);
                }
                let alias =
                    String::from_utf8(bytes).map_err(|_| TargetParseError::InvalidAliasEncoding)?;
                if alias.is_empty() || alias.contains('\0') {
                    return Err(TargetParseError::InvalidAliasEncoding);
                }
                Ok(Self::Alias(alias))
            }
            ["item", id, "meta"] => Ok(Self::ItemMetadata(parse_uuid(id)?)),
            ["item", id, "secret", generation] => Ok(Self::ItemSecret {
                item_id: parse_uuid(id)?,
                generation: parse_uuid(generation)?,
            }),
            _ => Err(TargetParseError::InvalidShape),
        }
    }
}

fn parse_uuid(value: &str) -> Result<Uuid, TargetParseError> {
    let id = Uuid::parse_str(value).map_err(|_| TargetParseError::InvalidUuid)?;
    if id.to_string() != value {
        return Err(TargetParseError::NonCanonicalUuid);
    }
    Ok(id)
}

/// Errors returned when parsing project-owned target names.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TargetParseError {
    #[error("credential target is outside the project namespace")]
    ForeignPrefix,
    #[error("credential target has an invalid shape")]
    InvalidShape,
    #[error("credential target contains an invalid UUID")]
    InvalidUuid,
    #[error("credential target UUID is not canonical")]
    NonCanonicalUuid,
    #[error("credential alias encoding is invalid")]
    InvalidAliasEncoding,
    #[error("credential alias is too long")]
    AliasTooLong,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_names_round_trip() {
        let item_id = Uuid::new_v4();
        let generation = Uuid::new_v4();
        let targets = [
            TargetName::Collection(Uuid::new_v4()),
            TargetName::Alias("default/中文".to_owned()),
            TargetName::ItemMetadata(item_id),
            TargetName::ItemSecret {
                item_id,
                generation,
            },
        ];

        for expected in targets {
            let encoded = expected.to_string();
            assert_eq!(encoded.parse::<TargetName>().unwrap(), expected);
        }
    }

    #[test]
    fn rejects_foreign_credentials() {
        assert_eq!(
            "OtherApplication/item".parse::<TargetName>(),
            Err(TargetParseError::ForeignPrefix)
        );
    }

    #[test]
    fn rejects_noncanonical_uuid() {
        let value = format!(
            "{CREDENTIAL_PREFIX}collection/{}",
            Uuid::new_v4().to_string().to_uppercase()
        );
        assert_eq!(
            value.parse::<TargetName>(),
            Err(TargetParseError::NonCanonicalUuid)
        );
    }

    #[test]
    fn target_parser_round_trips_many_ids_and_unicode_alias_boundaries() {
        for value in 1_u128..129 {
            let id = Uuid::from_u128(value);
            let generation = Uuid::from_u128(value << 64);
            for target in [
                TargetName::Collection(id),
                TargetName::ItemMetadata(id),
                TargetName::ItemSecret {
                    item_id: id,
                    generation,
                },
            ] {
                assert_eq!(target.to_string().parse::<TargetName>(), Ok(target));
            }
        }

        let alias = "é".repeat(MAX_ALIAS_BYTES / 2);
        let target = TargetName::Alias(alias);
        assert_eq!(target.to_string().parse::<TargetName>(), Ok(target));
        let oversized = TargetName::Alias("x".repeat(MAX_ALIAS_BYTES + 1)).to_string();
        assert_eq!(
            oversized.parse::<TargetName>(),
            Err(TargetParseError::AliasTooLong)
        );
    }

    #[test]
    fn parser_rejects_malformed_owned_targets_without_panicking() {
        let malformed = [
            "",
            CREDENTIAL_PREFIX,
            "WinCredLibSecret/v0/collection/00000000-0000-0000-0000-000000000000",
            "WinCredLibSecret/v1/collection/not-a-uuid",
            "WinCredLibSecret/v1/collection/00000000000000000000000000000000",
            "WinCredLibSecret/v1/item/00000000-0000-0000-0000-000000000000/secret",
            "WinCredLibSecret/v1/alias/%%%",
            "WinCredLibSecret/v1/alias/",
            "WinCredLibSecret/v1/item/00000000-0000-0000-0000-000000000000/meta/extra",
        ];

        for target in malformed {
            assert!(target.parse::<TargetName>().is_err(), "{target}");
        }
    }
}
