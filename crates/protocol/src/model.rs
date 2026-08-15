use std::{
    collections::BTreeMap,
    fmt,
    ops::{Deref, DerefMut},
};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use serde_bytes::ByteBuf;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ProtocolError;

/// Native maximum size of a `WinCred` generic credential blob.
pub const MAX_SECRET_BYTES: usize = 5 * 512;

/// Maximum encoded metadata blob accepted by the broker.
pub const MAX_METADATA_BYTES: usize = MAX_SECRET_BYTES;

/// Maximum UTF-8 label size accepted by this provider.
pub const MAX_LABEL_BYTES: usize = 1024;

/// Maximum UTF-8 alias size accepted by this provider.
pub const MAX_ALIAS_BYTES: usize = 255;

const MAX_ATTRIBUTE_COUNT: usize = 64;
const MAX_ATTRIBUTE_KEY_BYTES: usize = 255;
const MAX_ATTRIBUTE_VALUE_BYTES: usize = 1024;
const MAX_CONTENT_TYPE_BYTES: usize = 255;

/// Secret bytes with redacted debug output and zeroization on drop.
#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(value: Vec<u8>) -> Result<Self, ProtocolError> {
        if value.len() > MAX_SECRET_BYTES {
            return Err(ProtocolError::InvalidMetadata(format!(
                "secret is {} bytes; maximum is {MAX_SECRET_BYTES}",
                value.len()
            )));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn into_inner(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretBytes")
            .field("length", &self.0.len())
            .field("value", &"[REDACTED]")
            .finish()
    }
}

impl Deref for SecretBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.expose()
    }
}

impl DerefMut for SecretBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Serialize for SecretBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = ByteBuf::deserialize(deserializer)?.into_vec();
        Self::new(value).map_err(D::Error::custom)
    }
}

/// Persistent collection metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CollectionMetadata {
    pub schema_version: u16,
    pub id: Uuid,
    pub label: String,
    pub created: u64,
    pub modified: u64,
}

/// Persistent item metadata. The referenced generation is the commit record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ItemMetadata {
    pub schema_version: u16,
    pub id: Uuid,
    pub collection_id: Uuid,
    pub label: String,
    pub attributes: BTreeMap<String, String>,
    pub content_type: String,
    pub created: u64,
    pub modified: u64,
    pub current_generation: Uuid,
}

/// Persistent alias mapping.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AliasMetadata {
    pub schema_version: u16,
    pub name: String,
    pub collection_id: Uuid,
}

pub fn validate_label(label: &str) -> Result<(), ProtocolError> {
    validate_text("label", label, MAX_LABEL_BYTES, false)
}

pub fn validate_alias_name(name: &str) -> Result<(), ProtocolError> {
    validate_text("alias name", name, MAX_ALIAS_BYTES, false)
}

pub fn validate_content_type(content_type: &str) -> Result<(), ProtocolError> {
    validate_text("content type", content_type, MAX_CONTENT_TYPE_BYTES, false)
}

pub fn validate_attributes(attributes: &BTreeMap<String, String>) -> Result<(), ProtocolError> {
    if attributes.len() > MAX_ATTRIBUTE_COUNT {
        return Err(ProtocolError::InvalidMetadata(format!(
            "attribute count {} exceeds {MAX_ATTRIBUTE_COUNT}",
            attributes.len()
        )));
    }

    for (key, value) in attributes {
        validate_text("attribute key", key, MAX_ATTRIBUTE_KEY_BYTES, false)?;
        validate_text("attribute value", value, MAX_ATTRIBUTE_VALUE_BYTES, true)?;
    }
    Ok(())
}

fn validate_text(
    field: &str,
    value: &str,
    maximum: usize,
    allow_empty: bool,
) -> Result<(), ProtocolError> {
    if !allow_empty && value.is_empty() {
        return Err(ProtocolError::InvalidMetadata(format!(
            "{field} cannot be empty"
        )));
    }
    if value.len() > maximum {
        return Err(ProtocolError::InvalidMetadata(format!(
            "{field} is {} bytes; maximum is {maximum}",
            value.len()
        )));
    }
    if value.contains('\0') {
        return Err(ProtocolError::InvalidMetadata(format!(
            "{field} contains a NUL byte"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroize;

    #[test]
    fn accepts_native_secret_limit() {
        assert!(SecretBytes::new(vec![0xA5; MAX_SECRET_BYTES]).is_ok());
    }

    #[test]
    fn rejects_secret_above_native_limit() {
        assert!(SecretBytes::new(vec![0xA5; MAX_SECRET_BYTES + 1]).is_err());
    }

    #[test]
    fn debug_output_redacts_secret() {
        let secret = SecretBytes::new(b"never-print-me".to_vec()).unwrap();
        let output = format!("{secret:?}");
        assert!(output.contains("[REDACTED]"));
        assert!(!output.contains("never-print-me"));
    }

    #[test]
    fn validates_attribute_bounds() {
        let mut attributes = BTreeMap::new();
        attributes.insert("service".to_owned(), "example.com".to_owned());
        assert!(validate_attributes(&attributes).is_ok());

        attributes.insert("bad\0key".to_owned(), "value".to_owned());
        assert!(validate_attributes(&attributes).is_err());
    }

    #[test]
    fn validates_unicode_aliases_by_utf8_length() {
        assert!(validate_alias_name("默认🔐").is_ok());
        assert!(validate_alias_name(&"é".repeat(MAX_ALIAS_BYTES / 2)).is_ok());
        assert!(validate_alias_name(&"é".repeat((MAX_ALIAS_BYTES / 2) + 1)).is_err());
        assert!(validate_alias_name("").is_err());
        assert!(validate_alias_name("invalid\0alias").is_err());
    }

    #[test]
    fn explicit_zeroization_clears_the_observable_secret_value() {
        let mut secret = SecretBytes::new(vec![0xA5; 32]).unwrap();
        secret.zeroize();
        assert!(secret.expose().is_empty());
    }

    #[test]
    fn metadata_validators_enforce_text_and_attribute_boundaries() {
        assert!(validate_label(&"x".repeat(MAX_LABEL_BYTES)).is_ok());
        assert!(validate_label(&"x".repeat(MAX_LABEL_BYTES + 1)).is_err());
        assert!(validate_content_type("").is_err());

        let attributes = (0..65)
            .map(|index| (format!("key-{index}"), "value".to_owned()))
            .collect();
        assert!(validate_attributes(&attributes).is_err());
    }
}
