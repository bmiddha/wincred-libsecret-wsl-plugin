//! Shared broker protocol and persistent `WinCred` vault model.

mod error;
mod frame;
mod message;
mod model;
mod target;
mod vault;

pub use error::{BrokerError, ErrorCode, ProtocolError};
pub use frame::{MAX_FRAME_SIZE, read_frame, write_frame};
pub use message::{
    Capability, CapabilitySet, Envelope, Hello, HelloAck, Operation, PROTOCOL_VERSION, Request,
    Response, ResponseBody, VersionRange, negotiate,
};
pub use model::{
    AliasMetadata, CollectionMetadata, ItemMetadata, MAX_ALIAS_BYTES, MAX_LABEL_BYTES,
    MAX_METADATA_BYTES, MAX_SECRET_BYTES, SecretBytes, validate_alias_name, validate_attributes,
    validate_content_type, validate_label,
};
pub use target::{CREDENTIAL_PREFIX, TargetName, TargetParseError};
pub use vault::{CommitStep, GenerationCommit, RecoveryAction, RecoveryInventory, plan_recovery};
