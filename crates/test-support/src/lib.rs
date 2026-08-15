//! Shared test support.

/// Returns the protocol version used by test fixtures.
#[must_use]
pub const fn protocol_version() -> u16 {
    wincred_libsecret_protocol::PROTOCOL_VERSION
}
