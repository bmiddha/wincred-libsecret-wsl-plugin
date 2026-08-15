//! Storage and request handling for the Windows Credential Manager broker.

mod backend;
mod service;

#[cfg(windows)]
mod wincred;

pub use backend::{InMemoryBackend, VaultBackend};
pub use service::Broker;
#[cfg(windows)]
pub use wincred::WinCredBackend;
