//! Linux implementation of the freedesktop.org Secret Service API.
//!
//! The D-Bus layer is deliberately thin: all persistent state is held by the
//! Windows broker and the provider can therefore be exercised with an in-memory
//! broker in unit tests.

pub mod broker;
pub mod crypto;
pub mod error;
pub mod paths;
pub mod service;

pub use broker::{BrokerClient, InMemoryBroker, ProcessBroker};
pub use error::{ProviderError, Result};
pub use service::Provider;
