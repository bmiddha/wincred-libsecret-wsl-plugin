use std::{
    collections::BTreeMap,
    str::FromStr,
    sync::{Arc, Condvar, Mutex},
};

use wincred_libsecret_protocol::{BrokerError, ErrorCode, TargetName};
use zeroize::Zeroize;

/// A guard which serializes one logical vault operation.
pub trait VaultLock {}

/// The storage operations required by the broker.
///
/// Implementations must only be used with project-owned [`TargetName`] values.  The broker
/// validates all names discovered by enumeration before asking an implementation to mutate them.
pub trait VaultBackend {
    /// Acquires the backend's cross-process (where applicable) operation lock.
    fn acquire_lock(&self) -> Result<Box<dyn VaultLock>, BrokerError>;
    /// Reads the raw credential blob for an owned target.
    fn read(&self, target: &TargetName) -> Result<Option<Vec<u8>>, BrokerError>;
    /// Writes a raw credential blob for an owned target.
    fn write(&self, target: &TargetName, blob: &[u8]) -> Result<(), BrokerError>;
    /// Deletes an owned target. Missing targets are treated as already deleted.
    fn delete(&self, target: &TargetName) -> Result<(), BrokerError>;
    /// Enumerates credentials matching the project prefix only.
    fn enumerate(&self) -> Result<Vec<(String, Vec<u8>)>, BrokerError>;
}

#[derive(Default)]
struct MemoryData {
    credentials: Mutex<BTreeMap<String, Vec<u8>>>,
    locked: Mutex<bool>,
    available: Condvar,
}

/// An in-memory backend used by cross-platform unit tests.
#[derive(Clone, Default)]
pub struct InMemoryBackend {
    data: Arc<MemoryData>,
}

impl InMemoryBackend {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a raw target for corruption and namespace tests.
    pub fn insert_raw(&self, target: String, blob: Vec<u8>) {
        if let Ok(mut credentials) = self.data.credentials.lock() {
            credentials.insert(target, blob);
        }
    }
}

struct MemoryLock {
    data: Arc<MemoryData>,
}

impl VaultLock for MemoryLock {}

impl Drop for MemoryLock {
    fn drop(&mut self) {
        if let Ok(mut locked) = self.data.locked.lock() {
            *locked = false;
            self.data.available.notify_one();
        }
    }
}

impl VaultBackend for InMemoryBackend {
    fn acquire_lock(&self) -> Result<Box<dyn VaultLock>, BrokerError> {
        let mut locked = self
            .data
            .locked
            .lock()
            .map_err(|_| internal_error("memory operation lock is poisoned"))?;
        while *locked {
            locked = self
                .data
                .available
                .wait(locked)
                .map_err(|_| internal_error("memory operation lock is poisoned"))?;
        }
        *locked = true;
        Ok(Box::new(MemoryLock {
            data: Arc::clone(&self.data),
        }))
    }

    fn read(&self, target: &TargetName) -> Result<Option<Vec<u8>>, BrokerError> {
        let credentials = self
            .data
            .credentials
            .lock()
            .map_err(|_| internal_error("memory credential store is poisoned"))?;
        Ok(credentials.get(&target.to_string()).cloned())
    }

    fn write(&self, target: &TargetName, blob: &[u8]) -> Result<(), BrokerError> {
        let mut credentials = self
            .data
            .credentials
            .lock()
            .map_err(|_| internal_error("memory credential store is poisoned"))?;
        credentials.insert(target.to_string(), blob.to_vec());
        Ok(())
    }

    fn delete(&self, target: &TargetName) -> Result<(), BrokerError> {
        let mut credentials = self
            .data
            .credentials
            .lock()
            .map_err(|_| internal_error("memory credential store is poisoned"))?;
        if let Some(mut value) = credentials.remove(&target.to_string()) {
            value.zeroize();
        }
        Ok(())
    }

    fn enumerate(&self) -> Result<Vec<(String, Vec<u8>)>, BrokerError> {
        let credentials = self
            .data
            .credentials
            .lock()
            .map_err(|_| internal_error("memory credential store is poisoned"))?;
        Ok(credentials
            .iter()
            .filter(|(target, _)| target.starts_with(wincred_libsecret_protocol::CREDENTIAL_PREFIX))
            .map(|(target, blob)| {
                let blob = if matches!(
                    TargetName::from_str(target),
                    Ok(TargetName::ItemSecret { .. })
                ) {
                    Vec::new()
                } else {
                    blob.clone()
                };
                (target.clone(), blob)
            })
            .collect())
    }
}

pub(crate) fn internal_error(message: &'static str) -> BrokerError {
    BrokerError::new(ErrorCode::Internal, message)
}
