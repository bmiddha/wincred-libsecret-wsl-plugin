use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{Child, ChildStdin, Command},
    sync::{Mutex, oneshot},
    time::timeout,
};
use tracing::{debug, warn};
use wincred_libsecret_protocol::{
    AliasMetadata, BrokerError, Capability, CapabilitySet, CollectionMetadata, Envelope, ErrorCode,
    Hello, HelloAck, ItemMetadata, Operation, PROTOCOL_VERSION, Request, Response, ResponseBody,
    SecretBytes, VersionRange, read_frame, write_frame,
};

use crate::error::{ProviderError, Result};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[async_trait]
pub trait BrokerClient: Send + Sync {
    async fn call(&self, operation: Operation) -> Result<ResponseBody>;
}

/// Persistent broker child using only framed CBOR on stdout/stdin.
pub struct ProcessBroker {
    program: PathBuf,
    timeout: Duration,
    running: Mutex<Option<Arc<RunningBroker>>>,
}

struct RunningBroker {
    writer: Mutex<ChildStdin>,
    child: Mutex<Child>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Result<ResponseBody>>>>,
    requests: AtomicU64,
}

impl ProcessBroker {
    #[must_use]
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            timeout: REQUEST_TIMEOUT,
            running: Mutex::new(None),
        }
    }

    async fn running(&self) -> Result<Arc<RunningBroker>> {
        let mut guard = self.running.lock().await;
        if let Some(running) = &*guard {
            return Ok(Arc::clone(running));
        }
        let running = self.start().await?;
        *guard = Some(Arc::clone(&running));
        Ok(running)
    }

    async fn start(&self) -> Result<Arc<RunningBroker>> {
        let mut child = Command::new(&self.program)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|_| ProviderError::Transport)?;
        let mut stdin = child.stdin.take().ok_or(ProviderError::Transport)?;
        let mut stdout = child.stdout.take().ok_or(ProviderError::Transport)?;
        let stderr = child.stderr.take().ok_or(ProviderError::Transport)?;

        let hello = Envelope::current(Hello {
            versions: VersionRange::current(),
            capabilities: [
                Capability::BinarySecrets,
                Capability::Collections,
                Capability::Aliases,
                Capability::GenerationCommits,
                Capability::Reconciliation,
                Capability::AtomicItemMutations,
            ]
            .into_iter()
            .collect::<CapabilitySet>(),
        });
        timeout(self.timeout, write_frame(&mut stdin, &hello))
            .await
            .map_err(|_| ProviderError::Timeout)??;
        let acknowledgement: Envelope<HelloAck> = timeout(self.timeout, read_frame(&mut stdout))
            .await
            .map_err(|_| ProviderError::Timeout)??;
        acknowledgement.validate_version()?;
        if acknowledgement.payload.version != PROTOCOL_VERSION {
            return Err(ProviderError::Transport);
        }

        if !acknowledgement
            .payload
            .capabilities
            .contains(&Capability::AtomicItemMutations)
        {
            return Err(ProviderError::Transport);
        }

        let running = Arc::new(RunningBroker {
            writer: Mutex::new(stdin),
            child: Mutex::new(child),
            pending: Mutex::new(HashMap::new()),
            requests: AtomicU64::new(1),
        });
        Self::spawn_reader(&running, stdout, stderr);
        Ok(running)
    }

    fn spawn_reader(
        running: &Arc<RunningBroker>,
        mut stdout: tokio::process::ChildStdout,
        stderr: tokio::process::ChildStderr,
    ) {
        let reader = Arc::clone(running);
        tokio::spawn(async move {
            loop {
                let response: std::result::Result<Envelope<Response>, _> =
                    read_frame(&mut stdout).await;
                match response {
                    Ok(envelope) if envelope.validate_version().is_ok() => {
                        let response = envelope.payload;
                        if let Some(sender) =
                            reader.pending.lock().await.remove(&response.request_id)
                        {
                            let result = response.result.map_err(ProviderError::Broker);
                            let _ = sender.send(result);
                        }
                    }
                    Ok(_) => break,
                    Err(error) => {
                        debug!(error = %error, "broker protocol reader stopped");
                        break;
                    }
                }
            }
            let mut pending = reader.pending.lock().await;
            for (_, sender) in pending.drain() {
                let _ = sender.send(Err(ProviderError::Transport));
            }
        });
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                // Broker stderr can be influenced by a Windows error. Do not
                // forward it to journald, where it could disclose secret data.
                warn!(bytes = line.len(), "broker emitted redacted stderr");
            }
        });
    }

    async fn request_once(&self, operation: Operation) -> Result<ResponseBody> {
        let running = self.running().await?;
        let request_id = running.requests.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = oneshot::channel();
        running.pending.lock().await.insert(request_id, sender);
        let envelope = Envelope::current(Request {
            request_id,
            operation,
        });
        let write_result = {
            let mut writer = running.writer.lock().await;
            timeout(self.timeout, write_frame(&mut *writer, &envelope)).await
        };
        match write_result {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                running.pending.lock().await.remove(&request_id);
                return Err(ProviderError::Transport);
            }
            Err(_) => {
                running.pending.lock().await.remove(&request_id);
                return Err(ProviderError::Timeout);
            }
        }
        timeout(self.timeout, receiver)
            .await
            .map_err(|_| ProviderError::Timeout)?
            .map_err(|_| ProviderError::Transport)?
    }

    async fn restart(&self) {
        let old = self.running.lock().await.take();
        if let Some(old) = old {
            let _ = old.child.lock().await.kill().await;
            let mut pending = old.pending.lock().await;
            for (_, sender) in pending.drain() {
                let _ = sender.send(Err(ProviderError::Transport));
            }
        }
    }

    pub async fn shutdown(&self) {
        self.restart().await;
    }
}

fn retry_safe(operation: &Operation) -> bool {
    matches!(
        operation,
        Operation::Ping
            | Operation::ListCollections
            | Operation::GetCollection { .. }
            | Operation::ListAliases
            | Operation::ResolveAlias { .. }
            | Operation::SearchItems { .. }
            | Operation::ListItems { .. }
            | Operation::GetItem { .. }
    )
}

#[async_trait]
impl BrokerClient for ProcessBroker {
    async fn call(&self, operation: Operation) -> Result<ResponseBody> {
        let first = self.request_once(operation.clone()).await;
        if matches!(
            first,
            Err(ProviderError::Transport | ProviderError::Timeout)
        ) {
            self.restart().await;
            if retry_safe(&operation) {
                return self.request_once(operation).await;
            }
            return Err(ProviderError::Indeterminate);
        }
        first
    }
}

/// Deterministic test double that implements the complete protocol operation
/// surface without a Windows process.
#[derive(Default)]
pub struct InMemoryBroker {
    state: Mutex<MemoryState>,
}

#[derive(Default)]
struct MemoryState {
    collections: BTreeMap<uuid::Uuid, CollectionMetadata>,
    items: BTreeMap<uuid::Uuid, (ItemMetadata, SecretBytes)>,
    aliases: BTreeMap<String, AliasMetadata>,
}

impl InMemoryBroker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn not_found(message: impl Into<String>) -> ProviderError {
        ProviderError::Broker(BrokerError::new(ErrorCode::NotFound, message))
    }
}

#[allow(clippy::too_many_lines)]
#[async_trait]
impl BrokerClient for InMemoryBroker {
    async fn call(&self, operation: Operation) -> Result<ResponseBody> {
        let mut state = self.state.lock().await;
        match operation {
            Operation::Ping => Ok(ResponseBody::Pong),
            Operation::ListCollections => Ok(ResponseBody::Collections(
                state.collections.values().cloned().collect(),
            )),
            Operation::GetCollection { collection_id } => state
                .collections
                .get(&collection_id)
                .cloned()
                .map(ResponseBody::Collection)
                .ok_or_else(|| Self::not_found("collection not found")),
            Operation::CreateCollection { collection } => {
                if state.collections.contains_key(&collection.id) {
                    return Err(ProviderError::Broker(BrokerError::new(
                        ErrorCode::AlreadyExists,
                        "collection already exists",
                    )));
                }
                state.collections.insert(collection.id, collection.clone());
                Ok(ResponseBody::Collection(collection))
            }
            Operation::UpdateCollection { collection } => {
                if !state.collections.contains_key(&collection.id) {
                    return Err(Self::not_found("collection not found"));
                }
                state.collections.insert(collection.id, collection.clone());
                Ok(ResponseBody::Collection(collection))
            }
            Operation::DeleteCollection { collection_id } => {
                if state.collections.remove(&collection_id).is_none() {
                    return Err(Self::not_found("collection not found"));
                }
                state
                    .items
                    .retain(|_, (item, _)| item.collection_id != collection_id);
                state
                    .aliases
                    .retain(|_, alias| alias.collection_id != collection_id);
                Ok(ResponseBody::Empty)
            }
            Operation::ListAliases => Ok(ResponseBody::Aliases(
                state.aliases.values().cloned().collect(),
            )),
            Operation::ResolveAlias { name } => {
                Ok(ResponseBody::Alias(state.aliases.get(&name).cloned()))
            }
            Operation::SetAlias { alias } => {
                if !state.collections.contains_key(&alias.collection_id) {
                    return Err(Self::not_found("collection not found"));
                }
                state.aliases.insert(alias.name.clone(), alias.clone());
                Ok(ResponseBody::Alias(Some(alias)))
            }
            Operation::RemoveAlias { name } => {
                state.aliases.remove(&name);
                Ok(ResponseBody::Empty)
            }
            Operation::SearchItems { attributes } => Ok(ResponseBody::Items(
                state
                    .items
                    .values()
                    .filter(|(item, _)| {
                        attributes
                            .iter()
                            .all(|(key, value)| item.attributes.get(key) == Some(value))
                    })
                    .map(|(item, _)| item.clone())
                    .collect(),
            )),
            Operation::ListItems { collection_id } => {
                if !state.collections.contains_key(&collection_id) {
                    return Err(Self::not_found("collection not found"));
                }
                Ok(ResponseBody::Items(
                    state
                        .items
                        .values()
                        .filter(|(item, _)| item.collection_id == collection_id)
                        .map(|(item, _)| item.clone())
                        .collect(),
                ))
            }
            Operation::GetItem {
                item_id,
                include_secret,
            } => state
                .items
                .get(&item_id)
                .map(|(item, secret)| ResponseBody::Item {
                    item: item.clone(),
                    secret: include_secret.then(|| secret.clone()),
                })
                .ok_or_else(|| Self::not_found("item not found")),
            Operation::CreateItem { item, secret } => {
                if !state.collections.contains_key(&item.collection_id) {
                    return Err(Self::not_found("collection not found"));
                }
                if state.items.contains_key(&item.id) {
                    return Err(ProviderError::Broker(BrokerError::new(
                        ErrorCode::AlreadyExists,
                        "item already exists",
                    )));
                }
                state.items.insert(item.id, (item.clone(), secret));
                Ok(ResponseBody::Item { item, secret: None })
            }
            Operation::CreateOrReplaceItem {
                item,
                secret,
                replace,
            } => {
                if !state.collections.contains_key(&item.collection_id) {
                    return Err(Self::not_found("collection not found"));
                }
                if state.items.contains_key(&item.id) {
                    return Err(ProviderError::Broker(BrokerError::new(
                        ErrorCode::AlreadyExists,
                        "item already exists",
                    )));
                }
                let replaced_item_ids = if replace {
                    state
                        .items
                        .values()
                        .filter(|(existing, _)| {
                            existing.collection_id == item.collection_id
                                && existing.attributes == item.attributes
                        })
                        .map(|(existing, _)| existing.id)
                        .collect::<Vec<_>>()
                } else {
                    Vec::new()
                };
                state.items.insert(item.id, (item.clone(), secret));
                for replaced in &replaced_item_ids {
                    state.items.remove(replaced);
                }
                Ok(ResponseBody::ReplacedItem {
                    item,
                    replaced_item_ids,
                    cleanup_failed_item_ids: Vec::new(),
                })
            }
            Operation::UpdateItem { item, secret } => {
                let stored = state
                    .items
                    .get_mut(&item.id)
                    .ok_or_else(|| Self::not_found("item not found"))?;
                stored.0 = item.clone();
                if let Some(secret) = secret {
                    stored.1 = secret;
                }
                Ok(ResponseBody::Item { item, secret: None })
            }
            Operation::UpdateItemCas {
                item,
                secret,
                expected_modified,
            } => {
                let stored = state
                    .items
                    .get_mut(&item.id)
                    .ok_or_else(|| Self::not_found("item not found"))?;
                if stored.0.modified != expected_modified {
                    return Err(ProviderError::Broker(BrokerError::new(
                        ErrorCode::Conflict,
                        "item was modified by another provider",
                    )));
                }
                let mut item = item;
                item.modified = item.modified.max(stored.0.modified.saturating_add(1));
                stored.0 = item.clone();
                if let Some(secret) = secret {
                    stored.1 = secret;
                }
                Ok(ResponseBody::Item { item, secret: None })
            }
            Operation::DeleteItem { item_id } => state
                .items
                .remove(&item_id)
                .map(|_| ResponseBody::Empty)
                .ok_or_else(|| Self::not_found("item not found")),
            Operation::Reconcile => Ok(ResponseBody::Reconciled {
                removed_generations: 0,
                corrupt_items: Vec::new(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use futures_util::future::join_all;
    use uuid::Uuid;
    use wincred_libsecret_protocol::{CollectionMetadata, ItemMetadata};

    use super::*;

    fn collection() -> CollectionMetadata {
        CollectionMetadata {
            schema_version: 1,
            id: Uuid::new_v4(),
            label: "Unicode \u{1f512}".to_owned(),
            created: 1,
            modified: 1,
        }
    }

    #[tokio::test]
    async fn memory_broker_searches_attribute_subsets_and_keeps_binary_secret() {
        let broker = InMemoryBroker::new();
        let collection = collection();
        broker
            .call(Operation::CreateCollection {
                collection: collection.clone(),
            })
            .await
            .unwrap();
        let item = ItemMetadata {
            schema_version: 1,
            id: Uuid::new_v4(),
            collection_id: collection.id,
            label: "label".to_owned(),
            attributes: BTreeMap::from([
                ("service".to_owned(), "example.test".to_owned()),
                ("user".to_owned(), "ålice".to_owned()),
            ]),
            content_type: "application/octet-stream".to_owned(),
            created: 1,
            modified: 1,
            current_generation: Uuid::new_v4(),
        };
        broker
            .call(Operation::CreateItem {
                item: item.clone(),
                secret: SecretBytes::new(vec![0, 255, 0, 128]).unwrap(),
            })
            .await
            .unwrap();
        let ResponseBody::Items(found) = broker
            .call(Operation::SearchItems {
                attributes: BTreeMap::from([("service".to_owned(), "example.test".to_owned())]),
            })
            .await
            .unwrap()
        else {
            panic!("unexpected response");
        };
        assert_eq!(found, vec![item.clone()]);
        let ResponseBody::Item {
            secret: Some(secret),
            ..
        } = broker
            .call(Operation::GetItem {
                item_id: item.id,
                include_secret: true,
            })
            .await
            .unwrap()
        else {
            panic!("unexpected response");
        };
        assert_eq!(secret.expose(), &[0, 255, 0, 128]);
    }

    #[tokio::test]
    async fn memory_broker_serializes_concurrent_requests_safely() {
        let broker = Arc::new(InMemoryBroker::new());
        let requests = (0..32).map(|index| {
            let broker = Arc::clone(&broker);
            async move {
                let collection = CollectionMetadata {
                    schema_version: 1,
                    id: Uuid::new_v4(),
                    label: format!("collection-{index}"),
                    created: 1,
                    modified: 1,
                };
                broker
                    .call(Operation::CreateCollection { collection })
                    .await
            }
        });
        assert!(
            join_all(requests)
                .await
                .into_iter()
                .all(|result| result.is_ok())
        );
        let ResponseBody::Collections(collections) =
            broker.call(Operation::ListCollections).await.unwrap()
        else {
            panic!("unexpected response");
        };
        assert_eq!(collections.len(), 32);
    }

    #[test]
    fn commit_before_timeout_mutations_are_never_replayed() {
        let collection = collection();
        assert!(!retry_safe(&Operation::CreateCollection { collection }));
        assert!(!retry_safe(&Operation::DeleteItem {
            item_id: Uuid::new_v4()
        }));
        assert!(!retry_safe(&Operation::CreateOrReplaceItem {
            item: ItemMetadata {
                schema_version: 1,
                id: Uuid::new_v4(),
                collection_id: Uuid::new_v4(),
                label: "mutation".to_owned(),
                attributes: BTreeMap::new(),
                content_type: "text/plain".to_owned(),
                created: 0,
                modified: 0,
                current_generation: Uuid::new_v4(),
            },
            secret: SecretBytes::new(b"secret".to_vec()).unwrap(),
            replace: true,
        }));
        assert!(retry_safe(&Operation::ListCollections));
    }
}
