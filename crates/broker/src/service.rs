use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};

use ciborium::{de::from_reader, ser::into_writer};
use serde::{Serialize, de::DeserializeOwned};
use tracing::warn;
use uuid::Uuid;
use wincred_libsecret_protocol::{
    AliasMetadata, BrokerError, CollectionMetadata, ErrorCode, GenerationCommit, ItemMetadata,
    MAX_METADATA_BYTES, Operation, RecoveryAction, RecoveryInventory, ResponseBody, SecretBytes,
    TargetName, validate_alias_name as validate_protocol_alias_name, validate_attributes,
    validate_content_type, validate_label,
};
use zeroize::{Zeroize, Zeroizing};

use crate::VaultBackend;

const METADATA_SCHEMA_VERSION: u16 = 1;

/// Executes protocol operations against a credential vault.
pub struct Broker<B> {
    backend: B,
}

impl<B: VaultBackend> Broker<B> {
    #[must_use]
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    /// Executes one request while holding the backend's operation lock.
    pub fn execute(&self, operation: Operation) -> Result<ResponseBody, BrokerError> {
        let _lock = self.backend.acquire_lock()?;
        match operation {
            Operation::Ping => Ok(ResponseBody::Pong),
            Operation::ListCollections => self.list_collections(),
            Operation::GetCollection { collection_id } => Ok(ResponseBody::Collection(
                self.get_collection(collection_id)?,
            )),
            Operation::CreateCollection { collection } => self.create_collection(collection),
            Operation::UpdateCollection { collection } => self.update_collection(collection),
            Operation::DeleteCollection { collection_id } => self.delete_collection(collection_id),
            Operation::ListAliases => self.list_aliases(),
            Operation::ResolveAlias { name } => self.resolve_alias(&name),
            Operation::SetAlias { alias } => self.set_alias(alias),
            Operation::RemoveAlias { name } => self.remove_alias(&name),
            Operation::SearchItems { attributes } => self.search_items(&attributes),
            Operation::ListItems { collection_id } => self.list_items(collection_id),
            Operation::GetItem {
                item_id,
                include_secret,
            } => self.get_item(item_id, include_secret),
            Operation::CreateItem { item, secret } => self.create_item(item, secret),
            Operation::CreateOrReplaceItem {
                item,
                secret,
                replace,
            } => self.create_or_replace_item(item, secret, replace),
            Operation::UpdateItem { item, secret } => self.update_item(item, secret),
            Operation::UpdateItemCas {
                item,
                secret,
                expected_modified,
            } => self.update_item_cas(item, secret, expected_modified),
            Operation::DeleteItem { item_id } => self.delete_item(item_id),
            Operation::Reconcile => self.reconcile_locked(),
        }
    }

    /// Performs recovery after process startup. It is safe to call repeatedly.
    pub fn reconcile(&self) -> Result<ResponseBody, BrokerError> {
        let _lock = self.backend.acquire_lock()?;
        self.reconcile_locked()
    }

    fn list_collections(&self) -> Result<ResponseBody, BrokerError> {
        let mut collections = Vec::new();
        for entry in self.entries()? {
            if let EntryKind::Collection(id) = entry.kind {
                match decode_metadata::<CollectionMetadata>(&entry.blob) {
                    Ok(collection)
                        if collection.id == id && validate_collection(&collection).is_ok() =>
                    {
                        collections.push(collection);
                    }
                    _ => warn!(
                        event = "corrupt_collection_metadata",
                        "ignored corrupt collection metadata"
                    ),
                }
            }
        }
        collections.sort_by_key(|collection| collection.id);
        Ok(ResponseBody::Collections(collections))
    }

    fn get_collection(&self, id: Uuid) -> Result<CollectionMetadata, BrokerError> {
        let target = TargetName::Collection(id);
        let blob = self
            .backend
            .read(&target)?
            .ok_or_else(|| not_found("collection does not exist"))?;
        let collection: CollectionMetadata = decode_metadata(&blob)?;
        if collection.id != id {
            return Err(corrupt_state(
                "collection metadata identity does not match target",
            ));
        }
        validate_collection(&collection)?;
        Ok(collection)
    }

    fn create_collection(
        &self,
        collection: CollectionMetadata,
    ) -> Result<ResponseBody, BrokerError> {
        validate_collection(&collection)?;
        let target = TargetName::Collection(collection.id);
        if self.backend.read(&target)?.is_some() {
            return Err(already_exists("collection already exists"));
        }
        self.write_metadata(&target, &collection)?;
        Ok(ResponseBody::Collection(collection))
    }

    fn update_collection(
        &self,
        mut collection: CollectionMetadata,
    ) -> Result<ResponseBody, BrokerError> {
        let existing = self.get_collection(collection.id)?;
        validate_collection(&collection)?;
        collection.created = existing.created;
        self.write_metadata(&TargetName::Collection(collection.id), &collection)?;
        Ok(ResponseBody::Collection(collection))
    }

    fn delete_collection(&self, collection_id: Uuid) -> Result<ResponseBody, BrokerError> {
        self.get_collection(collection_id)?;
        let entries = self.entries()?;

        let item_ids: BTreeSet<Uuid> = entries
            .iter()
            .filter_map(|entry| match entry.kind {
                EntryKind::ItemMetadata(id) => decode_metadata::<ItemMetadata>(&entry.blob)
                    .ok()
                    .filter(|item| {
                        item.id == id
                            && validate_item(item).is_ok()
                            && item.collection_id == collection_id
                    })
                    .map(|item| item.id),
                _ => None,
            })
            .collect();
        let aliases: Vec<String> = entries
            .iter()
            .filter_map(|entry| match &entry.kind {
                EntryKind::Alias(name) => decode_metadata::<AliasMetadata>(&entry.blob)
                    .ok()
                    .filter(|alias| {
                        alias.name == *name
                            && validate_alias(alias).is_ok()
                            && alias.collection_id == collection_id
                    })
                    .map(|alias| alias.name),
                _ => None,
            })
            .collect();

        for item_id in item_ids {
            self.delete_item_from_entries(item_id, &entries)?;
        }
        for name in aliases {
            self.backend.delete(&TargetName::Alias(name))?;
        }
        self.backend
            .delete(&TargetName::Collection(collection_id))?;
        Ok(ResponseBody::Empty)
    }

    fn resolve_alias(&self, name: &str) -> Result<ResponseBody, BrokerError> {
        validate_alias_name(name)?;
        let target = TargetName::Alias(name.to_owned());
        let Some(blob) = self.backend.read(&target)? else {
            return Ok(ResponseBody::Alias(None));
        };
        let alias: AliasMetadata = decode_metadata(&blob)?;
        if alias.name != name {
            return Err(corrupt_state(
                "alias metadata identity does not match target",
            ));
        }
        validate_alias(&alias)?;
        if self.get_collection(alias.collection_id).is_err() {
            return Err(corrupt_state("alias references a missing collection"));
        }
        Ok(ResponseBody::Alias(Some(alias)))
    }

    fn list_aliases(&self) -> Result<ResponseBody, BrokerError> {
        let mut aliases = Vec::new();
        for entry in self.entries()? {
            if let EntryKind::Alias(name) = entry.kind {
                match decode_metadata::<AliasMetadata>(&entry.blob) {
                    Ok(alias)
                        if alias.name == name
                            && validate_alias(&alias).is_ok()
                            && self.get_collection(alias.collection_id).is_ok() =>
                    {
                        aliases.push(alias);
                    }
                    _ => {
                        warn!(
                            event = "corrupt_alias_metadata",
                            "ignored corrupt alias metadata"
                        );
                    }
                }
            }
        }
        aliases.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(ResponseBody::Aliases(aliases))
    }

    fn set_alias(&self, alias: AliasMetadata) -> Result<ResponseBody, BrokerError> {
        validate_alias(&alias)?;
        self.require_collection(alias.collection_id)?;
        self.write_metadata(&TargetName::Alias(alias.name.clone()), &alias)?;
        Ok(ResponseBody::Alias(Some(alias)))
    }

    fn remove_alias(&self, name: &str) -> Result<ResponseBody, BrokerError> {
        validate_alias_name(name)?;
        let target = TargetName::Alias(name.to_owned());
        if self.backend.read(&target)?.is_none() {
            return Err(not_found("alias does not exist"));
        }
        self.backend.delete(&target)?;
        Ok(ResponseBody::Empty)
    }

    fn search_items(
        &self,
        attributes: &BTreeMap<String, String>,
    ) -> Result<ResponseBody, BrokerError> {
        validate_attributes(attributes).map_err(|error| invalid_request(&error))?;
        let mut items = self.valid_items()?;
        items.retain(|item| {
            attributes
                .iter()
                .all(|(key, value)| item.attributes.get(key) == Some(value))
        });
        Ok(ResponseBody::Items(items))
    }

    fn list_items(&self, collection_id: Uuid) -> Result<ResponseBody, BrokerError> {
        self.get_collection(collection_id)?;
        let items = self
            .valid_items()?
            .into_iter()
            .filter(|item| item.collection_id == collection_id)
            .collect();
        Ok(ResponseBody::Items(items))
    }

    fn get_item(&self, id: Uuid, include_secret: bool) -> Result<ResponseBody, BrokerError> {
        let item = self.get_item_metadata(id)?;
        let secret = if include_secret {
            let target = TargetName::ItemSecret {
                item_id: id,
                generation: item.current_generation,
            };
            let blob = self
                .backend
                .read(&target)?
                .ok_or_else(|| corrupt_state("item metadata references a missing secret"))?;
            Some(SecretBytes::new(blob).map_err(|error| invalid_request(&error))?)
        } else {
            None
        };
        Ok(ResponseBody::Item { item, secret })
    }

    fn create_item(
        &self,
        item: ItemMetadata,
        secret: SecretBytes,
    ) -> Result<ResponseBody, BrokerError> {
        validate_item(&item)?;
        self.require_collection(item.collection_id)?;
        let metadata_target = TargetName::ItemMetadata(item.id);
        if self.backend.read(&metadata_target)?.is_some() {
            return Err(already_exists("item already exists"));
        }
        self.commit_new_generation(&item, None, secret)?;
        Ok(ResponseBody::Item { item, secret: None })
    }

    fn create_or_replace_item(
        &self,
        item: ItemMetadata,
        secret: SecretBytes,
        replace: bool,
    ) -> Result<ResponseBody, BrokerError> {
        validate_item(&item)?;
        self.require_collection(item.collection_id)?;
        let metadata_target = TargetName::ItemMetadata(item.id);
        if self.backend.read(&metadata_target)?.is_some() {
            return Err(already_exists("item already exists"));
        }

        let replaced_item_ids = if replace {
            self.valid_items()?
                .into_iter()
                .filter(|existing| {
                    existing.collection_id == item.collection_id
                        && existing.attributes == item.attributes
                })
                .map(|existing| existing.id)
                .collect()
        } else {
            Vec::new()
        };
        // The visibility commit of the new item happens before any replacement
        // is removed. Validation or writes can therefore never destroy an
        // existing secret. A failed cleanup leaves duplicate data for recovery,
        // not data loss.
        self.commit_new_generation(&item, None, secret)?;
        let entries = self.entries()?;
        let mut deleted_item_ids = Vec::new();
        let mut cleanup_failed_item_ids = Vec::new();
        for replaced in replaced_item_ids {
            if let Err(error) = self.delete_replaced_item(replaced, &entries) {
                // The new item is already committed. Do not turn an old
                // cleanup failure into a failed replacement that callers
                // might retry; recovery removes the orphaned credentials.
                warn!(event = "replace_cleanup_deferred", code = ?error.code, "replacement cleanup deferred");
                cleanup_failed_item_ids.push(replaced);
            } else {
                deleted_item_ids.push(replaced);
            }
        }
        Ok(ResponseBody::ReplacedItem {
            item,
            replaced_item_ids: deleted_item_ids,
            cleanup_failed_item_ids,
        })
    }

    fn delete_replaced_item(&self, id: Uuid, entries: &[Entry]) -> Result<(), BrokerError> {
        self.backend.delete(&TargetName::ItemMetadata(id))?;
        for entry in entries {
            if let EntryKind::ItemSecret {
                item_id,
                generation,
            } = entry.kind
                && item_id == id
                && let Err(error) = self.backend.delete(&TargetName::ItemSecret {
                    item_id,
                    generation,
                })
            {
                // Metadata deletion makes the replacement visible. Secret
                // cleanup is deliberately deferred rather than reporting a
                // false failed replacement after the new item committed.
                warn!(event = "replace_secret_cleanup_deferred", code = ?error.code, "replacement secret cleanup deferred");
            }
        }
        Ok(())
    }

    fn update_item(
        &self,
        mut item: ItemMetadata,
        secret: Option<SecretBytes>,
    ) -> Result<ResponseBody, BrokerError> {
        let existing = self.get_item_metadata(item.id)?;
        validate_item(&item)?;
        self.require_collection(item.collection_id)?;
        item.created = existing.created;
        item.modified = item.modified.max(existing.modified.saturating_add(1));

        if let Some(secret) = secret {
            if item.current_generation == existing.current_generation {
                return Err(BrokerError::new(
                    ErrorCode::Conflict,
                    "item update with a secret requires a new generation",
                ));
            }
            self.commit_new_generation(&item, Some(existing.current_generation), secret)?;
        } else {
            item.current_generation = existing.current_generation;
            self.write_metadata(&TargetName::ItemMetadata(item.id), &item)?;
        }

        Ok(ResponseBody::Item { item, secret: None })
    }

    fn update_item_cas(
        &self,
        item: ItemMetadata,
        secret: Option<SecretBytes>,
        expected_modified: u64,
    ) -> Result<ResponseBody, BrokerError> {
        let existing = self.get_item_metadata(item.id)?;
        if existing.modified != expected_modified {
            return Err(BrokerError::new(
                ErrorCode::Conflict,
                "item was modified by another provider",
            ));
        }
        self.update_item(item, secret)
    }

    fn delete_item(&self, id: Uuid) -> Result<ResponseBody, BrokerError> {
        self.get_item_metadata(id)?;
        self.delete_item_from_entries(id, &self.entries()?)?;
        Ok(ResponseBody::Empty)
    }

    fn delete_item_from_entries(&self, id: Uuid, entries: &[Entry]) -> Result<(), BrokerError> {
        self.backend.delete(&TargetName::ItemMetadata(id))?;
        for entry in entries {
            if let EntryKind::ItemSecret {
                item_id,
                generation,
            } = entry.kind
                && item_id == id
            {
                self.backend.delete(&TargetName::ItemSecret {
                    item_id,
                    generation,
                })?;
            }
        }
        Ok(())
    }

    fn commit_new_generation(
        &self,
        item: &ItemMetadata,
        previous_generation: Option<Uuid>,
        secret: SecretBytes,
    ) -> Result<(), BrokerError> {
        let commit = GenerationCommit {
            item_id: item.id,
            new_generation: item.current_generation,
            previous_generation,
        };
        let secret_target = TargetName::ItemSecret {
            item_id: item.id,
            generation: item.current_generation,
        };
        let metadata_target = TargetName::ItemMetadata(item.id);
        let mut metadata = encode_metadata(item)?;
        let mut secret = secret.into_inner();

        let secret_write = self.backend.write(&secret_target, &secret);
        secret.zeroize();
        secret_write?;
        let metadata_write = self.backend.write(&metadata_target, &metadata);
        metadata.zeroize();
        if let Err(error) = metadata_write {
            let _ = self.backend.delete(&secret_target);
            return Err(error);
        }

        // A failed old-generation delete leaves only an abandoned credential; reconciliation
        // removes it on the next startup without rolling back the committed metadata.
        for step in commit.steps() {
            if let wincred_libsecret_protocol::CommitStep::DeleteSecret(target) = step
                && let Err(error) = self.backend.delete(&target)
            {
                warn!(event = "generation_cleanup_deferred", code = ?error.code, "generation cleanup deferred");
            }
        }
        Ok(())
    }

    fn reconcile_locked(&self) -> Result<ResponseBody, BrokerError> {
        let entries = self.entries()?;
        let mut inventory = RecoveryInventory::default();
        for entry in &entries {
            match entry.kind {
                EntryKind::ItemMetadata(id) => match decode_metadata::<ItemMetadata>(&entry.blob) {
                    Ok(item) if item.id == id && validate_item(&item).is_ok() => {
                        inventory
                            .committed_generations
                            .insert(item.id, item.current_generation);
                    }
                    _ => warn!(
                        event = "corrupt_item_metadata",
                        "ignored corrupt item metadata"
                    ),
                },
                EntryKind::ItemSecret {
                    item_id,
                    generation,
                } => {
                    inventory.stored_generations.insert((item_id, generation));
                }
                _ => {}
            }
        }

        let mut removed_generations = 0;
        let mut corrupt_items = Vec::new();
        for action in wincred_libsecret_protocol::plan_recovery(&inventory) {
            match action {
                RecoveryAction::DeleteAbandonedGeneration {
                    item_id,
                    generation,
                } => {
                    self.backend.delete(&TargetName::ItemSecret {
                        item_id,
                        generation,
                    })?;
                    removed_generations += 1;
                }
                RecoveryAction::ReportMissingCommittedGeneration { item_id, .. } => {
                    corrupt_items.push(item_id);
                }
            }
        }
        Ok(ResponseBody::Reconciled {
            removed_generations,
            corrupt_items,
        })
    }

    fn get_item_metadata(&self, id: Uuid) -> Result<ItemMetadata, BrokerError> {
        let target = TargetName::ItemMetadata(id);
        let blob = self
            .backend
            .read(&target)?
            .ok_or_else(|| not_found("item does not exist"))?;
        let item: ItemMetadata = decode_metadata(&blob)?;
        if item.id != id {
            return Err(corrupt_state(
                "item metadata identity does not match target",
            ));
        }
        validate_item(&item)?;
        Ok(item)
    }

    fn require_collection(&self, id: Uuid) -> Result<CollectionMetadata, BrokerError> {
        self.get_collection(id).map_err(|error| {
            if error.code == ErrorCode::NotFound {
                BrokerError::new(
                    ErrorCode::InvalidCollection,
                    "referenced collection does not exist",
                )
            } else {
                error
            }
        })
    }

    fn valid_items(&self) -> Result<Vec<ItemMetadata>, BrokerError> {
        let mut items = Vec::new();
        for entry in self.entries()? {
            if let EntryKind::ItemMetadata(id) = entry.kind {
                match decode_metadata::<ItemMetadata>(&entry.blob) {
                    Ok(item) if item.id == id && validate_item(&item).is_ok() => items.push(item),
                    _ => warn!(
                        event = "corrupt_item_metadata",
                        "ignored corrupt item metadata"
                    ),
                }
            }
        }
        items.sort_by_key(|item| item.id);
        Ok(items)
    }

    fn write_metadata<T: Serialize>(
        &self,
        target: &TargetName,
        metadata: &T,
    ) -> Result<(), BrokerError> {
        let encoded = encode_metadata(metadata)?;
        self.backend.write(target, &encoded)
    }

    fn entries(&self) -> Result<Vec<Entry>, BrokerError> {
        let mut entries = Vec::new();
        let mut malformed = 0_usize;
        for (name, mut blob) in self.backend.enumerate()? {
            match TargetName::from_str(&name) {
                Ok(TargetName::Collection(id)) => entries.push(Entry {
                    kind: EntryKind::Collection(id),
                    blob: Zeroizing::new(blob),
                }),
                Ok(TargetName::Alias(name)) => entries.push(Entry {
                    kind: EntryKind::Alias(name),
                    blob: Zeroizing::new(blob),
                }),
                Ok(TargetName::ItemMetadata(id)) => entries.push(Entry {
                    kind: EntryKind::ItemMetadata(id),
                    blob: Zeroizing::new(blob),
                }),
                Ok(TargetName::ItemSecret {
                    item_id,
                    generation,
                }) => {
                    // Generation discovery needs only the target name. Never
                    // retain a second plaintext copy while enumerating.
                    blob.zeroize();
                    entries.push(Entry {
                        kind: EntryKind::ItemSecret {
                            item_id,
                            generation,
                        },
                        blob: Zeroizing::new(Vec::new()),
                    });
                }
                Err(_) => {
                    blob.zeroize();
                    malformed += 1;
                }
            }
        }
        if malformed != 0 {
            warn!(
                event = "malformed_project_credentials",
                count = malformed,
                "ignored malformed project credentials"
            );
        }
        Ok(entries)
    }
}

struct Entry {
    kind: EntryKind,
    blob: Zeroizing<Vec<u8>>,
}

enum EntryKind {
    Collection(Uuid),
    Alias(String),
    ItemMetadata(Uuid),
    ItemSecret { item_id: Uuid, generation: Uuid },
}

fn encode_metadata<T: Serialize>(metadata: &T) -> Result<Vec<u8>, BrokerError> {
    let mut encoded = Vec::new();
    into_writer(metadata, &mut encoded)
        .map_err(|_| BrokerError::new(ErrorCode::InvalidRequest, "metadata cannot be encoded"))?;
    if encoded.len() > MAX_METADATA_BYTES {
        encoded.zeroize();
        return Err(BrokerError::new(
            ErrorCode::MetadataTooLarge,
            "metadata exceeds the credential blob limit",
        ));
    }
    Ok(encoded)
}

fn decode_metadata<T: DeserializeOwned>(blob: &[u8]) -> Result<T, BrokerError> {
    if blob.len() > MAX_METADATA_BYTES {
        return Err(corrupt_state("metadata exceeds the credential blob limit"));
    }
    let mut input = blob;
    let decoded = from_reader(&mut input).map_err(|_| corrupt_state("metadata is malformed"))?;
    if !input.is_empty() {
        return Err(corrupt_state("metadata has trailing data"));
    }
    Ok(decoded)
}

fn validate_collection(collection: &CollectionMetadata) -> Result<(), BrokerError> {
    validate_schema_version(collection.schema_version)?;
    if collection.id.is_nil() {
        return Err(BrokerError::new(
            ErrorCode::InvalidRequest,
            "collection identifier cannot be nil",
        ));
    }
    validate_label(&collection.label).map_err(|error| invalid_request(&error))
}

fn validate_item(item: &ItemMetadata) -> Result<(), BrokerError> {
    validate_schema_version(item.schema_version)?;
    if item.id.is_nil() || item.collection_id.is_nil() || item.current_generation.is_nil() {
        return Err(BrokerError::new(
            ErrorCode::InvalidRequest,
            "metadata identifiers cannot be nil",
        ));
    }
    validate_label(&item.label).map_err(|error| invalid_request(&error))?;
    validate_attributes(&item.attributes).map_err(|error| invalid_request(&error))?;
    validate_content_type(&item.content_type).map_err(|error| invalid_request(&error))
}

fn validate_alias(alias: &AliasMetadata) -> Result<(), BrokerError> {
    validate_schema_version(alias.schema_version)?;
    validate_alias_name(&alias.name)?;
    if alias.collection_id.is_nil() {
        return Err(BrokerError::new(
            ErrorCode::InvalidRequest,
            "alias collection identifier cannot be nil",
        ));
    }
    Ok(())
}

fn validate_schema_version(schema_version: u16) -> Result<(), BrokerError> {
    if schema_version == METADATA_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(BrokerError::new(
            ErrorCode::InvalidRequest,
            "metadata schema version is unsupported",
        ))
    }
}

fn validate_alias_name(name: &str) -> Result<(), BrokerError> {
    validate_protocol_alias_name(name)
        .map_err(|_| BrokerError::new(ErrorCode::InvalidRequest, "alias name is invalid"))
}

fn invalid_request(error: &wincred_libsecret_protocol::ProtocolError) -> BrokerError {
    let code = if error.to_string().contains("secret") {
        ErrorCode::SecretTooLarge
    } else {
        ErrorCode::InvalidRequest
    };
    BrokerError::new(code, "request metadata is invalid")
}

fn not_found(message: &'static str) -> BrokerError {
    BrokerError::new(ErrorCode::NotFound, message)
}

fn already_exists(message: &'static str) -> BrokerError {
    BrokerError::new(ErrorCode::AlreadyExists, message)
}

fn corrupt_state(message: &'static str) -> BrokerError {
    BrokerError::new(ErrorCode::CorruptState, message)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        sync::{
            Arc, Barrier,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        thread,
        time::Duration,
    };

    use super::*;
    use crate::{InMemoryBackend, VaultBackend, backend::VaultLock};

    struct FaultBackend {
        inner: InMemoryBackend,
        fail_metadata_write: AtomicBool,
        fail_item_metadata_delete: AtomicBool,
        fail_secret_delete: AtomicBool,
        fail_lock: AtomicBool,
    }

    impl FaultBackend {
        fn new() -> Self {
            Self {
                inner: InMemoryBackend::new(),
                fail_metadata_write: AtomicBool::new(false),
                fail_item_metadata_delete: AtomicBool::new(false),
                fail_secret_delete: AtomicBool::new(false),
                fail_lock: AtomicBool::new(false),
            }
        }
    }

    impl VaultBackend for FaultBackend {
        fn acquire_lock(&self) -> Result<Box<dyn VaultLock>, BrokerError> {
            if self.fail_lock.load(Ordering::SeqCst) {
                return Err(BrokerError::new(ErrorCode::Conflict, "vault is busy"));
            }
            self.inner.acquire_lock()
        }

        fn read(&self, target: &TargetName) -> Result<Option<Vec<u8>>, BrokerError> {
            self.inner.read(target)
        }

        fn write(&self, target: &TargetName, blob: &[u8]) -> Result<(), BrokerError> {
            if matches!(target, TargetName::ItemMetadata(_))
                && self.fail_metadata_write.load(Ordering::SeqCst)
            {
                return Err(BrokerError::new(
                    ErrorCode::BackendUnavailable,
                    "injected metadata failure",
                ));
            }
            self.inner.write(target, blob)
        }

        fn delete(&self, target: &TargetName) -> Result<(), BrokerError> {
            if matches!(target, TargetName::ItemMetadata(_))
                && self.fail_item_metadata_delete.swap(false, Ordering::SeqCst)
            {
                return Err(BrokerError::new(
                    ErrorCode::BackendUnavailable,
                    "injected metadata delete failure",
                ));
            }
            if matches!(target, TargetName::ItemSecret { .. })
                && self.fail_secret_delete.swap(false, Ordering::SeqCst)
            {
                return Err(BrokerError::new(
                    ErrorCode::BackendUnavailable,
                    "injected delete failure",
                ));
            }
            self.inner.delete(target)
        }

        fn enumerate(&self) -> Result<Vec<(String, Vec<u8>)>, BrokerError> {
            self.inner.enumerate()
        }
    }

    fn collection() -> CollectionMetadata {
        CollectionMetadata {
            schema_version: METADATA_SCHEMA_VERSION,
            id: Uuid::new_v4(),
            label: "日本語 collection".to_owned(),
            created: 10,
            modified: 20,
        }
    }

    fn item(collection_id: Uuid) -> ItemMetadata {
        ItemMetadata {
            schema_version: METADATA_SCHEMA_VERSION,
            id: Uuid::new_v4(),
            collection_id,
            label: "binary item".to_owned(),
            attributes: BTreeMap::from([
                ("service".to_owned(), "example.test".to_owned()),
                ("account".to_owned(), "用户".to_owned()),
            ]),
            content_type: "application/octet-stream".to_owned(),
            created: 30,
            modified: 40,
            current_generation: Uuid::new_v4(),
        }
    }

    fn create_collection<B: VaultBackend>(broker: &Broker<B>, collection: CollectionMetadata) {
        assert!(matches!(
            broker
                .execute(Operation::CreateCollection { collection })
                .unwrap(),
            ResponseBody::Collection(_)
        ));
    }

    #[test]
    fn crud_search_and_binary_secret_round_trip() {
        let backend = InMemoryBackend::new();
        let broker = Broker::new(backend);
        let collection = collection();
        create_collection(&broker, collection.clone());
        let item = item(collection.id);
        let secret = SecretBytes::new(vec![0, 255, 1, 0, 254]).unwrap();
        broker
            .execute(Operation::CreateItem {
                item: item.clone(),
                secret: secret.clone(),
            })
            .unwrap();

        assert_eq!(
            broker
                .execute(Operation::SearchItems {
                    attributes: BTreeMap::from([("account".to_owned(), "用户".to_owned())]),
                })
                .unwrap(),
            ResponseBody::Items(vec![item.clone()])
        );
        assert_eq!(
            broker
                .execute(Operation::GetItem {
                    item_id: item.id,
                    include_secret: true,
                })
                .unwrap(),
            ResponseBody::Item {
                item,
                secret: Some(secret)
            }
        );
    }

    #[test]
    fn collection_crud_preserves_created_timestamp() {
        let broker = Broker::new(InMemoryBackend::new());
        let original = collection();
        create_collection(&broker, original.clone());
        assert_eq!(
            broker.execute(Operation::ListCollections).unwrap(),
            ResponseBody::Collections(vec![original.clone()])
        );

        let mut update = original.clone();
        update.label = "updated collection".to_owned();
        update.created = 999;
        update.modified = 21;
        let ResponseBody::Collection(stored) = broker
            .execute(Operation::UpdateCollection {
                collection: update.clone(),
            })
            .unwrap()
        else {
            panic!("expected collection");
        };
        assert_eq!(stored.created, original.created);
        assert_eq!(
            broker
                .execute(Operation::GetCollection {
                    collection_id: original.id,
                })
                .unwrap(),
            ResponseBody::Collection(stored)
        );
        assert_eq!(
            broker
                .execute(Operation::DeleteCollection {
                    collection_id: original.id,
                })
                .unwrap(),
            ResponseBody::Empty
        );
    }

    #[test]
    fn item_listing_and_direct_deletion_work() {
        let broker = Broker::new(InMemoryBackend::new());
        let collection = collection();
        create_collection(&broker, collection.clone());
        let item = item(collection.id);
        broker
            .execute(Operation::CreateItem {
                item: item.clone(),
                secret: SecretBytes::new(b"secret".to_vec()).unwrap(),
            })
            .unwrap();
        assert_eq!(
            broker
                .execute(Operation::ListItems {
                    collection_id: collection.id,
                })
                .unwrap(),
            ResponseBody::Items(vec![item.clone()])
        );
        assert_eq!(
            broker
                .execute(Operation::DeleteItem { item_id: item.id })
                .unwrap(),
            ResponseBody::Empty
        );
        assert_eq!(
            broker
                .execute(Operation::GetItem {
                    item_id: item.id,
                    include_secret: false,
                })
                .unwrap_err()
                .code,
            ErrorCode::NotFound
        );
    }

    #[test]
    fn secret_limit_boundary_is_enforced() {
        let backend = InMemoryBackend::new();
        let broker = Broker::new(backend);
        let collection = collection();
        create_collection(&broker, collection.clone());
        let item = item(collection.id);
        broker
            .execute(Operation::CreateItem {
                item,
                secret: SecretBytes::new(vec![7; 2560]).unwrap(),
            })
            .unwrap();
        assert!(SecretBytes::new(vec![7; 2561]).is_err());
    }

    #[test]
    fn updates_preserve_created_timestamp_and_cleanup_old_generation() {
        let backend = InMemoryBackend::new();
        let broker = Broker::new(backend.clone());
        let collection = collection();
        create_collection(&broker, collection.clone());
        let original = item(collection.id);
        broker
            .execute(Operation::CreateItem {
                item: original.clone(),
                secret: SecretBytes::new(b"old".to_vec()).unwrap(),
            })
            .unwrap();
        let mut update = original.clone();
        update.created = 999;
        update.modified = 41;
        update.current_generation = Uuid::new_v4();
        broker
            .execute(Operation::UpdateItem {
                item: update.clone(),
                secret: Some(SecretBytes::new(b"new".to_vec()).unwrap()),
            })
            .unwrap();

        let ResponseBody::Item { item: stored, .. } = broker
            .execute(Operation::GetItem {
                item_id: update.id,
                include_secret: true,
            })
            .unwrap()
        else {
            panic!("expected item");
        };
        assert_eq!(stored.created, original.created);
        assert!(
            backend
                .read(&TargetName::ItemSecret {
                    item_id: original.id,
                    generation: original.current_generation,
                })
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn reconcile_removes_abandoned_and_reports_missing_generations() {
        let backend = InMemoryBackend::new();
        let broker = Broker::new(backend.clone());
        let collection = collection();
        create_collection(&broker, collection.clone());
        let committed = item(collection.id);
        broker
            .execute(Operation::CreateItem {
                item: committed.clone(),
                secret: SecretBytes::new(b"committed".to_vec()).unwrap(),
            })
            .unwrap();
        let abandoned = Uuid::new_v4();
        backend
            .write(
                &TargetName::ItemSecret {
                    item_id: committed.id,
                    generation: abandoned,
                },
                b"abandoned",
            )
            .unwrap();
        let missing = item(collection.id);
        backend
            .write(
                &TargetName::ItemMetadata(missing.id),
                &encode_metadata(&missing).unwrap(),
            )
            .unwrap();

        assert_eq!(
            broker.execute(Operation::Reconcile).unwrap(),
            ResponseBody::Reconciled {
                removed_generations: 1,
                corrupt_items: vec![missing.id],
            }
        );
    }

    #[test]
    fn collection_delete_cascades_items_secrets_and_aliases() {
        let backend = InMemoryBackend::new();
        let broker = Broker::new(backend.clone());
        let collection = collection();
        create_collection(&broker, collection.clone());
        let item = item(collection.id);
        broker
            .execute(Operation::CreateItem {
                item: item.clone(),
                secret: SecretBytes::new(b"secret".to_vec()).unwrap(),
            })
            .unwrap();
        broker
            .execute(Operation::SetAlias {
                alias: AliasMetadata {
                    schema_version: METADATA_SCHEMA_VERSION,
                    name: "default".to_owned(),
                    collection_id: collection.id,
                },
            })
            .unwrap();
        broker
            .execute(Operation::DeleteCollection {
                collection_id: collection.id,
            })
            .unwrap();
        assert!(
            backend
                .read(&TargetName::ItemMetadata(item.id))
                .unwrap()
                .is_none()
        );
        assert!(
            backend
                .read(&TargetName::ItemSecret {
                    item_id: item.id,
                    generation: item.current_generation,
                })
                .unwrap()
                .is_none()
        );
        assert_eq!(
            broker
                .execute(Operation::ResolveAlias {
                    name: "default".to_owned()
                })
                .unwrap(),
            ResponseBody::Alias(None)
        );
    }

    #[test]
    fn malformed_metadata_and_targets_are_ignored_without_mutation() {
        let backend = InMemoryBackend::new();
        let broker = Broker::new(backend.clone());
        let id = Uuid::new_v4();
        backend.insert_raw(TargetName::Collection(id).to_string(), vec![255, 0]);
        backend.insert_raw(
            format!(
                "{}item/not-a-canonical-uuid/meta",
                wincred_libsecret_protocol::CREDENTIAL_PREFIX
            ),
            b"foreign-to-parser".to_vec(),
        );
        assert_eq!(
            broker.execute(Operation::ListCollections).unwrap(),
            ResponseBody::Collections(Vec::new())
        );
        assert_eq!(
            broker
                .execute(Operation::GetCollection { collection_id: id })
                .unwrap_err()
                .code,
            ErrorCode::CorruptState
        );
    }

    #[test]
    fn aliases_replace_and_require_existing_collections() {
        let backend = InMemoryBackend::new();
        let broker = Broker::new(backend);
        let first = collection();
        let second = collection();
        create_collection(&broker, first.clone());
        create_collection(&broker, second.clone());
        for collection_id in [first.id, second.id] {
            broker
                .execute(Operation::SetAlias {
                    alias: AliasMetadata {
                        schema_version: METADATA_SCHEMA_VERSION,
                        name: "default".to_owned(),
                        collection_id,
                    },
                })
                .unwrap();
        }
        assert_eq!(
            broker
                .execute(Operation::ResolveAlias {
                    name: "default".to_owned()
                })
                .unwrap(),
            ResponseBody::Alias(Some(AliasMetadata {
                schema_version: METADATA_SCHEMA_VERSION,
                name: "default".to_owned(),
                collection_id: second.id,
            }))
        );
        assert_eq!(
            broker
                .execute(Operation::RemoveAlias {
                    name: "default".to_owned()
                })
                .unwrap(),
            ResponseBody::Empty
        );
    }

    #[test]
    fn alias_enumeration_is_sorted_and_ignores_corrupt_metadata() {
        let backend = InMemoryBackend::new();
        let broker = Broker::new(backend.clone());
        let first = collection();
        let second = collection();
        create_collection(&broker, first.clone());
        create_collection(&broker, second.clone());
        let aliases = [
            AliasMetadata {
                schema_version: METADATA_SCHEMA_VERSION,
                name: "z-last".to_owned(),
                collection_id: first.id,
            },
            AliasMetadata {
                schema_version: METADATA_SCHEMA_VERSION,
                name: "a-first".to_owned(),
                collection_id: second.id,
            },
        ];
        for alias in &aliases {
            broker
                .execute(Operation::SetAlias {
                    alias: alias.clone(),
                })
                .unwrap();
        }
        backend.insert_raw(
            TargetName::Alias("corrupt".to_owned()).to_string(),
            vec![255],
        );
        backend.insert_raw(
            TargetName::Alias("mismatched".to_owned()).to_string(),
            encode_metadata(&AliasMetadata {
                schema_version: METADATA_SCHEMA_VERSION,
                name: "other".to_owned(),
                collection_id: first.id,
            })
            .unwrap(),
        );

        assert_eq!(
            broker.execute(Operation::ListAliases).unwrap(),
            ResponseBody::Aliases(vec![aliases[1].clone(), aliases[0].clone()])
        );
    }

    #[test]
    fn item_creation_reports_a_missing_collection() {
        let broker = Broker::new(InMemoryBackend::new());
        let error = broker
            .execute(Operation::CreateItem {
                item: item(Uuid::new_v4()),
                secret: SecretBytes::new(b"secret".to_vec()).unwrap(),
            })
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidCollection);
    }

    #[test]
    fn memory_lock_serializes_concurrent_callers() {
        let backend = InMemoryBackend::new();
        let barrier = Arc::new(Barrier::new(3));
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let backend = backend.clone();
            let barrier = Arc::clone(&barrier);
            let active = Arc::clone(&active);
            let maximum = Arc::clone(&maximum);
            workers.push(thread::spawn(move || {
                barrier.wait();
                let lock = backend.acquire_lock().unwrap();
                let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                maximum.fetch_max(current, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(20));
                active.fetch_sub(1, Ordering::SeqCst);
                drop(lock);
            }));
        }
        barrier.wait();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(maximum.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn secret_debug_is_redacted() {
        let secret = SecretBytes::new(b"do-not-log".to_vec()).unwrap();
        let debug = format!("{secret:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("do-not-log"));
    }

    #[test]
    fn failed_metadata_commit_removes_the_uncommitted_secret() {
        let backend = FaultBackend::new();
        let broker = Broker::new(backend);
        let collection = collection();
        create_collection(&broker, collection.clone());
        broker
            .backend
            .fail_metadata_write
            .store(true, Ordering::SeqCst);
        let item = item(collection.id);

        assert_eq!(
            broker
                .execute(Operation::CreateItem {
                    item: item.clone(),
                    secret: SecretBytes::new(vec![0xA5; 16]).unwrap(),
                })
                .unwrap_err()
                .code,
            ErrorCode::BackendUnavailable
        );
        assert!(
            broker
                .backend
                .read(&TargetName::ItemSecret {
                    item_id: item.id,
                    generation: item.current_generation,
                })
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn replacement_never_deletes_existing_item_before_new_metadata_commits() {
        let backend = FaultBackend::new();
        let broker = Broker::new(backend);
        let collection = collection();
        create_collection(&broker, collection.clone());
        let original = item(collection.id);
        broker
            .execute(Operation::CreateItem {
                item: original.clone(),
                secret: SecretBytes::new(b"old-secret".to_vec()).unwrap(),
            })
            .unwrap();

        broker
            .backend
            .fail_metadata_write
            .store(true, Ordering::SeqCst);
        let mut replacement = item(collection.id);
        replacement.attributes = original.attributes.clone();
        assert_eq!(
            broker
                .execute(Operation::CreateOrReplaceItem {
                    item: replacement,
                    secret: SecretBytes::new(b"new-secret".to_vec()).unwrap(),
                    replace: true,
                })
                .unwrap_err()
                .code,
            ErrorCode::BackendUnavailable
        );
        let ResponseBody::Item {
            secret: Some(secret),
            ..
        } = broker
            .execute(Operation::GetItem {
                item_id: original.id,
                include_secret: true,
            })
            .unwrap()
        else {
            panic!("expected original item");
        };
        assert_eq!(secret.expose(), b"old-secret");
    }

    #[test]
    fn replacement_cleanup_failure_keeps_the_new_committed_secret() {
        let backend = FaultBackend::new();
        let broker = Broker::new(backend);
        let collection = collection();
        create_collection(&broker, collection.clone());
        let original = item(collection.id);
        broker
            .execute(Operation::CreateItem {
                item: original.clone(),
                secret: SecretBytes::new(b"old-secret".to_vec()).unwrap(),
            })
            .unwrap();
        broker
            .backend
            .fail_secret_delete
            .store(true, Ordering::SeqCst);

        let mut replacement = item(collection.id);
        replacement.attributes = original.attributes.clone();
        let ResponseBody::ReplacedItem { item, .. } = broker
            .execute(Operation::CreateOrReplaceItem {
                item: replacement,
                secret: SecretBytes::new(b"new-secret".to_vec()).unwrap(),
                replace: true,
            })
            .unwrap()
        else {
            panic!("expected replacement");
        };
        let ResponseBody::Item {
            secret: Some(secret),
            ..
        } = broker
            .execute(Operation::GetItem {
                item_id: item.id,
                include_secret: true,
            })
            .unwrap()
        else {
            panic!("expected replacement item");
        };
        assert_eq!(secret.expose(), b"new-secret");
    }

    #[test]
    fn replacement_reports_only_metadata_deletions_that_committed() {
        let backend = FaultBackend::new();
        let broker = Broker::new(backend);
        let collection = collection();
        create_collection(&broker, collection.clone());
        let original = item(collection.id);
        broker
            .execute(Operation::CreateItem {
                item: original.clone(),
                secret: SecretBytes::new(b"old-secret".to_vec()).unwrap(),
            })
            .unwrap();
        broker
            .backend
            .fail_item_metadata_delete
            .store(true, Ordering::SeqCst);
        let mut replacement = item(collection.id);
        replacement.attributes = original.attributes.clone();
        let ResponseBody::ReplacedItem {
            replaced_item_ids,
            cleanup_failed_item_ids,
            ..
        } = broker
            .execute(Operation::CreateOrReplaceItem {
                item: replacement,
                secret: SecretBytes::new(b"new-secret".to_vec()).unwrap(),
                replace: true,
            })
            .unwrap()
        else {
            panic!("expected replacement");
        };
        assert!(replaced_item_ids.is_empty());
        assert_eq!(cleanup_failed_item_ids, vec![original.id]);
        assert!(matches!(
            broker.execute(Operation::GetItem {
                item_id: original.id,
                include_secret: true,
            }),
            Ok(ResponseBody::Item { .. })
        ));
    }

    #[test]
    fn compare_and_swap_rejects_stale_cross_broker_updates() {
        let backend = InMemoryBackend::new();
        let first = Broker::new(backend.clone());
        let second = Broker::new(backend);
        let collection = collection();
        create_collection(&first, collection.clone());
        let original = item(collection.id);
        first
            .execute(Operation::CreateItem {
                item: original.clone(),
                secret: SecretBytes::new(b"secret".to_vec()).unwrap(),
            })
            .unwrap();
        let mut first_update = original.clone();
        first_update.label = "first update".to_owned();
        first_update.modified += 1;
        first
            .execute(Operation::UpdateItemCas {
                item: first_update,
                secret: None,
                expected_modified: original.modified,
            })
            .unwrap();
        let mut stale_update = original.clone();
        stale_update.label = "stale update".to_owned();
        stale_update.modified += 1;
        assert_eq!(
            second
                .execute(Operation::UpdateItemCas {
                    item: stale_update,
                    secret: None,
                    expected_modified: original.modified,
                })
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
    }

    #[test]
    fn enumeration_discards_secret_blobs_after_target_parsing() {
        let backend = InMemoryBackend::new();
        let broker = Broker::new(backend.clone());
        let item_id = Uuid::new_v4();
        backend
            .write(
                &TargetName::ItemSecret {
                    item_id,
                    generation: Uuid::new_v4(),
                },
                b"secret",
            )
            .unwrap();
        let entries = broker.entries().unwrap();
        assert!(entries.iter().all(|entry| entry.blob.is_empty()));
    }

    #[test]
    fn recovery_removes_a_generation_left_by_interrupted_cleanup() {
        let backend = FaultBackend::new();
        let broker = Broker::new(backend);
        let collection = collection();
        create_collection(&broker, collection.clone());
        let original = item(collection.id);
        broker
            .execute(Operation::CreateItem {
                item: original.clone(),
                secret: SecretBytes::new(vec![1; 8]).unwrap(),
            })
            .unwrap();
        broker
            .backend
            .fail_secret_delete
            .store(true, Ordering::SeqCst);
        let mut replacement = original.clone();
        replacement.current_generation = Uuid::new_v4();
        broker
            .execute(Operation::UpdateItem {
                item: replacement.clone(),
                secret: Some(SecretBytes::new(vec![2; 8]).unwrap()),
            })
            .unwrap();

        assert_eq!(
            broker.execute(Operation::Reconcile).unwrap(),
            ResponseBody::Reconciled {
                removed_generations: 1,
                corrupt_items: Vec::new(),
            }
        );
        assert!(
            broker
                .backend
                .read(&TargetName::ItemSecret {
                    item_id: original.id,
                    generation: original.current_generation,
                })
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn lock_conflict_prevents_any_operation() {
        let backend = FaultBackend::new();
        let broker = Broker::new(backend);
        broker.backend.fail_lock.store(true, Ordering::SeqCst);
        assert_eq!(
            broker.execute(Operation::Ping).unwrap_err().code,
            ErrorCode::Conflict
        );
    }

    #[test]
    fn foreign_targets_are_neither_enumerated_nor_touched_by_recovery() {
        let backend = InMemoryBackend::new();
        backend.insert_raw("OtherApplication/credential".to_owned(), vec![0xA5; 4]);
        let broker = Broker::new(backend.clone());
        assert!(backend.enumerate().unwrap().is_empty());
        assert_eq!(
            broker.execute(Operation::Reconcile).unwrap(),
            ResponseBody::Reconciled {
                removed_generations: 0,
                corrupt_items: Vec::new(),
            }
        );
    }

    #[test]
    fn broker_operations_remain_serialized_under_contention() {
        let broker = Arc::new(Broker::new(InMemoryBackend::new()));
        let workers = (0..24)
            .map(|index| {
                let broker = Arc::clone(&broker);
                thread::spawn(move || {
                    broker.execute(Operation::CreateCollection {
                        collection: CollectionMetadata {
                            schema_version: METADATA_SCHEMA_VERSION,
                            id: Uuid::new_v4(),
                            label: format!("concurrent-{index}"),
                            created: 1,
                            modified: 1,
                        },
                    })
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            assert!(worker.join().unwrap().is_ok());
        }
        let ResponseBody::Collections(collections) =
            broker.execute(Operation::ListCollections).unwrap()
        else {
            panic!("expected collections");
        };
        assert_eq!(collections.len(), 24);
    }
}
