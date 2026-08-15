use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use rand::{TryRng, rngs::SysRng};
use tokio::sync::Mutex;
use uuid::Uuid;
use wincred_libsecret_protocol::{
    AliasMetadata, CollectionMetadata, ItemMetadata, MAX_SECRET_BYTES, Operation, ResponseBody,
    SecretBytes, validate_alias_name, validate_attributes, validate_content_type, validate_label,
};
use zbus::{
    Connection, interface,
    message::Header,
    object_server::{ObjectServer, SignalEmitter},
    zvariant::{OwnedObjectPath, OwnedValue, Value},
};

use crate::{
    broker::BrokerClient,
    crypto::SessionKey,
    error::{ProviderError, Result, SecretServiceError},
    paths::{
        COMPAT_PROMPT_PATH, SERVICE_PATH, alias_path, collection_id, collection_path, item_id,
        item_path, session_id, session_path,
    },
};

type DbusResult<T> = std::result::Result<T, SecretServiceError>;
type DbusSecret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

#[derive(Clone)]
pub struct Provider {
    broker: Arc<dyn BrokerClient>,
    sessions: Arc<Mutex<HashMap<Uuid, SessionRecord>>>,
}

struct SessionRecord {
    owner: String,
    key: SessionKey,
}

impl Provider {
    #[must_use]
    pub fn new(broker: Arc<dyn BrokerClient>) -> Self {
        Self {
            broker,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn initialize(&self, server: &ObjectServer) -> Result<()> {
        for collection in self.collections().await? {
            server
                .at(
                    collection_path(collection.id),
                    CollectionObject::new(self.clone(), collection.id),
                )
                .await
                .map_err(|_| ProviderError::Transport)?;
            for item in self.items(collection.id).await? {
                server
                    .at(item_path(item.id), ItemObject::new(self.clone(), item.id))
                    .await
                    .map_err(|_| ProviderError::Transport)?;
            }
        }
        for alias in self.aliases().await? {
            if let Some(path) = alias_path(&alias.name) {
                server
                    .at(
                        path,
                        CollectionObject::new(self.clone(), alias.collection_id),
                    )
                    .await
                    .map_err(|_| ProviderError::Transport)?;
            }
        }
        server
            .at(COMPAT_PROMPT_PATH, PromptObject)
            .await
            .map_err(|_| ProviderError::Transport)?;
        Ok(())
    }

    pub async fn remove_owner(&self, owner: &str) -> Vec<Uuid> {
        let mut sessions = self.sessions.lock().await;
        let removed = sessions
            .iter()
            .filter_map(|(id, session)| (session.owner == owner).then_some(*id))
            .collect::<Vec<_>>();
        sessions.retain(|_, session| session.owner != owner);
        removed
    }

    async fn response(&self, operation: Operation) -> Result<ResponseBody> {
        self.broker.call(operation).await
    }

    async fn collections(&self) -> Result<Vec<CollectionMetadata>> {
        match self.response(Operation::ListCollections).await? {
            ResponseBody::Collections(collections) => Ok(collections),
            _ => Err(ProviderError::Transport),
        }
    }

    async fn collection(&self, id: Uuid) -> Result<CollectionMetadata> {
        match self
            .response(Operation::GetCollection { collection_id: id })
            .await?
        {
            ResponseBody::Collection(collection) => Ok(collection),
            _ => Err(ProviderError::Transport),
        }
    }

    async fn items(&self, collection_id: Uuid) -> Result<Vec<ItemMetadata>> {
        match self
            .response(Operation::ListItems { collection_id })
            .await?
        {
            ResponseBody::Items(items) => Ok(items),
            _ => Err(ProviderError::Transport),
        }
    }

    async fn item(
        &self,
        id: Uuid,
        include_secret: bool,
    ) -> Result<(ItemMetadata, Option<SecretBytes>)> {
        match self
            .response(Operation::GetItem {
                item_id: id,
                include_secret,
            })
            .await?
        {
            ResponseBody::Item { item, secret } => Ok((item, secret)),
            _ => Err(ProviderError::Transport),
        }
    }

    async fn create_collection(&self, label: String) -> Result<CollectionMetadata> {
        validate_label(&label)?;
        let timestamp = now();
        let collection = CollectionMetadata {
            schema_version: 1,
            id: Uuid::new_v4(),
            label,
            created: timestamp,
            modified: timestamp,
        };
        match self
            .response(Operation::CreateCollection {
                collection: collection.clone(),
            })
            .await?
        {
            ResponseBody::Collection(collection) => Ok(collection),
            _ => Err(ProviderError::Transport),
        }
    }

    async fn update_collection_label(&self, id: Uuid, label: String) -> Result<()> {
        validate_label(&label)?;
        let mut collection = self.collection(id).await?;
        collection.label = label;
        collection.modified = now();
        match self
            .response(Operation::UpdateCollection { collection })
            .await?
        {
            ResponseBody::Collection(_) => Ok(()),
            _ => Err(ProviderError::Transport),
        }
    }

    async fn delete_collection(&self, id: Uuid) -> Result<()> {
        match self
            .response(Operation::DeleteCollection { collection_id: id })
            .await?
        {
            ResponseBody::Empty => Ok(()),
            _ => Err(ProviderError::Transport),
        }
    }

    async fn create_item(
        &self,
        collection_id: Uuid,
        label: String,
        attributes: BTreeMap<String, String>,
        content_type: String,
        secret: SecretBytes,
        replace: bool,
    ) -> Result<(ItemMetadata, Vec<Uuid>, Vec<Uuid>)> {
        validate_label(&label)?;
        validate_attributes(&attributes)?;
        validate_content_type(&content_type)?;
        let timestamp = now();
        let item = ItemMetadata {
            schema_version: 1,
            id: Uuid::new_v4(),
            collection_id,
            label,
            attributes,
            content_type,
            created: timestamp,
            modified: timestamp,
            current_generation: Uuid::new_v4(),
        };
        match self
            .response(Operation::CreateOrReplaceItem {
                item: item.clone(),
                secret,
                replace,
            })
            .await?
        {
            ResponseBody::ReplacedItem {
                item,
                replaced_item_ids,
                cleanup_failed_item_ids,
            } => Ok((item, replaced_item_ids, cleanup_failed_item_ids)),
            _ => Err(ProviderError::Transport),
        }
    }

    async fn update_item(
        &self,
        mut item: ItemMetadata,
        secret: Option<SecretBytes>,
    ) -> Result<ItemMetadata> {
        validate_label(&item.label)?;
        validate_attributes(&item.attributes)?;
        validate_content_type(&item.content_type)?;
        let expected_modified = item.modified;
        item.modified = now();
        if secret.is_some() {
            item.current_generation = Uuid::new_v4();
        }
        match self
            .response(Operation::UpdateItemCas {
                expected_modified,
                item,
                secret,
            })
            .await?
        {
            ResponseBody::Item { item, .. } => Ok(item),
            _ => Err(ProviderError::Transport),
        }
    }

    async fn delete_item(&self, id: Uuid) -> Result<()> {
        match self.response(Operation::DeleteItem { item_id: id }).await? {
            ResponseBody::Empty => Ok(()),
            _ => Err(ProviderError::Transport),
        }
    }

    fn open_session(algorithm: &str, input: OwnedValue) -> Result<(OwnedValue, Uuid, SessionKey)> {
        let (output, key) = match algorithm {
            "plain" => {
                let input = String::try_from(input).map_err(|_| {
                    ProviderError::InvalidRequest("plain session input must be a string".to_owned())
                })?;
                if !input.is_empty() {
                    return Err(ProviderError::InvalidRequest(
                        "plain session input must be empty".to_owned(),
                    ));
                }
                (variant(String::new()), SessionKey::plain())
            }
            "dh-ietf1024-sha256-aes128-cbc-pkcs7" => {
                let public = Vec::<u8>::try_from(input).map_err(|_| {
                    ProviderError::InvalidRequest(
                        "DH session input must be a byte array".to_owned(),
                    )
                })?;
                let (key, public) = SessionKey::open_dh(&public)?;
                (variant(public), key)
            }
            _ => {
                return Err(ProviderError::InvalidRequest(format!(
                    "unsupported session algorithm: {algorithm}"
                )));
            }
        };
        Ok((output, Uuid::new_v4(), key))
    }

    async fn insert_session(&self, id: Uuid, owner: String, key: SessionKey) {
        self.sessions
            .lock()
            .await
            .insert(id, SessionRecord { owner, key });
    }

    async fn close_session(&self, id: Uuid, owner: &str) -> Result<()> {
        let mut sessions = self.sessions.lock().await;
        let session = sessions.get(&id).ok_or(ProviderError::InvalidSession)?;
        if session.owner != owner {
            return Err(ProviderError::InvalidSession);
        }
        sessions.remove(&id);
        Ok(())
    }

    async fn decode_secret(
        &self,
        owner: &str,
        secret: DbusSecret,
    ) -> Result<(Uuid, SecretBytes, String)> {
        let session = session_id(secret.0.as_str()).ok_or_else(|| {
            ProviderError::InvalidRequest("secret contains an invalid session path".to_owned())
        })?;
        let mut clear = {
            let sessions = self.sessions.lock().await;
            let session_record = sessions
                .get(&session)
                .ok_or(ProviderError::InvalidSession)?;
            if session_record.owner != owner {
                return Err(ProviderError::InvalidSession);
            }
            session_record.key.decrypt(&secret.1, &secret.2)?
        };
        if clear.len() > MAX_SECRET_BYTES {
            zeroize::Zeroize::zeroize(&mut clear);
            return Err(ProviderError::SecretTooLarge);
        }
        let bytes = SecretBytes::new(clear)?;
        Ok((session, bytes, secret.3))
    }

    async fn encode_secret(
        &self,
        owner: &str,
        session: Uuid,
        secret: SecretBytes,
        content_type: String,
    ) -> Result<DbusSecret> {
        let (parameters, value) = {
            let sessions = self.sessions.lock().await;
            let session_record = sessions
                .get(&session)
                .ok_or(ProviderError::InvalidSession)?;
            if session_record.owner != owner {
                return Err(ProviderError::InvalidSession);
            }
            match &session_record.key {
                SessionKey::Plain => (
                    Vec::new(),
                    session_record.key.encrypt(&[], secret.expose())?,
                ),
                SessionKey::Dh { .. } => {
                    let mut parameters = vec![0_u8; 16];
                    SysRng
                        .try_fill_bytes(&mut parameters)
                        .map_err(|_| ProviderError::Indeterminate)?;
                    let value = session_record.key.encrypt(&parameters, secret.expose())?;
                    (parameters, value)
                }
            }
        };
        Ok((
            path(&session_path(session)),
            parameters,
            value,
            content_type,
        ))
    }

    async fn resolve_alias(&self, name: String) -> Result<Option<AliasMetadata>> {
        match self.response(Operation::ResolveAlias { name }).await? {
            ResponseBody::Alias(alias) => Ok(alias),
            _ => Err(ProviderError::Transport),
        }
    }

    async fn aliases(&self) -> Result<Vec<AliasMetadata>> {
        match self.response(Operation::ListAliases).await? {
            ResponseBody::Aliases(mut aliases) => {
                aliases.sort_by(|left, right| {
                    left.name
                        .cmp(&right.name)
                        .then_with(|| left.collection_id.cmp(&right.collection_id))
                });
                aliases.dedup_by(|left, right| left.name == right.name);
                Ok(aliases)
            }
            _ => Err(ProviderError::Transport),
        }
    }

    async fn set_alias(&self, name: String, collection_id: Option<Uuid>) -> Result<()> {
        validate_alias_name(&name)?;
        let response = match collection_id {
            Some(collection_id) => {
                self.response(Operation::SetAlias {
                    alias: AliasMetadata {
                        schema_version: 1,
                        name,
                        collection_id,
                    },
                })
                .await?
            }
            None => self.response(Operation::RemoveAlias { name }).await?,
        };
        matches!(response, ResponseBody::Empty | ResponseBody::Alias(Some(_)))
            .then_some(())
            .ok_or(ProviderError::Transport)
    }

    async fn search(&self, attributes: BTreeMap<String, String>) -> Result<Vec<ItemMetadata>> {
        validate_attributes(&attributes)?;
        match self.response(Operation::SearchItems { attributes }).await? {
            ResponseBody::Items(items) => Ok(items),
            _ => Err(ProviderError::Transport),
        }
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn path(value: &str) -> OwnedObjectPath {
    value
        .try_into()
        .expect("provider-generated object path is valid")
}

fn variant<T>(value: T) -> OwnedValue
where
    Value<'static>: From<T>,
{
    Value::from(value)
        .try_to_owned()
        .expect("D-Bus value without file descriptors is owned")
}

fn owner(header: &Header<'_>) -> DbusResult<String> {
    header
        .sender()
        .map(ToString::to_string)
        .ok_or_else(|| SecretServiceError::AccessDenied("missing D-Bus caller identity".to_owned()))
}

fn dbus(error: ProviderError) -> SecretServiceError {
    error.into()
}

async fn emit_item_changed(
    connection: &Connection,
    collection: Uuid,
    item: Uuid,
) -> zbus::Result<()> {
    let emitter = SignalEmitter::new(connection, collection_path(collection))?;
    CollectionObject::item_changed(&emitter, path(&item_path(item))).await
}

fn collection_label(properties: &HashMap<String, OwnedValue>) -> Result<String> {
    match properties
        .get("Label")
        .or_else(|| properties.get("org.freedesktop.Secret.Collection.Label"))
        .cloned()
    {
        Some(value) => String::try_from(value).map_err(|_| {
            ProviderError::InvalidRequest("collection Label must be a string".to_owned())
        }),
        // libsecret may request creation of its default collection without
        // providing display properties.
        None => Ok("Default".to_owned()),
    }
}

fn item_properties(
    properties: &HashMap<String, OwnedValue>,
) -> Result<(String, BTreeMap<String, String>)> {
    let label = properties
        .get("Label")
        .or_else(|| properties.get("org.freedesktop.Secret.Item.Label"))
        .cloned()
        .ok_or_else(|| ProviderError::InvalidRequest("item Label is required".to_owned()))
        .and_then(|value| {
            String::try_from(value).map_err(|_| {
                ProviderError::InvalidRequest("item Label must be a string".to_owned())
            })
        })?;
    let attributes = match properties
        .get("Attributes")
        .or_else(|| properties.get("org.freedesktop.Secret.Item.Attributes"))
    {
        Some(value) => HashMap::<String, String>::try_from(value.clone())
            .map_err(|_| ProviderError::InvalidRequest("item Attributes must be a{ss}".to_owned()))?
            .into_iter()
            .collect(),
        None => BTreeMap::new(),
    };
    Ok((label, attributes))
}

pub async fn remove_owner_sessions(server: &ObjectServer, provider: &Provider, owner: &str) {
    for session in provider.remove_owner(owner).await {
        let _ = server
            .remove::<SessionObject, _>(session_path(session))
            .await;
    }
}

pub struct SecretService {
    provider: Provider,
}

impl SecretService {
    #[must_use]
    pub fn new(provider: Provider) -> Self {
        Self { provider }
    }
}

#[interface(name = "org.freedesktop.Secret.Service")]
impl SecretService {
    async fn open_session(
        &self,
        algorithm: &str,
        input: OwnedValue,
        #[zbus(header)] header: Header<'_>,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> std::result::Result<(OwnedValue, OwnedObjectPath), SecretServiceError> {
        let owner = owner(&header)?;
        let (output, id, key) = Provider::open_session(algorithm, input).map_err(dbus)?;
        let object_path = session_path(id);
        server
            .at(
                object_path.as_str(),
                SessionObject::new(self.provider.clone(), id),
            )
            .await
            .map_err(|_| SecretServiceError::Failed("unable to register session".to_owned()))?;
        self.provider.insert_session(id, owner, key).await;
        Ok((output, path(&object_path)))
    }

    async fn create_collection(
        &self,
        properties: HashMap<String, OwnedValue>,
        alias: &str,
        #[zbus(object_server)] server: &ObjectServer,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> std::result::Result<(OwnedObjectPath, OwnedObjectPath), SecretServiceError> {
        let collection = self
            .provider
            .create_collection(collection_label(&properties).map_err(dbus)?)
            .await
            .map_err(dbus)?;
        let collection_path = collection_path(collection.id);
        if let Err(error) = server
            .at(
                collection_path.as_str(),
                CollectionObject::new(self.provider.clone(), collection.id),
            )
            .await
        {
            let _ = self.provider.delete_collection(collection.id).await;
            return Err(SecretServiceError::Failed(format!(
                "unable to register collection: {error}"
            )));
        }
        if !alias.is_empty() {
            if let Err(error) = self
                .provider
                .set_alias(alias.to_owned(), Some(collection.id))
                .await
            {
                let _ = server
                    .remove::<CollectionObject, _>(collection_path.as_str())
                    .await;
                let _ = self.provider.delete_collection(collection.id).await;
                return Err(dbus(error));
            }
            if let Some(alias_path) = alias_path(alias) {
                let _ = server
                    .remove::<CollectionObject, _>(alias_path.as_str())
                    .await;
                if let Err(error) = server
                    .at(
                        alias_path.as_str(),
                        CollectionObject::new(self.provider.clone(), collection.id),
                    )
                    .await
                {
                    let _ = self.provider.set_alias(alias.to_owned(), None).await;
                    let _ = server
                        .remove::<CollectionObject, _>(collection_path.as_str())
                        .await;
                    let _ = self.provider.delete_collection(collection.id).await;
                    return Err(SecretServiceError::Failed(format!(
                        "unable to register collection alias: {error}"
                    )));
                }
            }
            self.aliases_changed(&emitter).await.map_err(|_| {
                SecretServiceError::Failed("unable to emit alias update".to_owned())
            })?;
        }
        Self::collection_created(&emitter, path(&collection_path))
            .await
            .map_err(|_| {
                SecretServiceError::Failed("unable to emit collection signal".to_owned())
            })?;
        Ok((path(&collection_path), path("/")))
    }

    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> std::result::Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>), SecretServiceError> {
        let attributes = attributes.into_iter().collect();
        let items = self.provider.search(attributes).await.map_err(dbus)?;
        Ok((
            items
                .into_iter()
                .map(|item| path(&item_path(item.id)))
                .collect(),
            Vec::new(),
        ))
    }

    #[allow(clippy::unnecessary_wraps, clippy::unused_self)]
    fn unlock(
        &self,
        objects: Vec<OwnedObjectPath>,
    ) -> std::result::Result<(Vec<OwnedObjectPath>, OwnedObjectPath), SecretServiceError> {
        Ok((objects, path("/")))
    }

    #[allow(clippy::unnecessary_wraps, clippy::unused_self)]
    fn lock(
        &self,
        objects: Vec<OwnedObjectPath>,
    ) -> std::result::Result<(Vec<OwnedObjectPath>, OwnedObjectPath), SecretServiceError> {
        // WinCred access is tied to the active Windows logon session. There is
        // no independent collection lock to persist, so this is immediate.
        Ok((objects, path("/")))
    }

    async fn get_secrets(
        &self,
        items: Vec<OwnedObjectPath>,
        session: OwnedObjectPath,
        #[zbus(header)] header: Header<'_>,
    ) -> std::result::Result<HashMap<OwnedObjectPath, DbusSecret>, SecretServiceError> {
        let owner = owner(&header)?;
        let session = session_id(session.as_str())
            .ok_or_else(|| SecretServiceError::NoSuchSession("invalid session path".to_owned()))?;
        let mut raw = Vec::with_capacity(items.len());
        for item_path in items {
            let id = item_id(item_path.as_str())
                .ok_or_else(|| SecretServiceError::NoSuchObject("invalid item path".to_owned()))?;
            let (metadata, secret) = self.provider.item(id, true).await.map_err(dbus)?;
            let secret = secret
                .ok_or_else(|| SecretServiceError::Failed("broker omitted secret".to_owned()))?;
            raw.push((metadata, secret));
        }
        let mut values = HashMap::with_capacity(raw.len());
        for (metadata, secret) in raw {
            let content_type = metadata.content_type;
            let encoded = self
                .provider
                .encode_secret(&owner, session, secret, content_type)
                .await
                .map_err(dbus)?;
            values.insert(path(&item_path(metadata.id)), encoded);
        }
        Ok(values)
    }

    async fn read_alias(
        &self,
        name: &str,
    ) -> std::result::Result<OwnedObjectPath, SecretServiceError> {
        Ok(self
            .provider
            .resolve_alias(name.to_owned())
            .await
            .map_err(dbus)?
            .map_or_else(
                || path("/"),
                |alias| path(&collection_path(alias.collection_id)),
            ))
    }

    async fn set_alias(
        &self,
        name: &str,
        collection: OwnedObjectPath,
        #[zbus(object_server)] server: &ObjectServer,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> std::result::Result<(), SecretServiceError> {
        let id = if collection.as_str() == "/" {
            None
        } else {
            Some(collection_id(collection.as_str()).ok_or_else(|| {
                SecretServiceError::NoSuchObject("invalid collection path".to_owned())
            })?)
        };
        self.provider
            .set_alias(name.to_owned(), id)
            .await
            .map_err(dbus)?;
        if let Some(alias_path) = alias_path(name) {
            match id {
                Some(collection_id) => {
                    let _ = server
                        .remove::<CollectionObject, _>(alias_path.as_str())
                        .await;
                    server
                        .at(
                            alias_path.as_str(),
                            CollectionObject::new(self.provider.clone(), collection_id),
                        )
                        .await
                        .map_err(|_| {
                            SecretServiceError::Failed(
                                "unable to register collection alias".to_owned(),
                            )
                        })?;
                }
                None => {
                    let _ = server.remove::<CollectionObject, _>(alias_path).await;
                }
            }
        }
        self.aliases_changed(&emitter)
            .await
            .map_err(|_| SecretServiceError::Failed("unable to emit alias update".to_owned()))
    }

    #[zbus(property)]
    async fn collections(&self) -> zbus::fdo::Result<Vec<OwnedObjectPath>> {
        Ok(self
            .provider
            .collections()
            .await
            .map_err(dbus)?
            .into_iter()
            .map(|collection| path(&collection_path(collection.id)))
            .collect())
    }

    #[zbus(property)]
    async fn aliases(&self) -> zbus::fdo::Result<HashMap<String, OwnedObjectPath>> {
        Ok(self
            .provider
            .aliases()
            .await
            .map_err(dbus)?
            .into_iter()
            .map(|alias| (alias.name, path(&collection_path(alias.collection_id))))
            .collect())
    }

    #[zbus(signal)]
    async fn collection_created(
        signal_emitter: &SignalEmitter<'_>,
        collection: OwnedObjectPath,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn collection_deleted(
        signal_emitter: &SignalEmitter<'_>,
        collection: OwnedObjectPath,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn collection_changed(
        signal_emitter: &SignalEmitter<'_>,
        collection: OwnedObjectPath,
    ) -> zbus::Result<()>;
}

pub struct CollectionObject {
    provider: Provider,
    id: Uuid,
}

impl CollectionObject {
    fn new(provider: Provider, id: Uuid) -> Self {
        Self { provider, id }
    }
}

#[interface(name = "org.freedesktop.Secret.Collection")]
impl CollectionObject {
    async fn delete(
        &self,
        #[zbus(object_server)] server: &ObjectServer,
        #[zbus(connection)] connection: &Connection,
    ) -> std::result::Result<OwnedObjectPath, SecretServiceError> {
        let items = self.provider.items(self.id).await.map_err(dbus)?;
        let aliases = self
            .provider
            .aliases()
            .await
            .map_err(dbus)?
            .into_iter()
            .filter(|alias| alias.collection_id == self.id)
            .collect::<Vec<_>>();
        self.provider
            .delete_collection(self.id)
            .await
            .map_err(dbus)?;
        for item in items {
            let _ = server.remove::<ItemObject, _>(item_path(item.id)).await;
        }
        for alias in aliases {
            if let Some(path) = alias_path(&alias.name) {
                let _ = server.remove::<CollectionObject, _>(path).await;
            }
        }
        server
            .remove::<CollectionObject, _>(collection_path(self.id))
            .await
            .map_err(|_| {
                SecretServiceError::Failed("unable to unregister collection".to_owned())
            })?;
        let root = SignalEmitter::new(connection, SERVICE_PATH).map_err(|_| {
            SecretServiceError::Failed("unable to emit collection signal".to_owned())
        })?;
        SecretService::collection_deleted(&root, path(&collection_path(self.id)))
            .await
            .map_err(|_| {
                SecretServiceError::Failed("unable to emit collection signal".to_owned())
            })?;
        Ok(path("/"))
    }

    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> std::result::Result<Vec<OwnedObjectPath>, SecretServiceError> {
        let wanted: BTreeMap<_, _> = attributes.into_iter().collect();
        let items = self.provider.items(self.id).await.map_err(dbus)?;
        Ok(items
            .into_iter()
            .filter(|item| {
                wanted
                    .iter()
                    .all(|(key, value)| item.attributes.get(key) == Some(value))
            })
            .map(|item| path(&item_path(item.id)))
            .collect())
    }

    async fn create_item(
        &self,
        properties: HashMap<String, OwnedValue>,
        secret: DbusSecret,
        replace: bool,
        #[zbus(header)] header: Header<'_>,
        #[zbus(object_server)] server: &ObjectServer,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> std::result::Result<(OwnedObjectPath, OwnedObjectPath), SecretServiceError> {
        let owner = owner(&header)?;
        let (label, attributes) = item_properties(&properties).map_err(dbus)?;
        let (_, secret, content_type) = self
            .provider
            .decode_secret(&owner, secret)
            .await
            .map_err(dbus)?;
        validate_content_type(&content_type)
            .map_err(ProviderError::from)
            .map_err(dbus)?;

        let (item, replaced_item_ids, cleanup_failed_item_ids) = self
            .provider
            .create_item(self.id, label, attributes, content_type, secret, replace)
            .await
            .map_err(dbus)?;
        if !cleanup_failed_item_ids.is_empty() {
            tracing::warn!(
                count = cleanup_failed_item_ids.len(),
                "replacement left prior items registered after broker cleanup failure"
            );
        }
        for replaced in replaced_item_ids {
            let _ = server.remove::<ItemObject, _>(item_path(replaced)).await;
            Self::item_deleted(&emitter, path(&item_path(replaced)))
                .await
                .map_err(|_| SecretServiceError::Failed("unable to emit item signal".to_owned()))?;
        }
        let item_path = item_path(item.id);
        if let Err(error) = server
            .at(
                item_path.as_str(),
                ItemObject::new(self.provider.clone(), item.id),
            )
            .await
        {
            let _ = self.provider.delete_item(item.id).await;
            return Err(SecretServiceError::Failed(format!(
                "unable to register item: {error}"
            )));
        }
        Self::item_created(&emitter, path(&item_path))
            .await
            .map_err(|_| SecretServiceError::Failed("unable to emit item signal".to_owned()))?;
        Ok((path(&item_path), path("/")))
    }

    #[zbus(property)]
    async fn label(&self) -> zbus::fdo::Result<String> {
        Ok(self.provider.collection(self.id).await.map_err(dbus)?.label)
    }

    #[zbus(property)]
    async fn set_label(
        &self,
        label: String,
        #[zbus(connection)] connection: &Connection,
    ) -> zbus::fdo::Result<()> {
        self.provider
            .update_collection_label(self.id, label)
            .await
            .map_err(dbus)?;
        let emitter = SignalEmitter::new(connection, SERVICE_PATH)?;
        SecretService::collection_changed(&emitter, path(&collection_path(self.id))).await?;
        Ok(())
    }

    #[zbus(property)]
    #[allow(clippy::unused_self)]
    fn locked(&self) -> bool {
        false
    }

    #[zbus(property)]
    async fn created(&self) -> zbus::fdo::Result<u64> {
        Ok(self
            .provider
            .collection(self.id)
            .await
            .map_err(dbus)?
            .created)
    }

    #[zbus(property)]
    async fn modified(&self) -> zbus::fdo::Result<u64> {
        Ok(self
            .provider
            .collection(self.id)
            .await
            .map_err(dbus)?
            .modified)
    }

    #[zbus(property)]
    async fn items(&self) -> zbus::fdo::Result<Vec<OwnedObjectPath>> {
        Ok(self
            .provider
            .items(self.id)
            .await
            .map_err(dbus)?
            .into_iter()
            .map(|item| path(&item_path(item.id)))
            .collect())
    }

    #[zbus(signal)]
    async fn item_created(
        signal_emitter: &SignalEmitter<'_>,
        item: OwnedObjectPath,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn item_deleted(
        signal_emitter: &SignalEmitter<'_>,
        item: OwnedObjectPath,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn item_changed(
        signal_emitter: &SignalEmitter<'_>,
        item: OwnedObjectPath,
    ) -> zbus::Result<()>;
}

pub struct ItemObject {
    provider: Provider,
    id: Uuid,
}

impl ItemObject {
    fn new(provider: Provider, id: Uuid) -> Self {
        Self { provider, id }
    }
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl ItemObject {
    async fn delete(
        &self,
        #[zbus(object_server)] server: &ObjectServer,
        #[zbus(connection)] connection: &Connection,
    ) -> std::result::Result<OwnedObjectPath, SecretServiceError> {
        let item = self.provider.item(self.id, false).await.map_err(dbus)?.0;
        self.provider.delete_item(self.id).await.map_err(dbus)?;
        server
            .remove::<ItemObject, _>(item_path(self.id))
            .await
            .map_err(|_| SecretServiceError::Failed("unable to unregister item".to_owned()))?;
        let collection_emitter =
            SignalEmitter::new(connection, collection_path(item.collection_id))
                .map_err(|_| SecretServiceError::Failed("unable to emit item signal".to_owned()))?;
        CollectionObject::item_deleted(&collection_emitter, path(&item_path(self.id)))
            .await
            .map_err(|_| SecretServiceError::Failed("unable to emit item signal".to_owned()))?;
        Ok(path("/"))
    }

    async fn get_secret(
        &self,
        session: OwnedObjectPath,
        #[zbus(header)] header: Header<'_>,
    ) -> std::result::Result<DbusSecret, SecretServiceError> {
        let owner = owner(&header)?;
        let session = session_id(session.as_str())
            .ok_or_else(|| SecretServiceError::NoSuchSession("invalid session path".to_owned()))?;
        let (item, secret) = self.provider.item(self.id, true).await.map_err(dbus)?;
        self.provider
            .encode_secret(
                &owner,
                session,
                secret.ok_or_else(|| {
                    SecretServiceError::Failed("broker omitted secret".to_owned())
                })?,
                item.content_type,
            )
            .await
            .map_err(dbus)
    }

    async fn set_secret(
        &self,
        secret: DbusSecret,
        #[zbus(header)] header: Header<'_>,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> std::result::Result<(), SecretServiceError> {
        let owner = owner(&header)?;
        let (_, secret, content_type) = self
            .provider
            .decode_secret(&owner, secret)
            .await
            .map_err(dbus)?;
        let (mut item, _) = self.provider.item(self.id, false).await.map_err(dbus)?;
        item.content_type = content_type;
        let collection_id = item.collection_id;
        self.provider
            .update_item(item, Some(secret))
            .await
            .map_err(dbus)?;
        emit_item_changed(connection, collection_id, self.id)
            .await
            .map_err(|_| SecretServiceError::Failed("unable to emit item signal".to_owned()))?;
        Self::secret_changed(&emitter)
            .await
            .map_err(|_| SecretServiceError::Failed("unable to emit secret signal".to_owned()))
    }

    #[zbus(property)]
    async fn label(&self) -> zbus::fdo::Result<String> {
        Ok(self
            .provider
            .item(self.id, false)
            .await
            .map_err(dbus)?
            .0
            .label)
    }

    #[zbus(property)]
    async fn set_label(
        &self,
        label: String,
        #[zbus(connection)] connection: &Connection,
    ) -> zbus::fdo::Result<()> {
        let (mut item, _) = self.provider.item(self.id, false).await.map_err(dbus)?;
        item.label = label;
        let collection_id = item.collection_id;
        self.provider.update_item(item, None).await.map_err(dbus)?;
        emit_item_changed(connection, collection_id, self.id).await?;
        Ok(())
    }

    #[zbus(property)]
    async fn attributes(&self) -> zbus::fdo::Result<HashMap<String, String>> {
        Ok(self
            .provider
            .item(self.id, false)
            .await
            .map_err(dbus)?
            .0
            .attributes
            .into_iter()
            .collect())
    }

    #[zbus(property)]
    async fn set_attributes(
        &self,
        attributes: HashMap<String, String>,
        #[zbus(connection)] connection: &Connection,
    ) -> zbus::fdo::Result<()> {
        let (mut item, _) = self.provider.item(self.id, false).await.map_err(dbus)?;
        item.attributes = attributes.into_iter().collect();
        let collection_id = item.collection_id;
        self.provider.update_item(item, None).await.map_err(dbus)?;
        emit_item_changed(connection, collection_id, self.id).await?;
        Ok(())
    }

    #[zbus(property)]
    #[allow(clippy::unused_self)]
    fn locked(&self) -> bool {
        false
    }

    #[zbus(property)]
    async fn created(&self) -> zbus::fdo::Result<u64> {
        Ok(self
            .provider
            .item(self.id, false)
            .await
            .map_err(dbus)?
            .0
            .created)
    }

    #[zbus(property)]
    async fn modified(&self) -> zbus::fdo::Result<u64> {
        Ok(self
            .provider
            .item(self.id, false)
            .await
            .map_err(dbus)?
            .0
            .modified)
    }

    #[zbus(signal)]
    async fn secret_changed(signal_emitter: &SignalEmitter<'_>) -> zbus::Result<()>;
}

pub struct SessionObject {
    provider: Provider,
    id: Uuid,
}

impl SessionObject {
    fn new(provider: Provider, id: Uuid) -> Self {
        Self { provider, id }
    }
}

#[interface(name = "org.freedesktop.Secret.Session")]
impl SessionObject {
    async fn close(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> std::result::Result<(), SecretServiceError> {
        self.provider
            .close_session(self.id, &owner(&header)?)
            .await
            .map_err(dbus)?;
        server
            .remove::<SessionObject, _>(session_path(self.id))
            .await
            .map_err(|_| SecretServiceError::Failed("unable to unregister session".to_owned()))?;
        Ok(())
    }
}

pub struct PromptObject;

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl PromptObject {
    async fn prompt(
        &self,
        window_id: &str,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> std::result::Result<(), SecretServiceError> {
        let _ = window_id;
        Self::completed(&emitter, true, variant(String::new()))
            .await
            .map_err(|_| SecretServiceError::Failed("unable to emit prompt signal".to_owned()))
    }

    async fn dismiss(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> std::result::Result<(), SecretServiceError> {
        Self::completed(&emitter, true, variant(String::new()))
            .await
            .map_err(|_| SecretServiceError::Failed("unable to emit prompt signal".to_owned()))
    }

    #[zbus(signal)]
    async fn completed(
        signal_emitter: &SignalEmitter<'_>,
        dismissed: bool,
        result: OwnedValue,
    ) -> zbus::Result<()>;
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};

    use async_trait::async_trait;
    use wincred_libsecret_protocol::{BrokerError, ErrorCode};

    use super::*;
    use crate::InMemoryBroker;

    fn provider() -> Provider {
        Provider::new(Arc::new(InMemoryBroker::new()))
    }

    struct FailedReplacementCleanupBroker {
        prior_item: Uuid,
    }

    #[async_trait]
    impl BrokerClient for FailedReplacementCleanupBroker {
        async fn call(&self, operation: Operation) -> Result<ResponseBody> {
            let Operation::CreateOrReplaceItem { item, .. } = operation else {
                panic!("unexpected broker operation");
            };
            Ok(ResponseBody::ReplacedItem {
                item,
                replaced_item_ids: Vec::new(),
                cleanup_failed_item_ids: vec![self.prior_item],
            })
        }
    }

    #[tokio::test]
    async fn replacement_cleanup_failure_preserves_the_prior_item_id_for_registration() {
        let prior_item = Uuid::new_v4();
        let provider = Provider::new(Arc::new(FailedReplacementCleanupBroker { prior_item }));
        let (_, deleted, retained) = provider
            .create_item(
                Uuid::new_v4(),
                "Replacement".to_owned(),
                BTreeMap::new(),
                "application/octet-stream".to_owned(),
                SecretBytes::new(vec![1]).unwrap(),
                true,
            )
            .await
            .unwrap();
        assert!(deleted.is_empty());
        assert_eq!(retained, vec![prior_item]);
    }

    #[tokio::test]
    async fn aliases_lifecycle_and_search_subset() {
        let provider = provider();
        let collection = provider
            .create_collection("Passwords".to_owned())
            .await
            .unwrap();
        provider
            .set_alias("default".to_owned(), Some(collection.id))
            .await
            .unwrap();
        assert_eq!(
            provider
                .resolve_alias("default".to_owned())
                .await
                .unwrap()
                .unwrap()
                .collection_id,
            collection.id
        );
        let (item, _, _) = provider
            .create_item(
                collection.id,
                "credential".to_owned(),
                BTreeMap::from([
                    ("service".to_owned(), "example.test".to_owned()),
                    ("user".to_owned(), "unicode-å".to_owned()),
                ]),
                "application/octet-stream".to_owned(),
                SecretBytes::new(vec![0, 128, 255]).unwrap(),
                false,
            )
            .await
            .unwrap();
        let found = provider
            .search(BTreeMap::from([(
                "service".to_owned(),
                "example.test".to_owned(),
            )]))
            .await
            .unwrap();
        assert_eq!(found, vec![item]);
    }

    #[tokio::test]
    async fn lists_persisted_arbitrary_default_and_session_aliases_after_reload() {
        let broker = Arc::new(InMemoryBroker::new());
        let provider = Provider::new(broker.clone());
        let first = provider
            .create_collection("First".to_owned())
            .await
            .unwrap();
        let second = provider
            .create_collection("Second".to_owned())
            .await
            .unwrap();
        provider
            .set_alias("arbitrary".to_owned(), Some(second.id))
            .await
            .unwrap();
        provider
            .set_alias("default".to_owned(), Some(first.id))
            .await
            .unwrap();
        provider
            .set_alias("session".to_owned(), Some(second.id))
            .await
            .unwrap();

        let aliases = provider.aliases().await.unwrap();
        assert_eq!(
            aliases
                .iter()
                .map(|alias| alias.name.as_str())
                .collect::<Vec<_>>(),
            vec!["arbitrary", "default", "session"]
        );
        assert_eq!(aliases[0].collection_id, second.id);

        provider
            .set_alias("arbitrary".to_owned(), None)
            .await
            .unwrap();
        let reloaded = Provider::new(broker);
        assert_eq!(
            reloaded
                .aliases()
                .await
                .unwrap()
                .into_iter()
                .map(|alias| alias.name)
                .collect::<Vec<_>>(),
            vec!["default", "session"]
        );
    }

    struct FailingAliasBroker;

    #[async_trait]
    impl BrokerClient for FailingAliasBroker {
        async fn call(&self, operation: Operation) -> Result<ResponseBody> {
            if matches!(operation, Operation::ListAliases) {
                return Err(ProviderError::Broker(BrokerError::new(
                    ErrorCode::BackendUnavailable,
                    "broker is unavailable",
                )));
            }
            Err(ProviderError::Transport)
        }
    }

    #[tokio::test]
    async fn propagates_list_aliases_broker_errors() {
        let provider = Provider::new(Arc::new(FailingAliasBroker));
        assert!(matches!(
            provider.aliases().await,
            Err(ProviderError::Broker(BrokerError {
                code: ErrorCode::BackendUnavailable,
                ..
            }))
        ));
    }

    #[tokio::test]
    async fn sessions_are_caller_scoped_and_enforce_secret_limit() {
        let provider = provider();
        let (_, session, key) = Provider::open_session("plain", variant(String::new())).unwrap();
        provider
            .insert_session(session, ":1.5".to_owned(), key)
            .await;
        let oversized = (
            path(&session_path(session)),
            Vec::new(),
            vec![0_u8; MAX_SECRET_BYTES + 1],
            "application/octet-stream".to_owned(),
        );
        assert!(matches!(
            provider.decode_secret(":1.5", oversized).await,
            Err(ProviderError::SecretTooLarge)
        ));
        let (_, other, _) = Provider::open_session("plain", variant(String::new())).unwrap();
        assert!(matches!(
            provider
                .encode_secret(
                    ":1.5",
                    other,
                    SecretBytes::new(b"secret".to_vec()).unwrap(),
                    "text/plain".to_owned()
                )
                .await,
            Err(ProviderError::InvalidSession)
        ));
        assert_eq!(provider.remove_owner(":1.5").await, vec![session]);
        assert!(matches!(
            provider
                .encode_secret(
                    ":1.5",
                    session,
                    SecretBytes::new(b"secret".to_vec()).unwrap(),
                    "text/plain".to_owned()
                )
                .await,
            Err(ProviderError::InvalidSession)
        ));
    }

    #[tokio::test]
    async fn dh_secret_responses_use_fresh_ivs_and_round_trip() {
        let provider = provider();
        let session = Uuid::new_v4();
        provider
            .insert_session(
                session,
                ":1.5".to_owned(),
                SessionKey::Dh { key: [0x5A; 16] },
            )
            .await;
        let first = provider
            .encode_secret(
                ":1.5",
                session,
                SecretBytes::new(b"secret".to_vec()).unwrap(),
                "text/plain".to_owned(),
            )
            .await
            .unwrap();
        let second = provider
            .encode_secret(
                ":1.5",
                session,
                SecretBytes::new(b"secret".to_vec()).unwrap(),
                "text/plain".to_owned(),
            )
            .await
            .unwrap();
        assert_ne!(first.1, second.1);
        let key = SessionKey::Dh { key: [0x5A; 16] };
        assert_eq!(key.decrypt(&first.1, &first.2).unwrap(), b"secret");
        assert_eq!(key.decrypt(&second.1, &second.2).unwrap(), b"secret");
    }

    #[test]
    fn rejects_bad_item_properties() {
        assert!(item_properties(&HashMap::new()).is_err());
    }

    #[tokio::test]
    async fn validates_alias_unicode_and_utf8_boundaries_before_broker_calls() {
        let provider = provider();
        let collection = provider
            .create_collection("Aliases".to_owned())
            .await
            .unwrap();
        let valid = format!(
            "{}x",
            "é".repeat((wincred_libsecret_protocol::MAX_ALIAS_BYTES - 1) / "é".len())
        );
        provider
            .set_alias(valid.clone(), Some(collection.id))
            .await
            .unwrap();
        assert_eq!(
            provider
                .resolve_alias(valid.clone())
                .await
                .unwrap()
                .map(|alias| alias.collection_id),
            Some(collection.id)
        );
        assert!(matches!(
            provider
                .set_alias(format!("{valid}é"), Some(collection.id))
                .await,
            Err(ProviderError::InvalidRequest(_))
        ));
    }

    #[tokio::test]
    async fn sessions_support_binary_boundary_values_and_owner_scoped_close() {
        let provider = provider();
        let (_, session, key) = Provider::open_session("plain", variant(String::new())).unwrap();
        provider
            .insert_session(session, ":1.10".to_owned(), key)
            .await;
        let encoded = provider
            .encode_secret(
                ":1.10",
                session,
                SecretBytes::new(vec![0xA5; MAX_SECRET_BYTES]).unwrap(),
                "application/octet-stream".to_owned(),
            )
            .await
            .unwrap();
        let (_, decoded, content_type) = provider.decode_secret(":1.10", encoded).await.unwrap();
        assert_eq!(decoded.len(), MAX_SECRET_BYTES);
        assert_eq!(content_type, "application/octet-stream");
        assert!(matches!(
            provider.close_session(session, ":1.11").await,
            Err(ProviderError::InvalidSession)
        ));
        provider.close_session(session, ":1.10").await.unwrap();
        assert!(matches!(
            provider
                .encode_secret(
                    ":1.10",
                    session,
                    SecretBytes::new(vec![0xA5; 1]).unwrap(),
                    "application/octet-stream".to_owned(),
                )
                .await,
            Err(ProviderError::InvalidSession)
        ));
    }

    #[test]
    fn rejects_malformed_session_algorithms_and_crypto_inputs() {
        assert!(matches!(
            Provider::open_session("plain", variant("unexpected".to_owned())),
            Err(ProviderError::InvalidRequest(_))
        ));
        assert!(matches!(
            Provider::open_session(
                "dh-ietf1024-sha256-aes128-cbc-pkcs7",
                variant(Vec::<u8>::new())
            ),
            Err(ProviderError::InvalidRequest(_))
        ));
        assert!(matches!(
            Provider::open_session("unsupported", variant(String::new())),
            Err(ProviderError::InvalidRequest(_))
        ));
    }

    #[tokio::test]
    async fn update_and_delete_operations_keep_the_in_memory_contract() {
        let provider = provider();
        let collection = provider
            .create_collection("Mutable".to_owned())
            .await
            .unwrap();
        let (item, _, _) = provider
            .create_item(
                collection.id,
                "Original".to_owned(),
                BTreeMap::from([("kind".to_owned(), "test".to_owned())]),
                "application/octet-stream".to_owned(),
                SecretBytes::new(vec![0; 1]).unwrap(),
                false,
            )
            .await
            .unwrap();
        let (mut update, _) = provider.item(item.id, false).await.unwrap();
        update.label = "Updated".to_owned();
        let updated = provider.update_item(update, None).await.unwrap();
        assert_eq!(updated.label, "Updated");
        provider.delete_collection(collection.id).await.unwrap();
        assert!(matches!(
            provider.item(item.id, false).await,
            Err(ProviderError::Broker(BrokerError {
                code: ErrorCode::NotFound,
                ..
            }))
        ));
    }
}
