use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    AliasMetadata, BrokerError, CollectionMetadata, ItemMetadata, ProtocolError, SecretBytes,
};

/// Wire protocol version implemented by this build.
pub const PROTOCOL_VERSION: u16 = 1;

/// An inclusive range of supported protocol versions.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VersionRange {
    pub minimum: u16,
    pub maximum: u16,
}

impl VersionRange {
    #[must_use]
    pub const fn current() -> Self {
        Self {
            minimum: PROTOCOL_VERSION,
            maximum: PROTOCOL_VERSION,
        }
    }

    #[must_use]
    pub const fn contains(self, version: u16) -> bool {
        version >= self.minimum && version <= self.maximum
    }
}

/// Optional protocol behavior understood by a peer.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    BinarySecrets,
    Collections,
    Aliases,
    GenerationCommits,
    Reconciliation,
    AtomicItemMutations,
}

/// Deterministic capability set used during negotiation.
pub type CapabilitySet = BTreeSet<Capability>;

/// Initial provider handshake.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Hello {
    pub versions: VersionRange,
    pub capabilities: CapabilitySet,
}

/// Broker handshake response.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HelloAck {
    pub version: u16,
    pub capabilities: CapabilitySet,
}

/// Negotiates the highest common version and the capability intersection.
pub fn negotiate(
    client: &Hello,
    server_versions: VersionRange,
    server_capabilities: &CapabilitySet,
) -> Result<HelloAck, ProtocolError> {
    let minimum = client.versions.minimum.max(server_versions.minimum);
    let maximum = client.versions.maximum.min(server_versions.maximum);
    if minimum > maximum {
        return Err(ProtocolError::NoCommonVersion);
    }

    Ok(HelloAck {
        version: maximum,
        capabilities: client
            .capabilities
            .intersection(server_capabilities)
            .copied()
            .collect(),
    })
}

/// A top-level protocol envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Envelope<T> {
    pub version: u16,
    pub payload: T,
}

impl<T> Envelope<T> {
    #[must_use]
    pub const fn current(payload: T) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            payload,
        }
    }

    pub fn validate_version(&self) -> Result<(), ProtocolError> {
        if self.version == PROTOCOL_VERSION {
            Ok(())
        } else {
            Err(ProtocolError::UnsupportedVersion(self.version))
        }
    }
}

/// A correlated request sent to the broker.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Request {
    pub request_id: u64,
    pub operation: Operation,
}

/// Broker operations. Target names are intentionally absent from this API.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum Operation {
    Ping,
    ListCollections,
    GetCollection {
        collection_id: Uuid,
    },
    CreateCollection {
        collection: CollectionMetadata,
    },
    UpdateCollection {
        collection: CollectionMetadata,
    },
    DeleteCollection {
        collection_id: Uuid,
    },
    ListAliases,
    ResolveAlias {
        name: String,
    },
    SetAlias {
        alias: AliasMetadata,
    },
    RemoveAlias {
        name: String,
    },
    SearchItems {
        attributes: BTreeMap<String, String>,
    },
    ListItems {
        collection_id: Uuid,
    },
    GetItem {
        item_id: Uuid,
        include_secret: bool,
    },
    CreateItem {
        item: ItemMetadata,
        secret: SecretBytes,
    },
    /// Creates an item and, when requested, removes matching items only after
    /// the new generation has been durably committed.
    CreateOrReplaceItem {
        item: ItemMetadata,
        secret: SecretBytes,
        replace: bool,
    },
    UpdateItem {
        item: ItemMetadata,
        secret: Option<SecretBytes>,
    },
    /// Compares the persisted modification revision before applying an update.
    UpdateItemCas {
        item: ItemMetadata,
        secret: Option<SecretBytes>,
        expected_modified: u64,
    },
    DeleteItem {
        item_id: Uuid,
    },
    Reconcile,
}

/// A correlated broker response.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Response {
    pub request_id: u64,
    pub result: Result<ResponseBody, BrokerError>,
}

/// Successful broker response bodies.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "response", content = "value", rename_all = "snake_case")]
pub enum ResponseBody {
    Pong,
    Empty,
    Collection(CollectionMetadata),
    Collections(Vec<CollectionMetadata>),
    Aliases(Vec<AliasMetadata>),
    Alias(Option<AliasMetadata>),
    Item {
        item: ItemMetadata,
        secret: Option<SecretBytes>,
    },
    ReplacedItem {
        item: ItemMetadata,
        replaced_item_ids: Vec<Uuid>,
        #[serde(default)]
        cleanup_failed_item_ids: Vec<Uuid>,
    },
    Items(Vec<ItemMetadata>),
    Reconciled {
        removed_generations: usize,
        corrupt_items: Vec<Uuid>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capabilities(values: &[Capability]) -> CapabilitySet {
        values.iter().copied().collect()
    }

    #[test]
    fn negotiates_highest_common_version_and_capabilities() {
        let client = Hello {
            versions: VersionRange {
                minimum: 1,
                maximum: 3,
            },
            capabilities: capabilities(&[
                Capability::BinarySecrets,
                Capability::Collections,
                Capability::Aliases,
            ]),
        };
        let server = capabilities(&[Capability::Collections, Capability::GenerationCommits]);

        let negotiated = negotiate(
            &client,
            VersionRange {
                minimum: 1,
                maximum: 2,
            },
            &server,
        )
        .unwrap();

        assert_eq!(negotiated.version, 2);
        assert_eq!(
            negotiated.capabilities,
            capabilities(&[Capability::Collections])
        );
    }

    #[test]
    fn rejects_disjoint_versions() {
        let client = Hello {
            versions: VersionRange {
                minimum: 2,
                maximum: 3,
            },
            capabilities: CapabilitySet::new(),
        };

        assert!(matches!(
            negotiate(
                &client,
                VersionRange {
                    minimum: 1,
                    maximum: 1
                },
                &CapabilitySet::new()
            ),
            Err(ProtocolError::NoCommonVersion)
        ));
    }

    #[test]
    fn alias_enumeration_round_trips_on_the_wire() {
        let request = Envelope::current(Request {
            request_id: 7,
            operation: Operation::ListAliases,
        });
        let response = Envelope::current(Response {
            request_id: 7,
            result: Ok(ResponseBody::Aliases(vec![AliasMetadata {
                schema_version: 1,
                name: "default".to_owned(),
                collection_id: Uuid::new_v4(),
            }])),
        });

        let mut request_bytes = Vec::new();
        ciborium::ser::into_writer(&request, &mut request_bytes).unwrap();
        let decoded_request: Envelope<Request> =
            ciborium::de::from_reader(request_bytes.as_slice()).unwrap();
        assert_eq!(decoded_request, request);

        let mut response_bytes = Vec::new();
        ciborium::ser::into_writer(&response, &mut response_bytes).unwrap();
        let decoded_response: Envelope<Response> =
            ciborium::de::from_reader(response_bytes.as_slice()).unwrap();
        assert_eq!(decoded_response, response);
    }

    #[test]
    fn replacement_response_accepts_the_pre_cleanup_field_schema() {
        #[derive(Serialize)]
        #[serde(tag = "response", content = "value", rename_all = "snake_case")]
        enum LegacyResponseBody {
            ReplacedItem {
                item: ItemMetadata,
                replaced_item_ids: Vec<Uuid>,
            },
        }

        let item = ItemMetadata {
            schema_version: 1,
            id: Uuid::new_v4(),
            collection_id: Uuid::new_v4(),
            label: "item".to_owned(),
            attributes: BTreeMap::new(),
            content_type: "text/plain".to_owned(),
            created: 1,
            modified: 1,
            current_generation: Uuid::new_v4(),
        };
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(
            &LegacyResponseBody::ReplacedItem {
                item: item.clone(),
                replaced_item_ids: vec![Uuid::new_v4()],
            },
            &mut bytes,
        )
        .unwrap();
        let decoded: ResponseBody = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        let ResponseBody::ReplacedItem {
            item: decoded_item,
            cleanup_failed_item_ids,
            ..
        } = decoded
        else {
            panic!("expected replacement response");
        };
        assert_eq!(decoded_item, item);
        assert!(cleanup_failed_item_ids.is_empty());
    }

    #[test]
    fn decodes_and_preserves_the_v1_ping_compatibility_fixture() {
        // {"version": 1, "payload": {"request_id": 7, "operation":
        // {"operation": "ping"}}}; this fixture is deliberately independent
        // of the serializer used by the implementation.
        const V1_PING: &[u8] = &[
            0xA2, 0x67, b'v', b'e', b'r', b's', b'i', b'o', b'n', 0x01, 0x67, b'p', b'a', b'y',
            b'l', b'o', b'a', b'd', 0xA2, 0x6A, b'r', b'e', b'q', b'u', b'e', b's', b't', b'_',
            b'i', b'd', 0x07, 0x69, b'o', b'p', b'e', b'r', b'a', b't', b'i', b'o', b'n', 0xA1,
            0x69, b'o', b'p', b'e', b'r', b'a', b't', b'i', b'o', b'n', 0x64, b'p', b'i', b'n',
            b'g',
        ];
        let decoded: Envelope<Request> = ciborium::de::from_reader(V1_PING).unwrap();
        assert_eq!(
            decoded,
            Envelope::current(Request {
                request_id: 7,
                operation: Operation::Ping,
            })
        );
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&decoded, &mut encoded).unwrap();
        assert_eq!(encoded, V1_PING);
    }

    #[test]
    fn version_and_capability_mismatches_are_explicit() {
        assert!(matches!(
            Envelope::<Request> {
                version: PROTOCOL_VERSION + 1,
                payload: Request {
                    request_id: 1,
                    operation: Operation::Ping,
                },
            }
            .validate_version(),
            Err(ProtocolError::UnsupportedVersion(_))
        ));
        let client = Hello {
            versions: VersionRange::current(),
            capabilities: capabilities(&[Capability::BinarySecrets]),
        };
        let ack = negotiate(
            &client,
            VersionRange::current(),
            &capabilities(&[Capability::Aliases]),
        )
        .unwrap();
        assert!(ack.capabilities.is_empty());
    }
}
