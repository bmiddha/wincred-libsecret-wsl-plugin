#![cfg(windows)]

use std::{
    collections::BTreeMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use uuid::Uuid;
use wincred_libsecret_broker::{Broker, VaultBackend, WinCredBackend};
use wincred_libsecret_protocol::{
    AliasMetadata, CollectionMetadata, ErrorCode, ItemMetadata, Operation, ResponseBody,
    SecretBytes,
};

struct Cleanup<'a> {
    broker: &'a Broker<WinCredBackend>,
    collection_id: Uuid,
}

impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        let _ = self.broker.execute(Operation::DeleteCollection {
            collection_id: self.collection_id,
        });
    }
}

static WINCRED_TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
#[ignore = "uses the current user's Windows Credential Manager"]
fn wincred_crud_uses_only_randomized_project_ids_and_cleans_up() {
    assert_eq!(
        std::env::var("WINCRED_LIVE_TESTS").as_deref(),
        Ok("1"),
        "set WINCRED_LIVE_TESTS=1 to permit this live test"
    );
    let _serial = WINCRED_TEST_LOCK.lock().unwrap();
    let broker = Broker::new(WinCredBackend::new());
    let collection = CollectionMetadata {
        schema_version: 1,
        id: Uuid::new_v4(),
        label: format!("integration-{}", Uuid::new_v4()),
        created: 1,
        modified: 1,
    };
    let _cleanup = Cleanup {
        broker: &broker,
        collection_id: collection.id,
    };

    broker
        .execute(Operation::CreateCollection {
            collection: collection.clone(),
        })
        .unwrap();
    let alias = AliasMetadata {
        schema_version: 1,
        name: format!("integration-{}", Uuid::new_v4()),
        collection_id: collection.id,
    };
    broker
        .execute(Operation::SetAlias {
            alias: alias.clone(),
        })
        .unwrap();
    let ResponseBody::Aliases(aliases) = broker.execute(Operation::ListAliases).unwrap() else {
        panic!("expected aliases");
    };
    assert!(aliases.contains(&alias));
    let item = ItemMetadata {
        schema_version: 1,
        id: Uuid::new_v4(),
        collection_id: collection.id,
        label: "integration item".to_owned(),
        attributes: BTreeMap::from([("scope".to_owned(), "integration".to_owned())]),
        content_type: "application/octet-stream".to_owned(),
        created: 1,
        modified: 1,
        current_generation: Uuid::new_v4(),
    };
    let secret = SecretBytes::new(vec![0, 255, 0, 1]).unwrap();
    broker
        .execute(Operation::CreateItem {
            item: item.clone(),
            secret: secret.clone(),
        })
        .unwrap();
    assert_eq!(
        broker
            .execute(Operation::GetItem {
                item_id: item.id,
                include_secret: true,
            })
            .unwrap(),
        ResponseBody::Item {
            item,
            secret: Some(secret),
        }
    );
    assert_eq!(
        broker
            .execute(Operation::DeleteCollection {
                collection_id: collection.id,
            })
            .unwrap(),
        ResponseBody::Empty
    );
}

#[test]
#[ignore = "uses the current user's Windows Credential Manager"]
fn wincred_global_user_mutex_serializes_contending_threads() {
    assert_eq!(
        std::env::var("WINCRED_LIVE_TESTS").as_deref(),
        Ok("1"),
        "set WINCRED_LIVE_TESTS=1 to permit this live test"
    );
    let _serial = WINCRED_TEST_LOCK.lock().unwrap();
    let held = WinCredBackend::new().acquire_lock().unwrap();
    let started = Instant::now();
    let error = std::thread::spawn(|| match WinCredBackend::new().acquire_lock() {
        Ok(_) => panic!("contending mutex acquisition unexpectedly succeeded"),
        Err(error) => error,
    })
    .join()
    .unwrap();
    assert_eq!(error.code, ErrorCode::Conflict);
    assert!(
        started.elapsed() >= Duration::from_secs(4),
        "mutex contention returned before its bounded wait"
    );
    drop(held);
}
