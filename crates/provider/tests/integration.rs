//! Run with `dbus-run-session -- cargo test -p wincred-libsecret-provider --test integration`.

use std::{
    collections::HashMap,
    io::Write,
    process::{Command, Stdio},
    sync::Arc,
};

use sha2::{Digest, Sha256};
use wincred_libsecret_provider::{
    InMemoryBroker, Provider,
    paths::SERVICE_PATH,
    service::{SecretService, remove_owner_sessions},
};
use zbus::{
    Connection,
    zvariant::{OwnedObjectPath, OwnedValue, Value},
};

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn exposes_introspection_and_plain_session_on_a_session_bus() {
    if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none() {
        assert_ne!(
            std::env::var_os("WINCRED_REQUIRE_DBUS_TESTS").as_deref(),
            Some(std::ffi::OsStr::new("1")),
            "D-Bus integration test requires a session bus"
        );
        eprintln!("skipping D-Bus integration test: no session bus");
        return;
    }

    let provider = Provider::new(Arc::new(InMemoryBroker::new()));
    let service_connection = match Connection::session().await {
        Ok(connection) => connection,
        Err(error)
            if std::env::var_os("WINCRED_REQUIRE_DBUS_TESTS").as_deref()
                != Some(std::ffi::OsStr::new("1")) =>
        {
            eprintln!("skipping D-Bus integration test: session bus is unavailable: {error}");
            return;
        }
        Err(error) => panic!("required D-Bus session is unavailable: {error}"),
    };
    service_connection
        .object_server()
        .at(SERVICE_PATH, SecretService::new(provider.clone()))
        .await
        .unwrap();
    provider
        .initialize(service_connection.object_server())
        .await
        .unwrap();
    service_connection
        .request_name("org.freedesktop.secrets")
        .await
        .unwrap();

    let client = Connection::session().await.unwrap();
    let introspection = client
        .call_method(
            Some("org.freedesktop.secrets"),
            SERVICE_PATH,
            Some("org.freedesktop.DBus.Introspectable"),
            "Introspect",
            &(),
        )
        .await
        .unwrap()
        .body()
        .deserialize::<String>()
        .unwrap();
    assert!(introspection.contains("org.freedesktop.Secret.Service"));
    assert!(introspection.contains("OpenSession"));
    for member in [
        "CreateCollection",
        "SearchItems",
        "GetSecrets",
        "ReadAlias",
        "SetAlias",
        "Lock",
        "Unlock",
        "Collections",
        "Aliases",
        "CollectionCreated",
        "CollectionDeleted",
        "CollectionChanged",
    ] {
        assert!(
            introspection.contains(member),
            "missing service member {member}"
        );
    }

    let input: OwnedValue = Value::from("").try_to_owned().unwrap();
    let (_, session): (OwnedValue, OwnedObjectPath) = client
        .call_method(
            Some("org.freedesktop.secrets"),
            SERVICE_PATH,
            Some("org.freedesktop.Secret.Service"),
            "OpenSession",
            &("plain", input),
        )
        .await
        .unwrap()
        .body()
        .deserialize()
        .unwrap();
    assert!(
        session
            .as_str()
            .starts_with("/org/freedesktop/secrets/session/s")
    );

    let mut collection_properties = HashMap::new();
    collection_properties.insert(
        "Label".to_owned(),
        Value::from("Integration passwords").try_to_owned().unwrap(),
    );
    let (collection, prompt): (OwnedObjectPath, OwnedObjectPath) = client
        .call_method(
            Some("org.freedesktop.secrets"),
            SERVICE_PATH,
            Some("org.freedesktop.Secret.Service"),
            "CreateCollection",
            &(collection_properties, "default"),
        )
        .await
        .unwrap()
        .body()
        .deserialize()
        .unwrap();
    assert_eq!(prompt.as_str(), "/");

    let collection_introspection = client
        .call_method(
            Some("org.freedesktop.secrets"),
            collection.as_str(),
            Some("org.freedesktop.DBus.Introspectable"),
            "Introspect",
            &(),
        )
        .await
        .unwrap()
        .body()
        .deserialize::<String>()
        .unwrap();
    for member in [
        "org.freedesktop.Secret.Collection",
        "CreateItem",
        "SearchItems",
        "Items",
        "Locked",
        "ItemCreated",
        "ItemDeleted",
        "ItemChanged",
    ] {
        assert!(
            collection_introspection.contains(member),
            "missing collection member {member}"
        );
    }

    let mut item_properties = HashMap::new();
    item_properties.insert(
        "Label".to_owned(),
        Value::from("unicode 🔐").try_to_owned().unwrap(),
    );
    item_properties.insert(
        "Attributes".to_owned(),
        Value::from(HashMap::from([(
            "service".to_owned(),
            "example.test".to_owned(),
        )]))
        .try_to_owned()
        .unwrap(),
    );
    let secret = (
        session.clone(),
        Vec::<u8>::new(),
        vec![0_u8, 0xff, 0x80],
        "application/octet-stream".to_owned(),
    );
    let (item, prompt): (OwnedObjectPath, OwnedObjectPath) = client
        .call_method(
            Some("org.freedesktop.secrets"),
            collection.as_str(),
            Some("org.freedesktop.Secret.Collection"),
            "CreateItem",
            &(item_properties.clone(), secret, false),
        )
        .await
        .unwrap()
        .body()
        .deserialize()
        .unwrap();
    assert_eq!(prompt.as_str(), "/");
    let returned_secret: (OwnedObjectPath, Vec<u8>, Vec<u8>, String) = client
        .call_method(
            Some("org.freedesktop.secrets"),
            item.as_str(),
            Some("org.freedesktop.Secret.Item"),
            "GetSecret",
            &(session.clone(),),
        )
        .await
        .unwrap()
        .body()
        .deserialize()
        .unwrap();
    assert_eq!(returned_secret.2, vec![0, 0xff, 0x80]);
    assert_eq!(returned_secret.3, "application/octet-stream");

    let item_introspection = client
        .call_method(
            Some("org.freedesktop.secrets"),
            item.as_str(),
            Some("org.freedesktop.DBus.Introspectable"),
            "Introspect",
            &(),
        )
        .await
        .unwrap()
        .body()
        .deserialize::<String>()
        .unwrap();
    for member in [
        "org.freedesktop.Secret.Item",
        "GetSecret",
        "SetSecret",
        "Attributes",
        "Label",
        "SecretChanged",
    ] {
        assert!(
            item_introspection.contains(member),
            "missing item member {member}"
        );
    }

    let replacement_secret = (
        session.clone(),
        Vec::<u8>::new(),
        vec![b'r', b'e', b'p', b'l', b'a', b'c', b'e', b'd'],
        "application/octet-stream".to_owned(),
    );
    let (replacement, prompt): (OwnedObjectPath, OwnedObjectPath) = client
        .call_method(
            Some("org.freedesktop.secrets"),
            collection.as_str(),
            Some("org.freedesktop.Secret.Collection"),
            "CreateItem",
            &(item_properties, replacement_secret, true),
        )
        .await
        .unwrap()
        .body()
        .deserialize()
        .unwrap();
    assert_ne!(replacement, item);
    assert_eq!(prompt.as_str(), "/");

    let (unlocked, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) = client
        .call_method(
            Some("org.freedesktop.secrets"),
            SERVICE_PATH,
            Some("org.freedesktop.Secret.Service"),
            "SearchItems",
            &(HashMap::from([("service".to_owned(), "example.test".to_owned())])),
        )
        .await
        .unwrap()
        .body()
        .deserialize()
        .unwrap();
    assert_eq!(unlocked, vec![replacement.clone()]);
    assert!(locked.is_empty());

    let (locked, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = client
        .call_method(
            Some("org.freedesktop.secrets"),
            SERVICE_PATH,
            Some("org.freedesktop.Secret.Service"),
            "Lock",
            &(vec![collection.clone()],),
        )
        .await
        .unwrap()
        .body()
        .deserialize()
        .unwrap();
    assert_eq!(locked, vec![collection.clone()]);
    assert_eq!(prompt.as_str(), "/");
    let locked_property: OwnedValue = client
        .call_method(
            Some("org.freedesktop.secrets"),
            collection.as_str(),
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &("org.freedesktop.Secret.Collection", "Locked"),
        )
        .await
        .unwrap()
        .body()
        .deserialize()
        .unwrap();
    assert!(!bool::try_from(locked_property).unwrap());
    let (unlocked, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = client
        .call_method(
            Some("org.freedesktop.secrets"),
            SERVICE_PATH,
            Some("org.freedesktop.Secret.Service"),
            "Unlock",
            &(vec![collection.clone()],),
        )
        .await
        .unwrap()
        .body()
        .deserialize()
        .unwrap();
    assert_eq!(unlocked, vec![collection.clone()]);
    assert_eq!(prompt.as_str(), "/");

    for name in ["arbitrary-persisted", "session"] {
        client
            .call_method(
                Some("org.freedesktop.secrets"),
                SERVICE_PATH,
                Some("org.freedesktop.Secret.Service"),
                "SetAlias",
                &(name, collection.clone()),
            )
            .await
            .unwrap();
    }
    let aliases: HashMap<String, OwnedObjectPath> = client
        .call_method(
            Some("org.freedesktop.secrets"),
            SERVICE_PATH,
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &("org.freedesktop.Secret.Service", "Aliases"),
        )
        .await
        .unwrap()
        .body()
        .deserialize::<OwnedValue>()
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(aliases.get("default"), Some(&collection));
    assert_eq!(aliases.get("session"), Some(&collection));
    assert_eq!(aliases.get("arbitrary-persisted"), Some(&collection));
    client
        .call_method(
            Some("org.freedesktop.secrets"),
            SERVICE_PATH,
            Some("org.freedesktop.Secret.Service"),
            "SetAlias",
            &(
                "arbitrary-persisted",
                OwnedObjectPath::try_from("/").unwrap(),
            ),
        )
        .await
        .unwrap();
    let aliases: HashMap<String, OwnedObjectPath> = client
        .call_method(
            Some("org.freedesktop.secrets"),
            SERVICE_PATH,
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &("org.freedesktop.Secret.Service", "Aliases"),
        )
        .await
        .unwrap()
        .body()
        .deserialize::<OwnedValue>()
        .unwrap()
        .try_into()
        .unwrap();
    assert!(!aliases.contains_key("arbitrary-persisted"));

    let alias: OwnedObjectPath = client
        .call_method(
            Some("org.freedesktop.secrets"),
            SERVICE_PATH,
            Some("org.freedesktop.Secret.Service"),
            "ReadAlias",
            &("default",),
        )
        .await
        .unwrap()
        .body()
        .deserialize()
        .unwrap();
    assert_eq!(alias, collection);

    if Command::new("secret-tool")
        .arg("--version")
        .output()
        .is_ok()
    {
        let attribute = format!("component-{}", uuid::Uuid::new_v4());
        let input = b"libsecret-component-smoke";
        let output = tokio::task::spawn_blocking(move || {
            let mut store = Command::new("secret-tool")
                .args([
                    "store",
                    "--label=Component smoke",
                    "service",
                    "wincred-component-tests",
                    "id",
                    attribute.as_str(),
                ])
                .stdin(Stdio::piped())
                .spawn()
                .unwrap();
            let mut supplied = input.to_vec();
            supplied.push(b'\n');
            store.stdin.as_mut().unwrap().write_all(&supplied).unwrap();
            assert!(store.wait().unwrap().success());
            Command::new("secret-tool")
                .args([
                    "lookup",
                    "service",
                    "wincred-component-tests",
                    "id",
                    attribute.as_str(),
                ])
                .output()
                .unwrap()
        })
        .await
        .unwrap();
        assert!(output.status.success());
        let mut expected = input.to_vec();
        expected.push(b'\n');
        assert_eq!(
            Sha256::digest(&output.stdout),
            Sha256::digest(expected),
            "libsecret smoke response digest did not match"
        );
    }

    client
        .call_method(
            Some("org.freedesktop.secrets"),
            replacement.as_str(),
            Some("org.freedesktop.Secret.Item"),
            "Delete",
            &(),
        )
        .await
        .unwrap();
    let items: Vec<OwnedObjectPath> = client
        .call_method(
            Some("org.freedesktop.secrets"),
            collection.as_str(),
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &("org.freedesktop.Secret.Collection", "Items"),
        )
        .await
        .unwrap()
        .body()
        .deserialize::<OwnedValue>()
        .unwrap()
        .try_into()
        .unwrap();
    for item in items {
        client
            .call_method(
                Some("org.freedesktop.secrets"),
                item.as_str(),
                Some("org.freedesktop.Secret.Item"),
                "Delete",
                &(),
            )
            .await
            .unwrap();
    }
    let items: Vec<OwnedObjectPath> = client
        .call_method(
            Some("org.freedesktop.secrets"),
            collection.as_str(),
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &("org.freedesktop.Secret.Collection", "Items"),
        )
        .await
        .unwrap()
        .body()
        .deserialize::<OwnedValue>()
        .unwrap()
        .try_into()
        .unwrap();
    assert!(items.is_empty());

    let disconnected_client = Connection::session().await.unwrap();
    let disconnected_owner = disconnected_client.unique_name().unwrap().to_string();
    for _ in 0..3 {
        let input: OwnedValue = Value::from("").try_to_owned().unwrap();
        let (_, abandoned): (OwnedValue, OwnedObjectPath) = disconnected_client
            .call_method(
                Some("org.freedesktop.secrets"),
                SERVICE_PATH,
                Some("org.freedesktop.Secret.Service"),
                "OpenSession",
                &("plain", input),
            )
            .await
            .unwrap()
            .body()
            .deserialize()
            .unwrap();
        remove_owner_sessions(
            service_connection.object_server(),
            &provider,
            &disconnected_owner,
        )
        .await;
        assert!(
            client
                .call_method(
                    Some("org.freedesktop.secrets"),
                    abandoned.as_str(),
                    Some("org.freedesktop.DBus.Introspectable"),
                    "Introspect",
                    &(),
                )
                .await
                .is_err(),
            "disconnected session object was left registered"
        );
    }

    client
        .call_method(
            Some("org.freedesktop.secrets"),
            session.as_str(),
            Some("org.freedesktop.Secret.Session"),
            "Close",
            &(),
        )
        .await
        .unwrap();
    remove_owner_sessions(
        service_connection.object_server(),
        &provider,
        client.unique_name().unwrap().as_str(),
    )
    .await;
    assert!(
        client
            .call_method(
                Some("org.freedesktop.secrets"),
                session.as_str(),
                Some("org.freedesktop.DBus.Introspectable"),
                "Introspect",
                &(),
            )
            .await
            .is_err(),
        "explicitly closed session object was left registered"
    );
}
