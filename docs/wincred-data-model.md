# WinCred schema and data model

## Namespace and target grammar

Every persistent credential is a Windows Credential Manager **generic**
credential with `CRED_PERSIST_LOCAL_MACHINE` and this exact target prefix:

```text
WinCredLibSecret/v1/
```

The broker's typed target parser accepts only canonical lowercase UUIDs and
only these shapes:

| Purpose | Target |
| --- | --- |
| Collection metadata | `WinCredLibSecret/v1/collection/<collection-uuid>` |
| Alias metadata | `WinCredLibSecret/v1/alias/<base64url-no-padding-utf8-alias>` |
| Item metadata | `WinCredLibSecret/v1/item/<item-uuid>/meta` |
| Item secret generation | `WinCredLibSecret/v1/item/<item-uuid>/secret/<generation-uuid>` |

Aliases are UTF-8 then base64url encoded without padding, so a slash or
Unicode character in the alias cannot alter the target path. A malformed
owned-looking target is rejected; a target outside this prefix is foreign.
The backend enumerates with the prefix filter and the broker validates parsed
names before mutation. There is no operation that accepts an arbitrary
Credential Manager target, so this provider cannot browse, read, overwrite,
or delete another application's credential.

## CBOR metadata

Collection metadata stores:

```text
schema_version, id, label, created, modified
```

Item metadata stores:

```text
schema_version, id, collection_id, label, attributes, content_type,
created, modified, current_generation
```

Alias metadata stores:

```text
schema_version, name, collection_id
```

`id`, `collection_id`, and `current_generation` are UUIDs. Timestamps are
unsigned 64-bit values supplied by the service layer. Attributes are a
deterministically ordered string map. Metadata blobs are CBOR and are limited
to 2,560 bytes, matching the native WinCred credential-blob maximum.

## Limits and encoding

| Field | Rule |
| --- | --- |
| Secret | Binary bytes, maximum 2,560 bytes |
| Metadata blob | CBOR, maximum 2,560 bytes |
| Label | Nonempty UTF-8, no NUL, maximum 1,024 UTF-8 bytes |
| Alias | Nonempty UTF-8, no NUL, maximum 255 UTF-8 bytes |
| Content type | Nonempty UTF-8, no NUL, maximum 255 UTF-8 bytes |
| Attributes | At most 64 entries |
| Attribute key | Nonempty UTF-8, no NUL, maximum 255 UTF-8 bytes |
| Attribute value | UTF-8, no NUL, may be empty, maximum 1,024 UTF-8 bytes |

Byte limits are not character counts. Unicode is preserved as UTF-8 subject
to those limits. Secrets are not UTF-8 strings: all byte values, including
NUL, round-trip. A 2,560-byte secret is valid and a 2,561-byte secret is
rejected before it reaches the Windows API.

## Generation commit protocol

Item metadata is the commit record. For create or replacement, the broker:

1. writes the new binary secret at a fresh generation target;
2. writes item metadata whose `current_generation` names that generation;
3. deletes the prior generation, when there is one and it differs.

Thus a crash before step 2 leaves an uncommitted generation that is not
visible. A crash after step 2 can leave an old generation, but the metadata
already selects the new secret. Operations are serialized through the
cross-process mutex `Local\WinCredLibSecret-v1-broker`.

At broker startup and on explicit reconciliation, inventory is compared with
the metadata commit records:

- a stored generation that no metadata commits is deleted as abandoned;
- metadata that commits a missing generation is reported as a corrupt item,
  not deleted or guessed;
- malformed names/metadata are treated as corruption rather than a basis for
  unvalidated mutations.

This is recoverable consistency, not transactionality across Windows APIs or a
defense against a trusted vault principal deliberately replacing data.

## Collection and item removal

Deleting an item removes its metadata and every enumerated stored generation
for that item. Deleting a collection removes its collection metadata, valid
aliases that reference it, and items/generations identified by valid item
metadata. Missing target deletion is idempotent. The same project namespace is
shared by all enabled distros and Linux users under one Windows user; IDs
prevent accidental collision but do not create per-distro tenancy.

## Service view

The provider exposes standard Secret Service object paths:

```text
/org/freedesktop/secrets
/org/freedesktop/secrets/collection/c<32-hex-uuid>
/org/freedesktop/secrets/item/i<32-hex-uuid>
/org/freedesktop/secrets/session/s<32-hex-uuid>
```

Aliases whose names are valid D-Bus path segments are also available below
`/org/freedesktop/secrets/aliases/`. Persisted aliases need not be limited to
that path-safe subset; the metadata representation remains Unicode-safe.

Collections are always reported unlocked. `Lock`, `Unlock`, and the
compatibility Prompt object preserve API compatibility but do not create a
new passphrase, authentication prompt, or encryption layer.
