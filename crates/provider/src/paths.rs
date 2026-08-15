//! Stable, valid D-Bus paths for persistent protocol UUIDs.

use uuid::Uuid;

pub const SERVICE_PATH: &str = "/org/freedesktop/secrets";
pub const COMPAT_PROMPT_PATH: &str = "/org/freedesktop/secrets/prompt/compatibility";

fn segment(prefix: char, id: Uuid) -> String {
    format!("{prefix}{}", id.simple())
}

#[must_use]
pub fn collection_path(id: Uuid) -> String {
    format!("{SERVICE_PATH}/collection/{}", segment('c', id))
}

#[must_use]
pub fn item_path(id: Uuid) -> String {
    format!("{SERVICE_PATH}/item/{}", segment('i', id))
}

#[must_use]
pub fn session_path(id: Uuid) -> String {
    format!("{SERVICE_PATH}/session/{}", segment('s', id))
}

#[must_use]
pub fn alias_path(name: &str) -> Option<String> {
    (!name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'))
    .then(|| format!("{SERVICE_PATH}/aliases/{name}"))
}

fn parse(path: &str, kind: &str, prefix: char) -> Option<Uuid> {
    let value = path.strip_prefix(&format!("{SERVICE_PATH}/{kind}/"))?;
    let value = value.strip_prefix(prefix)?;
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Uuid::parse_str(value).ok()
}

#[must_use]
pub fn collection_id(path: &str) -> Option<Uuid> {
    parse(path, "collection", 'c')
}

#[must_use]
pub fn item_id(path: &str) -> Option<Uuid> {
    parse(path, "item", 'i')
}

#[must_use]
pub fn session_id(path: &str) -> Option<Uuid> {
    parse(path, "session", 's')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_stable_and_valid() {
        let id = Uuid::parse_str("01234567-89ab-cdef-0123-456789abcdef").unwrap();
        assert_eq!(
            collection_path(id),
            "/org/freedesktop/secrets/collection/c0123456789abcdef0123456789abcdef"
        );
        assert_eq!(collection_id(&collection_path(id)), Some(id));
        assert_eq!(item_id(&item_path(id)), Some(id));
        assert_eq!(session_id(&session_path(id)), Some(id));
    }

    #[test]
    fn rejects_paths_outside_our_namespace() {
        assert_eq!(
            collection_id("/org/freedesktop/secrets/collection/0123"),
            None
        );
        assert_eq!(item_id("/org/freedesktop/secrets/collection/c0123"), None);
    }

    #[test]
    fn creates_object_paths_only_for_safe_dbus_alias_segments() {
        assert_eq!(
            alias_path("default").as_deref(),
            Some("/org/freedesktop/secrets/aliases/default")
        );
        assert!(alias_path("session_1").is_some());
        assert_eq!(alias_path(""), None);
        assert_eq!(alias_path("arbitrary-persisted"), None);
        assert_eq!(alias_path("默认"), None);
    }
}
