//! Narrow Win32 Credential Manager bindings used by the production backend.

#![allow(unsafe_code)]

use std::{
    ffi::c_void,
    mem::{MaybeUninit, size_of},
    slice,
    str::FromStr,
};

use crate::{VaultBackend, backend::VaultLock};
use wincred_libsecret_protocol::{BrokerError, CREDENTIAL_PREFIX, ErrorCode, TargetName};
use windows::{
    Win32::{
        Foundation::{
            CloseHandle, ERROR_ACCESS_DENIED, ERROR_NOT_FOUND, HANDLE, HLOCAL, LocalFree,
            WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT,
        },
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            },
            Credentials::{
                CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredDeleteW,
                CredEnumerateW, CredFree, CredReadW, CredWriteW,
            },
            GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
            TOKEN_USER, TokenUser,
        },
        System::Threading::{
            CreateMutexW, GetCurrentProcess, OpenProcessToken, ReleaseMutex, WaitForSingleObject,
        },
    },
    core::{HRESULT, PCWSTR, PWSTR},
};

const LOCK_WAIT_MILLISECONDS: u32 = 5_000;
const MUTEX_PREFIX: &str = r"Global\WinCredLibSecret-v1-";

/// Production credential store backed by Windows Credential Manager.
#[derive(Clone, Copy, Debug, Default)]
pub struct WinCredBackend;

impl WinCredBackend {
    /// Constructs the backend. Credential Manager availability is checked on the first operation.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // The Win32 API returned this handle and it remains valid until this wrapper is dropped.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

struct MutexLock {
    handle: OwnedHandle,
    owns_mutex: bool,
}

impl VaultLock for MutexLock {}

impl Drop for MutexLock {
    fn drop(&mut self) {
        if self.owns_mutex {
            // This thread acquired the named mutex, so it is the only thread allowed to release it.
            let _ = unsafe { ReleaseMutex(self.handle.0) };
        }
    }
}

struct CredAllocation(*mut c_void);

impl Drop for CredAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // CredReadW and CredEnumerateW allocate through CredAlloc and require CredFree.
            unsafe { CredFree(self.0) };
        }
    }
}

impl VaultBackend for WinCredBackend {
    fn acquire_lock(&self) -> Result<Box<dyn VaultLock>, BrokerError> {
        let sid = current_user_sid()?;
        let name = wide(&mutex_name(&sid));
        let descriptor = security_descriptor_for_sid(&sid)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: false.into(),
        };
        // The NUL-terminated buffer remains alive for the duration of CreateMutexW.
        let handle =
            unsafe { CreateMutexW(Some(&raw const attributes), false, PCWSTR(name.as_ptr())) }
                .map_err(|error| map_windows_error(&error))?;
        let handle = OwnedHandle(handle);
        // Bounded waiting prevents a wedged broker process from blocking WSL indefinitely.
        match unsafe { WaitForSingleObject(handle.0, LOCK_WAIT_MILLISECONDS) } {
            WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(Box::new(MutexLock {
                handle,
                owns_mutex: true,
            })),
            WAIT_TIMEOUT => Err(BrokerError::new(
                ErrorCode::Conflict,
                "credential vault is busy",
            )),
            _ => Err(BrokerError::new(
                ErrorCode::BackendUnavailable,
                "credential vault lock failed",
            )),
        }
    }

    fn read(&self, target: &TargetName) -> Result<Option<Vec<u8>>, BrokerError> {
        let target = wide_target(target);
        let mut credential = MaybeUninit::<*mut CREDENTIALW>::zeroed();
        // CredReadW initializes the out pointer on success. The target buffer is NUL-terminated.
        match unsafe {
            CredReadW(
                PCWSTR(target.as_ptr()),
                CRED_TYPE_GENERIC,
                None,
                credential.as_mut_ptr(),
            )
        } {
            Ok(()) => {
                // Successful CredReadW returned a CredAlloc allocation and a non-null credential.
                let credential = unsafe { credential.assume_init() };
                if credential.is_null() {
                    return Err(BrokerError::new(
                        ErrorCode::BackendUnavailable,
                        "credential manager returned an empty credential",
                    ));
                }
                let allocation = CredAllocation(credential.cast());
                // The credential and blob are owned by allocation, which remains live while copying.
                let blob = unsafe { credential_blob(&*credential) };
                unsafe { wipe_credential_blob(&*credential) };
                drop(allocation);
                Ok(Some(blob))
            }
            Err(error) if is_not_found(&error) => Ok(None),
            Err(error) => Err(map_windows_error(&error)),
        }
    }

    fn write(&self, target: &TargetName, blob: &[u8]) -> Result<(), BrokerError> {
        let target = wide_target(target);
        let blob_size = u32::try_from(blob.len()).map_err(|_| {
            BrokerError::new(
                ErrorCode::SecretTooLarge,
                "credential blob exceeds WinCred limit",
            )
        })?;
        let mut credential = CREDENTIALW {
            Type: CRED_TYPE_GENERIC,
            TargetName: PWSTR(target.as_ptr().cast_mut()),
            CredentialBlobSize: blob_size,
            CredentialBlob: blob.as_ptr().cast_mut(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            ..Default::default()
        };
        // All fields point to buffers kept alive through this synchronous call.
        unsafe { CredWriteW(&raw mut credential, 0) }.map_err(|error| map_windows_error(&error))
    }

    fn delete(&self, target: &TargetName) -> Result<(), BrokerError> {
        let target = wide_target(target);
        // The target buffer remains alive for this synchronous call.
        match unsafe { CredDeleteW(PCWSTR(target.as_ptr()), CRED_TYPE_GENERIC, None) } {
            Ok(()) => Ok(()),
            Err(error) if is_not_found(&error) => Ok(()),
            Err(error) => Err(map_windows_error(&error)),
        }
    }

    fn enumerate(&self) -> Result<Vec<(String, Vec<u8>)>, BrokerError> {
        let filter = wide(&format!("{CREDENTIAL_PREFIX}*"));
        let mut count = 0_u32;
        let mut credentials: *mut *mut CREDENTIALW = std::ptr::null_mut();
        // The filter is prefix-only; Credential Manager allocates one CredAlloc block on success.
        match unsafe {
            CredEnumerateW(
                PCWSTR(filter.as_ptr()),
                None,
                &raw mut count,
                &raw mut credentials,
            )
        } {
            Ok(()) => {}
            Err(error) if is_not_found(&error) => return Ok(Vec::new()),
            Err(error) => return Err(map_windows_error(&error)),
        }
        if credentials.is_null() {
            return Err(BrokerError::new(
                ErrorCode::BackendUnavailable,
                "credential manager returned an empty enumeration",
            ));
        }
        let allocation = CredAllocation(credentials.cast());
        let count = usize::try_from(count).map_err(|_| {
            BrokerError::new(
                ErrorCode::BackendUnavailable,
                "credential manager returned an invalid enumeration",
            )
        })?;
        // CredEnumerateW guarantees an array of count credential pointers until CredFree.
        let pointers = unsafe { slice::from_raw_parts(credentials, count) };
        let mut entries = Vec::with_capacity(count);
        for &credential in pointers {
            if credential.is_null() {
                continue;
            }
            // Both fields reside in the CredAlloc allocation, which is still owned by allocation.
            let credential = unsafe { &*credential };
            if credential.Type != CRED_TYPE_GENERIC {
                continue;
            }
            let Ok(name) = (unsafe { PCWSTR(credential.TargetName.0).to_string() }) else {
                continue;
            };
            if !name.starts_with(CREDENTIAL_PREFIX) {
                continue;
            }
            if matches!(
                TargetName::from_str(&name),
                Ok(TargetName::ItemSecret { .. })
            ) {
                entries.push((name, Vec::new()));
                continue;
            }
            let blob = unsafe { credential_blob(credential) };
            entries.push((name, blob));
        }
        for &credential in pointers {
            if !credential.is_null() {
                unsafe { wipe_credential_blob(&*credential) };
            }
        }
        drop(allocation);
        Ok(entries)
    }
}

unsafe fn credential_blob(credential: &CREDENTIALW) -> Vec<u8> {
    let length = credential.CredentialBlobSize as usize;
    if length == 0 {
        return Vec::new();
    }
    if credential.CredentialBlob.is_null() {
        return Vec::new();
    }
    // Credential Manager promises CredentialBlobSize bytes when CredentialBlob is non-null.
    unsafe { slice::from_raw_parts(credential.CredentialBlob, length).to_vec() }
}

unsafe fn wipe_credential_blob(credential: &CREDENTIALW) {
    let length = credential.CredentialBlobSize as usize;
    if length != 0 && !credential.CredentialBlob.is_null() {
        // The allocation remains owned by CredAlloc until CredFree runs.
        unsafe { std::ptr::write_bytes(credential.CredentialBlob, 0, length) };
    }
}

struct LocalSecurityDescriptor(*mut c_void);

impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            let _ = unsafe { LocalFree(Some(HLOCAL(self.0))) };
        }
    }
}

fn current_user_sid() -> Result<String, BrokerError> {
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) }
        .map_err(|error| map_windows_error(&error))?;
    let token = OwnedHandle(token);
    let mut length = 0_u32;
    let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &raw mut length) };
    if length == 0 {
        return Err(BrokerError::new(
            ErrorCode::BackendUnavailable,
            "current user SID unavailable",
        ));
    }
    let word_count = (length as usize).div_ceil(size_of::<usize>());
    let mut buffer = vec![0_usize; word_count];
    unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            length,
            &raw mut length,
        )
    }
    .map_err(|error| map_windows_error(&error))?;
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut sid = PWSTR::null();
    unsafe { ConvertSidToStringSidW(user.User.Sid, &raw mut sid) }
        .map_err(|error| map_windows_error(&error))?;
    let sid_memory = LocalSecurityDescriptor(sid.0.cast());
    let value = unsafe { sid.to_string() }.map_err(|_| {
        BrokerError::new(
            ErrorCode::BackendUnavailable,
            "current user SID unavailable",
        )
    })?;
    drop(sid_memory);
    Ok(value)
}

fn security_descriptor_for_sid(sid: &str) -> Result<LocalSecurityDescriptor, BrokerError> {
    let sddl = wide(&mutex_sddl(sid));
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            1,
            &raw mut descriptor,
            None,
        )
    }
    .map_err(|error| map_windows_error(&error))?;
    Ok(LocalSecurityDescriptor(descriptor.0.cast()))
}

fn mutex_name(sid: &str) -> String {
    format!("{MUTEX_PREFIX}{sid}")
}

fn mutex_sddl(sid: &str) -> String {
    format!("D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{sid})")
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn wide_target(target: &TargetName) -> Vec<u16> {
    wide(&target.to_string())
}

fn is_not_found(error: &windows::core::Error) -> bool {
    error.code() == HRESULT::from_win32(ERROR_NOT_FOUND.0)
}

fn map_windows_error(error: &windows::core::Error) -> BrokerError {
    let code = if error.code() == HRESULT::from_win32(ERROR_ACCESS_DENIED.0) {
        ErrorCode::PermissionDenied
    } else {
        ErrorCode::BackendUnavailable
    };
    BrokerError::new(code, "Windows Credential Manager operation failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutex_name_is_global_and_user_namespaced() {
        assert_eq!(
            mutex_name("S-1-5-21-1"),
            r"Global\WinCredLibSecret-v1-S-1-5-21-1"
        );
        assert_ne!(mutex_name("S-1-5-21-1"), mutex_name("S-1-5-21-2"));
    }

    #[test]
    fn descriptor_accepts_system_admin_and_user() {
        let descriptor = security_descriptor_for_sid("S-1-5-18").unwrap();
        assert!(!descriptor.0.is_null());
    }

    #[test]
    fn mutex_acl_grants_the_sid_system_and_administrators() {
        assert_eq!(
            mutex_sddl("S-1-5-21-1"),
            "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;S-1-5-21-1)"
        );
    }

    #[test]
    fn wiping_credential_blob_clears_the_source_allocation() {
        let mut blob = vec![0x5a; 16];
        let credential = CREDENTIALW {
            CredentialBlobSize: u32::try_from(blob.len()).unwrap(),
            CredentialBlob: blob.as_mut_ptr(),
            ..Default::default()
        };
        unsafe { wipe_credential_blob(&credential) };
        assert!(blob.iter().all(|byte| *byte == 0));
    }
}
