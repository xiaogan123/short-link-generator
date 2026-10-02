//! Source-only binding to the frozen private C credential client ABI.
//! This crate is not wired into the application or a signed XPC service.

use std::ffi::{c_char, CString};
use std::fmt;
use std::ptr;
use zeroize::Zeroizing;

pub const VALUE_MAX: usize = 16 * 1024;
pub const ACCOUNT_ID_MAX: usize = 64;
pub const LOCATION_ID_LENGTH: usize = 32;

const OP_CURRENT_READ: i32 = 1;
const OP_CURRENT_UPSERT: i32 = 2;
const OP_CURRENT_DELETE: i32 = 3;
const OP_CURRENT_CREATE_ONLY: i32 = 4;
const OP_EXPLICIT_LEGACY_READ: i32 = 5;
const STATUS_OK: i32 = 0;
const STATUS_MISSING: i32 = 1;
const STATUS_DENIED: i32 = 2;
const STATUS_CANCELLED: i32 = 3;
const STATUS_UNAVAILABLE: i32 = 4;
const STATUS_ALREADY_EXISTS: i32 = 5;
const STATUS_INVALID: i32 = 6;
const STATUS_IPC_FAILURE: i32 = 7;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Token,
    Selftest,
    Probe,
    SelftestPending,
}
impl Kind {
    fn as_cstr(self) -> &'static [u8] {
        match self {
            Self::Token => b"token\0",
            Self::Selftest => b"selftest\0",
            Self::Probe => b"probe\0",
            Self::SelftestPending => b"selftest-pending\0",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    CurrentRead,
    CurrentUpsert,
    CurrentDelete,
    CurrentCreateOnly,
    ExplicitLegacyRead,
}
impl Operation {
    fn raw(self) -> i32 {
        match self {
            Self::CurrentRead => OP_CURRENT_READ,
            Self::CurrentUpsert => OP_CURRENT_UPSERT,
            Self::CurrentDelete => OP_CURRENT_DELETE,
            Self::CurrentCreateOnly => OP_CURRENT_CREATE_ONLY,
            Self::ExplicitLegacyRead => OP_EXPLICIT_LEGACY_READ,
        }
    }
    fn is_read(self) -> bool {
        matches!(self, Self::CurrentRead | Self::ExplicitLegacyRead)
    }
    fn is_write(self) -> bool {
        matches!(self, Self::CurrentUpsert | Self::CurrentCreateOnly)
    }
}

#[derive(Eq, PartialEq)]
pub enum Outcome {
    Value(Zeroizing<String>),
    Missing,
    Committed,
    Created,
    AlreadyExists,
}
impl fmt::Debug for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Value(_) => f.write_str("Value(<redacted>)"),
            Self::Missing => f.write_str("Missing"),
            Self::Committed => f.write_str("Committed"),
            Self::Created => f.write_str("Created"),
            Self::AlreadyExists => f.write_str("AlreadyExists"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidInput,
    Denied,
    Cancelled,
    Unavailable,
    IpcFailure,
    Protocol,
}

// Equality guard only. Callers cannot construct a Keychain path or domain.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Location([u8; LOCATION_ID_LENGTH]);

pub fn capture_location() -> Result<Location, Error> {
    let mut identity = [0u8; LOCATION_ID_LENGTH];
    let status = unsafe { product_credential_location_snapshot(identity.as_mut_ptr()) };
    if status != 0 || identity.iter().all(|byte| *byte == 0) {
        return Err(Error::Unavailable);
    }
    Ok(Location(identity))
}

// C credential_operation and credential_status are both 4-byte enums in the
// bound Mac clang ABI. i32 prevents UB from an unknown enum discriminant.
#[repr(C)]
struct CRequest {
    operation: i32,
    kind: *const c_char,
    account_id: *const c_char,
    value: *const u8,
    value_length: usize,
}
#[repr(C)]
struct CResult {
    status: i32,
    value: *mut u8,
    value_length: usize,
}

unsafe extern "C" {
    fn product_credential_location_snapshot(identity: *mut u8) -> i32;
    fn product_credential_call(
        request: *const CRequest,
        location: *const u8,
        result: *mut CResult,
    ) -> i32;
    fn product_credential_result_clear(result: *mut CResult);
}

struct ResultGuard(CResult);
impl Drop for ResultGuard {
    fn drop(&mut self) {
        // Always return C-owned storage to the matching allocator/clear ABI,
        // including malformed status, invalid UTF-8, and oversized results.
        unsafe { product_credential_result_clear(&mut self.0) }
    }
}

fn valid_account_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= ACCOUNT_ID_MAX
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Exactly one C call; no reconnect, automatic legacy fallback, or retry.
/// The caller owns input secret bytes and must keep them alive through return.
pub fn call_once(
    operation: Operation,
    kind: Kind,
    account_id: &str,
    value: Option<&str>,
    location: &Location,
) -> Result<Outcome, Error> {
    if !valid_account_id(account_id)
        || (operation.is_write() != value.is_some())
        || value.is_some_and(|v| v.len() > VALUE_MAX)
    {
        return Err(Error::InvalidInput);
    }
    let account_id = CString::new(account_id).map_err(|_| Error::InvalidInput)?;
    let value_bytes = value.map(str::as_bytes);
    let request = CRequest {
        operation: operation.raw(),
        kind: kind.as_cstr().as_ptr().cast(),
        account_id: account_id.as_ptr(),
        value: value_bytes.map_or(ptr::null(), |bytes| bytes.as_ptr()),
        value_length: value_bytes.map_or(0, <[u8]>::len),
    };
    let mut guard = ResultGuard(CResult {
        status: STATUS_INVALID,
        value: ptr::null_mut(),
        value_length: 0,
    });
    // SAFETY: request strings and byte slices remain alive for this synchronous
    // C call. The C implementation is a trusted in-process ABI component.
    let returned = unsafe { product_credential_call(&request, location.0.as_ptr(), &mut guard.0) };
    let response = &guard.0;
    if returned != response.status {
        return Err(Error::Protocol);
    }
    let status = response.status;
    if !(STATUS_OK..=STATUS_IPC_FAILURE).contains(&status) {
        return Err(Error::Protocol);
    }
    let read_success = operation.is_read() && status == STATUS_OK;
    if read_success {
        if response.value.is_null() || response.value_length > VALUE_MAX {
            return Err(Error::Protocol);
        }
        // SAFETY: for an accepted read, the trusted C ABI promises a live
        // malloc-owned allocation of at least value_length bytes. Arbitrary
        // hostile pointers cannot be made safe by Rust validation.
        let bytes = unsafe { std::slice::from_raw_parts(response.value, response.value_length) };
        let text = std::str::from_utf8(bytes).map_err(|_| Error::Protocol)?;
        return Ok(Outcome::Value(Zeroizing::new(text.to_owned())));
    }
    if !response.value.is_null() || response.value_length != 0 {
        return Err(Error::Protocol);
    }
    match (operation, status) {
        (Operation::CurrentCreateOnly, STATUS_OK) => Ok(Outcome::Created),
        (op, STATUS_OK) if !op.is_read() => Ok(Outcome::Committed),
        (op, STATUS_MISSING) if op.is_read() => Ok(Outcome::Missing),
        (Operation::CurrentCreateOnly, STATUS_ALREADY_EXISTS) => Ok(Outcome::AlreadyExists),
        (_, STATUS_DENIED) => Err(Error::Denied),
        (_, STATUS_CANCELLED) => Err(Error::Cancelled),
        (_, STATUS_UNAVAILABLE) => Err(Error::Unavailable),
        (_, STATUS_IPC_FAILURE) => Err(Error::IpcFailure),
        _ => Err(Error::Protocol),
    }
}
