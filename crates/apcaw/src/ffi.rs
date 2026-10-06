// SPDX-License-Identifier: BSD-2-Clause
//! C ABI (declared in `include/apcaw.h`).
//!
//! Conventions: keys are raw 32-byte buffers, samples are mono `double` at
//! 44100 Hz. Functions returning `int` give `0` on success, `1` when signing
//! failed for a reason tied to the input (too short, message too long, ...),
//! `-1` for invalid arguments and `-2` for an internal panic; the message of
//! the last failure on the calling thread is `apcaw_last_error()`. Strings
//! returned by the library are released with `apcaw_string_free`.

use std::cell::RefCell;
use std::ffi::{c_char, c_int, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use crate::{keygen, keygen_from_seed, verify, Options, Profile, PublicKey};

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::default());
}

fn set_error(msg: impl Into<String>) {
    let s = msg.into().replace('\0', " ");
    LAST_ERROR.with(|e| *e.borrow_mut() = CString::new(s).unwrap_or_default());
}

const OK: c_int = 0;
const FAILED: c_int = 1;
const BAD_ARGS: c_int = -1;
const PANIC: c_int = -2;

fn guard(f: impl FnOnce() -> c_int) -> c_int {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(c) => c,
        Err(_) => {
            set_error("internal error (panic)");
            PANIC
        }
    }
}

/// `NULL` or `""` means `None`; otherwise a profile id.
unsafe fn profile_arg(p: *const c_char) -> Result<Option<Profile>, String> {
    if p.is_null() {
        return Ok(None);
    }
    let s = CStr::from_ptr(p).to_str().map_err(|_| "profile is not UTF-8".to_string())?;
    if s.is_empty() || s == "auto" {
        return Ok(None);
    }
    Profile::by_id(s).map(Some).ok_or_else(|| format!("unknown profile {s:?} (expected \"wb\" or \"nb\")"))
}

unsafe fn slice<'a, T>(p: *const T, n: usize) -> &'a [T] {
    if n == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(p, n)
    }
}

unsafe fn key32(p: *const u8) -> [u8; 32] {
    let mut k = [0u8; 32];
    k.copy_from_slice(std::slice::from_raw_parts(p, 32));
    k
}

fn options(legacy: c_int) -> Options {
    if legacy != 0 {
        Options::legacy()
    } else {
        Options::v1()
    }
}

/// Library version, a static NUL-terminated string (do not free).
#[no_mangle]
pub extern "C" fn apcaw_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

/// Message of the last failure on this thread (static until the next call; do not free).
#[no_mangle]
pub extern "C" fn apcaw_last_error() -> *const c_char {
    LAST_ERROR.with(|e| e.borrow().as_ptr())
}

/// Generate a key pair from the OS RNG: 32-byte secret seed and public key.
///
/// # Safety
/// `sk_out` and `pk_out` must each be valid for 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn apcaw_keygen(sk_out: *mut u8, pk_out: *mut u8) -> c_int {
    if sk_out.is_null() || pk_out.is_null() {
        set_error("apcaw_keygen: NULL output buffer");
        return BAD_ARGS;
    }
    guard(|| {
        let kp = keygen();
        ptr::copy_nonoverlapping(kp.secret.seed().as_ptr(), sk_out, 32);
        ptr::copy_nonoverlapping(kp.public.as_bytes().as_ptr(), pk_out, 32);
        OK
    })
}

/// Derive the public key of a 32-byte secret seed.
///
/// # Safety
/// `sk` must be valid for 32 readable bytes, `pk_out` for 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn apcaw_public_key(sk: *const u8, pk_out: *mut u8) -> c_int {
    if sk.is_null() || pk_out.is_null() {
        set_error("apcaw_public_key: NULL argument");
        return BAD_ARGS;
    }
    guard(|| {
        let kp = keygen_from_seed(key32(sk));
        ptr::copy_nonoverlapping(kp.public.as_bytes().as_ptr(), pk_out, 32);
        OK
    })
}

/// Sign `n` samples at rate `sr` with the message `msg[0..msg_len]` and
/// write `n` watermarked samples to `out` (which may equal `samples`).
/// `profile` is `"wb"`, `"nb"` or NULL (WB); `legacy != 0` selects the
/// legacy algorithm. Returns 0, 1 (signing failed) or -1/-2.
///
/// # Safety
/// `samples` and `out` must be valid for `n` doubles, `sk` for 32 bytes,
/// `msg` for `msg_len` bytes (may be NULL when `msg_len == 0`), `profile`
/// NULL or a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn apcaw_sign_f64(
    samples: *const f64,
    n: usize,
    sr: u32,
    sk: *const u8,
    msg: *const u8,
    msg_len: usize,
    profile: *const c_char,
    legacy: c_int,
    out: *mut f64,
) -> c_int {
    if (samples.is_null() && n > 0) || (out.is_null() && n > 0) || sk.is_null() || (msg.is_null() && msg_len > 0) {
        set_error("apcaw_sign_f64: NULL argument");
        return BAD_ARGS;
    }
    let prof = match profile_arg(profile) {
        Ok(p) => p.unwrap_or(Profile::WB),
        Err(e) => {
            set_error(e);
            return BAD_ARGS;
        }
    };
    guard(|| {
        let x = slice(samples, n).to_vec();
        let kp = keygen_from_seed(key32(sk));
        match crate::sign(&x, sr, &kp.secret, slice(msg, msg_len), &prof, &options(legacy)) {
            Ok(y) => {
                ptr::copy_nonoverlapping(y.as_ptr(), out, n);
                OK
            }
            Err(e) => {
                set_error(e.to_string());
                FAILED
            }
        }
    })
}

/// Verify `n` samples at rate `sr` against the 32-byte public key `pk`.
/// `profile` NULL tries WB then NB; `resync != 0` adds the offset search.
/// Returns the report as a JSON object (the keys of `apcaw verify --json`
/// without `file`), to be released with `apcaw_string_free`, or NULL on
/// invalid arguments (see `apcaw_last_error`).
///
/// # Safety
/// `samples` must be valid for `n` doubles, `pk` for 32 bytes, `profile`
/// NULL or a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn apcaw_verify_f64(
    samples: *const f64,
    n: usize,
    sr: u32,
    pk: *const u8,
    profile: *const c_char,
    legacy: c_int,
    resync: c_int,
) -> *mut c_char {
    if (samples.is_null() && n > 0) || pk.is_null() {
        set_error("apcaw_verify_f64: NULL argument");
        return ptr::null_mut();
    }
    let prof = match profile_arg(profile) {
        Ok(p) => p,
        Err(e) => {
            set_error(e);
            return ptr::null_mut();
        }
    };
    let r = catch_unwind(AssertUnwindSafe(|| {
        let pk = PublicKey::from_bytes(key32(pk));
        let x = slice(samples, n);
        let rep = verify(x, sr, &pk, prof.as_ref(), &options(legacy), resync != 0);
        serde_json::to_string(&rep).expect("report serializes")
    }));
    match r {
        Ok(s) => CString::new(s).map_or(ptr::null_mut(), CString::into_raw),
        Err(_) => {
            set_error("internal error (panic)");
            ptr::null_mut()
        }
    }
}

/// Release a string returned by the library (NULL is ignored).
///
/// # Safety
/// `s` must come from this library and not have been freed.
#[no_mangle]
pub unsafe extern "C" fn apcaw_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}
