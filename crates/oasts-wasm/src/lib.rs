//! WebAssembly front-end for the compiler.
//!
//! Marshalling only. The core stays the single source of truth for diagnostics and emission, the
//! same rule the Node binding follows, so a browser and a CLI compiling the same document emit the
//! same bytes.
//!
//! The boundary is one length-prefixed JSON blob in and one out, which is why the module declares
//! no imports and needs no JavaScript glue. A caller allocates with [`oasts_alloc`], writes the
//! request, calls [`oasts_generate`], reads a little-endian `u32` length followed by that many
//! bytes of UTF-8 JSON, and releases both buffers with [`oasts_free`].
//!
//! Request: `{"spec": "<OpenAPI document>", "config": { ... }}`.
//! Response: `{"files": [{"path", "content"}], "diagnostics": [ ... ], "error": null}`, where
//! `error` is non-null only when the request itself could not be read — a compiler failure is
//! reported as diagnostics with no files, exactly as the other front-ends report it.

use std::alloc::{self, Layout};
use std::ptr;
use std::slice;

use oasts_core::diag::{Diagnostic, Severity};
use oasts_core::pipeline::compile_in_memory;
use serde_json::{Value, json};

/// Width of the little-endian length written ahead of every response body.
const LENGTH_PREFIX: usize = 4;

/// Every buffer crossing the boundary is a plain byte run, so alignment is 1.
fn layout(len: usize) -> Layout {
    Layout::from_size_align(len, 1).expect("a byte layout of any length is valid")
}

/// Reserves `len` bytes for the caller to write a request into.
///
/// Returns null for a zero-length request, which is not a request.
#[unsafe(no_mangle)]
pub extern "C" fn oasts_alloc(len: usize) -> *mut u8 {
    if len == 0 {
        return ptr::null_mut();
    }
    // SAFETY: `len` is non-zero, so the layout describes a non-zero allocation.
    unsafe { alloc::alloc(layout(len)) }
}

/// Releases a buffer obtained from [`oasts_alloc`] or [`oasts_generate`].
///
/// # Safety
///
/// `ptr` must be null or a buffer this module allocated, and `len` must be the length it was
/// allocated with: for a response, the length prefix plus the body it announces. A buffer must not
/// be released twice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oasts_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    // SAFETY: the contract above requires `ptr` to come from this module's allocator with exactly
    // this length, which is the layout reconstructed here.
    unsafe { alloc::dealloc(ptr, layout(len)) };
}

/// Compiles one request into a length-prefixed JSON response.
///
/// The returned buffer belongs to the caller and is released with [`oasts_free`].
///
/// # Safety
///
/// `request` must be null or point at `len` initialised bytes in one live allocation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oasts_generate(request: *const u8, len: usize) -> *mut u8 {
    let request = if request.is_null() || len == 0 {
        &[][..]
    } else {
        // SAFETY: the caller passes a pointer and length from `oasts_alloc`, so the run is one
        // live allocation of exactly `len` initialised bytes.
        unsafe { slice::from_raw_parts(request, len) }
    };
    length_prefixed(&generate(request))
}

/// Copies `body` into a fresh buffer behind its own little-endian `u32` length.
fn length_prefixed(body: &str) -> *mut u8 {
    let body = body.as_bytes();
    let announced =
        u32::try_from(body.len()).expect("a response shorter than a wasm address space");
    let total = LENGTH_PREFIX + body.len();
    // SAFETY: `total` is at least the prefix width, so the allocation is non-zero.
    let buffer = unsafe { alloc::alloc(layout(total)) };
    if buffer.is_null() {
        return buffer;
    }
    // SAFETY: `buffer` owns `total` bytes, which is exactly what the two writes below fill.
    unsafe {
        ptr::copy_nonoverlapping(announced.to_le_bytes().as_ptr(), buffer, LENGTH_PREFIX);
        ptr::copy_nonoverlapping(body.as_ptr(), buffer.add(LENGTH_PREFIX), body.len());
    }
    buffer
}

/// The whole boundary, with no pointers in it.
fn generate(request: &[u8]) -> String {
    let request = match serde_json::from_slice::<Value>(request) {
        Ok(request) => request,
        Err(error) => return failed(&format!("request is not valid JSON: {error}")),
    };
    let Some(spec) = request.get("spec").and_then(Value::as_str) else {
        return failed("request.spec must be the OpenAPI document as a string");
    };
    let Some(config) = request.get("config") else {
        return failed("request.config must be the configuration object");
    };
    let config = serde_json::to_vec(config).expect("a parsed JSON value re-serializes");

    match compile_in_memory(spec.as_bytes(), &config) {
        Ok(compiled) => json!({
            "files": compiled
                .files
                .iter()
                .map(|file| json!({ "path": file.relative_path, "content": file.content }))
                .collect::<Vec<_>>(),
            "diagnostics": rendered(&compiled.diagnostics),
            "error": Value::Null,
        })
        .to_string(),
        Err(diagnostics) => json!({
            "files": [],
            "diagnostics": rendered(&diagnostics),
            "error": Value::Null,
        })
        .to_string(),
    }
}

/// A response for a request this module could not read at all.
fn failed(reason: &str) -> String {
    json!({ "files": [], "diagnostics": [], "error": reason }).to_string()
}

/// The cross-boundary diagnostic shape, matching the Node binding's field for field.
fn rendered(diagnostics: &[Diagnostic]) -> Vec<Value> {
    diagnostics
        .iter()
        .map(|diagnostic| {
            json!({
                "code": diagnostic.code,
                "severity": match diagnostic.severity {
                    Severity::Error => "error",
                    Severity::Warning => "warning",
                },
                "message": diagnostic.message,
                "sourceId": diagnostic.source_id,
                "line": diagnostic.line,
                "col": diagnostic.col,
                "jsonPointer": diagnostic.json_pointer,
            })
        })
        .collect()
}
