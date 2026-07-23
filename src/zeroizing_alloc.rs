// SPDX-License-Identifier: Apache-2.0
//! Zeroizing allocator wrapper for the WASM build.
//!
//! ## Why
//!
//! The wasm-bindgen pattern for returning byte arrays to JS goes:
//!
//! 1. Rust function returns `Box<[u8]>` containing secret material.
//! 2. wasm-bindgen glue gets the (ptr, len) pair.
//! 3. JS calls `slice` on the WASM memory view to copy bytes into
//! a JS-managed Uint8Array.
//! 4. JS calls back into WASM via `__wbindgen_free(ptr, len, align)`.
//! 5. WASM's allocator frees the page.
//!
//! Step 5 returns the page to the allocator's free list WITHOUT
//! scrubbing it. The bytes sit in WASM linear memory until the page
//! is allocated for something else.
//!
//! That residue matters in a defense-in-depth posture: an attacker
//! who later achieves XSS in the same realm can read the entire
//! `WebAssembly.Memory` instance as an ArrayBuffer. Even brief
//! residue (Master Key, AuthKey, decrypted DEK) is exfiltratable.
//!
//! Where the host application's CSP is strict and rejects `unsafe-inline`
//! and `unsafe-eval`, XSS is not the expected attack path. But "secrets
//! persist in freed memory" is exactly the kind of finding a cryptography
//! consultant flags, and closing it structurally is cheaper than
//! arguing it's mitigated by other layers.
//!
//! ## How
//!
//! We register a custom global allocator that wraps `dlmalloc`.
//! On `dealloc`, we zero the freed region BEFORE handing it back.
//! Allocation pass-through is unchanged.
//!
//! Performance impact: a `memset(0, len)` per dealloc. WASM's
//! `memory.fill` instruction is fast. For workloads of this shape
//! -- a few KB of secret material per operation -- the overhead is
//! negligible.
//!
//! ## Caveat
//!
//! This allocator scrubs the *freed-page* region but NOT bytes that
//! were copied to other places (the stack, other heap allocations
//! that happen to share a cache line, JIT-spilled register saves).
//! Comprehensive scrubbing is impossible in WASM today. This is a
//! best-effort layer; the more effective layer is JS-side
//! `wipeSecret` on the Uint8Array the caller received.

#![allow(unsafe_code)]

use core::alloc::{GlobalAlloc, Layout};

/// Global allocator that delegates to `dlmalloc` for allocation and
/// scrubs freed memory on dealloc.
pub struct ZeroizingAllocator {
    inner: dlmalloc::GlobalDlmalloc,
}

impl ZeroizingAllocator {
    /// Construct. Must be a `const fn` so it can initialize a `static`.
    pub const fn new() -> Self {
        Self {
            inner: dlmalloc::GlobalDlmalloc {},
        }
    }
}

unsafe impl GlobalAlloc for ZeroizingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Allocation is pass-through. We don't pre-zero because
        // (a) Rust's safe code never reads uninitialized memory and
        // (b) the `alloc_zeroed` path is the right place for callers
        // who need zeroed bytes.
        self.inner.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // Zero the bytes BEFORE returning the page to the free list.
        // Volatile writes prevent the compiler from optimizing this
        // away on the assumption that "deallocated memory is never
        // read again."
        //
        // The loop compiles to a `memory.fill` instruction on modern
        // wasm-opt because the body has no observable side-effects
        // beyond the write. wasm-opt with `-O2` recognizes the pattern.
        let mut i = 0;
        while i < layout.size() {
            core::ptr::write_volatile(ptr.add(i), 0);
            i += 1;
        }
        self.inner.dealloc(ptr, layout);
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        self.inner.alloc_zeroed(layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // For realloc, dlmalloc may move the allocation. If it does,
        // the OLD location ends up freed -- same scrubbing concern as
        // dealloc. Implement as alloc-new + copy + zero-old + dealloc-old
        // to guarantee scrubbing on the old page.
        let new_layout = Layout::from_size_align_unchecked(new_size, layout.align());
        let new_ptr = self.alloc(new_layout);
        if !new_ptr.is_null() {
            let copy_size = core::cmp::min(layout.size(), new_size);
            core::ptr::copy_nonoverlapping(ptr, new_ptr, copy_size);
            self.dealloc(ptr, layout);
        }
        new_ptr
    }
}

#[global_allocator]
static GLOBAL: ZeroizingAllocator = ZeroizingAllocator::new();
