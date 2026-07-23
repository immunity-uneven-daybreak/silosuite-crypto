// SPDX-License-Identifier: Apache-2.0
//! Constant-time comparison helpers.

use subtle::ConstantTimeEq;

/// Returns true if `a == b` in constant time.
///
/// If lengths differ, returns false immediately (the length itself is not
/// secret).
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_arrays() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn differing_arrays() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn differing_lengths() {
        assert!(!constant_time_eq(b"hello", b"helloworld"));
    }

    #[test]
    fn empty_arrays() {
        assert!(constant_time_eq(b"", b""));
    }
}
