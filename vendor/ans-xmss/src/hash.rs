// SPDX-License-Identifier: Apache-2.0
// Product-copy relicensing authorised by Paweł Piekut / Pplastechniek, 2026-11-08.
//! RFC 8391 §5.1 SHA2-256 instantiations of F, H, H_msg, PRF.

use sha2::{Digest, Sha256};

use crate::adrs::Adrs;
use crate::params::{N, NBytes};

fn sha256(parts: &[&[u8]]) -> NBytes {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    let out = h.finalize();
    let mut a = [0u8; N];
    a.copy_from_slice(&out);
    a
}

fn pad(id: u8) -> NBytes {
    let mut p = [0u8; N];
    p[N - 1] = id;
    p
}

/// F(KEY, M)  KEY=n, M=n
pub fn f(key: &NBytes, m: &NBytes) -> NBytes {
    sha256(&[&pad(0), key, m])
}

/// H(KEY, M)  KEY=n, M=2n
pub fn h(key: &NBytes, left: &NBytes, right: &NBytes) -> NBytes {
    let mut m = [0u8; 2 * N];
    m[..N].copy_from_slice(left);
    m[N..].copy_from_slice(right);
    sha256(&[&pad(1), key, &m])
}

/// H_msg(KEY, M)  KEY=3n
pub fn h_msg(key_3n: &[u8], m: &[u8]) -> NBytes {
    debug_assert_eq!(key_3n.len(), 3 * N);
    sha256(&[&pad(2), key_3n, m])
}

/// PRF(KEY, M)  KEY=n, M=32 (ADRS)
pub fn prf(key: &NBytes, m32: &[u8]) -> NBytes {
    debug_assert_eq!(m32.len(), 32);
    sha256(&[&pad(3), key, m32])
}

/// PRF_keygen — IETF xmss-reference (RFC 8391 §7 companion).
/// SHA-256(toByte(4, n) || SK_SEED || PUB_SEED || ADRS)
pub fn prf_keygen(sk_seed: &NBytes, pub_seed: &NBytes, adrs: &Adrs) -> NBytes {
    sha256(&[&pad(4), sk_seed, pub_seed, adrs.as_bytes()])
}

pub fn prf_adrs(key: &NBytes, adrs: &Adrs) -> NBytes {
    prf(key, adrs.as_bytes())
}

pub fn xor_n(a: &NBytes, b: &NBytes) -> NBytes {
    let mut o = [0u8; N];
    for i in 0..N {
        o[i] = a[i] ^ b[i];
    }
    o
}

#[cfg(test)]
mod fips180_4 {
    use sha2::{Digest, Sha256};

    /// FIPS 180-4 SHA-256 of the empty bit string.
    const NIST_SHA256_EMPTY: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    /// FIPS 180-4 SHA-256 of ASCII "abc".
    const NIST_SHA256_ABC: &str =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn sha256_empty() {
        assert_eq!(hex::encode(Sha256::digest(b"")), NIST_SHA256_EMPTY);
    }

    #[test]
    fn sha256_abc() {
        assert_eq!(hex::encode(Sha256::digest(b"abc")), NIST_SHA256_ABC);
    }

    #[test]
    fn xmss_hash_is_sha2_not_sha3() {
        // XMSS-SHA2_10_256 (RFC 8391) instantiates F/H/PRF with SHA-256.
        // Native NOTE-ID instantiates SHA3-256. These empty digests differ.
        assert_ne!(
            NIST_SHA256_EMPTY,
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
    }
}
