// SPDX-License-Identifier: Apache-2.0
// Product-copy relicensing authorised by Paweł Piekut / Pplastechniek, 2026-11-08.
//! WOTS+ as specified in RFC 8391 §3. Used only inside XMSS.
//! This is NIST WOTS+, not PopChain's 16-chain toy.

use crate::adrs::{Adrs, TYPE_OTS};
use crate::hash::{f, prf_adrs, prf_keygen, xor_n};
use crate::params::{LEN, LEN1, LEN2, LOG_W, N, NBytes, W};

pub type WotsPk = [NBytes; LEN];
pub type WotsSig = [NBytes; LEN];
pub type WotsSk = [NBytes; LEN];

/// RFC 8391 Algorithm 2.
fn base_w(x: &[u8], out_len: usize) -> Vec<u32> {
    let mut out = Vec::with_capacity(out_len);
    let mut i_in = 0usize;
    let mut total = 0u32;
    let mut bits = 0i32;
    for _ in 0..out_len {
        if bits == 0 {
            total = x[i_in] as u32;
            i_in += 1;
            bits += 8;
        }
        bits -= LOG_W as i32;
        out.push((total >> bits) & ((W as u32) - 1));
    }
    out
}

/// RFC 8391 Algorithm 1: chain(X, i, s, SEED, ADRS)
fn chain(mut x: NBytes, i: u32, s: u32, seed: &NBytes, adrs: &mut Adrs) -> NBytes {
    if s == 0 {
        return x;
    }
    debug_assert!(i + s <= (W as u32) - 1);
    for k in i..(i + s) {
        adrs.set_hash_address(k);
        adrs.set_key_and_mask(0);
        let key = prf_adrs(seed, adrs);
        adrs.set_key_and_mask(1);
        let bm = prf_adrs(seed, adrs);
        x = f(&key, &xor_n(&x, &bm));
    }
    x
}

/// IETF companion WOTS+ SK: PRF_keygen(SK_SEED, PUB_SEED || ADRS).
/// RFC 8391 §7 reference (padding 4). Not PopChain.
pub fn expand_sk_adrs(sk_seed: &NBytes, pub_seed: &NBytes, adrs: &mut Adrs) -> WotsSk {
    adrs.set_hash_address(0);
    adrs.set_key_and_mask(0);
    let mut sk = [[0u8; N]; LEN];
    for i in 0..LEN {
        adrs.set_chain_address(i as u32);
        sk[i] = prf_keygen(sk_seed, pub_seed, adrs);
    }
    sk
}

pub fn expand_sk(sk_seed: &NBytes, pub_seed: &NBytes, leaf: u32) -> WotsSk {
    let mut adrs = Adrs::new();
    adrs.set_type(TYPE_OTS);
    adrs.set_ots_address(leaf);
    expand_sk_adrs(sk_seed, pub_seed, &mut adrs)
}

pub fn pk_from_sk_adrs(sk: &WotsSk, seed: &NBytes, adrs: &mut Adrs) -> WotsPk {
    let mut pk = [[0u8; N]; LEN];
    for i in 0..LEN {
        adrs.set_chain_address(i as u32);
        pk[i] = chain(sk[i], 0, (W as u32) - 1, seed, adrs);
    }
    pk
}

pub fn pk_from_sk(sk: &WotsSk, seed: &NBytes, leaf: u32) -> WotsPk {
    let mut adrs = Adrs::new();
    adrs.set_type(TYPE_OTS);
    adrs.set_ots_address(leaf);
    pk_from_sk_adrs(sk, seed, &mut adrs)
}

fn chain_lengths(msg: &NBytes) -> [u32; LEN] {
    let mut msg_w = base_w(msg, LEN1);
    let mut csum: u32 = 0;
    for &v in &msg_w {
        csum += (W as u32) - 1 - v;
    }
    // RFC 8391: csum <<= (8 - ((len_2 * lg(w)) % 8)); toByte(csum, ceil(len_2*lg(w)/8))
    csum <<= 4;
    let csum_bytes = [(csum >> 8) as u8, csum as u8];
    let mut csum_w = base_w(&csum_bytes, LEN2);
    msg_w.append(&mut csum_w);
    let mut out = [0u32; LEN];
    out.copy_from_slice(&msg_w);
    out
}

pub fn sign_adrs(sk: &WotsSk, msg: &NBytes, seed: &NBytes, adrs: &mut Adrs) -> WotsSig {
    let lengths = chain_lengths(msg);
    let mut sig = [[0u8; N]; LEN];
    for i in 0..LEN {
        adrs.set_chain_address(i as u32);
        sig[i] = chain(sk[i], 0, lengths[i], seed, adrs);
    }
    sig
}

pub fn sign(sk: &WotsSk, msg: &NBytes, seed: &NBytes, leaf: u32) -> WotsSig {
    let mut adrs = Adrs::new();
    adrs.set_type(TYPE_OTS);
    adrs.set_ots_address(leaf);
    sign_adrs(sk, msg, seed, &mut adrs)
}

pub fn pk_from_sig(sig: &WotsSig, msg: &NBytes, seed: &NBytes, leaf: u32) -> WotsPk {
    let mut adrs = Adrs::new();
    adrs.set_type(TYPE_OTS);
    adrs.set_ots_address(leaf);
    pk_from_sig_adrs(sig, msg, seed, &mut adrs)
}

/// pk_from_sig with a caller-built OTS address (layer/tree set for XMSS^MT).
pub fn pk_from_sig_adrs(sig: &WotsSig, msg: &NBytes, seed: &NBytes, adrs: &mut Adrs) -> WotsPk {
    let lengths = chain_lengths(msg);
    let adrs = adrs;
    let mut pk = [[0u8; N]; LEN];
    for i in 0..LEN {
        adrs.set_chain_address(i as u32);
        pk[i] = chain(
            sig[i],
            lengths[i],
            (W as u32) - 1 - lengths[i],
            seed,
            adrs,
        );
    }
    pk
}

/// Standalone WOTS SK from a seed S (RFC 8391 Algorithm 4) — used in unit tests.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wots_sign_recovers_pk() {
        let sk_seed = [7u8; N];
        let seed = [9u8; N];
        let leaf = 3u32;
        let sk = expand_sk(&sk_seed, &seed, leaf);
        let pk = pk_from_sk(&sk, &seed, leaf);
        let msg = [3u8; N];
        let sig = sign(&sk, &msg, &seed, leaf);
        let pk2 = pk_from_sig(&sig, &msg, &seed, leaf);
        assert_eq!(pk, pk2);
        let mut bad = msg;
        bad[0] ^= 1;
        let pk3 = pk_from_sig(&sig, &bad, &seed, leaf);
        assert_ne!(pk, pk3);
    }
}


