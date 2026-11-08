// SPDX-License-Identifier: Apache-2.0
// Product-copy relicensing authorised by Paweł Piekut / Pplastechniek, 2026-11-08.
//! XMSS-SHA2_10_256 — RFC 8391 §4 / SP 800-208.

use rand::rngs::OsRng;
use rand::RngCore;

use crate::adrs::{to_byte_n, Adrs, TYPE_HASHTREE, TYPE_LTREE};
use crate::hash::{h, h_msg, prf, prf_adrs, xor_n};
use crate::params::{H, LEAVES, LEN, N, NBytes, PARAM_NAME};

/// IANA XMSS-SHA2_10_256 (RFC 8391 §8).
pub const OID: u32 = 0x0000_0001;
/// IETF companion uses 4-byte index for single-tree XMSS.
pub const INDEX_BYTES: usize = 4;
pub const SIG_BYTES: usize = INDEX_BYTES + N + LEN * N + H * N;
pub const PK_BYTES: usize = 2 * N;
use crate::wots::{self, WotsPk, WotsSig};

#[derive(Clone)]
pub struct XmssSk {
    pub idx: u32,
    pub sk_seed: NBytes,
    pub sk_prf: NBytes,
    pub pub_seed: NBytes,
    pub root: NBytes,
}

#[derive(Clone)]
pub struct XmssPk {
    pub root: NBytes,
    pub pub_seed: NBytes,
}

#[derive(Clone)]
pub struct XmssSig {
    pub idx: u32,
    pub randomness: NBytes,
    pub wots: WotsSig,
    pub auth: [NBytes; H],
}

fn rand_hash(left: &NBytes, right: &NBytes, seed: &NBytes, adrs: &mut Adrs) -> NBytes {
    adrs.set_key_and_mask(0);
    let key = prf_adrs(seed, adrs);
    adrs.set_key_and_mask(1);
    let bm0 = prf_adrs(seed, adrs);
    adrs.set_key_and_mask(2);
    let bm1 = prf_adrs(seed, adrs);
    h(&key, &xor_n(left, &bm0), &xor_n(right, &bm1))
}

/// RFC 8391 l-tree: compress WOTS+ pk to one n-byte leaf.
fn ltree(pk: &WotsPk, seed: &NBytes, leaf: u32) -> NBytes {
    let mut nodes: Vec<NBytes> = pk.to_vec();
    let mut adrs = Adrs::new();
    adrs.set_type(TYPE_LTREE);
    adrs.set_ltree_address(leaf);
    let mut height = 0u32;
    while nodes.len() > 1 {
        let mut next = Vec::new();
        adrs.set_tree_height(height);
        let mut i = 0usize;
        while i + 1 < nodes.len() {
            adrs.set_tree_index((i / 2) as u32);
            next.push(rand_hash(&nodes[i], &nodes[i + 1], seed, &mut adrs));
            i += 2;
        }
        if i < nodes.len() {
            next.push(nodes[i]);
        }
        nodes = next;
        height += 1;
    }
    nodes[0]
}

fn leaf_node(sk_seed: &NBytes, pub_seed: &NBytes, idx: u32) -> NBytes {
    let sk = wots::expand_sk(sk_seed, pub_seed, idx);
    let pk = wots::pk_from_sk(&sk, pub_seed, idx);
    ltree(&pk, pub_seed, idx)
}

/// Bottom-up Merkle tree. Returns root and, if `auth_for` is Some, the auth path for that leaf.
fn merkle(
    sk_seed: &NBytes,
    pub_seed: &NBytes,
    auth_for: Option<u32>,
) -> (NBytes, Option<[NBytes; H]>) {
    let mut level: Vec<NBytes> = (0..LEAVES as u32)
        .map(|i| leaf_node(sk_seed, pub_seed, i))
        .collect();
    let mut auth = [[0u8; N]; H];
    if let Some(idx) = auth_for {
        auth[0] = level[(idx ^ 1) as usize];
    }
    let mut adrs = Adrs::new();
    adrs.set_type(TYPE_HASHTREE);
    for height in 0..H {
        let mut next = Vec::with_capacity(level.len() / 2);
        adrs.set_tree_height(height as u32);
        for i in 0..(level.len() / 2) {
            adrs.set_tree_index(i as u32);
            next.push(rand_hash(&level[2 * i], &level[2 * i + 1], pub_seed, &mut adrs));
        }
        if let Some(idx) = auth_for {
            if height + 1 < H {
                let parent = idx >> (height + 1);
                let sib = parent ^ 1;
                auth[height + 1] = next[sib as usize];
            }
        }
        level = next;
    }
    (level[0], auth_for.map(|_| auth))
}

pub fn keygen_from_seed(sk_seed: NBytes, sk_prf: NBytes, pub_seed: NBytes) -> (XmssSk, XmssPk) {
    let (root, _) = merkle(&sk_seed, &pub_seed, None);
    let sk = XmssSk {
        idx: 0,
        sk_seed,
        sk_prf,
        pub_seed,
        root,
    };
    let pk = XmssPk { root, pub_seed };
    (sk, pk)
}

pub fn keygen() -> (XmssSk, XmssPk) {
    let mut rng = OsRng;
    let mut sk_seed = [0u8; N];
    let mut sk_prf = [0u8; N];
    let mut pub_seed = [0u8; N];
    rng.fill_bytes(&mut sk_seed);
    rng.fill_bytes(&mut sk_prf);
    rng.fill_bytes(&mut pub_seed);
    keygen_from_seed(sk_seed, sk_prf, pub_seed)
}

fn message_hash(sk_prf: &NBytes, root: &NBytes, idx: u32, msg: &[u8]) -> (NBytes, NBytes) {
    let r = prf(sk_prf, &to_byte_n(idx as u64));
    let mut key = [0u8; 3 * N];
    key[..N].copy_from_slice(&r);
    key[N..2 * N].copy_from_slice(root);
    key[2 * N..].copy_from_slice(&to_byte_n(idx as u64));
    let digest = h_msg(&key, msg);
    (r, digest)
}

pub fn sign(sk: &mut XmssSk, msg: &[u8]) -> Result<XmssSig, XmssError> {
    if sk.idx as usize >= LEAVES {
        return Err(XmssError::NoLeaves);
    }
    let idx = sk.idx;
    let (r, digest) = message_hash(&sk.sk_prf, &sk.root, idx, msg);
    let wots_sk = wots::expand_sk(&sk.sk_seed, &sk.pub_seed, idx);
    let wots = wots::sign(&wots_sk, &digest, &sk.pub_seed, idx);
    let (_, auth) = merkle(&sk.sk_seed, &sk.pub_seed, Some(idx));
    let auth = auth.expect("auth");
    sk.idx += 1;
    Ok(XmssSig {
        idx,
        randomness: r,
        wots,
        auth,
    })
}

pub fn verify(pk: &XmssPk, msg: &[u8], sig: &XmssSig) -> bool {
    if sig.idx as usize >= LEAVES {
        return false;
    }
    let mut key = [0u8; 3 * N];
    key[..N].copy_from_slice(&sig.randomness);
    key[N..2 * N].copy_from_slice(&pk.root);
    key[2 * N..].copy_from_slice(&to_byte_n(sig.idx as u64));
    let digest = h_msg(&key, msg);
    let wots_pk = wots::pk_from_sig(&sig.wots, &digest, &pk.pub_seed, sig.idx);
    let mut node = ltree(&wots_pk, &pk.pub_seed, sig.idx);
    let mut adrs = Adrs::new();
    adrs.set_type(TYPE_HASHTREE);
    let mut idx = sig.idx;
    for height in 0..H {
        adrs.set_tree_height(height as u32);
        adrs.set_tree_index(idx >> 1);
        if idx & 1 == 0 {
            node = rand_hash(&node, &sig.auth[height], &pk.pub_seed, &mut adrs);
        } else {
            node = rand_hash(&sig.auth[height], &node, &pk.pub_seed, &mut adrs);
        }
        idx >>= 1;
    }
    node == pk.root
}

#[derive(Debug, thiserror::Error)]
pub enum XmssError {
    #[error("XMSS tree exhausted")]
    NoLeaves,
    #[error("public key length is not {PK_BYTES}")]
    BadPkLen,
    #[error("signature length is not {SIG_BYTES}")]
    BadSigLen,
}

impl XmssPk {
    /// IETF core PK: root || PUB_SEED (OID omitted).
    pub fn to_bytes(&self) -> [u8; PK_BYTES] {
        let mut out = [0u8; PK_BYTES];
        out[..N].copy_from_slice(&self.root);
        out[N..].copy_from_slice(&self.pub_seed);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, XmssError> {
        if b.len() != PK_BYTES {
            return Err(XmssError::BadPkLen);
        }
        let mut root = [0u8; N];
        let mut pub_seed = [0u8; N];
        root.copy_from_slice(&b[..N]);
        pub_seed.copy_from_slice(&b[N..]);
        Ok(Self { root, pub_seed })
    }

    pub fn to_bytes_with_oid(&self) -> [u8; 4 + PK_BYTES] {
        let mut out = [0u8; 4 + PK_BYTES];
        out[..4].copy_from_slice(&OID.to_be_bytes());
        out[4..].copy_from_slice(&self.to_bytes());
        out
    }
}

impl XmssSig {
    /// IETF companion: idx(4 BE) || r || WOTS+ || AUTH.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(SIG_BYTES);
        v.extend_from_slice(&self.idx.to_be_bytes());
        v.extend_from_slice(&self.randomness);
        for chain in &self.wots {
            v.extend_from_slice(chain);
        }
        for node in &self.auth {
            v.extend_from_slice(node);
        }
        debug_assert_eq!(v.len(), SIG_BYTES);
        v
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, XmssError> {
        if b.len() != SIG_BYTES {
            return Err(XmssError::BadSigLen);
        }
        let idx = u32::from_be_bytes(b[0..INDEX_BYTES].try_into().unwrap());
        let mut randomness = [0u8; N];
        randomness.copy_from_slice(&b[INDEX_BYTES..INDEX_BYTES + N]);
        let mut off = INDEX_BYTES + N;
        let mut wots = [[0u8; N]; LEN];
        for item in &mut wots {
            item.copy_from_slice(&b[off..off + N]);
            off += N;
        }
        let mut auth = [[0u8; N]; H];
        for item in &mut auth {
            item.copy_from_slice(&b[off..off + N]);
            off += N;
        }
        debug_assert_eq!(off, SIG_BYTES);
        Ok(Self {
            idx,
            randomness,
            wots,
            auth,
        })
    }
}

/// Full Merkle tree cache (2^H leaves .. root), built once per key.
/// Lets signing reuse nodes instead of recomputing 1024 leaves per signature.
/// Holds only public nodes; contains no secret material.
#[derive(Clone)]
pub struct TreeCache {
    levels: Vec<Vec<NBytes>>, // levels[0] = leaves, levels[H] = [root]
}

impl TreeCache {
    pub fn build(sk: &XmssSk) -> Self {
        let mut levels: Vec<Vec<NBytes>> = Vec::with_capacity(H + 1);
        levels.push((0..LEAVES as u32).map(|i| leaf_node(&sk.sk_seed, &sk.pub_seed, i)).collect());
        let mut adrs = Adrs::new();
        adrs.set_type(TYPE_HASHTREE);
        for height in 0..H {
            adrs.set_tree_height(height as u32);
            let prev = &levels[height];
            let mut next = Vec::with_capacity(prev.len() / 2);
            for i in 0..prev.len() / 2 {
                adrs.set_tree_index(i as u32);
                next.push(rand_hash(&prev[2 * i], &prev[2 * i + 1], &sk.pub_seed, &mut adrs));
            }
            levels.push(next);
        }
        Self { levels }
    }
    pub fn root(&self) -> NBytes {
        self.levels[H][0]
    }
    pub fn auth_path(&self, idx: u32) -> [NBytes; H] {
        let mut auth = [[0u8; N]; H];
        for (height, a) in auth.iter_mut().enumerate() {
            *a = self.levels[height][((idx >> height) ^ 1) as usize];
        }
        auth
    }
}

/// Sign at an explicit leaf index WITHOUT touching any counter.
/// Only the crash-safe `keystore` may call this, after it has durably
/// persisted `idx + 1`. Crate-private on purpose.
pub(crate) fn sign_at(sk: &XmssSk, cache: &TreeCache, idx: u32, msg: &[u8]) -> Result<XmssSig, XmssError> {
    if idx as usize >= LEAVES {
        return Err(XmssError::NoLeaves);
    }
    let (r, digest) = message_hash(&sk.sk_prf, &sk.root, idx, msg);
    let wots_sk = wots::expand_sk(&sk.sk_seed, &sk.pub_seed, idx);
    let wots = wots::sign(&wots_sk, &digest, &sk.pub_seed, idx);
    Ok(XmssSig { idx, randomness: r, wots, auth: cache.auth_path(idx) })
}

pub fn param_name() -> &'static str {
    PARAM_NAME
}

#[cfg(test)]
mod tests {
    use super::*;
    fn statement_bytes() -> Vec<u8> { b"ans-l0 xmss self-test statement v1".to_vec() }

    #[test]
    fn sign_statement_and_verify() {
        let (mut sk, pk) = keygen();
        let msg = statement_bytes();
        let sig = sign(&mut sk, &msg).unwrap();
        assert_eq!(sig.idx, 0);
        assert!(verify(&pk, &msg, &sig));
        let mut bad = msg.clone();
        bad[0] ^= 0xff;
        assert!(!verify(&pk, &bad, &sig));
        assert_eq!(sk.idx, 1);
    }

    #[test]
    fn cached_signing_is_byte_identical_to_reference() {
        let (mut sk, pk) = keygen_from_seed([1u8; N], [2u8; N], [3u8; N]);
        let cache = TreeCache::build(&sk);
        assert_eq!(cache.root(), pk.root);
        for idx in [0u32, 1, 511, 1023] {
            sk.idx = idx;
            let a = sign(&mut sk.clone(), b"m").unwrap();
            let b = sign_at(&sk, &cache, idx, b"m").unwrap();
            assert_eq!(a.to_bytes(), b.to_bytes());
        }
    }
}
