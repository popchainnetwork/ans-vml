#![forbid(unsafe_code)]

use anyhow::{anyhow, Result};
use blake3::Hasher;
use rand::RngCore;

pub const WOTS_CHAIN_LEN: usize = 16;
pub const WOTS_KEY_SIZE: usize = 32;

#[derive(Debug, Clone)]
pub struct WotsKeypair {
    pub sk: Vec<[u8; WOTS_KEY_SIZE]>,
    pub pk: Vec<[u8; WOTS_KEY_SIZE]>,
}

fn hash_bytes(parts: &[&[u8]]) -> [u8; WOTS_KEY_SIZE] {
    let mut h = Hasher::new();
    for p in parts {
        h.update(p);
    }
    *h.finalize().as_bytes()
}

pub fn generate_wots_keypair() -> WotsKeypair {
    let mut rng = rand::thread_rng();

    let mut sk = Vec::with_capacity(WOTS_CHAIN_LEN);
    let mut pk = Vec::with_capacity(WOTS_CHAIN_LEN);

    for _ in 0..WOTS_CHAIN_LEN {
        let mut secret = [0u8; WOTS_KEY_SIZE];
        rng.fill_bytes(&mut secret);

        let public = hash_bytes(&[b"popchain-wots-pk", &secret]);

        sk.push(secret);
        pk.push(public);
    }

    WotsKeypair { sk, pk }
}

pub fn sign_wots(msg: &[u8], kp: &WotsKeypair) -> Vec<[u8; WOTS_KEY_SIZE]> {
    let mut sig = Vec::with_capacity(kp.pk.len());

    for (i, pk_elem) in kp.pk.iter().enumerate() {
        let idx = [i as u8];

        let s = hash_bytes(&[b"popchain-wots-sig", msg, &idx, pk_elem]);

        sig.push(s);
    }

    sig
}

pub fn verify_wots(msg: &[u8], sig: &[[u8; WOTS_KEY_SIZE]], pk: &[[u8; WOTS_KEY_SIZE]]) -> bool {
    if sig.len() != pk.len() {
        return false;
    }

    for i in 0..sig.len() {
        let idx = [i as u8];

        let expected = hash_bytes(&[b"popchain-wots-sig", msg, &idx, &pk[i]]);

        if sig[i] != expected {
            return false;
        }
    }

    true
}

pub fn pseudo_root_from_pk(pk: &[[u8; WOTS_KEY_SIZE]]) -> [u8; WOTS_KEY_SIZE] {
    let mut h = Hasher::new();
    h.update(b"popchain-wots-pseudo-root");
    h.update(&(pk.len() as u64).to_le_bytes());

    for elem in pk {
        h.update(elem);
    }

    *h.finalize().as_bytes()
}

pub fn pk_to_hex(pk: &[[u8; WOTS_KEY_SIZE]]) -> String {
    let mut out = Vec::with_capacity(pk.len() * WOTS_KEY_SIZE);
    for elem in pk {
        out.extend_from_slice(elem);
    }
    hex::encode(out)
}

pub fn sig_to_hex(sig: &[[u8; WOTS_KEY_SIZE]]) -> String {
    let mut out = Vec::with_capacity(sig.len() * WOTS_KEY_SIZE);
    for elem in sig {
        out.extend_from_slice(elem);
    }
    hex::encode(out)
}

pub fn pk_from_hex(s: &str) -> Result<Vec<[u8; WOTS_KEY_SIZE]>> {
    let bytes = hex::decode(s).map_err(|e| anyhow!("wots pk hex decode: {e}"))?;

    if bytes.len() % WOTS_KEY_SIZE != 0 {
        return Err(anyhow!(
            "wots pk byte length {} is not divisible by {}",
            bytes.len(),
            WOTS_KEY_SIZE
        ));
    }

    let elems = bytes.len() / WOTS_KEY_SIZE;

    if elems != WOTS_CHAIN_LEN {
        return Err(anyhow!(
            "wots pk element count {} != expected {}",
            elems,
            WOTS_CHAIN_LEN
        ));
    }

    let mut out = Vec::with_capacity(elems);

    for chunk in bytes.chunks_exact(WOTS_KEY_SIZE) {
        let mut arr = [0u8; WOTS_KEY_SIZE];
        arr.copy_from_slice(chunk);
        out.push(arr);
    }

    Ok(out)
}

pub fn sig_from_hex(s: &str) -> Result<Vec<[u8; WOTS_KEY_SIZE]>> {
    let bytes = hex::decode(s).map_err(|e| anyhow!("wots sig hex decode: {e}"))?;

    if bytes.len() % WOTS_KEY_SIZE != 0 {
        return Err(anyhow!(
            "wots sig byte length {} is not divisible by {}",
            bytes.len(),
            WOTS_KEY_SIZE
        ));
    }

    let elems = bytes.len() / WOTS_KEY_SIZE;

    if elems != WOTS_CHAIN_LEN {
        return Err(anyhow!(
            "wots sig element count {} != expected {}",
            elems,
            WOTS_CHAIN_LEN
        ));
    }

    let mut out = Vec::with_capacity(elems);

    for chunk in bytes.chunks_exact(WOTS_KEY_SIZE) {
        let mut arr = [0u8; WOTS_KEY_SIZE];
        arr.copy_from_slice(chunk);
        out.push(arr);
    }

    Ok(out)
}
