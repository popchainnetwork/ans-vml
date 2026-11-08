// SPDX-License-Identifier: Apache-2.0
// Product-copy relicensing authorised by Paweł Piekut / Pplastechniek, 2026-11-08.
//! RFC 8391 §2.5 address. 32 bytes, big-endian fields.

use crate::params::N;

pub const ADRS_LEN: usize = 32;
pub const TYPE_OTS: u32 = 0;
pub const TYPE_LTREE: u32 = 1;
pub const TYPE_HASHTREE: u32 = 2;

#[derive(Clone, Copy, Debug)]
pub struct Adrs(pub [u8; ADRS_LEN]);

impl Adrs {
    pub fn new() -> Self {
        Self([0u8; ADRS_LEN])
    }

    pub fn from_words(w: [u32; 8]) -> Self {
        let mut a = [0u8; ADRS_LEN];
        for i in 0..8 {
            a[i * 4..i * 4 + 4].copy_from_slice(&w[i].to_be_bytes());
        }
        Self(a)
    }

    fn set_u32(&mut self, off: usize, v: u32) {
        self.0[off..off + 4].copy_from_slice(&v.to_be_bytes());
    }

    pub fn set_layer(&mut self, v: u32) {
        self.set_u32(0, v);
    }

    pub fn set_tree(&mut self, v: u64) {
        self.0[4..12].copy_from_slice(&v.to_be_bytes());
    }

    pub fn set_type(&mut self, t: u32) {
        self.set_u32(12, t);
        self.0[16..32].fill(0);
    }

    pub fn set_ots_address(&mut self, v: u32) {
        self.set_u32(16, v);
    }

    pub fn set_ltree_address(&mut self, v: u32) {
        self.set_u32(16, v);
    }

    pub fn set_chain_address(&mut self, v: u32) {
        self.set_u32(20, v);
    }

    pub fn set_tree_height(&mut self, v: u32) {
        self.set_u32(20, v);
    }

    pub fn set_hash_address(&mut self, v: u32) {
        self.set_u32(24, v);
    }

    pub fn set_tree_index(&mut self, v: u32) {
        self.set_u32(24, v);
    }

    pub fn get_tree_height(&self) -> u32 {
        u32::from_be_bytes(self.0[20..24].try_into().unwrap())
    }

    pub fn get_tree_index(&self) -> u32 {
        u32::from_be_bytes(self.0[24..28].try_into().unwrap())
    }

    pub fn set_key_and_mask(&mut self, v: u32) {
        self.set_u32(28, v);
    }

    pub fn as_bytes(&self) -> &[u8; ADRS_LEN] {
        &self.0
    }
}

impl Default for Adrs {
    fn default() -> Self {
        Self::new()
    }
}

pub fn to_byte_n(x: u64) -> [u8; N] {
    let mut b = [0u8; N];
    b[N - 8..].copy_from_slice(&x.to_be_bytes());
    b
}
