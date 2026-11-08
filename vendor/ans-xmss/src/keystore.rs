// SPDX-License-Identifier: Apache-2.0
// Product-copy relicensing authorised by Paweł Piekut / Pplastechniek, 2026-11-08.
//! Crash-safe XMSS state (NIST SP 800-208 §8.1: a one-time key MUST never be reused).
//!
//! Protocol for every signature:
//!   1. reserve(): idx = next; durably persist next = idx + 1
//!      (write tmp -> fsync -> rename -> fsync dir) AND append idx to the
//!      append-only journal (fsync). Only then is the index handed out.
//!   2. release(reservation, msg): compute the signature for that idx.
//! A crash between 1 and 2 burns the leaf (safe); it can never re-issue it.
//!
//! Rollback detection: on open, `next` must be > every index in the journal.
//! Restoring an old state file (but not the journal) is refused.
//! Restoring BOTH from an old backup cannot be detected locally; that case is
//! caught at chain level by (pk_id, idx) uniqueness (see ans-chain).
//!
//! This module stores NO secret key bytes; the caller supplies `XmssSk`.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::params::{NBytes, LEAVES, N};
use crate::xmss::{sign_at, TreeCache, XmssError, XmssSig, XmssSk};
use crate::xmssmt::{mt_sign_at, MtCache, MtSig, MtSk, MT_LIMIT};

const MAGIC: &[u8; 4] = b"AXS2";
const STATE_LEN: usize = 4 + 8 + N + 32;

/// A stateful hash-based signature scheme usable by the crash-safe store.
pub trait Scheme {
    type Sk: Clone;
    type Cache;
    type Sig;
    /// Number of usable indices (0..limit).
    const LIMIT: u64;
    fn root(sk: &Self::Sk) -> NBytes;
    fn cache(sk: &Self::Sk) -> Self::Cache;
    fn sign_at(sk: &Self::Sk, c: &mut Self::Cache, idx: u64, msg: &[u8]) -> Result<Self::Sig, XmssError>;
}
pub struct Xmss;
impl Scheme for Xmss {
    type Sk = XmssSk; type Cache = TreeCache; type Sig = XmssSig;
    const LIMIT: u64 = LEAVES as u64;
    fn root(sk: &XmssSk) -> NBytes { sk.root }
    fn cache(sk: &XmssSk) -> TreeCache { TreeCache::build(sk) }
    fn sign_at(sk: &XmssSk, c: &mut TreeCache, idx: u64, msg: &[u8]) -> Result<XmssSig, XmssError> { sign_at(sk, c, idx as u32, msg) }
}
pub struct XmssMt;
impl Scheme for XmssMt {
    type Sk = MtSk; type Cache = MtCache; type Sig = MtSig;
    const LIMIT: u64 = MT_LIMIT;
    fn root(sk: &MtSk) -> NBytes { sk.root }
    fn cache(_: &MtSk) -> MtCache { MtCache::default() }
    fn sign_at(sk: &MtSk, c: &mut MtCache, idx: u64, msg: &[u8]) -> Result<MtSig, XmssError> { mt_sign_at(sk, c, idx, msg) }
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("state file missing; refuse to guess index (run init explicitly)")]
    Missing,
    #[error("state file already exists; refuse to overwrite")]
    Exists,
    #[error("state file corrupt (magic/len/checksum)")]
    Corrupt,
    #[error("state file belongs to a different key root")]
    WrongKey,
    #[error("state rollback detected: next={next} but journal has used idx={used}")]
    Rollback { next: u64, used: u64 },
    #[error("journal corrupt")]
    JournalCorrupt,
    #[error(transparent)]
    Xmss(#[from] XmssError),
}

fn encode(next: u64, root: &NBytes) -> [u8; STATE_LEN] {
    let mut b = [0u8; STATE_LEN];
    b[..4].copy_from_slice(MAGIC);
    b[4..12].copy_from_slice(&next.to_be_bytes());
    b[12..12 + N].copy_from_slice(root);
    let d = Sha256::digest(&b[..12 + N]);
    b[12 + N..].copy_from_slice(&d);
    b
}
fn decode(b: &[u8]) -> Result<(u64, NBytes), StoreError> {
    if b.len() != STATE_LEN || &b[..4] != MAGIC { return Err(StoreError::Corrupt); }
    if Sha256::digest(&b[..12 + N]).as_slice() != &b[12 + N..] { return Err(StoreError::Corrupt); }
    Ok((u64::from_be_bytes(b[4..12].try_into().unwrap()), b[12..12 + N].try_into().unwrap()))
}
fn fsync_dir(p: &Path) -> std::io::Result<()> {
    if let Some(d) = p.parent() { File::open(if d.as_os_str().is_empty() { Path::new(".") } else { d })?.sync_all()?; }
    Ok(())
}
fn journal_path(p: &Path) -> PathBuf { let mut s = p.as_os_str().to_owned(); s.push(".journal"); PathBuf::from(s) }
fn journal_max(p: &Path) -> Result<Option<u64>, StoreError> {
    let mut buf = Vec::new();
    match File::open(journal_path(p)) {
        Ok(mut f) => { f.read_to_end(&mut buf)?; }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    if buf.len() % 8 != 0 { return Err(StoreError::JournalCorrupt); }
    Ok(buf.chunks(8).map(|c| u64::from_be_bytes(c.try_into().unwrap())).max())
}

/// A durably reserved, not-yet-used index. Consumed by `release`.
#[must_use]
pub struct Reservation { idx: u64 }
impl Reservation { pub fn idx(&self) -> u64 { self.idx } }

pub struct Stateful<S: Scheme> { sk: S::Sk, cache: S::Cache, path: PathBuf, next: u64 }
pub type StatefulSigner = Stateful<Xmss>;
pub type MtStatefulSigner = Stateful<XmssMt>;

impl<S: Scheme> Stateful<S> {
    pub fn init(sk: S::Sk, path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        if path.exists() || journal_path(&path).exists() { return Err(StoreError::Exists); }
        let s = Self { cache: S::cache(&sk), sk, path, next: 0 };
        s.write_state(0)?;
        Ok(s)
    }
    pub fn open(sk: S::Sk, path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(StoreError::Missing),
            Err(e) => return Err(e.into()),
        };
        let (next, root) = decode(&bytes)?;
        if root != S::root(&sk) { return Err(StoreError::WrongKey); }
        if let Some(used) = journal_max(&path)? { if next <= used { return Err(StoreError::Rollback { next, used }); } }
        Ok(Self { cache: S::cache(&sk), sk, path, next })
    }
    pub fn next_index(&self) -> u64 { self.next }
    pub fn remaining(&self) -> u64 { S::LIMIT.saturating_sub(self.next) }
    fn write_state(&self, next: u64) -> Result<(), StoreError> {
        let mut tmp = self.path.as_os_str().to_owned(); tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        { let mut f = OpenOptions::new().write(true).create(true).truncate(true).open(&tmp)?;
          f.write_all(&encode(next, &S::root(&self.sk)))?; f.sync_all()?; }
        fs::rename(&tmp, &self.path)?;
        fsync_dir(&self.path)?;
        Ok(())
    }
    /// Step 1: durably burn the next index BEFORE any signature exists.
    pub fn reserve(&mut self) -> Result<Reservation, StoreError> {
        let idx = self.next;
        if idx >= S::LIMIT { return Err(XmssError::NoLeaves.into()); }
        { let mut j = OpenOptions::new().append(true).create(true).open(journal_path(&self.path))?;
          j.write_all(&idx.to_be_bytes())?; j.sync_all()?; }
        self.write_state(idx + 1)?;
        self.next = idx + 1;
        Ok(Reservation { idx })
    }
    /// Step 2: produce the signature for a reserved index.
    pub fn release(&mut self, r: Reservation, msg: &[u8]) -> Result<S::Sig, StoreError> {
        Ok(S::sign_at(&self.sk, &mut self.cache, r.idx, msg)?)
    }
    pub fn sign(&mut self, msg: &[u8]) -> Result<S::Sig, StoreError> { let r = self.reserve()?; self.release(r, msg) }
    /// Test-only helper: jump the persisted counter forward (never backward).
    pub fn skip_to(&mut self, idx: u64) -> Result<(), StoreError> {
        if idx < self.next { return Err(StoreError::Rollback { next: idx, used: self.next }); }
        { let mut j = OpenOptions::new().append(true).create(true).open(journal_path(&self.path))?;
          if idx > 0 { j.write_all(&(idx - 1).to_be_bytes())?; } j.sync_all()?; }
        self.write_state(idx)?; self.next = idx; Ok(())
    }
}
