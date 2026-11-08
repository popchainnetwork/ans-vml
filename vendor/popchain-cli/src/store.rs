#![forbid(unsafe_code)]

use anyhow::{anyhow, Context, Result};
use fs4::FileExt;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::journal::BlockDeltaV0;
use crate::types::Hash32;
use crate::util;

#[derive(Clone, Debug)]
pub struct Store {
    root: PathBuf,
    lock_file: Arc<fs::File>,
}

impl Store {
    pub fn open(root: &Path) -> Result<Self> {
        fs::create_dir_all(root).with_context(|| format!("create_dir_all {}", root.display()))?;
        fs::create_dir_all(root.join("blocks"))
            .with_context(|| format!("create_dir_all {}", root.join("blocks").display()))?;
        fs::create_dir_all(root.join("heights"))
            .with_context(|| format!("create_dir_all {}", root.join("heights").display()))?;
        fs::create_dir_all(root.join("deltas"))
            .with_context(|| format!("create_dir_all {}", root.join("deltas").display()))?;
        fs::create_dir_all(root.join("finality"))
            .with_context(|| format!("create_dir_all {}", root.join("finality").display()))?;

        let lock_path = root.join(".lock");
        let f = fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .with_context(|| format!("open {}", lock_path.display()))?;

        Ok(Self {
            root: root.to_path_buf(),
            lock_file: Arc::new(f),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn with_shared_lock<T>(&self, f: impl FnOnce() -> Result<T>) -> Result<T> {
        self.lock_file
            .lock_shared()
            .with_context(|| format!("lock(shared) {}", self.root.display()))?;

        let res = f();

        self.lock_file
            .unlock()
            .with_context(|| format!("unlock(shared) {}", self.root.display()))?;

        res
    }

    fn with_exclusive_lock<T>(&self, f: impl FnOnce() -> Result<T>) -> Result<T> {
        self.lock_file
            .lock_exclusive()
            .with_context(|| format!("lock(exclusive) {}", self.root.display()))?;

        let res = f();

        self.lock_file
            .unlock()
            .with_context(|| format!("unlock(exclusive) {}", self.root.display()))?;

        res
    }

    fn genesis_path(&self) -> PathBuf {
        self.root.join("genesis.json")
    }

    fn state_path(&self) -> PathBuf {
        self.root.join("state.json")
    }

    fn blocks_dir(&self) -> PathBuf {
        self.root.join("blocks")
    }

    fn heights_dir(&self) -> PathBuf {
        self.root.join("heights")
    }

    fn deltas_dir(&self) -> PathBuf {
        self.root.join("deltas")
    }

    fn finality_dir(&self) -> PathBuf {
        self.root.join("finality")
    }

    fn block_path(&self, h: &Hash32) -> PathBuf {
        self.blocks_dir().join(format!("{}.json", h.to_hex()))
    }

    fn height_index_path(&self, height: u64) -> PathBuf {
        self.heights_dir().join(format!("{height}.json"))
    }

    fn delta_path(&self, h: &Hash32) -> PathBuf {
        self.deltas_dir().join(format!("{}.json", h.to_hex()))
    }

    fn finality_record_path(&self, epoch: u64) -> PathBuf {
        self.finality_dir().join(format!("epoch_{epoch}.json"))
    }

    fn read_json<T: DeserializeOwned>(&self, path: &Path) -> Result<T> {
        util::read_json(path)
    }

    fn write_json<T: Serialize>(&self, path: &Path, v: &T) -> Result<()> {
        util::atomic_write_json(path, v, true)
    }

    pub fn write_genesis<T: Serialize>(&self, g: &T) -> Result<()> {
        self.with_exclusive_lock(|| self.write_json(&self.genesis_path(), g))
    }

    pub fn read_genesis<T: DeserializeOwned>(&self) -> Result<T> {
        self.with_shared_lock(|| self.read_json(&self.genesis_path()))
    }

    pub fn write_state<T: Serialize>(&self, st: &T) -> Result<()> {
        self.with_exclusive_lock(|| self.write_json(&self.state_path(), st))
    }

    pub fn read_state<T: DeserializeOwned>(&self) -> Result<T> {
        self.with_shared_lock(|| self.read_json(&self.state_path()))
    }

    pub fn has_block(&self, h: &Hash32) -> Result<bool> {
        Ok(self.block_path(h).exists())
    }

    pub fn write_block_by_hash<T: Serialize>(&self, h: &Hash32, blk: &T) -> Result<()> {
        self.with_exclusive_lock(|| self.write_json(&self.block_path(h), blk))
    }

    pub fn read_block_by_hash<T: DeserializeOwned>(&self, h: &Hash32) -> Result<T> {
        self.with_shared_lock(|| self.read_json(&self.block_path(h)))
    }

    pub fn read_height_index(&self, height: u64) -> Result<Vec<Hash32>> {
        let p = self.height_index_path(height);
        if !p.exists() {
            return Ok(Vec::new());
        }

        self.with_shared_lock(|| self.read_json(&p))
    }

    pub fn append_height_index(&self, height: u64, h: &Hash32) -> Result<()> {
        self.with_exclusive_lock(|| {
            let p = self.height_index_path(height);
            let mut v: Vec<Hash32> = if p.exists() {
                self.read_json(&p)?
            } else {
                Vec::new()
            };

            if v.iter().any(|x| x == h) {
                return Ok(());
            }

            v.push(*h);
            v.sort();
            self.write_json(&p, &v)
        })
    }

    pub fn write_delta(&self, block_hash: &Hash32, d: &BlockDeltaV0) -> Result<()> {
        self.with_exclusive_lock(|| self.write_json(&self.delta_path(block_hash), d))
    }

    pub fn has_delta(&self, block_hash: &Hash32) -> Result<bool> {
        Ok(self.delta_path(block_hash).exists())
    }

    pub fn read_delta(&self, block_hash: &Hash32) -> Result<BlockDeltaV0> {
        self.with_shared_lock(|| {
            let p = self.delta_path(block_hash);
            if !p.exists() {
                return Err(anyhow!("missing delta for block {}", block_hash.to_hex()));
            }
            self.read_json(&p)
        })
    }

    pub fn has_finality_record(&self, epoch: u64) -> Result<bool> {
        Ok(self.finality_record_path(epoch).exists())
    }

    pub fn write_finality_record<T: Serialize>(&self, epoch: u64, record: &T) -> Result<()> {
        self.with_exclusive_lock(|| self.write_json(&self.finality_record_path(epoch), record))
    }

    pub fn read_finality_record<T: DeserializeOwned>(&self, epoch: u64) -> Result<T> {
        self.with_shared_lock(|| {
            let p = self.finality_record_path(epoch);
            if !p.exists() {
                return Err(anyhow!("missing finality record for epoch {epoch}"));
            }
            self.read_json(&p)
        })
    }
}
