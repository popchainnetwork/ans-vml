#![forbid(unsafe_code)]

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::chain::BlockV1;
use crate::types::Hash32;

/// Default epoch size for PopChain alpha.
/// Later this can move to genesis / protocol params.
pub const DEFAULT_EPOCH_LEN: u64 = 100;

/// Deterministic epoch id from height.
/// Height 0 (genesis) belongs to epoch 0.
/// Heights 1..=100 belong to epoch 1 if epoch_len=100.
/// Heights 101..=200 belong to epoch 2, etc.
pub fn epoch_of_height(height: u64, epoch_len: u64) -> Result<u64> {
    if epoch_len == 0 {
        return Err(anyhow!("epoch_len must be > 0"));
    }
    if height == 0 {
        return Ok(0);
    }
    Ok(((height - 1) / epoch_len) + 1)
}

/// First block height of an epoch.
/// epoch 0 => height 0
/// epoch 1 => height 1
pub fn epoch_start_height(epoch_id: u64, epoch_len: u64) -> Result<u64> {
    if epoch_len == 0 {
        return Err(anyhow!("epoch_len must be > 0"));
    }
    if epoch_id == 0 {
        return Ok(0);
    }
    Ok(((epoch_id - 1) * epoch_len) + 1)
}

/// Last block height of an epoch.
/// epoch 0 => height 0
/// epoch 1 => height epoch_len
pub fn epoch_end_height(epoch_id: u64, epoch_len: u64) -> Result<u64> {
    if epoch_len == 0 {
        return Err(anyhow!("epoch_len must be > 0"));
    }
    if epoch_id == 0 {
        return Ok(0);
    }
    Ok(epoch_id * epoch_len)
}

/// Returns true when the supplied block slice is a complete epoch:
/// - epoch 0 => exactly 1 genesis block
/// - epoch N>0 => exactly epoch_len blocks
pub fn is_complete_epoch(epoch_id: u64, epoch_len: u64, blocks: &[BlockV1]) -> Result<bool> {
    if epoch_len == 0 {
        return Err(anyhow!("epoch_len must be > 0"));
    }

    if epoch_id == 0 {
        if blocks.len() != 1 {
            return Ok(false);
        }
        return Ok(blocks[0].header.height == 0);
    }

    Ok(blocks.len() == epoch_len as usize)
}

/// Minimal deterministic finalized epoch record.
/// This is the canonical checkpoint object stored/indexed by the chain.
///
/// Fields:
/// - epoch_hash_hex: hash of the ordered canonical block list
/// - finality_hash_hex: stable seal over the finality record itself
///
/// Important:
/// finality_hash_hex must stay stable for the same canonical epoch.
/// Therefore finalized_unix is informational only and is NOT part of the seal hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochFinalityV0 {
    pub version: u32,
    pub epoch_id: u64,
    pub epoch_len: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub block_count: u64,
    pub epoch_hash_hex: String,
    pub finalized_unix: u64,
    pub finality_hash_hex: String,
}

/// Deterministic epoch hash:
/// sha256 over ordered block_hash_hex values in the epoch, plus boundaries.
///
/// Important:
/// - blocks must already be canonical and ordered by height
/// - genesis epoch (0) may contain exactly one block (height 0)
pub fn epoch_hash_from_blocks(epoch_id: u64, epoch_len: u64, blocks: &[BlockV1]) -> Result<Hash32> {
    if epoch_len == 0 {
        return Err(anyhow!("epoch_len must be > 0"));
    }

    let start = epoch_start_height(epoch_id, epoch_len)?;
    let end = epoch_end_height(epoch_id, epoch_len)?;

    if epoch_id == 0 {
        if blocks.len() != 1 {
            return Err(anyhow!("epoch 0 must contain exactly 1 block"));
        }
        if blocks[0].header.height != 0 {
            return Err(anyhow!("epoch 0 block height must be 0"));
        }
    } else if blocks.is_empty() {
        return Err(anyhow!("epoch blocks empty"));
    }

    let mut h = Sha256::new();
    h.update(b"popchain:epoch-hash:v0");
    h.update(epoch_id.to_le_bytes());
    h.update(epoch_len.to_le_bytes());
    h.update(start.to_le_bytes());
    h.update(end.to_le_bytes());
    h.update((blocks.len() as u64).to_le_bytes());

    let mut expected_height = start;
    for blk in blocks {
        let got_epoch = epoch_of_height(blk.header.height, epoch_len)?;
        if got_epoch != epoch_id {
            return Err(anyhow!(
                "block height {} belongs to epoch {}, not {}",
                blk.header.height,
                got_epoch,
                epoch_id
            ));
        }

        if blk.header.height != expected_height {
            return Err(anyhow!(
                "non-contiguous epoch blocks: expected height {}, got {}",
                expected_height,
                blk.header.height
            ));
        }

        h.update(blk.block_hash_hex.as_bytes());
        expected_height = expected_height.saturating_add(1);
    }

    if epoch_id != 0 {
        let expected_count = epoch_len as usize;
        if blocks.len() != expected_count {
            return Err(anyhow!(
                "epoch {} incomplete: expected {} blocks, got {}",
                epoch_id,
                expected_count,
                blocks.len()
            ));
        }
    }

    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    Ok(Hash32(arr))
}

/// Deterministic epoch finality seal.
/// This is the stable hash of the finality record itself.
///
/// IMPORTANT:
/// finalized_unix is intentionally NOT included here,
/// so the seal remains stable for the same canonical epoch.
pub fn finality_hash(
    version: u32,
    epoch_id: u64,
    epoch_len: u64,
    start_height: u64,
    end_height: u64,
    block_count: u64,
    epoch_hash_hex: &str,
) -> Hash32 {
    let mut h = Sha256::new();

    h.update(b"popchain:epoch-finality:v0");
    h.update(version.to_le_bytes());
    h.update(epoch_id.to_le_bytes());
    h.update(epoch_len.to_le_bytes());
    h.update(start_height.to_le_bytes());
    h.update(end_height.to_le_bytes());
    h.update(block_count.to_le_bytes());
    h.update(epoch_hash_hex.as_bytes());

    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    Hash32(arr)
}

pub fn finalize_epoch_from_blocks(
    epoch_id: u64,
    epoch_len: u64,
    blocks: &[BlockV1],
    finalized_unix: u64,
) -> Result<EpochFinalityV0> {
    if !is_complete_epoch(epoch_id, epoch_len, blocks)? {
        return Err(anyhow!("cannot finalize incomplete epoch {}", epoch_id));
    }

    let start_height = epoch_start_height(epoch_id, epoch_len)?;
    let end_height = epoch_end_height(epoch_id, epoch_len)?;
    let epoch_hash = epoch_hash_from_blocks(epoch_id, epoch_len, blocks)?;
    let version = 0u32;
    let block_count = blocks.len() as u64;

    let finality_hash_hex = finality_hash(
        version,
        epoch_id,
        epoch_len,
        start_height,
        end_height,
        block_count,
        &epoch_hash.to_hex(),
    )
    .to_hex();

    Ok(EpochFinalityV0 {
        version,
        epoch_id,
        epoch_len,
        start_height,
        end_height,
        block_count,
        epoch_hash_hex: epoch_hash.to_hex(),
        finalized_unix,
        finality_hash_hex,
    })
}

/// Re-validates a finality record against canonical epoch blocks.
pub fn verify_epoch_finality_record(fin: &EpochFinalityV0, blocks: &[BlockV1]) -> Result<()> {
    if fin.version != 0 {
        return Err(anyhow!(
            "unsupported epoch finality version {}",
            fin.version
        ));
    }
    if fin.epoch_len == 0 {
        return Err(anyhow!("epoch_len must be > 0"));
    }

    let expected_start = epoch_start_height(fin.epoch_id, fin.epoch_len)?;
    let expected_end = epoch_end_height(fin.epoch_id, fin.epoch_len)?;

    if fin.start_height != expected_start {
        return Err(anyhow!(
            "epoch finality start_height mismatch: expected {}, got {}",
            expected_start,
            fin.start_height
        ));
    }

    if fin.end_height != expected_end {
        return Err(anyhow!(
            "epoch finality end_height mismatch: expected {}, got {}",
            expected_end,
            fin.end_height
        ));
    }

    if !is_complete_epoch(fin.epoch_id, fin.epoch_len, blocks)? {
        return Err(anyhow!("epoch {} is incomplete", fin.epoch_id));
    }

    let expected_epoch_hash = epoch_hash_from_blocks(fin.epoch_id, fin.epoch_len, blocks)?;
    if fin.epoch_hash_hex != expected_epoch_hash.to_hex() {
        return Err(anyhow!(
            "epoch_hash mismatch: expected {}, got {}",
            expected_epoch_hash.to_hex(),
            fin.epoch_hash_hex
        ));
    }

    let expected_block_count = blocks.len() as u64;
    if fin.block_count != expected_block_count {
        return Err(anyhow!(
            "block_count mismatch: expected {}, got {}",
            expected_block_count,
            fin.block_count
        ));
    }

    let expected_finality_hash = finality_hash(
        fin.version,
        fin.epoch_id,
        fin.epoch_len,
        fin.start_height,
        fin.end_height,
        fin.block_count,
        &fin.epoch_hash_hex,
    );

    if fin.finality_hash_hex != expected_finality_hash.to_hex() {
        return Err(anyhow!(
            "finality_hash mismatch: expected {}, got {}",
            expected_finality_hash.to_hex(),
            fin.finality_hash_hex
        ));
    }

    Ok(())
}
