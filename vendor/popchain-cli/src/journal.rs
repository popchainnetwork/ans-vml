#![forbid(unsafe_code)]

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::metrics::ProofV0;
use crate::util;

// ============================================================
// 1) REORG / REPLAY DELTA STATE
// ============================================================

/// Zmiana w indeksie anti-replay dla jednej maszyny.
/// Pozwala apply/unapply deterministycznie przy zmianie best chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineReplayDeltaV0 {
    pub machine_id: String,
    /// Poprzednia wartość (None = brak wpisu => zero_hash)
    pub prev_capture_hash_hex_before: Option<String>,
    /// Nowa wartość po apply
    pub capture_hash_hex_after: String,
}

/// Delta stanu dla jednego bloku.
/// Na dziś: tylko anti-replay per machine.
/// Potem tu dojdą np. UTXO delty dla BINCOIN.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockDeltaV0 {
    pub version: u32,
    pub machine_replay: Vec<MachineReplayDeltaV0>,
}

impl BlockDeltaV0 {
    pub fn new() -> Self {
        Self {
            version: 0,
            machine_replay: Vec::new(),
        }
    }

    /// Apply proof replay state to machine_last_capture_hash
    /// and record deltas so block can be unapplied later.
    pub fn apply_machine_replay(
        &mut self,
        machine_last_capture_hash: &mut HashMap<String, String>,
        proofs: &[ProofV0],
    ) -> Result<()> {
        // Local expected map so multiple proofs for same machine in one block
        // chain correctly in block order.
        let mut expected: HashMap<String, String> = machine_last_capture_hash.clone();

        for p in proofs {
            if p.machine_id.is_empty() {
                return Err(anyhow!("machine_id empty"));
            }

            let exp = expected
                .get(&p.machine_id)
                .cloned()
                .unwrap_or_else(util::zero_hash32_hex);

            if p.prev_capture_hash_hex != exp {
                return Err(anyhow!(
                    "replay/prev mismatch for machine_id={} expected_prev={} got_prev={}",
                    p.machine_id,
                    exp,
                    p.prev_capture_hash_hex
                ));
            }

            let before = machine_last_capture_hash.get(&p.machine_id).cloned();

            self.machine_replay.push(MachineReplayDeltaV0 {
                machine_id: p.machine_id.clone(),
                prev_capture_hash_hex_before: before,
                capture_hash_hex_after: p.metrics.sha256_hex.clone(),
            });

            machine_last_capture_hash.insert(p.machine_id.clone(), p.metrics.sha256_hex.clone());
            expected.insert(p.machine_id.clone(), p.metrics.sha256_hex.clone());
        }

        Ok(())
    }

    /// Undo replay-state changes in reverse order.
    pub fn unapply_machine_replay(
        &self,
        machine_last_capture_hash: &mut HashMap<String, String>,
    ) -> Result<()> {
        for d in self.machine_replay.iter().rev() {
            if d.machine_id.is_empty() {
                return Err(anyhow!("delta machine_id empty"));
            }

            match &d.prev_capture_hash_hex_before {
                Some(prev) => {
                    machine_last_capture_hash.insert(d.machine_id.clone(), prev.clone());
                }
                None => {
                    machine_last_capture_hash.remove(&d.machine_id);
                }
            }
        }
        Ok(())
    }
}

// ============================================================
// 2) APPEND-ONLY RUNTIME JOURNAL (NDJSON)
// ============================================================

/// Minimal append-only journal for demo / debugging / VC screenshots.
///
/// File: <db_root>/journal.ndjson
#[derive(Debug, Clone)]
pub struct Journal {
    path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntryV0 {
    pub version: u32,
    pub unix: u64,
    pub level: String, // INFO | WARN | ERROR
    pub kind: String,  // block.accept / block.reject / tx.accept / peer.error ...
    #[serde(default)]
    pub fields: Value,
}

impl Journal {
    pub fn open(db_root: &Path) -> Result<Self> {
        std::fs::create_dir_all(db_root)
            .with_context(|| format!("create_dir_all {}", db_root.display()))?;
        Ok(Self {
            path: db_root.join("journal.ndjson"),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(&self, e: &JournalEntryV0) -> Result<()> {
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("open append {}", self.path.display()))?;

        let line = serde_json::to_string(e).context("serialize journal entry")?;
        f.write_all(line.as_bytes()).context("write journal line")?;
        f.write_all(b"\n").context("write journal nl")?;
        f.flush().context("flush journal")?;
        f.sync_data().context("sync journal")?;
        Ok(())
    }

    pub fn info(&self, kind: &str, fields: Value) -> Result<()> {
        self.append(&JournalEntryV0 {
            version: 0,
            unix: util::now_unix(),
            level: "INFO".to_string(),
            kind: kind.to_string(),
            fields,
        })
    }

    pub fn warn(&self, kind: &str, fields: Value) -> Result<()> {
        self.append(&JournalEntryV0 {
            version: 0,
            unix: util::now_unix(),
            level: "WARN".to_string(),
            kind: kind.to_string(),
            fields,
        })
    }

    pub fn error(&self, kind: &str, fields: Value) -> Result<()> {
        self.append(&JournalEntryV0 {
            version: 0,
            unix: util::now_unix(),
            level: "ERROR".to_string(),
            kind: kind.to_string(),
            fields,
        })
    }
}
