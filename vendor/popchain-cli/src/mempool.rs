#![forbid(unsafe_code)]

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::app::{verify_event, AppEventV0, MAX_APP_BYTES_PER_BLOCK, MAX_APP_EVENTS_PER_BLOCK};

/// Mempool limits: deterministic and DoS-safe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolLimitsV0 {
    /// Max number of events stored.
    pub max_items: usize,
    /// Max total bytes stored (sum of payload_len).
    pub max_total_bytes: u64,
    /// Max age of an event in seconds before it is dropped.
    pub max_age_secs: u64,
}

impl Default for MempoolLimitsV0 {
    fn default() -> Self {
        Self {
            max_items: 4096,
            max_total_bytes: 8 * 1024 * 1024, // 8 MB
            max_age_secs: 60 * 10,            // 10 min
        }
    }
}

/// Unique deterministic key for ordering + dedupe.
/// Order: kind, payload_sha256_hex, payload_len, inserted_unix, tie_seq
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct EventKey {
    kind: String,
    sha: String,
    len: u64,
    inserted_unix: u64,
    tie_seq: u64,
}

/// Stored mempool item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolItemV0 {
    pub event: AppEventV0,
    pub inserted_unix: u64,
}

/// Mempool with deterministic selection order, dedupe by (kind, sha, len).
///
/// - Selection is stable across nodes given same contents
/// - Uses BTreeMap for deterministic iteration
/// - Provides pruning by age and capacity
#[derive(Debug)]
pub struct MempoolV0 {
    limits: MempoolLimitsV0,
    /// Ordering key -> item
    items: BTreeMap<EventKey, MempoolItemV0>,
    /// Dedupe index: (kind, sha, len) -> ordered keys present
    dedupe: BTreeMap<(String, String, u64), BTreeSet<EventKey>>,
    total_bytes: u64,
    seq: u64,
}

impl MempoolV0 {
    pub fn new(limits: MempoolLimitsV0) -> Self {
        Self {
            limits,
            items: BTreeMap::new(),
            dedupe: BTreeMap::new(),
            total_bytes: 0,
            seq: 0,
        }
    }

    pub fn limits(&self) -> &MempoolLimitsV0 {
        &self.limits
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    pub fn now_unix() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs()
    }

    /// Backwards-compatible name used by net/tests.
    /// Returns Ok(true) if inserted, Ok(false) if duplicate.
    pub fn add_event(&mut self, ev: AppEventV0) -> Result<bool> {
        self.insert_event(ev)
    }

    /// Validate and insert event into mempool.
    /// Returns Ok(true) if inserted, Ok(false) if duplicate.
    pub fn insert_event(&mut self, ev: AppEventV0) -> Result<bool> {
        verify_event(&ev)?;

        // Cap absurd single payload to avoid DoS.
        if ev.payload_len > MAX_APP_BYTES_PER_BLOCK {
            return Err(anyhow!("event payload too large for any block"));
        }

        let inserted_unix = Self::now_unix();
        let dedupe_key = (
            ev.kind.clone(),
            ev.payload_sha256_hex.clone(),
            ev.payload_len,
        );

        // Dedupe: if any key exists for (kind, sha, len) -> treat as duplicate
        if self.dedupe.contains_key(&dedupe_key) {
            return Ok(false);
        }

        self.seq = self.seq.saturating_add(1);
        let key = EventKey {
            kind: ev.kind.clone(),
            sha: ev.payload_sha256_hex.clone(),
            len: ev.payload_len,
            inserted_unix,
            tie_seq: self.seq,
        };

        let item = MempoolItemV0 {
            event: ev,
            inserted_unix,
        };

        self.total_bytes = self.total_bytes.saturating_add(item.event.payload_len);
        self.items.insert(key.clone(), item);
        self.dedupe.entry(dedupe_key).or_default().insert(key);

        self.enforce_limits();
        Ok(true)
    }

    fn enforce_limits(&mut self) {
        self.prune_by_age();

        // capacity pruning: deterministic eviction of "worst" keys:
        // remove newest (largest ordering key) first to preserve older backlog.
        while self.items.len() > self.limits.max_items
            || self.total_bytes > self.limits.max_total_bytes
        {
            let last_key = match self.items.keys().next_back().cloned() {
                Some(k) => k,
                None => break,
            };
            let _ = self.remove_key(&last_key);
        }
    }

    pub fn prune_by_age(&mut self) {
        let now = Self::now_unix();
        let max_age = self.limits.max_age_secs;

        let mut to_remove = Vec::new();
        for (k, it) in &self.items {
            let age = now.saturating_sub(it.inserted_unix);
            if age > max_age {
                to_remove.push(k.clone());
            }
        }
        for k in to_remove {
            let _ = self.remove_key(&k);
        }
    }

    fn remove_key(&mut self, k: &EventKey) -> bool {
        let it = match self.items.remove(k) {
            Some(i) => i,
            None => return false,
        };

        self.total_bytes = self.total_bytes.saturating_sub(it.event.payload_len);

        let dk = (
            it.event.kind.clone(),
            it.event.payload_sha256_hex.clone(),
            it.event.payload_len,
        );
        if let Some(set) = self.dedupe.get_mut(&dk) {
            set.remove(k);
            if set.is_empty() {
                self.dedupe.remove(&dk);
            }
        }
        true
    }

    /// Deterministically select events for the next block, respecting block limits.
    /// Returned events are in canonical order.
    pub fn select_for_block(&self) -> Vec<AppEventV0> {
        let mut out = Vec::new();
        let mut total: u64 = 0;

        for (_k, it) in &self.items {
            if out.len() >= MAX_APP_EVENTS_PER_BLOCK {
                break;
            }
            let new_total = total.saturating_add(it.event.payload_len);
            if new_total > MAX_APP_BYTES_PER_BLOCK {
                continue;
            }
            out.push(it.event.clone());
            total = new_total;
        }

        out
    }

    /// Remove a list of events (e.g., those included in a block).
    pub fn remove_events(&mut self, evs: &[AppEventV0]) {
        for ev in evs {
            let dk = (
                ev.kind.clone(),
                ev.payload_sha256_hex.clone(),
                ev.payload_len,
            );
            let keys: Vec<EventKey> = match self.dedupe.get(&dk) {
                Some(s) => s.iter().cloned().collect(),
                None => continue,
            };
            for k in keys {
                let _ = self.remove_key(&k);
            }
        }
        self.enforce_limits();
    }
}
