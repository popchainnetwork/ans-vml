#![forbid(unsafe_code)]

use crate::types::BlockHash;
use std::collections::{BTreeSet, HashMap, HashSet};

/// In-memory block DAG for forks + deterministic traversal.
///
/// Determinism:
/// - tips are stored in BTreeSet (ordered by hash bytes)
/// - children lists are maintained sorted
#[derive(Clone, Debug, Default)]
pub struct BlockGraph {
    parent: HashMap<BlockHash, BlockHash>,
    children: HashMap<BlockHash, Vec<BlockHash>>,
    height: HashMap<BlockHash, u64>,

    tips: BTreeSet<BlockHash>,
    orphans: HashSet<BlockHash>,

    waiting_by_parent: HashMap<BlockHash, Vec<BlockHash>>,
    genesis: Option<BlockHash>,
}

impl BlockGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_genesis(&mut self, g: BlockHash) {
        self.genesis = Some(g);
        self.height.insert(g, 0);
        self.tips.insert(g);
    }

    pub fn height_of(&self, h: &BlockHash) -> Option<u64> {
        self.height.get(h).copied()
    }

    pub fn parent_of(&self, h: &BlockHash) -> Option<BlockHash> {
        self.parent.get(h).copied()
    }

    pub fn tips(&self) -> Vec<BlockHash> {
        self.tips.iter().copied().collect()
    }

    pub fn is_orphan(&self, h: &BlockHash) -> bool {
        self.orphans.contains(h)
    }

    fn insert_sorted(vec: &mut Vec<BlockHash>, h: BlockHash) {
        if vec.contains(&h) {
            return;
        }
        vec.push(h);
        vec.sort_by(|a, b| a.0.cmp(&b.0));
    }

    /// Insert a block reference into the graph.
    /// Returns true if connected (parent known), else marks orphan.
    pub fn insert(
        &mut self,
        hash: BlockHash,
        parent: BlockHash,
        parent_height: Option<u64>,
    ) -> bool {
        if self.height.contains_key(&hash) {
            return true;
        }

        if parent_height.is_none() {
            self.orphans.insert(hash);
            let e = self.waiting_by_parent.entry(parent).or_default();
            Self::insert_sorted(e, hash);
            return false;
        }

        let ph = parent_height.unwrap();

        self.orphans.remove(&hash);
        self.parent.insert(hash, parent);
        self.height.insert(hash, ph.saturating_add(1));

        self.tips.remove(&parent);
        self.tips.insert(hash);

        let ch = self.children.entry(parent).or_default();
        Self::insert_sorted(ch, hash);

        // Attach any waiting orphans whose parent is this node
        if let Some(mut waiters) = self.waiting_by_parent.remove(&hash) {
            waiters.sort_by(|a, b| a.0.cmp(&b.0));
            for w in waiters {
                let wh = self.height.get(&hash).copied();
                let _ = self.insert(w, hash, wh);
            }
        }

        true
    }

    /// Common ancestor using height alignment and backtracking.
    pub fn common_ancestor(&self, mut a: BlockHash, mut b: BlockHash) -> Option<BlockHash> {
        let mut ha = self.height_of(&a)?;
        let mut hb = self.height_of(&b)?;

        while ha > hb {
            a = self.parent_of(&a)?;
            ha -= 1;
        }
        while hb > ha {
            b = self.parent_of(&b)?;
            hb -= 1;
        }
        while a != b {
            a = self.parent_of(&a)?;
            b = self.parent_of(&b)?;
        }
        Some(a)
    }

    /// Path from ancestor -> tip (excluding ancestor, including tip). Empty if not ancestor.
    pub fn path_from_ancestor(&self, ancestor: BlockHash, tip: BlockHash) -> Vec<BlockHash> {
        let ca = match self.common_ancestor(ancestor, tip) {
            Some(x) => x,
            None => return Vec::new(),
        };
        if ca != ancestor {
            return Vec::new();
        }

        let mut rev = Vec::new();
        let mut cur = tip;

        while cur != ancestor {
            rev.push(cur);
            cur = match self.parent_of(&cur) {
                Some(p) => p,
                None => return Vec::new(),
            };
        }

        rev.reverse();
        rev
    }

    /// Walk back from tip (including tip) for up to limit blocks.
    pub fn walk_back(&self, mut tip: BlockHash, limit: usize) -> Vec<BlockHash> {
        let mut out = Vec::new();
        for _ in 0..limit {
            out.push(tip);
            match self.parent_of(&tip) {
                Some(p) => tip = p,
                None => break,
            }
        }
        out
    }
}
