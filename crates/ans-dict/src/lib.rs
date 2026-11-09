// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Paweł Piekut / Pplastechniek
//! ANS dictionary core. A crystal is a set of leaves; its index is a SHA3-256
//! merkle root over canonically serialized, sorted leaves. Integrity only:
//! a root proves the leaves are unchanged, not that they are linguistically correct.
pub mod author;
pub mod book;
pub mod exec;
pub mod forms;
pub mod import;
pub mod sync;

use anyhow::{anyhow, bail, Result};
use serde_json::{Map, Value};
use sha3::{Digest, Sha3_256};
use std::collections::BTreeMap;

pub const WORD_SCHEMA: &str = "ans-word-crystal-v1";
pub const CHAR_SCHEMA: &str = "ans-character-crystal-v1";

/// One fact with its source. All values are strings so serialization is unambiguous.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Leaf(pub BTreeMap<String, String>);

#[derive(Debug, PartialEq, Eq)]
pub enum LeafKind<'a> { Identity, Character, Translation, Sense, Form, CharacterReference, Block, Script, Exec, Other(&'a str) }

impl Leaf {
    pub fn new(pairs: &[(&str, &str)]) -> Leaf {
        Leaf(pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect())
    }
    pub fn get(&self, k: &str) -> Option<&str> { self.0.get(k).map(String::as_str) }
    pub fn kind(&self) -> LeafKind<'_> {
        match self.get("kind").unwrap_or("") {
            "identity" => LeafKind::Identity, "character" => LeafKind::Character,
            "translation" => LeafKind::Translation, "sense" => LeafKind::Sense, "form" => LeafKind::Form,
            "character_reference" => LeafKind::CharacterReference, "block" => LeafKind::Block,
            "script" => LeafKind::Script, "exec" => LeafKind::Exec, o => LeafKind::Other(o),
        }
    }
    /// Canonical bytes: compact JSON, keys sorted, UTF-8 unescaped
    /// (identical to Python json.dumps(sort_keys=True, ensure_ascii=False, separators=(',',':'))).
    pub fn canonical(&self) -> Vec<u8> { serde_json::to_vec(&self.0).expect("string map serializes") }
    pub fn from_value(v: &Value) -> Result<Leaf> {
        let o = v.as_object().ok_or_else(|| anyhow!("leaf is not an object"))?;
        let mut m = BTreeMap::new();
        for (k, v) in o { m.insert(k.clone(), v.as_str().ok_or_else(|| anyhow!("leaf field {k} is not a string"))?.to_string()); }
        if !m.contains_key("kind") { bail!("leaf without kind"); }
        Ok(Leaf(m))
    }
    pub fn to_value(&self) -> Value { Value::Object(self.0.iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))).collect()) }
}

/// SHA3-256 merkle root; order-independent; rejects empty and duplicate leaves.
pub fn merkle_root(leaves: &[Leaf]) -> Result<String> {
    if leaves.is_empty() { bail!("empty crystal"); }
    let mut bytes: Vec<Vec<u8>> = leaves.iter().map(Leaf::canonical).collect();
    bytes.sort();
    if bytes.windows(2).any(|w| w[0] == w[1]) { bail!("duplicate leaves"); }
    let mut nodes: Vec<Vec<u8>> = bytes.iter().map(|b| { let mut h = Sha3_256::new(); h.update([0u8]); h.update(b); h.finalize().to_vec() }).collect();
    while nodes.len() > 1 {
        nodes = nodes.chunks(2).map(|p| { let mut h = Sha3_256::new(); h.update([1u8]); h.update(&p[0]); h.update(p.get(1).unwrap_or(&p[0])); h.finalize().to_vec() }).collect();
    }
    Ok(hex::encode(&nodes[0]))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CrystalKind { Word, Letter }

/// A word or letter crystal. `meta` keeps wrapper fields (gaps, counts, ...) which are NOT bound by the root.
#[derive(Clone, Debug)]
pub struct Crystal { pub kind: CrystalKind, pub id: String, pub root: String, pub leaves: Vec<Leaf>, pub meta: Map<String, Value> }

impl Crystal {
    pub fn build(kind: CrystalKind, id: &str, mut leaves: Vec<Leaf>, meta: Map<String, Value>) -> Result<Crystal> {
        leaves.sort_by(|a, b| a.canonical().cmp(&b.canonical()));
        let root = merkle_root(&leaves)?;
        Ok(Crystal { kind, id: id.to_string(), root, leaves, meta })
    }
    /// Parse and verify: the declared root must equal the recomputed root.
    pub fn parse(text: &str) -> Result<Crystal> {
        let v: Value = serde_json::from_str(text)?;
        let o = v.as_object().ok_or_else(|| anyhow!("crystal is not an object"))?;
        let (kind, id) = match o.get("schema").and_then(Value::as_str) {
            Some(WORD_SCHEMA) => (CrystalKind::Word, o.get("word")),
            Some(CHAR_SCHEMA) => (CrystalKind::Letter, o.get("character")),
            s => bail!("unknown crystal schema {s:?}"),
        };
        let id = id.and_then(Value::as_str).ok_or_else(|| anyhow!("crystal id missing"))?.to_string();
        let leaves = o.get("leaves").and_then(Value::as_array).ok_or_else(|| anyhow!("leaves missing"))?
            .iter().map(Leaf::from_value).collect::<Result<Vec<_>>>()?;
        let declared = o.get("root").and_then(Value::as_str).ok_or_else(|| anyhow!("root missing"))?;
        let root = merkle_root(&leaves)?;
        if root != declared { bail!("merkle root mismatch: declared {declared}, recomputed {root}"); }
        let schema = if kind == CrystalKind::Word { WORD_SCHEMA } else { CHAR_SCHEMA };
        let identities: Vec<_> = leaves.iter().filter(|l| l.get("kind") == Some("identity")).collect();
        if identities.len() != 1 || identities[0].get("value") != Some(id.as_str()) {
            bail!("crystal identity mismatch: wrapper must match one root-bound identity leaf");
        }
        if identities[0].get("schema").is_some_and(|bound| bound != schema) {
            bail!("crystal schema mismatch with root-bound identity");
        }
        let meta = o.iter().filter(|(k, _)| !matches!(k.as_str(), "leaves" | "root")).map(|(k, v)| (k.clone(), v.clone())).collect();
        Ok(Crystal { kind, id, root, leaves, meta })
    }
    pub fn index(&self) -> String {
        format!("ans:{}:sha3-256:{}", if self.kind == CrystalKind::Word { "word" } else { "character" }, self.root)
    }
    pub fn to_json(&self) -> String {
        let mut o = self.meta.clone();
        o.insert("schema".into(), Value::String(if self.kind == CrystalKind::Word { WORD_SCHEMA } else { CHAR_SCHEMA }.into()));
        o.insert(if self.kind == CrystalKind::Word { "word" } else { "character" }.into(), Value::String(self.id.clone()));
        o.insert("root".into(), Value::String(self.root.clone()));
        o.insert("index".into(), Value::String(self.index()));
        o.insert("leaves".into(), Value::Array(self.leaves.iter().map(Leaf::to_value).collect()));
        serde_json::to_string_pretty(&Value::Object(o)).unwrap() + "\n"
    }
    /// Store filename: letters `uXXXX.crystal.json`, words `<folded>.crystal.json`.
    pub fn file_name(&self) -> String {
        match self.kind {
            CrystalKind::Letter => self.id.chars().map(|c| format!("u{:04x}", c as u32)).collect::<String>() + ".crystal.json",
            CrystalKind::Word => forms::fold(&self.id).chars().map(|c| if c.is_ascii_alphanumeric() { c.to_string() } else { format!("_{:x}", c as u32) }).collect::<String>() + ".crystal.json",
        }
    }
    pub fn of_kind<'a>(&'a self, kind: &'a str) -> impl Iterator<Item = &'a Leaf> + 'a { self.leaves.iter().filter(move |l| l.get("kind") == Some(kind)) }
}

#[cfg(test)]
mod tests {
    use super::*;
    pub const RDZEN_ROOT: &str = "a8e5657614f0a4721d298b03d9f897bc64e3c4937059ea7a3393b90367a20b52";
    pub fn asset(name: &str) -> String { std::fs::read_to_string(format!("{}/../../assets/crystals/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap() }
    #[test]
    fn rdzen_root_reproduces_in_rust() {
        let c = Crystal::parse(&asset("rdzen.crystal.json")).unwrap();
        assert_eq!(c.root, RDZEN_ROOT);
        assert_eq!(c.leaves.len(), 820);
        let mut rev = c.leaves.clone(); rev.reverse();
        assert_eq!(merkle_root(&rev).unwrap(), RDZEN_ROOT);
        // round trip through our own serializer keeps the root
        assert_eq!(Crystal::parse(&c.to_json()).unwrap().root, RDZEN_ROOT);
    }
    #[test]
    fn tamper_is_rejected() {
        let mut v: Value = serde_json::from_str(&asset("rdzen.crystal.json")).unwrap();
        v["leaves"][0]["value"] = Value::String("tampered".into());
        assert!(Crystal::parse(&v.to_string()).unwrap_err().to_string().contains("mismatch"));
        assert!(merkle_root(&[]).is_err());
        let l = Leaf::new(&[("kind", "x")]);
        assert!(merkle_root(&[l.clone(), l]).is_err());
    }
}
