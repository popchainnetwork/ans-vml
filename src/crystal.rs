// SPDX-License-Identifier: Apache-2.0
//! Content integrity, not a signature or linguistic completeness proof.
use anyhow::{bail, Result};
use serde_json::{json, Value};

const LETTERS: [&str; 5] = [
 include_str!("../assets/crystals/u0072.crystal.json"),
 include_str!("../assets/crystals/u0064.crystal.json"),
 include_str!("../assets/crystals/u007a.crystal.json"),
 include_str!("../assets/crystals/u0065.crystal.json"),
 include_str!("../assets/crystals/u0144.crystal.json"),
];
fn components(leaves: &[Value]) -> Result<Vec<Value>> {
 let mut result = Vec::new();
 for (position, raw) in LETTERS.iter().enumerate() {
  let d: Value = serde_json::from_str(raw)?;
  let ls = d["leaves"].as_array().ok_or_else(|| anyhow::anyhow!("character leaves"))?;
  let r = root(ls)?;
  if d["root"].as_str() != Some(r.as_str()) { bail!("character integrity mismatch"); }
  let c = d["character"].as_str().ok_or_else(|| anyhow::anyhow!("character missing"))?;
  let matches: Vec<_> = leaves.iter().filter(|l| l["kind"] == "character_reference" && l["position"] == position.to_string()).collect();
  if matches.len() != 1 || matches[0]["root"] != r || matches[0]["value"] != c { bail!("word/character composition mismatch"); }
  result.push(json!({"position":position,"character":c,"root":r,"leaves":ls.len()}));
 }
 if leaves.iter().filter(|l|l["kind"]=="character_reference").count()!=LETTERS.len() { bail!("extra character references"); }
 Ok(result)
}
const DATA: &str = include_str!("../assets/crystals/rdzen.crystal.json");

/// Merkle root via the ans-dict crate (single implementation of canonical form + SHA3 tree).
fn root(leaves: &[Value]) -> Result<String> {
    let ls = leaves.iter().map(ans_dict::Leaf::from_value).collect::<Result<Vec<_>>>()?;
    ans_dict::merkle_root(&ls)
}

pub fn summary(word: &str) -> Result<Value> {
    if !matches!(word.to_lowercase().as_str(), "rdzen" | "rdzeń") { bail!("crystal available only for rdzeń / rdzen"); }
    let data: Value = serde_json::from_str(DATA)?;
    let leaves = data["leaves"].as_array().ok_or_else(|| anyhow::anyhow!("missing leaves"))?;
    let characters = components(leaves)?;
    let actual = root(leaves)?;
    if data["root"].as_str() != Some(actual.as_str()) { bail!("crystal integrity mismatch"); }
    let count = |kind: &str| leaves.iter().filter(|v| v["kind"] == kind).count();
    let languages: std::collections::BTreeSet<_> = leaves.iter().filter(|v| v["kind"] == "translation" || v["kind"] == "sense").filter_map(|v| v["lang"].as_str()).collect();
    let counts = json!({"leaves": leaves.len(), "languages": languages.len(), "forms": count("form"), "senses": count("sense"), "translations": count("translation")});
    if data["counts"] != counts { bail!("crystal counts mismatch"); }
    Ok(json!({"word": "rdzeń", "characters": characters, "root": actual, "index": format!("ans:word:sha3-256:{actual}"), "counts":counts,"verified":true,"complete":false,"minted":false,"signed":false,"gaps":data["gaps"],"sample":leaves.iter().filter(|v|v["kind"] == "sense").take(2).collect::<Vec<_>>(),"data_license":"CC-BY-SA-4.0; Wiktionary contributors","integrity_scope":"hash binds leaves, not wrapper metadata; not linguistic validation or ownership"}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pinned_root_reproduces_and_order_is_irrelevant() {
        let d: Value = serde_json::from_str(DATA).unwrap();
        let mut leaves = d["leaves"].as_array().unwrap().clone();
        let expected = "a8e5657614f0a4721d298b03d9f897bc64e3c4937059ea7a3393b90367a20b52";
        assert_eq!(root(&leaves).unwrap(), expected);
        leaves.reverse();
        assert_eq!(root(&leaves).unwrap(), expected);
        leaves[0]["value"] = json!("tampered");
        assert_ne!(root(&leaves).unwrap(), expected);
        assert_eq!(summary("rdzen").unwrap()["counts"], d["counts"]);
        assert!(summary("unknown").is_err());
    }
    #[test]
    fn word_binds_ordered_character_roots() {
        let d: Value = serde_json::from_str(DATA).unwrap();
        let mut leaves = d["leaves"].as_array().unwrap().clone();
        let chars = components(&leaves).unwrap();
        assert_eq!(chars.iter().map(|c|c["character"].as_str().unwrap()).collect::<String>(), "rdzeń");
        assert_eq!(chars.len(),5);
        let reference = leaves.iter_mut().find(|l|l["kind"]=="character_reference").unwrap();
        reference["root"] = json!("tampered");
        assert!(components(&leaves).is_err());
    }
    #[test]
    fn reject_empty_and_duplicate_leaves() {
        assert!(root(&[]).is_err());
        assert!(root(&[json!({"kind":"y"}),json!({"kind":"y"})]).is_err());
    }
}
