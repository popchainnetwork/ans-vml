// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Paweł Piekut / Pplastechniek
//! `ans word` dictionary lookup and `ans boot --plan` dry-run. No network, no keys.
use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use std::path::Path;

pub const EXAMPLE: &str = include_str!("../assets/dictionary.example.json");

fn fold(s: &str) -> String {
    s.trim().to_lowercase().chars().map(|c| match c {
        'ą'=>'a','ć'=>'c','ę'=>'e','ł'=>'l','ń'=>'n','ó'=>'o','ś'=>'s','ź'|'ż'=>'z', o=>o }).collect()
}

pub fn load(root: &Path) -> Result<(Value, String)> {
    let p = root.join("dictionary.json");
    if p.exists() {
        return Ok((serde_json::from_str(&std::fs::read_to_string(&p)?)?, p.display().to_string()));
    }
    Ok((serde_json::from_str(EXAMPLE)?, "built-in examples (core/assets/dictionary.example.json)".into()))
}

pub fn lookup(dict: &Value, word: &str, lang: Option<&str>) -> Result<Value> {
    if let Some(l) = lang { if !["pl","en","nl"].contains(&l) { bail!("--lang pl|en|nl") } }
    let q = fold(word);
    let e = dict["entries"].as_array().ok_or(anyhow!("dictionary has no entries"))?
        .iter().find(|e| fold(e["word"].as_str().unwrap_or("")) == q
            || e["translations"].as_object().map(|t| t.values().any(|v| fold(v.as_str().unwrap_or("")) == q)).unwrap_or(false))
        .ok_or(anyhow!("word not in book: {word}"))?;
    let meaning = match lang { Some(l) => json!({l: e["meaning"][l]}), None => e["meaning"].clone() };
    Ok(json!({"word":e["word"],"example":e["example"].as_bool().unwrap_or(false),
        "translations":e["translations"],"meaning":meaning,"sources":e["sources"],
        "custodian_value":e["custodian_value"],
        "signature":"unsigned: no public signing path in core; secret keys are never read"}))
}

pub fn boot_plan() -> Value {
    json!({"dry_run":true,"network":false,"sudo":false,"target":"clean Raspberry Pi 5 (64-bit Linux)",
     "steps":[
      {"n":1,"step":"check","detail":"aarch64, disk >= 8 GB, clock synced"},
      {"n":2,"step":"fetch open-source libs","detail":"rust toolchain + vendored ans-xmss, popchain-cli (Apache-2.0)"},
      {"n":3,"step":"build","detail":"cargo build --release -p ans-core -j2"},
      {"n":4,"step":"build book","detail":"create ANS_HOME/book.json (anchor 417696) and dictionary.json"},
      {"n":5,"step":"init custodian","detail":"ans init <word>  (key created locally, mode 0600, never printed)"},
      {"n":6,"step":"start exploit","detail":"ans up  (local custodian node on 127.0.0.1)"},
      {"n":7,"step":"start wallet","detail":"pending: wallet framework not yet in core"},
      {"n":8,"step":"verify","detail":"ans status ; ans word exploit"}],
     "note":"plan only; nothing executed"})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn finds_exploit_pl() {
        let d: Value = serde_json::from_str(EXAMPLE).unwrap();
        let r = lookup(&d, "exploit", Some("pl")).unwrap();
        assert!(r["meaning"]["pl"].as_str().unwrap().contains("custodiana"));
        assert!(r["meaning"].get("en").is_none());
    }
    #[test] fn finds_by_translation_with_diacritics() {
        let d: Value = serde_json::from_str(EXAMPLE).unwrap();
        assert_eq!(lookup(&d, "Księga", None).unwrap()["word"], "ksiega");
        assert_eq!(lookup(&d, "bewaarder", None).unwrap()["word"], "custodian");
    }
    #[test] fn rejects_bad_lang_and_unknown() {
        let d: Value = serde_json::from_str(EXAMPLE).unwrap();
        assert!(lookup(&d, "exploit", Some("de")).is_err());
        assert!(lookup(&d, "nieznane", None).is_err());
    }
    #[test] fn plan_is_dry() {
        let p = boot_plan();
        assert_eq!(p["dry_run"], true); assert_eq!(p["network"], false);
        assert!(p["steps"].as_array().unwrap().len() >= 6);
    }
}
