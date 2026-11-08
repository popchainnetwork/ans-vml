// SPDX-License-Identifier: Apache-2.0
//! Importers (Rust, no Python): existing crystal JSON, and Kaikki/Wiktextract JSONL
//! entries (open Wiktionary extract, CC-BY-SA) into a word crystal with computed forms.
use crate::{forms, Crystal, CrystalKind, Leaf};
use anyhow::{anyhow, bail, Result};
use serde_json::{json, Map, Value};

pub fn crystal_json(text: &str) -> Result<Crystal> { Crystal::parse(text) }

/// Build a word crystal from Kaikki JSONL lines for `word` in language `lang`.
/// `letters` supplies verified letter crystals (one per character, in order).
pub fn kaikki(jsonl: &str, word: &str, lang: &str, source: &str, letters: &[Crystal]) -> Result<Crystal> {
    let mut leaves = vec![Leaf::new(&[("kind","identity"),("lang",lang),("value",word),("schema",crate::WORD_SCHEMA),("scope","finite lexical snapshot; NOT all languages/forms/meanings"),("data_license","CC-BY-SA-4.0"),("attribution","Wiktionary contributors via Kaikki/wiktextract")])];
    let mut n = 0;
    for line in jsonl.lines().filter(|l| !l.trim().is_empty()) {
        let e: Value = serde_json::from_str(line)?;
        if e["word"] != word || e["lang_code"] != lang { continue; }
        n += 1;
        for (i, s) in e["senses"].as_array().into_iter().flatten().enumerate() {
            for g in s["glosses"].as_array().into_iter().flatten().filter_map(Value::as_str) {
                leaves.push(Leaf::new(&[("kind","sense"),("lang",lang),("sense",&format!("{lang}-{}", i + 1)),("value",g),("source",source)]));
            }
        }
        for t in e["translations"].as_array().into_iter().flatten() {
            if let (Some(code), Some(w)) = (t["code"].as_str(), t["word"].as_str()) {
                leaves.push(Leaf::new(&[("kind","translation"),("lang",code),("value",w),("table",t["sense"].as_str().unwrap_or("")),("source",source)]));
            }
        }
    }
    if n == 0 { bail!("{word} ({lang}) not found in snapshot"); }
    let chars: Vec<char> = word.chars().collect();
    if letters.len() != chars.len() { bail!("need {} letter crystals", chars.len()); }
    for (i, (c, l)) in chars.iter().zip(letters).enumerate() {
        if l.id != c.to_string() { bail!("letter crystal {} does not match {c}", l.id); }
        leaves.push(Leaf::new(&[("kind","character_reference"),("lang",lang),("value",&l.id),("position",&i.to_string()),("root",&l.root),("source",&format!("local:unicode/{}", l.file_name())),("relation","ordered word composition")]));
    }
    let folded = forms::fold(word);
    let ucd = "https://www.unicode.org/Public/17.0.0/ucd/UnicodeData.txt";
    leaves.push(Leaf::new(&[("kind","form"),("form","codepoints"),("lang",lang),("of",word),("value",&forms::codepoints(word)),("source",ucd)]));
    leaves.push(Leaf::new(&[("kind","form"),("form","ASCII_fold_lossy"),("lang",lang),("of",word),("value",&folded),("source","https://www.unicode.org/reports/tr15/")]));
    if let Some(m) = folded.chars().map(forms::morse).collect::<Option<Vec<_>>>() {
        leaves.push(Leaf::new(&[("kind","form"),("form","International_Morse_of_ASCII_fold"),("lang",lang),("of",word),("value",&m.join(" ")),("source",forms::ITU_MORSE)]));
    }
    if let Some(b) = word.to_lowercase().chars().map(forms::polish_braille).collect::<Option<String>>() {
        leaves.push(Leaf::new(&[("kind","form"),("form","Polish_Braille_uncontracted"),("lang",lang),("of",word),("value",&b),("source",forms::PL_BRAILLE)]));
    }
    leaves.sort(); leaves.dedup();
    let meta: Map<String, Value> = json!({"language":lang,"complete":false,"minted":false,"signed":false}).as_object().ok_or_else(|| anyhow!("meta"))?.clone();
    Crystal::build(CrystalKind::Word, word, leaves, meta)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn kaikki_fixture_builds_reproducible_crystal() {
        let ucd = forms::Ucd::load(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/crystals")).unwrap();
        let letters: Vec<_> = "dom".chars().map(|c| ucd.letter(c).unwrap()).collect();
        let jsonl = r#"{"word":"dom","lang_code":"pl","senses":[{"glosses":["house"]}],"translations":[{"code":"en","word":"house","sense":"building"},{"code":"nl","word":"huis","sense":"building"}]}"#;
        let a = kaikki(jsonl, "dom", "pl", "fixture", &letters).unwrap();
        let b = kaikki(jsonl, "dom", "pl", "fixture", &letters).unwrap();
        assert_eq!(a.root, b.root);
        assert_eq!(Crystal::parse(&a.to_json()).unwrap().root, a.root);
        assert!(a.leaves.iter().any(|l| l.get("form") == Some("International_Morse_of_ASCII_fold") && l.get("value") == Some("-.. --- --")));
        assert!(kaikki(jsonl, "kot", "pl", "fixture", &letters).is_err());
    }
}
