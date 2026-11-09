// SPDX-License-Identifier: Apache-2.0
//! Compose user-authored crystals from explicit CLI text. Leaves bind identity,
//! schema, content, language, source, license and attribution into the Merkle
//! root. This does not validate linguistic truth, legal rights, or completeness.
use crate::{forms, Crystal, CrystalKind, Leaf, CHAR_SCHEMA, WORD_SCHEMA};
use anyhow::{bail, Result};
use serde_json::{json, Map, Value};

const UNVERIFIED_LICENSE: &str = "unspecified/unverified";
const UNVERIFIED_SOURCE: &str = "user-supplied; unverified";
const UNVERIFIED_ATTRIBUTION: &str = "user-supplied; unverified factual accuracy; not rights-validated";
const WORD_SCOPE: &str =
    "user-authored experimental snapshot; NOT linguistic validation, rights clearance, completeness, translation quality, or execution permission";
const CHAR_SCOPE: &str =
    "user-authored experimental character; NOT full UCD metadata, universal alphabet, phonetic value, or cross-script equivalence";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Provenance {
    pub source: String,
    pub license: String,
    pub attribution: String,
    pub unverified: bool,
}

impl Provenance {
    pub fn explicit(source: &str, license: &str, attribution: Option<&str>) -> Result<Self> {
        let source = require_text("source", source, 1, 2048)?;
        let license = require_text("license", license, 1, 256)?;
        let attribution = match attribution {
            Some(a) => require_text("attribution", a, 1, 2048)?,
            None => format!("{UNVERIFIED_ATTRIBUTION}; license/source were supplied by the author"),
        };
        Ok(Self {
            source,
            license,
            attribution,
            unverified: false,
        })
    }
    pub fn unverified() -> Self {
        Self {
            source: UNVERIFIED_SOURCE.into(),
            license: UNVERIFIED_LICENSE.into(),
            attribution: UNVERIFIED_ATTRIBUTION.into(),
            unverified: true,
        }
    }
}

fn require_text(label: &str, raw: &str, min: usize, max: usize) -> Result<String> {
    if raw.len() < min || raw.len() > max {
        bail!("{label} must contain {min}–{max} UTF-8 bytes");
    }
    if raw.chars().any(|c| c.is_control()) {
        bail!("{label} must not contain control characters");
    }
    if raw.trim() != raw {
        bail!("{label} must not include leading or trailing whitespace (identifiers are not silently trimmed or Unicode-normalized)");
    }
    if raw.is_empty() {
        bail!("{label} must not be empty");
    }
    Ok(raw.to_owned())
}

fn require_language(lang: &str) -> Result<String> {
    let lang = require_text("language", lang, 2, 16)?;
    if !lang
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || !lang.as_bytes()[0].is_ascii_lowercase()
        || lang == "und"
    {
        bail!("Word language must be an explicit lowercase tag such as en or pl; und is reserved for characters");
    }
    Ok(lang)
}

fn require_word_id(word: &str) -> Result<String> {
    let word = require_text("word", word, 1, 128)?;
    if word.chars().any(|c| matches!(c, '/' | '\\' | '\0')) {
        bail!("Word identity must not contain path separators");
    }
    if word.chars().count() < 1 {
        bail!("Word identity must contain at least one Unicode scalar");
    }
    Ok(word)
}

fn require_character(id: &str) -> Result<char> {
    let id = require_text("character", id, 1, 8)?;
    let mut chars = id.chars();
    let Some(c) = chars.next() else {
        bail!("Character identity must be one Unicode scalar");
    };
    if chars.next().is_some() {
        bail!("Character identity must be exactly one Unicode scalar; no silent normalization");
    }
    if c.is_control() || c.is_whitespace() {
        bail!("Character identity must not be control or whitespace");
    }
    Ok(c)
}

/// Build a character crystal from explicit CLI text. Root-bound leaves only;
/// no UCD name/category invention and no claim of universal alphabet coverage.
pub fn character(id: &str, provenance: &Provenance) -> Result<Crystal> {
    let c = require_character(id)?;
    let s = c.to_string();
    let cp = format!("U+{:04X}", c as u32);
    let mut leaves = vec![
        Leaf::new(&[
            ("kind", "identity"),
            ("value", &s),
            ("schema", CHAR_SCHEMA),
            ("scope", CHAR_SCOPE),
            ("source", &provenance.source),
            ("data_license", &provenance.license),
            ("attribution", &provenance.attribution),
            ("provenance", "user-supplied"),
            (
                "accuracy",
                if provenance.unverified {
                    "unverified"
                } else {
                    "author-asserted; not independently validated"
                },
            ),
        ]),
        Leaf::new(&[
            ("kind", "character"),
            ("value", &s),
            ("codepoint", &cp),
            (
                "note",
                "codepoint derived from the Unicode scalar only; not a full UCD record",
            ),
            ("source", &provenance.source),
        ]),
    ];
    leaves.sort();
    leaves.dedup();
    let meta: Map<String, Value> = json!({
        "complete": false,
        "minted": false,
        "signed": false,
        "authored": true,
        "gaps": [
            "User-authored character: not a full Unicode Character Database crystal.",
            "No phonetic value, case mapping, or cross-script equivalence is inferred.",
            "Merkle root binds authored leaves only; not linguistic truth or rights clearance."
        ]
    })
    .as_object()
    .unwrap()
    .clone();
    Crystal::build(CrystalKind::Letter, &s, leaves, meta)
}

/// Build a word crystal from explicit CLI text. Character references are omitted
/// so the root stays deterministic from the supplied bytes and does not depend on
/// ambient alphabet state; mint still requires separately minted characters for
/// each lowercase scalar of the spelling under the existing letters_of rule.
pub fn word(id: &str, language: &str, meaning: &str, provenance: &Provenance) -> Result<Crystal> {
    let word = require_word_id(id)?;
    let lang = require_language(language)?;
    let meaning = require_text("meaning", meaning, 1, 8192)?;
    let mut leaves = vec![
        Leaf::new(&[
            ("kind", "identity"),
            ("lang", &lang),
            ("value", &word),
            ("schema", WORD_SCHEMA),
            ("scope", WORD_SCOPE),
            ("source", &provenance.source),
            ("data_license", &provenance.license),
            ("attribution", &provenance.attribution),
            ("provenance", "user-supplied"),
            (
                "accuracy",
                if provenance.unverified {
                    "unverified"
                } else {
                    "author-asserted; not independently validated"
                },
            ),
        ]),
        Leaf::new(&[
            ("kind", "sense"),
            ("lang", &lang),
            ("sense", &format!("{lang}-1")),
            ("value", &meaning),
            ("source", &provenance.source),
            ("accuracy", "user-supplied/unverified factual accuracy"),
            (
                "note",
                "hashed authored gloss only; the runtime does not understand language semantics",
            ),
        ]),
    ];
    let ucd = "https://www.unicode.org/Public/17.0.0/ucd/UnicodeData.txt";
    let folded = forms::fold(&word);
    leaves.push(Leaf::new(&[
        ("kind", "form"),
        ("form", "codepoints"),
        ("lang", &lang),
        ("of", &word),
        ("value", &forms::codepoints(&word)),
        ("source", ucd),
    ]));
    leaves.push(Leaf::new(&[
        ("kind", "form"),
        ("form", "ASCII_fold_lossy"),
        ("lang", &lang),
        ("of", &word),
        ("value", &folded),
        ("source", "https://www.unicode.org/reports/tr15/"),
        (
            "method",
            "lookup fold only; identity bytes are not Unicode-normalized",
        ),
    ]));
    if let Some(m) = folded.chars().map(forms::morse).collect::<Option<Vec<_>>>() {
        leaves.push(Leaf::new(&[
            ("kind", "form"),
            ("form", "International_Morse_of_ASCII_fold"),
            ("lang", &lang),
            ("of", &word),
            ("value", &m.join(" ")),
            ("source", forms::ITU_MORSE),
        ]));
    }
    if let Some(b) = word
        .to_lowercase()
        .chars()
        .map(forms::polish_braille)
        .collect::<Option<String>>()
    {
        leaves.push(Leaf::new(&[
            ("kind", "form"),
            ("form", "Polish_Braille_uncontracted"),
            ("lang", &lang),
            ("of", &word),
            ("value", &b),
            ("source", forms::PL_BRAILLE),
        ]));
    }
    leaves.sort();
    leaves.dedup();
    let meta: Map<String, Value> = json!({
        "language": lang,
        "complete": false,
        "minted": false,
        "signed": false,
        "authored": true,
        "gaps": [
            "User-authored word: sense text is supplied/unverified, not a certified definition.",
            "No character_reference leaves are auto-bound; mint still requires each lowercase spelling scalar to be a minted character.",
            "Merkle root binds authored leaves only; not linguistic truth, rights clearance, translation quality, or execution permission."
        ]
    })
    .as_object()
    .unwrap()
    .clone();
    Crystal::build(CrystalKind::Word, &word, leaves, meta)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authored_roots_are_deterministic_and_content_bound() {
        let p = Provenance::explicit("local-test", "CC0-1.0", Some("test author")).unwrap();
        let a = word("dom", "pl", "house", &p).unwrap();
        let b = word("dom", "pl", "house", &p).unwrap();
        assert_eq!(a.root, b.root);
        assert_eq!(Crystal::parse(&a.to_json()).unwrap().root, a.root);
        let meaning = word("dom", "pl", "home", &p).unwrap();
        let lang = word("dom", "en", "house", &p).unwrap();
        let source = word(
            "dom",
            "pl",
            "house",
            &Provenance::explicit("other-source", "CC0-1.0", Some("test author")).unwrap(),
        )
        .unwrap();
        let license = word(
            "dom",
            "pl",
            "house",
            &Provenance::explicit("local-test", "MIT", Some("test author")).unwrap(),
        )
        .unwrap();
        let attribution = word(
            "dom",
            "pl",
            "house",
            &Provenance::explicit("local-test", "CC0-1.0", Some("other")).unwrap(),
        )
        .unwrap();
        assert_ne!(a.root, meaning.root);
        assert_ne!(a.root, lang.root);
        assert_ne!(a.root, source.root);
        assert_ne!(a.root, license.root);
        assert_ne!(a.root, attribution.root);
        let ch = character("d", &p).unwrap();
        assert_eq!(ch.id, "d");
        assert_eq!(ch.kind, CrystalKind::Letter);
        assert!(ch.of_kind("character").any(|l| l.get("value") == Some("d")));
        assert!(word("", "pl", "x", &p).is_err());
        assert!(word(" dom", "pl", "x", &p).is_err());
        assert!(word("dom", "UND", "x", &p).is_err());
        assert!(word("dom", "und", "x", &p).is_err());
        assert!(character("ab", &p).is_err());
        assert!(character(" ", &p).is_err());
        assert!(Provenance::explicit("", "MIT", None).is_err());
    }
}
