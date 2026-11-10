// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Paweł Piekut / Pplastechniek
//! Human-readable console text for operations on words.
//!
//! The same results are available unchanged as JSON (`--json`, or whenever stdout is not a
//! terminal), so scripts and tests keep their machine format. This module only renders; it never
//! decides acceptance, so the text cannot claim more than the underlying result says.
use serde_json::Value;

/// How a command result is printed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Output {
    Text,
    Json,
}

impl Output {
    /// `--json` / `--text` win; otherwise text on an interactive terminal and JSON when piped.
    pub fn choose(json: bool, text: bool, stdout_is_terminal: bool) -> Self {
        match (json, text) {
            (true, _) => Output::Json,
            (_, true) => Output::Text,
            _ if stdout_is_terminal => Output::Text,
            _ => Output::Json,
        }
    }
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or("")
}
fn short(root: &str) -> String {
    if root.len() > 12 { format!("{}…", &root[..12]) } else { root.to_owned() }
}
fn network(v: &Value) -> String {
    match v["network"].as_str() {
        Some(n) if !n.is_empty() => format!(" on {n}"),
        _ => String::new(),
    }
}
fn noun(v: &Value) -> &'static str {
    if v["layer"] == 1 { "Character" } else { "Word" }
}
const FOOTER: &str = "  Local journal only; private key never printed.";

/// Renders a word-level command (`mint`, `mint-alphabet`, `mint-meaning`, `delegate`, `revoke`,
/// `run`). Returns None for shapes it does not know, so the caller falls back to JSON.
pub fn word_command(cmd: &str, v: &Value) -> Option<String> {
    match cmd {
        "mint-meaning" => Some(meaning(v)),
        "delegate" | "revoke" => Some(grant(cmd, v)),
        "mint" | "mint-alphabet" => mint_list(v),
        "run" => Some(run(v)),
        _ => None,
    }
}

fn meaning(v: &Value) -> String {
    let (word, lang) = (s(v, "word"), s(v, "lang"));
    if v["already"] == true {
        return format!("Word \"{word}\" already has this meaning ({lang}); nothing new was signed.");
    }
    format!(
        "Meaning added to word \"{word}\" ({lang}): signed as block {}{}.\n  Recorded as intent → word.meaning → outcome, operation {}.\n{FOOTER}",
        v["block"], network(v), s(v, "op_id")
    )
}

fn grant(cmd: &str, v: &Value) -> String {
    let (word, scope) = (s(v, "word"), s(v, "scope"));
    match (cmd, v["already"] == true, s(v, "state")) {
        ("delegate", true, "already delegated") => {
            format!("Word \"{word}\" is already delegated for scope \"{scope}\"; nothing was signed.")
        }
        ("revoke", true, "not delegated") => {
            format!("Word \"{word}\" is not delegated for scope \"{scope}\"; nothing to revoke, nothing was signed.")
        }
        ("delegate", true, _) => {
            format!("Word \"{word}\" was already delegated for scope \"{scope}\" by operation {}; nothing new was signed.", s(v, "op_id"))
        }
        ("revoke", true, _) => {
            format!("Delegation of word \"{word}\" for scope \"{scope}\" was already revoked by operation {}; nothing new was signed.", s(v, "op_id"))
        }
        ("delegate", false, _) => format!(
            "Word \"{word}\" delegated for scope \"{scope}\": signed as block {}{}.\n  Recorded as intent → word.delegate → outcome, operation {}.\n{FOOTER}",
            v["block"], network(v), s(v, "op_id")
        ),
        _ => format!(
            "Delegation of word \"{word}\" for scope \"{scope}\" revoked: signed as block {}{}.\n  Recorded as intent → word.revoke → outcome, operation {}.\n{FOOTER}",
            v["block"], network(v), s(v, "op_id")
        ),
    }
}

fn mint_list(v: &Value) -> Option<String> {
    let items = v["minted"].as_array()?;
    let mut lines: Vec<String> = items.iter().map(mint_item).collect();
    if items.is_empty() {
        lines.push("Nothing to mint.".into());
    }
    lines.push(FOOTER.into());
    Some(lines.join("\n"))
}

fn mint_item(m: &Value) -> String {
    let word = s(m, "word");
    if let Some(reason) = m["refused"].as_str() {
        return format!("Word \"{word}\" was not minted: {reason}");
    }
    if m["legacy_native_only"] == true {
        return format!(
            "Word \"{word}\" has an old native mint (block {}) without a dictionary lifecycle; it is not promoted automatically.",
            m["block"]
        );
    }
    if m["already"] == true {
        return format!("{} \"{word}\" is already minted (block {}); nothing new was signed.", noun(m), m["block"]);
    }
    format!(
        "{} \"{word}\" minted as block {}{} (draft → validate → mint).",
        noun(m), m["block"], network(m)
    )
}

fn run(v: &Value) -> String {
    let word = s(v, "word");
    let function = v["resolved"]["function"].as_str().unwrap_or("its built-in function");
    if v["dry_run"] == true {
        return format!(
            "Word \"{word}\" may run: function {function}, minted at block {}, delegation active.\n  Dry run; nothing was executed.",
            v["mint_block"]
        );
    }
    format!(
        "Word \"{word}\" ran {function} on \"{}\":\n  {}",
        s(v, "input"),
        v["output"].as_str().unwrap_or("")
    )
}

/// Renders an owner `dictionary write|draft|validate|mint|inspect` receipt.
pub fn dictionary_receipt(sub: &str, target: &str, v: &Value) -> Option<String> {
    let receipt = v.get("receipt")?;
    let status = receipt["status"].as_str()?;
    let entry = &receipt["entry"];
    let word = entry["word"]["spelling"].as_str().unwrap_or(target);
    let lang = entry["word"]["language"].as_str().unwrap_or("");
    let lang = if lang.is_empty() || lang == "und" { String::new() } else { format!(" ({lang})") };
    let op = s(v, "op_id");
    let block = v["outcome"]["seq"].clone();
    let replay = if v["retry"] == true { "\n  This operation ID was used before; its stored receipt was replayed." } else { "" };
    let (noun, lower) = if entry["crystal"]["character"].is_string() { ("Character", "character") } else { ("Word", "word") };
    let state = match entry["state"].as_str().unwrap_or("recorded") {
        "draft" => "a draft".to_owned(),
        other => other.to_owned(),
    };
    let mut text = match status {
        "accepted" => format!(
            "{noun} \"{word}\"{lang} is {}{state}: dictionary {sub} accepted (operation {op}, outcome block {block}).{replay}",
            if sub == "inspect" { "" } else { "now " }
        ),
        "rejected" => format!(
            "Dictionary {sub} of {lower} \"{word}\" was rejected: {}.\n  The rejection is signed (outcome block {block}); the {lower} did not change.{replay}",
            receipt["reason"].as_str().unwrap_or("no reason given").trim_end_matches('.')
        ),
        "interrupted" => format!(
            "Dictionary {sub} of {lower} \"{word}\" ended as interrupted (operation {op}); it was closed without applying its effect. Run it again with a new operation ID."
        ),
        other => format!("Dictionary {sub} of {lower} \"{word}\": {other} (operation {op})."),
    };
    if let Some(gaps) = entry["crystal"]["gaps"].as_array() {
        for g in gaps.iter().filter_map(Value::as_str) {
            text.push_str(&format!("\n  Note: {g}"));
        }
    }
    text.push('\n');
    text.push_str(FOOTER);
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn no_json(t: &str) {
        assert!(!t.contains('{') && !t.contains('}') && !t.contains('['), "looks like JSON: {t}");
    }

    #[test]
    fn mode_prefers_flags_then_terminal() {
        assert_eq!(Output::choose(false, false, true), Output::Text);
        assert_eq!(Output::choose(false, false, false), Output::Json);
        assert_eq!(Output::choose(true, false, true), Output::Json);
        assert_eq!(Output::choose(false, true, false), Output::Text);
    }

    #[test]
    fn word_operations_read_as_sentences() {
        let m = json!({"action":"word.meaning","word":"oak","lang":"en","block":32,"network":"devnet","op_id":"legacy-meaning-x"});
        let t = word_command("mint-meaning", &m).unwrap();
        assert!(t.starts_with("Meaning added to word \"oak\" (en): signed as block 32 on devnet."), "{t}");
        no_json(&t);
        let again = word_command("mint-meaning", &json!({"already":true,"word":"oak","lang":"en"})).unwrap();
        assert!(again.contains("nothing new was signed"), "{again}");

        let d = word_command("delegate", &json!({"word":"oak","scope":"run","block":35,"network":"devnet","op_id":"g0"})).unwrap();
        assert!(d.starts_with("Word \"oak\" delegated for scope \"run\": signed as block 35"), "{d}");
        let dd = word_command("delegate", &json!({"already":true,"state":"already delegated","word":"oak","scope":"run"})).unwrap();
        assert!(dd.contains("already delegated") && dd.contains("nothing was signed"), "{dd}");
        let r = word_command("revoke", &json!({"word":"oak","scope":"run","block":38,"network":"devnet","op_id":"g1"})).unwrap();
        assert!(r.starts_with("Delegation of word \"oak\" for scope \"run\" revoked"), "{r}");
        let rr = word_command("revoke", &json!({"already":true,"state":"not delegated","word":"oak","scope":"run"})).unwrap();
        assert!(rr.contains("nothing to revoke"), "{rr}");
        for t in [&d, &dd, &r, &rr] { no_json(t); }

        let mint = json!({"minted":[
            {"word":"a","layer":1,"block":3,"network":"devnet","lifecycle":"minted"},
            {"word":"oak","layer":2,"block":29,"already":true},
            {"word":"ox","refused":"letter 'x' (U+0078) is not minted; mint the alphabet first"}]});
        let t = word_command("mint", &mint).unwrap();
        assert!(t.contains("Character \"a\" minted as block 3 on devnet"), "{t}");
        assert!(t.contains("Word \"oak\" is already minted (block 29)"), "{t}");
        assert!(t.contains("Word \"ox\" was not minted: letter 'x'"), "{t}");

        let plan = word_command("run", &json!({"word":"hash","dry_run":true,"mint_block":9,"resolved":{"function":"sha3_256"}})).unwrap();
        assert!(plan.contains("may run: function sha3_256") && plan.contains("nothing was executed"), "{plan}");
        let ran = word_command("run", &json!({"word":"hash","input":"abc","output":"3a98","resolved":{"function":"sha3_256"}})).unwrap();
        assert_eq!(ran, "Word \"hash\" ran sha3_256 on \"abc\":\n  3a98");
        assert!(word_command("sync", &json!({})).is_none());
    }

    #[test]
    fn dictionary_receipts_report_status_without_overclaiming() {
        let ok = json!({"op_id":"w-v","retry":false,"outcome":{"seq":30},"receipt":{"status":"accepted","entry":{"state":"validated","word":{"language":"en","spelling":"oak"},"crystal":{"gaps":["sense text is unverified"]}}}});
        let t = dictionary_receipt("validate", "oak", &ok).unwrap();
        assert!(t.starts_with("Word \"oak\" (en) is now validated: dictionary validate accepted (operation w-v, outcome block 30)."), "{t}");
        assert!(t.contains("Note: sense text is unverified"), "{t}");
        no_json(&t);
        let rej = json!({"op_id":"w-m","retry":true,"outcome":{"seq":31},"receipt":{"status":"rejected","reason":"letter 'a' (U+0061) is not minted; mint the alphabet first","entry":null}});
        let t = dictionary_receipt("mint", "oak", &rej).unwrap();
        assert!(t.contains("Dictionary mint of word \"oak\" was rejected: letter 'a'"), "{t}");
        assert!(t.contains("the word did not change") && t.contains("stored receipt was replayed"), "{t}");
        assert!(!t.contains("is now"), "{t}");
        assert!(dictionary_receipt("mint", "oak", &json!({"help":"x"})).is_none());
        let ch = json!({"op_id":"c-o","outcome":{"seq":4},"receipt":{"status":"accepted","entry":{"state":"draft","word":{"language":"und","spelling":"o"},"crystal":{"character":"o"}}}});
        let t = dictionary_receipt("write", "o", &ch).unwrap();
        assert!(t.starts_with("Character \"o\" is now a draft: dictionary write accepted"), "{t}");
    }
}
