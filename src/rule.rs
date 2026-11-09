// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Paweł Piekut / Pplastechniek
//! The word rule: decides whether a word may be stored (sync) or executed (run).
//! A word counts only if its crystal root re-verifies, it is MINTED (a signed
//! `word.mint` event binding that root in an XMSSMT-signed custodian journal),
//! it has a known kind (meaning or exec), and for `run` a signed, unrevoked
//! `word.delegate` grant for the exec scope exists in the local journal.
use ans_dict::{exec, Crystal};
use anyhow::{bail, Result};
use serde_json::{json, Value};

pub const LOCK: &str = include_str!("../Cargo.lock");

#[derive(Debug, PartialEq)]
pub enum Kind { Meaning, Exec(String) }

pub fn kind(c: &Crystal) -> Result<Kind> {
    if let Some(e) = exec::exec_of(c)? { return Ok(Kind::Exec(e.scope)); }
    if c.leaves.iter().any(|l| matches!(l.get("kind"), Some("sense") | Some("translation") | Some("character"))) { return Ok(Kind::Meaning); }
    bail!("word has neither meaning nor exec leaves")
}

fn action(e: &Value) -> &str { e["body"]["action"].as_str().unwrap_or("") }
fn root_of(e: &Value) -> &str { e["body"]["data"]["root"].as_str().unwrap_or("") }

/// A signed mint event for `root`: from the local journal or a peer-supplied proof.
pub fn mint_proof<'a>(root: &str, journal: &'a [Value], peer_proofs: &'a [Value], valid: &dyn Fn(&Value) -> bool) -> Option<&'a Value> {
    journal.iter().chain(peer_proofs).find(|e| action(e) == "word.mint" && root_of(e) == root && valid(e))
}

pub fn delegated(root: &str, scope: &str, journal: &[Value], valid: &dyn Fn(&Value) -> bool) -> bool {
    let mut ok = false;
    // Only dictionary-service grants count; bare legacy word.delegate events are ignored.
    for e in journal.iter().filter(|e| root_of(e) == root && e["body"]["data"]["scope"] == scope && e["body"]["data"]["service"] == "dictionary" && valid(e)) {
        match action(e) { "word.delegate" => ok = true, "word.revoke" => ok = false, _ => {} }
    }
    ok
}

/// Minted letter lookup: char -> (letter root, mint block).
pub type Letters<'a> = &'a dyn Fn(char) -> Option<(String, Value)>;

/// Layer 2 rule: every character of a word must be an already-minted letter crystal,
/// and any character_reference leaf must point at exactly that minted root.
pub fn letters_of(c: &Crystal, letters: Letters) -> Result<Vec<Value>> {
    if c.kind == ans_dict::CrystalKind::Letter { return Ok(vec![]); }
    let mut out = vec![];
    for (i, ch) in c.id.to_lowercase().chars().enumerate() {
        let (root, block) = letters(ch).ok_or_else(|| anyhow::anyhow!("letter '{ch}' (U+{:04X}) is not minted; mint the alphabet first", ch as u32))?;
        if let Some(r) = c.of_kind("character_reference").find(|l| l.get("position") == Some(i.to_string().as_str())) {
            if r.get("root") != Some(root.as_str()) { bail!("character_reference {i} root does not match minted letter '{ch}'"); }
        }
        out.push(json!({"char":ch.to_string(),"root":root,"block":block}));
    }
    Ok(out)
}

#[derive(Debug)]
pub enum Use<'a> { Store, Run { scope: &'a str } }

/// Accept/reject with reason. `c` was produced by Crystal::parse, so its root already re-verified.
pub fn check(c: &Crystal, u: Use, journal: &[Value], peer_proofs: &[Value], valid: &dyn Fn(&Value) -> bool, letters: Letters) -> Value {
    let r = (|| -> Result<Value> {
        let k = kind(c)?;
        letters_of(c, letters)?;
        let proof = mint_proof(&c.root, journal, peer_proofs, valid).ok_or_else(|| anyhow::anyhow!("not minted: no valid signed word.mint for root {}", c.root))?;
        let mut out = json!({"accept":true,"word":c.id,"root":c.root,"kind":format!("{k:?}"),"mint_block":proof["seq"],"mint_key":proof["xmss"]["pk"].as_str().map(|p| &p[..16.min(p.len())])});
        if let Use::Run { scope } = u {
            let Kind::Exec(need) = &k else { bail!("word has no exec leaf; nothing to run") };
            if need != scope { bail!("exec requires scope {need}, asked {scope}"); }
            if !delegated(&c.root, scope, journal, valid) { bail!("no signed delegation for scope {scope}; run `ans delegate {} {scope}` as the custodian", c.id); }
            out["resolved"] = exec::resolve(&exec::exec_of(c)?.unwrap(), LOCK)?;
        }
        Ok(out)
    })();
    r.unwrap_or_else(|e| json!({"accept":false,"word":c.id,"root":c.root,"reason":e.to_string()}))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hash_word() -> Crystal { exec::exec_word("hash", "sha3_256", "run", "sha3", "0.10.9", LOCK, "compute SHA3-256 of a string").unwrap() }
    fn dir(n: &str) -> std::path::PathBuf { let d = std::env::temp_dir().join(format!("ans-rule-{n}-{}", std::process::id())); let _ = std::fs::remove_dir_all(&d); d }
    #[test]
    fn unminted_refused_minted_runs_tamper_and_revoke_refused() {
        let d = dir("a");
        let w = hash_word();
        let v = |e: &Value| crate::exploit::event_valid(e);
        let all = |ch: char| Some((format!("root-{ch}"), json!(1)));
        let no_s = |ch: char| (ch != 's').then(|| (format!("root-{ch}"), json!(1)));
        assert!(letters_of(&w, &no_s).unwrap_err().to_string().contains("letter 's'"));
        let j = crate::exploit::journal("alice", &d).unwrap();
        assert!(check(&w, Use::Store, &j, &[], &v, &all)["reason"].as_str().unwrap().contains("not minted"));
        crate::exploit::record_local("alice", &d, "word.mint", json!({"word":"hash","root":w.root,"file":w.file_name()})).unwrap();
        let j = crate::exploit::journal("alice", &d).unwrap();
        assert_eq!(check(&w, Use::Store, &j, &[], &v, &all)["accept"], true);
        assert!(check(&w, Use::Store, &j, &[], &v, &no_s)["reason"].as_str().unwrap().contains("not minted"));
        let r = check(&w, Use::Run { scope: "run" }, &j, &[], &v, &all);
        assert!(r["reason"].as_str().unwrap().contains("no signed delegation"), "{r}");
        // The signer refuses grants written outside a dictionary transaction.
        let bare = crate::exploit::record_local("alice", &d, "word.delegate", json!({"word":"hash","root":w.root,"scope":"run"}));
        assert!(bare.unwrap_err().to_string().contains("dictionary lifecycle"));
        let in_tx = |id: &str, act: &str| {
            let intent = crate::exploit::record_local("alice", &d, "dictionary.intent", json!({"request":{"op_id":id}})).unwrap();
            crate::exploit::record_local("alice", &d, act, json!({"word":"hash","root":w.root,"scope":"run","op_id":id,"service":"dictionary"})).unwrap();
            crate::exploit::record_local("alice", &d, "dictionary.outcome", json!({"intent_hash":intent["hash"]})).unwrap();
        };
        in_tx("grant-1", "word.delegate");
        let j = crate::exploit::journal("alice", &d).unwrap();
        let r = check(&w, Use::Run { scope: "run" }, &j, &[], &v, &all);
        assert_eq!(r["accept"], true, "{r}");
        assert_eq!(exec::run_builtin("sha3_256", "abc").unwrap(), "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
        // a forged mint event (signature broken) does not count
        let mut forged = j.iter().find(|e| action(e) == "word.mint").unwrap().clone();
        forged["body"]["data"]["root"] = json!("00".repeat(32));
        let fake = Crystal { root: "00".repeat(32), ..w.clone() };
        assert_eq!(check(&fake, Use::Store, &[], &[forged], &v, &all)["accept"], false);
        // tampered crystal never parses
        let mut t: Value = serde_json::from_str(&w.to_json()).unwrap();
        t["leaves"][0]["value"] = json!("x");
        assert!(Crystal::parse(&t.to_string()).is_err());
        // revoke
        in_tx("revoke-1", "word.revoke");
        let j = crate::exploit::journal("alice", &d).unwrap();
        assert_eq!(check(&w, Use::Run { scope: "run" }, &j, &[], &v, &all)["accept"], false);
        let _ = std::fs::remove_dir_all(&d);
    }
}
