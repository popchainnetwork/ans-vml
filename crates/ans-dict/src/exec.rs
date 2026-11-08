// SPDX-License-Identifier: Apache-2.0
//! Executable words. An `exec` leaf names a function and the open-source package
//! that implements it, pinned like Cargo does: registry + name + version + checksum
//! (or git URL + commit). Only built-in functions linked into this binary can run;
//! nothing is fetched or executed from the network.
use crate::{Crystal, CrystalKind, Leaf};
use anyhow::{anyhow, bail, Result};
use serde_json::{json, Map, Value};
use sha3::{Digest, Sha3_256};

#[derive(Debug, Clone)]
pub struct Exec { pub function: String, pub scope: String, pub registry: String, pub package: String, pub version: String, pub checksum: String, pub source: String }

impl Exec {
    pub fn from_leaf(l: &Leaf) -> Result<Exec> {
        let g = |k: &str| l.get(k).map(str::to_string).ok_or_else(|| anyhow!("exec leaf missing {k}"));
        Ok(Exec { function: g("function")?, scope: g("scope")?, registry: g("registry")?, package: g("package")?, version: g("version")?, checksum: g("checksum")?, source: g("source")? })
    }
}

pub fn exec_of(c: &Crystal) -> Result<Option<Exec>> {
    let mut it = c.of_kind("exec");
    let first = it.next();
    if it.next().is_some() { bail!("more than one exec leaf"); }
    first.map(Exec::from_leaf).transpose()
}

/// Find `[[package]] name/version` in a Cargo.lock and return (source, checksum).
pub fn lock_entry(lock: &str, name: &str, version: &str) -> Option<(String, String)> {
    lock.split("[[package]]").find_map(|blk| {
        let get = |k: &str| blk.lines().find_map(|l| l.strip_prefix(&format!("{k} = \"")).and_then(|r| r.strip_suffix('"')).map(str::to_string));
        (get("name")? == name && get("version")? == version).then(|| Some((get("source")?, get("checksum")?))).flatten()
    })
}

/// Resolve an exec leaf against real lockfile metadata. Errors on any mismatch.
pub fn resolve(e: &Exec, lock: &str) -> Result<Value> {
    if e.registry != "crates.io" { bail!("registry {} not supported yet (crates.io only; git pinning not implemented)", e.registry); }
    let (src, sum) = lock_entry(lock, &e.package, &e.version).ok_or_else(|| anyhow!("{} {} not in Cargo.lock", e.package, e.version))?;
    if sum != e.checksum { bail!("hash mismatch for {} {}: word pins {}, Cargo.lock has {}", e.package, e.version, e.checksum, sum); }
    if !builtin_known(&e.function) { bail!("function {} is not a built-in; remote code is never executed", e.function); }
    Ok(json!({"function":e.function,"scope":e.scope,"package":e.package,"version":e.version,"registry_source":src,
        "download":format!("https://static.crates.io/crates/{0}/{0}-{1}.crate", e.package, e.version),
        "expected_sha256":sum,"checksum_from":"Cargo.lock (cargo verifies .crate sha256 at build)","linked_in_binary":true,"network_fetch":false}))
}

fn builtin_known(f: &str) -> bool { f == "sha3_256" }

pub fn run_builtin(f: &str, input: &str) -> Result<String> {
    match f { "sha3_256" => Ok(hex::encode(Sha3_256::digest(input.as_bytes()))), _ => bail!("unknown built-in {f}") }
}

/// Build an executable word whose checksum is read from Cargo.lock, never typed in.
pub fn exec_word(word: &str, function: &str, scope: &str, package: &str, version: &str, lock: &str, meaning: &str) -> Result<Crystal> {
    let (_, sum) = lock_entry(lock, package, version).ok_or_else(|| anyhow!("{package} {version} not in Cargo.lock"))?;
    let leaves = vec![
        Leaf::new(&[("kind","identity"),("value",word),("schema",crate::WORD_SCHEMA),("scope","executable word; local built-in only")]),
        Leaf::new(&[("kind","sense"),("lang","en"),("value",meaning),("source","local:ans-dict exec")]),
        Leaf::new(&[("kind","exec"),("function",function),("scope",scope),("registry","crates.io"),("package",package),("version",version),("checksum",&sum),("source","registry+https://github.com/rust-lang/crates.io-index")]),
        Leaf::new(&[("kind","form"),("form","codepoints"),("value",&crate::forms::codepoints(word)),("source","https://www.unicode.org/Public/17.0.0/ucd/UnicodeData.txt")]),
    ];
    let meta: Map<String, Value> = json!({"language":"en","complete":false,"minted":false,"signed":false}).as_object().unwrap().clone();
    Crystal::build(CrystalKind::Word, word, leaves, meta)
}

#[cfg(test)]
mod tests {
    use super::*;
    const LOCK: &str = include_str!("../../../Cargo.lock");
    #[test]
    fn resolves_from_real_lock_and_rejects_mismatch() {
        let c = exec_word("hash", "sha3_256", "run", "sha3", "0.10.9", LOCK, "compute SHA3-256 of a string").unwrap();
        let e = exec_of(&c).unwrap().unwrap();
        let r = resolve(&e, LOCK).unwrap();
        assert_eq!(r["expected_sha256"], "77fd7028345d415a4034cf8777cd4f8ab1851274233b45f84e3d955502d93874");
        let mut bad = e.clone(); bad.checksum = "00".repeat(32);
        assert!(resolve(&bad, LOCK).unwrap_err().to_string().contains("hash mismatch"));
        let mut f = e.clone(); f.function = "shell".into();
        assert!(resolve(&f, LOCK).is_err());
        assert_eq!(run_builtin("sha3_256", "").unwrap(), "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    }
}
