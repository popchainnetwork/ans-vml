// SPDX-License-Identifier: Apache-2.0
//! Book: a directory of verified crystals. Every read re-verifies the merkle root.
use crate::{forms::fold, Crystal, CrystalKind};
use anyhow::{anyhow, bail, Result};
use std::path::{Path, PathBuf};

pub struct Book { pub dir: PathBuf }

pub fn valid_file_name(f: &str) -> bool {
    f.ends_with(".crystal.json") && f.len() < 200 && !f.starts_with('.')
        && f.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
}

impl Book {
    pub fn open(dir: &Path) -> Result<Book> { std::fs::create_dir_all(dir)?; Ok(Book { dir: dir.into() }) }
    /// Verify then store; returns file name. Same root already present => no-op.
    pub fn add_text(&self, text: &str) -> Result<(String, Crystal)> {
        let c = Crystal::parse(text)?;
        let f = c.file_name();
        if !valid_file_name(&f) { bail!("bad crystal file name {f}"); }
        let p = self.dir.join(&f);
        if p.exists() {
            let old = Crystal::parse(&std::fs::read_to_string(&p)?)?;
            if old.root != c.root || old.id != c.id || old.kind != c.kind {
                bail!("{f} cache identity/type/root mismatch; refusing to overwrite");
            }
            return Ok((f, c));
        }
        let tmp = self.dir.join(format!(".{f}.tmp"));
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, &p)?;
        Ok((f, c))
    }
    pub fn add(&self, c: &Crystal) -> Result<String> { Ok(self.add_text(&c.to_json())?.0) }
    pub fn raw(&self, file: &str) -> Result<String> {
        if !valid_file_name(file) { bail!("bad crystal file name"); }
        Ok(std::fs::read_to_string(self.dir.join(file))?)
    }
    pub fn get(&self, file: &str) -> Result<Crystal> {
        let c = Crystal::parse(&self.raw(file)?)?;
        if c.file_name() != file { bail!("cache filename does not match crystal identity/type"); }
        Ok(c)
    }
    pub fn list(&self) -> Result<Vec<(String, Crystal)>> {
        let mut names: Vec<String> = std::fs::read_dir(&self.dir)?.filter_map(|e| e.ok()?.file_name().into_string().ok()).filter(|f| valid_file_name(f)).collect();
        names.sort();
        names.into_iter().map(|f| { let c = self.get(&f)?; Ok((f, c)) }).collect()
    }
    /// Lookup a word by its id, any translation, or any written form; diacritic-insensitive.
    pub fn lookup(&self, q: &str) -> Result<Crystal> {
        let q = fold(q);
        for (_, c) in self.list()? {
            if c.kind != CrystalKind::Word { continue; }
            let hit = fold(&c.id) == q || c.leaves.iter().any(|l| matches!(l.get("kind"), Some("translation") | Some("form")) && l.get("value").map(fold).as_deref() == Some(q.as_str()));
            if hit { return Ok(c); }
        }
        Err(anyhow!("word not in book: {q}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn same_root_identity_and_schema_tamper_are_not_cache_hits() {
        let d = std::env::temp_dir().join(format!("ans-book-identity-{}", randless_unique()));
        let b = Book::open(&d).unwrap();
        let original = crate::tests::asset("u0072.crystal.json");
        let (file, c) = b.add_text(&original).unwrap();
        for schema_tamper in [false, true] {
            let mut v: serde_json::Value = serde_json::from_str(&original).unwrap();
            if schema_tamper {
                v["schema"] = serde_json::json!(crate::WORD_SCHEMA);
                v["word"] = serde_json::json!("r");
            } else { v["character"] = serde_json::json!("x"); }
            assert_eq!(v["root"], c.root);
            std::fs::write(d.join(&file), v.to_string()).unwrap();
            assert!(b.add(&c).is_err());
            assert!(b.get(&file).is_err());
            assert!(b.list().is_err());
            assert_eq!(std::fs::read_to_string(d.join(&file)).unwrap(), v.to_string());
        }
        std::fs::remove_dir_all(d).unwrap();
    }
    fn randless_unique() -> u128 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() }
    #[test]
    fn add_list_lookup() {
        let d = std::env::temp_dir().join(format!("ans-dict-book-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let b = Book::open(&d).unwrap();
        let (f, c) = b.add_text(&crate::tests::asset("rdzen.crystal.json")).unwrap();
        assert_eq!(f, "rdzen.crystal.json");
        assert_eq!(b.lookup("RDZEŃ").unwrap().root, c.root);
        assert_eq!(b.lookup("rdzen").unwrap().root, c.root);
        // any translation, e.g. English "core" or "pith" if present
        let tr = c.of_kind("translation").next().unwrap().get("value").unwrap().to_string();
        assert_eq!(b.lookup(&tr).unwrap().root, c.root);
        assert!(b.lookup("nonexistentword").is_err());
        assert_eq!(b.list().unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&d);
    }
}
