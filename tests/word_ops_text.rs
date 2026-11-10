// SPDX-License-Identifier: Apache-2.0
//! Console output of operations on words: sentences with `--text` (or on a terminal), unchanged
//! JSON with `--json` or when piped. Temp dirs and throwaway devnet keys only.
use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

struct Home(PathBuf);
impl Home {
    fn new() -> Self {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let p = std::env::temp_dir().join(format!("ans-text-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    fn run(&self, args: &[&str]) -> (bool, String, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_ans")).args(args).env("ANS_HOME", &self.0).env_remove("ANS_TEST_CRASH_AFTER").output().unwrap();
        (out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
    }
    fn text(&self, args: &[&str]) -> String {
        let mut a = vec!["--text", "--as", "alice"];
        a.extend_from_slice(args);
        let (ok, out, err) = self.run(&a);
        assert!(ok, "{args:?}: {err}");
        assert!(!out.contains('{') && !out.contains('}'), "{args:?} printed JSON-like text: {out}");
        out
    }
    fn json(&self, args: &[&str]) -> Value {
        let mut a = vec!["--as", "alice"];
        a.extend_from_slice(args);
        let (ok, out, err) = self.run(&a);
        assert!(ok, "{args:?}: {err}");
        serde_json::from_str(&out).unwrap_or_else(|e| panic!("{args:?} not JSON when piped ({e}): {out}"))
    }
    fn events(&self) -> Vec<Value> {
        std::fs::read_to_string(self.0.join("custodians/alice/chain.ndjson")).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect()
    }
    fn count(&self, action: &str) -> usize {
        self.events().iter().filter(|e| e["body"]["action"] == action).count()
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn word_operations_print_sentences_and_keep_json_for_pipes() {
    let h = Home::new();
    let (ok, _, err) = h.run(&["init", "alice"]);
    assert!(ok, "{err}");
    for ch in ["o", "a", "k"] {
        let t = h.text(&["dictionary", "write", "character", ch, "--unverified", "--operation-id", &format!("c-{ch}")]);
        assert!(t.starts_with(&format!("Character \"{ch}\" is now a draft: dictionary write accepted")), "{t}");
        h.text(&["dictionary", "validate", ch, "--operation-id", &format!("c-{ch}-v")]);
        let t = h.text(&["dictionary", "mint", ch, "--operation-id", &format!("c-{ch}-m")]);
        assert!(t.starts_with(&format!("Character \"{ch}\" is now minted")), "{t}");
    }
    let t = h.text(&["dictionary", "write", "word", "oak", "--lang", "en", "--meaning", "a tree", "--license", "CC0-1.0", "--source", "test", "--attribution", "test fixture", "--operation-id", "w"]);
    assert!(t.contains("Word \"oak\" (en) is now a draft") && t.contains("Note: User-authored word"), "{t}");
    // A rejection reads as a rejection, never as success.
    let t = h.text(&["dictionary", "mint", "oak", "--operation-id", "early"]);
    assert!(t.starts_with("Dictionary mint of word \"oak\" was rejected: Mint requires validated state"), "{t}");
    assert!(!t.contains("is now"), "{t}");
    h.text(&["dictionary", "validate", "oak", "--operation-id", "w-v"]);
    assert!(h.text(&["dictionary", "mint", "oak", "--operation-id", "w-m"]).starts_with("Word \"oak\" (en) is now minted"));

    // Meaning: accept, then idempotent repeat signs nothing. The output flag is not signed text.
    let t = h.text(&["mint-meaning", "oak", "en", "a large tree"]);
    assert!(t.starts_with("Meaning added to word \"oak\" (en): signed as block "), "{t}");
    assert!(t.contains("intent → word.meaning → outcome"), "{t}");
    let n = h.events().len();
    let again = h.json(&["mint-meaning", "oak", "en", "a large tree"]);
    assert_eq!(again["already"], true, "{again}");
    assert_eq!(h.events().len(), n);
    assert_eq!(h.count("word.meaning"), 1);

    // Delegate / revoke, each with its no-op repeat.
    assert!(h.text(&["delegate", "oak", "review"]).starts_with("Word \"oak\" delegated for scope \"review\": signed as block "));
    assert!(h.text(&["delegate", "oak", "review"]).contains("is already delegated for scope \"review\"; nothing was signed"));
    assert!(h.text(&["revoke", "oak", "review"]).starts_with("Delegation of word \"oak\" for scope \"review\" revoked"));
    assert!(h.text(&["revoke", "oak", "review"]).contains("nothing to revoke, nothing was signed"));
    assert_eq!((h.count("word.delegate"), h.count("word.revoke")), (1, 1));
    assert!(h.text(&["mint", "oak"]).starts_with("Word \"oak\" is already minted (block "));

    // Refusals stay plain sentences on stderr and sign nothing.
    let n = h.events().len();
    let (ok, out, err) = h.run(&["--text", "--as", "alice", "run", "oak", "x"]);
    assert!(!ok && out.is_empty() && err.starts_with("ans: refused: no active dictionary delegation"), "{out} {err}");
    assert_eq!(h.events().len(), n);

    // Piped default and explicit --json keep the machine format.
    let j = h.json(&["delegate", "oak", "review"]);
    assert_eq!(j["action"], "word.delegate");
    assert_eq!(j["service"], "dictionary");
    let mut a = vec!["--json", "--as", "alice", "revoke", "oak", "review"];
    let (ok, out, _) = h.run(&a);
    assert!(ok && serde_json::from_str::<Value>(&out).unwrap()["action"] == "word.revoke");
    // Ambiguous output flags are refused before anything is signed.
    let n = h.events().len();
    a[0] = "--text";
    a.push("--json");
    let (ok, _, err) = h.run(&a);
    assert!(!ok && err.contains("Choose one output format"), "{err}");
    let (ok, _, err) = h.run(&["--text", "--as", "alice", "mint-meaning", "oak", "en", "x", "--text"]);
    assert!(!ok && err.contains("given more than once"), "{err}");
    assert_eq!(h.events().len(), n);
}
