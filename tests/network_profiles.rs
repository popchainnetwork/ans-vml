// SPDX-License-Identifier: Apache-2.0
//! Network-profile gates and a full local "mainnet rehearsal" on a throwaway profile.
//! Uses only temp dirs and throwaway keys created by the binary; nothing leaves the machine.
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

struct Env {
    tmp: PathBuf,
}
impl Env {
    fn new(tag: &str) -> Self {
        let tmp = std::env::temp_dir().join(format!("ans-net-{tag}-{}-{}", std::process::id(), rand_suffix()));
        std::fs::create_dir_all(&tmp).unwrap();
        Self { tmp }
    }
    fn home(&self) -> PathBuf {
        self.tmp.join("home")
    }
    fn run(&self, args: &[&str]) -> (bool, Value, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_ans"))
            .args(args)
            .env("ANS_HOME", self.home())
            .env_remove("ANS_TEST_CRASH_AFTER")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        (out.status.success(), serde_json::from_str(&stdout).unwrap_or(Value::Null), stderr)
    }
    fn ok(&self, args: &[&str]) -> Value {
        let (ok, v, err) = self.run(args);
        assert!(ok, "{args:?} failed: {err}");
        v
    }
    fn refused(&self, args: &[&str], needle: &str) {
        let (ok, v, err) = self.run(args);
        assert!(!ok, "{args:?} unexpectedly succeeded: {v}");
        assert!(err.contains(needle), "{args:?}: expected {needle:?} in {err}");
    }
}
impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.tmp);
    }
}
fn rand_suffix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64
}
fn s(p: &Path) -> String {
    p.display().to_string()
}
fn chain(home: &Path, who: &str) -> Vec<Value> {
    std::fs::read_to_string(home.join("custodians").join(who).join("chain.ndjson"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[test]
fn protected_profiles_refuse_without_every_gate() {
    let e = Env::new("gates");
    let key = e.tmp.join("rehearsal.seed");
    let k = s(&key);
    e.ok(&["network", "throwaway-key", &k]);
    // Never overwrite an existing key file.
    e.refused(&["network", "throwaway-key", &k], "Refusing to create key");
    // No confirmation / mismatched confirmation / no key path.
    e.refused(&["--network", "rehearsal", "--custodian-key", &k, "network", "init", "alice"], "requires explicit operator flags");
    e.refused(&["--network", "rehearsal", "--confirm-network", "mainnet", "--custodian-key", &k, "network", "init", "alice"], "--confirm-network must repeat");
    e.refused(&["--network", "rehearsal", "--confirm-network", "rehearsal", "network", "init", "alice"], "--custodian-key PATH is required");
    // Legacy init cannot create a protected identity.
    e.refused(&["--network", "mainnet", "--confirm-network", "mainnet", "init", "alice"], "Protected profiles are initialized only");
    // A demo-named key is refused; a key outside 0600 is refused.
    let demo = e.tmp.join("xmss-demo.seed");
    std::fs::copy(&key, &demo).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&demo, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    e.refused(&["--network", "testnet", "--confirm-network", "testnet", "--custodian-key", &s(&demo), "network", "init", "alice"], "Demo keys are refused");
    let loose = e.tmp.join("loose.seed");
    std::fs::copy(&key, &loose).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    e.refused(&["--network", "testnet", "--confirm-network", "testnet", "--custodian-key", &s(&loose), "network", "init", "alice"], "chmod 600");
    // Rehearsal refuses a key without the throwaway marker; mainnet refuses throwaway keys.
    let real_looking = e.tmp.join("operator.seed");
    std::fs::copy(&key, &real_looking).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&real_looking, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    e.refused(&["--network", "rehearsal", "--confirm-network", "rehearsal", "--custodian-key", &s(&real_looking), "network", "init", "alice"], "Rehearsal accepts only keys created");
    e.refused(&["--network", "mainnet", "--confirm-network", "mainnet", "--custodian-key", &k, "network", "init", "alice"], "Throwaway/test keys are refused on mainnet");
    // Mainnet passes every other gate and is still refused in this readiness build.
    e.refused(&["--network", "mainnet", "--confirm-network", "mainnet", "--custodian-key", &s(&real_looking), "network", "init", "alice"], "Mainnet signing is not enabled");
    assert!(!e.home().join("custodians/alice").exists(), "refused init must not create state");

    // A protected custodian opens only with the same confirmation + key on every invocation.
    e.ok(&["--network", "rehearsal", "--confirm-network", "rehearsal", "--custodian-key", &k, "network", "init", "alice"]);
    assert!(!e.home().join("custodians/alice/xmss-demo.seed").exists(), "no demo key is created");
    e.refused(&["--as", "alice", "dictionary", "write", "character", "o", "--unverified"], "requires explicit operator flags");
    e.refused(&["--network", "rehearsal", "--as", "alice", "dictionary", "write", "character", "o", "--unverified"], "requires explicit operator flags");
    e.refused(&["--network", "rehearsal", "--confirm-network", "rehearsal", "--custodian-key", &s(&real_looking), "--as", "alice", "dictionary", "write", "character", "o", "--unverified"], "does not match the key path");
    e.refused(&["--network", "devnet", "--as", "alice", "dictionary", "write", "character", "o", "--unverified"], "Network profile mismatch");
    // Test crash hook sentinel is refused in protected profiles.
    std::fs::write(e.home().join("custodians/alice/allow-test-crash"), "").unwrap();
    e.refused(&["--network", "rehearsal", "--confirm-network", "rehearsal", "--custodian-key", &k, "--as", "alice", "dictionary", "write", "character", "o", "--unverified"], "Test crash hook is refused");
    std::fs::remove_file(e.home().join("custodians/alice/allow-test-crash")).unwrap();
    // Implicit identity creation is refused: a profile file without a journal never gets a genesis.
    let carol = e.home().join("custodians/carol");
    std::fs::create_dir_all(&carol).unwrap();
    std::fs::write(carol.join("network.json"), serde_json::to_vec(&serde_json::json!({"schema":1,"network":"rehearsal","key_path":k})).unwrap()).unwrap();
    e.refused(&["--network", "rehearsal", "--confirm-network", "rehearsal", "--custodian-key", &k, "--as", "carol", "dictionary", "write", "character", "o", "--unverified"], "never create");
    assert!(!carol.join("chain.ndjson").exists() && !carol.join("xmss.state").exists() && !carol.join("kernel").exists());
    // An emptied journal is refused too (kernel/journal mismatch or empty-journal gate).
    let j = e.home().join("custodians/alice/chain.ndjson");
    let saved = std::fs::read(&j).unwrap();
    std::fs::write(&j, b"").unwrap();
    e.refused(&["--network", "rehearsal", "--confirm-network", "rehearsal", "--custodian-key", &k, "--as", "alice", "dictionary", "write", "character", "o", "--unverified"], "never create identities implicitly");
    std::fs::write(&j, saved).unwrap();
    assert!(chain(&e.home(), "alice").iter().all(|ev| ev["body"]["network"] == "rehearsal"));
}

#[test]
fn mainnet_rehearsal_full_flow_and_cross_network_refusal() {
    let e = Env::new("rehearsal");
    let key = e.tmp.join("rehearsal.seed");
    let k = s(&key);
    e.ok(&["network", "throwaway-key", &k]);
    let p = ["--network", "rehearsal", "--confirm-network", "rehearsal", "--custodian-key", k.as_str()];
    let r = |rest: &[&str]| -> Value {
        let mut a: Vec<&str> = p.to_vec();
        a.extend_from_slice(rest);
        e.ok(&a)
    };
    r(&["network", "init", "alice"]);
    for ch in ["o", "a", "k"] {
        r(&["--as", "alice", "dictionary", "write", "character", ch, "--unverified", "--operation-id", &format!("c-{ch}")]);
        r(&["--as", "alice", "dictionary", "validate", ch, "--operation-id", &format!("c-{ch}-v")]);
        r(&["--as", "alice", "dictionary", "mint", ch, "--operation-id", &format!("c-{ch}-m")]);
    }
    r(&["--as", "alice", "dictionary", "write", "word", "oak", "--lang", "en", "--meaning", "a tree", "--license", "CC0-1.0", "--source", "rehearsal", "--attribution", "throwaway rehearsal; not a rights claim", "--operation-id", "w"]);
    r(&["--as", "alice", "dictionary", "validate", "oak", "--operation-id", "w-v"]);
    let minted = r(&["--as", "alice", "dictionary", "mint", "oak", "--operation-id", "w-m"]);
    assert_eq!(minted["receipt"]["status"], "accepted", "{minted}");
    let pk = minted["outcome"]["xmss"]["pk"].as_str().unwrap().to_owned();
    // Migrated legacy operations work in the protected profile and replay strictly.
    // Outputs report the network the events were actually signed under.
    for out in [
        r(&["--as", "alice", "mint-meaning", "oak", "en", "a large tree"]),
        r(&["--as", "alice", "delegate", "oak", "review"]),
        r(&["--as", "alice", "revoke", "oak", "review"]),
        r(&["--as", "alice", "mint", "oak"]),
    ] {
        assert_eq!(out["network"], "rehearsal", "{out}");
    }
    assert_eq!(r(&["--as", "alice", "mint", "oak"])["minted"][0]["network"], "rehearsal");
    // Repeated global flags are refused before anything is signed (no leftover args in text).
    let before = chain(&e.home(), "alice").len();
    let mut dup: Vec<&str> = p.to_vec();
    dup.extend_from_slice(&["--as", "alice", "mint-meaning", "oak", "en", "x", "--network", "mainnet"]);
    let (ok, _, err) = e.run(&dup);
    assert!(!ok && err.contains("given more than once"), "{err}");
    let home = s(&e.home());
    for flag in ["--as", "--data", "--confirm-network", "--custodian-key"] {
        let mut dup: Vec<&str> = p.to_vec();
        dup.extend_from_slice(&["--data", &home, "--as", "alice", "mint-meaning", "oak", "en", "x", flag, "y"]);
        let (ok, _, err) = e.run(&dup);
        assert!(!ok && err.contains("given more than once"), "{flag}: {err}");
    }
    assert_eq!(chain(&e.home(), "alice").len(), before);
    // Every signed event is bound to the rehearsal profile.
    let events = chain(&e.home(), "alice");
    assert!(events.iter().all(|ev| ev["body"]["network"] == "rehearsal"));
    assert!(events.iter().any(|ev| ev["body"]["action"] == "word.meaning"));
    // Export + verify under the right profile; refused under devnet and mainnet.
    let proof = r(&["--as", "alice", "dictionary", "export", "oak", "--expect-key", &pk]);
    let proof_path = e.tmp.join("oak.rehearsal.proof.json");
    std::fs::write(&proof_path, serde_json::to_vec(&proof).unwrap()).unwrap();
    let pp = s(&proof_path);
    let ok = e.ok(&["--network", "rehearsal", "dictionary", "verify", &pp, "--expect-key", &pk]);
    assert_eq!(ok["network"], "rehearsal");
    assert_eq!(ok["word_dependency_path_verified"], true);
    e.refused(&["dictionary", "verify", &pp, "--expect-key", &pk], "Network profile mismatch");
    e.refused(&["--network", "mainnet", "dictionary", "verify", &pp, "--expect-key", &pk], "Network profile mismatch");
    // Re-labelling an event's network breaks its signature (the field is signed).
    let mut forged: Value = proof.clone();
    for a in forged["attestations"].as_array_mut().unwrap() {
        a["event"]["body"]["network"] = Value::from("mainnet");
    }
    let fp = e.tmp.join("forged.json");
    std::fs::write(&fp, serde_json::to_vec(&forged).unwrap()).unwrap();
    e.refused(&["--network", "mainnet", "dictionary", "verify", &s(&fp), "--expect-key", &pk], "");

    // A devnet custodian/proof in the same home is never accepted as rehearsal or mainnet.
    e.ok(&["init", "bob"]);
    for ch in ["o", "a", "k"] {
        e.ok(&["--as", "bob", "dictionary", "write", "character", ch, "--unverified", "--operation-id", &format!("d-{ch}")]);
        e.ok(&["--as", "bob", "dictionary", "validate", ch, "--operation-id", &format!("d-{ch}-v")]);
        e.ok(&["--as", "bob", "dictionary", "mint", ch, "--operation-id", &format!("d-{ch}-m")]);
    }
    let dev = e.ok(&["--as", "bob", "dictionary", "mint", "o", "--operation-id", "d-o-m"]);
    let dpk = dev["outcome"]["xmss"]["pk"].as_str().unwrap().to_owned();
    let dproof = e.ok(&["--as", "bob", "dictionary", "export", "o", "--expect-key", &dpk]);
    let dpath = e.tmp.join("o.devnet.proof.json");
    std::fs::write(&dpath, serde_json::to_vec(&dproof).unwrap()).unwrap();
    assert_eq!(e.ok(&["dictionary", "verify", &s(&dpath), "--expect-key", &dpk])["network"], "devnet");
    e.refused(&["--network", "rehearsal", "dictionary", "verify", &s(&dpath), "--expect-key", &dpk], "Network profile mismatch");
    e.refused(&["--network", "mainnet", "dictionary", "verify", &s(&dpath), "--expect-key", &dpk], "Network profile mismatch");
    // Copying a devnet journal under a protected profile file is refused on open.
    let bob = e.home().join("custodians/bob");
    std::fs::write(bob.join("network.json"), serde_json::to_vec(&serde_json::json!({"schema":1,"network":"rehearsal","key_path":k})).unwrap()).unwrap();
    let mut a: Vec<&str> = p.to_vec();
    a.extend_from_slice(&["--as", "bob", "delegate", "o", "x"]);
    let (ok, _, err) = e.run(&a);
    assert!(!ok, "devnet journal must not open as rehearsal: {err}");

    // `ans init` over a (former) protected custodian whose profile file was removed must refuse
    // before writing any devnet key material.
    let alice = e.home().join("custodians/alice");
    std::fs::rename(alice.join("network.json"), e.tmp.join("alice-network.json.moved")).unwrap();
    let (ok, _, err) = e.run(&["init", "alice"]);
    assert!(!ok && err.contains("protected network profile"), "{err}");
    assert!(!alice.join("xmss-demo.seed").exists() && !alice.join("xmss-demo.state").exists());
    let (ok, _, err) = e.run(&["--as", "alice", "delegate", "oak", "x"]);
    assert!(!ok, "{err}");
    assert!(!alice.join("xmss-demo.seed").exists() && !alice.join("xmss-demo.state").exists());
}
