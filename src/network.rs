// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Paweł Piekut / Pplastechniek
//! Network profiles for custodian journals.
//!
//! Every signed event carries `body.network`; events written before profiles existed have no
//! field and count as `devnet`. A journal, writer or public proof bound to one profile is never
//! accepted under another. `devnet` is the default local demo (auto-created demo key, test crash
//! hook allowed). Every other profile is *protected*: it opens a signer only with an explicit
//! operator confirmation, an externally provided custodian key file, no demo key, no test crash
//! hook, and never creates identities implicitly. `rehearsal` is a throwaway local profile that
//! exercises exactly those gates. `mainnet` signing is compiled out (`MAINNET_SIGNING_ENABLED`)
//! until the open items in MAINNET-READINESS.md are closed.
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    cell::RefCell,
    path::{Path, PathBuf},
};

/// Readiness build: mainnet passes every gate and is then still refused.
pub const MAINNET_SIGNING_ENABLED: bool = false;
pub const PROFILE_FILE: &str = "network.json";
pub const STATE_FILE: &str = "xmss.state";
pub const THROWAWAY_SUFFIX: &str = ".throwaway";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Network {
    Devnet,
    Testnet,
    Rehearsal,
    Mainnet,
}
impl Network {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "devnet" => Network::Devnet,
            "testnet" => Network::Testnet,
            "rehearsal" => Network::Rehearsal,
            "mainnet" => Network::Mainnet,
            _ => bail!("Unknown network profile {s:?}; use devnet|testnet|rehearsal|mainnet"),
        })
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Network::Devnet => "devnet",
            Network::Testnet => "testnet",
            Network::Rehearsal => "rehearsal",
            Network::Mainnet => "mainnet",
        }
    }
    pub fn protected(self) -> bool {
        self != Network::Devnet
    }
}
/// Network profile an event is bound to (signed body field; absent = legacy devnet).
pub fn of_event(e: &Value) -> &str {
    e["body"]["network"].as_str().unwrap_or("devnet")
}
/// All events must share one profile; returns it.
pub fn of_journal(events: &[Value]) -> Result<Network> {
    let first = events.first().map(of_event).unwrap_or("devnet");
    if events.iter().any(|e| of_event(e) != first) {
        bail!("Mixed network profiles in one journal");
    }
    Network::parse(first)
}
pub fn require(events: &[Value], expected: Network) -> Result<()> {
    let found = of_journal(events)?;
    if found != expected {
        bail!(
            "Network profile mismatch: signed events are {}, expected {}",
            found.as_str(),
            expected.as_str()
        );
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub schema: u32,
    pub network: Network,
    /// External custodian key file (96-byte XMSSMT seed). Path only; never copied or printed.
    pub key_path: PathBuf,
}
/// Profile of a custodian directory; `None` means the devnet demo layout.
pub fn load(dir: &Path) -> Result<Option<Profile>> {
    let p = dir.join(PROFILE_FILE);
    if !p.exists() {
        return Ok(None);
    }
    let profile: Profile = serde_json::from_slice(&std::fs::read(&p)?)?;
    if profile.schema != 1 || !profile.network.protected() {
        bail!("Invalid network profile file");
    }
    Ok(Some(profile))
}
pub fn network_of_dir(dir: &Path) -> Result<Network> {
    Ok(load(dir)?.map(|p| p.network).unwrap_or(Network::Devnet))
}

#[derive(Clone, Debug, Default)]
struct Operator {
    network: Option<Network>,
    confirmed: Option<Network>,
    key_path: Option<PathBuf>,
    init: bool,
}
thread_local! {static OPERATOR: RefCell<Operator> = RefCell::new(Operator::default());}
/// Record the operator's explicit CLI flags for this thread (`--network`, `--confirm-network`,
/// `--custodian-key`). Nothing is persisted.
pub fn set_operator(network: Option<Network>, confirmed: Option<Network>, key_path: Option<PathBuf>) {
    OPERATOR.with(|o| {
        *o.borrow_mut() = Operator { network, confirmed, key_path, init: false };
    });
}
pub fn operator_network() -> Option<Network> {
    OPERATOR.with(|o| o.borrow().network)
}
pub fn operator_key() -> Option<PathBuf> {
    OPERATOR.with(|o| o.borrow().key_path.clone())
}
pub fn clear_operator() {
    OPERATOR.with(|o| *o.borrow_mut() = Operator::default());
}
/// Explicit identity creation window used only by `ans network init`.
pub fn with_init<T>(f: impl FnOnce() -> Result<T>) -> Result<T> {
    OPERATOR.with(|o| o.borrow_mut().init = true);
    let r = f();
    OPERATOR.with(|o| o.borrow_mut().init = false);
    r
}
pub fn init_allowed() -> bool {
    OPERATOR.with(|o| o.borrow().init)
}

/// Gates for a protected custodian key. Order is stable so each refusal is observable.
pub fn check_key(dir: &Path, network: Network, key: &Path) -> Result<()> {
    if !key.is_absolute() {
        bail!("Custodian key path must be absolute");
    }
    let meta = std::fs::symlink_metadata(key)
        .map_err(|_| anyhow!("Custodian key file not found; protected profiles never create identities"))?;
    if !meta.file_type().is_file() {
        bail!("Custodian key must be a regular file, not a symlink or directory");
    }
    if meta.len() != 96 {
        bail!("Custodian key must be a 96-byte XMSSMT seed file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            bail!("Custodian key file must not be readable by group or others (chmod 600)");
        }
    }
    let name = key.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if name == "xmss-demo.seed" || name.contains("demo") {
        bail!("Demo keys are refused in protected profiles");
    }
    let custodians = dir.parent().unwrap_or(dir);
    let canonical = std::fs::canonicalize(key)?;
    if canonical.starts_with(std::fs::canonicalize(custodians).unwrap_or(custodians.to_path_buf())) {
        bail!("Custodian key must live outside the custodian data directory");
    }
    let throwaway = PathBuf::from(format!("{}{THROWAWAY_SUFFIX}", key.display())).exists();
    if network == Network::Mainnet && throwaway {
        bail!("Throwaway/test keys are refused on mainnet");
    }
    if network == Network::Rehearsal && !throwaway {
        bail!("Rehearsal accepts only keys created by `ans network throwaway-key`; never use a real key");
    }
    Ok(())
}
/// Admission for opening a protected signer.
pub fn admit(dir: &Path, profile: &Profile) -> Result<()> {
    admit_operator(dir, profile.network, &profile.key_path)
}
/// Operator gates for `network` with key `key` (also run before `network init` writes anything).
pub fn admit_operator(dir: &Path, n: Network, key: &Path) -> Result<()> {
    let op = OPERATOR.with(|o| o.borrow().clone());
    if op.network != Some(n) || op.confirmed != Some(n) {
        bail!(
            "{} custodian requires explicit operator flags: --network {0} --confirm-network {0} --custodian-key PATH",
            n.as_str()
        );
    }
    if op.key_path.as_deref() != Some(key) {
        bail!("--custodian-key does not match the key path bound to this custodian");
    }
    if std::env::var_os("ANS_TEST_CRASH_AFTER").is_some() || dir.join("allow-test-crash").exists() {
        bail!("Test crash hook is refused in protected profiles");
    }
    check_key(dir, n, key)?;
    if n == Network::Mainnet && !MAINNET_SIGNING_ENABLED {
        bail!("Mainnet signing is not enabled in this build (readiness only; see MAINNET-READINESS.md)");
    }
    Ok(())
}
/// Explicit throwaway key for rehearsal: random 96 bytes, mode 0600, plus a `.throwaway` marker.
/// Refuses to overwrite. The key bytes are never printed.
pub fn throwaway_key(path: &Path) -> Result<Value> {
    use rand::RngCore;
    use std::io::Write;
    if !path.is_absolute() {
        bail!("Path must be absolute");
    }
    let mut bytes = [0u8; 96];
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut opts = std::fs::OpenOptions::new();
    opts.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| anyhow!("Refusing to create key at {}: {e}", path.display()))?;
    f.write_all(&bytes)?;
    f.sync_all()?;
    std::fs::write(
        format!("{}{THROWAWAY_SUFFIX}", path.display()),
        "throwaway rehearsal key; refused on mainnet\n",
    )?;
    Ok(serde_json::json!({"ok":true,"key_path":path,"throwaway":true,"private_key":"written mode 0600; never printed","use":"rehearsal only; refused on mainnet"}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn legacy_events_are_devnet_and_profiles_never_mix() {
        let legacy = json!({"body":{"action":"x"}});
        let main = json!({"body":{"action":"x","network":"mainnet"}});
        let dev = json!({"body":{"action":"x","network":"devnet"}});
        assert_eq!(of_journal(&[legacy.clone(), dev.clone()]).unwrap(), Network::Devnet);
        assert!(require(&[legacy.clone()], Network::Mainnet).is_err());
        assert!(require(&[main.clone()], Network::Devnet).is_err());
        assert!(of_journal(&[legacy, main.clone()]).is_err());
        assert!(of_journal(&[json!({"body":{"network":"moonnet"}})]).is_err());
        assert_eq!(of_journal(&[main]).unwrap(), Network::Mainnet);
        assert!(!MAINNET_SIGNING_ENABLED);
    }
}
