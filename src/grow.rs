// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Paweł Piekut / Pplastechniek
//! A seed grows locally; remote placements remain an inert, explicit plan.
use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::Duration,
};
#[derive(Clone)]
enum Role {
    Node,
    Book,
    State,
}
impl Role {
    fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "node" => Self::Node,
            "book" => Self::Book,
            "state" => Self::State,
            _ => bail!("Unknown placement role"),
        })
    }
    fn label(&self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Book => "book",
            Self::State => "state",
        }
    }
}
struct Host {
    name: String,
    address: String,
    enabled: bool,
    roles: Vec<Role>,
}
impl Host {
    fn local(&self) -> bool {
        ["localhost", "127.0.0.1", "::1"].contains(&self.address.as_str())
    }
}
fn hash(v: &Value) -> String {
    hex::encode(Sha256::digest(serde_json::to_vec(v).unwrap()))
}
fn private_dir(p: &Path) -> Result<()> {
    fs::create_dir_all(p)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(p, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
fn write_snapshot(p: &Path, v: &Value) -> Result<String> {
    let bytes = serde_json::to_vec_pretty(v)?;
    if p.exists() && fs::read(p)? == bytes {
        return Ok(hex::encode(Sha256::digest(&bytes)));
    }
    if p.exists() {
        // Keep any interrupted/externally changed version; never delete it.
        let mut n = 1;
        loop {
            let backup = p.with_extension(format!("json_incomplete_{n}"));
            if !backup.exists() {
                fs::copy(p, backup)?;
                break;
            }
            n += 1;
        }
    }
    let mut f = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(p)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    f.write_all(&bytes)?;
    f.sync_all()?;
    Ok(hex::encode(Sha256::digest(bytes)))
}
fn hosts(path: &Path) -> Result<(Vec<Host>, u64, String)> {
    let (text, source) = if path.exists() {
        if fs::metadata(path)?.len() > 65536 {
            bail!("hosts.toml exceeds 64 KiB")
        }
        (fs::read_to_string(path)?, path.display().to_string())
    } else {
        (
            include_str!("../assets/hosts.example.toml").into(),
            "embedded public hosts example; no file created".into(),
        )
    };
    let parsed: toml::Value = text
        .parse()
        .map_err(|_| anyhow!("Invalid hosts.toml (file contents withheld)"))?;
    let rows = parsed
        .get("hosts")
        .and_then(toml::Value::as_array)
        .ok_or(anyhow!("hosts.toml requires [[hosts]]"))?;
    if rows.is_empty() || rows.len() > 32 {
        bail!("Configure 1..32 hosts")
    }
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for row in rows {
        let name = row
            .get("name")
            .and_then(toml::Value::as_str)
            .ok_or(anyhow!("Host name required"))?;
        if name.is_empty()
            || name.len() > 40
            || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
            || !seen.insert(name.to_owned())
        {
            bail!("Host names must be unique safe labels")
        }
        let address = row
            .get("address")
            .and_then(toml::Value::as_str)
            .ok_or(anyhow!("Host address required"))?;
        if address.is_empty()
            || address.len() > 253
            || !address
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b".-:".contains(&c))
        {
            bail!("Host addresses only; credentials/URLs are forbidden")
        }
        let roles = row
            .get("roles")
            .and_then(toml::Value::as_array)
            .ok_or(anyhow!("Host roles required"))?
            .iter()
            .map(|r| Role::parse(r.as_str().unwrap_or("")))
            .collect::<Result<Vec<_>>>()?;
        if roles.is_empty() {
            bail!("At least one role per host")
        }
        result.push(Host {
            name: name.into(),
            address: address.into(),
            enabled: row
                .get("enabled")
                .and_then(toml::Value::as_bool)
                .unwrap_or(false),
            roles,
        });
    }
    let replicas = parsed
        .get("replicas")
        .and_then(toml::Value::as_integer)
        .unwrap_or(1);
    if !(1..=32).contains(&replicas) {
        bail!("replicas must be 1..32")
    }
    Ok((result, replicas as u64, source))
}
fn ensure_runtime(root: &Path, c: &Value) -> Result<Option<u32>> {
    let words: Vec<_> = c["custodians"]
        .as_object()
        .ok_or(anyhow!("ans init <word> first"))?
        .keys()
        .collect();
    if words.is_empty() {
        bail!("Initialize a custodian first: ans init <word>")
    }
    let ready = || {
        words
            .iter()
            .all(|w| super::exploit::call(w, None, "/health").is_ok())
            && super::get_local(&format!(
                "http://127.0.0.1:{}/health",
                c["web_port"].as_u64().unwrap_or(9330)
            ))
            .map(|v| v["ok"] == true && v["product"] == "ans")
            .unwrap_or(false)
    };
    if ready() {
        return Ok(None);
    }
    let port = c["web_port"].as_u64().unwrap_or(9330) as u16;
    drop(
        std::net::TcpListener::bind(("127.0.0.1", port)).map_err(|_| {
            anyhow!("Local port occupied: restart your existing ans up after adding accounts")
        })?,
    );
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join("grow-core.log"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        log.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    let mut launcher = Command::new(std::env::current_exe()?);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        launcher.process_group(0);
    }
    let mut child = launcher
        .arg("--data")
        .arg(root.canonicalize()?)
        .arg("up")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .spawn()?;
    let pid = child.id();
    for _ in 0..120 {
        if ready() {
            return Ok(Some(pid));
        }
        thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    bail!("Local runtime did not become ready; inspect grow-core.log locally")
}
pub fn run(root: &Path, args: &[String]) -> Result<Value> {
    let mut apply = false;
    let mut mode_seen = false;
    let mut supplied_hosts = false;
    let mut path = PathBuf::from("hosts.toml");
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--plan" | "--apply" => {
                if mode_seen {
                    bail!("Choose --plan OR --apply")
                };
                mode_seen = true;
                apply = args[i] == "--apply";
            }
            "--hosts" => {
                supplied_hosts = true;
                i += 1;
                path = PathBuf::from(args.get(i).ok_or(anyhow!("--hosts requires a file"))?);
            }
            _ => bail!("grow --plan|--apply [--hosts hosts.toml]"),
        };
        i += 1;
    }
    if supplied_hosts && !path.exists() {
        bail!("Explicit hosts file does not exist")
    }
    let (hosts, replicas, source) = hosts(&path)?;
    if hosts.iter().any(|h| !h.local()) {
        bail!("Apache core grow supports localhost only; hosted placement is not included")
    }
    let c = if root.join("config.json").exists() {
        super::read_json(&root.join("config.json"))?
    } else {
        json!({"custodians":{},"web_port":9330})
    };
    let placements:Vec<_>=hosts.iter().map(|h|json!({"host":h.name,"address":h.address,"enabled":h.enabled,"local":h.local(),"roles":h.roles.iter().map(Role::label).collect::<Vec<_>>(),"apply":if !h.enabled{"disabled"}else if h.local(){"local only"}else{"blocked: requires explicit future wrzucaj approval; remote backend not implemented"},"model_worker":"descriptor only; no model is loaded"})).collect();
    let available = hosts
        .iter()
        .filter(|h| h.enabled && h.roles.iter().any(|r| matches!(r, Role::Book)))
        .map(|h| {
            if h.local() {
                "localhost".to_owned()
            } else {
                h.address.clone()
            }
        })
        .collect::<BTreeSet<_>>()
        .len();
    let plan = json!({"seed":"ans","hosts_source":source,"placements":placements,"custodians":c["custodians"].as_object().map(|m|m.keys().cloned().collect::<Vec<_>>()).unwrap_or_default(),"replicas_requested":replicas,"planned_book_locations":available,"independent_local_fault_domains":if hosts.iter().any(|h|h.enabled&&h.local()){1}else{0},"remote_durability":false,"replication_goal_met":available as u64>=replicas,"remote_connections":false,"hardware_attestation":false,"state_replica":"logical custodian view; no signing keys or seeds; not a full signer recovery backup","models_loaded":false});
    if !apply {
        return Ok(
            json!({"ok":true,"mode":"dry-run","writes":false,"network_requests":false,"plan":plan}),
        );
    }
    let active: Vec<_> = hosts.iter().filter(|h| h.enabled).collect();
    if active.is_empty() {
        bail!("No enabled local host")
    }
    if active.iter().any(|h| !h.local()) {
        bail!("Remote --apply refused before writes/network. Only localhost is supported; no SSH/deployment backend is enabled.")
    }
    if (available as u64) < replicas {
        bail!("Replication goal unmet: add sufficient localhost placements or lower replicas")
    }
    if !root.join("config.json").exists() {
        bail!("Initialize a custodian first: ans init <word>")
    }
    super::exploit::configure(super::mappings(&c));
    let started = ensure_runtime(root, &c)?;
    let mut states = serde_json::Map::new();
    for w in c["custodians"].as_object().unwrap().keys() {
        let verified = super::exploit::call(w, None, "/verify")?;
        if verified["ok"] != true || verified["kernel_valid"] != true {
            bail!("Invalid local chain")
        };
        let mut state = super::local_call(w, "state", json!({}))?;
        state.as_object_mut().unwrap().remove("height");
        states.insert(w.clone(), state);
    }
    let book = super::read_json(&root.join("book.json"))?;
    let plan_hash = hash(&plan);
    let checkpoint = hash(&json!({"plan_hash":plan_hash,"book":book,"logical_states":states}));
    let dir = root.join("growth").join(&checkpoint);
    private_dir(&root.join("growth"))?;
    private_dir(&dir)?;
    let mut files = Vec::new();
    for h in &active {
        for role in &h.roles {
            let list: Vec<(String, Value)> = match role {
                Role::Book => vec![(format!("{}-book.json", h.name), book.clone())],
                Role::State => states
                    .iter()
                    .map(|(w, s)| (format!("{}-{w}-state.json", h.name), s.clone()))
                    .collect(),
                Role::Node => vec![(
                    format!("{}-node.json", h.name),
                    json!({"custodians":c["custodians"],"placement":"existing per-custodian local validator actors","hardware_vm":false}),
                )],
            };
            for (name, value) in list {
                let digest = write_snapshot(&dir.join(&name), &value)?;
                files.push(json!({"host":h.name,"file":name,"sha256":digest,"mode":"0600","role":role.label()}));
            }
        }
    }
    // Artifacts are durable before any signing. Receipts are idempotent by checkpoint+host.
    let mut receipts = Vec::new();
    for h in &active {
        for w in c["custodians"].as_object().unwrap().keys() {
            let own_files: Vec<_> = files
                .iter()
                .filter(|f| f["host"] == h.name)
                .cloned()
                .collect();
            receipts.push(super::local_call(w,"grow_record",json!({"host":h.address,"host_name":h.name,"checkpoint":checkpoint,"plan_hash":plan_hash,"files":own_files}))?);
        }
    }
    let result = json!({"ok":true,"mode":"applied-local-only","checkpoint":checkpoint,"directory":dir,"started_local_runtime_pid":started,"plan":plan,"files":files,"receipts":receipts,"hardware_attestation":false,"attestation":"XMSSMT first-validator + PopChain kernel; no hardware quote","remote_connections":false,"models_loaded":false});
    let receipt_file = dir.join("receipt.json");
    let receipt_matches = super::read_json(&receipt_file)
        .map(|v| v["checkpoint"] == result["checkpoint"] && v["files"] == result["files"])
        .unwrap_or(false);
    if !receipt_matches {
        write_snapshot(&receipt_file, &result)?;
    }
    Ok(result)
}
