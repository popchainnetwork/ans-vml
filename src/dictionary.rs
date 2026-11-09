// SPDX-License-Identifier: Apache-2.0
//! Offline, single-custodian lifecycle over the existing signed journal.
//! Book is a cache. Interrupted operations are never silently resumed.
use ans_dict::{book::Book, Crystal, CrystalKind};
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha3::{Digest, Sha3_256};
use std::{collections::BTreeMap, fs::OpenOptions, path::Path};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct OperationId(pub String);
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct ContentRoot(pub String);
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WordId {
    pub language: String,
    pub spelling: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Draft,
    Validated,
    Minted,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Draft { word: WordId, crystal: Value },
    Validate { root: ContentRoot },
    Mint { root: ContentRoot },
    Inspect { root: ContentRoot },
    Run { root: ContentRoot },
    /// Layer-3 meaning attached to a minted word (not a letter). Native effect: `word.meaning`.
    Meaning { root: ContentRoot, lang: String, text: String },
    /// Signed execution grant for a minted root. Native effect: `word.delegate`.
    Delegate { root: ContentRoot, scope: String },
    /// Withdraws an active grant. Native effect: `word.revoke`.
    Revoke { root: ContentRoot, scope: String },
}
impl Command {
    /// Root of an existing lifecycle the command transitions or annotates (None for Draft).
    pub fn target(&self) -> Option<&ContentRoot> {
        match self {
            Command::Draft { .. } => None,
            Command::Validate { root }
            | Command::Mint { root }
            | Command::Inspect { root }
            | Command::Run { root }
            | Command::Meaning { root, .. }
            | Command::Delegate { root, .. }
            | Command::Revoke { root, .. } => Some(root),
        }
    }
    /// Native journal action written for annotation commands on a minted root.
    pub fn annotation_action(&self) -> Option<&'static str> {
        match self {
            Command::Meaning { .. } => Some("word.meaning"),
            Command::Delegate { .. } => Some("word.delegate"),
            Command::Revoke { .. } => Some("word.revoke"),
            _ => None,
        }
    }
}
/// Language tag for meanings: 2–35 ASCII letters, digits or hyphens.
pub fn valid_lang(lang: &str) -> bool {
    (2..=35).contains(&lang.len()) && lang.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
}
/// Grant scopes: 1–64 lowercase ASCII letters, digits, '-', '_' or '.'.
pub fn valid_scope(scope: &str) -> bool {
    (1..=64).contains(&scope.len())
        && scope
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'-' | b'_' | b'.'))
}
pub fn text_sha3(text: &str) -> String {
    hex::encode(Sha3_256::digest(text.as_bytes()))
}
/// Expected native payload for an annotation command. Shared by the writer and strict replay
/// so a signed effect that differs in any field is refused.
pub fn annotation_payload(command: &Command, op_id: &OperationId, c: &Crystal, mint_block: u64) -> Option<Value> {
    let base = |extra: Value| {
        let mut v = json!({"word":c.id,"root":c.root,"op_id":op_id,"service":"dictionary","chain":"local test journal; not mainnet"});
        for (k, x) in extra.as_object().unwrap() {
            v[k] = x.clone();
        }
        v
    };
    Some(match command {
        Command::Meaning { lang, text, .. } => base(json!({"layer":3,"word_root":c.root,"word_block":mint_block,"lang":lang,"text":text,"text_sha3":text_sha3(text)})),
        Command::Delegate { scope, .. } | Command::Revoke { scope, .. } => base(json!({"scope":scope})),
        _ => return None,
    })
}
/// Active grants derived from signed dictionary-service delegate/revoke effects, in journal order.
/// Callers must pass a journal that strict replay has accepted.
pub fn active_grants(journal: &[Value]) -> std::collections::BTreeSet<(String, String)> {
    let mut grants = std::collections::BTreeSet::new();
    for e in journal {
        if data(e)["service"] != "dictionary" {
            continue;
        }
        let key = (
            data(e)["root"].as_str().unwrap_or("").to_owned(),
            data(e)["scope"].as_str().unwrap_or("").to_owned(),
        );
        match action(e) {
            "word.delegate" => {
                grants.insert(key);
            }
            "word.revoke" => {
                grants.remove(&key);
            }
            _ => {}
        }
    }
    grants
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub op_id: OperationId,
    pub command: Command,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub word: WordId,
    pub root: ContentRoot,
    pub state: State,
    pub crystal: Value,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Accepted,
    Rejected,
    Interrupted,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Receipt {
    pub status: Status,
    pub reason: Option<String>,
    pub entry: Option<Entry>,
}
fn hash(v: &Value) -> Result<String> {
    Ok(hex::encode(Sha3_256::digest(serde_json::to_vec(v)?)))
}
fn data(e: &Value) -> &Value {
    &e["body"]["data"]
}
fn action(e: &Value) -> &str {
    e["body"]["action"].as_str().unwrap_or("")
}
fn append(owner: &str, dir: &Path, kind: &str, data: Value) -> Result<Value> {
    crate::exploit::record_local(owner, dir, kind, data)
}
fn finish(owner: &str, dir: &Path, intent: &Value, receipt: &Receipt) -> Result<Value> {
    append(
        owner,
        dir,
        "dictionary.outcome",
        json!({"intent_hash":intent["hash"],"op_id":data(intent)["request"]["op_id"],"command_digest":data(intent)["command_digest"],"canonical":data(intent)["canonical"],"receipt":receipt}),
    )
}
fn replay(events: &[Value]) -> Result<BTreeMap<String, Entry>> {
    crate::dictionary_read::replay_verified(events)
}
fn rejected(reason: impl Into<String>) -> Receipt {
    Receipt {
        status: Status::Rejected,
        reason: Some(reason.into()),
        entry: None,
    }
}
fn evaluate(
    root_dir: &Path,
    owner: &str,
    dir: &Path,
    req: &Request,
    entries: &BTreeMap<String, Entry>,
    journal: &[Value],
) -> Result<Entry> {
    match &req.command {
        Command::Draft { word, crystal } => {
            let c = Crystal::parse(&serde_json::to_string(crystal)?)?;
            if word.language.trim().is_empty() || word.spelling != c.id {
                bail!("Word identity must match the crystal and declare a language");
            }
            let identity_matches = c.of_kind("identity").any(|l| {
                l.get("value") == Some(word.spelling.as_str())
                    && (l.get("lang").or(l.get("language")) == Some(word.language.as_str())
                        || (c.kind == CrystalKind::Letter
                            && word.language == "und"
                            && l.get("lang").is_none()
                            && l.get("language").is_none()))
            });
            if !identity_matches {
                bail!("Word identity and language must be root-bound identity leaves");
            }
            if c.kind == CrystalKind::Letter
                && (word.language != "und" || word.spelling.chars().count() != 1)
            {
                bail!("Character identity must be one Unicode scalar with language und");
            }
            if entries.contains_key(&c.root) {
                bail!("Root already has a lifecycle; use a new operation only for a transition");
            }
            if entries.values().any(|e| e.word == *word) {
                bail!("This word identity already has an immutable root; revisions are not implemented");
            }
            // Store bytes only as a rebuildable cache. No validation or execution permission follows.
            Book::open(&root_dir.join("book"))?.add(&c)?;
            Ok(Entry {
                word: word.clone(),
                root: ContentRoot(c.root),
                state: State::Draft,
                crystal: crystal.clone(),
            })
        }
        command => {
            let root = command.target().expect("non-draft command has a target");
            let mut e = entries
                .get(&root.0)
                .cloned()
                .ok_or_else(|| anyhow!("Unknown lifecycle root"))?;
            let c = Crystal::parse(&serde_json::to_string(&e.crystal)?)?;
            if c.root != root.0 {
                bail!("Root mismatch");
            }
            match command {
                Command::Validate{..} => {
                    if e.state!=State::Draft { bail!("Validation requires draft state"); }
                    crate::rule::kind(&c)?;
                    if c.kind == CrystalKind::Letter && !c.of_kind("character").any(|l| l.get("value") == Some(c.id.as_str())) {
                        bail!("Character leaf must match its root-bound identity");
                    }
                    // This slice does not introduce asset/font adapters. Never approve unverified references.
                    if c.leaves.iter().any(|l| matches!(l.get("kind"),Some("asset")|Some("font"))) { bail!("Asset/font verification is not implemented; validation refused"); }
                    e.state=State::Validated;
                }
                Command::Mint{..} => {
                    if e.state!=State::Validated { bail!("Mint requires validated state"); }
                    if let Some(existing) = crate::rule::mint_proof(&c.root,journal,&[],&crate::exploit::event_valid) {
                        // Idempotent completion: same operation already wrote the native effect
                        // (crash between word.mint and dictionary.outcome). Foreign mints stay refused.
                        if data(existing)["op_id"] == req.op_id.0 {
                            e.state = State::Minted;
                        } else {
                            bail!("A native mint already exists; automatic reconciliation is refused");
                        }
                    } else {
                        let letters = if c.kind==CrystalKind::Letter { vec![] } else {
                            crate::rule::letters_of(&c,&|ch| entries.values().find(|e|e.word.language=="und" && e.word.spelling==ch.to_string() && e.state==State::Minted && Crystal::parse(&e.crystal.to_string()).is_ok_and(|c|c.kind==CrystalKind::Letter)).and_then(|e|journal.iter().find(|v|action(v)=="word.mint" && data(v)["root"]==e.root.0 && data(v)["layer"]==1)).map(|v|(data(v)["root"].as_str().unwrap_or("").to_owned(),v["seq"].clone())))?
                        };
                        append(owner,dir,"word.mint",json!({"word":c.id,"root":c.root,"file":c.file_name(),"layer":if c.kind==CrystalKind::Letter{1}else{2},"letters":letters,"op_id":req.op_id,"service":"dictionary","chain":"local test journal; not mainnet"}))?;
                        e.state=State::Minted;
                    }
                }
                Command::Inspect{..} => {},
                Command::Run{..} => bail!("Execution refused: this service has no executable-permission approval adapter; minting is not permission"),
                Command::Meaning { .. } | Command::Delegate { .. } | Command::Revoke { .. } => {
                    if e.state != State::Minted { bail!("Requires a minted dictionary word; mint it first"); }
                    if journal.iter().any(|v| data(v)["op_id"] == req.op_id.0 && command.annotation_action() == Some(action(v))) {
                        bail!("A native effect for this operation already exists; automatic reconciliation is refused");
                    }
                    let grants = active_grants(journal);
                    match command {
                        Command::Meaning { lang, text, .. } => {
                            if c.kind == CrystalKind::Letter { bail!("Meanings attach to words, not letters"); }
                            if !valid_lang(lang) { bail!("Meaning language must be 2–35 ASCII letters, digits or hyphens"); }
                            if text.trim().is_empty() || text.len() > 4096 { bail!("Meaning text must contain 1–4096 bytes"); }
                        }
                        Command::Delegate { scope, .. } => {
                            if !valid_scope(scope) { bail!("Scope must be 1–64 lowercase ASCII letters, digits, '-', '_' or '.'"); }
                            if grants.contains(&(c.root.clone(), scope.clone())) { bail!("Scope is already delegated for this root"); }
                        }
                        Command::Revoke { scope, .. } => {
                            if !valid_scope(scope) { bail!("Scope must be 1–64 lowercase ASCII letters, digits, '-', '_' or '.'"); }
                            if !grants.contains(&(c.root.clone(), scope.clone())) { bail!("No active delegation for this root and scope"); }
                        }
                        _ => unreachable!(),
                    }
                    let block = crate::rule::mint_proof(&c.root, journal, &[], &crate::exploit::event_valid)
                        .filter(|m| data(m)["service"] == "dictionary")
                        .and_then(|m| m["seq"].as_u64())
                        .ok_or_else(|| anyhow!("Minted lifecycle has no dictionary native mint"))?;
                    let payload = annotation_payload(command, &req.op_id, &c, block).unwrap();
                    append(owner, dir, command.annotation_action().unwrap(), payload)?;
                }
                _=>unreachable!()
            }
            Ok(e)
        }
    }
}
/// Admission requires a parseable envelope and existing disposable/offline custodian.
/// Every admitted attempt (including retry/conflict/rejection) gets intent + outcome.
pub fn apply(root: &Path, owner: &str, req: Request) -> Result<Value> {
    transact(root, owner, req.op_id, |_| Ok(req.command))
}
fn transact(
    root: &Path,
    owner: &str,
    op_id: OperationId,
    prepare: impl FnOnce(&BTreeMap<String, Entry>) -> Result<Command>,
) -> Result<Value> {
    if op_id.0.is_empty() || op_id.0.len() > 128 {
        bail!("Operation ID must contain 1–128 bytes");
    }
    if owner.is_empty()
        || !owner
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    {
        bail!("Explicit local custodian required (--as)");
    }
    let dir = root.join("custodians").join(owner);
    if !["chain.ndjson", "xmss-demo.seed", "xmss-demo.state"]
        .iter()
        .all(|name| dir.join(name).is_file())
    {
        bail!(
            "Initialize a fresh local test custodian first; this service never creates identities"
        );
    }
    let _lock = lock_dictionary(&dir)?;
    recover_all(owner, &dir)?;
    let journal = crate::exploit::journal(owner, &dir)?;
    let entries = crate::dictionary_read::writer_entries(root, owner, &journal)?;
    let req = Request {
        op_id,
        command: prepare(&entries)?,
    };
    let digest = hash(&serde_json::to_value(&req.command)?)?;
    let prior = journal.iter().find(|e| {
        action(e) == "dictionary.outcome"
            && data(e)["canonical"] == true
            && data(e)["op_id"] == req.op_id.0
    });
    let canonical = prior.is_none();
    let intent = append(
        owner,
        &dir,
        "dictionary.intent",
        json!({"request":req,"command_digest":digest,"canonical":canonical}),
    )?;
    let receipt = if let Some(prior) = prior {
        if data(prior)["command_digest"] != digest {
            rejected("Operation ID is already bound to a different command")
        } else {
            serde_json::from_value(data(prior)["receipt"].clone())?
        }
    } else {
        let result = (|| {
            let book = Book::open(&root.join("book"))?;
            for entry in entries.values() {
                book.add(&Crystal::parse(&serde_json::to_string(&entry.crystal)?)?)?;
            }
            evaluate(root, owner, &dir, &req, &entries, &journal)
        })();
        match result {
            Ok(e) => Receipt {
                status: Status::Accepted,
                reason: None,
                entry: Some(e),
            },
            Err(e) => rejected(e.to_string()),
        }
    };
    let outcome = finish(owner, &dir, &intent, &receipt)?;
    Ok(
        json!({"op_id":req.op_id,"retry":!canonical,"receipt":receipt,"intent_hash":intent["hash"],"outcome":outcome,"scope":"offline experimental local custodian"}),
    )
}
fn lock_dictionary(dir: &Path) -> Result<std::fs::File> {
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(dir.join("dictionary.lock"))?;
    fs4::FileExt::try_lock_exclusive(&lock)
        .map_err(|_| anyhow!("Dictionary service busy; retry later"))?;
    Ok(lock)
}
/// Close every intent that lacks an outcome (caller holds dictionary.lock).
fn recover_all(owner: &str, dir: &Path) -> Result<()> {
    let dir = dir.to_path_buf();
    let mut journal = crate::exploit::journal(owner, &dir)?;
    let pending: Vec<_> = journal
        .iter()
        .filter(|e| {
            action(e) == "dictionary.intent"
                && !journal.iter().any(|o| {
                    action(o) == "dictionary.outcome" && data(o)["intent_hash"] == e["hash"]
                })
        })
        .cloned()
        .collect();
    for intent in pending {
        let request: Request = serde_json::from_value(data(&intent)["request"].clone())?;
        let digest = hash(&serde_json::to_value(&request.command)?)?;
        if data(&intent)["command_digest"] != digest {
            bail!("Pending intent command digest mismatch");
        }
        let receipt = match data(&intent)["canonical"].as_bool() {
            Some(true) => recover_canonical_pending(&journal, &intent, &request)?,
            Some(false) => {
                let index=journal.iter().position(|e|action(e)=="dictionary.outcome" && data(e)["canonical"]==true && data(e)["op_id"]==request.op_id.0).ok_or_else(||anyhow!("Interrupted retry has no completed original receipt; refusing to infer effects"))?;
                // Authenticate and replay the completed original before copying a receipt.
                crate::dictionary_read::replay_verified(&journal[..=index])?;
                let original = &journal[index];
                if data(original)["command_digest"] != digest {
                    rejected("Operation ID is already bound to a different command")
                } else {
                    serde_json::from_value(data(original)["receipt"].clone())?
                }
            }
            None => bail!("Pending intent is missing its canonical flag"),
        };
        journal.push(finish(owner, &dir, &intent, &receipt)?);
    }
    Ok(())
}
/// Recover interrupted dictionary operations without starting a new one.
pub fn recover(root: &Path, owner: &str) -> Result<()> {
    let dir = custodian_ready(root, owner)?;
    let _lock = lock_dictionary(&dir)?;
    recover_all(owner, &dir)
}
/// Models prepare the same typed request but never call the signer through MCP.
pub fn proposal(value: Value) -> Result<Value> {
    let request: Request = serde_json::from_value(value)?;
    Ok(
        json!({"request":request,"executed":false,"signed":false,"next":"Custodian reviews and invokes ans dictionary apply REQUEST.json with explicit --as"}),
    )
}

fn recover_canonical_pending(
    journal: &[Value],
    intent: &Value,
    request: &Request,
) -> Result<Receipt> {
    // Default: fail closed — do not guess success.
    let interrupted = Receipt {
        status: Status::Interrupted,
        reason: Some(
            "Previous attempt has no durable outcome; effects are not resumed or inferred".into(),
        ),
        entry: None,
    };
    if let Some(native_action) = request.command.annotation_action() {
        return recover_annotation_pending(journal, intent, request, native_action, interrupted);
    }
    let Command::Mint { root } = &request.command else {
        return Ok(interrupted);
    };
    // Only complete when the native mint for THIS op_id is already durable after the intent.
    let intent_seq = intent["seq"].as_u64().unwrap_or(0);
    let Some(native) = journal.iter().find(|e| {
        action(e) == "word.mint"
            && e["seq"].as_u64().unwrap_or(0) > intent_seq
            && data(e)["root"] == root.0
            && data(e)["op_id"] == request.op_id.0
    }) else {
        return Ok(interrupted);
    };
    let native_seq = native["seq"].as_u64().unwrap_or(0);
    // Strict adjacency: do not append an Accepted outcome after unrelated events.
    if journal
        .iter()
        .any(|e| e["seq"].as_u64().unwrap_or(0) > native_seq)
    {
        bail!(
            "Dictionary mint recovery blocked: unrelated signed events follow the native mint before its outcome; refuse automatic repair"
        );
    }
    let Some(prior) = journal.iter().rev().find_map(|e| {
        if action(e) != "dictionary.outcome" || data(e)["receipt"]["status"] != "accepted" {
            return None;
        }
        let entry: Entry = serde_json::from_value(data(e)["receipt"]["entry"].clone()).ok()?;
        (entry.root == *root && entry.state == State::Validated).then_some(entry)
    }) else {
        return Ok(interrupted);
    };
    if prior.crystal["root"] != root.0 {
        return Ok(interrupted);
    }
    let mut entry = prior;
    entry.state = State::Minted;
    Ok(Receipt {
        status: Status::Accepted,
        reason: Some(
            "Recovered: native word.mint for this operation was durable before outcome".into(),
        ),
        entry: Some(entry),
    })
}

/// Meaning/delegate/revoke crash window: the native effect for THIS op_id is durable directly
/// after the intent and nothing else follows. Only then is the outcome completed as Accepted;
/// any other shape stays Interrupted (no effect) or refuses automatic repair.
fn recover_annotation_pending(
    journal: &[Value],
    intent: &Value,
    request: &Request,
    native_action: &str,
    interrupted: Receipt,
) -> Result<Receipt> {
    let root = request.command.target().expect("annotation has a target");
    let intent_seq = intent["seq"].as_u64().unwrap_or(0);
    let Some(native) = journal.iter().find(|e| {
        action(e) == native_action
            && e["seq"].as_u64().unwrap_or(0) > intent_seq
            && data(e)["root"] == root.0
            && data(e)["op_id"] == request.op_id.0
    }) else {
        return Ok(interrupted);
    };
    let native_seq = native["seq"].as_u64().unwrap_or(0);
    if native_seq != intent_seq + 1
        || journal
            .iter()
            .any(|e| e["seq"].as_u64().unwrap_or(0) > native_seq)
    {
        bail!("Dictionary recovery blocked: unrelated signed events surround the native effect; refuse automatic repair");
    }
    let Some(entry) = journal.iter().rev().find_map(|e| {
        if action(e) != "dictionary.outcome" || data(e)["receipt"]["status"] != "accepted" {
            return None;
        }
        let entry: Entry = serde_json::from_value(data(e)["receipt"]["entry"].clone()).ok()?;
        (entry.root == *root && entry.state == State::Minted).then_some(entry)
    }) else {
        return Ok(interrupted);
    };
    let c = Crystal::parse(&serde_json::to_string(&entry.crystal)?)?;
    let block = journal
        .iter()
        .find(|m| action(m) == "word.mint" && data(m)["root"] == root.0 && data(m)["service"] == "dictionary")
        .and_then(|m| m["seq"].as_u64())
        .unwrap_or(0);
    if annotation_payload(&request.command, &request.op_id, &c, block).as_ref() != Some(data(native)) {
        bail!("Dictionary recovery blocked: native effect does not match the signed intent");
    }
    Ok(Receipt {
        status: Status::Accepted,
        reason: Some(format!("Recovered: native {native_action} for this operation was durable before outcome")),
        entry: Some(entry),
    })
}

/// Attempt-scoped IDs for legacy `ans mint` convenience path only.
/// Explicit `dictionary … --operation-id` semantics are unchanged: same ID replays the
/// original receipt. After a rejected/interrupted canonical legacy attempt, the next
/// convenience call opens `legacy-{stage}-{root}-retry-{seq}` so prerequisites can be
/// revalidated without duplicating accepted effects.
fn next_legacy_operation_id(
    journal: &[Value],
    stage: &str,
    content_root: &str,
) -> Result<OperationId> {
    let base = format!("legacy-{stage}-{content_root}");
    let latest = latest_attempt(journal, &base, |command| match (command, stage) {
        (Command::Draft { crystal, .. }, "draft") => crystal
            .get("root")
            .and_then(|v| v.as_str())
            .is_some_and(|r| r == content_root),
        (Command::Validate { root }, "validate") => root.0 == content_root,
        (Command::Mint { root }, "mint") => root.0 == content_root,
        _ => false,
    })?;
    Ok(attempt_id(&base, latest))
}
/// Latest canonical outcome among `base` / `base-retry-*` operations whose command matches.
fn latest_attempt(
    journal: &[Value],
    base: &str,
    matches: impl Fn(&Command) -> bool,
) -> Result<Option<(u64, String, String)>> {
    let mut latest: Option<(u64, String, String)> = None;
    for event in journal {
        if action(event) != "dictionary.outcome" || data(event)["canonical"] != true {
            continue;
        }
        let op = match data(event)["op_id"].as_str() {
            Some(op) if op == base || op.starts_with(&format!("{base}-retry-")) => op.to_owned(),
            _ => continue,
        };
        let Some(intent) = journal.iter().find(|i| {
            action(i) == "dictionary.intent" && i["hash"] == data(event)["intent_hash"]
        }) else {
            continue;
        };
        let request: Request = serde_json::from_value(data(intent)["request"].clone())?;
        if !matches(&request.command) {
            continue;
        }
        let status = data(event)["receipt"]["status"]
            .as_str()
            .unwrap_or("")
            .to_owned();
        let seq = event["seq"].as_u64().unwrap_or(0);
        if latest.as_ref().map(|(s, _, _)| seq >= *s).unwrap_or(true) {
            latest = Some((seq, status, op));
        }
    }
    Ok(latest)
}
fn attempt_id(base: &str, latest: Option<(u64, String, String)>) -> OperationId {
    match latest {
        None => OperationId(base.to_owned()),
        Some((_, status, op)) if status == "accepted" => OperationId(op),
        Some((seq, status, _)) if status == "rejected" || status == "interrupted" => {
            OperationId(format!("{base}-retry-{seq}"))
        }
        Some((_, _, op)) => OperationId(op),
    }
}
fn custodian_ready(root: &Path, owner: &str) -> Result<std::path::PathBuf> {
    if owner.is_empty() {
        bail!("Explicit local custodian required (--as)");
    }
    let dir = root.join("custodians").join(owner);
    if !["chain.ndjson", "xmss-demo.seed", "xmss-demo.state"]
        .iter()
        .all(|name| dir.join(name).is_file())
    {
        bail!("Initialize a fresh local test custodian first; this service never creates identities");
    }
    Ok(dir)
}
/// Legacy `ans mint-meaning|delegate|revoke` adapter: one typed dictionary operation with a
/// deterministic, attempt-scoped operation ID. Accepted outcomes are idempotent (no new signature);
/// rejected/interrupted attempts get `-retry-{seq}` so prerequisites are re-checked.
/// Grant IDs include the number of completed grant transitions so delegate→revoke→delegate
/// opens a new operation rather than replaying the first receipt.
pub fn legacy_annotation(root: &Path, owner: &str, crystal: &Crystal, command: Command) -> Result<Value> {
    let dir = custodian_ready(root, owner)?;
    recover(root, owner)?;
    let lifecycle = crate::dictionary_read::show(root, owner, &crystal.root, None)
        .ok()
        .and_then(|item| item.lifecycle);
    if lifecycle != Some(State::Minted) {
        bail!(
            "refused: {} has no minted dictionary lifecycle; run `ans --as {owner} mint {}` first",
            crystal.id,
            crystal.id
        );
    }
    let journal = crate::exploit::journal(owner, &dir)?;
    let short = |v: &str| text_sha3(v)[..16].to_owned();
    let (stage, base, already) = match &command {
        Command::Meaning { lang, text, .. } => (
            "meaning",
            format!("legacy-meaning-{}-{}", crystal.root, short(&format!("{lang}\0{text}"))),
            None,
        ),
        Command::Delegate { scope, .. } | Command::Revoke { scope, .. } => {
            let delegate = matches!(command, Command::Delegate { .. });
            let key = (crystal.root.clone(), scope.clone());
            let active = active_grants(&journal).contains(&key);
            let transitions = journal
                .iter()
                .filter(|e| {
                    matches!(action(e), "word.delegate" | "word.revoke")
                        && data(e)["service"] == "dictionary"
                        && data(e)["root"] == key.0
                        && data(e)["scope"] == key.1
                })
                .count();
            let stage = if delegate { "delegate" } else { "revoke" };
            (
                stage,
                format!("legacy-{stage}-{}-{}-g{transitions}", crystal.root, short(scope)),
                (active == delegate).then_some(if delegate { "already delegated" } else { "not delegated" }),
            )
        }
        _ => bail!("Unsupported legacy annotation"),
    };
    let wanted = serde_json::to_value(&command)?;
    let latest = latest_attempt(&journal, &base, |c| serde_json::to_value(c).ok().as_ref() == Some(&wanted))?;
    if let Some((_, status, op)) = &latest {
        if status == "accepted" {
            return Ok(json!({"ok":true,"already":true,"action":format!("word.{stage}"),"word":crystal.id,"root":crystal.root,"op_id":op,"service":"dictionary","network":"none: local journal only"}));
        }
    }
    if let Some(state) = already {
        if latest.is_none() {
            return Ok(json!({"ok":true,"already":true,"state":state,"action":format!("word.{stage}"),"word":crystal.id,"root":crystal.root,"service":"dictionary","signed":false}));
        }
    }
    let op_id = attempt_id(&base, latest);
    let result = apply(root, owner, Request { op_id: op_id.clone(), command: command.clone() })?;
    let result = match result["receipt"]["status"].as_str() {
        // A canonical attempt interrupted earlier was closed by `apply`; open a fresh attempt once.
        Some("interrupted") => {
            let journal = crate::exploit::journal(owner, &dir)?;
            let latest = latest_attempt(&journal, &base, |c| serde_json::to_value(c).ok().as_ref() == Some(&wanted))?;
            apply(root, owner, Request { op_id: attempt_id(&base, latest), command })?
        }
        _ => result,
    };
    let result = ensure_accepted(result, stage)?;
    let journal = crate::exploit::journal(owner, &dir)?;
    let native = journal
        .iter()
        .rev()
        .find(|e| action(e) == format!("word.{stage}") && data(e)["op_id"] == result["op_id"])
        .ok_or_else(|| anyhow!("Dictionary {stage} accepted without a native effect"))?;
    Ok(json!({"ok":true,"action":format!("word.{stage}"),"word":crystal.id,"root":crystal.root,"block":native["seq"],"op_id":result["op_id"],"retry":result["retry"],"service":"dictionary","lifecycle_adapter":"legacy_annotation","network":"none: local journal only","private_key":"never printed"}))
}
/// Adopt an existing book/UCD crystal into the typed dictionary lifecycle and mint it.
/// Used by legacy `ans mint` / `mint-alphabet` so there is one ledger path: draft → validate → mint
/// with dictionary.intent/outcome and the same native word.mint event shape the strict reader expects.
/// Does not invent meanings, licenses or provenance; crystal bytes must already be complete.
/// Bare legacy `word.mint` without lifecycle is reported, never auto-promoted.
pub fn adopt_book_crystal(root: &Path, owner: &str, crystal: &Crystal) -> Result<Value> {
    if owner.is_empty() {
        bail!("Explicit local custodian required (--as)");
    }
    let dir = root.join("custodians").join(owner);
    if !["chain.ndjson", "xmss-demo.seed", "xmss-demo.state"]
        .iter()
        .all(|name| dir.join(name).is_file())
    {
        bail!("Initialize a fresh local test custodian first; this service never creates identities");
    }
    // Cache bytes only; lifecycle authority remains the signed journal. Provenance/root stay crystal-bound.
    Book::open(&root.join("book"))?.add(crystal)?;
    let content = ContentRoot(crystal.root.clone());
    let word = word_id_from_crystal(crystal)?;
    let crystal_value: Value = serde_json::from_str(&crystal.to_json())?;
    // All legacy stages use attempt-scoped IDs after rejected/interrupted outcomes.
    // Explicit dictionary --operation-id receipt semantics stay unchanged.
    for _ in 0..12 {
        let lifecycle = match crate::dictionary_read::show(root, owner, &crystal.root, None) {
            Ok(item) => item.lifecycle,
            Err(_) => None,
        };
        let journal = crate::exploit::journal(owner, &dir)?;
        let bare = crate::rule::mint_proof(
            &crystal.root,
            &journal,
            &[],
            &crate::exploit::event_valid,
        );
        if lifecycle == Some(State::Minted) {
            let block = bare.map(|e| e["seq"].clone());
            return Ok(json!({
                "already": true,
                "lifecycle": "minted",
                "service": "dictionary",
                "word": crystal.id,
                "root": crystal.root,
                "block": block,
                "layer": if crystal.kind == CrystalKind::Letter { 1 } else { 2 },
                "network": "none: local journal only",
                "private_key": "never printed"
            }));
        }
        if lifecycle.is_none() {
            if let Some(e) = bare {
                return Ok(json!({
                    "already": true,
                    "legacy_native_only": true,
                    "lifecycle": null,
                    "refused_auto_reconcile": true,
                    "word": crystal.id,
                    "root": crystal.root,
                    "block": e["seq"],
                    "next": "Native word.mint exists without dictionary lifecycle; automatic promotion is refused"
                }));
            }
            let journal = crate::exploit::journal(owner, &dir)?;
            let draft_id = next_legacy_operation_id(&journal, "draft", &crystal.root)?;
            let drafted = apply(
                root,
                owner,
                Request {
                    op_id: draft_id,
                    command: Command::Draft {
                        word: word.clone(),
                        crystal: crystal_value.clone(),
                    },
                },
            )?;
            match drafted["receipt"]["status"].as_str() {
                Some("accepted") | Some("interrupted") => continue,
                Some("rejected") => {
                    let reason = drafted["receipt"]["reason"].as_str().unwrap_or("");
                    if reason.contains("already has a lifecycle")
                        || reason.contains("immutable root")
                        || reason.contains("Dictionary service busy")
                    {
                        continue;
                    }
                    bail!("dictionary draft refused: {reason}");
                }
                other => bail!("dictionary draft returned unexpected status {other:?}"),
            }
        }
        if lifecycle == Some(State::Draft) {
            let journal = crate::exploit::journal(owner, &dir)?;
            let validate_id = next_legacy_operation_id(&journal, "validate", &crystal.root)?;
            let validated = apply(
                root,
                owner,
                Request {
                    op_id: validate_id,
                    command: Command::Validate {
                        root: content.clone(),
                    },
                },
            )?;
            match validated["receipt"]["status"].as_str() {
                Some("accepted") | Some("interrupted") => continue,
                Some("rejected") => {
                    let reason = validated["receipt"]["reason"].as_str().unwrap_or("");
                    if reason.contains("Validation requires draft")
                        || reason.contains("Dictionary service busy")
                    {
                        continue;
                    }
                    bail!("dictionary validate refused: {reason}");
                }
                other => bail!("dictionary validate returned unexpected status {other:?}"),
            }
        }
        if lifecycle == Some(State::Validated) {
            let journal = crate::exploit::journal(owner, &dir)?;
            let mint_id = next_legacy_operation_id(&journal, "mint", &crystal.root)?;
            let minted = apply(
                root,
                owner,
                Request {
                    op_id: mint_id.clone(),
                    command: Command::Mint {
                        root: content.clone(),
                    },
                },
            )?;
            match minted["receipt"]["status"].as_str() {
                Some("accepted") => {
                    let journal = crate::exploit::journal(owner, &dir)?;
                    let native = crate::rule::mint_proof(
                        &crystal.root,
                        &journal,
                        &[],
                        &crate::exploit::event_valid,
                    )
                    .ok_or_else(|| anyhow!("Dictionary mint accepted without a native word.mint event"))?;
                    return Ok(json!({
                        "already": minted["retry"],
                        "lifecycle": "minted",
                        "service": "dictionary",
                        "word": crystal.id,
                        "root": crystal.root,
                        "block": native["seq"],
                        "layer": native["body"]["data"]["layer"],
                        "op_id": minted["op_id"],
                        "retry": minted["retry"],
                        "state": "minted",
                        "network": "none: local journal only",
                        "private_key": "never printed"
                    }));
                }
                Some("interrupted") => continue,
                Some("rejected") => {
                    let reason = minted["receipt"]["reason"].as_str().unwrap_or("");
                    if reason.contains("Mint requires validated")
                        || reason.contains("Dictionary service busy")
                        || reason.contains("native mint already exists")
                    {
                        continue;
                    }
                    bail!("dictionary mint refused: {reason}");
                }
                other => bail!("dictionary mint returned unexpected status {other:?}"),
            }
        }
    }
    bail!("Dictionary adopt could not converge under concurrent writers; retry")
}
fn word_id_from_crystal(c: &Crystal) -> Result<WordId> {
    let identity = c
        .of_kind("identity")
        .next()
        .ok_or_else(|| anyhow!("Crystal requires a root-bound identity"))?;
    let language = identity
        .get("lang")
        .or(identity.get("language"))
        .or_else(|| (c.kind == CrystalKind::Letter).then_some("und"))
        .ok_or_else(|| anyhow!("Word crystal needs a root-bound identity language"))?
        .to_owned();
    if c.kind == CrystalKind::Letter && (language != "und" || c.id.chars().count() != 1) {
        bail!("Character identity must be one Unicode scalar with language und");
    }
    Ok(WordId {
        language,
        spelling: c.id.clone(),
    })
}
fn ensure_accepted(result: Value, step: &str) -> Result<Value> {
    match result["receipt"]["status"].as_str() {
        Some("accepted") => Ok(result),
        Some("rejected") => {
            let reason = result["receipt"]["reason"]
                .as_str()
                .unwrap_or("rejected")
                .to_owned();
            bail!("dictionary {step} refused: {reason}")
        }
        other => bail!("dictionary {step} returned unexpected status {other:?}"),
    }
}
pub const HELP: &str = "ANS dictionary — local experimental lifecycle

Read-only (no signer or identity creation):
  ans dictionary list
  ans [--as OWNER] dictionary show WORD_OR_ROOT
  ans --as OWNER dictionary export WORD_OR_ROOT --expect-key HEX
  ans dictionary verify PROOF_FILE --expect-key HEX
  ans dictionary serve PROOF_FILE --expect-key HEX [--port N] [--package FILE.tar.gz]

Owner commands SIGN journal intent/outcome events (existing disposable --as required):
  ans --as OWNER dictionary write character CHAR (--unverified | --license L --source S [--attribution A]) [--operation-id ID]
  ans --as OWNER dictionary write word WORD --lang LANG --meaning TEXT (--unverified | --license L --source S [--attribution A]) [--operation-id ID]
  ans --as OWNER dictionary draft CRYSTAL_FILE [--operation-id ID]
  ans --as OWNER dictionary validate WORD_OR_ROOT [--operation-id ID]
  ans --as OWNER dictionary mint WORD_OR_ROOT [--operation-id ID]
  ans --as OWNER dictionary inspect WORD_OR_ROOT [--operation-id ID]

write composes a NEW crystal from explicit CLI text (no handwritten JSON), binds
identity/schema/content/language/source/license/attribution as root leaves, then
drafts only. It does not validate, mint, understand language, or clear rights.
Unicode identity bytes are preserved as typed; they are not silently normalized.
Characters use language und. Word identity is language+spelling; the same spelling
in another language is a different entry. Revising an existing identity is refused.
Draft checks Merkle/identity bytes but stays Draft; validate is a separate structural step.
Mint requires Validated state and verified minted characters; mint is not execution permission.
Inspect signs a receipt; show/list are read-only alternatives.
IDs omitted on owner commands are generated with OS randomness and printed as op_id.
Reuse --operation-id for retries: same command returns its original receipt; a different
command is rejected. Use show for current state, since a retry returns its old receipt.
Legacy `ans mint` / `ans mint-alphabet` now adopt existing book crystals through this
same draft→validate→mint service (deterministic legacy-* operation IDs). They do not
invent meanings or rights. `ans mint-meaning|delegate|revoke` are typed dictionary
operations on minted words; `ans run` requires a minted lifecycle plus an active
dictionary delegation. skill_run is disabled.
Advanced typed entry point: ans --as OWNER dictionary apply REQUEST.json.
Admitted calls return receipts even when rejected: check receipt.status, not just exit 0.
Receipts include public signatures/keys, never secret signer seed or counter data.
This service never initializes identities. Use only fresh offline test identities.
";
fn operation_id(explicit: Option<&str>) -> Result<OperationId> {
    let id = if let Some(id) = explicit {
        id.to_owned()
    } else {
        use rand::RngCore;
        let mut bytes = [0u8; 16];
        rand::rngs::OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|e| anyhow!("Cannot generate an operation ID: {e}"))?;
        format!("cli-{}", hex::encode(bytes))
    };
    if id.is_empty() || id.len() > 128 {
        bail!("Operation ID must contain 1–128 bytes");
    }
    Ok(OperationId(id))
}
fn take_flag(args: &[String], name: &str) -> Result<(Option<String>, Vec<String>)> {
    let mut out = Vec::with_capacity(args.len());
    let mut value = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == name {
            if value.is_some() {
                bail!("Flag {name} may be supplied only once");
            }
            let v = args
                .get(i + 1)
                .ok_or_else(|| anyhow!("Flag {name} requires a value"))?;
            if v.starts_with('-') {
                bail!("Flag {name} requires an explicit value");
            }
            value = Some(v.clone());
            i += 2;
            continue;
        }
        out.push(args[i].clone());
        i += 1;
    }
    Ok((value, out))
}
fn take_switch(args: &[String], name: &str) -> Result<(bool, Vec<String>)> {
    let mut out = Vec::with_capacity(args.len());
    let mut seen = false;
    for a in args {
        if a == name {
            if seen {
                bail!("Flag {name} may be supplied only once");
            }
            seen = true;
            continue;
        }
        out.push(a.clone());
    }
    Ok((seen, out))
}
fn provenance_from_args(args: &[String]) -> Result<(ans_dict::author::Provenance, Vec<String>)> {
    let (unverified, args) = take_switch(args, "--unverified")?;
    let (license, args) = take_flag(&args, "--license")?;
    let (source, args) = take_flag(&args, "--source")?;
    let (attribution, args) = take_flag(&args, "--attribution")?;
    let provenance = if unverified {
        if license.is_some() || source.is_some() || attribution.is_some() {
            bail!("Use either --unverified or explicit --license/--source, not both");
        }
        ans_dict::author::Provenance::unverified()
    } else {
        let license = license.ok_or_else(|| {
            anyhow!("Authoring requires --license LICENSE and --source SOURCE, or --unverified")
        })?;
        let source = source.ok_or_else(|| {
            anyhow!("Authoring requires --license LICENSE and --source SOURCE, or --unverified")
        })?;
        ans_dict::author::Provenance::explicit(&source, &license, attribution.as_deref())?
    };
    Ok((provenance, args))
}
fn write_command(args: &[String]) -> Result<(Command, Value)> {
    if args.is_empty() {
        bail!("Usage: dictionary write character|word ...; see dictionary --help");
    }
    let kind = args[0].as_str();
    let (provenance, rest) = provenance_from_args(&args[1..])?;
    match kind {
        "character" => {
            if rest.len() != 1 {
                bail!("Usage: dictionary write character CHAR (--unverified | --license L --source S [--attribution A]) [--operation-id ID]");
            }
            let crystal = ans_dict::author::character(&rest[0], &provenance)?;
            let summary = json!({
                "kind":"character",
                "id":crystal.id,
                "language":"und",
                "root":crystal.root,
                "index":crystal.index(),
                "provenance": if provenance.unverified {"user-supplied/unverified"} else {"user-supplied/author-asserted"},
                "rights_claim":"not validated",
                "semantic_understanding":false,
                "next":"draft only; run validate then mint separately"
            });
            Ok((
                Command::Draft {
                    word: WordId { language: "und".into(), spelling: crystal.id.clone() },
                    crystal: serde_json::from_str(&crystal.to_json())?,
                },
                summary,
            ))
        }
        "word" => {
            let (lang, rest) = take_flag(&rest, "--lang")?;
            let (meaning, rest) = take_flag(&rest, "--meaning")?;
            let lang = lang.ok_or_else(|| anyhow!("write word requires --lang LANG"))?;
            let meaning = meaning.ok_or_else(|| anyhow!("write word requires --meaning TEXT"))?;
            if rest.len() != 1 {
                bail!("Usage: dictionary write word WORD --lang LANG --meaning TEXT (--unverified | --license L --source S [--attribution A]) [--operation-id ID]");
            }
            let crystal = ans_dict::author::word(&rest[0], &lang, &meaning, &provenance)?;
            let required: Vec<String> = crystal.id.to_lowercase().chars().map(|c| c.to_string()).collect();
            let summary = json!({
                "kind":"word",
                "id":crystal.id,
                "language":lang,
                "root":crystal.root,
                "index":crystal.index(),
                "provenance": if provenance.unverified {"user-supplied/unverified"} else {"user-supplied/author-asserted"},
                "rights_claim":"not validated",
                "semantic_understanding":false,
                "character_references_bound":false,
                "mint_requires_lowercase_characters":required,
                "next":"draft only; mint each required character before word mint"
            });
            Ok((
                Command::Draft {
                    word: WordId { language: lang, spelling: crystal.id.clone() },
                    crystal: serde_json::from_str(&crystal.to_json())?,
                },
                summary,
            ))
        }
        _ => bail!("write supports character or word; see dictionary --help"),
    }
}
fn draft_file(path: &str) -> Result<Command> {
    use std::io::Read;
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| anyhow!("Cannot read crystal file '{path}'"))?;
    if !metadata.file_type().is_file() {
        bail!("Draft needs a regular crystal file, not a directory or symlink");
    }
    const LIMIT: u64 = 8 * 1024 * 1024;
    if metadata.len() > LIMIT {
        bail!("Crystal file exceeds the owner CLI's 8 MiB limit");
    }
    let mut text = String::new();
    std::fs::File::open(path)?
        .take(LIMIT + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > LIMIT {
        bail!("Crystal file exceeds the owner CLI's 8 MiB limit");
    }
    let c = Crystal::parse(&text).map_err(|e| anyhow!("Crystal content was not admitted: {e}"))?;
    let identity = c
        .of_kind("identity")
        .next()
        .ok_or_else(|| anyhow!("Crystal requires a root-bound identity"))?;
    let language = identity
        .get("lang")
        .or(identity.get("language"))
        .or_else(|| (c.kind == CrystalKind::Letter).then_some("und"))
        .ok_or_else(|| anyhow!("Word crystal needs a root-bound identity language"))?;
    Ok(Command::Draft {
        word: WordId {
            language: language.into(),
            spelling: c.id.clone(),
        },
        crystal: serde_json::from_str(&text)?,
    })
}
fn resolve(entries: &BTreeMap<String, Entry>, query: &str) -> Result<ContentRoot> {
    if query.len() == 64 && query.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(ContentRoot(query.to_ascii_lowercase()));
    }
    let matches = entries
        .values()
        .filter(|e| {
            Crystal::parse(&e.crystal.to_string())
                .is_ok_and(|c| crate::dictionary_read::matches(&c, query))
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        bail!("Expected one lifecycle entry for '{query}', found {}; draft it first or use an exact content root",matches.len());
    }
    Ok(matches[0].root.clone())
}
pub fn cli(root: &Path, owner: &str, args: &[String]) -> Result<Value> {
    if args.is_empty()
        || args.iter().any(|a| matches!(a.as_str(), "--help" | "-h"))
        || args[0] == "help"
    {
        return Ok(json!({"help":HELP,"signer_opened":false}));
    }
    let command = args[0].as_str();
    if command == "write" {
        if owner.is_empty() {
            bail!("Owner commands sign journal events; pass --as OWNER for an existing disposable offline identity. For read-only access use dictionary show/list");
        }
        let (explicit, write_args) = take_flag(&args[1..], "--operation-id")?;
        // Failed composition must not open a signer or create an identity.
        let (typed, authored) = write_command(&write_args)?;
        let id = operation_id(explicit.as_deref())?;
        let mut result = apply(
            root,
            owner,
            Request {
                op_id: id,
                command: typed,
            },
        )?;
        if let Some(obj) = result.as_object_mut() {
            obj.insert("authored".into(), authored);
        }
        return Ok(result);
    }
    if matches!(command, "draft" | "validate" | "mint" | "inspect") {
        if args.len() != 2 && args.len() != 4 {
            bail!("Usage: dictionary {command} TARGET [--operation-id ID]; use dictionary --help");
        }
        let explicit = if args.len() == 4 {
            if args[2] != "--operation-id" {
                bail!("Only --operation-id ID is accepted after the target");
            }
            Some(args[3].as_str())
        } else {
            None
        };
        if owner.is_empty() {
            bail!("Owner commands sign journal events; pass --as OWNER for an existing disposable offline identity. For read-only access use dictionary show/list");
        }
        let target = args[1].trim();
        if target.is_empty() || target.starts_with('-') {
            bail!("An explicit target is required; use dictionary --help");
        }
        let id = operation_id(explicit)?;
        if command == "draft" {
            return apply(
                root,
                owner,
                Request {
                    op_id: id,
                    command: draft_file(target)?,
                },
            );
        }
        if target.len() > 1024
            || target
                .chars()
                .any(|c| c.is_control() || matches!(c, '/' | '\\'))
        {
            bail!("Entry target must be a word/character or content root, not a file path");
        }
        return transact(root, owner, id, |entries| {
            let root = resolve(entries, target)?;
            Ok(match command {
                "validate" => Command::Validate { root },
                "mint" => Command::Mint { root },
                "inspect" => Command::Inspect { root },
                _ => unreachable!(),
            })
        });
    }
    if command != "apply" {
        return crate::dictionary_read::cli(root, owner, args);
    }
    if args.len() != 2 {
        bail!("Usage: ans --as OWNER dictionary apply REQUEST.json");
    }
    apply(
        root,
        owner,
        serde_json::from_str(&std::fs::read_to_string(&args[1])?)?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ans_dict::Leaf;
    struct Home(std::path::PathBuf);
    impl Home {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "ans-dictionary-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ));
            std::fs::create_dir_all(&p).unwrap();
            crate::exploit::initialize("alice", &p.join("custodians/alice")).unwrap();
            Self(p)
        }
        fn journal(&self) -> Vec<Value> {
            crate::exploit::journal("alice", &self.0.join("custodians/alice")).unwrap()
        }
        fn apply(&self, id: &str, command: Command) -> Value {
            apply(
                &self.0,
                "alice",
                Request {
                    op_id: OperationId(id.into()),
                    command,
                },
            )
            .unwrap()
        }
    }
    impl Drop for Home {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn crystal(letter: &str, meaning: bool) -> Value {
        let mut leaves = vec![Leaf::new(&[
            ("kind", "identity"),
            ("value", letter),
            ("lang", "und"),
        ])];
        if meaning {
            leaves.push(Leaf::new(&[("kind", "character"), ("value", letter)]));
        }
        serde_json::from_str(
            &Crystal::build(CrystalKind::Letter, letter, leaves, Default::default())
                .unwrap()
                .to_json(),
        )
        .unwrap()
    }
    fn draft(v: Value) -> Command {
        Command::Draft {
            word: WordId {
                language: "und".into(),
                spelling: v["character"].as_str().unwrap().into(),
            },
            crystal: v,
        }
    }
    fn root(v: &Value) -> ContentRoot {
        ContentRoot(v["root"].as_str().unwrap().into())
    }
    fn status(v: &Value) -> &str {
        v["receipt"]["status"].as_str().unwrap()
    }
    #[test]
    fn lifecycle_retries_conflicts_and_mint_is_not_permission() {
        let h = Home::new();
        let c = crystal("a", true);
        let r = root(&c);
        let first = h.apply("draft", draft(c.clone()));
        assert_eq!(status(&first), "accepted");
        assert!(crate::exploit::event_valid(&first["outcome"]));
        assert_eq!(
            first["outcome"]["body"]["data"]["intent_hash"],
            first["intent_hash"]
        );
        assert_eq!(
            status(&h.apply("early-mint", Command::Mint { root: r.clone() })),
            "rejected"
        );
        assert_eq!(
            status(&h.apply("validate", Command::Validate { root: r.clone() })),
            "accepted"
        );
        let minted = h.apply("mint", Command::Mint { root: r.clone() });
        assert_eq!(minted["receipt"]["entry"]["state"], "minted");
        let retry = h.apply("mint", Command::Mint { root: r.clone() });
        assert_eq!(retry["retry"], true);
        assert_eq!(retry["receipt"], minted["receipt"]);
        assert_eq!(
            status(&h.apply("mint", Command::Run { root: r.clone() })),
            "rejected"
        );
        assert_eq!(
            status(&h.apply("run", Command::Run { root: r.clone() })),
            "rejected"
        );
        // Losing the cache does not lose authority; replay restores the same bytes/root.
        let book = Book::open(&h.0.join("book")).unwrap();
        let c = Crystal::parse(&c.to_string()).unwrap();
        std::fs::remove_file(book.dir.join(c.file_name())).unwrap();
        let inspected = h.apply("inspect", Command::Inspect { root: r });
        assert_eq!(inspected["receipt"]["entry"]["state"], "minted");
        assert_eq!(book.get(&c.file_name()).unwrap().root, c.root);
        let j = h.journal();
        assert_eq!(j.iter().filter(|e| action(e) == "word.mint").count(), 1);
        assert_eq!(
            j.iter()
                .filter(|e| action(e) == "dictionary.intent")
                .count(),
            8
        );
        assert_eq!(
            j.iter()
                .filter(|e| action(e) == "dictionary.outcome")
                .count(),
            8
        );
    }
    #[test]
    fn blank_tampered_and_immutable_entries_are_rejected() {
        let h = Home::new();
        let blank = crystal("b", false);
        let r = root(&blank);
        assert_eq!(status(&h.apply("blank", draft(blank))), "accepted");
        assert_eq!(
            status(&h.apply("run-blank", Command::Run { root: r.clone() })),
            "rejected"
        );
        assert_eq!(
            status(&h.apply("validate-blank", Command::Validate { root: r })),
            "rejected"
        );
        let mut tamper = crystal("c", true);
        tamper["leaves"][0]["value"] = json!("altered");
        assert_eq!(status(&h.apply("tamper", draft(tamper))), "rejected");
        assert_eq!(
            status(&h.apply("revision", draft(crystal("b", true)))),
            "rejected"
        );
        let mut alias = crystal("c", true);
        alias["character"] = json!("d");
        assert_eq!(status(&h.apply("identity-alias", draft(alias))), "rejected");
        assert!(h.journal().iter().all(crate::exploit::event_valid));
    }
    fn cli_args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }
    fn public_files(root: &Path) -> BTreeMap<std::path::PathBuf, Vec<u8>> {
        fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<std::path::PathBuf, Vec<u8>>) {
            for file in std::fs::read_dir(dir).unwrap() {
                let path = file.unwrap().path();
                if path.is_dir() {
                    walk(root, &path, out)
                } else {
                    out.insert(
                        path.strip_prefix(root).unwrap().into(),
                        std::fs::read(path).unwrap(),
                    );
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(root, root, &mut out);
        out
    }
    #[test]
    fn friendly_owner_cli_preserves_typed_receipts_retry_and_read_only_boundaries() {
        let h = Home::new();
        let fixture = h.0.join("a.crystal.json");
        std::fs::write(&fixture, crystal("a", true).to_string()).unwrap();
        let first = cli(
            &h.0,
            "alice",
            &cli_args(&[
                "draft",
                fixture.to_str().unwrap(),
                "--operation-id",
                "draft",
            ]),
        )
        .unwrap();
        assert_eq!(status(&first), "accepted");
        let early = cli(
            &h.0,
            "alice",
            &cli_args(&["mint", "a", "--operation-id", "early"]),
        )
        .unwrap();
        assert_eq!(status(&early), "rejected");
        let validated = cli(
            &h.0,
            "alice",
            &cli_args(&["validate", "a", "--operation-id", "validate"]),
        )
        .unwrap();
        assert_eq!(status(&validated), "accepted");
        let conflict = cli(
            &h.0,
            "alice",
            &cli_args(&["mint", "a", "--operation-id", "draft"]),
        )
        .unwrap();
        assert_eq!(status(&conflict), "rejected");
        assert_eq!(conflict["retry"], true);
        let minted = cli(
            &h.0,
            "alice",
            &cli_args(&["mint", "a", "--operation-id", "mint"]),
        )
        .unwrap();
        assert_eq!(minted["receipt"]["entry"]["state"], "minted");
        let retry = cli(
            &h.0,
            "alice",
            &cli_args(&["mint", "a", "--operation-id", "mint"]),
        )
        .unwrap();
        assert_eq!(retry["retry"], true);
        assert_eq!(retry["receipt"], minted["receipt"]);
        let one = cli(&h.0, "alice", &cli_args(&["inspect", "a"])).unwrap();
        let two = cli(&h.0, "alice", &cli_args(&["inspect", "a"])).unwrap();
        assert_ne!(one["op_id"], two["op_id"]);
        assert!(one["op_id"].as_str().unwrap().starts_with("cli-"));
        let journal = h.journal();
        assert_eq!(
            journal.iter().filter(|e| action(e) == "word.mint").count(),
            1
        );
        for value in [&first, &minted, &one] {
            let text = value.to_string();
            assert!(
                !text.contains("xmss-demo.seed")
                    && !text.contains("xmss-demo.state")
                    && !text.contains("private_key")
            );
        }
        for file in ["xmss-demo.seed", "xmss-demo.state"] {
            std::fs::remove_file(h.0.join("custodians/alice").join(file)).unwrap();
        }
        let before = public_files(&h.0);
        let shown = cli(&h.0, "alice", &cli_args(&["show", "a"])).unwrap();
        assert_eq!(shown["lifecycle"], "minted");
        assert_eq!(
            cli(&h.0, "alice", &cli_args(&["list"])).unwrap()["read_only"],
            true
        );
        assert_eq!(
            cli(&h.0, "", &cli_args(&["--help"])).unwrap()["signer_opened"],
            false
        );
        assert_eq!(public_files(&h.0), before);
    }
    #[test]
    fn friendly_parse_and_missing_signer_never_create_identity_state() {
        let scratch = std::env::temp_dir().join(format!(
            "ans-owner-parse-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&scratch).unwrap();
        let root = scratch.join("not-created");
        let valid = scratch.join("valid.json");
        std::fs::write(&valid, crystal("a", true).to_string()).unwrap();
        let invalid = scratch.join("invalid.json");
        std::fs::write(&invalid, "not a crystal").unwrap();
        let missing = scratch.join("missing.json");
        assert!(cli(&root, "", &cli_args(&["draft", valid.to_str().unwrap()])).is_err());
        for path in [&valid, &invalid, &missing, &scratch] {
            assert!(cli(
                &root,
                "alice",
                &cli_args(&["draft", path.to_str().unwrap()])
            )
            .is_err());
            assert!(!root.exists());
        }
        let too_large = scratch.join("large.json");
        std::fs::File::create(&too_large)
            .unwrap()
            .set_len(8 * 1024 * 1024 + 1)
            .unwrap();
        assert!(cli(
            &root,
            "alice",
            &cli_args(&["draft", too_large.to_str().unwrap()])
        )
        .is_err());
        for args in [
            vec!["mint"],
            vec!["mint", "../secret"],
            vec!["mint", "a", "--other", "value"],
            vec!["mint", "a", "--operation-id"],
            vec!["mint", "a", "--operation-id", ""],
        ] {
            assert!(cli(&root, "alice", &cli_args(&args)).is_err());
            assert!(!root.exists());
        }
        assert_eq!(
            cli(&root, "", &cli_args(&["--help"])).unwrap()["signer_opened"],
            false
        );
        assert!(!root.exists());
        std::fs::remove_dir_all(scratch).unwrap();
    }
    #[test]
    fn auto_operation_ids_are_unique_and_explicit_ids_are_stable() {
        let mut ids = std::collections::BTreeSet::new();
        for _ in 0..256 {
            let id = operation_id(None).unwrap();
            assert_eq!(id.0.len(), 36);
            assert!(ids.insert(id.0));
        }
        assert_eq!(operation_id(Some("retry-this")).unwrap().0, "retry-this");
        assert!(operation_id(Some("")).is_err());
        assert!(operation_id(Some(&"x".repeat(129))).is_err());
    }
    #[test]
    fn interrupted_retry_recovery_regressions() {
        for case in ["accepted", "rejected", "conflict"] {
            let h = Home::new();
            let c = crystal("a", true);
            let r = root(&c);
            let original_command = if case == "rejected" {
                Command::Inspect { root: r.clone() }
            } else {
                h.apply("draft", draft(c.clone()));
                h.apply("validate", Command::Validate { root: r.clone() });
                Command::Mint { root: r.clone() }
            };
            let original = h.apply("original", original_command.clone());
            if case == "rejected" {
                // The old rejection must remain rejected even though a fresh inspect
                // would now succeed after the entry is created and minted.
                h.apply("later-draft", draft(c));
                h.apply("later-validate", Command::Validate { root: r.clone() });
                h.apply("later-mint", Command::Mint { root: r.clone() });
            }

            let retry_command = if case == "conflict" {
                Command::Inspect { root: r.clone() }
            } else {
                original_command
            };
            let request = Request {
                op_id: OperationId("original".into()),
                command: retry_command,
            };
            let digest = hash(&serde_json::to_value(&request.command).unwrap()).unwrap();
            let intent = append(
                "alice",
                &h.0.join("custodians/alice"),
                "dictionary.intent",
                json!({"request":request,"command_digest":digest,"canonical":false}),
            )
            .unwrap();
            let before = h
                .journal()
                .iter()
                .filter(|e| action(e) == "word.mint")
                .count();
            let target = "a".to_string();
            let binary = std::env::var("ANS_RECOVERY_SMOKE_BINARY").ok();
            let result = if let Some(binary) = binary.as_ref() {
                let output = std::process::Command::new(binary)
                    .args([
                        "--data",
                        h.0.to_str().unwrap(),
                        "--as",
                        "alice",
                        "dictionary",
                        "inspect",
                        &target,
                        "--operation-id",
                        "after-crash",
                    ])
                    .output()
                    .unwrap();
                if output.status.success() {
                    serde_json::from_slice::<Value>(&output.stdout).map_err(anyhow::Error::from)
                } else {
                    Err(anyhow!(String::from_utf8_lossy(&output.stderr).into_owned()))
                }
            } else {
                cli(
                    &h.0,
                    "alice",
                    &[
                        "inspect".into(),
                        target,
                        "--operation-id".into(),
                        "after-crash".into(),
                    ],
                )
            };
            let events = h.journal();
            let recovered = events
                .iter()
                .find(|e| {
                    action(e) == "dictionary.outcome" && data(e)["intent_hash"] == intent["hash"]
                })
                .unwrap();
            println!(
                "RECOVERY_EVIDENCE {}",
                json!({"case":case,"surface":if binary.is_some(){"external_cli"}else{"in_process_cli"},"original_status":original["receipt"]["status"],"recovered_status":data(recovered)["receipt"]["status"],"error":result.as_ref().err().map(ToString::to_string),"native_mints_before":before,"native_mints_after":events.iter().filter(|e|action(e)=="word.mint").count()})
            );
            assert!(
                result.is_ok(),
                "Recovered retry must not poison strict replay: {result:?}"
            );
            let expected = if case == "conflict" {
                "rejected"
            } else {
                original["receipt"]["status"].as_str().unwrap()
            };
            assert_eq!(data(recovered)["receipt"]["status"], expected);
            if case != "conflict" {
                assert_eq!(data(recovered)["receipt"], original["receipt"]);
            }
            assert_eq!(
                events.iter().filter(|e| action(e) == "word.mint").count(),
                before
            );
            assert!(crate::dictionary_read::replay_verified(&events).is_ok());
        }
    }
    #[test]
    fn interrupted_intent_is_closed_without_resuming_effect() {
        let h = Home::new();
        let req = Request {
            op_id: OperationId("crashed".into()),
            command: draft(crystal("a", true)),
        };
        let digest = hash(&serde_json::to_value(&req.command).unwrap()).unwrap();
        append(
            "alice",
            &h.0.join("custodians/alice"),
            "dictionary.intent",
            json!({"request":req,"command_digest":digest,"canonical":true}),
        )
        .unwrap();
        let retry = apply(&h.0, "alice", req).unwrap();
        assert_eq!(status(&retry), "interrupted");
        assert!(!h.journal().iter().any(|e| action(e) == "word.mint"));
        assert!(replay(&h.journal()).unwrap().is_empty());
        assert_eq!(
            h.journal()
                .iter()
                .filter(|e| action(e) == "dictionary.outcome")
                .count(),
            2
        );
    }
    #[test]
    fn interrupted_native_mint_is_not_repeated_or_declared_successful() {
        // Durable word.mint for the same op_id before outcome must complete once on recovery
        // (accepted lifecycle), never invent a second native mint, and foreign op_ids still refuse.
        let h = Home::new();
        let c = crystal("a", true);
        let r = root(&c);
        h.apply("draft", draft(c));
        h.apply("validate", Command::Validate { root: r.clone() });
        let req = Request {
            op_id: OperationId("mint-crash".into()),
            command: Command::Mint { root: r.clone() },
        };
        let digest = hash(&serde_json::to_value(&req.command).unwrap()).unwrap();
        let dir = h.0.join("custodians/alice");
        append(
            "alice",
            &dir,
            "dictionary.intent",
            json!({"request":req,"command_digest":digest,"canonical":true}),
        )
        .unwrap();
        append(
            "alice",
            &dir,
            "word.mint",
            json!({
                "word":"a",
                "root":r.0,
                "file":"u0061.crystal.json",
                "layer":1,
                "letters":[],
                "op_id":"mint-crash",
                "service":"dictionary",
                "chain":"local test journal; not mainnet"
            }),
        )
        .unwrap();
        let recovered = apply(&h.0, "alice", req).unwrap();
        assert_eq!(status(&recovered), "accepted");
        assert_eq!(recovered["receipt"]["entry"]["state"], "minted");
        assert_eq!(
            status(&h.apply("new-mint", Command::Mint { root: r })),
            "rejected"
        );
        assert_eq!(
            h.journal()
                .iter()
                .filter(|e| action(e) == "word.mint")
                .count(),
            1
        );
    }
    #[test]
    fn replay_refuses_cache_identity_and_schema_tamper() {
        let h = Home::new();
        let c: Value =
            serde_json::from_str(include_str!("../assets/crystals/u0072.crystal.json")).unwrap();
        let r = root(&c);
        h.apply("draft", draft(c.clone()));
        h.apply("validate", Command::Validate { root: r.clone() });
        h.apply("mint", Command::Mint { root: r.clone() });
        let cache = h.0.join("book/u0072.crystal.json");
        for (i, schema_tamper) in [false, true].into_iter().enumerate() {
            let mut damaged = c.clone();
            if schema_tamper {
                damaged["schema"] = json!(ans_dict::WORD_SCHEMA);
                damaged["word"] = json!("r");
            } else {
                damaged["character"] = json!("x");
            }
            std::fs::write(&cache, damaged.to_string()).unwrap();
            let result = h.apply(
                &format!("corrupt-{i}"),
                Command::Inspect { root: r.clone() },
            );
            assert_eq!(status(&result), "rejected");
            assert!(crate::exploit::event_valid(&result["outcome"]));
            assert!(Book::open(&h.0.join("book")).unwrap().list().is_err());
            assert_eq!(
                std::fs::read_to_string(&cache).unwrap(),
                damaged.to_string()
            );
        }
    }
    #[test]
    fn native_mint_and_outcome_match_kernel_payload_and_reject_tamper() {
        use base64::Engine;
        let h = Home::new();
        let c = crystal("a", true);
        let r = root(&c);
        h.apply("draft", draft(c));
        h.apply("validate", Command::Validate { root: r.clone() });
        let result = h.apply("mint", Command::Mint { root: r.clone() });
        let journal = h.journal();
        let native = journal.iter().find(|e| action(e) == "word.mint").unwrap();
        assert_eq!(data(native)["root"], r.0);
        assert_eq!(data(native)["op_id"], "mint");
        assert_eq!(
            result["outcome"]["body"]["data"]["receipt"]["entry"]["root"],
            r.0
        );
        let db = popchain_cli::chain::Db::open(&h.0.join("custodians/alice/kernel")).unwrap();
        assert_eq!(db.read_state().unwrap().best_height as usize, journal.len());
        for e in [native, &result["outcome"]] {
            assert!(crate::exploit::event_valid(e));
            assert_eq!(e["xmss"]["scheme"], "XMSSMT-SHA2_20/2_256 (WOTS+)");
            let b = db.read_block_by_height(e["seq"].as_u64().unwrap()).unwrap();
            db.verify_block(&b).unwrap();
            let payload = &b.app_events[0];
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(&payload.payload_b64)
                .unwrap();
            assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), *e);
            assert_eq!(
                payload.payload_sha256_hex,
                hex::encode(sha2::Sha256::digest(&bytes))
            );
            let mut bad = e.clone();
            bad["body"]["data"]["forged"] = json!(true);
            assert!(!crate::exploit::event_valid(&bad));
            let mut unsigned = e.clone();
            unsigned.as_object_mut().unwrap().remove("xmss");
            assert!(!crate::exploit::event_valid(&unsigned));
            let mut bad_block = b.clone();
            bad_block.app_events[0].payload_b64 = "dGFtcGVy".into();
            assert!(db.verify_block(&bad_block).is_err());
        }
    }
    #[test]
    fn signed_outcome_without_bound_intent_is_not_authority() {
        let h = Home::new();
        append("alice", &h.0.join("custodians/alice"), "dictionary.outcome", json!({
            "intent_hash":"absent", "op_id":"forged-link", "canonical":true,
            "command_digest":"absent", "receipt":{"status":"accepted","reason":null,"entry":null}
        })).unwrap();
        let before = h.journal().len();
        assert!(apply(
            &h.0,
            "alice",
            Request {
                op_id: OperationId("inspect".into()),
                command: Command::Inspect {
                    root: ContentRoot("00".repeat(32))
                }
            }
        )
        .unwrap_err()
        .to_string()
        .contains("bound intent"));
        assert_eq!(h.journal().len(), before);
    }
    #[test]
    fn authored_write_cli_drafts_only_and_keeps_identity_rules() {
        let h = Home::new();
        let ch = cli(
            &h.0,
            "alice",
            &cli_args(&[
                "write",
                "character",
                "d",
                "--license",
                "CC0-1.0",
                "--source",
                "local-test",
                "--attribution",
                "test",
                "--operation-id",
                "char-d",
            ]),
        )
        .unwrap();
        assert_eq!(status(&ch), "accepted");
        assert_eq!(ch["receipt"]["entry"]["state"], "draft");
        assert_eq!(ch["authored"]["kind"], "character");
        assert_eq!(ch["authored"]["rights_claim"], "not validated");
        assert_eq!(ch["authored"]["semantic_understanding"], false);
        let root_d = ch["authored"]["root"].as_str().unwrap().to_owned();
        assert_eq!(
            status(
                &cli(
                    &h.0,
                    "alice",
                    &cli_args(&["validate", "d", "--operation-id", "char-d-validate"])
                )
                .unwrap()
            ),
            "accepted"
        );
        assert_eq!(
            status(
                &cli(
                    &h.0,
                    "alice",
                    &cli_args(&["mint", "d", "--operation-id", "char-d-mint"])
                )
                .unwrap()
            ),
            "accepted"
        );
        for (ch, id) in [("o", "char-o"), ("m", "char-m")] {
            assert_eq!(
                status(
                    &cli(
                        &h.0,
                        "alice",
                        &cli_args(&[
                            "write",
                            "character",
                            ch,
                            "--unverified",
                            "--operation-id",
                            id
                        ])
                    )
                    .unwrap()
                ),
                "accepted"
            );
            assert_eq!(
                status(
                    &cli(
                        &h.0,
                        "alice",
                        &cli_args(&["validate", ch, "--operation-id", &format!("{id}-v")])
                    )
                    .unwrap()
                ),
                "accepted"
            );
            assert_eq!(
                status(
                    &cli(
                        &h.0,
                        "alice",
                        &cli_args(&["mint", ch, "--operation-id", &format!("{id}-m")])
                    )
                    .unwrap()
                ),
                "accepted"
            );
        }
        let early = cli(
            &h.0,
            "alice",
            &cli_args(&[
                "write",
                "word",
                "dom",
                "--lang",
                "pl",
                "--meaning",
                "house",
                "--license",
                "CC0-1.0",
                "--source",
                "local-test",
                "--operation-id",
                "word-dom",
            ]),
        )
        .unwrap();
        assert_eq!(status(&early), "accepted");
        assert_eq!(early["receipt"]["entry"]["state"], "draft");
        assert_eq!(early["authored"]["character_references_bound"], false);
        let word_root = early["authored"]["root"].as_str().unwrap().to_owned();
        assert_ne!(word_root, root_d);
        assert_eq!(
            status(
                &cli(
                    &h.0,
                    "alice",
                    &cli_args(&["validate", "dom", "--operation-id", "word-dom-validate"])
                )
                .unwrap()
            ),
            "accepted"
        );
        // Before this unit only d/o/m were minted; minting the word must succeed now.
        let minted = cli(
            &h.0,
            "alice",
            &cli_args(&["mint", "dom", "--operation-id", "word-dom-mint"]),
        )
        .unwrap();
        assert_eq!(status(&minted), "accepted");
        assert_eq!(minted["receipt"]["entry"]["state"], "minted");
        let retry = cli(
            &h.0,
            "alice",
            &cli_args(&["mint", "dom", "--operation-id", "word-dom-mint"]),
        )
        .unwrap();
        assert_eq!(retry["retry"], true);
        assert_eq!(retry["receipt"], minted["receipt"]);
        let conflict = cli(
            &h.0,
            "alice",
            &cli_args(&["inspect", "dom", "--operation-id", "word-dom-mint"]),
        )
        .unwrap();
        assert_eq!(status(&conflict), "rejected");
        // Lifecycle WordId is language-scoped, but crystal cache filenames are spelling-fold
        // only. A second language with the same folded spelling must refuse, not overwrite.
        let same_spelling_other_lang = cli(
            &h.0,
            "alice",
            &cli_args(&[
                "write",
                "word",
                "dom",
                "--lang",
                "en",
                "--meaning",
                "house",
                "--unverified",
                "--operation-id",
                "word-dom-en",
            ]),
        )
        .unwrap();
        assert_eq!(status(&same_spelling_other_lang), "rejected");
        assert!(same_spelling_other_lang["receipt"]["reason"]
            .as_str()
            .unwrap_or("")
            .contains("refusing to overwrite")
            || same_spelling_other_lang["receipt"]["reason"]
                .as_str()
                .unwrap_or("")
                .contains("immutable root")
            || same_spelling_other_lang["receipt"]["reason"]
                .as_str()
                .unwrap_or("")
                .contains("mismatch"));
        // Distinct spelling in another language is admitted as its own WordId/root.
        let en = cli(
            &h.0,
            "alice",
            &cli_args(&[
                "write",
                "word",
                "oak",
                "--lang",
                "en",
                "--meaning",
                "a tree",
                "--unverified",
                "--operation-id",
                "word-oak-en",
            ]),
        )
        .unwrap();
        assert_eq!(status(&en), "accepted");
        assert_ne!(en["authored"]["root"], early["authored"]["root"]);
        assert_eq!(en["receipt"]["entry"]["word"]["language"], "en");
        // Same language+spelling collision refuses revision.
        assert_eq!(
            status(
                &cli(
                    &h.0,
                    "alice",
                    &cli_args(&[
                        "write",
                        "word",
                        "dom",
                        "--lang",
                        "pl",
                        "--meaning",
                        "home",
                        "--unverified",
                        "--operation-id",
                        "word-dom-rev"
                    ])
                )
                .unwrap()
            ),
            "rejected"
        );
        // Missing required characters reject word mint.
        let kot = cli(
            &h.0,
            "alice",
            &cli_args(&[
                "write",
                "word",
                "kot",
                "--lang",
                "pl",
                "--meaning",
                "cat",
                "--unverified",
                "--operation-id",
                "word-kot",
            ]),
        )
        .unwrap();
        assert_eq!(status(&kot), "accepted");
        assert_eq!(
            status(
                &cli(
                    &h.0,
                    "alice",
                    &cli_args(&["validate", "kot", "--operation-id", "word-kot-v"])
                )
                .unwrap()
            ),
            "accepted"
        );
        let missing = cli(
            &h.0,
            "alice",
            &cli_args(&["mint", "kot", "--operation-id", "word-kot-m"]),
        )
        .unwrap();
        assert_eq!(status(&missing), "rejected");
        assert!(missing["receipt"]["reason"]
            .as_str()
            .unwrap()
            .contains("not minted"));
        // Changing committed meaning changes root (fresh identity spelling).
        let other = ans_dict::author::word(
            "kot",
            "pl",
            "cat",
            &ans_dict::author::Provenance::unverified(),
        )
        .unwrap();
        let changed = ans_dict::author::word(
            "kot",
            "pl",
            "feline",
            &ans_dict::author::Provenance::unverified(),
        )
        .unwrap();
        assert_ne!(other.root, changed.root);
        assert!(cli(
            &h.0,
            "alice",
            &cli_args(&["write", "character", "", "--unverified"])
        )
        .is_err());
        assert!(cli(
            &h.0,
            "alice",
            &cli_args(&["write", "word", "x", "--lang", "pl", "--meaning", "y"])
        )
        .is_err());
        assert!(cli(&h.0, "", &cli_args(&["write", "character", "z", "--unverified"])).is_err());
        let before = h.journal().len();
        assert!(cli(
            &h.0,
            "alice",
            &cli_args(&["write", "word", " bad", "--lang", "pl", "--meaning", "x", "--unverified"])
        )
        .is_err());
        assert_eq!(h.journal().len(), before);
        // Drafts cannot execute.
        assert_eq!(
            status(&h.apply(
                "run-authored",
                Command::Run {
                    root: ContentRoot(word_root)
                }
            )),
            "rejected"
        );
        let mints = h
            .journal()
            .iter()
            .filter(|e| action(e) == "word.mint")
            .count();
        assert_eq!(mints, 4);
    }
    #[test]
    fn legacy_mint_cli_adopts_dictionary_lifecycle_without_double_native_mint() {
        let h = Home::new();
        let letter = crystal("q", true);
        let book = Book::open(&h.0.join("book")).unwrap();
        let c = Crystal::parse(&letter.to_string()).unwrap();
        book.add(&c).unwrap();
        let first_wrap = crate::words::handle(
            "mint",
            &cli_args(&["mint", "q"]),
            &h.0,
            "alice",
        )
        .unwrap()
        .unwrap();
        assert_eq!(first_wrap["service"], "dictionary");
        assert_eq!(first_wrap["lifecycle_adapter"], "adopt_book_crystal");
        let first = &first_wrap["minted"][0];
        assert_eq!(first["lifecycle"], "minted");
        assert_eq!(first["already"], false);
        assert_eq!(first["service"], "dictionary");
        let root = first["root"].as_str().unwrap().to_owned();
        let journal = h.journal();
        assert_eq!(
            journal
                .iter()
                .filter(|e| action(e) == "word.mint")
                .count(),
            1
        );
        assert!(journal.iter().any(|e| action(e) == "dictionary.intent"));
        assert!(journal.iter().any(|e| action(e) == "dictionary.outcome"));
        let again_wrap = crate::words::handle(
            "mint",
            &cli_args(&["mint", "q"]),
            &h.0,
            "alice",
        )
        .unwrap()
        .unwrap();
        let again = &again_wrap["minted"][0];
        assert_eq!(again["already"], true);
        assert_eq!(again["lifecycle"], "minted");
        assert_eq!(
            h.journal()
                .iter()
                .filter(|e| action(e) == "word.mint")
                .count(),
            1
        );
        let shown = crate::dictionary_read::show(&h.0, "alice", &root, None).unwrap();
        assert_eq!(shown.lifecycle, Some(State::Minted));
        // Word crystal without minted letter dependencies is rejected.
        let leaves = vec![
            ans_dict::Leaf::new(&[
                ("kind", "identity"),
                ("lang", "en"),
                ("value", "xz"),
                ("schema", ans_dict::WORD_SCHEMA),
            ]),
            ans_dict::Leaf::new(&[
                ("kind", "sense"),
                ("lang", "en"),
                ("sense", "en-1"),
                ("value", "test"),
                ("source", "fixture"),
            ]),
        ];
        let word = Crystal::build(
            CrystalKind::Word,
            "xz",
            leaves,
            Default::default(),
        )
        .unwrap();
        book.add(&word).unwrap();
        let refused = crate::words::handle(
            "mint",
            &cli_args(&["mint", "xz"]),
            &h.0,
            "alice",
        )
        .unwrap()
        .unwrap();
        let reason = refused["minted"][0]["refused"].as_str().unwrap_or("");
        assert!(
            reason.contains("not minted") || reason.contains("refused"),
            "{refused}"
        );
        assert_eq!(
            h.journal()
                .iter()
                .filter(|e| action(e) == "word.mint")
                .count(),
            1
        );
        // Bare legacy native mint without lifecycle is not auto-promoted.
        let orphan = crystal("z", true);
        let oc = Crystal::parse(&orphan.to_string()).unwrap();
        book.add(&oc).unwrap();
        crate::exploit::record_local(
            "alice",
            &h.0.join("custodians/alice"),
            "word.mint",
            json!({
                "word": oc.id,
                "root": oc.root,
                "file": oc.file_name(),
                "layer": 1,
                "letters": [],
                "chain": "legacy fixture"
            }),
        )
        .unwrap();
        let legacy_only = crate::dictionary::adopt_book_crystal(&h.0, "alice", &oc).unwrap();
        assert_eq!(legacy_only["legacy_native_only"], true);
        assert_eq!(legacy_only["refused_auto_reconcile"], true);
        assert_eq!(legacy_only["lifecycle"], Value::Null);
    }
    #[test]
    fn mint_recovers_when_native_effect_durable_before_outcome() {
        let h = Home::new();
        let c = crystal("w", true);
        let r = root(&c);
        assert_eq!(status(&h.apply("d", draft(c.clone()))), "accepted");
        assert_eq!(status(&h.apply("v", Command::Validate { root: r.clone() })), "accepted");
        // Sign mint intent only, then native mint, skip outcome (simulate crash boundary).
        let dir = h.0.join("custodians/alice");
        let req = Request {
            op_id: OperationId("crash-mint".into()),
            command: Command::Mint { root: r.clone() },
        };
        let digest = hash(&serde_json::to_value(&req.command).unwrap()).unwrap();
        let intent = append(
            "alice",
            &dir,
            "dictionary.intent",
            json!({"request":req,"command_digest":digest,"canonical":true}),
        )
        .unwrap();
        let native = append(
            "alice",
            &dir,
            "word.mint",
            json!({
                "word":"w",
                "root":r.0,
                "file":"u0077.crystal.json",
                "layer":1,
                "letters":[],
                "op_id":"crash-mint",
                "service":"dictionary",
                "chain":"local test journal; not mainnet"
            }),
        )
        .unwrap();
        assert!(intent["seq"].as_u64().unwrap() < native["seq"].as_u64().unwrap());
        let before_mints = h
            .journal()
            .iter()
            .filter(|e| action(e) == "word.mint")
            .count();
        assert_eq!(before_mints, 1);
        // Recovery on next admission must accept without a second native mint.
        let recovered = h.apply("crash-mint", Command::Mint { root: r.clone() });
        assert_eq!(status(&recovered), "accepted");
        assert_eq!(recovered["receipt"]["entry"]["state"], "minted");
        assert!(recovered["receipt"]["reason"]
            .as_str()
            .unwrap_or("")
            .contains("Recovered"));
        assert_eq!(
            h.journal()
                .iter()
                .filter(|e| action(e) == "word.mint")
                .count(),
            1
        );
        let shown = crate::dictionary_read::show(&h.0, "alice", &r.0, None).unwrap();
        assert_eq!(shown.lifecycle, Some(State::Minted));
        // Exact retry still returns one mint.
        let retry = h.apply("crash-mint", Command::Mint { root: r });
        assert_eq!(retry["retry"], true);
        assert_eq!(
            h.journal()
                .iter()
                .filter(|e| action(e) == "word.mint")
                .count(),
            1
        );
    }
    #[test]
    fn mint_crash_after_intent_before_native_stays_interrupted_not_guessed() {
        let h = Home::new();
        let c = crystal("v", true);
        let r = root(&c);
        assert_eq!(status(&h.apply("d", draft(c))), "accepted");
        assert_eq!(status(&h.apply("v", Command::Validate { root: r.clone() })), "accepted");
        let dir = h.0.join("custodians/alice");
        let req = Request {
            op_id: OperationId("intent-only".into()),
            command: Command::Mint { root: r.clone() },
        };
        let digest = hash(&serde_json::to_value(&req.command).unwrap()).unwrap();
        append(
            "alice",
            &dir,
            "dictionary.intent",
            json!({"request":req,"command_digest":digest,"canonical":true}),
        )
        .unwrap();
        let recovered = h.apply("intent-only", Command::Mint { root: r.clone() });
        // First call recovers pending as Interrupted (no native effect), then may proceed as retry?
        // After Interrupted canonical outcome exists, same op_id retry returns Interrupted receipt.
        assert_eq!(status(&recovered), "interrupted");
        assert_eq!(
            h.journal()
                .iter()
                .filter(|e| action(e) == "word.mint")
                .count(),
            0
        );
        // A new operation id can still mint successfully.
        let minted = h.apply("intent-only-2", Command::Mint { root: r });
        assert_eq!(status(&minted), "accepted");
        assert_eq!(
            h.journal()
                .iter()
                .filter(|e| action(e) == "word.mint")
                .count(),
            1
        );
    }
    #[test]
    fn concurrent_dictionary_lock_rejects_second_writer() {
        let h = Home::new();
        let c = crystal("u", true);
        assert_eq!(status(&h.apply("d", draft(c.clone()))), "accepted");
        let dir = h.0.join("custodians/alice");
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(dir.join("dictionary.lock"))
            .unwrap();
        fs4::FileExt::try_lock_exclusive(&lock).unwrap();
        let err = apply(
            &h.0,
            "alice",
            Request {
                op_id: OperationId("busy".into()),
                command: Command::Validate {
                    root: root(&c),
                },
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("busy"), "{err}");
        drop(lock);
    }
    #[test]
    fn mixed_legacy_writer_refused_while_dictionary_mint_pending() {
        // Crash window: durable intent+native mint, no outcome yet. Legacy delegate must not
        // interleave; recovery then completes contiguous outcome without a second native mint.
        let h = Home::new();
        let c = crystal("z", true);
        let r = root(&c);
        assert_eq!(status(&h.apply("d", draft(c.clone()))), "accepted");
        assert_eq!(
            status(&h.apply("v", Command::Validate { root: r.clone() })),
            "accepted"
        );
        let dir = h.0.join("custodians/alice");
        let req = Request {
            op_id: OperationId("native-gap".into()),
            command: Command::Mint { root: r.clone() },
        };
        let digest = hash(&serde_json::to_value(&req.command).unwrap()).unwrap();
        append(
            "alice",
            &dir,
            "dictionary.intent",
            json!({"request":req,"command_digest":digest,"canonical":true}),
        )
        .unwrap();
        append(
            "alice",
            &dir,
            "word.mint",
            json!({
                "word":"z",
                "root":r.0,
                "file":"u007a.crystal.json",
                "layer":1,
                "letters":[],
                "op_id":"native-gap",
                "service":"dictionary",
                "chain":"local test journal; not mainnet"
            }),
        )
        .unwrap();
        // Non-dictionary signed writes cannot interleave with the pending mint.
        let blocked = crate::exploit::record_local("alice", &dir, "contact.add", json!({"word":"bob.ans"}))
            .unwrap_err()
            .to_string();
        assert!(
            blocked.contains("incomplete") || blocked.contains("Dictionary operation"),
            "{blocked}"
        );
        // Legacy delegate is now a dictionary operation itself; it never writes before recovery.
        assert!(crate::exploit::record_local("alice", &dir, "word.delegate", json!({"root":r.0,"scope":"review-only-scope"})).is_err());
        assert!(!h
            .journal()
            .iter()
            .any(|e| action(e) == "word.delegate"));
        let recovered = h.apply("native-gap", Command::Mint { root: r.clone() });
        assert_eq!(status(&recovered), "accepted");
        assert_eq!(recovered["receipt"]["entry"]["state"], "minted");
        assert_eq!(
            h.journal()
                .iter()
                .filter(|e| action(e) == "word.mint")
                .count(),
            1
        );
        let shown = crate::dictionary_read::show(&h.0, "alice", &r.0, None).unwrap();
        assert_eq!(shown.lifecycle, Some(State::Minted));
        let delegated = crate::words::handle(
            "delegate",
            &cli_args(&["delegate", "z", "review-only-scope"]),
            &h.0,
            "alice",
        )
        .unwrap()
        .unwrap();
        assert_eq!(delegated["ok"], true);
        let journal = h.journal();
        let mint_idx = journal
            .iter()
            .position(|e| action(e) == "word.mint" && data(e)["op_id"] == "native-gap")
            .unwrap();
        assert_eq!(action(&journal[mint_idx - 1]), "dictionary.intent");
        assert_eq!(action(&journal[mint_idx + 1]), "dictionary.outcome");
        assert!(crate::dictionary_read::replay_verified(&journal).is_ok());
    }
    #[test]
    fn legacy_draft_retries_after_interrupted_attempt() {
        // Interrupted legacy-draft-ROOT must not stick forever; convenience mint opens a new attempt.
        let h = Home::new();
        let c = crystal("p", true);
        let r = root(&c);
        let parsed = Crystal::parse(&c.to_string()).unwrap();
        Book::open(&h.0.join("book")).unwrap().add(&parsed).unwrap();
        let dir = h.0.join("custodians/alice");
        let req = Request {
            op_id: OperationId(format!("legacy-draft-{}", r.0)),
            command: draft(c.clone()),
        };
        let digest = hash(&serde_json::to_value(&req.command).unwrap()).unwrap();
        append(
            "alice",
            &dir,
            "dictionary.intent",
            json!({"request":req,"command_digest":digest,"canonical":true}),
        )
        .unwrap();
        let wrap = crate::words::handle(
            "mint",
            &cli_args(&["mint", "p"]),
            &h.0,
            "alice",
        )
        .unwrap()
        .unwrap();
        assert_eq!(wrap["minted"][0]["lifecycle"], "minted", "{wrap}");
        let journal = h.journal();
        assert!(journal.iter().any(|e| {
            action(e) == "dictionary.outcome"
                && data(e)["op_id"] == format!("legacy-draft-{}", r.0)
                && data(e)["receipt"]["status"] == "interrupted"
        }));
        assert!(journal.iter().any(|e| {
            action(e) == "dictionary.outcome"
                && data(e)["receipt"]["status"] == "accepted"
                && data(e)["op_id"]
                    .as_str()
                    .unwrap_or("")
                    .starts_with(&format!("legacy-draft-{}-retry-", r.0))
        }));
        assert_eq!(
            journal
                .iter()
                .filter(|e| action(e) == "word.mint")
                .count(),
            1
        );
        assert!(crate::dictionary_read::replay_verified(&journal).is_ok());
    }
    #[test]
    fn legacy_validate_retries_after_interrupted_attempt() {
        // Interrupted legacy-validate-ROOT must open attempt-scoped retry, then mint once.
        let h = Home::new();
        let c = crystal("q", true);
        let r = root(&c);
        let parsed = Crystal::parse(&c.to_string()).unwrap();
        Book::open(&h.0.join("book")).unwrap().add(&parsed).unwrap();
        assert_eq!(
            status(&h.apply(
                &format!("legacy-draft-{}", r.0),
                draft(c.clone())
            )),
            "accepted"
        );
        let dir = h.0.join("custodians/alice");
        let req = Request {
            op_id: OperationId(format!("legacy-validate-{}", r.0)),
            command: Command::Validate { root: r.clone() },
        };
        let digest = hash(&serde_json::to_value(&req.command).unwrap()).unwrap();
        append(
            "alice",
            &dir,
            "dictionary.intent",
            json!({"request":req,"command_digest":digest,"canonical":true}),
        )
        .unwrap();
        let wrap = crate::words::handle(
            "mint",
            &cli_args(&["mint", "q"]),
            &h.0,
            "alice",
        )
        .unwrap()
        .unwrap();
        assert_eq!(wrap["minted"][0]["lifecycle"], "minted", "{wrap}");
        let journal = h.journal();
        assert!(journal.iter().any(|e| {
            action(e) == "dictionary.outcome"
                && data(e)["op_id"] == format!("legacy-validate-{}", r.0)
                && data(e)["receipt"]["status"] == "interrupted"
        }));
        assert!(journal.iter().any(|e| {
            action(e) == "dictionary.outcome"
                && data(e)["receipt"]["status"] == "accepted"
                && data(e)["op_id"]
                    .as_str()
                    .unwrap_or("")
                    .starts_with(&format!("legacy-validate-{}-retry-", r.0))
        }));
        assert_eq!(
            journal
                .iter()
                .filter(|e| action(e) == "word.mint")
                .count(),
            1
        );
        let again = crate::words::handle(
            "mint",
            &cli_args(&["mint", "q"]),
            &h.0,
            "alice",
        )
        .unwrap()
        .unwrap();
        assert_eq!(again["minted"][0]["already"], true);
        assert_eq!(
            h.journal()
                .iter()
                .filter(|e| action(e) == "word.mint")
                .count(),
            1
        );
        assert!(crate::dictionary_read::replay_verified(&h.journal()).is_ok());
    }
    #[test]
    fn online_exploit_record_refused_while_dictionary_mint_pending() {
        // Online serve/api uses Exploit::record directly (not only record_local). Pending
        // dictionary mint must refuse foreign appends at that common choke point too.
        let h = Home::new();
        let c = crystal("y", true);
        let r = root(&c);
        assert_eq!(status(&h.apply("d", draft(c.clone()))), "accepted");
        assert_eq!(
            status(&h.apply("v", Command::Validate { root: r.clone() })),
            "accepted"
        );
        let dir = h.0.join("custodians/alice");
        let req = Request {
            op_id: OperationId("online-gap".into()),
            command: Command::Mint { root: r.clone() },
        };
        let digest = hash(&serde_json::to_value(&req.command).unwrap()).unwrap();
        append(
            "alice",
            &dir,
            "dictionary.intent",
            json!({"request":req,"command_digest":digest,"canonical":true}),
        )
        .unwrap();
        append(
            "alice",
            &dir,
            "word.mint",
            json!({
                "word":"y",
                "root":r.0,
                "file":"u0079.crystal.json",
                "layer":1,
                "letters":[],
                "op_id":"online-gap",
                "service":"dictionary",
                "chain":"local test journal; not mainnet"
            }),
        )
        .unwrap();
        let before = h.journal().len();
        for (action_name, payload) in [
            (
                "contact.add",
                json!({"word":"bob"}),
            ),
            (
                "custodian.login",
                json!({"local_demo":true}),
            ),
            (
                "skill.list",
                json!({"count":0}),
            ),
        ] {
            let err = crate::exploit::record_online_style("alice", &dir, action_name, payload)
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("incomplete") || err.contains("Dictionary operation"),
                "{action_name}: {err}"
            );
        }
        assert_eq!(h.journal().len(), before);
        // Dictionary recovery must still proceed through the same choke point.
        let recovered = h.apply("online-gap", Command::Mint { root: r.clone() });
        assert_eq!(status(&recovered), "accepted");
        assert_eq!(recovered["receipt"]["entry"]["state"], "minted");
        assert_eq!(
            h.journal()
                .iter()
                .filter(|e| action(e) == "word.mint")
                .count(),
            1
        );
        // After outcome, online-style foreign mutation is admitted again.
        crate::exploit::record_online_style(
            "alice",
            &dir,
            "contact.add",
            json!({"word":"bob"}),
        )
        .unwrap();
        assert!(h
            .journal()
            .iter()
            .any(|e| action(e) == "contact.add"));
        let journal = h.journal();
        let mint_idx = journal
            .iter()
            .position(|e| action(e) == "word.mint" && data(e)["op_id"] == "online-gap")
            .unwrap();
        assert_eq!(action(&journal[mint_idx - 1]), "dictionary.intent");
        assert_eq!(action(&journal[mint_idx + 1]), "dictionary.outcome");
        assert!(crate::dictionary_read::replay_verified(&journal).is_ok());
    }
    #[test]
    fn legacy_mint_gets_new_attempt_after_dependency_rejection() {
        // Deterministic legacy-mint-ROOT must stay idempotent for exact retries, but after a
        // rejected attempt the convenience CLI must open a new attempt once dependencies exist.
        let h = Home::new();
        let book = Book::open(&h.0.join("book")).unwrap();
        let leaves = vec![
            ans_dict::Leaf::new(&[
                ("kind", "identity"),
                ("lang", "en"),
                ("value", "xy"),
                ("schema", ans_dict::WORD_SCHEMA),
            ]),
            ans_dict::Leaf::new(&[
                ("kind", "sense"),
                ("lang", "en"),
                ("sense", "en-1"),
                ("value", "fixture gloss"),
                ("source", "fixture"),
            ]),
        ];
        let word = Crystal::build(CrystalKind::Word, "xy", leaves, Default::default()).unwrap();
        book.add(&word).unwrap();
        let early = crate::words::handle(
            "mint",
            &cli_args(&["mint", "xy"]),
            &h.0,
            "alice",
        )
        .unwrap()
        .unwrap();
        let refused = early["minted"][0]["refused"].as_str().unwrap_or("");
        assert!(refused.contains("not minted"), "{early}");
        let journal = h.journal();
        let rejected_ops = journal
            .iter()
            .filter(|e| {
                action(e) == "dictionary.outcome"
                    && data(e)["canonical"] == true
                    && data(e)["receipt"]["status"] == "rejected"
                    && data(e)["op_id"]
                        .as_str()
                        .unwrap_or("")
                        .starts_with(&format!("legacy-mint-{}", word.root))
            })
            .count();
        assert_eq!(rejected_ops, 1, "expected one canonical rejected mint attempt");
        for ch in ["x", "y"] {
            let letter = crystal(ch, true);
            let c = Crystal::parse(&letter.to_string()).unwrap();
            book.add(&c).unwrap();
            let minted = crate::words::handle(
                "mint",
                &cli_args(&["mint", ch]),
                &h.0,
                "alice",
            )
            .unwrap()
            .unwrap();
            assert_eq!(minted["minted"][0]["lifecycle"], "minted", "{minted}");
        }
        let again = crate::words::handle(
            "mint",
            &cli_args(&["mint", "xy"]),
            &h.0,
            "alice",
        )
        .unwrap()
        .unwrap();
        let item = &again["minted"][0];
        assert_eq!(item["lifecycle"], "minted", "{again}");
        let op = item["op_id"].as_str().unwrap();
        assert!(
            op.starts_with(&format!("legacy-mint-{}-retry-", word.root)),
            "expected attempt-scoped op_id after rejection, got {op}"
        );
        assert_eq!(
            h.journal()
                .iter()
                .filter(|e| action(e) == "word.mint" && data(e)["root"] == word.root)
                .count(),
            1
        );
        let shown = crate::dictionary_read::show(&h.0, "alice", &word.root, None).unwrap();
        assert_eq!(shown.lifecycle, Some(State::Minted));
        let third = crate::words::handle(
            "mint",
            &cli_args(&["mint", "xy"]),
            &h.0,
            "alice",
        )
        .unwrap()
        .unwrap();
        assert_eq!(third["minted"][0]["already"], true);
        assert_eq!(
            h.journal()
                .iter()
                .filter(|e| action(e) == "word.mint" && data(e)["root"] == word.root)
                .count(),
            1
        );
    }
    #[test]
    fn signer_lock_fails_closed_and_mcp_only_prepares_request() {
        let h = Home::new();
        let dir = h.0.join("custodians/alice");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.join("writer.lock"))
            .unwrap();
        fs4::FileExt::try_lock_exclusive(&lock).unwrap();
        assert!(crate::exploit::journal("alice", &dir)
            .unwrap_err()
            .to_string()
            .contains("already open"));
        drop(lock);
        let before = h.journal().len();
        let p =
            proposal(json!({"op_id":"proposal","command":{"kind":"inspect","root":"a"}})).unwrap();
        assert_eq!(p["signed"], false);
        assert_eq!(p["executed"], false);
        assert_eq!(h.journal().len(), before);
    }

    // ---- Legacy mint-meaning / delegate / revoke through the typed lifecycle ----
    fn legacy(h: &Home, v: &[&str]) -> Result<Value> {
        crate::words::handle(v[0], &cli_args(v), &h.0, "alice").map(Option::unwrap)
    }
    fn mint_letters(h: &Home, letters: &str) {
        let book = Book::open(&h.0.join("book")).unwrap();
        for ch in letters.chars() {
            let c = Crystal::parse(&crystal(&ch.to_string(), true).to_string()).unwrap();
            book.add(&c).unwrap();
            let out = legacy(h, &["mint", &ch.to_string()]).unwrap();
            assert_eq!(out["minted"][0]["lifecycle"], "minted", "{out}");
        }
    }
    /// Word crystal with a root-bound English identity; optionally an exec leaf (built-in sha3_256).
    fn word_crystal(id: &str, exec: bool) -> Crystal {
        let mut leaves = vec![
            Leaf::new(&[("kind", "identity"), ("lang", "en"), ("value", id), ("schema", ans_dict::WORD_SCHEMA)]),
            Leaf::new(&[("kind", "sense"), ("lang", "en"), ("sense", "en-1"), ("value", "fixture"), ("source", "fixture")]),
        ];
        if exec {
            let reference = ans_dict::exec::exec_word("hash", "sha3_256", "run", "sha3", "0.10.9", crate::rule::LOCK, "x").unwrap();
            let e = reference.of_kind("exec").next().unwrap();
            let sum = e.get("checksum").unwrap().to_owned();
            leaves.push(Leaf::new(&[("kind","exec"),("function","sha3_256"),("scope","run"),("registry","crates.io"),("package","sha3"),("version","0.10.9"),("checksum",&sum),("source","registry+https://github.com/rust-lang/crates.io-index")]));
        }
        Crystal::build(CrystalKind::Word, id, leaves, Default::default()).unwrap()
    }
    fn minted_word(h: &Home, id: &str, exec: bool) -> Crystal {
        mint_letters(h, id);
        let w = word_crystal(id, exec);
        Book::open(&h.0.join("book")).unwrap().add(&w).unwrap();
        let out = legacy(h, &["mint", id]).unwrap();
        assert_eq!(out["minted"][0]["lifecycle"], "minted", "{out}");
        w
    }
    fn count(h: &Home, act: &str) -> usize {
        h.journal().iter().filter(|e| action(e) == act).count()
    }
    fn dir(h: &Home) -> std::path::PathBuf {
        h.0.join("custodians/alice")
    }
    #[test]
    fn legacy_meaning_delegate_revoke_accept_idempotently_and_replay() {
        let h = Home::new();
        let w = minted_word(&h, "ab", false);
        let before = h.journal().len();
        let m = legacy(&h, &["mint-meaning", "ab", "en", "a test word"]).unwrap();
        assert_eq!(m["service"], "dictionary");
        assert_eq!(m["lifecycle_adapter"], "legacy_annotation");
        assert!(m["op_id"].as_str().unwrap().starts_with("legacy-meaning-"));
        // intent + native + outcome, signed and bound.
        let j = h.journal();
        assert_eq!(j.len(), before + 3);
        assert_eq!(action(&j[before]), "dictionary.intent");
        assert_eq!(action(&j[before + 1]), "word.meaning");
        assert_eq!(action(&j[before + 2]), "dictionary.outcome");
        assert_eq!(data(&j[before + 1])["text_sha3"], text_sha3("a test word"));
        assert_eq!(data(&j[before + 2])["receipt"]["entry"]["state"], "minted");
        // Same meaning again: idempotent, no new signature.
        let again = legacy(&h, &["mint-meaning", "ab", "en", "a test word"]).unwrap();
        assert_eq!(again["already"], true);
        assert_eq!(h.journal().len(), before + 3);
        // Letters and unminted words are refused before any signature.
        assert!(legacy(&h, &["mint-meaning", "a", "en", "x"]).unwrap_err().to_string().contains("not letters"));
        let unminted = word_crystal("ba", false);
        Book::open(&h.0.join("book")).unwrap().add(&unminted).unwrap();
        assert!(legacy(&h, &["mint-meaning", "ba", "en", "x"]).unwrap_err().to_string().contains("no minted dictionary lifecycle"));
        assert!(legacy(&h, &["delegate", "ba", "run"]).unwrap_err().to_string().contains("no minted dictionary lifecycle"));
        assert_eq!(h.journal().len(), before + 3);
        // delegate → already → revoke → not delegated → delegate again (new generation).
        let d1 = legacy(&h, &["delegate", "ab", "review"]).unwrap();
        assert!(d1["op_id"].as_str().unwrap().ends_with("-g0"), "{d1}");
        let n = h.journal().len();
        assert_eq!(legacy(&h, &["delegate", "ab", "review"]).unwrap()["already"], true);
        assert_eq!(h.journal().len(), n);
        let r1 = legacy(&h, &["revoke", "ab", "review"]).unwrap();
        assert!(r1["op_id"].as_str().unwrap().ends_with("-g1"), "{r1}");
        let n = h.journal().len();
        assert_eq!(legacy(&h, &["revoke", "ab", "review"]).unwrap()["state"], "not delegated");
        assert_eq!(h.journal().len(), n);
        let d2 = legacy(&h, &["delegate", "ab", "review"]).unwrap();
        assert!(d2["op_id"].as_str().unwrap().ends_with("-g2"), "{d2}");
        assert_eq!(count(&h, "word.delegate"), 2);
        assert_eq!(count(&h, "word.revoke"), 1);
        let j = h.journal();
        assert!(active_grants(&j).contains(&(w.root.clone(), "review".into())));
        let entries = crate::dictionary_read::replay_verified(&j).unwrap();
        assert_eq!(entries[&w.root].state, State::Minted);
        // Public reader and proof export still work; proofs exclude annotations.
        let item = crate::dictionary_read::show(&h.0, "alice", &w.root, None).unwrap();
        assert_eq!(item.lifecycle, Some(State::Minted));
        let key = j[0]["xmss"]["pk"].as_str().unwrap().to_owned();
        let proof = crate::dictionary_read::export(&h.0, "alice", &w.root, &key).unwrap();
        assert_eq!(crate::dictionary_read::verify(&proof, &key).unwrap()["word_dependency_path_verified"], true);
    }
    #[test]
    fn annotation_rejections_are_signed_without_effects_and_legacy_retries() {
        let h = Home::new();
        mint_letters(&h, "cd");
        let w = word_crystal("cd", false);
        Book::open(&h.0.join("book")).unwrap().add(&w).unwrap();
        let r = ContentRoot(w.root.clone());
        // Explicit typed requests: invalid scope / revoke without grant / unknown root are rejected.
        assert_eq!(status(&h.apply("bad-scope", Command::Delegate { root: r.clone(), scope: "BAD SCOPE".into() })), "rejected");
        // Pre-mint rejection at the exact legacy ID; once minted the legacy path opens -retry-.
        let base = format!("legacy-delegate-{}-{}-g0", w.root, &text_sha3("run")[..16]);
        let early = h.apply(&base, Command::Delegate { root: r.clone(), scope: "run".into() });
        assert_eq!(status(&early), "rejected");
        assert_eq!(count(&h, "word.delegate"), 0);
        assert_eq!(legacy(&h, &["mint", "cd"]).unwrap()["minted"][0]["lifecycle"], "minted");
        assert_eq!(status(&h.apply("no-grant", Command::Revoke { root: r.clone(), scope: "run".into() })), "rejected");
        assert_eq!(status(&h.apply("letter-meaning", Command::Meaning { root: ContentRoot(Crystal::parse(&crystal("c", true).to_string()).unwrap().root), lang: "en".into(), text: "x".into() })), "rejected");
        assert_eq!(status(&h.apply("empty", Command::Meaning { root: r.clone(), lang: "en".into(), text: " ".into() })), "rejected");
        assert_eq!(count(&h, "word.revoke") + count(&h, "word.meaning"), 0);
        let retried = legacy(&h, &["delegate", "cd", "run"]).unwrap();
        assert!(retried["op_id"].as_str().unwrap().starts_with(&format!("{base}-retry-")), "{retried}");
        assert_eq!(count(&h, "word.delegate"), 1);
        // Explicit same-ID retry replays the original rejection (receipt stability).
        let replayed = h.apply(&base, Command::Delegate { root: r.clone(), scope: "run".into() });
        assert_eq!(replayed["retry"], true);
        assert_eq!(status(&replayed), "rejected");
        assert_eq!(count(&h, "word.delegate"), 1);
        assert!(crate::dictionary_read::replay_verified(&h.journal()).is_ok());
    }
    #[test]
    fn annotation_interrupts_recover_without_duplicate_effects() {
        let h = Home::new();
        let w = minted_word(&h, "ef", false);
        let r = ContentRoot(w.root.clone());
        let open_intent = |id: &str, command: Command| {
            let req = Request { op_id: OperationId(id.into()), command };
            let digest = hash(&serde_json::to_value(&req.command).unwrap()).unwrap();
            append("alice", &dir(&h), "dictionary.intent", json!({"request":req,"command_digest":digest,"canonical":true})).unwrap()
        };
        // (a) crash after intent, before native: Interrupted, legacy retry opens a new attempt.
        let scope_hash = &text_sha3("run")[..16];
        let base = format!("legacy-delegate-{}-{scope_hash}-g0", w.root);
        open_intent(&base, Command::Delegate { root: r.clone(), scope: "run".into() });
        // Pending gate: unrelated signed writes refuse; bare native effects refuse.
        assert!(crate::exploit::record_local("alice", &dir(&h), "contact.add", json!({"word":"bob.ans"})).is_err());
        assert!(crate::exploit::record_local("alice", &dir(&h), "word.delegate", json!({"root":w.root,"scope":"run","service":"dictionary","op_id":"other"})).is_err());
        let out = legacy(&h, &["delegate", "ef", "run"]).unwrap();
        assert!(out["op_id"].as_str().unwrap().starts_with(&format!("{base}-retry-")), "{out}");
        let j = h.journal();
        let interrupted = j.iter().find(|e| action(e) == "dictionary.outcome" && data(e)["op_id"] == base).unwrap();
        assert_eq!(data(interrupted)["receipt"]["status"], "interrupted");
        assert_eq!(count(&h, "word.delegate"), 1);
        // (b) crash after durable native, before outcome: recovered as Accepted, never repeated.
        let mbase = format!("legacy-meaning-{}-{}", w.root, &text_sha3("en\0durable")[..16]);
        let intent = open_intent(&mbase, Command::Meaning { root: r.clone(), lang: "en".into(), text: "durable".into() });
        let block = h.journal().iter().find(|e| action(e) == "word.mint" && data(e)["root"] == w.root).unwrap()["seq"].as_u64().unwrap();
        let cmd = Command::Meaning { root: r.clone(), lang: "en".into(), text: "durable".into() };
        append("alice", &dir(&h), "word.meaning", annotation_payload(&cmd, &OperationId(mbase.clone()), &w, block).unwrap()).unwrap();
        assert!(crate::dictionary_read::replay_verified(&h.journal()).is_err());
        let again = legacy(&h, &["mint-meaning", "ef", "en", "durable"]).unwrap();
        assert_eq!(again["already"], true, "{again}");
        assert_eq!(count(&h, "word.meaning"), 1);
        let j = h.journal();
        let outcome = j.iter().find(|e| action(e) == "dictionary.outcome" && data(e)["intent_hash"] == intent["hash"]).unwrap();
        assert_eq!(data(outcome)["receipt"]["status"], "accepted");
        assert!(data(outcome)["receipt"]["reason"].as_str().unwrap().contains("Recovered"));
        // (c) crash after native delegate: grant becomes active exactly once.
        let rbase = format!("legacy-revoke-{}-{scope_hash}-g1", w.root);
        let rcmd = Command::Revoke { root: r.clone(), scope: "run".into() };
        open_intent(&rbase, rcmd.clone());
        append("alice", &dir(&h), "word.revoke", annotation_payload(&rcmd, &OperationId(rbase.clone()), &w, block).unwrap()).unwrap();
        assert_eq!(legacy(&h, &["revoke", "ef", "run"]).unwrap()["state"], "not delegated");
        assert_eq!(count(&h, "word.revoke"), 1);
        let j = h.journal();
        assert!(!active_grants(&j).contains(&(w.root.clone(), "run".into())));
        assert!(crate::dictionary_read::replay_verified(&j).is_ok());
    }
    #[test]
    fn annotation_replay_rejects_forged_or_unbound_effects() {
        // Each case writes genuinely signed events that the signer accepts inside an open intent;
        // strict replay must still refuse the history.
        let h = Home::new();
        let w = minted_word(&h, "gh", false);
        let r = ContentRoot(w.root.clone());
        let block = h.journal().iter().find(|e| action(e) == "word.mint" && data(e)["root"] == w.root).unwrap()["seq"].as_u64().unwrap();
        let entry: Entry = crate::dictionary_read::replay_verified(&h.journal()).unwrap()[&w.root].clone();
        let forge = |id: &str, cmd: Command, native: Option<Value>, status: &str| {
            let req = Request { op_id: OperationId(id.into()), command: cmd.clone() };
            let digest = hash(&serde_json::to_value(&req.command).unwrap()).unwrap();
            let intent = append("alice", &dir(&h), "dictionary.intent", json!({"request":req,"command_digest":digest,"canonical":true})).unwrap();
            if let Some(n) = native {
                append("alice", &dir(&h), cmd.annotation_action().unwrap(), n).unwrap();
            }
            let receipt = if status == "accepted" { json!({"status":"accepted","reason":null,"entry":entry}) } else { json!({"status":status,"reason":"x","entry":null}) };
            append("alice", &dir(&h), "dictionary.outcome", json!({"intent_hash":intent["hash"],"op_id":id,"command_digest":digest,"canonical":true,"receipt":receipt})).unwrap();
        };
        // Case 1: payload scope differs from the signed intent.
        let cmd = Command::Delegate { root: r.clone(), scope: "run".into() };
        let mut bad = annotation_payload(&cmd, &OperationId("f1".into()), &w, block).unwrap();
        bad["scope"] = json!("admin");
        forge("f1", cmd, Some(bad), "accepted");
        let err = crate::dictionary_read::replay_verified(&h.journal()).unwrap_err().to_string();
        assert!(err.contains("payload mismatch"), "{err}");
        // A writer refuses to admit anything on top of a history that fails replay.
        assert!(apply(&h.0, "alice", Request { op_id: OperationId("after".into()), command: Command::Inspect { root: r.clone() } }).is_err());

        let h = Home::new();
        let w = minted_word(&h, "gh", false);
        let r = ContentRoot(w.root.clone());
        let block = h.journal().iter().find(|e| action(e) == "word.mint" && data(e)["root"] == w.root).unwrap()["seq"].as_u64().unwrap();
        let entry: Entry = crate::dictionary_read::replay_verified(&h.journal()).unwrap()[&w.root].clone();
        let forge = |id: &str, cmd: Command, native: Option<Value>, status: &str| {
            let req = Request { op_id: OperationId(id.into()), command: cmd.clone() };
            let digest = hash(&serde_json::to_value(&req.command).unwrap()).unwrap();
            let intent = append("alice", &dir(&h), "dictionary.intent", json!({"request":req,"command_digest":digest,"canonical":true})).unwrap();
            if let Some(n) = native {
                append("alice", &dir(&h), cmd.annotation_action().unwrap(), n).unwrap();
            }
            let receipt = if status == "accepted" { json!({"status":"accepted","reason":null,"entry":entry}) } else { json!({"status":status,"reason":"x","entry":null}) };
            append("alice", &dir(&h), "dictionary.outcome", json!({"intent_hash":intent["hash"],"op_id":id,"command_digest":digest,"canonical":true,"receipt":receipt})).unwrap();
        };
        // Case 2: native effect written but the outcome says rejected (unbound effect).
        let cmd = Command::Delegate { root: r.clone(), scope: "run".into() };
        let native = annotation_payload(&cmd, &OperationId("f2".into()), &w, block).unwrap();
        forge("f2", cmd, Some(native), "rejected");
        let err = crate::dictionary_read::replay_verified(&h.journal()).unwrap_err().to_string();
        assert!(err.contains("without an accepted outcome"), "{err}");

        let h = Home::new();
        let w = minted_word(&h, "gh", false);
        let r = ContentRoot(w.root.clone());
        let block = h.journal().iter().find(|e| action(e) == "word.mint" && data(e)["root"] == w.root).unwrap()["seq"].as_u64().unwrap();
        let entry: Entry = crate::dictionary_read::replay_verified(&h.journal()).unwrap()[&w.root].clone();
        // Case 3: accepted revoke with no prior grant.
        let cmd = Command::Revoke { root: r.clone(), scope: "run".into() };
        let native = annotation_payload(&cmd, &OperationId("f3".into()), &w, block).unwrap();
        let req = Request { op_id: OperationId("f3".into()), command: cmd.clone() };
        let digest = hash(&serde_json::to_value(&req.command).unwrap()).unwrap();
        let intent = append("alice", &dir(&h), "dictionary.intent", json!({"request":req,"command_digest":digest,"canonical":true})).unwrap();
        append("alice", &dir(&h), "word.revoke", native).unwrap();
        append("alice", &dir(&h), "dictionary.outcome", json!({"intent_hash":intent["hash"],"op_id":"f3","command_digest":digest,"canonical":true,"receipt":{"status":"accepted","reason":null,"entry":entry}})).unwrap();
        let err = crate::dictionary_read::replay_verified(&h.journal()).unwrap_err().to_string();
        assert!(err.contains("Revoke without active delegation"), "{err}");

        // Case 4: byte tamper of a signed meaning event breaks the journal itself.
        let h = Home::new();
        minted_word(&h, "gh", false);
        legacy(&h, &["mint-meaning", "gh", "en", "honest"]).unwrap();
        let path = dir(&h).join("chain.ndjson");
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replace("\"text\":\"honest\"", "\"text\":\"forged\"")).unwrap();
        assert!(crate::exploit::journal("alice", &dir(&h)).is_err());
    }
    #[test]
    fn run_and_skill_run_fail_closed_unless_dictionary_rules_pass() {
        let h = Home::new();
        let w = minted_word(&h, "has", true);
        // Minted executable word without a dictionary delegation: refused.
        let e = legacy(&h, &["run", "has", "abc"]).unwrap_err().to_string();
        assert!(e.contains("no active dictionary delegation"), "{e}");
        // A bare legacy grant cannot be signed at all.
        assert!(crate::exploit::record_local("alice", &dir(&h), "word.delegate", json!({"word":"has","root":w.root,"scope":"run"})).is_err());
        legacy(&h, &["delegate", "has", "run"]).unwrap();
        let plan = legacy(&h, &["run", "has", "--plan"]).unwrap();
        assert_eq!(plan["accept"], true, "{plan}");
        assert_eq!(plan["service"], "dictionary");
        let out = legacy(&h, &["run", "has", "abc"]).unwrap();
        assert_eq!(out["output"], "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
        legacy(&h, &["revoke", "has", "run"]).unwrap();
        assert!(legacy(&h, &["run", "has", "abc"]).unwrap_err().to_string().contains("no active dictionary delegation"));
        // Word in the book but without a dictionary lifecycle: refused even with no journal tricks.
        let loose = word_crystal("sah", true);
        Book::open(&h.0.join("book")).unwrap().add(&loose).unwrap();
        assert!(legacy(&h, &["run", "sah"]).unwrap_err().to_string().contains("no minted dictionary lifecycle"));
        // MCP `run` goes through the same handler.
        let mcp = crate::words::mcp_call("run", &json!({"word":"has","input":"abc"}), &h.0, "alice").unwrap();
        assert!(mcp.is_err());
        let n = h.journal().len();
        let skill = crate::exploit::api_for_test("alice", &dir(&h), &json!({"op":"skill_run","name":"reference","action":"read"}));
        assert!(skill.unwrap_err().to_string().contains("skill_run is disabled"));
        assert_eq!(h.journal().len(), n);
        assert!(crate::dictionary_read::replay_verified(&h.journal()).is_ok());
    }
}
