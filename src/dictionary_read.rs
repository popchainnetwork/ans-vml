// SPDX-License-Identifier: Apache-2.0
//! Public, non-mutating dictionary snapshots and selective dependency attestations.
use crate::dictionary::{Command, Entry, Receipt, Request, State, Status};
use ans_dict::{Crystal, CrystalKind};
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use popchain_cli::{
    chain::{verify_block_commitments, BlockV1},
    types::Hash32,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha3::{Digest, Sha3_256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attestation {
    event: Value,
    block: BlockV1,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    format: String,
    entry: Entry,
    attestations: Vec<Attestation>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Item {
    pub id: String,
    pub root: String,
    pub kind: String,
    pub language: Option<String>,
    pub provenance: String,
    pub lifecycle: Option<State>,
    pub minted_block: Option<u64>,
    pub signer: Option<String>,
    pub trust: String,
    pub content: Value,
}
fn d(e: &Value) -> &Value {
    &e["body"]["data"]
}
fn action(e: &Value) -> &str {
    e["body"]["action"].as_str().unwrap_or("")
}
fn digest(v: &Value) -> Result<String> {
    Ok(hex::encode(Sha3_256::digest(serde_json::to_vec(v)?)))
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str()
        .ok_or_else(|| anyhow!("Missing public field {k}"))
}
fn seq(e: &Value) -> Result<u64> {
    e["seq"]
        .as_u64()
        .ok_or_else(|| anyhow!("Invalid event sequence"))
}
// Only this exact public file allowlist is read; no signer or database is opened.
fn read(path: &Path) -> Result<Vec<u8>> {
    if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        bail!("Public snapshot file must not be a symlink");
    }
    std::fs::read(path).with_context(|| format!("Read public snapshot {}", path.display()))
}
fn signature_check(e: &Value, expected: &str) -> Result<()> {
    if text(&e["xmss"], "pk")? != expected || !crate::exploit::event_valid(e) {
        bail!("Signature or expected signer mismatch");
    }
    let signature = ans_xmss::MtSig::from_bytes(&hex::decode(text(&e["xmss"], "sig")?)?)
        .map_err(|_| anyhow!("Invalid signature encoding"))?;
    if e["xmss"]["idx"] != signature.idx {
        bail!("Signature index metadata mismatch");
    }
    Ok(())
}
fn event_check(a: &Attestation, expected: &str) -> Result<()> {
    let e = &a.event;
    signature_check(e, expected)?;
    verify_block_commitments(&a.block)?;
    if a.block.header.height != seq(e)? || a.block.app_events.len() != 1 {
        bail!("Block/event position mismatch");
    }
    let payload = &a.block.app_events[0];
    if payload.kind != "ans.product.exploit.v1" {
        bail!("Wrong application payload kind");
    }
    let bytes = base64::engine::general_purpose::STANDARD.decode(&payload.payload_b64)?;
    if serde_json::from_slice::<Value>(&bytes)? != *e {
        bail!("Block/event payload mismatch");
    }
    Ok(())
}
fn follows(after: &Value, before: &Value) -> Result<()> {
    if seq(after)? != seq(before)? + 1 || after["prev"] != before["hash"] {
        bail!("Operation events are reordered or disconnected");
    }
    Ok(())
}
fn crystal_entry(e: &Entry) -> Result<Crystal> {
    let c = Crystal::parse(&serde_json::to_string(&e.crystal)?)?;
    let identity = c
        .of_kind("identity")
        .next()
        .ok_or_else(|| anyhow!("Missing identity"))?;
    let language = identity.get("lang").or(identity.get("language"));
    if c.root != e.root.0
        || c.id != e.word.spelling
        || e.word.language.trim().is_empty()
        || !(language == Some(e.word.language.as_str())
            || (c.kind == CrystalKind::Letter && language.is_none() && e.word.language == "und"))
    {
        bail!("Entry root/identity/language mismatch");
    }
    if c.kind == CrystalKind::Letter && (c.id.chars().count() != 1 || e.word.language != "und") {
        bail!("Character identity must be one scalar with language und");
    }
    Ok(c)
}
fn validate(c: &Crystal) -> Result<()> {
    crate::rule::kind(c)?;
    if c.kind == CrystalKind::Letter
        && !c
            .of_kind("character")
            .any(|l| l.get("value") == Some(c.id.as_str()))
    {
        bail!("Character leaf/identity mismatch");
    }
    if c.leaves
        .iter()
        .any(|l| matches!(l.get("kind"), Some("asset") | Some("font")))
    {
        bail!("Asset/font verification is not supported");
    }
    Ok(())
}
// One semantic replay engine serves local writer admission and public proofs.
// Selected proofs attest paths at signed sequences, not complete history.
fn reduce(
    events: &[Attestation],
    expected: &str,
    selected: bool,
) -> Result<BTreeMap<String, Entry>> {
    let mut prior: Option<&Attestation> = None;
    for a in events {
        event_check(a, expected)?;
        if prior.is_some_and(|p| {
            seq(&a.event).ok() == seq(&p.event).ok().and_then(|s| s.checked_add(1))
                && a.block.header.prev_block_hash_hex != p.block.block_hash_hex
        }) {
            bail!("Selected consecutive block references do not link");
        }
        if selected && !a.block.proofs.is_empty() {
            bail!("Proof contains unrelated kernel proofs");
        }
        prior = Some(a);
    }
    replay_events(
        &events.iter().map(|a| a.event.clone()).collect::<Vec<_>>(),
        expected,
        selected,
    )
}
pub fn replay_verified(events: &[Value]) -> Result<BTreeMap<String, Entry>> {
    let key = events
        .first()
        .and_then(|e| e["xmss"]["pk"].as_str())
        .ok_or_else(|| anyhow!("Empty signed journal"))?;
    replay_events(events, key, false)
}
fn replay_events(
    events: &[Value],
    expected: &str,
    selected: bool,
) -> Result<BTreeMap<String, Entry>> {
    if hex::decode(expected)?.len() != 64 {
        bail!("Expected signer must be a 64-byte XMSSMT public key");
    }
    let mut entries: BTreeMap<String, Entry> = BTreeMap::new();
    let mut intents: BTreeMap<String, (Request, bool, String, Value)> = BTreeMap::new();
    let mut originals: BTreeMap<String, (String, Option<Receipt>)> = BTreeMap::new();
    let mut completed = BTreeSet::new();
    let mut mint_roots = BTreeSet::new();
    let mut prior_seq = 0;
    let mut prior_idx = None;
    let mut prior_event: Option<&Value> = None;
    let mut owner: Option<&str> = None;
    let mut minted: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for e in events {
        signature_check(e, expected)?;
        let n = seq(e)?;
        let idx = e["xmss"]["idx"]
            .as_u64()
            .ok_or_else(|| anyhow!("Missing signature index"))?;
        if n <= prior_seq || prior_idx.is_some_and(|p| idx <= p) {
            bail!("Reordered events or duplicate signature effects");
        }
        let current_owner = text(&e["body"], "custodian")?;
        if owner.is_some_and(|p| p != current_owner) {
            bail!("Mixed custodians");
        }
        owner = Some(current_owner);
        if !selected {
            if let Some(p) = prior_event {
                follows(e, p)?;
            } else if n != 1 || e["prev"] != "0".repeat(64) {
                bail!("Incomplete journal snapshot");
            }
        }
        prior_seq = n;
        prior_idx = Some(idx);
        prior_event = Some(e);
        match action(e) {
            "dictionary.intent" => {
                let request: Request = serde_json::from_value(d(e)["request"].clone())?;
                if request.op_id.0.is_empty() || request.op_id.0.len() > 128 {
                    bail!("Invalid operation ID");
                }
                let hash = digest(&serde_json::to_value(&request.command)?)?;
                let canonical = d(e)["canonical"]
                    .as_bool()
                    .ok_or_else(|| anyhow!("Missing canonical flag"))?;
                if d(e)["command_digest"] != hash
                    || canonical == originals.contains_key(&request.op_id.0)
                {
                    bail!("Invalid command digest or duplicate canonical operation");
                }
                if canonical {
                    originals.insert(request.op_id.0.clone(), (hash.clone(), None));
                }
                if intents
                    .insert(
                        text(e, "hash")?.into(),
                        (request, canonical, hash, e.clone()),
                    )
                    .is_some()
                {
                    bail!("Duplicate intent");
                }
            }
            "word.mint" => {
                if !mint_roots.insert(text(d(e), "root")?.to_owned()) {
                    bail!("Duplicate native mint effect");
                }
                if selected && d(e)["service"] != "dictionary" {
                    bail!("Selected proof includes a legacy mint");
                }
            }
            "dictionary.outcome" => {
                let intent_hash = text(d(e), "intent_hash")?;
                let (request, canonical, hash, intent) = intents
                    .get(intent_hash)
                    .ok_or_else(|| anyhow!("Dictionary outcome has no preceding bound intent"))?;
                if !completed.insert(intent_hash.to_string())
                    || d(e)["op_id"] != request.op_id.0
                    || d(e)["command_digest"] != *hash
                    || d(e)["canonical"] != *canonical
                {
                    bail!("Mismatched or repeated outcome");
                }
                let receipt: Receipt = serde_json::from_value(d(e)["receipt"].clone())?;
                if !canonical {
                    let (original_digest, original_receipt) = originals
                        .get(&request.op_id.0)
                        .ok_or_else(|| anyhow!("Retry without original"))?;
                    if original_digest == hash {
                        if serde_json::to_value(&receipt)?
                            != serde_json::to_value(
                                original_receipt
                                    .as_ref()
                                    .ok_or_else(|| anyhow!("Retry before completion"))?,
                            )?
                        {
                            bail!("Retry changed original receipt");
                        }
                    } else if receipt.status != Status::Rejected || receipt.entry.is_some() {
                        bail!("Conflicting operation was not rejected");
                    }
                    continue;
                }
                if receipt.status != Status::Accepted {
                    if receipt.entry.is_some() {
                        bail!("Non-accepted outcome contains authoritative entry");
                    }
                } else {
                    let next = receipt
                        .entry
                        .as_ref()
                        .ok_or_else(|| anyhow!("Accepted outcome without entry"))?;
                    let c = crystal_entry(next)?;
                    match &request.command {
                        Command::Draft { word, crystal } => {
                            follows(e, intent)?;
                            if next.state != State::Draft
                                || next.word != *word
                                || next.crystal != *crystal
                                || entries.contains_key(&c.root)
                                || entries.values().any(|p| p.word == *word)
                            {
                                bail!("Invalid draft transition or duplicate identity");
                            }
                        }
                        command => {
                            let root = match command {
                                Command::Validate { root }
                                | Command::Mint { root }
                                | Command::Inspect { root }
                                | Command::Run { root } => root,
                                _ => unreachable!(),
                            };
                            let old = entries
                                .get(&root.0)
                                .ok_or_else(|| anyhow!("Transition has no draft"))?;
                            if old.word != next.word
                                || old.root != next.root
                                || old.crystal != next.crystal
                            {
                                bail!("Transition changed immutable content");
                            }
                            match command {
                                Command::Validate { .. } => {
                                    follows(e, intent)?;
                                    validate(&c)?;
                                    if old.state != State::Draft || next.state != State::Validated {
                                        bail!("Invalid validation transition");
                                    }
                                }
                                Command::Mint { .. } => {
                                    if old.state != State::Validated || next.state != State::Minted
                                    {
                                        bail!("Invalid mint transition");
                                    }
                                    let native = events
                                        .iter()
                                        .find(|m| {
                                            action(m) == "word.mint"
                                                && d(m)["op_id"] == request.op_id.0
                                                && d(m)["root"] == root.0
                                                && seq(m).is_ok_and(|s| {
                                                    s > seq(intent).unwrap_or(u64::MAX) && s < n
                                                })
                                        })
                                        .ok_or_else(|| anyhow!("Missing native mint event"))?;
                                    follows(native, intent)?;
                                    follows(e, native)?;
                                    let letters = crate::rule::letters_of(&c, &|ch| {
                                        entries
                                            .values()
                                            .find(|letter| {
                                                letter.word.language == "und"
                                                    && letter.word.spelling == ch.to_string()
                                                    && letter.state == State::Minted
                                                    && crystal_entry(letter).is_ok_and(|c| {
                                                        c.kind == CrystalKind::Letter
                                                    })
                                            })
                                            .and_then(|letter| {
                                                minted
                                                    .get(&letter.root.0)
                                                    .filter(|(_, outcome)| {
                                                        *outcome < seq(intent).unwrap_or(0)
                                                    })
                                                    .map(|(block, _)| {
                                                        (letter.root.0.clone(), json!(block))
                                                    })
                                            })
                                    })?;
                                    if d(native)["word"] != c.id
                                        || d(native)["file"] != c.file_name()
                                        || d(native)["layer"]
                                            != if c.kind == CrystalKind::Letter { 1 } else { 2 }
                                        || d(native)["service"] != "dictionary"
                                        || d(native)["letters"] != json!(letters)
                                    {
                                        bail!("Native mint identity/type/dependencies mismatch");
                                    }
                                    minted.insert(c.root.clone(), (seq(native)?, n));
                                }
                                Command::Inspect { .. } => {
                                    follows(e, intent)?;
                                    if old.state != next.state {
                                        bail!("Inspection advanced lifecycle");
                                    }
                                }
                                Command::Run { .. } => {
                                    bail!("Accepted execution has no approval adapter")
                                }
                                _ => unreachable!(),
                            }
                        }
                    }
                    entries.insert(c.root, next.clone());
                }
                originals.get_mut(&request.op_id.0).unwrap().1 = Some(receipt);
            }
            _ if selected => bail!("Proof contains unrelated history"),
            _ => {}
        }
    }
    if intents.len() != completed.len() {
        bail!("Incomplete operation; use a stable public snapshot");
    }
    Ok(entries)
}
fn public_snapshot(
    root: &Path,
    owner: &str,
    anchor: Option<&str>,
) -> Result<(Vec<Attestation>, String)> {
    if owner.is_empty()
        || !owner
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    {
        bail!("Explicit local custodian required");
    }
    let dir = root.join("custodians").join(owner);
    let path = dir.join("chain.ndjson");
    let bytes = read(&path)?;
    let mut result = Vec::new();
    let mut previous_block: Option<String> = None;
    let state_before = read(&dir.join("kernel/state.json"))?;
    for line in std::str::from_utf8(&bytes)?.lines() {
        let event: Value = serde_json::from_str(line)?;
        let n = seq(&event)?;
        if event["body"]["custodian"] != format!("{owner}.ans") {
            bail!("Snapshot custodian mismatch");
        }
        let hashes: Vec<Hash32> =
            serde_json::from_slice(&read(&dir.join(format!("kernel/heights/{n}.json")))?)?;
        if hashes.len() != 1 {
            bail!("Ambiguous block height; verified canonical snapshot required");
        }
        let hash = hashes[0].to_hex();
        let block: BlockV1 =
            serde_json::from_slice(&read(&dir.join(format!("kernel/blocks/{hash}.json")))?)?;
        if block.block_hash_hex != hash
            || previous_block
                .as_ref()
                .is_some_and(|p| *p != block.header.prev_block_hash_hex)
        {
            bail!("Kernel hash chain mismatch");
        }
        previous_block = Some(hash);
        result.push(Attestation { event, block });
    }
    let state: Value = serde_json::from_slice(&state_before)?;
    if state["best_height"] != result.len()
        || previous_block
            .as_ref()
            .is_some_and(|tip| state["best_tip_hash_hex"] != *tip)
        || read(&path)? != bytes
        || read(&dir.join("kernel/state.json"))? != state_before
    {
        bail!("Public snapshot changed or projection is incomplete; retry when writer is idle");
    }
    let key = result
        .first()
        .and_then(|a| a.event["xmss"]["pk"].as_str())
        .ok_or_else(|| anyhow!("Empty signed snapshot"))?
        .to_string();
    if anchor.is_some_and(|a| a != key) {
        bail!("Expected signer mismatch");
    }
    reduce(&result, &key, false)?;
    Ok((result, key))
}
pub fn writer_entries(
    root: &Path,
    owner: &str,
    events: &[Value],
) -> Result<BTreeMap<String, Entry>> {
    let key = events
        .first()
        .and_then(|e| e["xmss"]["pk"].as_str())
        .ok_or_else(|| anyhow!("Empty writer journal"))?;
    let (public, verified_key) = public_snapshot(root, owner, Some(key))?;
    if public.iter().map(|a| &a.event).ne(events.iter()) {
        bail!("Writer/public snapshot changed before admission");
    }
    reduce(&public, &verified_key, false)
}
fn item(
    c: &Crystal,
    content: Value,
    state: Option<State>,
    signer: Option<String>,
    anchored: bool,
) -> Item {
    Item {
        id: c.id.clone(),
        root: c.root.clone(),
        kind: if c.kind == CrystalKind::Letter {
            "letter"
        } else {
            "word"
        }
        .into(),
        language: c
            .of_kind("identity")
            .next()
            .and_then(|l| l.get("lang").or(l.get("language")))
            .map(str::to_string)
            .or_else(|| (c.kind == CrystalKind::Letter).then(|| "und".into())),
        provenance: if state.is_some() {
            "signed_lifecycle_snapshot"
        } else {
            "cache_only_imported"
        }
        .into(),
        lifecycle: state,
        minted_block: None,
        signer,
        trust: if anchored {
            "expected_signer_matched_local_not_global"
        } else {
            "unanchored_content_not_global_authority"
        }
        .into(),
        content,
    }
}
pub fn browse(root: &Path, owner: &str, anchor: Option<&str>) -> Result<Vec<Item>> {
    let mut items = BTreeMap::new();
    if !owner.is_empty() {
        let (events, key) = public_snapshot(root, owner, anchor)?;
        for entry in reduce(&events, &key, false)?.into_values() {
            let c = crystal_entry(&entry)?;
            let mut record = item(
                &c,
                entry.crystal,
                Some(entry.state),
                Some(key.clone()),
                anchor.is_some(),
            );
            if record.lifecycle == Some(State::Minted) {
                record.minted_block = events
                    .iter()
                    .find(|a| action(&a.event) == "word.mint" && d(&a.event)["root"] == c.root)
                    .and_then(|a| seq(&a.event).ok());
            }
            items.insert(c.root.clone(), record);
        }
    } else if anchor.is_some() {
        bail!("Expected signer requires an explicit custodian snapshot");
    }
    let book = root.join("book");
    if book.exists() {
        for file in std::fs::read_dir(&book)? {
            let file = file?;
            let name = file.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| anyhow!("Invalid cache filename"))?;
            if !ans_dict::book::valid_file_name(name) {
                continue;
            }
            let bytes = read(&file.path())?;
            let content: Value = serde_json::from_slice(&bytes)?;
            let c = Crystal::parse(std::str::from_utf8(&bytes)?)?;
            if c.file_name() != name {
                bail!("Cache filename does not match identity/type");
            }
            if items.values().any(|i| {
                i.provenance == "signed_lifecycle_snapshot"
                    && Crystal::parse(&i.content.to_string())
                        .is_ok_and(|old| old.file_name() == name && old.root != c.root)
            }) {
                bail!("Cache root conflicts with the authoritative snapshot filename");
            }
            if let Some(existing) = items.get(&c.root) {
                let old = Crystal::parse(&serde_json::to_string(&existing.content)?)?;
                if old.id != c.id || old.kind != c.kind {
                    bail!("Cache/lifecycle identity or type mismatch");
                }
            } else {
                items.insert(c.root.clone(), item(&c, content, None, None, false));
            }
        }
    }
    Ok(items.into_values().collect())
}
pub fn matches(c: &Crystal, query: &str) -> bool {
    let q = ans_dict::forms::fold(query);
    ans_dict::forms::fold(&c.id) == q
        || (c.kind == CrystalKind::Word
            && c.leaves.iter().any(|l| {
                matches!(l.get("kind"), Some("translation") | Some("form"))
                    && l.get("value").map(ans_dict::forms::fold).as_deref() == Some(q.as_str())
            }))
}
pub fn show(root: &Path, owner: &str, query: &str, anchor: Option<&str>) -> Result<Item> {
    let found: Vec<_> = browse(root, owner, anchor)?
        .into_iter()
        .filter(|i| {
            i.root == query
                || i.id == query
                || Crystal::parse(&i.content.to_string()).is_ok_and(|c| matches(&c, query))
        })
        .collect();
    if found.len() != 1 {
        bail!(
            "Expected one dictionary entry, found {}; use its content root",
            found.len()
        );
    }
    Ok(found.into_iter().next().unwrap())
}
fn dependency_roots(entry: &Entry, entries: &BTreeMap<String, Entry>) -> Result<BTreeSet<String>> {
    let c = crystal_entry(entry)?;
    let mut roots = BTreeSet::from([entry.root.0.clone()]);
    if c.kind == CrystalKind::Word {
        for ch in c.id.to_lowercase().chars() {
            let letter = entries
                .values()
                .find(|e| {
                    e.word.spelling == ch.to_string()
                        && e.word.language == "und"
                        && e.state == State::Minted
                        && crystal_entry(e).is_ok_and(|c| c.kind == CrystalKind::Letter)
                })
                .ok_or_else(|| anyhow!("Missing verified minted dependency '{ch}'"))?;
            roots.insert(letter.root.0.clone());
        }
    }
    Ok(roots)
}
pub fn export(root: &Path, owner: &str, query: &str, anchor: &str) -> Result<Proof> {
    let (events, key) = public_snapshot(root, owner, Some(anchor))?;
    let entries = reduce(&events, &key, false)?;
    let mut candidates = entries
        .values()
        .filter(|e| e.root.0 == query || crystal_entry(e).is_ok_and(|c| matches(&c, query)))
        .cloned()
        .collect::<Vec<_>>();
    if candidates.len() != 1 {
        bail!(
            "Expected one signed lifecycle entry, found {}; use its content root",
            candidates.len()
        );
    }
    let entry = candidates.pop().unwrap();
    if entry.state != State::Minted {
        bail!("Export requires a verified minted entry");
    }
    let word = crystal_entry(&entry)?.kind == CrystalKind::Word;
    let roots = dependency_roots(&entry, &entries)?;
    let mut hashes = BTreeSet::new();
    let mut op_ids = BTreeSet::new();
    for a in &events {
        let e = &a.event;
        if action(e) == "dictionary.outcome"
            && d(e)["canonical"] == true
            && d(e)["receipt"]["status"] == "accepted"
            && d(e)["receipt"]["entry"]["root"]
                .as_str()
                .is_some_and(|r| roots.contains(r))
        {
            let ih = text(d(e), "intent_hash")?;
            let intent = events
                .iter()
                .find(|a| a.event["hash"] == ih)
                .ok_or_else(|| anyhow!("Missing intent"))?;
            let request: Request = serde_json::from_value(d(&intent.event)["request"].clone())?;
            if matches!(
                request.command,
                Command::Draft { .. } | Command::Validate { .. } | Command::Mint { .. }
            ) {
                hashes.insert(text(e, "hash")?.to_string());
                hashes.insert(ih.to_string());
                op_ids.insert(request.op_id.0);
            }
        }
    }
    let selected = events
        .into_iter()
        .filter(|a| {
            hashes.contains(a.event["hash"].as_str().unwrap_or(""))
                || (action(&a.event) == "word.mint"
                    && d(&a.event)["root"]
                        .as_str()
                        .is_some_and(|r| roots.contains(r))
                    && d(&a.event)["op_id"]
                        .as_str()
                        .is_some_and(|id| op_ids.contains(id)))
        })
        .collect();
    let proof = Proof {
        format: if word {
            "ans-word-dependency-path-v1"
        } else {
            "ans-character-path-v1"
        }
        .into(),
        entry,
        attestations: selected,
    };
    verify(&proof, anchor)?;
    Ok(proof)
}
pub fn verify(proof: &Proof, anchor: &str) -> Result<Value> {
    let c = crystal_entry(&proof.entry)?;
    let word = c.kind == CrystalKind::Word;
    if proof.format
        != if word {
            "ans-word-dependency-path-v1"
        } else {
            "ans-character-path-v1"
        }
        || proof.entry.state != State::Minted
        || proof.attestations.is_empty()
    {
        bail!("Unsupported or incomplete dictionary proof");
    }
    let entries = reduce(&proof.attestations, anchor, true)?;
    let roots = dependency_roots(&proof.entry, &entries)?;
    if proof.attestations.len() != roots.len() * 7
        || entries.keys().cloned().collect::<BTreeSet<_>>() != roots
        || entries.values().any(|e| e.state != State::Minted)
        || serde_json::to_value(
            entries
                .get(&proof.entry.root.0)
                .ok_or_else(|| anyhow!("Missing proven root"))?,
        )? != serde_json::to_value(&proof.entry)?
    {
        bail!("Proof entry/dependency closure does not match the attested transition path");
    }
    let native = proof
        .attestations
        .iter()
        .find(|a| action(&a.event) == "word.mint" && d(&a.event)["root"] == proof.entry.root.0)
        .ok_or_else(|| anyhow!("Missing proven native mint"))?;
    let mut result = json!({"path_verified":true,"root":proof.entry.root,"identity":proof.entry.word,"attested_state":"minted","at_sequence":seq(&proof.attestations.last().unwrap().event)?,"expected_signer":anchor,"dependency_count":roots.len()-1,"dependencies":d(&native.event)["letters"],"scope":"selected signed transition and dependency paths with block payload commitments; not complete/current history, consensus, global naming, factual truth, or outer block signature"});
    result[if word {
        "word_dependency_path_verified"
    } else {
        "character_path_verified"
    }] = json!(true);
    Ok(result)
}
pub fn summary(record: &Item, lang: Option<&str>, limit: usize) -> Result<Value> {
    let c = Crystal::parse(&serde_json::to_string(&record.content)?)?;
    let pick = |kind: &str| {
        c.of_kind(kind)
            .filter(|l| lang.is_none_or(|x| l.get("lang") == Some(x)))
            .take(limit)
            .map(|l| l.to_value())
            .collect::<Vec<_>>()
    };
    Ok(
        json!({"word":c.id,"root":c.root,"index":c.index(),"leaves":c.leaves.len(),"senses":pick("sense"),"translations":pick("translation"),"forms":pick("form"),"exec":pick("exec"),"provenance":record.provenance,"lifecycle":record.lifecycle,"minted_block":record.minted_block,"signer":record.signer,"trust":record.trust,"content_check":"SHA3 Merkle root and identity recomputed; not linguistic truth"}),
    )
}
pub fn legacy_list(root: &Path, owner: &str) -> Result<Value> {
    let entries = browse(root, owner, None)?;
    let crystals=entries.iter().map(|i|{let c=Crystal::parse(&i.content.to_string())?;Ok(json!({"file":c.file_name(),"id":i.id,"root":i.root,"leaves":c.leaves.len(),"minted_block":i.minted_block,"provenance":i.provenance,"lifecycle":i.lifecycle,"trust":i.trust}))}).collect::<Result<Vec<_>>>()?;
    let node = std::fs::read_to_string(root.join("node_id"))
        .ok()
        .map(|s| s.trim().to_owned());
    Ok(
        json!({"node":node,"crystals":crystals,"read_only":true,"peer_mint_claims":"not treated as verified lifecycle state"}),
    )
}
pub fn cli(root: &Path, owner: &str, args: &[String]) -> Result<Value> {
    let mut args = args.to_vec();
    let anchor = if let Some(i) = args.iter().position(|a| a == "--expect-key") {
        if i + 1 >= args.len() {
            bail!("--expect-key requires a public key");
        }
        let key = args.remove(i + 1);
        args.remove(i);
        Some(key)
    } else {
        None
    };
    match args.as_slice() {
        [cmd] if cmd=="list" => Ok(json!({"entries":browse(root,owner,anchor.as_deref())?,"read_only":true,"execution_enabled":false})),
        [cmd,query] if cmd=="show" => Ok(serde_json::to_value(show(root,owner,query,anchor.as_deref())?)?),
        [cmd,query] if cmd=="export" => Ok(serde_json::to_value(export(root,owner,query,anchor.as_deref().ok_or_else(||anyhow!("Export requires an external --expect-key public trust anchor"))?)?)?),
        [cmd,path] if cmd=="verify" => { let proof:Proof=serde_json::from_slice(&read(Path::new(path))?)?;verify(&proof,anchor.as_deref().ok_or_else(||anyhow!("Verification requires an external --expect-key public trust anchor"))?) },
        _=>bail!("Usage: dictionary list | show WORD_OR_ROOT | export WORD_OR_ROOT --expect-key HEX | verify PROOF_FILE --expect-key HEX")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dictionary::{ContentRoot, OperationId, WordId};
    struct Home(std::path::PathBuf);
    impl Home {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "ans-public-reader-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ));
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        fn dir(&self) -> std::path::PathBuf {
            self.0.join("custodians/alice")
        }
        fn fixture() -> Value {
            serde_json::from_str(include_str!("../assets/crystals/u0072.crystal.json")).unwrap()
        }
        fn initialize(&self) {
            crate::exploit::initialize("alice", &self.dir()).unwrap();
        }
        fn apply(&self, id: &str, command: Command) {
            let result = crate::dictionary::apply(
                &self.0,
                "alice",
                Request {
                    op_id: OperationId(id.into()),
                    command,
                },
            )
            .unwrap();
            assert_eq!(result["receipt"]["status"], "accepted");
        }
        fn mint(&self) -> String {
            self.initialize();
            let c = Self::fixture();
            let root = ContentRoot(c["root"].as_str().unwrap().into());
            self.apply(
                "draft",
                Command::Draft {
                    word: WordId {
                        language: "und".into(),
                        spelling: "r".into(),
                    },
                    crystal: c,
                },
            );
            self.apply("validate", Command::Validate { root: root.clone() });
            self.apply("mint", Command::Mint { root });
            self.key()
        }
        fn key(&self) -> String {
            let s = std::fs::read_to_string(self.dir().join("chain.ndjson")).unwrap();
            serde_json::from_str::<Value>(s.lines().next().unwrap()).unwrap()["xmss"]["pk"]
                .as_str()
                .unwrap()
                .into()
        }
    }
    impl Drop for Home {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn files(root: &Path) -> BTreeMap<String, Vec<u8>> {
        fn visit(root: &Path, p: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
            for f in std::fs::read_dir(p).unwrap() {
                let p = f.unwrap().path();
                if p.is_dir() {
                    visit(root, &p, out)
                } else {
                    out.insert(
                        p.strip_prefix(root).unwrap().to_string_lossy().into(),
                        std::fs::read(&p).unwrap(),
                    );
                }
            }
        }
        let mut out = BTreeMap::new();
        visit(root, root, &mut out);
        out
    }
    #[test]
    fn public_character_proof_is_anchored_selective_read_only_and_tamper_evident() {
        let h = Home::new();
        let key = h.mint();
        // A separate cached word must remain unminted and must not leak into the proof.
        ans_dict::book::Book::open(&h.0.join("book"))
            .unwrap()
            .add_text(include_str!("../assets/crystals/rdzen.crystal.json"))
            .unwrap();
        // Reader works without either private signer file, even while writer lock is held.
        for f in ["xmss-demo.seed", "xmss-demo.state"] {
            std::fs::remove_file(h.dir().join(f)).unwrap();
        }
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(h.dir().join("writer.lock"))
            .unwrap();
        fs4::FileExt::try_lock_exclusive(&lock).unwrap();
        let before = files(&h.0);
        let entries = browse(&h.0, "alice", Some(&key)).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries.iter().find(|i| i.id == "rdzeń").unwrap().lifecycle,
            None
        );
        assert_eq!(
            show(&h.0, "alice", "r", Some(&key)).unwrap().lifecycle,
            Some(State::Minted)
        );
        assert!(browse(&h.0, "alice", Some(&"00".repeat(64))).is_err());
        let proof = export(&h.0, "alice", "r", &key).unwrap();
        let encoded = serde_json::to_string(&proof).unwrap();
        assert!(
            !encoded.contains("rdzeń")
                && !encoded.contains("custodian.install")
                && !encoded.contains("xmss-demo")
        );
        assert_eq!(
            verify(&proof, &key).unwrap()["character_path_verified"],
            true
        );
        assert!(verify(&proof, &"00".repeat(64)).is_err());
        assert!(cli(&h.0, "alice", &["export".into(), "r".into()]).is_err());
        for field in ["character", "schema", "root", "leaves"] {
            let mut bad = proof.clone();
            bad.entry.crystal[field] = json!("tampered");
            assert!(verify(&bad, &key).is_err());
        }
        let mut bad = proof.clone();
        bad.entry.root.0 = "00".repeat(32);
        assert!(verify(&bad, &key).is_err());
        let mut bad = proof.clone();
        bad.attestations[0].event["xmss"]["sig"] = json!("00");
        assert!(verify(&bad, &key).is_err());
        let mut bad = proof.clone();
        bad.attestations.retain(|a| action(&a.event) != "word.mint");
        assert!(verify(&bad, &key).is_err());
        let mut bad = proof.clone();
        bad.attestations.swap(1, 3);
        assert!(verify(&bad, &key).is_err());
        let mut bad = proof.clone();
        bad.attestations.push(bad.attestations[5].clone());
        assert!(verify(&bad, &key).is_err());
        let mut bad = proof.clone();
        bad.attestations[5].block.block_hash_hex = "00".repeat(32);
        assert!(verify(&bad, &key).is_err());
        let mut bad = proof.clone();
        bad.attestations[5].block.app_events[0].payload_b64 = "dGFtcGVy".into();
        assert!(verify(&bad, &key).is_err());
        // Missing cache is read from the signed snapshot without repair.
        let cache = h.0.join("book/u0072.crystal.json");
        let cache_bytes = std::fs::read(&cache).unwrap();
        std::fs::remove_file(&cache).unwrap();
        assert_eq!(
            show(&h.0, "alice", "r", Some(&key)).unwrap().lifecycle,
            Some(State::Minted)
        );
        assert!(!cache.exists());
        std::fs::write(&cache, cache_bytes).unwrap();
        // An in-flight/incomplete kernel projection is not a valid snapshot.
        let state_path = h.dir().join("kernel/state.json");
        let state_bytes = std::fs::read(&state_path).unwrap();
        let mut state: Value = serde_json::from_slice(&state_bytes).unwrap();
        state["best_height"] = json!(0);
        std::fs::write(&state_path, state.to_string()).unwrap();
        assert!(browse(&h.0, "alice", Some(&key)).is_err());
        std::fs::write(&state_path, state_bytes).unwrap();
        assert_eq!(files(&h.0), before);
        // Offline verification needs ONLY the selected public bundle and anchor.
        let standalone = Home::new();
        let path = standalone.0.join("proof.json");
        std::fs::write(&path, encoded).unwrap();
        let before = files(&standalone.0);
        assert_eq!(
            cli(
                &standalone.0,
                "",
                &[
                    "verify".into(),
                    path.to_string_lossy().into(),
                    "--expect-key".into(),
                    key
                ]
            )
            .unwrap()["character_path_verified"],
            true
        );
        assert_eq!(files(&standalone.0), before);
    }
    #[test]
    fn pinned_word_dependency_closure_round_trips_without_a_signer() {
        let h = Home::new();
        h.initialize();
        let word: Value =
            serde_json::from_str(include_str!("../assets/crystals/rdzen.crystal.json")).unwrap();
        let wr = ContentRoot(word["root"].as_str().unwrap().into());
        h.apply(
            "word-draft",
            Command::Draft {
                word: WordId {
                    language: "pl".into(),
                    spelling: "rdzeń".into(),
                },
                crystal: word,
            },
        );
        h.apply("word-validate", Command::Validate { root: wr.clone() });
        let early = crate::dictionary::apply(
            &h.0,
            "alice",
            Request {
                op_id: OperationId("word-missing-letters".into()),
                command: Command::Mint { root: wr.clone() },
            },
        )
        .unwrap();
        assert_eq!(early["receipt"]["status"], "rejected");
        let fixtures = [
            include_str!("../assets/crystals/u0072.crystal.json"),
            include_str!("../assets/crystals/u0064.crystal.json"),
            include_str!("../assets/crystals/u007a.crystal.json"),
            include_str!("../assets/crystals/u0065.crystal.json"),
            include_str!("../assets/crystals/u0144.crystal.json"),
        ];
        for (i, fixture) in fixtures.iter().enumerate() {
            let c: Value = serde_json::from_str(fixture).unwrap();
            let root = ContentRoot(c["root"].as_str().unwrap().into());
            let spelling = c["character"].as_str().unwrap().to_string();
            h.apply(
                &format!("char-{i}-draft"),
                Command::Draft {
                    word: WordId {
                        language: "und".into(),
                        spelling,
                    },
                    crystal: c,
                },
            );
            h.apply(
                &format!("char-{i}-validate"),
                Command::Validate { root: root.clone() },
            );
            h.apply(&format!("char-{i}-mint"), Command::Mint { root });
        }
        h.apply("word-mint", Command::Mint { root: wr.clone() });
        // A retry and rejected duplicate effects must not add another proof path.
        h.apply("word-mint", Command::Mint { root: wr.clone() });
        let rejected = crate::dictionary::apply(
            &h.0,
            "alice",
            Request {
                op_id: OperationId("duplicate-word-mint".into()),
                command: Command::Mint { root: wr.clone() },
            },
        )
        .unwrap();
        assert_eq!(rejected["receipt"]["status"], "rejected");
        let key = h.key();
        for file in ["xmss-demo.seed", "xmss-demo.state"] {
            std::fs::remove_file(h.dir().join(file)).unwrap();
        }
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(h.dir().join("writer.lock"))
            .unwrap();
        fs4::FileExt::try_lock_exclusive(&lock).unwrap();
        let before = files(&h.0);
        let shown = show(&h.0, "alice", "rdzen", Some(&key)).unwrap();
        assert_eq!(shown.lifecycle, Some(State::Minted));
        assert_eq!(
            shown.root,
            "a8e5657614f0a4721d298b03d9f897bc64e3c4937059ea7a3393b90367a20b52"
        );
        let proof = export(&h.0, "alice", &wr.0, &key).unwrap();
        assert_eq!(proof.format, "ans-word-dependency-path-v1");
        assert_eq!(proof.attestations.len(), 42);
        let result = verify(&proof, &key).unwrap();
        assert_eq!(result["word_dependency_path_verified"], true);
        assert_eq!(result["dependency_count"], 5);
        assert_eq!(result["dependencies"].as_array().unwrap().len(), 5);
        let encoded = serde_json::to_string(&proof).unwrap();
        assert!(
            !encoded.contains("word-missing-letters")
                && !encoded.contains("duplicate-word-mint")
                && !encoded.contains("custodian.install")
        );
        let target = proof
            .attestations
            .iter()
            .position(|a| action(&a.event) == "word.mint" && d(&a.event)["root"] == wr.0)
            .unwrap();
        let mut bad = proof.clone();
        bad.attestations[target].event["body"]["data"]["letters"][0]["root"] =
            json!("00".repeat(32));
        assert!(verify(&bad, &key).is_err());
        let mut bad = proof.clone();
        bad.attestations[target].block.app_events[0].payload_b64 = "dGFtcGVy".into();
        assert!(verify(&bad, &key).is_err());
        let omitted = "5ba8bc33de237191762c45b50d780b6a11769189ceadb8b9bc0999c1eff6def0";
        let mut bad = proof.clone();
        bad.attestations.retain(|a| {
            let e = &a.event;
            d(e)["root"] != omitted
                && d(e)["receipt"]["entry"]["root"] != omitted
                && d(e)["request"]["command"]["root"] != omitted
                && d(e)["request"]["command"]["crystal"]["root"] != omitted
        });
        assert_eq!(bad.attestations.len(), 35);
        assert!(verify(&bad, &key)
            .unwrap_err()
            .to_string()
            .contains("not minted"));
        let mut bad = proof.clone();
        let last = bad.attestations.pop().unwrap();
        bad.attestations.insert(0, last);
        assert!(verify(&bad, &key).is_err());
        let mut bad = proof.clone();
        bad.attestations.push(bad.attestations[target].clone());
        assert!(verify(&bad, &key).is_err());
        assert!(verify(&proof, &"00".repeat(64)).is_err());
        assert_eq!(files(&h.0), before);
        let public = Home::new();
        let path = public.0.join("word.proof.json");
        std::fs::write(&path, encoded).unwrap();
        let before = files(&public.0);
        assert_eq!(
            cli(
                &public.0,
                "",
                &[
                    "verify".into(),
                    path.to_string_lossy().into(),
                    "--expect-key".into(),
                    key
                ]
            )
            .unwrap()["word_dependency_path_verified"],
            true
        );
        assert_eq!(files(&public.0), before);
    }
    #[test]
    fn signed_word_mint_cannot_reach_forward_to_later_character_lifecycles() {
        fn append(h: &Home, id: &str, command: Command, entry: &Entry, native: Option<Value>) {
            let request = Request {
                op_id: OperationId(id.into()),
                command,
            };
            let hash = digest(&serde_json::to_value(&request.command).unwrap()).unwrap();
            let intent = crate::exploit::record_local(
                "alice",
                &h.dir(),
                "dictionary.intent",
                json!({"request":request,"command_digest":hash,"canonical":true}),
            )
            .unwrap();
            if let Some(native) = native {
                crate::exploit::record_local("alice", &h.dir(), "word.mint", native).unwrap();
            }
            crate::exploit::record_local("alice",&h.dir(),"dictionary.outcome",json!({"intent_hash":intent["hash"],"op_id":id,"command_digest":hash,"canonical":true,"receipt":{"status":"accepted","reason":null,"entry":entry}})).unwrap();
        }
        let h = Home::new();
        h.initialize();
        let c: Value =
            serde_json::from_str(include_str!("../assets/crystals/rdzen.crystal.json")).unwrap();
        let root = ContentRoot(c["root"].as_str().unwrap().into());
        h.apply(
            "word-draft",
            Command::Draft {
                word: WordId {
                    language: "pl".into(),
                    spelling: "rdzeń".into(),
                },
                crystal: c.clone(),
            },
        );
        h.apply("word-validate", Command::Validate { root: root.clone() });
        let word = Entry {
            word: WordId {
                language: "pl".into(),
                spelling: "rdzeń".into(),
            },
            root: root.clone(),
            state: State::Minted,
            crystal: c,
        };
        append(
            &h,
            "early-word-mint",
            Command::Mint { root: root.clone() },
            &word,
            Some(
                json!({"op_id":"early-word-mint","word":"rdzeń","root":root,"file":"rdzen.crystal.json","layer":2,"service":"dictionary","letters":[]}),
            ),
        );
        // These genuinely signed valid-looking character transitions occur TOO LATE.
        let c = Home::fixture();
        let lr = ContentRoot(c["root"].as_str().unwrap().into());
        let mut letter = Entry {
            word: WordId {
                language: "und".into(),
                spelling: "r".into(),
            },
            root: lr.clone(),
            state: State::Draft,
            crystal: c.clone(),
        };
        append(
            &h,
            "late-char-draft",
            Command::Draft {
                word: letter.word.clone(),
                crystal: c,
            },
            &letter,
            None,
        );
        letter.state = State::Validated;
        append(
            &h,
            "late-char-validate",
            Command::Validate { root: lr.clone() },
            &letter,
            None,
        );
        letter.state = State::Minted;
        append(
            &h,
            "late-char-mint",
            Command::Mint { root: lr.clone() },
            &letter,
            Some(
                json!({"op_id":"late-char-mint","word":"r","root":lr,"file":"u0072.crystal.json","layer":1,"service":"dictionary","letters":[]}),
            ),
        );
        let journal = std::fs::read_to_string(h.dir().join("chain.ndjson")).unwrap();
        assert!(journal
            .lines()
            .all(|l| crate::exploit::event_valid(&serde_json::from_str::<Value>(l).unwrap())));
        assert!(browse(&h.0, "alice", Some(&h.key()))
            .unwrap_err()
            .to_string()
            .contains("not minted"));
        let before = std::fs::read(h.dir().join("chain.ndjson")).unwrap();
        assert!(crate::dictionary::apply(
            &h.0,
            "alice",
            Request {
                op_id: OperationId("refuse-invalid-word-history".into()),
                command: Command::Inspect { root }
            }
        )
        .is_err());
        assert_eq!(std::fs::read(h.dir().join("chain.ndjson")).unwrap(), before);
    }
    #[test]
    fn signed_receipt_cannot_skip_draft_and_validation_and_duplicate_mints_fail_closed() {
        let h = Home::new();
        h.initialize();
        let c = Home::fixture();
        let root = ContentRoot(c["root"].as_str().unwrap().into());
        let request = Request {
            op_id: OperationId("invalid".into()),
            command: Command::Validate { root: root.clone() },
        };
        let hash = digest(&serde_json::to_value(&request.command).unwrap()).unwrap();
        let intent = crate::exploit::record_local(
            "alice",
            &h.dir(),
            "dictionary.intent",
            json!({"request":request,"command_digest":hash,"canonical":true}),
        )
        .unwrap();
        let entry = Entry {
            word: WordId {
                language: "und".into(),
                spelling: "r".into(),
            },
            root,
            state: State::Minted,
            crystal: c,
        };
        crate::exploit::record_local("alice",&h.dir(),"dictionary.outcome",json!({"intent_hash":intent["hash"],"op_id":"invalid","command_digest":hash,"canonical":true,"receipt":{"status":"accepted","reason":null,"entry":entry}})).unwrap();
        assert!(browse(&h.0, "alice", Some(&h.key()))
            .unwrap_err()
            .to_string()
            .contains("no draft"));
        let before = std::fs::read(h.dir().join("chain.ndjson")).unwrap();
        assert!(crate::dictionary::apply(
            &h.0,
            "alice",
            Request {
                op_id: OperationId("writer-must-refuse-invalid-history".into()),
                command: Command::Inspect {
                    root: ContentRoot("00".repeat(32))
                }
            }
        )
        .is_err());
        assert_eq!(std::fs::read(h.dir().join("chain.ndjson")).unwrap(), before);
        let valid = Home::new();
        let key = valid.mint();
        let chain = std::fs::read_to_string(valid.dir().join("chain.ndjson")).unwrap();
        let native = chain
            .lines()
            .map(|l| serde_json::from_str::<Value>(l).unwrap())
            .find(|e| action(e) == "word.mint")
            .unwrap();
        crate::exploit::record_local("alice", &valid.dir(), "word.mint", d(&native).clone())
            .unwrap();
        assert!(browse(&valid.0, "alice", Some(&key))
            .unwrap_err()
            .to_string()
            .contains("Duplicate native mint"));
    }
    #[test]
    fn signed_minted_receipt_requires_an_exact_native_effect() {
        for missing in [true, false] {
            let h = Home::new();
            h.initialize();
            let c = Home::fixture();
            let root = ContentRoot(c["root"].as_str().unwrap().into());
            h.apply(
                "draft",
                Command::Draft {
                    word: WordId {
                        language: "und".into(),
                        spelling: "r".into(),
                    },
                    crystal: c.clone(),
                },
            );
            h.apply("validate", Command::Validate { root: root.clone() });
            let request = Request {
                op_id: OperationId("forged-mint".into()),
                command: Command::Mint { root: root.clone() },
            };
            let hash = digest(&serde_json::to_value(&request.command).unwrap()).unwrap();
            let intent = crate::exploit::record_local(
                "alice",
                &h.dir(),
                "dictionary.intent",
                json!({"request":request,"command_digest":hash,"canonical":true}),
            )
            .unwrap();
            if !missing {
                crate::exploit::record_local("alice",&h.dir(),"word.mint",json!({"op_id":"forged-mint","root":root,"word":"x","file":"u0072.crystal.json","layer":1,"service":"dictionary","letters":[]})).unwrap();
            }
            let entry = Entry {
                word: WordId {
                    language: "und".into(),
                    spelling: "r".into(),
                },
                root,
                state: State::Minted,
                crystal: c,
            };
            crate::exploit::record_local("alice",&h.dir(),"dictionary.outcome",json!({"intent_hash":intent["hash"],"op_id":"forged-mint","command_digest":hash,"canonical":true,"receipt":{"status":"accepted","reason":null,"entry":entry}})).unwrap();
            let error = browse(&h.0, "alice", Some(&h.key()))
                .unwrap_err()
                .to_string();
            assert!(
                error.contains(if missing {
                    "Missing native mint"
                } else {
                    "Native mint identity"
                }),
                "{error}"
            );
        }
    }
    #[test]
    fn empty_and_imported_browse_does_not_create_state_and_corruption_is_not_hidden() {
        let h = Home::new();
        let before = files(&h.0);
        assert!(browse(&h.0, "", None).unwrap().is_empty());
        assert_eq!(files(&h.0), before);
        let b = ans_dict::book::Book::open(&h.0.join("book")).unwrap();
        let c = Home::fixture();
        let filename = "u0072.crystal.json";
        b.add_text(&c.to_string()).unwrap();
        let before = files(&h.0);
        let i = show(&h.0, "", "r", None).unwrap();
        assert_eq!(i.provenance, "cache_only_imported");
        assert_eq!(i.lifecycle, None);
        assert_eq!(files(&h.0), before);
        for key in ["character", "schema", "root", "leaves"] {
            let mut v = c.clone();
            v[key] = json!("tampered");
            std::fs::write(b.dir.join(filename), v.to_string()).unwrap();
            let before = files(&h.0);
            assert!(browse(&h.0, "", None).is_err());
            assert_eq!(files(&h.0), before);
        }
    }
}
