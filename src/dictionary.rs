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
            let root = match command {
                Command::Validate { root }
                | Command::Mint { root }
                | Command::Inspect { root }
                | Command::Run { root } => root,
                _ => unreachable!(),
            };
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
                    if crate::rule::mint_proof(&c.root,journal,&[],&crate::exploit::event_valid).is_some() { bail!("A native mint already exists; automatic reconciliation is refused"); }
                    let letters = if c.kind==CrystalKind::Letter { vec![] } else {
                        crate::rule::letters_of(&c,&|ch| entries.values().find(|e|e.word.language=="und" && e.word.spelling==ch.to_string() && e.state==State::Minted && Crystal::parse(&e.crystal.to_string()).is_ok_and(|c|c.kind==CrystalKind::Letter)).and_then(|e|journal.iter().find(|v|action(v)=="word.mint" && data(v)["root"]==e.root.0 && data(v)["layer"]==1)).map(|v|(data(v)["root"].as_str().unwrap_or("").to_owned(),v["seq"].clone())))?
                    };
                    append(owner,dir,"word.mint",json!({"word":c.id,"root":c.root,"file":c.file_name(),"layer":if c.kind==CrystalKind::Letter{1}else{2},"letters":letters,"op_id":req.op_id,"service":"dictionary","chain":"local test journal; not mainnet"}))?;
                    e.state=State::Minted;
                }
                Command::Inspect{..} => {},
                Command::Run{..} => bail!("Execution refused: this service has no executable-permission approval adapter; minting is not permission"),
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
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(dir.join("dictionary.lock"))?;
    fs4::FileExt::try_lock_exclusive(&lock)
        .map_err(|_| anyhow!("Dictionary service busy; retry later"))?;
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
            Some(true) => Receipt {
                status: Status::Interrupted,
                reason: Some(
                    "Previous attempt has no durable outcome; effects are not resumed or inferred"
                        .into(),
                ),
                entry: None,
            },
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
    journal = crate::exploit::journal(owner, &dir)?;
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
/// Models prepare the same typed request but never call the signer through MCP.
pub fn proposal(value: Value) -> Result<Value> {
    let request: Request = serde_json::from_value(value)?;
    Ok(
        json!({"request":request,"executed":false,"signed":false,"next":"Custodian reviews and invokes ans dictionary apply REQUEST.json with explicit --as"}),
    )
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
    Book::open(&root.join("book"))?.add(crystal)?;
    let content = ContentRoot(crystal.root.clone());
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
    }
    let word = word_id_from_crystal(crystal)?;
    let crystal_value: Value = serde_json::from_str(&crystal.to_json())?;
    if lifecycle.is_none() {
        ensure_accepted(apply(
            root,
            owner,
            Request {
                op_id: OperationId(format!("legacy-draft-{}", crystal.root)),
                command: Command::Draft {
                    word: word.clone(),
                    crystal: crystal_value,
                },
            },
        )?, "draft")?;
    }
    if lifecycle.is_none() || lifecycle == Some(State::Draft) {
        ensure_accepted(apply(
            root,
            owner,
            Request {
                op_id: OperationId(format!("legacy-validate-{}", crystal.root)),
                command: Command::Validate {
                    root: content.clone(),
                },
            },
        )?, "validate")?;
    }
    let minted = ensure_accepted(apply(
        root,
        owner,
        Request {
            op_id: OperationId(format!("legacy-mint-{}", crystal.root)),
            command: Command::Mint {
                root: content,
            },
        },
    )?, "mint")?;
    let entry = &minted["receipt"]["entry"];
    let journal = crate::exploit::journal(owner, &dir)?;
    let native = crate::rule::mint_proof(
        &crystal.root,
        &journal,
        &[],
        &crate::exploit::event_valid,
    )
    .ok_or_else(|| anyhow!("Dictionary mint accepted without a native word.mint event"))?;
    Ok(json!({
        "already": false,
        "lifecycle": "minted",
        "service": "dictionary",
        "word": crystal.id,
        "root": crystal.root,
        "block": native["seq"],
        "layer": native["body"]["data"]["layer"],
        "op_id": minted["op_id"],
        "retry": minted["retry"],
        "state": entry["state"],
        "network": "none: local journal only",
        "private_key": "never printed"
    }))
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
  ans dictionary serve PROOF_FILE --expect-key HEX [--port N]

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
invent meanings or rights. `mint-meaning`, delegate/revoke/run remain separate.
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
            json!({"word":"a","root":r,"layer":1,"op_id":"mint-crash"}),
        )
        .unwrap();
        assert_eq!(status(&apply(&h.0, "alice", req).unwrap()), "interrupted");
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
}
