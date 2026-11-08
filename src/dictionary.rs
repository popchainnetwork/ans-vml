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
    let mut entries = BTreeMap::new();
    for e in events
        .iter()
        .filter(|e| action(e) == "dictionary.outcome" && data(e)["canonical"] == true)
    {
        let r: Receipt = serde_json::from_value(data(e)["receipt"].clone())?;
        if r.status == Status::Accepted {
            if let Some(entry) = r.entry {
                entries.insert(entry.root.0.clone(), entry);
            }
        }
    }
    Ok(entries)
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
                        crate::rule::letters_of(&c,&|ch| journal.iter().find(|v|action(v)=="word.mint" && data(v)["word"]==ch.to_string() && data(v)["layer"]==1).map(|v|(data(v)["root"].as_str().unwrap_or("").to_owned(),v["seq"].clone())))?
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
    if req.op_id.0.is_empty() || req.op_id.0.len() > 128 {
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
        finish(
            owner,
            &dir,
            &intent,
            &Receipt {
                status: Status::Interrupted,
                reason: Some(
                    "Previous attempt has no durable outcome; effects are not resumed or inferred"
                        .into(),
                ),
                entry: None,
            },
        )?;
    }
    journal = crate::exploit::journal(owner, &dir)?;
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
        let entries = replay(&journal)?;
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
pub fn cli(root: &Path, owner: &str, args: &[String]) -> Result<Value> {
    if args.len() != 2 || args[0] != "apply" {
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
