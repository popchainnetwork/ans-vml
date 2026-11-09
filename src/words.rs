// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Paweł Piekut / Pplastechniek
//! CLI for the word book: book seed|add|list|import-kaikki|serve, mint, delegate, revoke, run, sync.
//! Local only: the genesis chain is the local custodian journal under ANS_HOME. No mainnet.
use crate::{exploit, rule};
use ans_dict::{book::Book, exec, forms, import, sync, Crystal};
use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

const SEED: [&str; 6] = [
    include_str!("../assets/crystals/rdzen.crystal.json"),
    include_str!("../assets/crystals/u0072.crystal.json"),
    include_str!("../assets/crystals/u0064.crystal.json"),
    include_str!("../assets/crystals/u007a.crystal.json"),
    include_str!("../assets/crystals/u0065.crystal.json"),
    include_str!("../assets/crystals/u0144.crystal.json"),
];

fn book(root: &Path) -> Result<Book> { Book::open(&root.join("book")) }
fn cdir(root: &Path, actor: &str) -> Result<PathBuf> {
    if actor.is_empty() { bail!("no custodian: run `ans init <word>` first or pass --as WORD"); }
    let d = root.join("custodians").join(actor);
    if !d.exists() { bail!("custodian {actor} not initialized in this ANS_HOME"); }
    Ok(d)
}
fn node_id(root: &Path) -> Result<String> {
    let p = root.join("node_id");
    if let Ok(s) = std::fs::read_to_string(&p) { return Ok(s.trim().into()); }
    let mut b = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
    let id = format!("node-{}", hex::encode(b));
    std::fs::create_dir_all(root)?;
    std::fs::write(&p, &id)?;
    Ok(id)
}
fn proofs_dir(root: &Path) -> PathBuf { root.join("book-proofs") }
fn peer_proofs(root: &Path) -> Vec<Value> {
    std::fs::read_dir(proofs_dir(root)).into_iter().flatten().filter_map(|e| serde_json::from_str(&std::fs::read_to_string(e.ok()?.path()).ok()?).ok()).collect()
}
fn journal(root: &Path, actor: &str) -> Result<Vec<Value>> {
    match cdir(root, actor) { Ok(d) => exploit::journal(actor, &d), Err(_) => Ok(vec![]) }
}
fn find(b: &Book, w: &str) -> Result<Crystal> {
    let f = format!("{w}.crystal.json");
    if ans_dict::book::valid_file_name(&f) { if let Ok(c) = b.get(&f) { return Ok(c); } }
    // Single Unicode scalar: also resolve letter crystals stored as uXXXX.crystal.json.
    if w.chars().count() == 1 {
        if let Some(ch) = w.chars().next() {
            let letter = format!("u{:04x}.crystal.json", ch as u32);
            if let Ok(c) = b.get(&letter) { return Ok(c); }
        }
    }
    b.lookup(w)
}
fn valid(e: &Value) -> bool { exploit::event_valid(e) }
pub const ALPHABET: &str = "abcdefghijklmnopqrstuvwxyząćęłńóśźż";
/// Minted letter lookup against the book + local journal + stored peer proofs (read fresh each call).
fn letter_lookup<'a>(root: &Path, j: &'a [Value]) -> impl Fn(char) -> Option<(String, Value)> + 'a {
    let root = root.to_path_buf();
    move |ch: char| {
        let c = Book::open(&root.join("book")).ok()?.get(&format!("u{:04x}.crystal.json", ch as u32)).ok()?;
        let p = peer_proofs(&root);
        rule::mint_proof(&c.root, j, &p, &valid).map(|e| (c.root.clone(), e["seq"].clone()))
    }
}
fn mint_one(root: &Path, actor: &str, _d: &Path, c: &Crystal) -> Result<Value> {
    // Single ledger: legacy mint CLI adopts the crystal through the typed dictionary lifecycle.
    crate::dictionary::adopt_book_crystal(root, actor, c)
}

pub fn handle(cmd: &str, args: &[String], root: &Path, actor: &str) -> Result<Option<Value>> {
    let arg = |i: usize, usage: &str| args.get(i).cloned().ok_or_else(|| anyhow!("usage: {usage}"));
    let flag = |f: &str| args.iter().position(|s| s == f).and_then(|i| args.get(i + 1)).cloned();
    Ok(Some(match (cmd, args.get(1).map(String::as_str)) {
        ("book", Some("seed")) => {
            let b = book(root)?;
            let mut added = vec![];
            for t in SEED { let (f, c) = b.add_text(t)?; added.push(json!({"file":f,"root":c.root})); }
            let h = exec::exec_word("hash", "sha3_256", "run", "sha3", "0.10.9", rule::LOCK, "compute SHA3-256 of a string")?;
            added.push(json!({"file":b.add(&h)?,"root":h.root}));
            json!({"ok":true,"book":b.dir,"node":node_id(root)?,"added":added,"minted":false})
        }
        ("book", Some("add")) => {
            let (f, c) = book(root)?.add_text(&std::fs::read_to_string(arg(2, "ans book add <crystal.json>")?)?)?;
            json!({"ok":true,"file":f,"root":c.root,"minted":false,"next":format!("ans --as OWNER mint {} (dictionary lifecycle)", c.id)})
        }
        ("book", Some("import-kaikki")) => {
            let (file, w, lang) = (arg(2, "ans book import-kaikki <file.jsonl> <word> <lang> --ucd DIR")?, arg(3, "word")?, arg(4, "lang")?);
            let ucd = forms::Ucd::load(Path::new(&flag("--ucd").ok_or_else(|| anyhow!("--ucd DIR (UnicodeData/Blocks/Scripts)"))?))?;
            let b = book(root)?;
            let letters = w.chars().map(|c| { let l = ucd.letter(c)?; b.add(&l)?; Ok(l) }).collect::<Result<Vec<_>>>()?;
            let c = import::kaikki(&std::fs::read_to_string(&file)?, &w, &lang, &format!("kaikki:{file}"), &letters)?;
            json!({"ok":true,"file":b.add(&c)?,"root":c.root,"leaves":c.leaves.len(),"letters":letters.iter().map(|l| json!({"char":l.id,"root":l.root})).collect::<Vec<_>>()})
        }
        ("book", Some("list")) => {
            crate::dictionary_read::legacy_list(root,actor)?
        }
        ("book", Some("serve")) => {
            let port: u16 = flag("--port").ok_or_else(|| anyhow!("ans book serve --port N"))?.parse()?;
            let b = book(root)?; let me = node_id(root)?;
            let l = std::net::TcpListener::bind(("127.0.0.1", port))?;
            eprintln!("serving book of {me} on http://127.0.0.1:{port} (localhost only)");
            let index = || -> Result<Value> {
                let j = journal(root, actor)?; let p = peer_proofs(root);
                let origins = origins(root);
                Ok(json!({"node":me,"crystals":b.list()?.into_iter().map(|(f, c)| {
                    let proof = rule::mint_proof(&c.root, &j, &p, &valid).cloned();
                    json!({"file":f,"root":c.root,"kind":if c.kind == ans_dict::CrystalKind::Letter {"letter"} else {"word"},"origin":origins.get(&c.root).cloned().unwrap_or(json!(me.clone())),"proof":proof})
                }).collect::<Vec<_>>()}))
            };
            sync::serve(l, &b, &index, flag("--requests").map(|r| r.parse()).transpose()?)?;
            json!({"ok":true,"stopped":true})
        }
        ("mint-alphabet", _) => {
            let d = cdir(root, actor)?;
            let ucd = forms::Ucd::load(Path::new(&flag("--ucd").ok_or_else(|| anyhow!("ans mint-alphabet --ucd DIR"))?))?;
            let b = book(root)?;
            let mut res = vec![];
            for ch in ALPHABET.chars() { let l = ucd.letter(ch)?; b.add(&l)?; res.push(mint_one(root, actor, &d, &l)?); }
            json!({"ok":true,"layer":1,"service":"dictionary","lifecycle_adapter":"adopt_book_crystal","alphabet":ALPHABET,"minted":res,"network":"none: local journal only"})
        }
        ("mint", _) => {
            let d = cdir(root, actor)?;
            let b = book(root)?;
            let mut targets: Vec<Crystal> = if args.iter().any(|a| a == "--all") { b.list()?.into_iter().map(|x| x.1).collect() } else { vec![find(&b, &arg(1, "ans mint <word>|--all")?)?] };
            targets.sort_by_key(|c| c.kind != ans_dict::CrystalKind::Letter); // layer 1 before layer 2
            let mut res = vec![];
            for c in targets { res.push(match mint_one(root, actor, &d, &c) { Ok(v) => v, Err(e) => json!({"word":c.id,"root":c.root,"refused":e.to_string()}) }); }
            json!({"ok":true,"custodian":actor,"service":"dictionary","lifecycle_adapter":"adopt_book_crystal","minted":res,"network":"none: local journal only","private_key":"never printed"})
        }
        ("mint-meaning", _) => {
            let usage = "ans mint-meaning <word> <lang> <text>";
            cdir(root, actor)?;
            let c = find(&book(root)?, &arg(1, usage)?)?;
            let (lang, text) = (arg(2, usage)?, args[3.min(args.len())..].join(" "));
            if text.is_empty() { bail!("usage: {usage}"); }
            if c.kind == ans_dict::CrystalKind::Letter { bail!("meanings attach to words, not letters"); }
            let command = crate::dictionary::Command::Meaning { root: crate::dictionary::ContentRoot(c.root.clone()), lang: lang.clone(), text };
            let mut v = crate::dictionary::legacy_annotation(root, actor, &c, command)?;
            v["layer"] = json!(3);
            v["lang"] = json!(lang);
            v
        }
        ("delegate", _) | ("revoke", _) => {
            let usage = "ans delegate|revoke <word> <scope>";
            cdir(root, actor)?;
            let c = find(&book(root)?, &arg(1, usage)?)?;
            let scope = arg(2, usage)?;
            let target = crate::dictionary::ContentRoot(c.root.clone());
            let command = if cmd == "delegate" {
                crate::dictionary::Command::Delegate { root: target, scope: scope.clone() }
            } else {
                crate::dictionary::Command::Revoke { root: target, scope: scope.clone() }
            };
            let mut v = crate::dictionary::legacy_annotation(root, actor, &c, command)?;
            v["scope"] = json!(scope);
            v
        }
        ("run", _) => {
            // Execution is routed through dictionary rules: strict-replayed minted lifecycle,
            // an active dictionary delegation for the scope, then the word rule. Fails closed.
            let c = find(&book(root)?, &arg(1, "ans run <word> [--plan] [input]")?)?;
            let scope = flag("--scope").unwrap_or_else(|| "run".into());
            let j = journal(root, actor)?;
            let lifecycle = crate::dictionary_read::show(root, actor, &c.root, None).ok().and_then(|i| i.lifecycle);
            if lifecycle != Some(crate::dictionary::State::Minted) {
                bail!("refused: {} is not minted: no minted dictionary lifecycle; execution requires dictionary rules", c.id);
            }
            if !crate::dictionary::active_grants(&j).contains(&(c.root.clone(), scope.clone())) {
                bail!("refused: no active dictionary delegation for scope {scope}; run `ans --as OWNER delegate {} {scope}`", c.id);
            }
            let mut v = rule::check(&c, rule::Use::Run { scope: &scope }, &j, &[], &valid, &letter_lookup(root, &j));
            if v["accept"] != true { bail!("refused: {}", v["reason"].as_str().unwrap_or("")); }
            v["service"] = json!("dictionary");
            if args.iter().any(|a| a == "--plan") { v["dry_run"] = json!(true); return Ok(Some(v)); }
            let input = args.iter().skip(2).find(|a| !a.starts_with("--") && Some(a.as_str()) != Some(scope.as_str())).cloned().unwrap_or_default();
            v["output"] = json!(exec::run_builtin(v["resolved"]["function"].as_str().unwrap(), &input)?);
            v["input"] = json!(input);
            v
        }
        ("sync", _) => {
            let peer = arg(1, "ans sync http://127.0.0.1:PORT")?;
            let b = book(root)?; let me = node_id(root)?;
            let j = journal(root, actor)?;
            let rule_fn = |c: &Crystal, e: &Value| -> Result<()> {
                let proofs: Vec<Value> = e["proof"].is_object().then(|| e["proof"].clone()).into_iter().collect();
                let v = rule::check(c, rule::Use::Store, &j, &proofs, &valid, &letter_lookup(root, &j));
                if v["accept"] != true { bail!("{}", v["reason"].as_str().unwrap_or("rule rejected")); }
                if let Some(p) = proofs.first() { std::fs::create_dir_all(proofs_dir(root))?; std::fs::write(proofs_dir(root).join(format!("{}.json", c.root)), p.to_string())?; }
                Ok(())
            };
            let recs = sync::pull(&peer, &b, &me, &root.join("sync.log.jsonl"), &rule_fn)?;
            let count = |s: &str| recs.iter().filter(|r| r["status"] == s).count();
            json!({"ok":true,"node":me,"accepted":count("accepted"),"unchanged":count("unchanged"),"rejected":count("rejected"),"records":recs,"log":root.join("sync.log.jsonl")})
        }
        _ => return Ok(None),
    }))
}

fn origins(root: &Path) -> std::collections::HashMap<String, Value> {
    std::fs::read_to_string(root.join("sync.log.jsonl")).unwrap_or_default().lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|r| r["status"] == "accepted")
        .map(|r| (r["root"].as_str().unwrap_or("").to_string(), r["origin"].clone())).collect()
}

/// Dictionary tools for models over the core MCP stdio server. Models can read, propose
/// and plan; minting and delegation stay with the custodian CLI (models never sign).
pub fn mcp_tools() -> Vec<Value> {
    let w = json!({"type":"object","properties":{"word":{"type":"string"}},"required":["word"]});
    vec![
        json!({"name":"dictionary_propose","description":"Prepare a typed dictionary lifecycle request for explicit offline custodian approval; never signs or executes","inputSchema":{"type":"object","properties":{"op_id":{"type":"string"},"command":{"type":"object"}},"required":["op_id","command"]}}),
        json!({"name":"word","description":"Look up a word crystal in the local book (any translation/form, diacritic-insensitive); root is re-verified","inputSchema":w}),
        json!({"name":"list_words","description":"Read public dictionary content with provenance; mint block is present only for a verified lifecycle native mint, null otherwise","inputSchema":{"type":"object","properties":{}}}),
        json!({"name":"mint_request","description":"Propose minting a word: runs the rule dry and queues a request. Does NOT mint or sign. Custodian approves with `ans mint`, which adopts the book crystal through the typed dictionary draft→validate→mint lifecycle","inputSchema":w}),
        json!({"name":"run_plan","description":"Dry-run an executable word: rule check (minted, letters minted, delegation) and pinned package/hash resolution","inputSchema":w}),
        json!({"name":"run","description":"Run a minted, rule-accepted, delegated executable word (built-in functions only)","inputSchema":{"type":"object","properties":{"word":{"type":"string"},"input":{"type":"string"}},"required":["word"]}}),
    ]
}

pub fn mcp_call(name: &str, a: &Value, root: &Path, actor: &str) -> Option<Result<Value>> {
    let w = a["word"].as_str().unwrap_or("").to_string();
    let argv = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    Some(match name {
        "dictionary_propose" => crate::dictionary::proposal(a.clone()),
        "word" => crate::dictionary_read::show(root,actor,&w,None).and_then(|record|crate::dictionary_read::summary(&record,None,20)),
        "list_words" => handle("book", &argv(&["book", "list"]), root, actor).map(Option::unwrap),
        "run_plan" => handle("run", &argv(&["run", &w, "--plan"]), root, actor).map(Option::unwrap),
        "run" => handle("run", &argv(&["run", &w, a["input"].as_str().unwrap_or("")]), root, actor).map(Option::unwrap),
        "mint_request" => (|| {
            let b = book(root)?; let c = find(&b, &w)?;
            let j = journal(root, actor)?;
            let kind = rule::kind(&c).map(|k| format!("{k:?}"));
            let letters = rule::letters_of(&c, &letter_lookup(root, &j));
            let already = rule::mint_proof(&c.root, &j, &peer_proofs(root), &valid).map(|e| e["seq"].clone());
            let ready = kind.is_ok() && letters.is_ok() && already.is_none();
            let kind_s = kind.as_ref().ok().cloned();
            let blocking: Vec<String> = [kind.err().map(|e| e.to_string()), letters.err().map(|e| e.to_string())].into_iter().flatten().collect();
            let req = json!({"word":c.id,"root":c.root,"requested_by":"mcp client (unsigned)","time_unix":sync::now(),"ready":ready,
                "kind":kind_s,"blocking":blocking,"already_minted_block":already});
            if ready { let d = root.join("mint-requests"); std::fs::create_dir_all(&d)?; std::fs::write(d.join(format!("{}.json", c.root)), req.to_string())?; }
            Ok(json!({"request":req,"minted":false,"signed":false,"service":"dictionary","next":format!("custodian approves with: ans --as OWNER mint {} (routes through dictionary lifecycle)", c.id)}))
        })(),
        _ => return None,
    })
}
