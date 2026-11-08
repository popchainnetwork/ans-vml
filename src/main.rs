// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Paweł Piekut / Pplastechniek
//! One local Rust product; no Python, external process launch, keys in output or live networks.
#![allow(dead_code)]
mod chip;
mod crystal;
mod delegation;
mod exploit;
mod grow;
mod pq;
mod word;
mod rule;
mod words;
mod dictionary;
mod dictionary_read;
mod dictionary_web;
use anyhow::{anyhow, bail, Result};
use rand::RngCore;
use serde_json::{json, Value};
use sha2::Digest;
use sha3::Sha3_256;
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::{Ipv4Addr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};
const WORLD: &str = include_str!("../assets/world.html");
const LOGIN: &str = include_str!("../assets/login.html");
const THREE: &str = include_str!("../assets/three.module.js");
const ATOM: &str = include_str!("../assets/atom.svg");
fn js(s: &str) -> Value {
    serde_json::from_str(s).unwrap()
}
fn out(v: Value) {
    println!("{}", serde_json::to_string_pretty(&v).unwrap())
}
fn read_json(p: &Path) -> Result<Value> {
    Ok(serde_json::from_slice(&fs::read(p)?)?)
}
fn save(p: &Path, v: &Value) -> Result<()> {
    fs::write(p, serde_json::to_vec_pretty(v)?)?;
    Ok(())
}
fn normalize(s: &str) -> Result<String> {
    let w = s.trim().trim_end_matches(".ans");
    if w.len() < 3
        || w.len() > 63
        || !w
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    {
        bail!("Owner name must contain 3–63 lowercase ASCII letters, digits, or hyphens")
    };
    Ok(w.into())
}
fn config(root: &Path) -> Result<Value> {
    let path = root.join("config.json");
    if path.exists() {
        return read_json(&path);
    }
    fs::create_dir_all(root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    }
    let port = std::env::var("ANS_WEB_PORT")
        .unwrap_or("9330".into())
        .parse::<u16>()?;
    let c = json!({"schema":1,"anchor":417696,"web_port":port,"current":"","custodians":{},"peers":[{"name":"mesh-local","url":"http://127.0.0.1:8450/health","kind":"health"},{"name":"ans-local","url":"http://127.0.0.1:8443/health","kind":"health"}],"policy":{"remote_posts":false,"no_mainnet":true,"no_models":true,"core_license":"Apache-2.0"}});
    save(&path, &c)?;
    Ok(c)
}
fn mappings(c: &Value) -> BTreeMap<String, u16> {
    c["custodians"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(w, v)| (format!("{w}.ans"), v["port"].as_u64().unwrap() as u16))
        .collect()
}
fn book(root: &Path, c: &Value) -> Result<Value> {
    let entries:Vec<_>=c["custodians"].as_object().unwrap().iter().map(|(word,v)|json!({"word":format!("{word}.ans"),"node":format!("http://127.0.0.1:{}",v["port"]),"source":"local installation","global_ownership_verified":false})).collect();
    let b = json!({"anchor":417696,"genesis":{"kernel":"kernel.ans","messenger":"echo.ans","scope":"local-demo naming; not global registration"},"words":entries,"GEN002":js(include_str!("../assets/gen002-reference.json"))});
    save(&root.join("book.json"), &b)?;
    Ok(b)
}
fn get_local(url: &str) -> Result<Value> {
    let rest = url
        .strip_prefix("http://")
        .ok_or(anyhow!("Only HTTP LAN/localhost discovery"))?;
    let (authority, path) = rest
        .split_once('/')
        .map(|(a, b)| (a, format!("/{b}")))
        .unwrap_or((rest, "/".into()));
    let (host, port) = authority.split_once(':').unwrap_or((authority, "80"));
    let ip: Ipv4Addr = if host == "localhost" {
        "127.0.0.1".parse()?
    } else {
        host.parse()?
    };
    if !ip.is_private() && !ip.is_loopback() {
        bail!("Discovery blocked outside LAN/localhost")
    };
    let port: u16 = port.parse()?;
    let mut stream = TcpStream::connect_timeout(&(ip, port).into(), Duration::from_millis(350))?;
    stream.set_read_timeout(Some(Duration::from_millis(800)))?;
    write!(
        stream,
        "GET {path} HTTP/1.0\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
    )?;
    let mut data = Vec::new();
    stream.take(131072).read_to_end(&mut data)?;
    let text = String::from_utf8_lossy(&data);
    let (header, body) = text.split_once("\r\n\r\n").ok_or(anyhow!("HTTP"))?;
    if !header.lines().next().unwrap_or("").contains(" 200 ") {
        bail!("Peer did not return 200")
    };
    Ok(serde_json::from_str(body).unwrap_or(json!({"response":"non-JSON health reply"})))
}
fn discover(root: &Path, c: &Value) -> Result<Value> {
    let mut peers = Vec::new();
    let mut synced = Vec::new();
    for peer in c["peers"].as_array().unwrap() {
        let url = peer["url"].as_str().unwrap_or("");
        match get_local(url){Ok(v)=>{if peer["kind"]=="ans-book"{if let Some(words)=v["words"].as_array(){for w in words.iter().take(256){if let Some(word)=w["word"].as_str(){if normalize(word).is_ok(){synced.push(json!({"word":word,"source":url,"verified":false}));}}}}}peers.push(json!({"name":peer["name"],"url":url,"online":true,"read_only":true}));},Err(e)=>peers.push(json!({"name":peer["name"],"url":url,"online":false,"error":e.to_string(),"read_only":true}))}
    }
    let report = json!({"anchor":417696,"peers":peers,"remote_registration":false,"existing_Echo_adapter":"not configured; no external account/session accessed","existing_mesh_daemon":"not started or changed","wg0":"untouched","book_source":if synced.is_empty(){"genesis + local custodians"}else{"genesis + local custodians + unverified peer records"},"peer_words":synced});
    save(&root.join("network.json"), &report)?;
    Ok(report)
}
fn local_call(w: &str, op: &str, data: Value) -> Result<Value> {
    let mut b = data;
    b["op"] = json!(op);
    b["_source"] = json!({"surface":"cli","app":"ans","origin":"local ans CLI","device":"local CLI — not hardware attested"});
    let r = exploit::call(w, Some(&b), "/api")?;
    if r["ok"] != true {
        bail!("{}", r["error"].as_str().unwrap_or("operation refused"))
    };
    Ok(r)
}
struct Web {
    config: Value,
    sessions: Mutex<BTreeMap<String, String>>,
}
fn response(
    stream: &mut TcpStream,
    status: u16,
    mime: &str,
    body: &[u8],
    cookie: Option<&str>,
) -> Result<()> {
    write!(stream,"HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n",status,if status==200{"OK"}else{"Error"},mime,body.len())?;
    if let Some(c) = cookie {
        write!(
            stream,
            "Set-Cookie: ans_session={}; HttpOnly; SameSite=Strict; Path=/\r\n",
            c
        )?;
    }
    write!(stream, "\r\n")?;
    stream.write_all(body)?;
    Ok(())
}
fn json_response(
    stream: &mut TcpStream,
    status: u16,
    v: Value,
    cookie: Option<&str>,
) -> Result<()> {
    response(
        stream,
        status,
        "application/json; charset=utf-8",
        &serde_json::to_vec(&v)?,
        cookie,
    )
}
fn web_connection(mut stream: TcpStream, web: Arc<Web>) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut bytes = Vec::new();
    let mut buf = [0u8; 4096];
    let end = loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            bail!("EOF")
        };
        bytes.extend_from_slice(&buf[..n]);
        if let Some(i) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        };
        if bytes.len() > 16384 {
            bail!("Headers")
        }
    };
    let header = String::from_utf8(bytes[..end].to_vec())?;
    let first: Vec<_> = header
        .lines()
        .next()
        .unwrap_or("")
        .split_whitespace()
        .collect();
    let method = first.first().copied().unwrap_or("");
    let path = first
        .get(1)
        .copied()
        .unwrap_or("/")
        .split('?')
        .next()
        .unwrap_or("/");
    let length = header
        .lines()
        .find_map(|l| {
            l.split_once(':')
                .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, v)| v.trim().parse::<usize>().ok())
        })
        .unwrap_or(0);
    if length > 65536 {
        bail!("Body")
    };
    while bytes.len() < end + length {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            bail!("EOF")
        };
        bytes.extend_from_slice(&buf[..n]);
    }
    let cookie = header
        .lines()
        .find_map(|l| {
            l.split_once(':')
                .filter(|(k, _)| k.eq_ignore_ascii_case("cookie"))
                .map(|(_, v)| v)
        })
        .unwrap_or("");
    let token = cookie
        .split(';')
        .find_map(|c| c.trim().strip_prefix("ans_session="));
    let session = token.and_then(|t| web.sessions.lock().unwrap().get(t).cloned());
    let port = web.config["web_port"].as_u64().unwrap();
    let origin = header.lines().find_map(|l| {
        l.split_once(':')
            .filter(|(k, _)| k.eq_ignore_ascii_case("origin"))
            .map(|(_, v)| v.trim())
    });
    if origin.is_some_and(|o| {
        o != format!("http://127.0.0.1:{port}") && o != format!("http://localhost:{port}")
    }) {
        return json_response(
            &mut stream,
            403,
            json!({"ok":false,"error":"Origin refused"}),
            None,
        );
    }
    if method == "GET" {
        return match path {
            "/" | "/scene/" => response(
                &mut stream,
                200,
                "text/html; charset=utf-8",
                LOGIN.as_bytes(),
                None,
            ),
            "/scene/three.module.js" => response(
                &mut stream,
                200,
                "application/javascript",
                THREE.as_bytes(),
                None,
            ),
            "/atom.svg" | "/scene/atom.svg" => {
                response(&mut stream, 200, "image/svg+xml", ATOM.as_bytes(), None)
            }
            "/api/session" => json_response(
                &mut stream,
                200,
                json!({"logged_in":session.is_some()}),
                None,
            ),
            "/health" => json_response(
                &mut stream,
                200,
                json!({"ok":true,"product":"ans","anchor":417696}),
                None,
            ),
            _ => {
                if path.starts_with("/1/") {
                    let w = normalize(path.trim_start_matches("/1/"))?;
                    if session.as_deref() != Some(&w) {
                        return response(
                            &mut stream,
                            200,
                            "text/html; charset=utf-8",
                            LOGIN.as_bytes(),
                            None,
                        );
                    }
                    let html = WORLD.replace(
                        "<script>",
                        &format!("<script>window.ANS_CUSTODIAN='{}';", w),
                    );
                    response(
                        &mut stream,
                        200,
                        "text/html; charset=utf-8",
                        html.as_bytes(),
                        None,
                    )
                } else {
                    json_response(
                        &mut stream,
                        404,
                        json!({"ok":false,"error":"not found"}),
                        None,
                    )
                }
            }
        };
    }
    if method != "POST" {
        return json_response(&mut stream, 405, json!({"ok":false}), None);
    }
    if !header.lines().any(|l| {
        l.to_ascii_lowercase()
            .starts_with("content-type: application/json")
    }) {
        return json_response(
            &mut stream,
            400,
            json!({"ok":false,"error":"JSON only"}),
            None,
        );
    }
    let mut body: Value = serde_json::from_slice(&bytes[end..end + length])?;
    if path == "/api/do" && body["op"] == "custodian_login" {
        let w = normalize(body["custodian"].as_str().unwrap_or(""))?;
        if web.config["custodians"].get(&w).is_none() {
            return json_response(
                &mut stream,
                403,
                json!({"ok":false,"error":"Najpierw ans init <słowo>"}),
                None,
            );
        }
        body = json!({"op":"login","_source":{"surface":"browser","app":"ans-web","origin":format!("http://127.0.0.1:{port}"),"device":"browser — not hardware attested"}});
        let r = exploit::call(&w, Some(&body), "/api")?;
        if r["ok"] != true {
            return json_response(&mut stream, 400, r, None);
        }
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        let nonce = hex::encode(nonce);
        web.sessions
            .lock()
            .unwrap()
            .insert(nonce.clone(), w.clone());
        return json_response(
            &mut stream,
            200,
            json!({"ok":true,"routes":[format!("/1/{w}"),format!("/1/{w}")]}),
            Some(&nonce),
        );
    }
    if path == "/api/exploit" {
        let Some(w) = session else {
            return json_response(
                &mut stream,
                401,
                json!({"ok":false,"error":"Zaloguj się"}),
                None,
            );
        };
        if body["custodian"]
            .as_str()
            .unwrap_or(&w)
            .trim_end_matches(".ans")
            != w
        {
            return json_response(
                &mut stream,
                403,
                json!({"ok":false,"error":"Ta sesja ma innego custodiana"}),
                None,
            );
        }
        body.as_object_mut().unwrap().remove("custodian");
        body["_source"] = json!({"surface":"browser","app":"ans-web","origin":format!("http://127.0.0.1:{port}"),"device":"browser — not hardware attested"});
        let result = exploit::call(&w, Some(&body), "/api")?;
        return json_response(&mut stream, 200, result, None);
    }
    json_response(&mut stream, 404, json!({"ok":false}), None)
}
fn up(root: &Path, c: &Value) -> Result<()> {
    if c["custodians"].as_object().unwrap().is_empty() {
        bail!("Najpierw ans init <słowo>")
    };
    let web_port = c["web_port"].as_u64().unwrap() as u16;
    let listener = TcpListener::bind(("127.0.0.1", web_port))?;
    for w in c["custodians"].as_object().unwrap().keys() {
        let word = w.clone();
        let dir = root.join("custodians").join(w);
        thread::spawn(move || {
            if let Err(e) = exploit::serve(&word, &dir) {
                eprintln!("custodian {word}: {e}")
            }
        });
    }
    for w in c["custodians"].as_object().unwrap().keys() {
        let mut ready = false;
        for _ in 0..120 {
            if exploit::call(w, None, "/health").is_ok() {
                ready = true;
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        if !ready {
            bail!("Custodian {w} did not start")
        }
    }
    let words: Vec<_> = c["custodians"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    let host = &words[0];
    for w in &words {
        let st = local_call(w, "state", json!({}))?;
        for other in &words {
            if w != other
                && !st["contacts"]
                    .as_array()
                    .unwrap()
                    .contains(&json!(format!("{other}.ans")))
            {
                local_call(w, "contact_add", json!({"word":other}))?;
            }
        }
    }
    let channel = format!("{}.ans/#ogolny", host);
    let st = local_call(host, "state", json!({}))?;
    if !st["channels"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["id"] == channel)
    {
        local_call(
            host,
            "channel_create",
            json!({"name":"ogolny","public":true}),
        )?;
    }
    for w in &words {
        if w != host {
            local_call(w, "channel_join", json!({"channel":channel}))?;
        }
    }
    book(root, c)?;
    println!(
        "ANS LOCAL DEMO — http://127.0.0.1:{web_port}/ — {} custodians / one Rust process",
        words.len()
    );
    println!("No remote registration, no models, no mainnet. License choice pending.");
    let web = Arc::new(Web {
        config: c.clone(),
        sessions: Mutex::new(BTreeMap::new()),
    });
    for socket in listener.incoming() {
        if let Ok(socket) = socket {
            let web = web.clone();
            thread::spawn(move || {
                let _ = web_connection(socket, web);
            });
        }
    }
    Ok(())
}
fn attest(c: &Value) -> Result<Value> {
    ans_xmss::kat::wots_kat().map_err(|e| anyhow!(e))?;
    ans_xmss::kat::xmss_kat().map_err(|e| anyhow!(e))?;
    ans_xmss::kat::official_sig_parses_and_verifies().map_err(|e| anyhow!(e))?;
    let vectors = include_str!("../vendor/ans-xmss/kat/xmssmt_sha2_20_2_256.txt");
    let find = |key: &str| -> Result<Vec<u8>> {
        let line = vectors
            .lines()
            .find_map(|l| l.split_once(' ').filter(|(k, _)| *k == key).map(|(_, v)| v))
            .ok_or(anyhow!("KAT vector missing"))?;
        Ok(hex::decode(line)?)
    };
    let pk = ans_xmss::MtPk::from_bytes(&find("pk")?).map_err(|_| anyhow!("KAT pk"))?;
    for idx in [0, 1029, 1048574] {
        let sig = ans_xmss::MtSig::from_bytes(&find(&format!("sig_{idx}"))?)
            .map_err(|_| anyhow!("KAT sig"))?;
        if !ans_xmss::mt_verify(&pk, &[0x25], &sig) || ans_xmss::mt_verify(&pk, &[0x26], &sig) {
            bail!("XMSSMT reference KAT failed")
        }
    }
    let mut chains = serde_json::Map::new();
    for w in c["custodians"].as_object().unwrap().keys() {
        let r = exploit::call(w, None, "/verify")?;
        if r["ok"] != true || r["kernel_valid"] != true || r["xmss_all_valid"] != true {
            bail!("Invalid chain {w}")
        };
        chains.insert(w.clone(), r);
    }
    let reference = js(include_str!("../assets/gen002-reference.json"));
    let mut g = Vec::from(b"bitxbit.pq.v1:mesh".as_slice());
    g.extend(hex::decode(reference["note_id"].as_str().unwrap())?);
    g.extend(417696u64.to_le_bytes());
    g.extend(hex::decode(reference["crystal_sha3"].as_str().unwrap())?);
    Ok(
        json!({"ok":true,"anchor":417696,"KAT":{"WOTS_reference":true,"XMSS_reference":true,"XMSSMT_reference_signatures":true,"tampered_message_rejected":true},"PQ_schemes":pq::schemes(),"GEN002":reference,"golden_vector_id":hex::encode(Sha3_256::digest(&g)),"chains":chains,"scope":"local cryptographic/kernel checks, not a consensus or product certification"}),
    )
}
fn run() -> Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut root = std::env::var("ANS_HOME")
        .map(PathBuf::from)
        .unwrap_or(std::env::current_dir()?.join("ans-data"));
    let mut actor = String::new();
    for flag in ["--data", "--as"] {
        if let Some(i) = args.iter().position(|s| s == flag) {
            let value = args
                .get(i + 1)
                .ok_or(anyhow!("Missing flag value"))?
                .clone();
            if flag == "--data" {
                root = PathBuf::from(value)
            } else {
                actor = normalize(&value)?
            }
            args.drain(i..=i + 1);
        }
    }
    let cmd = args.first().map(String::as_str).unwrap_or("help");
    if cmd == "help" || cmd == "--help" {
        println!("ans init|install <word> | grow --plan|--apply [--hosts hosts.toml] | up | status | chat [to text] | skill list|add|grant|revoke|run | node [resolve /word/channel] | book resolve <word> | attest | word <slowo> [--lang pl|en|nl | --crystal] | boot --plan | book seed|add|list|import-kaikki|serve --port N | mint <word>|--all | delegate|revoke <word> <scope> | run <word> [--plan] [input] | sync http://127.0.0.1:PORT | licenses | inventory\nDictionary: dictionary --help. Read-only list/show/export/verify/serve; owner draft/validate/mint/inspect TARGET [--operation-id ID] require explicit --as and sign journal events. Advanced: apply REQUEST.json.\nGlobal: --data DIR --as WORD. LOCAL DEMO; Apache-2.0 core; paid modules excluded.");
        return Ok(());
    }
    if cmd == "dictionary" {
        if args.len()==1 || args[1]=="help" || args[1..].iter().any(|a|matches!(a.as_str(),"--help"|"-h")){println!("{}",dictionary::HELP);return Ok(());}
        out(dictionary::cli(&root, &actor, &args[1..])?);
        return Ok(());
    }
    if cmd == "mcp" || (cmd == "book" && args.get(1).is_some_and(|a|a=="list")) {
        // Read-only startup must not create config, identity, node ID or cache.
        let c=if root.join("config.json").exists(){read_json(&root.join("config.json"))?}else{json!({"current":"","custodians":{}})};
        if actor.is_empty(){actor=c["current"].as_str().unwrap_or("").into();}
        if cmd=="mcp" {exploit::configure(mappings(&c));return mcp(&actor,&root);}
        out(dictionary_read::legacy_list(&root,&actor)?);return Ok(());
    }
    if cmd == "word" {
        if args.iter().any(|s| s == "--crystal") {
            let w = args.get(1).ok_or(anyhow!("ans word <slowo> --crystal"))?;
            out(crystal::summary(w)?);
            return Ok(());
        }
        let w = args.get(1).ok_or(anyhow!("ans word <slowo> [--lang pl|en|nl]"))?;
        let records=dictionary_read::browse(&root,&actor,None)?;
        if let Some(record)=records.iter().find(|r|r.kind=="word" && ans_dict::Crystal::parse(&r.content.to_string()).is_ok_and(|c|dictionary_read::matches(&c,w))) {
            let lang=args.iter().position(|s|s=="--lang").and_then(|i|args.get(i+1)).map(String::as_str);
            let mut value=dictionary_read::summary(record,lang,12)?;
            value["book"]=json!(root.join("book"));out(value);return Ok(());
        }
        let lang = args.iter().position(|s| s == "--lang").and_then(|i| args.get(i + 1)).map(String::as_str);
        let (d, src) = word::load(&root)?;
        let mut r = word::lookup(&d, w, lang)?;
        r["book"] = json!(src);
        r["provenance"]=json!("legacy_json_unverified");
        r["lifecycle"]=Value::Null;
        println!("{}", serde_json::to_string_pretty(&r)?);
        return Ok(());
    }
    if cmd == "boot" {
        if !args.iter().any(|s| s == "--plan") { bail!("only `ans boot --plan` (dry-run) is available"); }
        println!("{}", serde_json::to_string_pretty(&word::boot_plan())?);
        return Ok(());
    }
    if cmd == "licenses" {
        println!("{}", include_str!("../assets/third-party.txt"));
        return Ok(());
    }
    if cmd == "inventory" {
        println!("{}", include_str!("../assets/inventory.json"));
        return Ok(());
    }
    if cmd == "grow" {
        out(grow::run(&root, &args[1..])?);
        return Ok(());
    }
    let mut c = config(&root)?;
    if actor.is_empty() {
        actor = c["current"].as_str().unwrap_or("").into()
    }
    if let Some(v) = words::handle(cmd, &args, &root, &actor)? {
        out(v);
        return Ok(());
    }
    if cmd == "init" || cmd == "install" {
        let word = normalize(args.get(1).ok_or(anyhow!("ans init <word>"))?)?;
        if c["custodians"].get(&word).is_some() {
            out(json!({"ok":true,"already_initialized":true,"word":word}));
            return Ok(());
        }
        let index = c["custodians"].as_object().unwrap().len() as u16;
        let port = c["web_port"].as_u64().unwrap() as u16 + 10 + index;
        let test = TcpListener::bind(("127.0.0.1", port))?;
        drop(test);
        c["custodians"][&word] = json!({"port":port});
        if actor.is_empty() {
            c["current"] = json!(word)
        }
        exploit::configure(mappings(&c));
        let verification = exploit::initialize(&word, &root.join("custodians").join(&word))?;
        save(&root.join("config.json"), &c)?;
        book(&root, &c)?;
        let network = discover(&root, &c)?;
        out(
            json!({"ok":true,"word":format!("{word}.ans"),"private_key":"created locally, mode 0600; never printed","verification":verification,"network":network,"next":"ans up opens local chat corridor; external Echo/mesh registration pending configured adapters"}),
        );
        return Ok(());
    }
    exploit::configure(mappings(&c));
    if cmd == "mcp" {
        return mcp(&actor, &root);
    }
    match cmd {
        "up" => up(&root, &c),
        "status" => {
            let mut nodes = serde_json::Map::new();
            for w in c["custodians"].as_object().unwrap().keys() {
                nodes.insert(
                    w.clone(),
                    exploit::call(w, None, "/verify").unwrap_or(json!({"online":false})),
                );
            }
            out(
                json!({"anchor":417696,"nodes":nodes,"network":read_json(&root.join("network.json")).unwrap_or(Value::Null)}),
            );
            Ok(())
        }
        "chat" => {
            if args.len() < 3 {
                out(
                    json!({"url":format!("http://127.0.0.1:{}/",c["web_port"]),"hint":"login with a local custodian word"}),
                );
            } else {
                out(local_call(
                    &actor,
                    "dm_send",
                    json!({"to":args[1],"text":args[2..].join(" "),"attachment":null}),
                )?);
            }
            Ok(())
        }
        "skill" => {
            let action = args.get(1).map(String::as_str).unwrap_or("list");
            let name = args.get(2).cloned().unwrap_or_default();
            let result = match action {
                "list" => local_call(&actor, "skill_list", json!({})),
                "add" => local_call(&actor, "skill_install", json!({"name":name})),
                "grant" => {
                    let scopes: Vec<_> = args[3.min(args.len())..].iter().collect();
                    local_call(&actor, "skill_add", json!({"name":name,"scopes":scopes}))
                }
                "revoke" | "remove" => local_call(&actor, "skill_remove", json!({"name":name})),
                "run" => local_call(
                    &actor,
                    "skill_run",
                    json!({"name":name,"action":args.get(3).cloned().unwrap_or("read".into())}),
                ),
                _ => bail!("skill list|add|grant|revoke|run"),
            }?;
            out(result);
            Ok(())
        }
        "node" => {
            if args.get(1).map(String::as_str) == Some("resolve") {
                out(js(&chip::guide(
                    args.get(2).ok_or(anyhow!("node resolve /word/channel"))?,
                )
                .map_err(|e| anyhow!(e))?));
            } else {
                out(
                    json!({"runtime":"one Rust process; custodian validator threads; not hardware VMs","bounded_guide":js(&chip::guide("/pawel/echo").map_err(|e|anyhow!(e))?),"brain_router":"not ported; no model loaded","inventory":js(include_str!("../assets/inventory.json"))}),
                );
            }
            Ok(())
        }
        "book" => {
            let word = normalize(args.get(2).ok_or(anyhow!("book resolve <word>"))?)?;
            let b = read_json(&root.join("book.json"))?;
            let entry = b["words"]
                .as_array()
                .unwrap()
                .iter()
                .find(|v| v["word"] == format!("{word}.ans"))
                .cloned();
            let peer = read_json(&root.join("network.json")).unwrap_or(Value::Null);
            let entries = peer["peer_words"].as_array().cloned().unwrap_or_default();
            out(
                json!({"anchor":417696,"local":entry,"peer":entries.into_iter().filter(|v|v["word"]==format!("{word}.ans")).collect::<Vec<_>>(),"global_verified":false}),
            );
            Ok(())
        }
        "attest" => {
            out(attest(&c)?);
            Ok(())
        }
        _ => bail!("Unknown command; ans --help"),
    }
}
fn mcp_call(actor: &str, op: &str, mut body: Value) -> Result<Value> {
    body["op"] = json!(op);
    body["_source"] = json!({"surface":"mcp","app":"ans-mcp","origin":"local stdio","device":"local client — not hardware attested"});
    let value = exploit::call(actor, Some(&body), "/api")?;
    if value["ok"] != true {
        bail!("{}", value["error"])
    }
    Ok(value)
}
fn mcp(actor: &str, root: &std::path::Path) -> Result<()> {
    use std::io::BufRead;
    let stdin = std::io::stdin();
    let mut legacy_initialized = false;
    for line in stdin.lock().lines() {
        let line = line?;
        let request: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => {
                println!(
                    "{}",
                    json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}})
                );
                continue;
            }
        };
        let Some(id) = request.get("id").cloned() else {
            continue;
        };
        let method = request["method"].as_str().unwrap_or("");
        let meta = &request["params"]["_meta"];
        let modern = meta["io.modelcontextprotocol/protocolVersion"].is_string();
        if modern {
            let version = meta["io.modelcontextprotocol/protocolVersion"]
                .as_str()
                .unwrap();
            if version != "2026-07-28" {
                println!(
                    "{}",
                    json!({"jsonrpc":"2.0","id":id,"error":{"code":-32022,"message":"Unsupported protocol version","data":{"supported":["2026-07-28","2025-03-26"],"requested":version}}})
                );
                continue;
            }
            if !meta["io.modelcontextprotocol/clientInfo"].is_object()
                || !meta["io.modelcontextprotocol/clientCapabilities"].is_object()
            {
                println!(
                    "{}",
                    json!({"jsonrpc":"2.0","id":id,"error":{"code":-32602,"message":"Required MCP client metadata missing"}})
                );
                continue;
            }
        } else if method != "initialize" && !legacy_initialized {
            println!(
                "{}",
                json!({"jsonrpc":"2.0","id":id,"error":{"code":-32600,"message":"Use modern metadata (2026-07-28), or legacy initialize (2025-03-26)"}})
            );
            continue;
        }
        let result: Result<Value> = match method {
            "server/discover" => Ok(
                json!({"resultType":"complete","supportedVersions":["2026-07-28","2025-03-26"],"capabilities":{"tools":{}},"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"ans-local-exploit","version":"0.1.0"}},"instructions":"Local custodian only; demo actions and crystal fees require explicit grants."}),
            ),
            "initialize" => {
                legacy_initialized = true;
                Ok(
                    json!({"protocolVersion":"2025-03-26","capabilities":{"tools":{}},"serverInfo":{"name":"ans-local-exploit","version":"0.1.0"}}),
                )
            }
            "ping" => Ok(json!({})),
            "tools/list" => Ok(
                json!({"tools":[{"name":"exploit_state","description":"Read own local custodian state","inputSchema":{"type":"object","properties":{}}},{"name":"skill_list","description":"List own grants","inputSchema":{"type":"object","properties":{}}},{"name":"skill_run","description":"Run a consented demo plugin action; may debit demo leaves","inputSchema":{"type":"object","properties":{"name":{"type":"string"},"action":{"type":"string"}},"required":["name","action"]}}]}),
            ).map(|mut v| { v["tools"].as_array_mut().unwrap().extend(words::mcp_tools()); v }
            ),
            "tools/call" => {
                let name = request["params"]["name"].as_str().unwrap_or("");
                let args = request["params"]["arguments"].clone();
                let r = match name {
                    "exploit_state" => mcp_call(actor, "state", json!({})),
                    "skill_list" => mcp_call(actor, "skill_list", json!({})),
                    "skill_run" => mcp_call(actor, "skill_run", args),
                    other => words::mcp_call(other, &args, root, actor).unwrap_or_else(|| Err(anyhow!("Unknown tool"))),
                };
                Ok(match r {
                    Ok(value) => {
                        json!({"content":[{"type":"text","text":serde_json::to_string(&value)?}],"isError":false})
                    }
                    Err(e) => {
                        json!({"content":[{"type":"text","text":e.to_string()}],"isError":true})
                    }
                })
            }
            _ => Err(anyhow!("Method not found")),
        };
        let reply = match result {
            Ok(mut v) => {
                if modern {
                    v["resultType"] = json!("complete")
                };
                json!({"jsonrpc":"2.0","id":id,"result":v})
            }
            Err(e) => {
                json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":e.to_string()}})
            }
        };
        println!("{}", reply);
        std::io::stdout().flush()?;
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("ans: {e}");
        std::process::exit(1)
    }
}
