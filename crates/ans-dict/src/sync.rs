// SPDX-License-Identifier: Apache-2.0
//! Localhost/LAN book sync over minimal HTTP/1.0 (std only).
//! GET /book/index -> {"node":id,"crystals":[{file,root,origin,proof}]}; GET /book/crystal/<file> -> raw JSON.
//! The puller recomputes every merkle root, checks it against the index, and runs a
//! caller-supplied rule (e.g. "must be minted") before storing. Every decision is logged.
use crate::{book::{valid_file_name, Book}, Crystal};
use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::time::Duration;

const MAX: u64 = 16 << 20;

pub fn now() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) }

/// Serve `index` and crystal files. `requests` bounds the loop (None = forever).
pub fn serve(listener: TcpListener, book: &Book, index: &dyn Fn() -> Result<Value>, requests: Option<usize>) -> Result<()> {
    let mut served = 0;
    for s in listener.incoming() {
        let mut s = s?;
        if let Err(e) = handle(&mut s, book, index) { eprintln!("ans sync serve: {e}"); }
        served += 1;
        if requests.is_some_and(|r| served >= r) { break; }
    }
    Ok(())
}

fn handle(s: &mut TcpStream, book: &Book, index: &dyn Fn() -> Result<Value>) -> Result<()> {
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < 8192 {
        let n = s.read(&mut chunk)?;
        if n == 0 { break; }
        buf.extend_from_slice(&chunk[..n]);
    }
    let req = String::from_utf8_lossy(&buf);
    let path = req.split_whitespace().nth(1).unwrap_or("/");
    let (code, body) = if !req.starts_with("GET ") { ("405", "{}".to_string()) }
        else if path == "/book/index" { match index() { Ok(v) => ("200", v.to_string()), Err(e) => ("500", json!({"error":e.to_string()}).to_string()) } }
        else if let Some(f) = path.strip_prefix("/book/crystal/") { match book.raw(f) { Ok(t) => ("200", t), Err(_) => ("404", "{}".into()) } }
        else { ("404", "{}".into()) };
    write!(s, "HTTP/1.0 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())?;
    s.flush()?;
    s.shutdown(std::net::Shutdown::Write)?;
    Ok(())
}

pub fn get(base: &str, path: &str) -> Result<String> {
    let auth = base.strip_prefix("http://").ok_or_else(|| anyhow!("only http:// peers"))?.trim_end_matches('/');
    let addr: std::net::SocketAddr = auth.replace("localhost", "127.0.0.1").parse().map_err(|_| anyhow!("peer must be ip:port"))?;
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(3))?;
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    write!(s, "GET {path} HTTP/1.0\r\nHost: {auth}\r\n\r\n")?;
    let mut out = Vec::new();
    s.take(MAX).read_to_end(&mut out)?;
    let text = String::from_utf8(out)?;
    let (head, body) = text.split_once("\r\n\r\n").ok_or_else(|| anyhow!("bad http response"))?;
    if !head.starts_with("HTTP/1.0 200") && !head.starts_with("HTTP/1.1 200") { bail!("peer {path}: {}", head.lines().next().unwrap_or("")); }
    Ok(body.to_string())
}

/// Pull from peer. `rule(crystal, index_entry)` must accept before anything is stored.
pub fn pull(peer: &str, book: &Book, me: &str, log: &Path, rule: &dyn Fn(&Crystal, &Value) -> Result<()>) -> Result<Vec<Value>> {
    let idx: Value = serde_json::from_str(&get(peer, "/book/index")?)?;
    let peer_id = idx["node"].as_str().unwrap_or("unknown").to_string();
    let mut records = Vec::new();
    let mut entries = idx["crystals"].as_array().ok_or_else(|| anyhow!("index without crystals"))?.clone();
    entries.sort_by_key(|e| e["kind"] != "letter"); // letters (layer 1) before words that depend on them
    for e in &entries {
        let file = e["file"].as_str().unwrap_or("");
        let declared = e["root"].as_str().unwrap_or("");
        let origin = e["origin"].as_str().unwrap_or(&peer_id).to_string();
        let result: Result<&str> = (|| {
            if !valid_file_name(file) { bail!("bad file name"); }
            if let Ok(have) = book.get(file) { if have.root == declared { return Ok("unchanged"); } }
            let text = get(peer, &format!("/book/crystal/{file}"))?;
            let c = Crystal::parse(&text)?; // recomputes root, rejects mismatch
            if c.root != declared { bail!("root {} differs from index {declared}", c.root); }
            if c.file_name() != file { bail!("file name does not match crystal id"); }
            rule(&c, e)?;
            book.add_text(&text)?;
            Ok("accepted")
        })();
        let (status, reason) = match result { Ok(s) => (s, String::new()), Err(err) => ("rejected", err.to_string()) };
        let r = json!({"who":me,"from_node":peer_id,"peer":peer,"origin":origin,"file":file,"root":declared,"status":status,"reason":reason,"time_unix":now()});
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(log)?;
        writeln!(f, "{r}")?;
        records.push(r);
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn tmp(n: &str) -> std::path::PathBuf { let d = std::env::temp_dir().join(format!("ans-dict-sync-{n}-{}", std::process::id())); let _ = std::fs::remove_dir_all(&d); d }
    fn spawn(book_dir: std::path::PathBuf, tamper: bool, requests: usize) -> String {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        std::thread::spawn(move || {
            let b = Book::open(&book_dir).unwrap();
            let idx = || -> Result<Value> {
                let list: Vec<Value> = b.list()?.into_iter().map(|(f, c)| json!({"file":f,"root":if tamper {"00".repeat(32)} else {c.root},"origin":"node-a"})).collect();
                Ok(json!({"node":"node-a","crystals":list}))
            };
            serve(l, &b, &idx, Some(requests)).unwrap();
        });
        url
    }
    #[test]
    fn b_gets_identical_crystals_then_new_word_and_rejects_tamper() {
        let (a, b, c) = (tmp("a"), tmp("b"), tmp("c"));
        let ba = Book::open(&a).unwrap();
        for f in ["rdzen", "u0072", "u0064", "u007a", "u0065", "u0144"] { ba.add_text(&crate::tests::asset(&format!("{f}.crystal.json"))).unwrap(); }
        let bb = Book::open(&b).unwrap();
        let url = spawn(a.clone(), false, 7);
        let log = b.join("sync.log");
        let r = pull(&url, &bb, "node-b", &log, &|_, _| Ok(())).unwrap();
        assert_eq!(r.iter().filter(|x| x["status"] == "accepted").count(), 6);
        for (f, c) in ba.list().unwrap() { assert_eq!(bb.get(&f).unwrap().root, c.root); assert_eq!(ba.raw(&f).unwrap(), bb.raw(&f).unwrap()); }
        // add a word to A; B picks it up, rest unchanged
        let lock = include_str!("../../../Cargo.lock");
        ba.add(&crate::exec::exec_word("hash", "sha3_256", "run", "sha3", "0.10.9", lock, "sha3").unwrap()).unwrap();
        let url = spawn(a.clone(), false, 2);
        let r = pull(&url, &bb, "node-b", &log, &|_, _| Ok(())).unwrap();
        assert_eq!(r.iter().filter(|x| x["status"] == "accepted").count(), 1);
        assert!(bb.get("hash.crystal.json").is_ok());
        assert_eq!(std::fs::read_to_string(&log).unwrap().lines().count(), 13);
        // rule refusal and root mismatch are both rejected and nothing is stored
        let bc = Book::open(&c).unwrap();
        let url = spawn(a.clone(), false, 8);
        let r = pull(&url, &bc, "node-c", &c.join("log"), &|_, _| bail!("not minted")).unwrap();
        assert!(r.iter().all(|x| x["status"] == "rejected") && bc.list().unwrap().is_empty());
        let url = spawn(a.clone(), true, 8);
        let r = pull(&url, &bc, "node-c", &c.join("log"), &|_, _| Ok(())).unwrap();
        assert!(r.iter().all(|x| x["status"] == "rejected" && x["reason"].as_str().unwrap().contains("differs")));
        for d in [a, b, c] { let _ = std::fs::remove_dir_all(d); }
    }
}
