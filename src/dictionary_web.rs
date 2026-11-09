// SPDX-License-Identifier: Apache-2.0
//! Isolated loopback visitor: immutable selected proof, a pure proof verifier and an
//! optional read-only package download. No signer, journal or legacy runtime is opened.
use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    time::Duration,
};
const HTML: &str = include_str!("../assets/dictionary-visitor.html");
const CSS: &str = include_str!("../assets/dictionary-visitor.css");
const JS: &str = include_str!("../assets/dictionary-visitor.js");
const ICON: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" shape-rendering="crispEdges"><rect width="16" height="16" fill="#03020a"/><rect x="4" y="2" width="8" height="1" fill="#00f0ff"/><rect x="3" y="3" width="1" height="1" fill="#00f0ff"/><rect x="4" y="3" width="2" height="1" fill="#cffaff"/><rect x="6" y="3" width="4" height="1" fill="#00f0ff"/><rect x="10" y="3" width="2" height="1" fill="#ff3df0"/><rect x="12" y="3" width="1" height="1" fill="#00f0ff"/><rect x="2" y="4" width="1" height="1" fill="#00f0ff"/><rect x="3" y="4" width="2" height="1" fill="#cffaff"/><rect x="5" y="4" width="5" height="1" fill="#00f0ff"/><rect x="10" y="4" width="3" height="1" fill="#ff3df0"/><rect x="13" y="4" width="1" height="1" fill="#00f0ff"/><rect x="1" y="5" width="1" height="1" fill="#00f0ff"/><rect x="2" y="5" width="1" height="1" fill="#cffaff"/><rect x="3" y="5" width="7" height="1" fill="#00f0ff"/><rect x="10" y="5" width="3" height="1" fill="#ff3df0"/><rect x="13" y="5" width="1" height="1" fill="#9a5cff"/><rect x="14" y="5" width="1" height="1" fill="#00f0ff"/><rect x="0" y="6" width="16" height="1" fill="#00f0ff"/><rect x="1" y="7" width="1" height="1" fill="#0b6a7a"/><rect x="2" y="7" width="6" height="1" fill="#00f0ff"/><rect x="8" y="7" width="4" height="1" fill="#ff3df0"/><rect x="12" y="7" width="2" height="1" fill="#9a5cff"/><rect x="14" y="7" width="1" height="1" fill="#0b6a7a"/><rect x="2" y="8" width="1" height="1" fill="#0b6a7a"/><rect x="3" y="8" width="5" height="1" fill="#00f0ff"/><rect x="8" y="8" width="3" height="1" fill="#ff3df0"/><rect x="11" y="8" width="2" height="1" fill="#9a5cff"/><rect x="13" y="8" width="1" height="1" fill="#0b6a7a"/><rect x="3" y="9" width="1" height="1" fill="#0b6a7a"/><rect x="4" y="9" width="4" height="1" fill="#00f0ff"/><rect x="8" y="9" width="2" height="1" fill="#ff3df0"/><rect x="10" y="9" width="2" height="1" fill="#9a5cff"/><rect x="12" y="9" width="1" height="1" fill="#0b6a7a"/><rect x="4" y="10" width="1" height="1" fill="#0b6a7a"/><rect x="5" y="10" width="3" height="1" fill="#00f0ff"/><rect x="8" y="10" width="1" height="1" fill="#ff3df0"/><rect x="9" y="10" width="2" height="1" fill="#9a5cff"/><rect x="11" y="10" width="1" height="1" fill="#0b6a7a"/><rect x="5" y="11" width="1" height="1" fill="#0b6a7a"/><rect x="6" y="11" width="2" height="1" fill="#00f0ff"/><rect x="8" y="11" width="1" height="1" fill="#ff3df0"/><rect x="9" y="11" width="1" height="1" fill="#9a5cff"/><rect x="10" y="11" width="1" height="1" fill="#0b6a7a"/><rect x="6" y="12" width="1" height="1" fill="#0b6a7a"/><rect x="7" y="12" width="1" height="1" fill="#00f0ff"/><rect x="8" y="12" width="1" height="1" fill="#9a5cff"/><rect x="9" y="12" width="1" height="1" fill="#0b6a7a"/><rect x="7" y="13" width="2" height="1" fill="#0b6a7a"/></svg>"##;
const MANIFEST: &str = r##"{"name":"Genesis dictionary (local experimental)","short_name":"Genesis","start_url":"/","scope":"/","display":"standalone","background_color":"#03020a","theme_color":"#03020a","icons":[{"src":"/favicon.svg","sizes":"any","type":"image/svg+xml","purpose":"any"}]}"##;
const MAX_HEADERS: usize = 8192;
/// Upper bound for a pasted/uploaded proof submitted to the pure verifier.
pub(crate) const MAX_BODY: usize = 8 * 1024 * 1024;
const CSP:&str="default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
pub struct Package {
    name: String,
    bytes: Vec<u8>,
    sha256: String,
    sidecar_matched: bool,
}
impl Package {
    pub fn load(path: &Path) -> Result<Self> {
        if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
            bail!("Package file must not be a symlink");
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|n| {
                n.ends_with(".tar.gz")
                    && n.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
            })
            .ok_or_else(|| anyhow!("Package must be a plainly named .tar.gz file"))?
            .to_string();
        let bytes = std::fs::read(path)?;
        let sha256 = hex::encode(Sha256::digest(&bytes));
        let sidecar = path.with_file_name(format!("{name}.sha256"));
        let sidecar_matched = match std::fs::read_to_string(&sidecar) {
            Ok(text) => {
                let expected = text.split_whitespace().next().unwrap_or("").to_lowercase();
                if expected != sha256 {
                    bail!("Package SHA-256 does not match its .sha256 sidecar");
                }
                true
            }
            Err(_) => false,
        };
        Ok(Self {
            name,
            bytes,
            sha256,
            sidecar_matched,
        })
    }
}
pub struct Visitor {
    data: Value,
    proof: Vec<u8>,
    package: Option<Package>,
}
#[derive(Debug, PartialEq)]
pub(crate) enum Method {
    Get,
    Post,
}
#[derive(Debug)]
pub(crate) struct Request {
    pub(crate) method: Method,
    pub(crate) path: String,
    pub(crate) body_len: usize,
}
type Reply = (u16, &'static str, Vec<u8>, Option<String>);
const JSON_KIND: &str = "application/json; charset=utf-8";
fn json_bytes(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).expect("JSON values serialize")
}
/// Pure, read-only check of a submitted proof against a submitted expected key.
pub(crate) fn verify_submission(body: &[u8]) -> (u16, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => {
            return (
                400,
                json!({"error":"Send JSON: {\"expected_key\": HEX, \"proof\": PROOF}"}),
            )
        }
    };
    let key = parsed["expected_key"]
        .as_str()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if key.is_empty()
        || key.len() > 512
        || key.len() % 2 != 0
        || !key.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return (
            200,
            json!({"valid":false,"reason":"Expected key must be the signer's public key in hex"}),
        );
    }
    let proof = match serde_json::from_value::<crate::dictionary_read::Proof>(parsed["proof"].clone()) {
        Ok(p) => p,
        Err(_) => {
            return (
                200,
                json!({"valid":false,"reason":"This JSON is not a Genesis dictionary proof"}),
            )
        }
    };
    match std::panic::catch_unwind(|| crate::dictionary_read::verify(&proof, &key)) {
        Ok(Ok(result)) => (200, json!({"valid":true,"result":result})),
        Ok(Err(e)) => (200, json!({"valid":false,"reason":format!("{e:#}")})),
        Err(_) => (
            200,
            json!({"valid":false,"reason":"The proof could not be checked"}),
        ),
    }
}
impl Visitor {
    pub fn load(path: &Path, anchor: &str) -> Result<Self> {
        let (data, proof) = crate::dictionary_read::visitor_data(path, anchor)?;
        Ok(Self {
            data,
            proof,
            package: None,
        })
    }
    fn route(&self, request: &Request, body: &[u8]) -> Reply {
        if request.method == Method::Post {
            // `target` admits POST for this single path only.
            let (code, value) = verify_submission(body);
            return (code, JSON_KIND, json_bytes(&value), None);
        }
        let path = request.path.as_str();
        match path {
            "/" => (200, "text/html; charset=utf-8", HTML.as_bytes().to_vec(), None),
            "/app.css" => (200, "text/css; charset=utf-8", CSS.as_bytes().to_vec(), None),
            "/app.js" => (
                200,
                "application/javascript; charset=utf-8",
                JS.as_bytes().to_vec(),
                None,
            ),
            "/favicon.svg" => (200, "image/svg+xml", ICON.as_bytes().to_vec(), None),
            "/manifest.webmanifest" => (
                200,
                "application/manifest+json; charset=utf-8",
                MANIFEST.as_bytes().to_vec(),
                None,
            ),
            "/api/entries" => {
                let entries=self.data["entries"].as_array().unwrap().iter().map(|e|json!({"id":e["id"],"root":e["root"],"kind":e["kind"],"language":e["language"],"state":e["state"],"signed_sequence":e["signed_sequence"],"dependency_count":e["dependencies"].as_array().unwrap().len()})).collect::<Vec<_>>();
                (
                    200,
                    JSON_KIND,
                    json_bytes(
                        &json!({"entries":entries,"target_root":self.data["target_root"],"mode":self.data["mode"],"scope":self.data["scope"]}),
                    ),
                    None,
                )
            }
            "/api/verification" => (200, JSON_KIND, json_bytes(&self.data["verification"]), None),
            "/api/package" => {
                let v = match &self.package {
                    Some(p) => {
                        json!({"available":true,"name":p.name,"size":p.bytes.len(),"sha256":p.sha256,"sidecar_matched":p.sidecar_matched,"platform":"linux-x86_64","download":"/download/package.tar.gz"})
                    }
                    None => json!({"available":false}),
                };
                (200, JSON_KIND, json_bytes(&v), None)
            }
            "/download/package.tar.gz" if self.package.is_some() => {
                let p = self.package.as_ref().unwrap();
                (200, "application/gzip", p.bytes.clone(), Some(p.name.clone()))
            }
            "/proof.json" => (
                200,
                JSON_KIND,
                self.proof.clone(),
                Some("genesis-dictionary-proof.json".into()),
            ),
            _ => {
                if let Some(root) = path.strip_prefix("/api/entry/") {
                    if root.len() == 64
                        && root
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    {
                        if let Some(e) = self.data["entries"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .find(|e| e["root"] == root)
                        {
                            return (200, JSON_KIND, json_bytes(e), None);
                        }
                    }
                }
                (
                    404,
                    JSON_KIND,
                    json_bytes(&json!({"error":"Not found in the selected public proof"})),
                    None,
                )
            }
        }
    }
}
fn respond(
    stream: &mut TcpStream,
    code: u16,
    kind: &str,
    body: &[u8],
    download: Option<&str>,
) -> Result<()> {
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        431 => "Request Header Fields Too Large",
        _ => "Error",
    };
    let mut head = format!("HTTP/1.1 {code} {reason}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nContent-Security-Policy: {CSP}\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nX-Frame-Options: DENY\r\nCross-Origin-Resource-Policy: same-origin\r\nCross-Origin-Opener-Policy: same-origin\r\nPermissions-Policy: camera=(), microphone=(), geolocation=()\r\n",body.len());
    if code == 405 {
        head.push_str("Allow: GET\r\n");
    }
    if let Some(name) = download {
        head.push_str(&format!(
            "Content-Disposition: attachment; filename={name}\r\n"
        ));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}
fn error(stream: &mut TcpStream, code: u16, message: &str) -> Result<()> {
    respond(
        stream,
        code,
        JSON_KIND,
        &serde_json::to_vec(&json!({"error":message}))?,
        None,
    )
}
pub(crate) fn target(header: &[u8], port: u16) -> std::result::Result<Request, (u16, &'static str)> {
    let bad = || (400, "Malformed read-only HTTP request");
    let header = std::str::from_utf8(header).map_err(|_| bad())?;
    if !header.is_ascii() {
        return Err(bad());
    }
    let mut lines = header.split("\r\n");
    let first = lines.next().ok_or_else(bad)?;
    let parts = first.split(' ').collect::<Vec<_>>();
    if parts.len() != 3 || !matches!(parts[2], "HTTP/1.0" | "HTTP/1.1") {
        return Err(bad());
    }
    let path = parts[1];
    let method = match (parts[0], path) {
        ("GET", _) => Method::Get,
        ("POST", "/api/verify") => Method::Post,
        _ => {
            return Err((
                405,
                "Visitor mode accepts GET and proof verification only; signing and execution are unavailable",
            ))
        }
    };
    if !path.starts_with('/')
        || path.contains("..")
        || path.contains('%')
        || path.contains('\\')
        || path.contains('?')
        || path.contains('#')
        || path.contains("//")
        || path.bytes().any(|b| b <= 32 || b >= 127)
    {
        return Err(bad());
    }
    let mut host = None;
    let mut length: Option<usize> = None;
    let mut json_body = false;
    for line in lines.filter(|l| !l.is_empty()) {
        let (name, value) = line.split_once(':').ok_or_else(bad)?;
        if name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || value.bytes().any(|b| (b < 32 && b != b'\t') || b == 127)
        {
            return Err(bad());
        }
        let value = value.trim();
        if name.eq_ignore_ascii_case("host") && host.replace(value).is_some() {
            return Err(bad());
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(bad());
        }
        if name.eq_ignore_ascii_case("content-length") {
            let n = value.parse::<usize>().map_err(|_| bad())?;
            if length.replace(n).is_some() {
                return Err(bad());
            }
        }
        if name.eq_ignore_ascii_case("content-type") {
            json_body = value
                .split(';')
                .next()
                .is_some_and(|t| t.trim().eq_ignore_ascii_case("application/json"));
        }
        if name.eq_ignore_ascii_case("origin")
            && value != format!("http://127.0.0.1:{port}")
            && value != format!("http://localhost:{port}")
        {
            return Err((403, "Cross-origin visitor requests are refused"));
        }
        if name.eq_ignore_ascii_case("sec-fetch-site") && value == "cross-site" {
            return Err((403, "Cross-site visitor requests are refused"));
        }
    }
    if !host.is_some_and(|h| h == format!("127.0.0.1:{port}") || h == format!("localhost:{port}")) {
        return Err((403, "Visitor host must be loopback"));
    }
    let body_len = match method {
        Method::Get => {
            if length.unwrap_or(0) != 0 {
                return Err(bad());
            }
            0
        }
        Method::Post => {
            let n = length.ok_or((400, "Proof verification needs a Content-Length"))?;
            if n == 0 {
                return Err(bad());
            }
            if n > MAX_BODY {
                return Err((413, "Proof submissions are limited to 8 MiB"));
            }
            if !json_body {
                return Err((415, "Proof verification accepts application/json only"));
            }
            n
        }
    };
    Ok(Request {
        method,
        path: path.to_string(),
        body_len,
    })
}
fn connection(mut stream: TcpStream, visitor: &Visitor) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    let port = stream.local_addr()?.port();
    let mut bytes = Vec::new();
    let mut buf = [0u8; 16384];
    let timed_out = |e: &std::io::Error| {
        matches!(
            e.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        )
    };
    let end = loop {
        match stream.read(&mut buf) {
            Ok(0) => return error(&mut stream, 400, "Incomplete HTTP request"),
            Ok(n) => bytes.extend_from_slice(&buf[..n]),
            Err(e) if timed_out(&e) => return error(&mut stream, 408, "Request timed out"),
            Err(e) => return Err(e.into()),
        }
        if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            if end + 4 > MAX_HEADERS {
                return error(&mut stream, 431, "Visitor request headers exceed 8192 bytes");
            }
            break end + 4;
        }
        if bytes.len() > MAX_HEADERS {
            return error(&mut stream, 431, "Visitor request headers exceed 8192 bytes");
        }
    };
    let request = match target(&bytes[..end], port) {
        Ok(r) => r,
        Err((code, message)) => return error(&mut stream, code, message),
    };
    let mut body = bytes.split_off(end);
    if body.len() > request.body_len {
        return error(
            &mut stream,
            400,
            "Unexpected request body or pipelining is unavailable",
        );
    }
    if body.len() < request.body_len {
        stream.set_read_timeout(Some(Duration::from_secs(15)))?;
        body.reserve(request.body_len - body.len());
        while body.len() < request.body_len {
            match stream.read(&mut buf) {
                Ok(0) => return error(&mut stream, 400, "Incomplete request body"),
                Ok(n) => body.extend_from_slice(&buf[..n]),
                Err(e) if timed_out(&e) => return error(&mut stream, 408, "Request timed out"),
                Err(e) => return Err(e.into()),
            }
            if body.len() > request.body_len {
                return error(
                    &mut stream,
                    400,
                    "Unexpected request body or pipelining is unavailable",
                );
            }
        }
    }
    let (code, kind, reply, download) = visitor.route(&request, &body);
    respond(&mut stream, code, kind, &reply, download.as_deref())
}
pub fn cli(args: &[String]) -> Result<Value> {
    let usage = "Usage: dictionary serve PROOF_FILE --expect-key HEX [--port N] [--package FILE.tar.gz]";
    if args.len() < 4 || args.len() % 2 != 0 {
        bail!("{usage}");
    }
    let path = args
        .get(1)
        .ok_or_else(|| anyhow!("Explicit public proof file required"))?;
    let mut anchor = None;
    let mut port = None;
    let mut package = None;
    for pair in args[2..].chunks_exact(2) {
        match pair[0].as_str() {
            "--expect-key" if anchor.is_none() => anchor = Some(pair[1].as_str()),
            "--port" if port.is_none() => {
                let p = pair[1].parse::<u16>()?;
                if p == 0 {
                    bail!("Choose an explicit non-zero loopback port");
                }
                port = Some(p);
            }
            "--package" if package.is_none() => package = Some(pair[1].as_str()),
            _ => bail!("Unknown or repeated visitor option. {usage}"),
        }
    }
    let port = port.unwrap_or(37121);
    let mut visitor = Visitor::load(
        Path::new(path),
        anchor.ok_or_else(|| anyhow!("External --expect-key is required"))?,
    )?;
    if let Some(p) = package {
        visitor.package = Some(Package::load(Path::new(p))?);
    }
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    println!(
        "{}",
        json!({"url":format!("http://127.0.0.1:{port}"),"pid":std::process::id(),"mode":"local_experimental_read_only_public_proof","entries":visitor.data["entries"].as_array().unwrap().len(),"package":visitor.package.as_ref().map(|p|json!({"name":p.name,"sha256":p.sha256})),"signer_opened":false})
    );
    std::io::stdout().flush()?;
    for stream in listener.incoming() {
        if let Ok(stream) = stream {
            let _ = connection(stream, &visitor);
        }
    }
    Ok(json!({"stopped":true}))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    fn exchange(visitor: &Visitor, request: &str) -> (u16, String, Vec<u8>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let visitor = Visitor {
            data: visitor.data.clone(),
            proof: visitor.proof.clone(),
            package: None,
        };
        let worker = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            connection(stream, &visitor).unwrap();
        });
        let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let request = request.replace("{HOST}", &format!("127.0.0.1:{port}"));
        client.write_all(request.as_bytes()).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut bytes = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match client.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => bytes.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset && !bytes.is_empty() => {
                    break
                }
                Err(e) => panic!("HTTP read: {e}"),
            }
        }
        worker.join().unwrap();
        let end = bytes.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let headers = String::from_utf8(bytes[..end].to_vec()).unwrap();
        let status = headers.split(' ').nth(1).unwrap().parse().unwrap();
        (status, headers, bytes[end..].to_vec())
    }
    pub(crate) fn actual_proof_http(path: &Path, anchor: &str, word: bool) {
        let before = std::fs::read(path).unwrap();
        let visitor = Visitor::load(path, anchor).unwrap();
        assert!(Visitor::load(path, &"00".repeat(64)).is_err());
        let get = |p: &str| format!("GET {p} HTTP/1.1\r\nHost: {{HOST}}\r\n\r\n");
        let (status, headers, body) = exchange(&visitor, &get("/api/entries"));
        assert_eq!(status, 200);
        assert!(
            headers.contains("Content-Security-Policy:")
                && headers.contains("X-Content-Type-Options: nosniff")
        );
        let list: Value = serde_json::from_slice(&body).unwrap();
        let root = list["target_root"].as_str().unwrap();
        assert_eq!(
            list["entries"].as_array().unwrap().len(),
            if word { 6 } else { 1 }
        );
        let (status, _, body) = exchange(&visitor, &get(&format!("/api/entry/{root}")));
        assert_eq!(status, 200);
        let detail: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(detail["state"], "minted");
        assert_eq!(detail["kind"], if word { "word" } else { "letter" });
        assert_eq!(detail["expected_signer"], anchor);
        assert_eq!(
            detail["dependencies"].as_array().unwrap().len(),
            if word { 5 } else { 0 }
        );
        let (status, _, body) = exchange(&visitor, &get("/api/verification"));
        assert_eq!(status, 200);
        let verified: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            verified[if word {
                "word_dependency_path_verified"
            } else {
                "character_path_verified"
            }],
            true
        );
        let (status, headers, body) = exchange(&visitor, &get("/proof.json"));
        assert_eq!(status, 200);
        assert!(headers.contains("Content-Disposition: attachment;"));
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            serde_json::from_slice::<Value>(&before).unwrap()
        );
        for path in ["/", "/app.css", "/app.js", "/favicon.svg", "/manifest.webmanifest"] {
            assert_eq!(exchange(&visitor, &get(path)).0, 200);
        }
        let (status, _, body) = exchange(&visitor, &get("/api/package"));
        assert_eq!(status, 200);
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap()["available"],
            false
        );
        assert_eq!(exchange(&visitor, &get("/download/package.tar.gz")).0, 404);
        let proof_value: Value = serde_json::from_slice(&before).unwrap();
        let post = |key: &str, proof: &Value| {
            let body = serde_json::to_string(&json!({"expected_key":key,"proof":proof})).unwrap();
            format!(
                "POST /api/verify HTTP/1.1\r\nHost: {{HOST}}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
        };
        let (status, _, body) = exchange(&visitor, &post(&anchor.to_uppercase(), &proof_value));
        assert_eq!(status, 200);
        let ok: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(ok["valid"], true);
        assert_eq!(ok["result"]["path_verified"], true);
        assert_eq!(ok["result"]["root"], root);
        let (status, _, body) = exchange(&visitor, &post(&"00".repeat(64), &proof_value));
        assert_eq!(status, 200);
        let wrong: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(wrong["valid"], false);
        assert!(wrong["reason"].as_str().unwrap().contains("mismatch"));
        let mut tampered = proof_value.clone();
        tampered["entry"]["state"] = json!("draft");
        let (_, _, body) = exchange(&visitor, &post(anchor, &tampered));
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["valid"], false);
        let (_, _, body) = exchange(&visitor, &post(anchor, &json!({"hello":"world"})));
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["valid"], false);
        let (_, _, body) = exchange(&visitor, &post("not-hex", &proof_value));
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["valid"], false);
        assert_eq!(
            exchange(
                &visitor,
                "POST /api/verify HTTP/1.1\r\nHost: {HOST}\r\nContent-Type: application/json\r\nContent-Length: 3\r\n\r\n{x}"
            )
            .0,
            400
        );
        assert_eq!(
            exchange(
                &visitor,
                "POST /api/verify HTTP/1.1\r\nHost: {HOST}\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n{}"
            )
            .0,
            415
        );
        assert_eq!(
            exchange(
                &visitor,
                "POST /api/verify HTTP/1.1\r\nHost: {HOST}\r\nContent-Type: application/json\r\nContent-Length: 9999999999\r\n\r\n"
            )
            .0,
            413
        );
        assert_eq!(
            exchange(
                &visitor,
                "POST /api/verify HTTP/1.1\r\nHost: {HOST}\r\nOrigin: http://evil.test\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"
            )
            .0,
            403
        );
        for path in [
            "/xmss-demo.seed",
            "/chain.ndjson",
            "/config.json",
            "/api/exploit",
            "/etc/passwd",
            "/missing",
            "/api/entry/00",
        ] {
            let (status, _, body) = exchange(&visitor, &get(path));
            assert_eq!(status, 404);
            assert!(!String::from_utf8(body).unwrap().contains(path));
        }
        assert_eq!(
            exchange(
                &visitor,
                "POST /api/exploit HTTP/1.1\r\nHost: {HOST}\r\nContent-Length: 0\r\n\r\n"
            )
            .0,
            405
        );
        assert_eq!(exchange(&visitor, &get("/../xmss-demo.seed")).0, 400);
        assert_eq!(exchange(&visitor, &get("/%2e%2e/chain.ndjson")).0, 400);
        assert_eq!(
            exchange(
                &visitor,
                &format!(
                    "GET / HTTP/1.1\r\nHost: {{HOST}}\r\nX-Large: {}\r\n\r\n",
                    "x".repeat(9000)
                )
            )
            .0,
            431
        );
        assert_eq!(std::fs::read(path).unwrap(), before);
    }
    #[test]
    fn request_parser_rejects_mutations_traversal_rebinding_and_body_smuggling() {
        let parse = |method: &str, path: &str, extra: &str| {
            target(
                format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:37121\r\n{extra}\r\n")
                    .as_bytes(),
                37121,
            )
        };
        assert_eq!(parse("GET", "/", "").unwrap().path, "/");
        assert_eq!(parse("GET", "/", "").unwrap().method, Method::Get);
        let post = parse(
            "POST",
            "/api/verify",
            "Content-Type: application/json; charset=utf-8\r\nContent-Length: 10\r\n",
        )
        .unwrap();
        assert_eq!((post.method, post.body_len), (Method::Post, 10));
        assert_eq!(parse("POST", "/api/verify", "Content-Type: application/json\r\n").unwrap_err().0, 400);
        assert_eq!(
            parse("POST", "/api/verify", "Content-Type: application/json\r\nContent-Length: 1\r\nContent-Length: 1\r\n")
                .unwrap_err()
                .0,
            400
        );
        for path in ["/", "/proof.json", "/api/entries", "/download/package.tar.gz"] {
            assert_eq!(parse("POST", path, "Content-Length: 0\r\n").unwrap_err().0, 405);
        }
        for method in ["POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] {
            assert_eq!(parse(method, "/api/exploit", "").unwrap_err().0, 405);
        }
        for path in [
            "/../secret",
            "/%2e%2e/secret",
            "//etc/passwd",
            "/proof.json?file=../seed",
            "/a\\b",
            "http://evil.test/",
        ] {
            assert_eq!(parse("GET", path, "").unwrap_err().0, 400);
        }
        assert_eq!(
            parse("GET", "/", "Origin: https://evil.test\r\n")
                .unwrap_err()
                .0,
            403
        );
        assert_eq!(parse("GET", "/", "Host: evil.test\r\n").unwrap_err().0, 400);
        assert_eq!(
            target(b"GET / HTTP/1.1\r\nHost: evil.test\r\n\r\n", 37121)
                .unwrap_err()
                .0,
            403
        );
        for extra in [
            "Transfer-Encoding: chunked\r\n",
            "Content-Length: 1\r\n",
            " invalid: folded\r\n",
        ] {
            assert_eq!(parse("GET", "/", extra).unwrap_err().0, 400);
        }
        assert!(target(b"GET / HTTP/9.9\r\nHost: 127.0.0.1:37121\r\n\r\n", 37121).is_err());
    }
    #[test]
    fn ui_assets_render_untrusted_strings_as_text_without_remote_dependencies() {
        assert!(
            !JS.contains("innerHTML")
                && !JS.contains("insertAdjacentHTML")
                && !JS.contains("eval(")
        );
        assert!(JS.contains("textContent"));
        assert!(
            !HTML.contains("https://")
                && !JS.contains("https://")
                && !CSS.contains("@import")
                && !CSS.contains("url(")
        );
        assert!(HTML.contains("lang=\"en\"") && HTML.contains("viewport"));
        assert!(CSS.contains("@media (min-width:") && CSS.contains("prefers-reduced-motion"));
        assert!(JS.contains("prefers-reduced-motion") && JS.contains("visibilitychange"));
        assert!(!JS.contains("/api/exploit") && !HTML.contains("Mint now"));
        for claim in ["Buy", "Pricing", "Stripe", "voice", "hologra", "production-ready", "guarantee"] {
            assert!(!HTML.contains(claim) && !JS.contains(claim), "{claim}");
        }
        assert!(HTML.contains("Experimental") && HTML.contains("not audited"));
        assert!(HTML.contains("/manifest.webmanifest"));
        assert!(MANIFEST.contains("\"start_url\":\"/\""));
        assert!(CSP.contains("form-action 'none'") && CSP.contains("frame-ancestors 'none'"));
    }
    #[test]
    fn package_download_is_hash_pinned_and_sidecar_checked() {
        let dir = std::env::temp_dir().join(format!("ans-visitor-package-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("demo-package.tar.gz");
        std::fs::write(&file, b"not really gzip but bytes").unwrap();
        let sha = hex::encode(Sha256::digest(b"not really gzip but bytes"));
        std::fs::write(dir.join("demo-package.tar.gz.sha256"), format!("{} demo\n", "ab".repeat(32))).unwrap();
        assert!(Package::load(&file).is_err());
        std::fs::write(dir.join("demo-package.tar.gz.sha256"), format!("{sha}  demo-package.tar.gz\n")).unwrap();
        let package = Package::load(&file).unwrap();
        assert!(package.sidecar_matched && package.sha256 == sha);
        let bad = dir.join("bad name.tar.gz");
        std::fs::write(&bad, b"x").unwrap();
        assert!(Package::load(&bad).is_err());
        assert!(Package::load(&dir.join("demo-package.tar.gz.sha256")).is_err());
        let visitor = Visitor {
            data: json!({"entries":[],"verification":{}}),
            proof: b"{}".to_vec(),
            package: Some(package),
        };
        let get = |p: &str| Request { method: Method::Get, path: p.into(), body_len: 0 };
        let (code, kind, body, name) = visitor.route(&get("/download/package.tar.gz"), b"");
        assert_eq!((code, kind, name.as_deref()), (200, "application/gzip", Some("demo-package.tar.gz")));
        assert_eq!(body, b"not really gzip but bytes");
        let (_, _, body, _) = visitor.route(&get("/api/package"), b"");
        let meta: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(meta["sha256"], sha);
        assert_eq!(meta["size"], 25);
        assert_eq!(meta["available"], true);
        std::fs::remove_dir_all(&dir).unwrap();
    }
    #[test]
    fn visitor_cli_has_no_public_bind_or_runtime_fallback() {
        assert!(cli(&["serve".into()]).is_err());
        assert!(cli(&[
            "serve".into(),
            "absent-proof.json".into(),
            "--bind".into(),
            "0.0.0.0".into()
        ])
        .is_err());
        assert!(cli(&[
            "serve".into(),
            "absent-proof.json".into(),
            "--expect-key".into(),
            "00".repeat(64),
            "--port".into(),
            "0".into()
        ])
        .is_err());
        assert!(cli(&[
            "serve".into(),
            "absent-proof.json".into(),
            "--expect-key".into(),
            "00".repeat(64),
            "--expect-key".into(),
            "11".repeat(64)
        ])
        .is_err());
    }
}
