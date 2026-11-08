// SPDX-License-Identifier: Apache-2.0
//! Isolated loopback visitor: immutable selected proof only, no legacy runtime.
use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    time::Duration,
};
const HTML: &str = include_str!("../assets/dictionary-visitor.html");
const CSS: &str = include_str!("../assets/dictionary-visitor.css");
const JS: &str = include_str!("../assets/dictionary-visitor.js");
const ICON: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><path fill="#c9a564" d="M32 3 55 22 43 52 32 61 21 52 9 22Z"/><path fill="#15120e" d="m32 9 14 16-14 26-14-26Z"/></svg>"##;
const MAX_HEADERS: usize = 8192;
const CSP:&str="default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
pub struct Visitor {
    data: Value,
    proof: Vec<u8>,
}
impl Visitor {
    pub fn load(path: &Path, anchor: &str) -> Result<Self> {
        let (data, proof) = crate::dictionary_read::visitor_data(path, anchor)?;
        Ok(Self { data, proof })
    }
    fn route(&self, path: &str) -> (u16, &'static str, Vec<u8>, bool) {
        let json = |v: &Value| serde_json::to_vec(v).expect("JSON values serialize");
        match path {
            "/" => (
                200,
                "text/html; charset=utf-8",
                HTML.as_bytes().to_vec(),
                false,
            ),
            "/app.css" => (
                200,
                "text/css; charset=utf-8",
                CSS.as_bytes().to_vec(),
                false,
            ),
            "/app.js" => (
                200,
                "application/javascript; charset=utf-8",
                JS.as_bytes().to_vec(),
                false,
            ),
            "/favicon.svg" => (200, "image/svg+xml", ICON.as_bytes().to_vec(), false),
            "/api/entries" => {
                let entries=self.data["entries"].as_array().unwrap().iter().map(|e|json!({"id":e["id"],"root":e["root"],"kind":e["kind"],"language":e["language"],"state":e["state"],"signed_sequence":e["signed_sequence"],"dependency_count":e["dependencies"].as_array().unwrap().len()})).collect::<Vec<_>>();
                (
                    200,
                    "application/json; charset=utf-8",
                    json(
                        &json!({"entries":entries,"target_root":self.data["target_root"],"mode":self.data["mode"],"scope":self.data["scope"]}),
                    ),
                    false,
                )
            }
            "/api/verification" => (
                200,
                "application/json; charset=utf-8",
                json(&self.data["verification"]),
                false,
            ),
            "/proof.json" => (
                200,
                "application/json; charset=utf-8",
                self.proof.clone(),
                true,
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
                            return (200, "application/json; charset=utf-8", json(e), false);
                        }
                    }
                }
                (
                    404,
                    "application/json; charset=utf-8",
                    json(&json!({"error":"Not found in the selected public proof"})),
                    false,
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
    download: bool,
) -> Result<()> {
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        431 => "Request Header Fields Too Large",
        _ => "Error",
    };
    write!(stream,"HTTP/1.1 {code} {reason}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nContent-Security-Policy: {CSP}\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nX-Frame-Options: DENY\r\nCross-Origin-Resource-Policy: same-origin\r\nCross-Origin-Opener-Policy: same-origin\r\nPermissions-Policy: camera=(), microphone=(), geolocation=()\r\n",body.len())?;
    if code == 405 {
        write!(stream, "Allow: GET\r\n")?;
    }
    if download {
        write!(
            stream,
            "Content-Disposition: attachment; filename=genesis-dictionary-proof.json\r\n"
        )?;
    }
    write!(stream, "\r\n")?;
    stream.write_all(body)?;
    Ok(())
}
fn error(stream: &mut TcpStream, code: u16, message: &str) -> Result<()> {
    respond(
        stream,
        code,
        "application/json; charset=utf-8",
        &serde_json::to_vec(&json!({"error":message}))?,
        false,
    )
}
fn target(header: &[u8], port: u16) -> std::result::Result<String, (u16, &'static str)> {
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
    if parts[0] != "GET" {
        return Err((
            405,
            "Visitor mode accepts GET only; signing and execution are unavailable",
        ));
    }
    let path = parts[1];
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
    for line in lines.filter(|l| !l.is_empty()) {
        let (name, value) = line.split_once(':').ok_or_else(bad)?;
        if name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || value.bytes().any(|b| (b < 32 && b != b'\t') || b == 127)
        {
            return Err(bad());
        }
        let value = value.trim();
        if name.eq_ignore_ascii_case("host") {
            if host.replace(value).is_some() {
                return Err(bad());
            }
        }
        if name.eq_ignore_ascii_case("transfer-encoding")
            || (name.eq_ignore_ascii_case("content-length") && value != "0")
        {
            return Err(bad());
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
    Ok(path.to_string())
}
fn connection(mut stream: TcpStream, visitor: &Visitor) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let port = stream.local_addr()?.port();
    let mut bytes = Vec::new();
    let mut buf = [0u8; 1024];
    let end = loop {
        match stream.read(&mut buf) {
            Ok(0) => return error(&mut stream, 400, "Incomplete HTTP request"),
            Ok(n) => bytes.extend_from_slice(&buf[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                return error(&mut stream, 408, "Request timed out")
            }
            Err(e) => return Err(e.into()),
        }
        if bytes.len() > MAX_HEADERS {
            return error(
                &mut stream,
                431,
                "Visitor request headers exceed 8192 bytes",
            );
        }
        if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            break end + 4;
        }
    };
    if end != bytes.len() {
        return error(
            &mut stream,
            400,
            "Request bodies and pipelining are unavailable",
        );
    }
    let path = match target(&bytes[..end], port) {
        Ok(p) => p,
        Err((code, message)) => return error(&mut stream, code, message),
    };
    let (code, kind, body, download) = visitor.route(&path);
    respond(&mut stream, code, kind, &body, download)
}
pub fn cli(args: &[String]) -> Result<Value> {
    if args.len() != 6 && args.len() != 4 {
        bail!("Usage: dictionary serve PROOF_FILE --expect-key HEX [--port N]");
    }
    let path = args
        .get(1)
        .ok_or_else(|| anyhow!("Explicit public proof file required"))?;
    let mut anchor = None;
    let mut port = 37121;
    for pair in args[2..].chunks_exact(2) {
        match pair[0].as_str() {
            "--expect-key" if anchor.is_none() => anchor = Some(pair[1].as_str()),
            "--port" if args.len() == 6 => {
                port = pair[1].parse::<u16>()?;
                if port == 0 {
                    bail!("Choose an explicit non-zero loopback port");
                }
            }
            _ => bail!("Unknown or repeated visitor option"),
        }
    }
    let visitor = Visitor::load(
        Path::new(path),
        anchor.ok_or_else(|| anyhow!("External --expect-key is required"))?,
    )?;
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    println!(
        "{}",
        json!({"url":format!("http://127.0.0.1:{port}"),"pid":std::process::id(),"mode":"local_experimental_read_only_public_proof","entries":visitor.data["entries"].as_array().unwrap().len(),"signer_opened":false})
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
        for path in ["/", "/app.css", "/app.js", "/favicon.svg"] {
            assert_eq!(exchange(&visitor, &get(path)).0, 200);
        }
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
        assert_eq!(parse("GET", "/", "").unwrap(), "/");
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
        assert!(CSS.contains("max-width:650px"));
        assert!(!JS.contains("/api/exploit") && !HTML.contains("Mint now"));
        assert!(CSP.contains("form-action 'none'") && CSP.contains("frame-ancestors 'none'"));
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
    }
}
