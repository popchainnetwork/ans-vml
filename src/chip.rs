// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Paweł Piekut / Pplastechniek
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

const PAGE: &str = r#"<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>CZIP · Don't Panic</title><style>body{background:#091117;color:#b8ffd1;font:18px monospace;max-width:640px;margin:12vh auto;padding:24px}a{color:inherit}input,button{font:inherit;background:#12252b;color:inherit;border:1px solid #467566;padding:10px;max-width:100%}small{color:#84a59b}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style><h1>DON'T PANIC.</h1><p>chip → VM → program → small world</p><form id="guide"><input name="q" value="/pawel/echo" aria-label="Place"><button>autostop</button></form><pre id="place">a1a5 · ANS · words as places</pre><small>Local world. No chain. No keys.</small><p><a href="/status">status</a></p><script>document.querySelector('#guide').onsubmit=async e=>{e.preventDefault();const r=await fetch('/resolve?q='+encodeURIComponent(new FormData(e.target).get('q')));document.querySelector('#place').textContent=JSON.stringify(await r.json(),null,2)}</script></html>"#;

#[derive(Clone, Copy, Debug)]
enum Op {
    EnterProgram,
    EnterWorld,
    ReadWords,
    NamePlace,
    Return,
    Halt,
}
const GUIDE: [Op; 6] = [
    Op::EnterProgram,
    Op::EnterWorld,
    Op::ReadWords,
    Op::NamePlace,
    Op::Return,
    Op::Halt,
];

#[derive(Debug, PartialEq)]
struct Place {
    name: String,
    channel: String,
}
impl Place {
    fn parse(path: &str) -> Result<Self, &'static str> {
        let rest = path.strip_prefix('/').ok_or("use /nazwa/kanal")?;
        let parts: Vec<_> = rest.split('/').collect();
        if parts.len() != 2 {
            return Err("use exactly /nazwa/kanal");
        }
        let name = parts[0];
        let valid = |s: &str| {
            !s.is_empty()
                && s.len() <= 63
                && s.bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
                && !s.starts_with('-')
                && !s.ends_with('-')
        };
        if name.len() < 3
            || !valid(name)
            || name.as_bytes().get(2..4) == Some(b"--")
            || !valid(parts[1])
        {
            return Err("ANS name: 3-63 lowercase ASCII letters, digits or hyphens; channel: 1-63; no edge hyphens");
        }
        Ok(Self {
            name: name.into(),
            channel: parts[1].into(),
        })
    }
    fn json(&self) -> String {
        format!(
            r#"{{"path":"/{}/{}","a1a5":"a1a5:ans/{}","ans":"{}.ans","url":"https://bitxbit.io/ans/{}","channel":"{}","scope":"local-world","registry_verified":false}}"#,
            self.name, self.channel, self.name, self.name, self.name, self.channel
        )
    }
}

struct World {
    words: BTreeMap<String, &'static str>,
    visits: u64,
    last_place: Option<Place>,
}
impl World {
    fn new() -> Self {
        Self {
            words: BTreeMap::from([
                ("a1a5".into(), "adres miejsca"),
                ("ans".into(), "atlas nazw"),
                ("czip".into(), "naczynie"),
                ("echo".into(), "kanal rozmowy"),
                ("pawel".into(), "podroznik"),
                ("rooster".into(), "przewodnik"),
            ]),
            visits: 0,
            last_place: None,
        }
    }
}

// A bounded interpreter, not hardware virtualization or a blockchain runtime.
// The vessel runs one embedded guide program; only that program enters the world.
struct Vm {
    pc: usize,
    frames: Vec<&'static str>,
    ticks: u64,
    instructions: u64,
    world: World,
    started: Instant,
}
impl Vm {
    fn new() -> Self {
        Self {
            pc: 0,
            frames: vec!["vessel"],
            ticks: 0,
            instructions: 0,
            world: World::new(),
            started: Instant::now(),
        }
    }
    fn resolve(&mut self, input: &str) -> Result<String, &'static str> {
        self.pc = 0;
        self.frames.truncate(1);
        let mut place = None;
        let mut output = None;
        // Gas is exactly the size of the trusted embedded program.
        for _ in 0..GUIDE.len() {
            let op = GUIDE[self.pc];
            self.pc += 1;
            self.instructions += 1;
            match op {
                Op::EnterProgram => self.frames.push("guide"),
                Op::EnterWorld => self.frames.push("word-world"),
                Op::ReadWords => match Place::parse(input) {
                    Ok(p) => place = Some(p),
                    Err(e) => {
                        self.frames.truncate(1);
                        return Err(e);
                    }
                },
                Op::NamePlace => {
                    if let Some(p) = place.take() {
                        output = Some(p.json());
                        self.world.last_place = Some(p);
                        self.world.visits += 1;
                    }
                }
                Op::Return => self.frames.truncate(1),
                Op::Halt => return output.ok_or("program returned no place"),
            }
        }
        Err("program exhausted its instruction budget")
    }
    fn status(&self, port: u16) -> String {
        let words = self
            .world
            .words
            .iter()
            .map(|(word, meaning)| format!(r#"{{"word":"{word}","meaning":"{meaning}"}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let last = self
            .world
            .last_place
            .as_ref()
            .map(Place::json)
            .unwrap_or("null".into());
        format!(
            r#"{{"chip":"bxb-chip","motto":"Don't Panic","listen":"127.0.0.1:{port}","uptime_ms":{},"vm":{{"kind":"bounded-interpreter","ticks":{},"instructions":{},"pc":{},"stack_depth":{},"program":"guide","bytecode_ops":6,"layers":["vessel","program","word-world"]}},"world":{{"visits":{},"words":[{}],"last_place":{}}},"chain":false,"persistence":false,"keys":false}}"#,
            self.started.elapsed().as_millis(),
            self.ticks,
            self.instructions,
            self.pc,
            self.frames.len(),
            self.world.visits,
            words,
            last
        )
    }
}

fn decode(value: &str) -> Result<String, &'static str> {
    let bytes = value.as_bytes();
    let mut result = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let pair = bytes.get(i + 1..i + 3).ok_or("invalid percent encoding")?;
                let digit = |b: u8| {
                    (b as char)
                        .to_digit(16)
                        .map(|n| n as u8)
                        .ok_or("invalid percent encoding")
                };
                result.push(digit(pair[0])? * 16 + digit(pair[1])?);
                i += 3;
            }
            b'+' => {
                result.push(b' ');
                i += 1;
            }
            b => {
                result.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(result).map_err(|_| "invalid UTF-8")
}
fn query(target: &str) -> Result<String, &'static str> {
    let (_, query) = target.split_once('?').ok_or("missing q")?;
    let mut found = None;
    for pair in query.split('&') {
        if let Some(("q", value)) = pair.split_once('=') {
            if found.is_some() {
                return Err("duplicate q");
            }
            found = Some(decode(value)?);
        }
    }
    found.ok_or("missing q")
}
fn response(stream: &mut TcpStream, code: &str, content_type: &str, body: &str) -> io::Result<()> {
    write!(stream, "HTTP/1.1 {code}\r\nContent-Type: {content_type}; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n{body}", body.len())
}
fn serve(mut stream: TcpStream, vm: &mut Vm, port: u16) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_millis(400)))?;
    stream.set_write_timeout(Some(Duration::from_millis(400)))?;
    let deadline = Instant::now() + Duration::from_millis(600);
    let mut header = Vec::new();
    let mut buf = [0; 1024];
    loop {
        if header.len() >= 8192 || Instant::now() > deadline {
            return response(
                &mut stream,
                "431 Request Header Fields Too Large",
                "application/json",
                r#"{"error":"header limit"}"#,
            );
        }
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        header.extend_from_slice(&buf[..n]);
        if header.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let text = match std::str::from_utf8(&header) {
        Ok(t) => t,
        Err(_) => {
            return response(
                &mut stream,
                "400 Bad Request",
                "application/json",
                r#"{"error":"invalid request"}"#,
            )
        }
    };
    let fields: Vec<_> = text
        .lines()
        .next()
        .unwrap_or("")
        .split_whitespace()
        .collect();
    if fields.len() != 3 || !matches!(fields[2], "HTTP/1.0" | "HTTP/1.1") {
        return response(
            &mut stream,
            "400 Bad Request",
            "application/json",
            r#"{"error":"invalid request"}"#,
        );
    }
    if fields[0] != "GET" {
        return response(
            &mut stream,
            "405 Method Not Allowed",
            "application/json",
            r#"{"error":"GET only"}"#,
        );
    }
    let target = fields[1];
    match target.split('?').next().unwrap_or("") {
        "/" => response(&mut stream, "200 OK", "text/html", PAGE),
        "/status" => response(&mut stream, "200 OK", "application/json", &vm.status(port)),
        "/resolve" => match query(target).and_then(|input| vm.resolve(&input)) {
            Ok(body) => response(&mut stream, "200 OK", "application/json", &body),
            Err(e) => response(
                &mut stream,
                "400 Bad Request",
                "application/json",
                &format!(r#"{{"error":"{e}"}}"#),
            ),
        },
        _ => response(
            &mut stream,
            "404 Not Found",
            "application/json",
            r#"{"error":"no such place"}"#,
        ),
    }
}

pub fn guide(path: &str) -> Result<String, String> {
    Vm::new().resolve(path).map_err(str::to_string)
}
