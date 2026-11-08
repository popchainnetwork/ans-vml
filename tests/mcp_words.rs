// SPDX-License-Identifier: Apache-2.0
//! MCP client test: list tools, call word, mint_request, run_plan over stdio.
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

#[test]
fn mcp_lists_dictionary_tools_and_refuses_unminted_run() {
    let bin = env!("CARGO_BIN_EXE_ans");
    let home = std::env::temp_dir().join(format!("ans-mcp-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    let st = Command::new(bin).args(["book", "seed"]).env("ANS_HOME", &home).output().unwrap();
    assert!(st.status.success(), "{}", String::from_utf8_lossy(&st.stderr));
    let mut child = Command::new(bin).arg("mcp").env("ANS_HOME", &home).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut call = |id: u64, method: &str, params: Value| -> Value {
        writeln!(stdin, "{}", json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})).unwrap();
        let mut line = String::new();
        out.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    };
    call(1, "initialize", json!({"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"0"}}));
    let tools = call(2, "tools/list", json!({}));
    let names: Vec<&str> = tools["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
    for n in ["word", "list_words", "mint_request", "run_plan", "run", "dictionary_propose"] { assert!(names.contains(&n), "{names:?}"); }
    let w = call(3, "tools/call", json!({"name":"word","arguments":{"word":"RDZEŃ"}}));
    assert_eq!(w["result"]["isError"], false);
    assert!(w["result"]["content"][0]["text"].as_str().unwrap().contains("a8e5657614f0a4721d298b03d9f897bc64e3c4937059ea7a3393b90367a20b52"));
    let r = call(4, "tools/call", json!({"name":"run_plan","arguments":{"word":"hash"}}));
    assert_eq!(r["result"]["isError"], true);
    assert!(r["result"]["content"][0]["text"].as_str().unwrap().contains("not minted"));
    let m = call(5, "tools/call", json!({"name":"mint_request","arguments":{"word":"hash"}}));
    let t: Value = serde_json::from_str(m["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(t["minted"], false);
    assert!(t["request"]["blocking"][0].as_str().unwrap().contains("not minted")); // letters not minted yet
    let proposed = call(6, "tools/call", json!({"name":"dictionary_propose","arguments":{"op_id":"review-only","command":{"kind":"inspect","root":"a8e5657614f0a4721d298b03d9f897bc64e3c4937059ea7a3393b90367a20b52"}}}));
    let proposal: Value = serde_json::from_str(proposed["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(proposal["executed"], false);
    assert_eq!(proposal["signed"], false);
    assert!(!home.join("custodians").exists(), "MCP proposal must not create a signer");
    drop(stdin);
    child.wait().unwrap();
    let _ = std::fs::remove_dir_all(&home);
}
