// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Paweł Piekut / Pplastechniek
//! Free reference capability for exercising grant/run/revoke and MCP. No market or billing.
use serde_json::{json, Value};
pub fn definition(name: &str) -> Option<Value> {
    if name != "local-reference" {
        return None;
    };
    Some(
        json!({"name":name,"delegation_scopes":["read","run"],"actions":["read","run"],"connect_type":"local-reference","reference":true}),
    )
}
