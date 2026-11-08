#![forbid(unsafe_code)]

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::util;

pub const BRIDGE_DIR: &str = "bridge";
pub const BRIDGE_EVENTS_FILE: &str = "bridge_events.json";

pub const BRIDGE_CHAIN_POPCHAIN: &str = "popchain";
pub const BRIDGE_CHAIN_SOLANA: &str = "solana";
pub const BRIDGE_CHAIN_ETHEREUM: &str = "ethereum";

pub const BRIDGE_ASSET_PUSDC: &str = "pUSDC";
pub const BRIDGE_ASSET_SOLANA_USDC: &str = "solana:USDC";
pub const BRIDGE_ASSET_ETH_USDC: &str = "ethereum:USDC";

pub const BRIDGE_STATUS_PENDING: &str = "pending";
pub const BRIDGE_STATUS_PENDING_LOCK: &str = "pending_lock";
pub const BRIDGE_STATUS_MINTED_ON_TARGET: &str = "minted_on_target";
pub const BRIDGE_STATUS_BURN_SEEN_ON_TARGET: &str = "burn_seen_on_target";
pub const BRIDGE_STATUS_UNLOCKED_ON_POP: &str = "unlocked_on_pop";
pub const BRIDGE_STATUS_DONE: &str = "done";
pub const BRIDGE_STATUS_FAILED: &str = "failed";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BridgeEventTypeV1 {
    Lock,
    Unlock,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeEventV1 {
    pub event_id: String,
    pub event_type: BridgeEventTypeV1,

    /// Backward-compatible legacy field used by existing demo/operator flows.
    pub chain: String,

    /// Backward-compatible asset field.
    pub asset: String,

    pub from: String,
    pub to: String,
    pub amount: String,
    pub status: String,
    pub timestamp_unix: u64,

    #[serde(default)]
    pub related_event_id: Option<String>,

    #[serde(default)]
    pub source_chain: Option<String>,

    #[serde(default)]
    pub target_chain: Option<String>,

    #[serde(default)]
    pub source_asset: Option<String>,

    #[serde(default)]
    pub target_asset: Option<String>,

    #[serde(default)]
    pub pop_address: Option<String>,

    #[serde(default)]
    pub external_recipient: Option<String>,

    #[serde(default)]
    pub external_tx_id: Option<String>,

    #[serde(default)]
    pub burn_tx_id: Option<String>,

    #[serde(default)]
    pub failure_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BridgeAuditSeverityV1 {
    Error,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeAuditIssueV1 {
    pub severity: BridgeAuditSeverityV1,
    pub code: String,
    pub event_id: Option<String>,
    pub related_event_id: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeAuditReportV1 {
    pub events_count: usize,
    pub error_count: usize,
    pub warning_count: usize,
    pub ok: bool,
    pub issues: Vec<BridgeAuditIssueV1>,
}

pub fn bridge_events_path_for_db_root(db_root: &Path) -> PathBuf {
    db_root.join(BRIDGE_DIR).join(BRIDGE_EVENTS_FILE)
}

pub fn read_bridge_events(path: &Path) -> Result<Vec<BridgeEventV1>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let raw = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }

    let mut events: Vec<BridgeEventV1> =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;

    for ev in &mut events {
        normalize_event_in_place(ev)?;
    }

    Ok(events)
}

pub fn write_bridge_events(path: &Path, events: &[BridgeEventV1]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create_dir_all {}", parent.display()))?;
    }

    let mut normalized = Vec::with_capacity(events.len());
    for ev in events {
        let mut cloned = ev.clone();
        normalize_event_in_place(&mut cloned)?;
        normalized.push(cloned);
    }

    util::atomic_write_json(path, &normalized, true)
        .with_context(|| format!("write {}", path.display()))
}

pub fn append_bridge_event(path: &Path, event: &BridgeEventV1) -> Result<()> {
    let mut events = read_bridge_events(path)?;
    if events.iter().any(|ev| ev.event_id == event.event_id) {
        bail!("duplicate bridge event_id {}", event.event_id);
    }

    let mut normalized = event.clone();
    normalize_event_in_place(&mut normalized)?;
    events.push(normalized);

    write_bridge_events(path, &events)
}

pub fn update_bridge_event_status(path: &Path, event_id: &str, new_status: &str) -> Result<()> {
    let mut events = read_bridge_events(path)?;
    let ev = events
        .iter_mut()
        .find(|ev| ev.event_id == event_id)
        .ok_or_else(|| anyhow!("bridge event not found: {}", event_id))?;

    validate_status(new_status)?;
    ev.status = new_status.to_string();

    if new_status == BRIDGE_STATUS_FAILED && ev.failure_reason.is_none() {
        ev.failure_reason = Some("bridge operator marked event as failed".to_string());
    }

    write_bridge_events(path, &events)
}

pub fn set_bridge_event_external_tx_id(
    path: &Path,
    event_id: &str,
    external_tx_id: &str,
) -> Result<()> {
    if external_tx_id.trim().is_empty() {
        bail!("external_tx_id empty");
    }

    let mut events = read_bridge_events(path)?;
    let ev = events
        .iter_mut()
        .find(|ev| ev.event_id == event_id)
        .ok_or_else(|| anyhow!("bridge event not found: {}", event_id))?;

    ev.external_tx_id = Some(external_tx_id.trim().to_string());
    write_bridge_events(path, &events)
}

pub fn set_bridge_event_burn_tx_id(path: &Path, event_id: &str, burn_tx_id: &str) -> Result<()> {
    if burn_tx_id.trim().is_empty() {
        bail!("burn_tx_id empty");
    }

    let mut events = read_bridge_events(path)?;
    let ev = events
        .iter_mut()
        .find(|ev| ev.event_id == event_id)
        .ok_or_else(|| anyhow!("bridge event not found: {}", event_id))?;

    ev.burn_tx_id = Some(burn_tx_id.trim().to_string());
    write_bridge_events(path, &events)
}

pub fn set_bridge_event_failure(path: &Path, event_id: &str, reason: &str) -> Result<()> {
    if reason.trim().is_empty() {
        bail!("failure reason empty");
    }

    let mut events = read_bridge_events(path)?;
    let ev = events
        .iter_mut()
        .find(|ev| ev.event_id == event_id)
        .ok_or_else(|| anyhow!("bridge event not found: {}", event_id))?;

    ev.status = BRIDGE_STATUS_FAILED.to_string();
    ev.failure_reason = Some(reason.trim().to_string());
    write_bridge_events(path, &events)
}

pub fn next_bridge_event_id(events: &[BridgeEventV1], prefix: &str) -> Result<String> {
    if prefix.trim().is_empty() {
        bail!("bridge event prefix empty");
    }

    let needle = format!("{}-", prefix.trim());
    let mut max_seen = 0u64;

    for ev in events {
        if !ev.event_id.starts_with(&needle) {
            continue;
        }

        let suffix = &ev.event_id[needle.len()..];
        let parsed = suffix
            .parse::<u64>()
            .with_context(|| format!("parse numeric suffix in event_id {}", ev.event_id))?;
        max_seen = max_seen.max(parsed);
    }

    Ok(format!("{}-{:06}", prefix.trim(), max_seen + 1))
}

pub fn make_lock_event(
    event_id: String,
    from: String,
    external_recipient: Option<String>,
    amount: u128,
) -> BridgeEventV1 {
    let recipient_value = external_recipient.unwrap_or_default();
    let target_chain = infer_target_chain_from_external_recipient(&recipient_value);
    let target_asset = infer_target_asset_from_target_chain(&target_chain);

    BridgeEventV1 {
        event_id,
        event_type: BridgeEventTypeV1::Lock,
        chain: BRIDGE_CHAIN_POPCHAIN.to_string(),
        asset: BRIDGE_ASSET_PUSDC.to_string(),
        from: from.clone(),
        to: recipient_value.clone(),
        amount: amount.to_string(),
        status: BRIDGE_STATUS_PENDING.to_string(),
        timestamp_unix: util::now_unix(),
        related_event_id: None,
        source_chain: Some(BRIDGE_CHAIN_POPCHAIN.to_string()),
        target_chain: Some(target_chain),
        source_asset: Some(BRIDGE_ASSET_PUSDC.to_string()),
        target_asset: Some(target_asset),
        pop_address: Some(from),
        external_recipient: if recipient_value.trim().is_empty() {
            None
        } else {
            Some(recipient_value)
        },
        external_tx_id: None,
        burn_tx_id: None,
        failure_reason: None,
    }
}

pub fn make_unlock_event(
    event_id: String,
    lock_owner_pop_address: String,
    target_pop_address: String,
    amount: u128,
    related_event_id: String,
    source_chain: String,
    source_asset: String,
) -> BridgeEventV1 {
    BridgeEventV1 {
        event_id,
        event_type: BridgeEventTypeV1::Unlock,
        chain: BRIDGE_CHAIN_POPCHAIN.to_string(),
        asset: BRIDGE_ASSET_PUSDC.to_string(),
        from: lock_owner_pop_address,
        to: target_pop_address.clone(),
        amount: amount.to_string(),
        status: BRIDGE_STATUS_DONE.to_string(),
        timestamp_unix: util::now_unix(),
        related_event_id: Some(related_event_id),
        source_chain: Some(source_chain),
        target_chain: Some(BRIDGE_CHAIN_POPCHAIN.to_string()),
        source_asset: Some(source_asset),
        target_asset: Some(BRIDGE_ASSET_PUSDC.to_string()),
        pop_address: Some(target_pop_address),
        external_recipient: None,
        external_tx_id: None,
        burn_tx_id: None,
        failure_reason: None,
    }
}

pub fn audit_bridge_events(events: &[BridgeEventV1]) -> BridgeAuditReportV1 {
    let mut issues = Vec::new();

    let mut seen_event_ids = HashSet::new();
    let mut lock_by_id: HashMap<&str, &BridgeEventV1> = HashMap::new();
    let mut unlocks_by_related: HashMap<&str, Vec<&BridgeEventV1>> = HashMap::new();

    for ev in events {
        if !seen_event_ids.insert(ev.event_id.as_str()) {
            push_error(
                &mut issues,
                "duplicate_event_id",
                Some(ev.event_id.clone()),
                None,
                format!("duplicate event_id detected: {}", ev.event_id),
            );
        }

        match ev.event_type {
            BridgeEventTypeV1::Lock => {
                lock_by_id.insert(ev.event_id.as_str(), ev);
            }
            BridgeEventTypeV1::Unlock => {
                if let Some(rel) = ev.related_event_id.as_deref() {
                    unlocks_by_related.entry(rel).or_default().push(ev);
                } else {
                    push_error(
                        &mut issues,
                        "unlock_missing_related_event_id",
                        Some(ev.event_id.clone()),
                        None,
                        format!("unlock event {} has no related_event_id", ev.event_id),
                    );
                }
            }
        }

        if ev.timestamp_unix == 0 {
            push_warning(
                &mut issues,
                "timestamp_zero",
                Some(ev.event_id.clone()),
                ev.related_event_id.clone(),
                format!("event {} has timestamp_unix=0", ev.event_id),
            );
        }

        if let Err(e) = validate_status(&ev.status) {
            push_error(
                &mut issues,
                "unsupported_status",
                Some(ev.event_id.clone()),
                ev.related_event_id.clone(),
                format!("event {} has invalid status: {}", ev.event_id, e),
            );
        }

        if ev.amount.parse::<u128>().is_err() {
            push_error(
                &mut issues,
                "amount_parse_failed",
                Some(ev.event_id.clone()),
                ev.related_event_id.clone(),
                format!(
                    "event {} amount is not a valid u128: {}",
                    ev.event_id, ev.amount
                ),
            );
        }

        match ev.event_type {
            BridgeEventTypeV1::Lock => audit_lock_event(ev, &mut issues),
            BridgeEventTypeV1::Unlock => audit_unlock_event_shallow(ev, &mut issues),
        }
    }

    for (related_id, unlocks) in &unlocks_by_related {
        if unlocks.len() > 1 {
            for unlock in unlocks {
                push_error(
                    &mut issues,
                    "duplicate_unlock_for_lock",
                    Some(unlock.event_id.clone()),
                    Some((*related_id).to_string()),
                    format!(
                        "multiple unlock events found for related_event_id={}",
                        related_id
                    ),
                );
            }
        }
    }

    for ev in events {
        if ev.event_type != BridgeEventTypeV1::Unlock {
            continue;
        }

        let related_id = match ev.related_event_id.as_deref() {
            Some(v) => v,
            None => continue,
        };

        let lock_ev = match lock_by_id.get(related_id) {
            Some(v) => *v,
            None => {
                push_error(
                    &mut issues,
                    "unlock_without_lock",
                    Some(ev.event_id.clone()),
                    Some(related_id.to_string()),
                    format!(
                        "unlock event {} points to missing lock {}",
                        ev.event_id, related_id
                    ),
                );
                continue;
            }
        };

        audit_unlock_event_against_lock(ev, lock_ev, &mut issues);
    }

    let error_count = issues
        .iter()
        .filter(|i| i.severity == BridgeAuditSeverityV1::Error)
        .count();

    let warning_count = issues
        .iter()
        .filter(|i| i.severity == BridgeAuditSeverityV1::Warning)
        .count();

    BridgeAuditReportV1 {
        events_count: events.len(),
        error_count,
        warning_count,
        ok: error_count == 0,
        issues,
    }
}

fn audit_lock_event(ev: &BridgeEventV1, issues: &mut Vec<BridgeAuditIssueV1>) {
    let source_chain = ev.source_chain.as_deref().unwrap_or("");
    let target_chain = ev.target_chain.as_deref().unwrap_or("");
    let source_asset = ev.source_asset.as_deref().unwrap_or("");
    let target_asset = ev.target_asset.as_deref().unwrap_or("");

    if source_chain != BRIDGE_CHAIN_POPCHAIN {
        push_error(
            issues,
            "lock_bad_source_chain",
            Some(ev.event_id.clone()),
            None,
            format!(
                "lock event {} should have source_chain={} but has {}",
                ev.event_id, BRIDGE_CHAIN_POPCHAIN, source_chain
            ),
        );
    }

    if source_asset != BRIDGE_ASSET_PUSDC {
        push_error(
            issues,
            "lock_bad_source_asset",
            Some(ev.event_id.clone()),
            None,
            format!(
                "lock event {} should have source_asset={} but has {}",
                ev.event_id, BRIDGE_ASSET_PUSDC, source_asset
            ),
        );
    }

    match target_chain {
        BRIDGE_CHAIN_ETHEREUM => {
            if target_asset != BRIDGE_ASSET_ETH_USDC {
                push_error(
                    issues,
                    "lock_bad_target_asset_for_eth",
                    Some(ev.event_id.clone()),
                    None,
                    format!(
                        "lock event {} target_chain=ethereum requires target_asset={} but has {}",
                        ev.event_id, BRIDGE_ASSET_ETH_USDC, target_asset
                    ),
                );
            }
        }
        BRIDGE_CHAIN_SOLANA => {
            if target_asset != BRIDGE_ASSET_SOLANA_USDC {
                push_error(
                    issues,
                    "lock_bad_target_asset_for_solana",
                    Some(ev.event_id.clone()),
                    None,
                    format!(
                        "lock event {} target_chain=solana requires target_asset={} but has {}",
                        ev.event_id, BRIDGE_ASSET_SOLANA_USDC, target_asset
                    ),
                );
            }
        }
        "" => {
            push_error(
                issues,
                "lock_missing_target_chain",
                Some(ev.event_id.clone()),
                None,
                format!("lock event {} has no target_chain", ev.event_id),
            );
        }
        other => {
            push_warning(
                issues,
                "lock_unknown_target_chain",
                Some(ev.event_id.clone()),
                None,
                format!(
                    "lock event {} has unrecognized target_chain={}",
                    ev.event_id, other
                ),
            );
        }
    }

    if ev.pop_address.as_deref().unwrap_or("").trim().is_empty() {
        push_warning(
            issues,
            "lock_missing_pop_address",
            Some(ev.event_id.clone()),
            None,
            format!("lock event {} has empty pop_address", ev.event_id),
        );
    }

    if target_chain == BRIDGE_CHAIN_ETHEREUM || target_chain == BRIDGE_CHAIN_SOLANA {
        if ev
            .external_recipient
            .as_deref()
            .unwrap_or("")
            .trim()
            .is_empty()
        {
            push_warning(
                issues,
                "lock_missing_external_recipient",
                Some(ev.event_id.clone()),
                None,
                format!(
                    "lock event {} target_chain={} but external_recipient is empty",
                    ev.event_id, target_chain
                ),
            );
        }
    }
}

fn audit_unlock_event_shallow(ev: &BridgeEventV1, issues: &mut Vec<BridgeAuditIssueV1>) {
    let target_chain = ev.target_chain.as_deref().unwrap_or("");
    let target_asset = ev.target_asset.as_deref().unwrap_or("");

    if target_chain != BRIDGE_CHAIN_POPCHAIN {
        push_error(
            issues,
            "unlock_bad_target_chain",
            Some(ev.event_id.clone()),
            ev.related_event_id.clone(),
            format!(
                "unlock event {} should have target_chain={} but has {}",
                ev.event_id, BRIDGE_CHAIN_POPCHAIN, target_chain
            ),
        );
    }

    if target_asset != BRIDGE_ASSET_PUSDC {
        push_error(
            issues,
            "unlock_bad_target_asset",
            Some(ev.event_id.clone()),
            ev.related_event_id.clone(),
            format!(
                "unlock event {} should have target_asset={} but has {}",
                ev.event_id, BRIDGE_ASSET_PUSDC, target_asset
            ),
        );
    }

    if ev.pop_address.as_deref().unwrap_or("").trim().is_empty() {
        push_warning(
            issues,
            "unlock_missing_pop_address",
            Some(ev.event_id.clone()),
            ev.related_event_id.clone(),
            format!("unlock event {} has empty pop_address", ev.event_id),
        );
    }
}

fn audit_unlock_event_against_lock(
    unlock_ev: &BridgeEventV1,
    lock_ev: &BridgeEventV1,
    issues: &mut Vec<BridgeAuditIssueV1>,
) {
    if unlock_ev.amount != lock_ev.amount {
        push_error(
            issues,
            "unlock_amount_mismatch",
            Some(unlock_ev.event_id.clone()),
            unlock_ev.related_event_id.clone(),
            format!(
                "unlock event {} amount {} does not match lock {} amount {}",
                unlock_ev.event_id, unlock_ev.amount, lock_ev.event_id, lock_ev.amount
            ),
        );
    }

    let expected_source_chain = lock_ev
        .target_chain
        .clone()
        .unwrap_or_else(|| BRIDGE_CHAIN_POPCHAIN.to_string());

    let expected_source_asset = lock_ev
        .target_asset
        .clone()
        .unwrap_or_else(|| BRIDGE_ASSET_PUSDC.to_string());

    let actual_source_chain = unlock_ev.source_chain.as_deref().unwrap_or("");
    let actual_source_asset = unlock_ev.source_asset.as_deref().unwrap_or("");

    if actual_source_chain != expected_source_chain {
        push_error(
            issues,
            "unlock_bad_source_chain_vs_lock",
            Some(unlock_ev.event_id.clone()),
            unlock_ev.related_event_id.clone(),
            format!(
                "unlock event {} source_chain={} but expected {} from lock {}",
                unlock_ev.event_id, actual_source_chain, expected_source_chain, lock_ev.event_id
            ),
        );
    }

    if actual_source_asset != expected_source_asset {
        push_error(
            issues,
            "unlock_bad_source_asset_vs_lock",
            Some(unlock_ev.event_id.clone()),
            unlock_ev.related_event_id.clone(),
            format!(
                "unlock event {} source_asset={} but expected {} from lock {}",
                unlock_ev.event_id, actual_source_asset, expected_source_asset, lock_ev.event_id
            ),
        );
    }

    if lock_ev.status == BRIDGE_STATUS_DONE && unlock_ev.status != BRIDGE_STATUS_DONE {
        push_warning(
            issues,
            "unlock_not_done_after_done_lock",
            Some(unlock_ev.event_id.clone()),
            unlock_ev.related_event_id.clone(),
            format!(
                "lock {} is done but unlock {} status is {}",
                lock_ev.event_id, unlock_ev.event_id, unlock_ev.status
            ),
        );
    }
}

fn push_error(
    issues: &mut Vec<BridgeAuditIssueV1>,
    code: &str,
    event_id: Option<String>,
    related_event_id: Option<String>,
    message: String,
) {
    issues.push(BridgeAuditIssueV1 {
        severity: BridgeAuditSeverityV1::Error,
        code: code.to_string(),
        event_id,
        related_event_id,
        message,
    });
}

fn push_warning(
    issues: &mut Vec<BridgeAuditIssueV1>,
    code: &str,
    event_id: Option<String>,
    related_event_id: Option<String>,
    message: String,
) {
    issues.push(BridgeAuditIssueV1 {
        severity: BridgeAuditSeverityV1::Warning,
        code: code.to_string(),
        event_id,
        related_event_id,
        message,
    });
}

fn normalize_event_in_place(ev: &mut BridgeEventV1) -> Result<()> {
    if ev.event_id.trim().is_empty() {
        bail!("bridge event_id empty");
    }

    if ev.from.trim().is_empty() {
        bail!("bridge event {} has empty from", ev.event_id);
    }

    if ev.amount.trim().is_empty() {
        bail!("bridge event {} has empty amount", ev.event_id);
    }
    ev.amount
        .parse::<u128>()
        .with_context(|| format!("parse amount for bridge event {}", ev.event_id))?;

    if ev.chain.trim().is_empty() {
        ev.chain = BRIDGE_CHAIN_POPCHAIN.to_string();
    }
    if ev.asset.trim().is_empty() {
        ev.asset = BRIDGE_ASSET_PUSDC.to_string();
    }

    if ev.timestamp_unix == 0 {
        ev.timestamp_unix = util::now_unix();
    }

    validate_status(&ev.status)?;

    if ev.source_chain.is_none() {
        ev.source_chain = Some(BRIDGE_CHAIN_POPCHAIN.to_string());
    }

    if ev.event_type == BridgeEventTypeV1::Lock {
        if ev.target_chain.is_none() {
            ev.target_chain = Some(infer_target_chain_from_external_recipient(&ev.to));
        }
        if ev.source_asset.is_none() {
            ev.source_asset = Some(BRIDGE_ASSET_PUSDC.to_string());
        }
        if ev.target_asset.is_none() {
            let tc = ev
                .target_chain
                .clone()
                .unwrap_or_else(|| BRIDGE_CHAIN_SOLANA.to_string());
            ev.target_asset = Some(infer_target_asset_from_target_chain(&tc));
        }
        if ev.pop_address.is_none() {
            ev.pop_address = Some(ev.from.clone());
        }
        if ev.external_recipient.is_none() && !ev.to.trim().is_empty() {
            ev.external_recipient = Some(ev.to.clone());
        }
    }

    if ev.event_type == BridgeEventTypeV1::Unlock {
        if ev.target_chain.is_none() {
            ev.target_chain = Some(BRIDGE_CHAIN_POPCHAIN.to_string());
        }
        if ev.source_asset.is_none() {
            ev.source_asset = Some(BRIDGE_ASSET_PUSDC.to_string());
        }
        if ev.target_asset.is_none() {
            ev.target_asset = Some(BRIDGE_ASSET_PUSDC.to_string());
        }
        if ev.pop_address.is_none() {
            if !ev.to.trim().is_empty() {
                ev.pop_address = Some(ev.to.clone());
            } else {
                ev.pop_address = Some(ev.from.clone());
            }
        }
    }

    Ok(())
}

fn validate_status(status: &str) -> Result<()> {
    match status {
        BRIDGE_STATUS_PENDING
        | BRIDGE_STATUS_PENDING_LOCK
        | BRIDGE_STATUS_MINTED_ON_TARGET
        | BRIDGE_STATUS_BURN_SEEN_ON_TARGET
        | BRIDGE_STATUS_UNLOCKED_ON_POP
        | BRIDGE_STATUS_DONE
        | BRIDGE_STATUS_FAILED => Ok(()),
        _ => bail!("unsupported bridge status {}", status),
    }
}

fn infer_target_chain_from_external_recipient(recipient: &str) -> String {
    let raw = recipient.trim();

    if raw.is_empty() {
        return BRIDGE_CHAIN_SOLANA.to_string();
    }

    if raw.starts_with("0x") || raw.starts_with("0X") {
        return BRIDGE_CHAIN_ETHEREUM.to_string();
    }

    BRIDGE_CHAIN_SOLANA.to_string()
}

fn infer_target_asset_from_target_chain(target_chain: &str) -> String {
    match target_chain {
        BRIDGE_CHAIN_ETHEREUM => BRIDGE_ASSET_ETH_USDC.to_string(),
        BRIDGE_CHAIN_SOLANA => BRIDGE_ASSET_SOLANA_USDC.to_string(),
        _ => BRIDGE_ASSET_PUSDC.to_string(),
    }
}
