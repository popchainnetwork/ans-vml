#![forbid(unsafe_code)]

use anyhow::{anyhow, bail, Result};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::types::AddressV1;

pub const MAX_APP_EVENTS_PER_BLOCK: usize = 64;
pub const MAX_APP_BYTES_PER_BLOCK: u64 = 256 * 1024; // 256 KB

pub const APP_KIND_TRANSFER_V0: &str = "transfer_v0";
pub const APP_KIND_PUSDC_TRANSFER_V0: &str = "pusdc_transfer_v0";
pub const APP_KIND_AMM_ADD_LIQUIDITY_V0: &str = "amm_add_liquidity_v0";
pub const APP_KIND_AMM_SWAP_BINCOIN_TO_PUSDC_V0: &str = "amm_swap_bincoin_to_pusdc_v0";
pub const APP_KIND_AMM_SWAP_PUSDC_TO_BINCOIN_V0: &str = "amm_swap_pusdc_to_bincoin_v0";
pub const APP_KIND_BRIDGE_LOCK_PUSDC_V0: &str = "bridge_lock_pusdc_v0";
pub const APP_KIND_BRIDGE_UNLOCK_PUSDC_V0: &str = "bridge_unlock_pusdc_v0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppEventV0 {
    pub kind: String,
    pub payload_b64: String,
    pub payload_len: u64,
    pub payload_sha256_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppTransferV0 {
    pub version: u32,
    pub from: String,
    pub to: String,
    pub amount: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppPusdcTransferV0 {
    pub version: u32,
    pub from: String,
    pub to: String,
    pub amount: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppAmmAddLiquidityV0 {
    pub version: u32,
    pub provider: String,
    pub bincoin_amount: String,
    pub pusdc_amount: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppAmmSwapBincoinToPusdcV0 {
    pub version: u32,
    pub user: String,
    pub amount_in: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppAmmSwapPusdcToBincoinV0 {
    pub version: u32,
    pub user: String,
    pub amount_in: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppBridgeLockPusdcV0 {
    pub version: u32,
    pub from: String,
    pub amount: String,
    pub target_chain: String,
    pub external_recipient: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppBridgeUnlockPusdcV0 {
    pub version: u32,
    pub to: String,
    pub amount: String,
    pub related_event_id: String,
    pub source_chain: String,
    pub source_asset: String,
}

pub fn verify_event(ev: &AppEventV0) -> Result<()> {
    if ev.kind.trim().is_empty() {
        return Err(anyhow!("event kind empty"));
    }

    if ev.payload_sha256_hex.len() != 64 {
        return Err(anyhow!("bad payload_sha256_hex length"));
    }

    let bytes = general_purpose::STANDARD
        .decode(&ev.payload_b64)
        .map_err(|e| anyhow!("base64 decode: {e}"))?;

    if bytes.len() as u64 != ev.payload_len {
        return Err(anyhow!("payload_len mismatch"));
    }

    let mut h = Sha256::new();
    h.update(&bytes);
    let got = hex::encode(h.finalize());

    if got != ev.payload_sha256_hex {
        return Err(anyhow!("payload sha256 mismatch"));
    }

    match ev.kind.as_str() {
        APP_KIND_TRANSFER_V0 => {
            let transfer = decode_transfer_payload_bytes(&bytes)?;
            verify_transfer(&transfer)?;
        }
        APP_KIND_PUSDC_TRANSFER_V0 => {
            let transfer = decode_pusdc_transfer_payload_bytes(&bytes)?;
            verify_pusdc_transfer(&transfer)?;
        }
        APP_KIND_AMM_ADD_LIQUIDITY_V0 => {
            let add = decode_amm_add_liquidity_payload_bytes(&bytes)?;
            verify_amm_add_liquidity(&add)?;
        }
        APP_KIND_AMM_SWAP_BINCOIN_TO_PUSDC_V0 => {
            let swap = decode_amm_swap_bincoin_to_pusdc_payload_bytes(&bytes)?;
            verify_amm_swap_bincoin_to_pusdc(&swap)?;
        }
        APP_KIND_AMM_SWAP_PUSDC_TO_BINCOIN_V0 => {
            let swap = decode_amm_swap_pusdc_to_bincoin_payload_bytes(&bytes)?;
            verify_amm_swap_pusdc_to_bincoin(&swap)?;
        }
        APP_KIND_BRIDGE_LOCK_PUSDC_V0 => {
            let lock = decode_bridge_lock_pusdc_payload_bytes(&bytes)?;
            verify_bridge_lock_pusdc(&lock)?;
        }
        APP_KIND_BRIDGE_UNLOCK_PUSDC_V0 => {
            let unlock = decode_bridge_unlock_pusdc_payload_bytes(&bytes)?;
            verify_bridge_unlock_pusdc(&unlock)?;
        }
        _ => {}
    }

    Ok(())
}

pub fn verify_transfer(transfer: &AppTransferV0) -> Result<()> {
    if transfer.version != 1 {
        bail!("unsupported transfer version {}", transfer.version);
    }

    let from = AddressV1::parse(&transfer.from)?;
    let to = AddressV1::parse(&transfer.to)?;

    if from == to {
        bail!("transfer from and to must differ");
    }

    let amount = parse_amount_u128(&transfer.amount)?;
    if amount == 0 {
        bail!("transfer amount must be > 0");
    }

    Ok(())
}

pub fn verify_pusdc_transfer(transfer: &AppPusdcTransferV0) -> Result<()> {
    if transfer.version != 1 {
        bail!("unsupported pUSDC transfer version {}", transfer.version);
    }

    let from = AddressV1::parse(&transfer.from)?;
    let to = AddressV1::parse(&transfer.to)?;

    if from == to {
        bail!("pUSDC transfer from and to must differ");
    }

    let amount = parse_amount_u128(&transfer.amount)?;
    if amount == 0 {
        bail!("pUSDC transfer amount must be > 0");
    }

    Ok(())
}

pub fn verify_amm_add_liquidity(add: &AppAmmAddLiquidityV0) -> Result<()> {
    if add.version != 1 {
        bail!("unsupported amm add liquidity version {}", add.version);
    }

    let _provider = AddressV1::parse(&add.provider)?;
    let bincoin_amount = parse_amount_u128(&add.bincoin_amount)?;
    let pusdc_amount = parse_amount_u128(&add.pusdc_amount)?;

    if bincoin_amount == 0 || pusdc_amount == 0 {
        bail!("amm add liquidity amounts must be > 0");
    }

    Ok(())
}

pub fn verify_amm_swap_bincoin_to_pusdc(swap: &AppAmmSwapBincoinToPusdcV0) -> Result<()> {
    if swap.version != 1 {
        bail!(
            "unsupported amm swap bincoin->pUSDC version {}",
            swap.version
        );
    }

    let _user = AddressV1::parse(&swap.user)?;
    let amount_in = parse_amount_u128(&swap.amount_in)?;
    if amount_in == 0 {
        bail!("amm swap bincoin->pUSDC amount_in must be > 0");
    }

    Ok(())
}

pub fn verify_amm_swap_pusdc_to_bincoin(swap: &AppAmmSwapPusdcToBincoinV0) -> Result<()> {
    if swap.version != 1 {
        bail!(
            "unsupported amm swap pUSDC->bincoin version {}",
            swap.version
        );
    }

    let _user = AddressV1::parse(&swap.user)?;
    let amount_in = parse_amount_u128(&swap.amount_in)?;
    if amount_in == 0 {
        bail!("amm swap pUSDC->bincoin amount_in must be > 0");
    }

    Ok(())
}

pub fn verify_bridge_lock_pusdc(lock: &AppBridgeLockPusdcV0) -> Result<()> {
    if lock.version != 1 {
        bail!("unsupported bridge lock pUSDC version {}", lock.version);
    }

    let _from = AddressV1::parse(&lock.from)?;
    let amount = parse_amount_u128(&lock.amount)?;
    if amount == 0 {
        bail!("bridge lock pUSDC amount must be > 0");
    }

    if lock.target_chain.trim().is_empty() {
        bail!("bridge lock pUSDC target_chain empty");
    }

    if lock.external_recipient.trim().is_empty() {
        bail!("bridge lock pUSDC external_recipient empty");
    }

    Ok(())
}

pub fn verify_bridge_unlock_pusdc(unlock: &AppBridgeUnlockPusdcV0) -> Result<()> {
    if unlock.version != 1 {
        bail!("unsupported bridge unlock pUSDC version {}", unlock.version);
    }

    let _to = AddressV1::parse(&unlock.to)?;
    let amount = parse_amount_u128(&unlock.amount)?;
    if amount == 0 {
        bail!("bridge unlock pUSDC amount must be > 0");
    }

    if unlock.related_event_id.trim().is_empty() {
        bail!("bridge unlock pUSDC related_event_id empty");
    }

    if unlock.source_chain.trim().is_empty() {
        bail!("bridge unlock pUSDC source_chain empty");
    }

    if unlock.source_asset.trim().is_empty() {
        bail!("bridge unlock pUSDC source_asset empty");
    }

    Ok(())
}

pub fn build_transfer_event(from: &str, to: &str, amount: u128) -> Result<AppEventV0> {
    let transfer = AppTransferV0 {
        version: 1,
        from: AddressV1::parse(from)?.to_string(),
        to: AddressV1::parse(to)?.to_string(),
        amount: amount.to_string(),
    };

    verify_transfer(&transfer)?;
    build_event_from_json(APP_KIND_TRANSFER_V0, &transfer)
}

pub fn build_pusdc_transfer_event(from: &str, to: &str, amount: u128) -> Result<AppEventV0> {
    let transfer = AppPusdcTransferV0 {
        version: 1,
        from: AddressV1::parse(from)?.to_string(),
        to: AddressV1::parse(to)?.to_string(),
        amount: amount.to_string(),
    };

    verify_pusdc_transfer(&transfer)?;
    build_event_from_json(APP_KIND_PUSDC_TRANSFER_V0, &transfer)
}

pub fn build_amm_add_liquidity_event(
    provider: &str,
    bincoin_amount: u128,
    pusdc_amount: u128,
) -> Result<AppEventV0> {
    let add = AppAmmAddLiquidityV0 {
        version: 1,
        provider: AddressV1::parse(provider)?.to_string(),
        bincoin_amount: bincoin_amount.to_string(),
        pusdc_amount: pusdc_amount.to_string(),
    };

    verify_amm_add_liquidity(&add)?;
    build_event_from_json(APP_KIND_AMM_ADD_LIQUIDITY_V0, &add)
}

pub fn build_amm_swap_bincoin_to_pusdc_event(user: &str, amount_in: u128) -> Result<AppEventV0> {
    let swap = AppAmmSwapBincoinToPusdcV0 {
        version: 1,
        user: AddressV1::parse(user)?.to_string(),
        amount_in: amount_in.to_string(),
    };

    verify_amm_swap_bincoin_to_pusdc(&swap)?;
    build_event_from_json(APP_KIND_AMM_SWAP_BINCOIN_TO_PUSDC_V0, &swap)
}

pub fn build_amm_swap_pusdc_to_bincoin_event(user: &str, amount_in: u128) -> Result<AppEventV0> {
    let swap = AppAmmSwapPusdcToBincoinV0 {
        version: 1,
        user: AddressV1::parse(user)?.to_string(),
        amount_in: amount_in.to_string(),
    };

    verify_amm_swap_pusdc_to_bincoin(&swap)?;
    build_event_from_json(APP_KIND_AMM_SWAP_PUSDC_TO_BINCOIN_V0, &swap)
}

pub fn build_bridge_lock_pusdc_event(
    from: &str,
    amount: u128,
    target_chain: &str,
    external_recipient: &str,
) -> Result<AppEventV0> {
    let lock = AppBridgeLockPusdcV0 {
        version: 1,
        from: AddressV1::parse(from)?.to_string(),
        amount: amount.to_string(),
        target_chain: target_chain.trim().to_string(),
        external_recipient: external_recipient.trim().to_string(),
    };

    verify_bridge_lock_pusdc(&lock)?;
    build_event_from_json(APP_KIND_BRIDGE_LOCK_PUSDC_V0, &lock)
}

pub fn build_bridge_unlock_pusdc_event(
    to: &str,
    amount: u128,
    related_event_id: &str,
    source_chain: &str,
    source_asset: &str,
) -> Result<AppEventV0> {
    let unlock = AppBridgeUnlockPusdcV0 {
        version: 1,
        to: AddressV1::parse(to)?.to_string(),
        amount: amount.to_string(),
        related_event_id: related_event_id.trim().to_string(),
        source_chain: source_chain.trim().to_string(),
        source_asset: source_asset.trim().to_string(),
    };

    verify_bridge_unlock_pusdc(&unlock)?;
    build_event_from_json(APP_KIND_BRIDGE_UNLOCK_PUSDC_V0, &unlock)
}

pub fn decode_transfer_event(ev: &AppEventV0) -> Result<AppTransferV0> {
    if ev.kind != APP_KIND_TRANSFER_V0 {
        bail!(
            "event kind mismatch expected={} got={}",
            APP_KIND_TRANSFER_V0,
            ev.kind
        );
    }

    verify_event(ev)?;
    let bytes = decode_event_payload_bytes(ev)?;
    let transfer = decode_transfer_payload_bytes(&bytes)?;
    verify_transfer(&transfer)?;
    Ok(transfer)
}

pub fn decode_pusdc_transfer_event(ev: &AppEventV0) -> Result<AppPusdcTransferV0> {
    if ev.kind != APP_KIND_PUSDC_TRANSFER_V0 {
        bail!(
            "event kind mismatch expected={} got={}",
            APP_KIND_PUSDC_TRANSFER_V0,
            ev.kind
        );
    }

    verify_event(ev)?;
    let bytes = decode_event_payload_bytes(ev)?;
    let transfer = decode_pusdc_transfer_payload_bytes(&bytes)?;
    verify_pusdc_transfer(&transfer)?;
    Ok(transfer)
}

pub fn decode_amm_add_liquidity_event(ev: &AppEventV0) -> Result<AppAmmAddLiquidityV0> {
    if ev.kind != APP_KIND_AMM_ADD_LIQUIDITY_V0 {
        bail!(
            "event kind mismatch expected={} got={}",
            APP_KIND_AMM_ADD_LIQUIDITY_V0,
            ev.kind
        );
    }

    verify_event(ev)?;
    let bytes = decode_event_payload_bytes(ev)?;
    let add = decode_amm_add_liquidity_payload_bytes(&bytes)?;
    verify_amm_add_liquidity(&add)?;
    Ok(add)
}

pub fn decode_amm_swap_bincoin_to_pusdc_event(
    ev: &AppEventV0,
) -> Result<AppAmmSwapBincoinToPusdcV0> {
    if ev.kind != APP_KIND_AMM_SWAP_BINCOIN_TO_PUSDC_V0 {
        bail!(
            "event kind mismatch expected={} got={}",
            APP_KIND_AMM_SWAP_BINCOIN_TO_PUSDC_V0,
            ev.kind
        );
    }

    verify_event(ev)?;
    let bytes = decode_event_payload_bytes(ev)?;
    let swap = decode_amm_swap_bincoin_to_pusdc_payload_bytes(&bytes)?;
    verify_amm_swap_bincoin_to_pusdc(&swap)?;
    Ok(swap)
}

pub fn decode_amm_swap_pusdc_to_bincoin_event(
    ev: &AppEventV0,
) -> Result<AppAmmSwapPusdcToBincoinV0> {
    if ev.kind != APP_KIND_AMM_SWAP_PUSDC_TO_BINCOIN_V0 {
        bail!(
            "event kind mismatch expected={} got={}",
            APP_KIND_AMM_SWAP_PUSDC_TO_BINCOIN_V0,
            ev.kind
        );
    }

    verify_event(ev)?;
    let bytes = decode_event_payload_bytes(ev)?;
    let swap = decode_amm_swap_pusdc_to_bincoin_payload_bytes(&bytes)?;
    verify_amm_swap_pusdc_to_bincoin(&swap)?;
    Ok(swap)
}

pub fn decode_bridge_lock_pusdc_event(ev: &AppEventV0) -> Result<AppBridgeLockPusdcV0> {
    if ev.kind != APP_KIND_BRIDGE_LOCK_PUSDC_V0 {
        bail!(
            "event kind mismatch expected={} got={}",
            APP_KIND_BRIDGE_LOCK_PUSDC_V0,
            ev.kind
        );
    }

    verify_event(ev)?;
    let bytes = decode_event_payload_bytes(ev)?;
    let lock = decode_bridge_lock_pusdc_payload_bytes(&bytes)?;
    verify_bridge_lock_pusdc(&lock)?;
    Ok(lock)
}

pub fn decode_bridge_unlock_pusdc_event(ev: &AppEventV0) -> Result<AppBridgeUnlockPusdcV0> {
    if ev.kind != APP_KIND_BRIDGE_UNLOCK_PUSDC_V0 {
        bail!(
            "event kind mismatch expected={} got={}",
            APP_KIND_BRIDGE_UNLOCK_PUSDC_V0,
            ev.kind
        );
    }

    verify_event(ev)?;
    let bytes = decode_event_payload_bytes(ev)?;
    let unlock = decode_bridge_unlock_pusdc_payload_bytes(&bytes)?;
    verify_bridge_unlock_pusdc(&unlock)?;
    Ok(unlock)
}

pub fn parse_amount_u128(raw: &str) -> Result<u128> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("amount empty");
    }

    let amount = trimmed
        .parse::<u128>()
        .map_err(|e| anyhow!("bad amount: {}", e))?;

    Ok(amount)
}

pub fn decode_event_payload_bytes(ev: &AppEventV0) -> Result<Vec<u8>> {
    general_purpose::STANDARD
        .decode(&ev.payload_b64)
        .map_err(|e| anyhow!("base64 decode: {e}"))
}

pub fn total_app_bytes(evs: &[AppEventV0]) -> u64 {
    evs.iter().map(|e| e.payload_len).sum()
}

pub fn app_events_hash_hex(evs: &[AppEventV0]) -> String {
    let mut h = Sha256::new();
    for e in evs {
        h.update(e.kind.as_bytes());
        h.update(e.payload_sha256_hex.as_bytes());
        h.update(e.payload_len.to_le_bytes());
    }
    hex::encode(h.finalize())
}

fn build_event_from_json<T: Serialize>(kind: &str, value: &T) -> Result<AppEventV0> {
    if kind.trim().is_empty() {
        bail!("event kind empty");
    }

    let bytes = serde_json::to_vec(value).map_err(|e| anyhow!("json serialize: {}", e))?;
    build_event_from_bytes(kind, &bytes)
}

fn build_event_from_bytes(kind: &str, bytes: &[u8]) -> Result<AppEventV0> {
    if kind.trim().is_empty() {
        bail!("event kind empty");
    }

    let mut h = Sha256::new();
    h.update(bytes);
    let sha = hex::encode(h.finalize());

    Ok(AppEventV0 {
        kind: kind.to_string(),
        payload_b64: general_purpose::STANDARD.encode(bytes),
        payload_len: bytes.len() as u64,
        payload_sha256_hex: sha,
    })
}

fn decode_transfer_payload_bytes(bytes: &[u8]) -> Result<AppTransferV0> {
    serde_json::from_slice(bytes).map_err(|e| anyhow!("transfer payload json parse: {}", e))
}

fn decode_pusdc_transfer_payload_bytes(bytes: &[u8]) -> Result<AppPusdcTransferV0> {
    serde_json::from_slice(bytes).map_err(|e| anyhow!("pUSDC transfer payload json parse: {}", e))
}

fn decode_amm_add_liquidity_payload_bytes(bytes: &[u8]) -> Result<AppAmmAddLiquidityV0> {
    serde_json::from_slice(bytes)
        .map_err(|e| anyhow!("amm add liquidity payload json parse: {}", e))
}

fn decode_amm_swap_bincoin_to_pusdc_payload_bytes(
    bytes: &[u8],
) -> Result<AppAmmSwapBincoinToPusdcV0> {
    serde_json::from_slice(bytes)
        .map_err(|e| anyhow!("amm swap bincoin->pUSDC payload json parse: {}", e))
}

fn decode_amm_swap_pusdc_to_bincoin_payload_bytes(
    bytes: &[u8],
) -> Result<AppAmmSwapPusdcToBincoinV0> {
    serde_json::from_slice(bytes)
        .map_err(|e| anyhow!("amm swap pUSDC->bincoin payload json parse: {}", e))
}

fn decode_bridge_lock_pusdc_payload_bytes(bytes: &[u8]) -> Result<AppBridgeLockPusdcV0> {
    serde_json::from_slice(bytes)
        .map_err(|e| anyhow!("bridge lock pUSDC payload json parse: {}", e))
}

fn decode_bridge_unlock_pusdc_payload_bytes(bytes: &[u8]) -> Result<AppBridgeUnlockPusdcV0> {
    serde_json::from_slice(bytes)
        .map_err(|e| anyhow!("bridge unlock pUSDC payload json parse: {}", e))
}
