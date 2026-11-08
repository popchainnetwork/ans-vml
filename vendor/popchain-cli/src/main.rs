#![forbid(unsafe_code)]

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use popchain_cli::{
    app::{
        build_amm_add_liquidity_event, build_amm_swap_bincoin_to_pusdc_event,
        build_amm_swap_pusdc_to_bincoin_event, build_pusdc_transfer_event, build_transfer_event,
    },
    bridge::{
        audit_bridge_events, bridge_events_path_for_db_root, read_bridge_events,
        set_bridge_event_burn_tx_id, set_bridge_event_external_tx_id, set_bridge_event_failure,
        update_bridge_event_status, BridgeAuditSeverityV1,
    },
    chain::{attach_block_signature_wots, slot_of_unix, Db},
    crypto::wots::{
        generate_wots_keypair, pk_to_hex, pseudo_root_from_pk, WotsKeypair, WOTS_CHAIN_LEN,
        WOTS_KEY_SIZE,
    },
    metrics::{
        build_pop1_container_from_bytes, compute_proof_from_file, derive_pop2_proof,
        pop1_container_hash, proof_v0_to_pop1, proof_v0_to_pop2,
        validate_pop1_container_against_bytes, validate_pop1_container_basic,
        validate_pop2_against_pop1, validate_pop2_basic, ProofV0, ScoringParamsV0,
    },
    net,
    types::{AddressV1, Hash32, Pop1ContainerV1, Pop2ProofV1},
    util,
    wallet::WalletV1,
};

const SYNC_SETTLE_MILLIS: u64 = 250;
const TIP_SETTLE_SECS: u64 = 1;

#[derive(Parser, Debug)]
#[command(name = "popchain-cli")]
#[command(
    about = "PopChain CLI v0.6.0 — deterministic L1 kernel + canonical PCIP/POP path + NDJSON P2P",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Init {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        chain_id: String,
        #[arg(long)]
        validators: String,
        #[arg(long, default_value_t = 5)]
        slot_secs: u64,
        #[arg(long, default_value = "")]
        validator_keys: String,
        #[arg(long, default_value = "")]
        reward_addresses: String,
        #[arg(long, default_value = "")]
        genesis_balances: String,
        #[arg(long, default_value = "")]
        treasury_address: String,
        #[arg(long, default_value = "")]
        genesis_pusdc_balances: String,
    },

    State {
        #[arg(long)]
        db: PathBuf,
    },

    FinalizeEpoch {
        #[arg(long)]
        db: PathBuf,
    },

    WalletNew,

    WalletInspect {
        #[arg(long)]
        address: String,
    },

    Balance {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        address: String,
    },

    BalancePusdc {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        address: String,
    },

    Transfer {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        from: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u128,
    },

    MintPusdc {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        treasury: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u128,
    },

    TransferPusdc {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        from: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u128,
    },

    TransferPusdcOnChain {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        from: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u128,
        #[arg(long)]
        producer: String,
        #[arg(long)]
        validator_key: Option<PathBuf>,
        #[arg(long, default_value = "")]
        broadcast: String,
    },

    AmmReserves {
        #[arg(long)]
        db: PathBuf,
    },

    AmmAddLiquidity {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        provider: String,
        #[arg(long)]
        bincoin: u128,
        #[arg(long)]
        pusdc: u128,
    },

    AmmAddLiquidityOnChain {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        provider: String,
        #[arg(long)]
        bincoin: u128,
        #[arg(long)]
        pusdc: u128,
        #[arg(long)]
        producer: String,
        #[arg(long)]
        validator_key: Option<PathBuf>,
        #[arg(long, default_value = "")]
        broadcast: String,
    },

    AmmQuoteBincoinToPusdc {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        amount_in: u128,
    },

    AmmQuotePusdcToBincoin {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        amount_in: u128,
    },

    AmmSwapBincoinToPusdc {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        user: String,
        #[arg(long)]
        amount_in: u128,
    },

    AmmSwapBincoinToPusdcOnChain {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        user: String,
        #[arg(long)]
        amount_in: u128,
        #[arg(long)]
        producer: String,
        #[arg(long)]
        validator_key: Option<PathBuf>,
        #[arg(long, default_value = "")]
        broadcast: String,
    },

    AmmSwapPusdcToBincoin {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        user: String,
        #[arg(long)]
        amount_in: u128,
    },

    AmmSwapPusdcToBincoinOnChain {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        user: String,
        #[arg(long)]
        amount_in: u128,
        #[arg(long)]
        producer: String,
        #[arg(long)]
        validator_key: Option<PathBuf>,
        #[arg(long, default_value = "")]
        broadcast: String,
    },

    LockPusdc {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        from: String,
        #[arg(long)]
        amount: u128,
        #[arg(long, alias = "solana-recipient", default_value = "")]
        external_recipient: String,
    },

    UnlockPusdc {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u128,
        #[arg(long)]
        event_id: String,
    },

    BridgeEvents {
        #[arg(long)]
        db: PathBuf,
    },

    BridgeAudit {
        #[arg(long)]
        db: PathBuf,
    },

    BridgeSetExternalTx {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        event_id: String,
        #[arg(long)]
        external_tx_id: String,
    },

    BridgeSetBurnTx {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        event_id: String,
        #[arg(long)]
        burn_tx_id: String,
    },

    BridgeSetStatus {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        event_id: String,
        #[arg(long)]
        status: String,
    },

    BridgeSetFailure {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        event_id: String,
        #[arg(long)]
        reason: String,
    },

    Faucet {
        #[arg(long)]
        dbs: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u128,
    },

    TransferOnChain {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        from: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u128,
        #[arg(long)]
        producer: String,
        #[arg(long)]
        validator_key: Option<PathBuf>,
        #[arg(long, default_value = "")]
        broadcast: String,
    },

    NetServe {
        #[arg(long)]
        db: PathBuf,
        #[arg(long, default_value = "127.0.0.1:7777")]
        bind: String,
    },

    NetConnect {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        addr: String,
    },

    RunSlots {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        vid: u32,
        #[arg(long)]
        producer: String,
        #[arg(long, default_value = "")]
        peers: String,
        #[arg(long)]
        validator_key: Option<PathBuf>,
    },

    Node {
        #[arg(long)]
        db: PathBuf,

        #[arg(long)]
        vid: u32,

        #[arg(long)]
        producer: String,

        #[arg(long, default_value = "127.0.0.1:7777")]
        bind: String,

        #[arg(long, default_value = "")]
        peers: String,

        #[arg(long)]
        validator_key: Option<PathBuf>,
    },

    ValidatorKeygen {
        #[arg(long)]
        validator: String,

        #[arg(long)]
        out: PathBuf,
    },

    ComputeProof {
        #[arg(long)]
        machine: String,

        #[arg(long)]
        file: PathBuf,

        #[arg(long)]
        out: PathBuf,

        #[arg(long)]
        db: Option<PathBuf>,

        #[arg(long, default_value_t = false)]
        auto_prev: bool,

        #[arg(long, default_value_t = 0)]
        sample_rate_hz: u64,

        #[arg(long, default_value_t = 0)]
        duration_ms: u64,

        #[arg(
            long,
            default_value = "0000000000000000000000000000000000000000000000000000000000000000"
        )]
        prev_capture_hash: String,
    },

    SubmitProof {
        #[arg(long)]
        db: PathBuf,

        #[arg(long)]
        proof: PathBuf,

        #[arg(long)]
        producer: String,

        #[arg(long)]
        validator_key: Option<PathBuf>,

        #[arg(long, default_value = "")]
        broadcast: String,
    },

    Process {
        #[arg(long)]
        db: PathBuf,

        #[arg(long)]
        producer: String,

        #[arg(long)]
        machine: String,

        #[arg(long)]
        file: PathBuf,

        #[arg(long)]
        validator_key: Option<PathBuf>,

        #[arg(long, default_value = "")]
        broadcast: String,

        #[arg(long, default_value_t = false)]
        auto_prev: bool,

        #[arg(long, default_value_t = 0)]
        sample_rate_hz: u64,

        #[arg(long, default_value_t = 0)]
        duration_ms: u64,

        #[arg(
            long,
            default_value = "0000000000000000000000000000000000000000000000000000000000000000"
        )]
        prev_capture_hash: String,
    },

    Pop1Create {
        #[arg(long)]
        machine: String,

        #[arg(long)]
        file: PathBuf,

        #[arg(long)]
        out: PathBuf,

        #[arg(long)]
        capture_start_unix: u64,

        #[arg(long)]
        capture_end_unix: u64,

        #[arg(
            long,
            default_value = "0000000000000000000000000000000000000000000000000000000000000000"
        )]
        prev_capture_hash: String,
    },

    Pop1Inspect {
        #[arg(long)]
        input: PathBuf,
    },

    Pop1Validate {
        #[arg(long)]
        input: PathBuf,

        #[arg(long)]
        file: Option<PathBuf>,
    },

    Pop2Create {
        #[arg(long)]
        pop1: PathBuf,

        #[arg(long)]
        out: PathBuf,
    },

    Pop2Inspect {
        #[arg(long)]
        input: PathBuf,
    },

    Pop2Validate {
        #[arg(long)]
        pop1: PathBuf,

        #[arg(long)]
        pop2: PathBuf,
    },

    LegacyProofInspect {
        #[arg(long)]
        input: PathBuf,
    },

    LegacyProofToPop {
        #[arg(long)]
        proof: PathBuf,

        #[arg(long)]
        pop1_out: PathBuf,

        #[arg(long)]
        pop2_out: PathBuf,
    },

    PcipCreatePop1 {
        #[arg(long)]
        machine: String,

        #[arg(long)]
        file: PathBuf,

        #[arg(long)]
        out: PathBuf,

        #[arg(long)]
        capture_start_unix: u64,

        #[arg(long)]
        capture_end_unix: u64,

        #[arg(
            long,
            default_value = "0000000000000000000000000000000000000000000000000000000000000000"
        )]
        prev_capture_hash: String,
    },

    PcipInspectPop1 {
        #[arg(long)]
        input: PathBuf,
    },

    PcipValidatePop1 {
        #[arg(long)]
        input: PathBuf,

        #[arg(long)]
        file: Option<PathBuf>,
    },

    PcipCreatePop2 {
        #[arg(long)]
        pop1: PathBuf,

        #[arg(long)]
        out: PathBuf,
    },

    PcipInspectPop2 {
        #[arg(long)]
        input: PathBuf,
    },

    PcipValidatePop2 {
        #[arg(long)]
        pop1: PathBuf,

        #[arg(long)]
        pop2: PathBuf,
    },

    PcipCreateBundle {
        #[arg(long)]
        machine: String,

        #[arg(long)]
        file: PathBuf,

        #[arg(long)]
        out: PathBuf,

        #[arg(long)]
        capture_start_unix: u64,

        #[arg(long)]
        capture_end_unix: u64,

        #[arg(
            long,
            default_value = "0000000000000000000000000000000000000000000000000000000000000000"
        )]
        prev_capture_hash: String,
    },

    PcipInspectBundle {
        #[arg(long)]
        input: PathBuf,
    },

    PcipValidateBundle {
        #[arg(long)]
        input: PathBuf,

        #[arg(long)]
        file: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ValidatorKeyFileV1 {
    version: u32,
    validator_id: String,
    wots_public_key_hex: String,
    wots_secret_key_hex: String,
    wots_root_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PcipBundleV1 {
    version: u32,
    pop1: Pop1ContainerV1,
    pop2: Pop2ProofV1,
}

fn banner() {
    println!(
        r#"
██████╗  ██████╗ ██████╗  ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗
██╔══██╗██╔═══██╗██╔══██╗██╔════╝██║  ██║██╔══██╗██║████╗  ██║
██████╔╝██║   ██║██████╔╝██║     ███████║███████║██║██╔██╗ ██║
██╔═══╝ ██║   ██║██╔═══╝ ██║     ██╔══██║██╔══██║██║██║╚██╗██║
██║     ╚██████╔╝██║     ╚██████╗██║  ██║██║  ██║██║██║ ╚████║
╚═╝      ╚═════╝ ╚═╝     ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝

popchain.network  —  Made in Netherlands  —  PPlastechniek 2026™
"#
    );
}

fn parse_validators(s: &str) -> Result<Vec<String>> {
    let parts: Vec<String> = s
        .split(',')
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect();

    if parts.is_empty() {
        bail!("validators empty (use --validators \"a,b,c\")");
    }

    Ok(parts)
}

fn parse_peers(s: &str) -> Vec<String> {
    s.split(',')
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect()
}

fn parse_paths_csv(s: &str) -> Vec<PathBuf> {
    s.split(',')
        .map(|x| x.trim())
        .filter(|x| !x.is_empty())
        .map(PathBuf::from)
        .collect()
}

fn parse_reward_addresses_csv(validators: &[String], s: &str) -> Result<HashMap<String, String>> {
    let mut out = HashMap::new();

    if s.trim().is_empty() {
        return Ok(out);
    }

    for part in s.split(',').map(|x| x.trim()).filter(|x| !x.is_empty()) {
        let (validator_id, address_raw) = part.split_once('=').ok_or_else(|| {
            anyhow!(
                "bad reward-address entry '{}', expected validator=address",
                part
            )
        })?;

        let validator_id = validator_id.trim().to_string();
        let address_raw = address_raw.trim();

        if !validators.iter().any(|v| v == &validator_id) {
            bail!(
                "reward address provided for unknown validator_id={}",
                validator_id
            );
        }

        let addr = AddressV1::parse(address_raw)
            .with_context(|| format!("parse reward address for validator_id={}", validator_id))?;

        if out.contains_key(&validator_id) {
            bail!("duplicate reward address for validator_id={}", validator_id);
        }

        out.insert(validator_id, addr.to_string());
    }

    Ok(out)
}

fn parse_genesis_balances_csv(s: &str) -> Result<HashMap<String, u128>> {
    let mut out = HashMap::new();

    if s.trim().is_empty() {
        return Ok(out);
    }

    for part in s.split(',').map(|x| x.trim()).filter(|x| !x.is_empty()) {
        let (address_raw, amount_raw) = part.split_once('=').ok_or_else(|| {
            anyhow!(
                "bad genesis-balance entry '{}', expected address=amount",
                part
            )
        })?;

        let addr = AddressV1::parse(address_raw.trim())
            .with_context(|| format!("parse genesis balance address '{}'", address_raw.trim()))?;

        let amount = amount_raw
            .trim()
            .parse::<u128>()
            .with_context(|| format!("parse genesis balance amount '{}'", amount_raw.trim()))?;

        if amount == 0 {
            bail!("genesis balance for {} must be > 0", addr);
        }

        if out.contains_key(&addr.to_string()) {
            bail!("duplicate genesis balance for {}", addr);
        }

        out.insert(addr.to_string(), amount);
    }

    Ok(out)
}

fn elems_to_hex(elems: &[[u8; WOTS_KEY_SIZE]]) -> String {
    let mut out = Vec::with_capacity(elems.len() * WOTS_KEY_SIZE);
    for elem in elems {
        out.extend_from_slice(elem);
    }
    hex::encode(out)
}

fn elems_from_hex(s: &str, label: &str) -> Result<Vec<[u8; WOTS_KEY_SIZE]>> {
    let bytes = hex::decode(s).with_context(|| format!("decode {}", label))?;

    if bytes.len() % WOTS_KEY_SIZE != 0 {
        bail!(
            "{} byte length {} is not divisible by {}",
            label,
            bytes.len(),
            WOTS_KEY_SIZE
        );
    }

    let count = bytes.len() / WOTS_KEY_SIZE;
    if count != WOTS_CHAIN_LEN {
        bail!(
            "{} element count {} != expected {}",
            label,
            count,
            WOTS_CHAIN_LEN
        );
    }

    let mut out = Vec::with_capacity(count);
    for chunk in bytes.chunks_exact(WOTS_KEY_SIZE) {
        let mut arr = [0u8; WOTS_KEY_SIZE];
        arr.copy_from_slice(chunk);
        out.push(arr);
    }

    Ok(out)
}

fn write_validator_key_file(path: &Path, validator_id: &str) -> Result<ValidatorKeyFileV1> {
    if validator_id.trim().is_empty() {
        bail!("validator id empty");
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create parent dir {}", parent.display()))?;
    }

    let kp = generate_wots_keypair();
    let root_hex = hex::encode(pseudo_root_from_pk(&kp.pk));

    let file = ValidatorKeyFileV1 {
        version: 1,
        validator_id: validator_id.to_string(),
        wots_public_key_hex: pk_to_hex(&kp.pk),
        wots_secret_key_hex: elems_to_hex(&kp.sk),
        wots_root_hex: root_hex,
    };

    let json = serde_json::to_string_pretty(&file).context("serialize validator key file")?;
    fs::write(path, json).with_context(|| format!("write {}", path.display()))?;

    Ok(file)
}

fn read_validator_key_file(path: &Path) -> Result<ValidatorKeyFileV1> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let file: ValidatorKeyFileV1 =
        serde_json::from_str(&raw).context("parse validator key json")?;

    if file.version != 1 {
        bail!("unsupported validator key version {}", file.version);
    }
    if file.validator_id.trim().is_empty() {
        bail!("validator key file has empty validator_id");
    }

    Ok(file)
}

fn load_wots_keypair_from_file(path: &Path) -> Result<(String, WotsKeypair, String)> {
    let file = read_validator_key_file(path)?;

    let sk = elems_from_hex(&file.wots_secret_key_hex, "wots_secret_key_hex")?;
    let pk = elems_from_hex(&file.wots_public_key_hex, "wots_public_key_hex")?;

    let recomputed_root = hex::encode(pseudo_root_from_pk(&pk));
    if recomputed_root != file.wots_root_hex {
        bail!(
            "validator key root mismatch: file_root={} recomputed_root={}",
            file.wots_root_hex,
            recomputed_root
        );
    }

    let kp = WotsKeypair { sk, pk };

    Ok((file.validator_id, kp, file.wots_root_hex))
}

fn collect_validator_roots_from_files(
    validators: &[String],
    validator_key_paths: &[PathBuf],
) -> Result<HashMap<String, String>> {
    if validator_key_paths.is_empty() {
        return Ok(HashMap::new());
    }

    let mut roots = HashMap::new();

    for path in validator_key_paths {
        let file = read_validator_key_file(path)?;

        if !validators.iter().any(|v| v == &file.validator_id) {
            bail!(
                "validator key file {} contains validator_id {} not present in --validators",
                path.display(),
                file.validator_id
            );
        }

        if roots.contains_key(&file.validator_id) {
            bail!(
                "duplicate validator key for validator_id {}",
                file.validator_id
            );
        }

        roots.insert(file.validator_id, file.wots_root_hex);
    }

    Ok(roots)
}

fn read_pop1_from_json(path: &Path) -> Result<Pop1ContainerV1> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&raw).context("parse POP-1 json")
}

fn write_pop1_to_json(path: &Path, pop1: &Pop1ContainerV1) -> Result<()> {
    let json = serde_json::to_string_pretty(pop1).context("serialize POP-1 json")?;
    fs::write(path, json).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn read_pop2_from_json(path: &Path) -> Result<Pop2ProofV1> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&raw).context("parse POP-2 json")
}

fn write_pop2_to_json(path: &Path, pop2: &Pop2ProofV1) -> Result<()> {
    let json = serde_json::to_string_pretty(pop2).context("serialize POP-2 json")?;
    fs::write(path, json).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn read_legacy_proof_from_json(path: &Path) -> Result<ProofV0> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&raw).context("parse legacy proof json")
}

fn write_legacy_proof_to_json(path: &Path, proof: &ProofV0) -> Result<()> {
    let json = serde_json::to_string_pretty(proof).context("serialize legacy proof json")?;
    fs::write(path, json).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn read_pcip_bundle_from_json(path: &Path) -> Result<PcipBundleV1> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&raw).context("parse PCIP bundle json")
}

fn write_pcip_bundle_to_json(path: &Path, bundle: &PcipBundleV1) -> Result<()> {
    let json = serde_json::to_string_pretty(bundle).context("serialize PCIP bundle json")?;
    fs::write(path, json).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn parse_hash32_hex(s: &str, label: &str) -> Result<Hash32> {
    Hash32::from_hex(s).with_context(|| format!("parse {}", label))
}

fn print_pop1(pop1: &Pop1ContainerV1) {
    println!("object: POP-1");
    println!("version: {}", pop1.header.version);
    println!("machine_id: {}", pop1.header.machine_id);
    println!("capture_start_unix: {}", pop1.header.capture_start_unix);
    println!("capture_end_unix: {}", pop1.header.capture_end_unix);
    println!("prev_capture_hash: {}", pop1.header.prev_capture_hash);
    println!("payload_size_bytes: {}", pop1.integrity.payload_size_bytes);
    println!("sha256: {}", pop1.integrity.sha256);
    println!("blake3: {}", pop1.integrity.blake3);
    println!("entropy_q32: {}", pop1.metrics.entropy_q32);
    println!("compression_ppm: {}", pop1.metrics.compression_ppm);
    println!("mad_q32: {}", pop1.metrics.mad_q32);
    println!("container_hash: {}", pop1_container_hash(pop1));
}

fn print_pop2(pop2: &Pop2ProofV1) {
    println!("object: POP-2");
    println!("version: {}", pop2.version);
    println!("machine_id: {}", pop2.machine_id);
    println!("capture_start_unix: {}", pop2.capture_start_unix);
    println!("capture_end_unix: {}", pop2.capture_end_unix);
    println!("container_hash: {}", pop2.container_hash);
    println!("score_u64: {}", pop2.score_u64);
    println!("mbw_u64: {}", pop2.mbw_u64);
    println!("proof_hash: {}", pop2.proof_hash);
}

fn build_pcip_bundle_from_file(
    machine: &str,
    file: &Path,
    capture_start_unix: u64,
    capture_end_unix: u64,
    prev_capture_hash_hex: &str,
) -> Result<PcipBundleV1> {
    let bytes = fs::read(file).with_context(|| format!("read {}", file.display()))?;
    let prev_capture_hash = parse_hash32_hex(prev_capture_hash_hex, "prev_capture_hash")?;
    let params = ScoringParamsV0::default();

    let pop1 = build_pop1_container_from_bytes(
        machine,
        &bytes,
        capture_start_unix,
        capture_end_unix,
        prev_capture_hash,
    )
    .context("build_pop1_container_from_bytes")?;

    let pop2 = derive_pop2_proof(&pop1, &params).context("derive_pop2_proof")?;

    Ok(PcipBundleV1 {
        version: 1,
        pop1,
        pop2,
    })
}

fn validate_pcip_bundle(bundle: &PcipBundleV1, file: Option<&Path>) -> Result<()> {
    if bundle.version != 1 {
        bail!("unsupported PCIP bundle version {}", bundle.version);
    }

    match file {
        Some(path) => {
            let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
            validate_pop1_container_against_bytes(&bundle.pop1, &bytes)?;
        }
        None => {
            validate_pop1_container_basic(&bundle.pop1)?;
        }
    }

    validate_pop2_basic(&bundle.pop2)?;
    validate_pop2_against_pop1(&bundle.pop2, &bundle.pop1, &ScoringParamsV0::default())?;

    Ok(())
}

fn apply_faucet_to_db(_db: &Path, _to: &str, _amount: u128) -> Result<(u128, String)> {
    bail!("faucet disabled: use genesis balances instead of editing state outside chain history")
}

async fn sync_with_peers(db: &Path, peers: &[String], context_label: &str) {
    if peers.is_empty() {
        return;
    }

    for peer in peers {
        let dbh = match Db::open(db) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[sync:{}] open db failed: {}", context_label, e);
                return;
            }
        };

        let shared = Arc::new(Mutex::new(dbh));
        if let Err(e) = net::connect_once(shared, peer).await {
            eprintln!("[sync:{}] peer={} failed: {}", context_label, peer, e);
        } else {
            eprintln!("[sync:{}] peer={} ok", context_label, peer);
        }
    }
}

async fn run_slot_loop(
    db: PathBuf,
    vid: u32,
    producer: String,
    peers: Vec<String>,
    validator_key: Option<PathBuf>,
) -> Result<()> {
    let mut dbh = Db::open(&db)?;

    let signing_key = match validator_key {
        Some(path) => {
            let (validator_id, kp, root_hex) = load_wots_keypair_from_file(&path)?;
            if validator_id != producer {
                bail!(
                    "--producer {} does not match validator key validator_id {}",
                    producer,
                    validator_id
                );
            }

            println!(
                "[slot] loaded validator key file={} validator_id={} root={}",
                path.display(),
                validator_id,
                root_hex
            );

            Some(kp)
        }
        None => {
            println!("[slot] validator_key not provided -> producing unsigned blocks");
            None
        }
    };

    let n = dbh.validators_len()?;
    if n == 0 {
        bail!("validators empty");
    }
    if (vid as usize) >= n {
        bail!("--vid {} out of range (validators={})", vid, n);
    }

    let slot_secs = dbh.slot_duration_secs()?;

    println!(
        "[slot] start producer={} vid={} slot_secs={} validators={} peers={}",
        producer,
        vid,
        slot_secs,
        n,
        peers.len()
    );

    let initial_state = dbh.read_state()?;
    let mut last_seen_tip = initial_state.best_tip_hash_hex.clone();
    let mut last_tip_change_unix = util::now_unix();

    sync_with_peers(&db, &peers, "startup").await;
    tokio::time::sleep(std::time::Duration::from_millis(SYNC_SETTLE_MILLIS)).await;

    dbh = Db::open(&db)?;
    let st_after_startup = dbh.read_state()?;
    if st_after_startup.best_tip_hash_hex != last_seen_tip {
        last_seen_tip = st_after_startup.best_tip_hash_hex.clone();
        last_tip_change_unix = util::now_unix();
    }

    loop {
        let slot_probe_unix = util::now_unix();
        let slot_before_sync = slot_of_unix(slot_probe_unix, slot_secs);

        let pre_sync_db = Db::open(&db)?;
        let pre_sync_state = pre_sync_db.read_state()?;

        sync_with_peers(&db, &peers, "pre-slot").await;
        tokio::time::sleep(std::time::Duration::from_millis(SYNC_SETTLE_MILLIS)).await;

        let now_after_sync = util::now_unix();
        let slot_after_sync = slot_of_unix(now_after_sync, slot_secs);

        if slot_after_sync != slot_before_sync {
            println!(
                "[slot] skip slot={} reason=slot-advanced-during-sync new_slot={}",
                slot_before_sync, slot_after_sync
            );
            let next_slot_unix = (slot_after_sync + 1) * slot_secs;
            let sleep_secs = next_slot_unix.saturating_sub(now_after_sync).max(1);
            tokio::time::sleep(std::time::Duration::from_secs(sleep_secs)).await;
            continue;
        }

        dbh = Db::open(&db)?;
        let post_sync_state = dbh.read_state()?;

        if post_sync_state.best_tip_hash_hex != last_seen_tip {
            last_seen_tip = post_sync_state.best_tip_hash_hex.clone();
            last_tip_change_unix = now_after_sync;
        }

        let leader = dbh.leader_vid_for_slot(slot_after_sync)?;

        if leader == vid {
            if post_sync_state.best_tip_hash_hex != pre_sync_state.best_tip_hash_hex {
                println!(
                    "[slot] skip slot={} reason=tip-changed-during-sync old_tip={} new_tip={}",
                    slot_after_sync,
                    pre_sync_state.best_tip_hash_hex,
                    post_sync_state.best_tip_hash_hex
                );
            } else if now_after_sync.saturating_sub(last_tip_change_unix) < TIP_SETTLE_SECS {
                println!(
                    "[slot] skip slot={} reason=tip-settle-window seconds_since_tip_change={}",
                    slot_after_sync,
                    now_after_sync.saturating_sub(last_tip_change_unix)
                );
            } else {
                tokio::time::sleep(std::time::Duration::from_millis(SYNC_SETTLE_MILLIS)).await;

                let final_probe_unix = util::now_unix();
                let final_probe_slot = slot_of_unix(final_probe_unix, slot_secs);
                if final_probe_slot != slot_after_sync {
                    println!(
                        "[slot] skip slot={} reason=slot-advanced-before-mine new_slot={}",
                        slot_after_sync, final_probe_slot
                    );
                } else {
                    dbh = Db::open(&db)?;
                    let final_state = dbh.read_state()?;

                    if final_state.best_tip_hash_hex != post_sync_state.best_tip_hash_hex {
                        last_seen_tip = final_state.best_tip_hash_hex.clone();
                        last_tip_change_unix = final_probe_unix;
                        println!(
                            "[slot] skip slot={} reason=tip-changed-before-mine old_tip={} new_tip={}",
                            slot_after_sync,
                            post_sync_state.best_tip_hash_hex,
                            final_state.best_tip_hash_hex
                        );
                    } else {
                        let epoch_id = format!("slot:{}", slot_after_sync);

                        let mut blk = dbh
                            .make_block_from_mempool(&producer, &epoch_id, vec![])
                            .context("make_block_from_mempool")?;

                        if let Some(kp) = &signing_key {
                            attach_block_signature_wots(&mut blk, &producer, kp)
                                .context("attach_block_signature_wots")?;
                        }

                        dbh.import_block(&blk).context("import_block")?;

                        last_seen_tip = blk.block_hash_hex.clone();
                        last_tip_change_unix = util::now_unix();

                        println!(
                            "[slot] mined slot={} leader_vid={} height={} tip={} signed={}",
                            slot_after_sync,
                            leader,
                            blk.header.height,
                            blk.block_hash_hex,
                            blk.block_signature.is_some()
                        );

                        if !peers.is_empty() {
                            let peers2 = peers.clone();
                            let blk2 = blk.clone();
                            tokio::spawn(async move {
                                net::broadcast_block(&peers2, blk2).await;
                            });
                        }
                    }
                }
            }
        } else {
            println!(
                "[slot] slot={} leader_vid={} (not me)",
                slot_after_sync, leader
            );
        }

        let next_slot_unix = (slot_after_sync + 1) * slot_secs;
        let now2 = util::now_unix();
        let sleep_secs = next_slot_unix.saturating_sub(now2).max(1);
        tokio::time::sleep(std::time::Duration::from_secs(sleep_secs)).await;
    }
}

fn print_bridge_event_jsonish(index: usize, ev: &serde_json::Value) {
    println!("event[{}]:", index);
    if let Some(obj) = ev.as_object() {
        let mut keys: Vec<_> = obj.keys().cloned().collect();
        keys.sort();
        for key in keys {
            let value = &obj[&key];
            println!("  {}: {}", key, value);
        }
    } else {
        println!("  {}", ev);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    banner();

    match cli.cmd {
        Commands::Init {
            db,
            chain_id,
            validators,
            slot_secs,
            validator_keys,
            reward_addresses,
            genesis_balances,
            treasury_address,
            genesis_pusdc_balances,
        } => {
            let validators = parse_validators(&validators)?;
            let validator_key_paths = parse_paths_csv(&validator_keys);
            let roots = collect_validator_roots_from_files(&validators, &validator_key_paths)?;
            let reward_map = parse_reward_addresses_csv(&validators, &reward_addresses)?;
            let genesis_balance_map = parse_genesis_balances_csv(&genesis_balances)?;
            let genesis_pusdc_balance_map = parse_genesis_balances_csv(&genesis_pusdc_balances)?;
            let treasury_address = if treasury_address.trim().is_empty() {
                None
            } else {
                Some(
                    AddressV1::parse(treasury_address.trim())
                        .context("parse treasury_address")?
                        .to_string(),
                )
            };

            let mut dbh = Db::open(&db)?;
            dbh.init_with_validator_wots_roots_reward_addresses_treasury_and_initial_balances(
                &chain_id,
                validators,
                roots.clone(),
                reward_map.clone(),
                treasury_address.clone(),
                genesis_balance_map.clone(),
                genesis_pusdc_balance_map.clone(),
                slot_secs,
            )?;

            println!("[ok] initialized {}", db.display());
            println!("validator_wots_roots_count: {}", roots.len());
            println!("validator_reward_addresses_count: {}", reward_map.len());
            println!("genesis_balances_count: {}", genesis_balance_map.len());
            println!(
                "genesis_pusdc_balances_count: {}",
                genesis_pusdc_balance_map.len()
            );
            if let Some(addr) = &treasury_address {
                println!("treasury_address: {}", addr);
            }

            if !roots.is_empty() {
                let mut rows: Vec<_> = roots.iter().collect();
                rows.sort_by(|a, b| a.0.cmp(b.0));
                for (validator_id, root_hex) in rows {
                    println!("  wots_root {} => {}", validator_id, root_hex);
                }
            }

            if !reward_map.is_empty() {
                let mut rows: Vec<_> = reward_map.iter().collect();
                rows.sort_by(|a, b| a.0.cmp(b.0));
                for (validator_id, addr) in rows {
                    println!("  reward_address {} => {}", validator_id, addr);
                }
            }

            if !genesis_balance_map.is_empty() {
                let mut rows: Vec<_> = genesis_balance_map.iter().collect();
                rows.sort_by(|a, b| a.0.cmp(b.0));
                println!("genesis_balances:");
                for (addr, amount) in rows {
                    println!("  {} => {}", addr, amount);
                }
            }

            if !genesis_pusdc_balance_map.is_empty() {
                let mut rows: Vec<_> = genesis_pusdc_balance_map.iter().collect();
                rows.sort_by(|a, b| a.0.cmp(b.0));
                println!("genesis_pusdc_balances:");
                for (addr, amount) in rows {
                    println!("  {} => {}", addr, amount);
                }
            }
        }

        Commands::State { db } => {
            let dbh = Db::open(&db)?;
            let g = dbh.read_genesis()?;
            let st = dbh.read_state()?;

            println!("chain_id: {}", g.chain_id);
            println!("validators: {}", g.validators.len());
            println!("slot_secs: {}", g.slot_duration_secs);
            println!("best_height: {}", st.best_height);
            println!("best_tip: {}", st.best_tip_hash_hex);
            println!("chain_mbw_v0: {}", st.chain_mbw_v0);
            println!("state_root_hex: {}", st.state_root_hex);

            println!(
                "machine_last_capture_hash_count: {}",
                st.machine_last_capture_hash.len()
            );

            println!("latest_finalized_epoch: {}", st.latest_finalized_epoch);
            println!(
                "latest_finalized_epoch_hash: {}",
                st.latest_finalized_epoch_hash_hex
            );

            println!(
                "validator_stake_credit_count: {}",
                st.validator_stake_credit.len()
            );
            if !st.validator_stake_credit.is_empty() {
                println!("validator_stake_credit:");
                let mut rows: Vec<_> = st.validator_stake_credit.iter().collect();
                rows.sort_by(|a, b| a.0.cmp(b.0));
                for (k, v) in rows {
                    println!("  {} => {}", k, v);
                }
            }

            println!(
                "validator_minted_bincoin_count: {}",
                st.validator_minted_bincoin.len()
            );
            if !st.validator_minted_bincoin.is_empty() {
                println!("validator_minted_bincoin:");
                let mut rows: Vec<_> = st.validator_minted_bincoin.iter().collect();
                rows.sort_by(|a, b| a.0.cmp(b.0));
                for (k, v) in rows {
                    println!("  {} => {}", k, v);
                }
            }

            println!("balances_count: {}", st.balances.len());
            if !st.balances.is_empty() {
                println!("balances:");
                let mut rows: Vec<_> = st.balances.iter().collect();
                rows.sort_by(|a, b| a.0.cmp(b.0));
                for (k, v) in rows {
                    println!("  {} => {}", k, v);
                }
            }

            println!("pusdc_balances_count: {}", st.pusdc_balances.len());
            if !st.pusdc_balances.is_empty() {
                println!("pusdc_balances:");
                let mut rows: Vec<_> = st.pusdc_balances.iter().collect();
                rows.sort_by(|a, b| a.0.cmp(b.0));
                for (k, v) in rows {
                    println!("  {} => {}", k, v);
                }
            }

            println!("pusdc_locked_count: {}", st.pusdc_locked.len());
            if !st.pusdc_locked.is_empty() {
                println!("pusdc_locked:");
                let mut rows: Vec<_> = st.pusdc_locked.iter().collect();
                rows.sort_by(|a, b| a.0.cmp(b.0));
                for (k, v) in rows {
                    println!("  {} => {}", k, v);
                }
            }

            println!("amm_bincoin_reserve: {}", st.amm_bincoin_reserve);
            println!("amm_pusdc_reserve: {}", st.amm_pusdc_reserve);

            println!(
                "validator_wots_roots_count: {}",
                g.validator_wots_roots_hex.len()
            );
            if !g.validator_wots_roots_hex.is_empty() {
                println!("validator_wots_roots_hex:");
                let mut rows: Vec<_> = g.validator_wots_roots_hex.iter().collect();
                rows.sort_by(|a, b| a.0.cmp(b.0));
                for (k, v) in rows {
                    println!("  {} => {}", k, v);
                }
            }

            println!(
                "validator_reward_addresses_count: {}",
                g.validator_reward_addresses.len()
            );
            if !g.validator_reward_addresses.is_empty() {
                println!("validator_reward_addresses:");
                let mut rows: Vec<_> = g.validator_reward_addresses.iter().collect();
                rows.sort_by(|a, b| a.0.cmp(b.0));
                for (k, v) in rows {
                    println!("  {} => {}", k, v);
                }
            }

            if let Some(addr) = &g.treasury_address {
                println!("treasury_address: {}", addr);
            }

            println!("initial_balances_count: {}", g.initial_balances.len());
            if !g.initial_balances.is_empty() {
                println!("initial_balances:");
                let mut rows: Vec<_> = g.initial_balances.iter().collect();
                rows.sort_by(|a, b| a.0.cmp(b.0));
                for (k, v) in rows {
                    println!("  {} => {}", k, v);
                }
            }

            println!(
                "initial_pusdc_balances_count: {}",
                g.initial_pusdc_balances.len()
            );
            if !g.initial_pusdc_balances.is_empty() {
                println!("initial_pusdc_balances:");
                let mut rows: Vec<_> = g.initial_pusdc_balances.iter().collect();
                rows.sort_by(|a, b| a.0.cmp(b.0));
                for (k, v) in rows {
                    println!("  {} => {}", k, v);
                }
            }
        }

        Commands::FinalizeEpoch { db } => {
            let mut dbh = Db::open(&db)?;
            let finalized_epoch = dbh.finalize_latest_complete_epoch()?;
            let st = dbh.read_state()?;

            println!("[ok] epoch finalized");
            println!("db: {}", db.display());
            println!("finalized_epoch: {}", finalized_epoch);
            println!("latest_finalized_epoch: {}", st.latest_finalized_epoch);
            println!(
                "latest_finalized_epoch_hash: {}",
                st.latest_finalized_epoch_hash_hex
            );
            println!("state_root_hex: {}", st.state_root_hex);
            println!(
                "artifact: {}",
                db.join("finality")
                    .join(format!("epoch_{}.json", finalized_epoch))
                    .display()
            );
        }

        Commands::WalletNew => {
            let wallet = WalletV1::generate();
            wallet.validate()?;

            println!("[ok] wallet generated");
            println!("address: {}", wallet.address_string());
        }

        Commands::WalletInspect { address } => {
            let wallet = WalletV1::from_address_str(&address)?;
            wallet.validate()?;

            println!("[ok] wallet address valid");
            println!("address: {}", wallet.address_string());
        }

        Commands::Balance { db, address } => {
            let addr = AddressV1::parse(&address)?;
            let dbh = Db::open(&db)?;
            let st = dbh.read_state()?;
            let amount = st.balances.get(&addr.to_string()).copied().unwrap_or(0);

            println!("[ok] balance");
            println!("address: {}", addr);
            println!("amount: {}", amount);
        }

        Commands::BalancePusdc { db, address } => {
            let addr = AddressV1::parse(&address)?;
            let dbh = Db::open(&db)?;
            let (available, locked, total) = dbh.balance_pusdc(&addr.to_string())?;

            println!("[ok] pUSDC balance");
            println!("address: {}", addr);
            println!("available: {}", available);
            println!("locked: {}", locked);
            println!("total: {}", total);
        }

        Commands::Transfer {
            db,
            from,
            to,
            amount,
        } => {
            let from_addr = AddressV1::parse(&from)?;
            let to_addr = AddressV1::parse(&to)?;

            let mut dbh = Db::open(&db)?;
            dbh.transfer_balance(&from_addr.to_string(), &to_addr.to_string(), amount)?;

            let st = dbh.read_state()?;
            let from_balance = st
                .balances
                .get(&from_addr.to_string())
                .copied()
                .unwrap_or(0);
            let to_balance = st.balances.get(&to_addr.to_string()).copied().unwrap_or(0);

            println!("[ok] transfer");
            println!("from: {}", from_addr);
            println!("to: {}", to_addr);
            println!("amount: {}", amount);
            println!("from_balance: {}", from_balance);
            println!("to_balance: {}", to_balance);
            println!("state_root_hex: {}", st.state_root_hex);
        }

        Commands::MintPusdc {
            db,
            treasury,
            to,
            amount,
        } => {
            let treasury_addr = AddressV1::parse(&treasury)?;
            let to_addr = AddressV1::parse(&to)?;

            let mut dbh = Db::open(&db)?;
            dbh.mint_pusdc(&treasury_addr.to_string(), &to_addr.to_string(), amount)?;

            let (available, locked, total) = dbh.balance_pusdc(&to_addr.to_string())?;
            let st = dbh.read_state()?;

            println!("[ok] pUSDC minted");
            println!("treasury: {}", treasury_addr);
            println!("to: {}", to_addr);
            println!("amount: {}", amount);
            println!("available: {}", available);
            println!("locked: {}", locked);
            println!("total: {}", total);
            println!("state_root_hex: {}", st.state_root_hex);
        }

        Commands::TransferPusdc {
            db,
            from,
            to,
            amount,
        } => {
            let from_addr = AddressV1::parse(&from)?;
            let to_addr = AddressV1::parse(&to)?;

            let mut dbh = Db::open(&db)?;
            dbh.transfer_pusdc(&from_addr.to_string(), &to_addr.to_string(), amount)?;

            let (from_available, from_locked, from_total) =
                dbh.balance_pusdc(&from_addr.to_string())?;
            let (to_available, to_locked, to_total) = dbh.balance_pusdc(&to_addr.to_string())?;
            let st = dbh.read_state()?;

            println!("[ok] pUSDC transfer");
            println!("from: {}", from_addr);
            println!("to: {}", to_addr);
            println!("amount: {}", amount);
            println!(
                "from_available: {} from_locked: {} from_total: {}",
                from_available, from_locked, from_total
            );
            println!(
                "to_available: {} to_locked: {} to_total: {}",
                to_available, to_locked, to_total
            );
            println!("state_root_hex: {}", st.state_root_hex);
        }

        Commands::TransferPusdcOnChain {
            db,
            from,
            to,
            amount,
            producer,
            validator_key,
            broadcast,
        } => {
            let from_addr = AddressV1::parse(&from)?;
            let to_addr = AddressV1::parse(&to)?;
            let broadcast_peers = parse_peers(&broadcast);

            if !broadcast_peers.is_empty() {
                sync_with_peers(&db, &broadcast_peers, "transfer-pusdc-pre-sync").await;
                tokio::time::sleep(std::time::Duration::from_millis(SYNC_SETTLE_MILLIS)).await;
            }

            let ev =
                build_pusdc_transfer_event(&from_addr.to_string(), &to_addr.to_string(), amount)?;

            let mut dbh = Db::open(&db)?;
            let epoch_id = format!("manual-pusdc-transfer:{}", util::now_unix());

            let mut blk = dbh
                .make_block_on_best(&producer, &epoch_id, vec![], vec![ev])
                .context("make_block_on_best with pUSDC transfer event")?;

            if let Some(path) = validator_key {
                let (validator_id, kp, root_hex) = load_wots_keypair_from_file(&path)?;
                if validator_id != producer {
                    bail!(
                        "--producer {} does not match validator key validator_id {}",
                        producer,
                        validator_id
                    );
                }

                attach_block_signature_wots(&mut blk, &producer, &kp)
                    .context("attach_block_signature_wots")?;

                println!(
                    "[transfer-pusdc-on-chain] loaded validator key file={} validator_id={} root={}",
                    path.display(),
                    validator_id,
                    root_hex
                );
            }

            dbh.import_block(&blk)
                .context("import pUSDC transfer block")?;

            let (from_available, from_locked, from_total) =
                dbh.balance_pusdc(&from_addr.to_string())?;
            let (to_available, to_locked, to_total) = dbh.balance_pusdc(&to_addr.to_string())?;
            let st = dbh.read_state()?;

            println!("[ok] pUSDC transfer submitted on-chain");
            println!("producer: {}", producer);
            println!("from: {}", from_addr);
            println!("to: {}", to_addr);
            println!("amount: {}", amount);
            println!("block_height: {}", blk.header.height);
            println!("block_hash: {}", blk.block_hash_hex);
            println!("signed: {}", blk.block_signature.is_some());
            println!(
                "from_available: {} from_locked: {} from_total: {}",
                from_available, from_locked, from_total
            );
            println!(
                "to_available: {} to_locked: {} to_total: {}",
                to_available, to_locked, to_total
            );
            println!("state_root_hex: {}", st.state_root_hex);

            if !broadcast_peers.is_empty() {
                net::broadcast_block(&broadcast_peers, blk.clone()).await;
                println!("broadcast_peers: {}", broadcast_peers.len());
                for peer in &broadcast_peers {
                    println!("  broadcast -> {}", peer);
                }
            }
        }

        Commands::AmmReserves { db } => {
            let dbh = Db::open(&db)?;
            let (bincoin_reserve, pusdc_reserve) = dbh.amm_reserves()?;

            println!("[ok] amm reserves");
            println!("amm_bincoin_reserve: {}", bincoin_reserve);
            println!("amm_pusdc_reserve: {}", pusdc_reserve);
        }

        Commands::AmmAddLiquidity {
            db,
            provider,
            bincoin,
            pusdc,
        } => {
            let provider_addr = AddressV1::parse(&provider)?;
            let mut dbh = Db::open(&db)?;
            dbh.amm_add_liquidity(&provider_addr.to_string(), bincoin, pusdc)?;

            let st = dbh.read_state()?;
            let provider_bincoin = st
                .balances
                .get(&provider_addr.to_string())
                .copied()
                .unwrap_or(0);
            let provider_pusdc = st
                .pusdc_balances
                .get(&provider_addr.to_string())
                .copied()
                .unwrap_or(0);

            println!("[ok] amm liquidity added");
            println!("provider: {}", provider_addr);
            println!("bincoin_added: {}", bincoin);
            println!("pusdc_added: {}", pusdc);
            println!("amm_bincoin_reserve: {}", st.amm_bincoin_reserve);
            println!("amm_pusdc_reserve: {}", st.amm_pusdc_reserve);
            println!("provider_bincoin_balance: {}", provider_bincoin);
            println!("provider_pusdc_balance: {}", provider_pusdc);
            println!("state_root_hex: {}", st.state_root_hex);
        }

        Commands::AmmAddLiquidityOnChain {
            db,
            provider,
            bincoin,
            pusdc,
            producer,
            validator_key,
            broadcast,
        } => {
            let provider_addr = AddressV1::parse(&provider)?;
            let broadcast_peers = parse_peers(&broadcast);

            if !broadcast_peers.is_empty() {
                sync_with_peers(&db, &broadcast_peers, "amm-add-liquidity-pre-sync").await;
                tokio::time::sleep(std::time::Duration::from_millis(SYNC_SETTLE_MILLIS)).await;
            }

            let ev = build_amm_add_liquidity_event(&provider_addr.to_string(), bincoin, pusdc)?;

            let mut dbh = Db::open(&db)?;
            let epoch_id = format!("manual-amm-add-liquidity:{}", util::now_unix());

            let mut blk = dbh
                .make_block_on_best(&producer, &epoch_id, vec![], vec![ev])
                .context("make_block_on_best with amm add liquidity event")?;

            if let Some(path) = validator_key {
                let (validator_id, kp, root_hex) = load_wots_keypair_from_file(&path)?;
                if validator_id != producer {
                    bail!(
                        "--producer {} does not match validator key validator_id {}",
                        producer,
                        validator_id
                    );
                }

                attach_block_signature_wots(&mut blk, &producer, &kp)
                    .context("attach_block_signature_wots")?;

                println!(
                    "[amm-add-liquidity-on-chain] loaded validator key file={} validator_id={} root={}",
                    path.display(),
                    validator_id,
                    root_hex
                );
            }

            dbh.import_block(&blk)
                .context("import amm add liquidity block")?;

            let st = dbh.read_state()?;
            let provider_bincoin = st
                .balances
                .get(&provider_addr.to_string())
                .copied()
                .unwrap_or(0);
            let provider_pusdc = st
                .pusdc_balances
                .get(&provider_addr.to_string())
                .copied()
                .unwrap_or(0);

            println!("[ok] amm liquidity added on-chain");
            println!("producer: {}", producer);
            println!("provider: {}", provider_addr);
            println!("bincoin_added: {}", bincoin);
            println!("pusdc_added: {}", pusdc);
            println!("block_height: {}", blk.header.height);
            println!("block_hash: {}", blk.block_hash_hex);
            println!("signed: {}", blk.block_signature.is_some());
            println!("amm_bincoin_reserve: {}", st.amm_bincoin_reserve);
            println!("amm_pusdc_reserve: {}", st.amm_pusdc_reserve);
            println!("provider_bincoin_balance: {}", provider_bincoin);
            println!("provider_pusdc_balance: {}", provider_pusdc);
            println!("state_root_hex: {}", st.state_root_hex);

            if !broadcast_peers.is_empty() {
                net::broadcast_block(&broadcast_peers, blk.clone()).await;
                println!("broadcast_peers: {}", broadcast_peers.len());
                for peer in &broadcast_peers {
                    println!("  broadcast -> {}", peer);
                }
            }
        }

        Commands::AmmQuoteBincoinToPusdc { db, amount_in } => {
            let dbh = Db::open(&db)?;
            let amount_out = dbh.amm_quote_bincoin_to_pusdc(amount_in)?;
            let (bincoin_reserve, pusdc_reserve) = dbh.amm_reserves()?;

            println!("[ok] amm quote");
            println!("direction: bincoin_to_pusdc");
            println!("amount_in: {}", amount_in);
            println!("amount_out: {}", amount_out);
            println!("amm_bincoin_reserve: {}", bincoin_reserve);
            println!("amm_pusdc_reserve: {}", pusdc_reserve);
        }

        Commands::AmmQuotePusdcToBincoin { db, amount_in } => {
            let dbh = Db::open(&db)?;
            let amount_out = dbh.amm_quote_pusdc_to_bincoin(amount_in)?;
            let (bincoin_reserve, pusdc_reserve) = dbh.amm_reserves()?;

            println!("[ok] amm quote");
            println!("direction: pusdc_to_bincoin");
            println!("amount_in: {}", amount_in);
            println!("amount_out: {}", amount_out);
            println!("amm_bincoin_reserve: {}", bincoin_reserve);
            println!("amm_pusdc_reserve: {}", pusdc_reserve);
        }

        Commands::AmmSwapBincoinToPusdc {
            db,
            user,
            amount_in,
        } => {
            let user_addr = AddressV1::parse(&user)?;
            let mut dbh = Db::open(&db)?;
            let amount_out = dbh.amm_swap_bincoin_to_pusdc(&user_addr.to_string(), amount_in)?;

            let st = dbh.read_state()?;
            let user_bincoin = st
                .balances
                .get(&user_addr.to_string())
                .copied()
                .unwrap_or(0);
            let user_pusdc = st
                .pusdc_balances
                .get(&user_addr.to_string())
                .copied()
                .unwrap_or(0);

            println!("[ok] amm swap");
            println!("direction: bincoin_to_pusdc");
            println!("user: {}", user_addr);
            println!("amount_in: {}", amount_in);
            println!("amount_out: {}", amount_out);
            println!("user_bincoin_balance: {}", user_bincoin);
            println!("user_pusdc_balance: {}", user_pusdc);
            println!("amm_bincoin_reserve: {}", st.amm_bincoin_reserve);
            println!("amm_pusdc_reserve: {}", st.amm_pusdc_reserve);
            println!("state_root_hex: {}", st.state_root_hex);
        }

        Commands::AmmSwapBincoinToPusdcOnChain {
            db,
            user,
            amount_in,
            producer,
            validator_key,
            broadcast,
        } => {
            let user_addr = AddressV1::parse(&user)?;
            let broadcast_peers = parse_peers(&broadcast);

            if !broadcast_peers.is_empty() {
                sync_with_peers(&db, &broadcast_peers, "amm-swap-b2p-pre-sync").await;
                tokio::time::sleep(std::time::Duration::from_millis(SYNC_SETTLE_MILLIS)).await;
            }

            let ev = build_amm_swap_bincoin_to_pusdc_event(&user_addr.to_string(), amount_in)?;

            let mut dbh = Db::open(&db)?;
            let epoch_id = format!("manual-amm-swap-bincoin-to-pusdc:{}", util::now_unix());

            let mut blk = dbh
                .make_block_on_best(&producer, &epoch_id, vec![], vec![ev])
                .context("make_block_on_best with amm swap bincoin->pUSDC event")?;

            if let Some(path) = validator_key {
                let (validator_id, kp, root_hex) = load_wots_keypair_from_file(&path)?;
                if validator_id != producer {
                    bail!(
                        "--producer {} does not match validator key validator_id {}",
                        producer,
                        validator_id
                    );
                }

                attach_block_signature_wots(&mut blk, &producer, &kp)
                    .context("attach_block_signature_wots")?;

                println!(
                    "[amm-swap-bincoin-to-pusdc-on-chain] loaded validator key file={} validator_id={} root={}",
                    path.display(),
                    validator_id,
                    root_hex
                );
            }

            dbh.import_block(&blk)
                .context("import amm swap bincoin->pUSDC block")?;

            let st = dbh.read_state()?;
            let user_bincoin = st
                .balances
                .get(&user_addr.to_string())
                .copied()
                .unwrap_or(0);
            let user_pusdc = st
                .pusdc_balances
                .get(&user_addr.to_string())
                .copied()
                .unwrap_or(0);

            println!("[ok] amm swap submitted on-chain");
            println!("direction: bincoin_to_pusdc");
            println!("producer: {}", producer);
            println!("user: {}", user_addr);
            println!("amount_in: {}", amount_in);
            println!("block_height: {}", blk.header.height);
            println!("block_hash: {}", blk.block_hash_hex);
            println!("signed: {}", blk.block_signature.is_some());
            println!("user_bincoin_balance: {}", user_bincoin);
            println!("user_pusdc_balance: {}", user_pusdc);
            println!("amm_bincoin_reserve: {}", st.amm_bincoin_reserve);
            println!("amm_pusdc_reserve: {}", st.amm_pusdc_reserve);
            println!("state_root_hex: {}", st.state_root_hex);

            if !broadcast_peers.is_empty() {
                net::broadcast_block(&broadcast_peers, blk.clone()).await;
                println!("broadcast_peers: {}", broadcast_peers.len());
                for peer in &broadcast_peers {
                    println!("  broadcast -> {}", peer);
                }
            }
        }

        Commands::AmmSwapPusdcToBincoin {
            db,
            user,
            amount_in,
        } => {
            let user_addr = AddressV1::parse(&user)?;
            let mut dbh = Db::open(&db)?;
            let amount_out = dbh.amm_swap_pusdc_to_bincoin(&user_addr.to_string(), amount_in)?;

            let st = dbh.read_state()?;
            let user_bincoin = st
                .balances
                .get(&user_addr.to_string())
                .copied()
                .unwrap_or(0);
            let user_pusdc = st
                .pusdc_balances
                .get(&user_addr.to_string())
                .copied()
                .unwrap_or(0);

            println!("[ok] amm swap");
            println!("direction: pusdc_to_bincoin");
            println!("user: {}", user_addr);
            println!("amount_in: {}", amount_in);
            println!("amount_out: {}", amount_out);
            println!("user_bincoin_balance: {}", user_bincoin);
            println!("user_pusdc_balance: {}", user_pusdc);
            println!("amm_bincoin_reserve: {}", st.amm_bincoin_reserve);
            println!("amm_pusdc_reserve: {}", st.amm_pusdc_reserve);
            println!("state_root_hex: {}", st.state_root_hex);
        }

        Commands::AmmSwapPusdcToBincoinOnChain {
            db,
            user,
            amount_in,
            producer,
            validator_key,
            broadcast,
        } => {
            let user_addr = AddressV1::parse(&user)?;
            let broadcast_peers = parse_peers(&broadcast);

            if !broadcast_peers.is_empty() {
                sync_with_peers(&db, &broadcast_peers, "amm-swap-p2b-pre-sync").await;
                tokio::time::sleep(std::time::Duration::from_millis(SYNC_SETTLE_MILLIS)).await;
            }

            let ev = build_amm_swap_pusdc_to_bincoin_event(&user_addr.to_string(), amount_in)?;

            let mut dbh = Db::open(&db)?;
            let epoch_id = format!("manual-amm-swap-pusdc-to-bincoin:{}", util::now_unix());

            let mut blk = dbh
                .make_block_on_best(&producer, &epoch_id, vec![], vec![ev])
                .context("make_block_on_best with amm swap pUSDC->bincoin event")?;

            if let Some(path) = validator_key {
                let (validator_id, kp, root_hex) = load_wots_keypair_from_file(&path)?;
                if validator_id != producer {
                    bail!(
                        "--producer {} does not match validator key validator_id {}",
                        producer,
                        validator_id
                    );
                }

                attach_block_signature_wots(&mut blk, &producer, &kp)
                    .context("attach_block_signature_wots")?;

                println!(
                    "[amm-swap-pusdc-to-bincoin-on-chain] loaded validator key file={} validator_id={} root={}",
                    path.display(),
                    validator_id,
                    root_hex
                );
            }

            dbh.import_block(&blk)
                .context("import amm swap pUSDC->bincoin block")?;

            let st = dbh.read_state()?;
            let user_bincoin = st
                .balances
                .get(&user_addr.to_string())
                .copied()
                .unwrap_or(0);
            let user_pusdc = st
                .pusdc_balances
                .get(&user_addr.to_string())
                .copied()
                .unwrap_or(0);

            println!("[ok] amm swap submitted on-chain");
            println!("direction: pusdc_to_bincoin");
            println!("producer: {}", producer);
            println!("user: {}", user_addr);
            println!("amount_in: {}", amount_in);
            println!("block_height: {}", blk.header.height);
            println!("block_hash: {}", blk.block_hash_hex);
            println!("signed: {}", blk.block_signature.is_some());
            println!("user_bincoin_balance: {}", user_bincoin);
            println!("user_pusdc_balance: {}", user_pusdc);
            println!("amm_bincoin_reserve: {}", st.amm_bincoin_reserve);
            println!("amm_pusdc_reserve: {}", st.amm_pusdc_reserve);
            println!("state_root_hex: {}", st.state_root_hex);

            if !broadcast_peers.is_empty() {
                net::broadcast_block(&broadcast_peers, blk.clone()).await;
                println!("broadcast_peers: {}", broadcast_peers.len());
                for peer in &broadcast_peers {
                    println!("  broadcast -> {}", peer);
                }
            }
        }

        Commands::LockPusdc {
            db,
            from,
            amount,
            external_recipient,
        } => {
            let from_addr = AddressV1::parse(&from)?;
            let mut dbh = Db::open(&db)?;

            let external_recipient = external_recipient.trim();
            if external_recipient.is_empty() {
                bail!("external_recipient empty");
            }

            let target_chain =
                if external_recipient.starts_with("0x") || external_recipient.starts_with("0X") {
                    "ethereum"
                } else {
                    "solana"
                };

            let producer_id = "v1";

            let (blk, ev) = dbh.lock_pusdc_on_chain(
                &from_addr.to_string(),
                amount,
                target_chain,
                external_recipient,
                producer_id,
            )?;

            let (available, locked, total) = dbh.balance_pusdc(&from_addr.to_string())?;
            let st = dbh.read_state()?;
            let bridge_file = bridge_events_path_for_db_root(&db);

            println!("[ok] pUSDC locked on-chain");
            println!("event_id: {}", ev.event_id);
            println!("from: {}", from_addr);
            println!("amount: {}", amount);
            println!("producer: {}", producer_id);
            println!("block_height: {}", blk.header.height);
            println!("block_hash: {}", blk.block_hash_hex);
            println!("signed: {}", blk.block_signature.is_some());
            println!("available: {}", available);
            println!("locked: {}", locked);
            println!("total: {}", total);
            println!("bridge_status: {}", ev.status);
            println!("state_root_hex: {}", st.state_root_hex);
            println!("bridge_file: {}", bridge_file.display());

            if let Some(v) = &ev.source_chain {
                println!("source_chain: {}", v);
            }
            if let Some(v) = &ev.target_chain {
                println!("target_chain: {}", v);
            }
            if let Some(v) = &ev.source_asset {
                println!("source_asset: {}", v);
            }
            if let Some(v) = &ev.target_asset {
                println!("target_asset: {}", v);
            }
            if let Some(v) = &ev.external_recipient {
                println!("external_recipient: {}", v);
            }
        }

        Commands::UnlockPusdc {
            db,
            to,
            amount,
            event_id,
        } => {
            let to_addr = AddressV1::parse(&to)?;
            let mut dbh = Db::open(&db)?;

            let bridge_file = bridge_events_path_for_db_root(&db);
            let events = read_bridge_events(&bridge_file)?;
            let lock_event = events
                .iter()
                .find(|ev| ev.event_id == event_id)
                .ok_or_else(|| anyhow!("bridge event not found: {}", event_id))?;

            let source_chain = lock_event
                .target_chain
                .clone()
                .unwrap_or_else(|| "popchain".to_string());

            let source_asset = lock_event
                .target_asset
                .clone()
                .unwrap_or_else(|| "pUSDC".to_string());

            let producer_id = "v1";

            let (blk, unlock_ev) = dbh.unlock_pusdc_on_chain(
                &to_addr.to_string(),
                amount,
                &event_id,
                &source_chain,
                &source_asset,
                producer_id,
            )?;

            let (available, locked, total) = dbh.balance_pusdc(&to_addr.to_string())?;
            let st = dbh.read_state()?;

            println!("[ok] pUSDC unlocked on-chain");
            println!("event_id: {}", event_id);
            println!("unlock_event_id: {}", unlock_ev.event_id);
            println!("to: {}", to_addr);
            println!("amount: {}", amount);
            println!("producer: {}", producer_id);
            println!("block_height: {}", blk.header.height);
            println!("block_hash: {}", blk.block_hash_hex);
            println!("signed: {}", blk.block_signature.is_some());
            println!("available: {}", available);
            println!("locked: {}", locked);
            println!("total: {}", total);
            println!("state_root_hex: {}", st.state_root_hex);
            println!("bridge_file: {}", bridge_file.display());
            println!("source_chain: {}", source_chain);
            println!("source_asset: {}", source_asset);
        }

        Commands::BridgeEvents { db } => {
            let path = bridge_events_path_for_db_root(&db);
            let events = read_bridge_events(&path)?;

            println!("[ok] bridge events");
            println!("bridge_file: {}", path.display());
            println!("events_count: {}", events.len());

            let json = serde_json::to_value(&events).context("serialize bridge events")?;
            if let Some(arr) = json.as_array() {
                for (idx, ev) in arr.iter().enumerate() {
                    print_bridge_event_jsonish(idx, ev);
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&json)?);
            }
        }

        Commands::BridgeAudit { db } => {
            let path = bridge_events_path_for_db_root(&db);
            let events = read_bridge_events(&path)?;
            let report = audit_bridge_events(&events);

            println!("[ok] bridge audit");
            println!("bridge_file: {}", path.display());
            println!("events_count: {}", report.events_count);
            println!("error_count: {}", report.error_count);
            println!("warning_count: {}", report.warning_count);
            println!("audit_ok: {}", report.ok);

            if report.issues.is_empty() {
                println!("issues: 0");
            } else {
                for (idx, issue) in report.issues.iter().enumerate() {
                    let severity = match issue.severity {
                        BridgeAuditSeverityV1::Error => "ERROR",
                        BridgeAuditSeverityV1::Warning => "WARNING",
                    };

                    println!("issue[{}]:", idx);
                    println!("  severity: {}", severity);
                    println!("  code: {}", issue.code);
                    if let Some(v) = &issue.event_id {
                        println!("  event_id: {}", v);
                    }
                    if let Some(v) = &issue.related_event_id {
                        println!("  related_event_id: {}", v);
                    }
                    println!("  message: {}", issue.message);
                }
            }

            if !report.ok {
                bail!(
                    "bridge audit failed: errors={} warnings={}",
                    report.error_count,
                    report.warning_count
                );
            }
        }

        Commands::BridgeSetExternalTx {
            db,
            event_id,
            external_tx_id,
        } => {
            let path = bridge_events_path_for_db_root(&db);
            set_bridge_event_external_tx_id(&path, &event_id, &external_tx_id)?;
            println!("[ok] bridge external tx updated");
            println!("bridge_file: {}", path.display());
            println!("event_id: {}", event_id);
            println!("external_tx_id: {}", external_tx_id);
        }

        Commands::BridgeSetBurnTx {
            db,
            event_id,
            burn_tx_id,
        } => {
            let path = bridge_events_path_for_db_root(&db);
            set_bridge_event_burn_tx_id(&path, &event_id, &burn_tx_id)?;
            println!("[ok] bridge burn tx updated");
            println!("bridge_file: {}", path.display());
            println!("event_id: {}", event_id);
            println!("burn_tx_id: {}", burn_tx_id);
        }

        Commands::BridgeSetStatus {
            db,
            event_id,
            status,
        } => {
            let path = bridge_events_path_for_db_root(&db);
            update_bridge_event_status(&path, &event_id, &status)?;
            println!("[ok] bridge status updated");
            println!("bridge_file: {}", path.display());
            println!("event_id: {}", event_id);
            println!("status: {}", status);
        }

        Commands::BridgeSetFailure {
            db,
            event_id,
            reason,
        } => {
            let path = bridge_events_path_for_db_root(&db);
            set_bridge_event_failure(&path, &event_id, &reason)?;
            println!("[ok] bridge failure recorded");
            println!("bridge_file: {}", path.display());
            println!("event_id: {}", event_id);
            println!("reason: {}", reason);
        }

        Commands::Faucet { dbs, to, amount } => {
            let db_paths = parse_paths_csv(&dbs);
            if db_paths.is_empty() {
                bail!(
                    "dbs empty (use --dbs \"demo_local/node-a,demo_local/node-b,demo_local/node-c\")"
                );
            }

            let addr = AddressV1::parse(&to)?;
            println!("[faucet] target: {}", addr);
            println!("[faucet] amount: {}", amount);

            for db in db_paths {
                let (new_balance, state_root_hex) =
                    apply_faucet_to_db(&db, &addr.to_string(), amount)?;
                println!("[ok] faucet applied");
                println!("db: {}", db.display());
                println!("to: {}", addr);
                println!("new_balance: {}", new_balance);
                println!("state_root_hex: {}", state_root_hex);
            }
        }

        Commands::TransferOnChain {
            db,
            from,
            to,
            amount,
            producer,
            validator_key,
            broadcast,
        } => {
            let from_addr = AddressV1::parse(&from)?;
            let to_addr = AddressV1::parse(&to)?;
            let broadcast_peers = parse_peers(&broadcast);

            if !broadcast_peers.is_empty() {
                sync_with_peers(&db, &broadcast_peers, "transfer-pre-sync").await;
                tokio::time::sleep(std::time::Duration::from_millis(SYNC_SETTLE_MILLIS)).await;
            }

            let transfer_event =
                build_transfer_event(&from_addr.to_string(), &to_addr.to_string(), amount)?;

            let mut dbh = Db::open(&db)?;
            let epoch_id = format!("manual-transfer:{}", util::now_unix());

            let mut blk = dbh
                .make_block_on_best(&producer, &epoch_id, vec![], vec![transfer_event])
                .context("make_block_on_best with transfer event")?;

            if let Some(path) = validator_key {
                let (validator_id, kp, root_hex) = load_wots_keypair_from_file(&path)?;
                if validator_id != producer {
                    bail!(
                        "--producer {} does not match validator key validator_id {}",
                        producer,
                        validator_id
                    );
                }

                attach_block_signature_wots(&mut blk, &producer, &kp)
                    .context("attach_block_signature_wots")?;

                println!(
                    "[transfer-on-chain] loaded validator key file={} validator_id={} root={}",
                    path.display(),
                    validator_id,
                    root_hex
                );
            }

            dbh.import_block(&blk).context("import transfer block")?;

            let st = dbh.read_state()?;
            let from_balance = st
                .balances
                .get(&from_addr.to_string())
                .copied()
                .unwrap_or(0);
            let to_balance = st.balances.get(&to_addr.to_string()).copied().unwrap_or(0);

            println!("[ok] transfer submitted on-chain");
            println!("producer: {}", producer);
            println!("from: {}", from_addr);
            println!("to: {}", to_addr);
            println!("amount: {}", amount);
            println!("block_height: {}", blk.header.height);
            println!("block_hash: {}", blk.block_hash_hex);
            println!("signed: {}", blk.block_signature.is_some());
            println!("from_balance: {}", from_balance);
            println!("to_balance: {}", to_balance);
            println!("state_root_hex: {}", st.state_root_hex);

            if !broadcast_peers.is_empty() {
                net::broadcast_block(&broadcast_peers, blk.clone()).await;
                println!("broadcast_peers: {}", broadcast_peers.len());
                for peer in &broadcast_peers {
                    println!("  broadcast -> {}", peer);
                }
            }
        }

        Commands::NetServe { db, bind } => {
            let dbh = Db::open(&db)?;
            let shared = Arc::new(Mutex::new(dbh));
            net::serve(shared, &bind).await?;
        }

        Commands::NetConnect { db, addr } => {
            let dbh = Db::open(&db)?;
            let shared = Arc::new(Mutex::new(dbh));
            net::connect_once(shared, &addr).await?;
        }

        Commands::RunSlots {
            db,
            vid,
            producer,
            peers,
            validator_key,
        } => {
            let peers = parse_peers(&peers);
            run_slot_loop(db, vid, producer, peers, validator_key).await?;
        }

        Commands::Node {
            db,
            vid,
            producer,
            bind,
            peers,
            validator_key,
        } => {
            let peers_vec = parse_peers(&peers);

            let db_for_server = Db::open(&db)?;
            let shared = Arc::new(Mutex::new(db_for_server));

            let bind2 = bind.clone();
            let shared2 = shared.clone();
            tokio::spawn(async move {
                if let Err(e) = net::serve(shared2, &bind2).await {
                    eprintln!("[node] net-serve error: {}", e);
                }
            });

            tokio::time::sleep(std::time::Duration::from_millis(150)).await;

            run_slot_loop(db, vid, producer, peers_vec, validator_key).await?;
        }

        Commands::ValidatorKeygen { validator, out } => {
            let file = write_validator_key_file(&out, &validator)?;
            println!("[ok] validator key generated");
            println!("validator_id: {}", file.validator_id);
            println!("wots_root_hex: {}", file.wots_root_hex);
            println!("out: {}", out.display());
        }

        Commands::ComputeProof {
            machine,
            file,
            out,
            db,
            auto_prev,
            sample_rate_hz,
            duration_ms,
            prev_capture_hash,
        } => {
            let params = ScoringParamsV0::default();

            let resolved_prev_capture_hash = if auto_prev {
                let db_path = db.as_ref().context("--auto-prev requires --db <PATH>")?;

                let dbh =
                    Db::open(db_path).with_context(|| format!("open db {}", db_path.display()))?;
                let st = dbh.read_state().context("read_state for --auto-prev")?;

                st.machine_last_capture_hash
                    .get(&machine)
                    .cloned()
                    .unwrap_or_else(util::zero_hash32_hex)
            } else {
                prev_capture_hash.clone()
            };

            let proof = compute_proof_from_file(
                &machine,
                &file,
                &params,
                sample_rate_hz,
                duration_ms,
                &resolved_prev_capture_hash,
            )
            .context("compute_proof_from_file")?;

            write_legacy_proof_to_json(&out, &proof)?;

            println!("[ok] legacy proof generated");
            println!("mode: compatibility");
            println!("machine_id: {}", proof.machine_id);
            println!("capture_start_unix: {}", proof.capture_start_unix);
            println!("capture_end_unix: {}", proof.capture_end_unix);
            println!("prev_capture_hash_hex: {}", proof.prev_capture_hash_hex);
            println!("mbw_u64: {}", proof.mbw_u64);
            println!("proof_hash_hex: {}", proof.proof_hash_hex);
            println!("out: {}", out.display());
        }

        Commands::SubmitProof {
            db,
            proof,
            producer,
            validator_key,
            broadcast,
        } => {
            let proof_v0 = read_legacy_proof_from_json(&proof)?;
            let broadcast_peers = parse_peers(&broadcast);

            let mut dbh = Db::open(&db)?;
            let epoch_id = format!("manual-proof:{}", util::now_unix());

            let mut blk = dbh
                .make_block_on_best(&producer, &epoch_id, vec![proof_v0.clone()], vec![])
                .context("make_block_on_best with proof")?;

            if let Some(path) = validator_key {
                let (validator_id, kp, root_hex) = load_wots_keypair_from_file(&path)?;
                if validator_id != producer {
                    bail!(
                        "--producer {} does not match validator key validator_id {}",
                        producer,
                        validator_id
                    );
                }

                attach_block_signature_wots(&mut blk, &producer, &kp)
                    .context("attach_block_signature_wots")?;

                println!(
                    "[submit-proof] loaded validator key file={} validator_id={} root={}",
                    path.display(),
                    validator_id,
                    root_hex
                );
            }

            dbh.import_block(&blk).context("import proof block")?;

            println!("[ok] proof submitted");
            println!("producer: {}", producer);
            println!("machine_id: {}", proof_v0.machine_id);
            println!("block_height: {}", blk.header.height);
            println!("block_hash: {}", blk.block_hash_hex);
            println!("block_mbw: {}", proof_v0.mbw_u64);
            println!("state_root_hex: {}", blk.header.state_root_hex);
            println!("signed: {}", blk.block_signature.is_some());

            if !broadcast_peers.is_empty() {
                net::broadcast_block(&broadcast_peers, blk.clone()).await;
                println!("broadcast_peers: {}", broadcast_peers.len());
                for peer in &broadcast_peers {
                    println!("  broadcast -> {}", peer);
                }
            }
        }

        Commands::Process {
            db,
            producer,
            machine,
            file,
            validator_key,
            broadcast,
            auto_prev,
            sample_rate_hz,
            duration_ms,
            prev_capture_hash,
        } => {
            let broadcast_peers = parse_peers(&broadcast);
            let params = ScoringParamsV0::default();

            let resolved_prev_capture_hash = if auto_prev {
                let dbh = Db::open(&db).with_context(|| format!("open db {}", db.display()))?;
                let st = dbh.read_state().context("read_state for --auto-prev")?;
                st.machine_last_capture_hash
                    .get(&machine)
                    .cloned()
                    .unwrap_or_else(util::zero_hash32_hex)
            } else {
                prev_capture_hash.clone()
            };

            let proof = compute_proof_from_file(
                &machine,
                &file,
                &params,
                sample_rate_hz,
                duration_ms,
                &resolved_prev_capture_hash,
            )
            .context("compute_proof_from_file")?;

            if !broadcast_peers.is_empty() {
                sync_with_peers(&db, &broadcast_peers, "process-pre-sync").await;
                tokio::time::sleep(std::time::Duration::from_millis(SYNC_SETTLE_MILLIS)).await;
            }

            let mut dbh = Db::open(&db)?;
            let epoch_id = format!("process:{}", util::now_unix());

            let mut blk = dbh
                .make_block_on_best(&producer, &epoch_id, vec![proof.clone()], vec![])
                .context("make_block_on_best with process proof")?;

            if let Some(path) = validator_key {
                let (validator_id, kp, root_hex) = load_wots_keypair_from_file(&path)?;
                if validator_id != producer {
                    bail!(
                        "--producer {} does not match validator key validator_id {}",
                        producer,
                        validator_id
                    );
                }

                attach_block_signature_wots(&mut blk, &producer, &kp)
                    .context("attach_block_signature_wots")?;

                println!(
                    "[process] loaded validator key file={} validator_id={} root={}",
                    path.display(),
                    validator_id,
                    root_hex
                );
            }

            dbh.import_block(&blk).context("import process block")?;

            let st = dbh.read_state()?;
            let producer_balance_key = dbh.reward_owner_for_producer(&producer)?;
            let producer_balance = st.balances.get(&producer_balance_key).copied().unwrap_or(0);

            println!("[ok] payload processed");
            println!("producer: {}", producer);
            println!("machine_id: {}", proof.machine_id);
            println!("file: {}", file.display());
            println!("capture_start_unix: {}", proof.capture_start_unix);
            println!("capture_end_unix: {}", proof.capture_end_unix);
            println!("prev_capture_hash_hex: {}", proof.prev_capture_hash_hex);
            println!("score_u64: {}", proof.score_u64);
            println!("mbw_u64: {}", proof.mbw_u64);
            println!("proof_hash_hex: {}", proof.proof_hash_hex);
            println!("block_height: {}", blk.header.height);
            println!("block_hash: {}", blk.block_hash_hex);
            println!("chain_mbw_v0: {}", blk.header.chain_mbw_v0);
            println!("state_root_hex: {}", blk.header.state_root_hex);
            println!("signed: {}", blk.block_signature.is_some());
            println!("producer_balance_key: {}", producer_balance_key);
            println!("producer_balance: {}", producer_balance);

            if !broadcast_peers.is_empty() {
                net::broadcast_block(&broadcast_peers, blk.clone()).await;
                println!("broadcast_peers: {}", broadcast_peers.len());
                for peer in &broadcast_peers {
                    println!("  broadcast -> {}", peer);
                }
            }
        }

        Commands::Pop1Create {
            machine,
            file,
            out,
            capture_start_unix,
            capture_end_unix,
            prev_capture_hash,
        } => {
            let bytes = fs::read(&file).with_context(|| format!("read {}", file.display()))?;
            let prev_capture_hash = parse_hash32_hex(&prev_capture_hash, "prev_capture_hash")?;

            let pop1 = build_pop1_container_from_bytes(
                &machine,
                &bytes,
                capture_start_unix,
                capture_end_unix,
                prev_capture_hash,
            )
            .context("build_pop1_container_from_bytes")?;

            write_pop1_to_json(&out, &pop1)?;

            println!("[ok] POP-1 created");
            println!("machine_id: {}", pop1.header.machine_id);
            println!("capture_start_unix: {}", pop1.header.capture_start_unix);
            println!("capture_end_unix: {}", pop1.header.capture_end_unix);
            println!("payload_size_bytes: {}", pop1.integrity.payload_size_bytes);
            println!("container_hash: {}", pop1_container_hash(&pop1));
            println!("out: {}", out.display());
        }

        Commands::Pop1Inspect { input } => {
            let pop1 = read_pop1_from_json(&input)?;
            print_pop1(&pop1);
        }

        Commands::Pop1Validate { input, file } => {
            let pop1 = read_pop1_from_json(&input)?;

            match file {
                Some(payload_file) => {
                    let bytes = fs::read(&payload_file)
                        .with_context(|| format!("read {}", payload_file.display()))?;
                    validate_pop1_container_against_bytes(&pop1, &bytes)?;
                    println!("[ok] POP-1 valid by full recomputation");
                }
                None => {
                    validate_pop1_container_basic(&pop1)?;
                    println!("[ok] POP-1 basic validation passed");
                }
            }

            println!("machine_id: {}", pop1.header.machine_id);
            println!("container_hash: {}", pop1_container_hash(&pop1));
        }

        Commands::Pop2Create { pop1, out } => {
            let params = ScoringParamsV0::default();
            let pop1_obj = read_pop1_from_json(&pop1)?;
            let pop2 = derive_pop2_proof(&pop1_obj, &params)?;

            write_pop2_to_json(&out, &pop2)?;

            println!("[ok] POP-2 created");
            println!("machine_id: {}", pop2.machine_id);
            println!("container_hash: {}", pop2.container_hash);
            println!("score_u64: {}", pop2.score_u64);
            println!("mbw_u64: {}", pop2.mbw_u64);
            println!("proof_hash: {}", pop2.proof_hash);
            println!("out: {}", out.display());
        }

        Commands::Pop2Inspect { input } => {
            let pop2 = read_pop2_from_json(&input)?;
            print_pop2(&pop2);
        }

        Commands::Pop2Validate { pop1, pop2 } => {
            let params = ScoringParamsV0::default();
            let pop1_obj = read_pop1_from_json(&pop1)?;
            let pop2_obj = read_pop2_from_json(&pop2)?;

            validate_pop2_against_pop1(&pop2_obj, &pop1_obj, &params)?;
            println!("[ok] POP-2 valid by full recomputation against POP-1");
            println!("machine_id: {}", pop2_obj.machine_id);
            println!("container_hash: {}", pop2_obj.container_hash);
            println!("proof_hash: {}", pop2_obj.proof_hash);
        }

        Commands::LegacyProofInspect { input } => {
            let proof = read_legacy_proof_from_json(&input)?;

            println!("object: LEGACY_PROOF_V0");
            println!("version: {}", proof.version);
            println!("machine_id: {}", proof.machine_id);
            println!("capture_start_unix: {}", proof.capture_start_unix);
            println!("capture_end_unix: {}", proof.capture_end_unix);
            println!("prev_capture_hash_hex: {}", proof.prev_capture_hash_hex);
            println!("bytes_len: {}", proof.metrics.bytes_len);
            println!("sha256_hex: {}", proof.metrics.sha256_hex);
            println!("blake3_hex: {}", proof.metrics.blake3_hex);
            println!("entropy_q32: {}", proof.metrics.entropy_q32);
            println!("compression_ppm: {}", proof.metrics.compression_ppm);
            println!("mad_q32: {}", proof.metrics.mad_q32);
            println!("score_u64: {}", proof.score_u64);
            println!("mbw_u64: {}", proof.mbw_u64);
            println!("proof_hash_hex: {}", proof.proof_hash_hex);
        }

        Commands::LegacyProofToPop {
            proof,
            pop1_out,
            pop2_out,
        } => {
            let proof_v0 = read_legacy_proof_from_json(&proof)?;
            let pop1 = proof_v0_to_pop1(&proof_v0)?;
            let pop2 = proof_v0_to_pop2(&proof_v0)?;

            write_pop1_to_json(&pop1_out, &pop1)?;
            write_pop2_to_json(&pop2_out, &pop2)?;

            println!("[ok] legacy proof converted");
            println!("machine_id: {}", proof_v0.machine_id);
            println!("pop1_out: {}", pop1_out.display());
            println!("pop2_out: {}", pop2_out.display());
            println!("container_hash: {}", pop2.container_hash);
            println!("proof_hash: {}", pop2.proof_hash);
        }

        Commands::PcipCreatePop1 {
            machine,
            file,
            out,
            capture_start_unix,
            capture_end_unix,
            prev_capture_hash,
        } => {
            let bytes = fs::read(&file).with_context(|| format!("read {}", file.display()))?;
            let prev_capture_hash = parse_hash32_hex(&prev_capture_hash, "prev_capture_hash")?;

            let pop1 = build_pop1_container_from_bytes(
                &machine,
                &bytes,
                capture_start_unix,
                capture_end_unix,
                prev_capture_hash,
            )
            .context("build_pop1_container_from_bytes")?;

            write_pop1_to_json(&out, &pop1)?;

            println!("[ok] PCIP POP-1 created");
            println!("machine_id: {}", pop1.header.machine_id);
            println!("container_hash: {}", pop1_container_hash(&pop1));
            println!("out: {}", out.display());
        }

        Commands::PcipInspectPop1 { input } => {
            let pop1 = read_pop1_from_json(&input)?;
            print_pop1(&pop1);
        }

        Commands::PcipValidatePop1 { input, file } => {
            let pop1 = read_pop1_from_json(&input)?;

            match file {
                Some(payload_file) => {
                    let bytes = fs::read(&payload_file)
                        .with_context(|| format!("read {}", payload_file.display()))?;
                    validate_pop1_container_against_bytes(&pop1, &bytes)?;
                    println!("[ok] PCIP POP-1 valid by full recomputation");
                }
                None => {
                    validate_pop1_container_basic(&pop1)?;
                    println!("[ok] PCIP POP-1 basic validation passed");
                }
            }

            println!("machine_id: {}", pop1.header.machine_id);
            println!("container_hash: {}", pop1_container_hash(&pop1));
        }

        Commands::PcipCreatePop2 { pop1, out } => {
            let params = ScoringParamsV0::default();
            let pop1_obj = read_pop1_from_json(&pop1)?;
            let pop2 = derive_pop2_proof(&pop1_obj, &params)?;

            write_pop2_to_json(&out, &pop2)?;

            println!("[ok] PCIP POP-2 created");
            println!("machine_id: {}", pop2.machine_id);
            println!("container_hash: {}", pop2.container_hash);
            println!("proof_hash: {}", pop2.proof_hash);
            println!("out: {}", out.display());
        }

        Commands::PcipInspectPop2 { input } => {
            let pop2 = read_pop2_from_json(&input)?;
            print_pop2(&pop2);
        }

        Commands::PcipValidatePop2 { pop1, pop2 } => {
            let params = ScoringParamsV0::default();
            let pop1_obj = read_pop1_from_json(&pop1)?;
            let pop2_obj = read_pop2_from_json(&pop2)?;

            validate_pop2_against_pop1(&pop2_obj, &pop1_obj, &params)?;
            println!("[ok] PCIP POP-2 valid by full recomputation against POP-1");
            println!("machine_id: {}", pop2_obj.machine_id);
            println!("container_hash: {}", pop2_obj.container_hash);
            println!("proof_hash: {}", pop2_obj.proof_hash);
        }

        Commands::PcipCreateBundle {
            machine,
            file,
            out,
            capture_start_unix,
            capture_end_unix,
            prev_capture_hash,
        } => {
            let bundle = build_pcip_bundle_from_file(
                &machine,
                &file,
                capture_start_unix,
                capture_end_unix,
                &prev_capture_hash,
            )?;

            write_pcip_bundle_to_json(&out, &bundle)?;

            println!("[ok] PCIP bundle created");
            println!("bundle_version: {}", bundle.version);
            println!("machine_id: {}", bundle.pop1.header.machine_id);
            println!("container_hash: {}", pop1_container_hash(&bundle.pop1));
            println!("proof_hash: {}", bundle.pop2.proof_hash);
            println!("out: {}", out.display());
        }

        Commands::PcipInspectBundle { input } => {
            let bundle = read_pcip_bundle_from_json(&input)?;

            println!("object: PCIP_BUNDLE_V1");
            println!("bundle_version: {}", bundle.version);
            print_pop1(&bundle.pop1);
            print_pop2(&bundle.pop2);
        }

        Commands::PcipValidateBundle { input, file } => {
            let bundle = read_pcip_bundle_from_json(&input)?;
            validate_pcip_bundle(&bundle, file.as_deref())?;

            println!("[ok] PCIP bundle validation passed");
            println!("bundle_version: {}", bundle.version);
            println!("machine_id: {}", bundle.pop1.header.machine_id);
            println!("container_hash: {}", pop1_container_hash(&bundle.pop1));
            println!("proof_hash: {}", bundle.pop2.proof_hash);
        }
    }

    Ok(())
}
