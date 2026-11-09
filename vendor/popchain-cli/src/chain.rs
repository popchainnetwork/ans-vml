#![forbid(unsafe_code)]

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, path::Path};

use crate::app::{
    app_events_hash_hex, build_bridge_lock_pusdc_event, build_bridge_unlock_pusdc_event,
    decode_amm_add_liquidity_event, decode_amm_swap_bincoin_to_pusdc_event,
    decode_amm_swap_pusdc_to_bincoin_event, decode_bridge_lock_pusdc_event,
    decode_bridge_unlock_pusdc_event, decode_pusdc_transfer_event, decode_transfer_event,
    total_app_bytes, verify_event, AppEventV0, APP_KIND_AMM_ADD_LIQUIDITY_V0,
    APP_KIND_AMM_SWAP_BINCOIN_TO_PUSDC_V0, APP_KIND_AMM_SWAP_PUSDC_TO_BINCOIN_V0,
    APP_KIND_BRIDGE_LOCK_PUSDC_V0, APP_KIND_BRIDGE_UNLOCK_PUSDC_V0, APP_KIND_PUSDC_TRANSFER_V0,
    APP_KIND_TRANSFER_V0, MAX_APP_BYTES_PER_BLOCK, MAX_APP_EVENTS_PER_BLOCK,
};
use crate::bridge::{
    append_bridge_event, bridge_events_path_for_db_root, make_lock_event, make_unlock_event,
    next_bridge_event_id, read_bridge_events, update_bridge_event_status, BridgeEventTypeV1,
    BridgeEventV1, BRIDGE_ASSET_PUSDC, BRIDGE_CHAIN_POPCHAIN, BRIDGE_STATUS_DONE,
    BRIDGE_STATUS_UNLOCKED_ON_POP,
};
use crate::crypto::wots::{
    pk_from_hex, pk_to_hex, pseudo_root_from_pk, sig_from_hex, sig_to_hex, sign_wots, verify_wots,
    WotsKeypair,
};
use crate::epoch::{finalize_epoch_from_blocks, verify_epoch_finality_record, DEFAULT_EPOCH_LEN};
use crate::graph::BlockGraph;
use crate::mempool::{MempoolLimitsV0, MempoolV0};
use crate::metrics::{
    proof_hashes_hex, proof_v0_to_pop1, proof_v0_to_pop2, validate_pop1_container_basic,
    validate_pop2_against_pop1, verify_proof_basic, ProofV0, ScoringParamsV0,
};
use crate::store::Store;
use crate::types::{AddressV1, BlockHash, BlockSignatureV1, Hash32};
use crate::util;

pub const BLOCK_VERSION: u32 = 1;
pub const DEFAULT_SLOT_DURATION_SECS: u64 = 5;
pub const AMM_POOL_ACCOUNT: &str = "__amm_pool__";

fn genesis_hash() -> BlockHash {
    Hash32::zero()
}

fn default_latest_finalized_epoch_hash_hex() -> String {
    genesis_hash().to_hex()
}

fn default_state_root_hex() -> String {
    Hash32::zero().to_hex()
}

mod serde_u128_string {
    use serde::{de, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(v: &u128, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_str(&v.to_string())
    }

    pub fn deserialize<'de, D>(d: D) -> Result<u128, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(d)?;
        raw.parse::<u128>()
            .map_err(|e| de::Error::custom(format!("bad u128: {}", e)))
    }
}

mod serde_map_u128_string {
    use std::collections::HashMap;

    use serde::{de, ser::SerializeMap, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(m: &HashMap<String, u128>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = s.serialize_map(Some(m.len()))?;
        for (k, v) in m {
            map.serialize_entry(k, &v.to_string())?;
        }
        map.end()
    }

    pub fn deserialize<'de, D>(d: D) -> Result<HashMap<String, u128>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = HashMap::<String, String>::deserialize(d)?;
        let mut out = HashMap::with_capacity(raw.len());
        for (k, v) in raw {
            let parsed = v
                .parse::<u128>()
                .map_err(|e| de::Error::custom(format!("bad u128 for key {}: {}", k, e)))?;
            out.insert(k, parsed);
        }
        Ok(out)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisV1 {
    pub version: u32,
    pub chain_id: String,
    pub validators: Vec<String>,

    #[serde(default)]
    pub validator_wots_roots_hex: HashMap<String, String>,

    #[serde(default)]
    pub validator_reward_addresses: HashMap<String, String>,

    #[serde(default)]
    pub treasury_address: Option<String>,

    #[serde(default, with = "serde_map_u128_string")]
    pub initial_balances: HashMap<String, u128>,

    #[serde(default, with = "serde_map_u128_string")]
    pub initial_pusdc_balances: HashMap<String, u128>,

    pub slot_duration_secs: u64,
    pub created_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateV1 {
    pub version: u32,
    pub best_tip_hash_hex: String,
    pub best_height: u64,

    #[serde(with = "serde_u128_string")]
    pub chain_mbw_v0: u128,

    pub machine_last_capture_hash: HashMap<String, String>,

    #[serde(default, with = "serde_map_u128_string")]
    pub validator_stake_credit: HashMap<String, u128>,

    #[serde(default, with = "serde_map_u128_string")]
    pub validator_minted_bincoin: HashMap<String, u128>,

    #[serde(default, with = "serde_map_u128_string")]
    pub balances: HashMap<String, u128>,

    #[serde(default, with = "serde_map_u128_string")]
    pub pusdc_balances: HashMap<String, u128>,

    #[serde(default, with = "serde_map_u128_string")]
    pub pusdc_locked: HashMap<String, u128>,

    #[serde(default, with = "serde_u128_string")]
    pub amm_bincoin_reserve: u128,

    #[serde(default, with = "serde_u128_string")]
    pub amm_pusdc_reserve: u128,

    #[serde(default)]
    pub latest_finalized_epoch: u64,

    #[serde(default = "default_latest_finalized_epoch_hash_hex")]
    pub latest_finalized_epoch_hash_hex: String,

    #[serde(default = "default_state_root_hex")]
    pub state_root_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeaderV1 {
    pub version: u32,
    pub height: u64,
    pub prev_block_hash_hex: String,
    pub chain_id: String,
    pub epoch_id: String,
    pub producer_id: String,
    pub timestamp_unix: u64,
    pub app_events_hash_hex: String,
    pub total_app_bytes: u64,
    pub proofs_hash_hex: String,

    #[serde(with = "serde_u128_string")]
    pub chain_mbw_v0: u128,

    #[serde(default = "default_state_root_hex")]
    pub state_root_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockV1 {
    pub header: BlockHeaderV1,
    pub proofs: Vec<ProofV0>,
    pub app_events: Vec<AppEventV0>,
    pub block_hash_hex: String,
    pub block_signature: Option<BlockSignatureV1>,
}

pub struct Db {
    store: Store,
    graph: BlockGraph,
    mempool: MempoolV0,
}

impl Db {
    pub fn open(root: &Path) -> Result<Self> {
        let store = Store::open(root)?;
        let mut db = Self {
            store,
            graph: BlockGraph::new(),
            mempool: MempoolV0::new(MempoolLimitsV0::default()),
        };
        db.bootstrap_graph_from_disk()?;

        if db.store.read_genesis::<GenesisV1>().is_ok() && db.store.read_state::<StateV1>().is_ok()
        {
            db.recompute_best_and_state()?;
        }

        Ok(db)
    }

    pub fn mempool_mut(&mut self) -> &mut MempoolV0 {
        &mut self.mempool
    }

    pub fn init(
        &mut self,
        chain_id: &str,
        validators: Vec<String>,
        slot_duration_secs: u64,
    ) -> Result<()> {
        self.init_with_validator_wots_roots_reward_addresses_and_initial_balances(
            chain_id,
            validators,
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            slot_duration_secs,
        )
    }

    pub fn init_with_validator_wots_roots(
        &mut self,
        chain_id: &str,
        validators: Vec<String>,
        validator_wots_roots_hex: HashMap<String, String>,
        slot_duration_secs: u64,
    ) -> Result<()> {
        self.init_with_validator_wots_roots_reward_addresses_and_initial_balances(
            chain_id,
            validators,
            validator_wots_roots_hex,
            HashMap::new(),
            HashMap::new(),
            slot_duration_secs,
        )
    }

    pub fn init_with_validator_wots_roots_and_reward_addresses(
        &mut self,
        chain_id: &str,
        validators: Vec<String>,
        validator_wots_roots_hex: HashMap<String, String>,
        validator_reward_addresses: HashMap<String, String>,
        slot_duration_secs: u64,
    ) -> Result<()> {
        self.init_with_validator_wots_roots_reward_addresses_and_initial_balances(
            chain_id,
            validators,
            validator_wots_roots_hex,
            validator_reward_addresses,
            HashMap::new(),
            slot_duration_secs,
        )
    }

    pub fn init_with_validator_wots_roots_reward_addresses_and_initial_balances(
        &mut self,
        chain_id: &str,
        validators: Vec<String>,
        validator_wots_roots_hex: HashMap<String, String>,
        validator_reward_addresses: HashMap<String, String>,
        initial_balances: HashMap<String, u128>,
        slot_duration_secs: u64,
    ) -> Result<()> {
        self.init_with_validator_wots_roots_reward_addresses_treasury_and_initial_balances(
            chain_id,
            validators,
            validator_wots_roots_hex,
            validator_reward_addresses,
            None,
            initial_balances,
            HashMap::new(),
            slot_duration_secs,
        )
    }

    pub fn init_with_validator_wots_roots_reward_addresses_treasury_and_initial_balances(
        &mut self,
        chain_id: &str,
        validators: Vec<String>,
        validator_wots_roots_hex: HashMap<String, String>,
        validator_reward_addresses: HashMap<String, String>,
        treasury_address: Option<String>,
        initial_balances: HashMap<String, u128>,
        initial_pusdc_balances: HashMap<String, u128>,
        slot_duration_secs: u64,
    ) -> Result<()> {
        if chain_id.is_empty() {
            return Err(anyhow!("chain_id empty"));
        }
        if validators.is_empty() {
            return Err(anyhow!("validators empty"));
        }

        for validator_id in validator_wots_roots_hex.keys() {
            if !validators.iter().any(|v| v == validator_id) {
                return Err(anyhow!(
                    "validator_wots_root provided for unknown validator_id={}",
                    validator_id
                ));
            }
        }

        for validator_id in validator_reward_addresses.keys() {
            if !validators.iter().any(|v| v == validator_id) {
                return Err(anyhow!(
                    "validator_reward_address provided for unknown validator_id={}",
                    validator_id
                ));
            }
        }

        if let Some(addr) = &treasury_address {
            let parsed = AddressV1::parse(addr)
                .with_context(|| format!("parse treasury_address {}", addr))?;
            if parsed.is_zero() {
                return Err(anyhow!("treasury_address cannot be zero"));
            }
        }

        for (addr, amount) in &initial_balances {
            let parsed = AddressV1::parse(addr)
                .with_context(|| format!("parse initial balance address {}", addr))?;
            if *amount == 0 {
                return Err(anyhow!("initial balance for {} must be > 0", parsed));
            }
        }

        for (addr, amount) in &initial_pusdc_balances {
            let parsed = AddressV1::parse(addr)
                .with_context(|| format!("parse initial pUSDC balance address {}", addr))?;
            if *amount == 0 {
                return Err(anyhow!("initial pUSDC balance for {} must be > 0", parsed));
            }
        }

        let created_unix = util::now_unix();

        let g = GenesisV1 {
            version: 1,
            chain_id: chain_id.to_string(),
            validators,
            validator_wots_roots_hex,
            validator_reward_addresses,
            treasury_address,
            initial_balances,
            initial_pusdc_balances,
            slot_duration_secs: slot_duration_secs.max(1),
            created_unix,
        };
        self.store.write_genesis(&g)?;

        let genesis_block_template = BlockV1 {
            header: BlockHeaderV1 {
                version: BLOCK_VERSION,
                height: 0,
                prev_block_hash_hex: genesis_hash().to_hex(),
                chain_id: chain_id.to_string(),
                epoch_id: "genesis".to_string(),
                producer_id: "genesis".to_string(),
                timestamp_unix: created_unix,
                app_events_hash_hex: app_events_hash_hex(&[]),
                total_app_bytes: 0,
                proofs_hash_hex: proof_hashes_hex(&[]),
                chain_mbw_v0: 0,
                state_root_hex: default_state_root_hex(),
            },
            proofs: Vec::new(),
            app_events: Vec::new(),
            block_hash_hex: genesis_hash().to_hex(),
            block_signature: None,
        };

        self.store
            .write_block_by_hash(&genesis_hash(), &genesis_block_template)?;
        self.store.append_height_index(0, &genesis_hash())?;

        let genesis_fin = finalize_epoch_from_blocks(
            0,
            DEFAULT_EPOCH_LEN,
            std::slice::from_ref(&genesis_block_template),
            deterministic_finality_time_from_blocks(std::slice::from_ref(&genesis_block_template)),
        )?;

        verify_epoch_finality_record(&genesis_fin, std::slice::from_ref(&genesis_block_template))?;
        self.store
            .write_finality_record(genesis_fin.epoch_id, &genesis_fin)?;

        let mut st = StateV1 {
            version: 1,
            best_tip_hash_hex: genesis_hash().to_hex(),
            best_height: 0,
            chain_mbw_v0: 0,
            machine_last_capture_hash: HashMap::new(),
            validator_stake_credit: HashMap::new(),
            validator_minted_bincoin: HashMap::new(),
            balances: g.initial_balances.clone(),
            pusdc_balances: g.initial_pusdc_balances.clone(),
            pusdc_locked: HashMap::new(),
            amm_bincoin_reserve: 0,
            amm_pusdc_reserve: 0,
            latest_finalized_epoch: genesis_fin.epoch_id,
            latest_finalized_epoch_hash_hex: genesis_fin.finality_hash_hex,
            state_root_hex: default_state_root_hex(),
        };

        st.state_root_hex = compute_state_root_hex(&st);
        self.store.write_state(&st)?;

        self.graph = BlockGraph::new();
        self.graph.set_genesis(genesis_hash());
        Ok(())
    }

    pub fn read_genesis(&self) -> Result<GenesisV1> {
        self.store.read_genesis()
    }

    pub fn read_state(&self) -> Result<StateV1> {
        let mut st: StateV1 = self.store.read_state()?;
        if st.state_root_hex.len() != 64 {
            st.state_root_hex = compute_state_root_hex(&st);
        }
        Ok(st)
    }

    pub fn transfer_balance(&mut self, from: &str, to: &str, amount: u128) -> Result<()> {
        let from_addr = AddressV1::parse(from)?;
        let to_addr = AddressV1::parse(to)?;

        if amount == 0 {
            return Err(anyhow!("amount must be > 0"));
        }
        if from_addr == to_addr {
            return Err(anyhow!("from and to must differ"));
        }

        let from_key = from_addr.to_string();
        let to_key = to_addr.to_string();

        let mut st = self.read_state()?;
        transfer_in_map(&mut st.balances, &from_key, &to_key, amount)?;

        st.state_root_hex = compute_state_root_hex(&st);
        self.store.write_state(&st)?;
        Ok(())
    }

    pub fn mint_pusdc(&mut self, treasury: &str, to: &str, amount: u128) -> Result<()> {
        let treasury_addr = AddressV1::parse(treasury)?;
        let to_addr = AddressV1::parse(to)?;

        if amount == 0 {
            return Err(anyhow!("amount must be > 0"));
        }

        let g = self.read_genesis()?;
        let expected_treasury = g
            .treasury_address
            .ok_or_else(|| anyhow!("treasury_address not configured in genesis"))?;

        if treasury_addr.to_string() != expected_treasury {
            return Err(anyhow!(
                "unauthorized treasury address: expected={} got={}",
                expected_treasury,
                treasury_addr
            ));
        }

        let mut st = self.read_state()?;
        checked_add_to_map(&mut st.pusdc_balances, &to_addr.to_string(), amount)?;
        st.state_root_hex = compute_state_root_hex(&st);
        self.store.write_state(&st)?;
        Ok(())
    }

    pub fn transfer_pusdc(&mut self, from: &str, to: &str, amount: u128) -> Result<()> {
        let from_addr = AddressV1::parse(from)?;
        let to_addr = AddressV1::parse(to)?;

        if amount == 0 {
            return Err(anyhow!("amount must be > 0"));
        }
        if from_addr == to_addr {
            return Err(anyhow!("from and to must differ"));
        }

        let mut st = self.read_state()?;
        transfer_in_map(
            &mut st.pusdc_balances,
            &from_addr.to_string(),
            &to_addr.to_string(),
            amount,
        )?;
        st.state_root_hex = compute_state_root_hex(&st);
        self.store.write_state(&st)?;
        Ok(())
    }

    pub fn balance_pusdc(&self, address: &str) -> Result<(u128, u128, u128)> {
        let addr = AddressV1::parse(address)?;
        let st = self.read_state()?;
        let key = addr.to_string();

        let available = st.pusdc_balances.get(&key).copied().unwrap_or(0);
        let locked = st.pusdc_locked.get(&key).copied().unwrap_or(0);
        let total = available
            .checked_add(locked)
            .ok_or_else(|| anyhow!("pUSDC total overflow"))?;

        Ok((available, locked, total))
    }

    // LEGACY direct-state path. Zostawiamy dla kompatybilności.
    pub fn lock_pusdc(
        &mut self,
        from: &str,
        amount: u128,
        external_recipient: Option<&str>,
    ) -> Result<BridgeEventV1> {
        let from_addr = AddressV1::parse(from)?;
        if amount == 0 {
            return Err(anyhow!("amount must be > 0"));
        }

        let from_key = from_addr.to_string();
        let mut st = self.read_state()?;

        move_between_maps(
            &mut st.pusdc_balances,
            &mut st.pusdc_locked,
            &from_key,
            &from_key,
            amount,
        )?;

        st.state_root_hex = compute_state_root_hex(&st);
        self.store.write_state(&st)?;

        let bridge_path = bridge_events_path_for_db_root(self.store.root());
        let existing = read_bridge_events(&bridge_path)?;
        let event_id = next_bridge_event_id(&existing, "lock")?;

        let ev = make_lock_event(
            event_id,
            from_key,
            external_recipient
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            amount,
        );

        append_bridge_event(&bridge_path, &ev)?;
        Ok(ev)
    }

    // LEGACY direct-state path. Zostawiamy dla kompatybilności.
    pub fn unlock_pusdc(&mut self, to: &str, amount: u128, event_id: &str) -> Result<()> {
        let to_addr = AddressV1::parse(to)?;
        if amount == 0 {
            return Err(anyhow!("amount must be > 0"));
        }
        if event_id.trim().is_empty() {
            return Err(anyhow!("event_id empty"));
        }

        let bridge_path = bridge_events_path_for_db_root(self.store.root());
        let events = read_bridge_events(&bridge_path)?;

        let lock_event = events
            .iter()
            .find(|ev| ev.event_id == event_id)
            .ok_or_else(|| anyhow!("bridge event not found: {}", event_id))?;

        if lock_event.event_type != BridgeEventTypeV1::Lock {
            return Err(anyhow!("bridge event {} is not LOCK", event_id));
        }

        if lock_event.asset != BRIDGE_ASSET_PUSDC {
            return Err(anyhow!(
                "bridge event {} asset mismatch: expected={} got={}",
                event_id,
                BRIDGE_ASSET_PUSDC,
                lock_event.asset
            ));
        }

        let already_unlocked = events.iter().any(|ev| {
            ev.event_type == BridgeEventTypeV1::Unlock
                && ev.related_event_id.as_deref() == Some(event_id)
        });
        if already_unlocked {
            return Err(anyhow!("bridge event {} already completed", event_id));
        }

        let lock_amount = lock_event
            .amount
            .parse::<u128>()
            .with_context(|| format!("parse bridge event amount for {}", event_id))?;

        if lock_amount != amount {
            return Err(anyhow!(
                "unlock amount mismatch for {}: expected={} got={}",
                event_id,
                lock_amount,
                amount
            ));
        }

        let mut st = self.read_state()?;
        let lock_owner = AddressV1::parse(&lock_event.from)?;
        let lock_owner_key = lock_owner.to_string();
        let to_key = to_addr.to_string();

        move_between_maps(
            &mut st.pusdc_locked,
            &mut st.pusdc_balances,
            &lock_owner_key,
            &to_key,
            amount,
        )?;

        st.state_root_hex = compute_state_root_hex(&st);
        self.store.write_state(&st)?;

        update_bridge_event_status(&bridge_path, event_id, BRIDGE_STATUS_DONE)?;

        let existing = read_bridge_events(&bridge_path)?;
        let unlock_event_id = next_bridge_event_id(&existing, "unlock")?;

        let source_chain = lock_event
            .target_chain
            .clone()
            .unwrap_or_else(|| BRIDGE_CHAIN_POPCHAIN.to_string());

        let source_asset = lock_event
            .target_asset
            .clone()
            .unwrap_or_else(|| BRIDGE_ASSET_PUSDC.to_string());

        let unlock_event = make_unlock_event(
            unlock_event_id,
            lock_owner_key,
            to_key,
            amount,
            event_id.to_string(),
            source_chain,
            source_asset,
        );
        append_bridge_event(&bridge_path, &unlock_event)?;

        Ok(())
    }

    pub fn lock_pusdc_on_chain(
        &mut self,
        from: &str,
        amount: u128,
        target_chain: &str,
        external_recipient: &str,
        producer_id: &str,
    ) -> Result<(BlockV1, BridgeEventV1)> {
        if target_chain.trim().is_empty() {
            bail!("target_chain empty");
        }
        if external_recipient.trim().is_empty() {
            bail!("external_recipient empty");
        }

        let ev = build_bridge_lock_pusdc_event(from, amount, target_chain, external_recipient)?;
        let epoch_id = format!("manual-bridge-lock-pusdc:{}", util::now_unix());

        let blk = self.make_block_on_best(producer_id, &epoch_id, Vec::new(), vec![ev])?;
        self.import_block(&blk)?;

        let bridge_path = bridge_events_path_for_db_root(self.store.root());
        let existing = read_bridge_events(&bridge_path)?;
        let event_id = next_bridge_event_id(&existing, "lock")?;

        let bridge_event = make_lock_event(
            event_id,
            AddressV1::parse(from)?.to_string(),
            Some(external_recipient.trim().to_string()),
            amount,
        );

        append_bridge_event(&bridge_path, &bridge_event)?;
        Ok((blk, bridge_event))
    }

    pub fn unlock_pusdc_on_chain(
        &mut self,
        to: &str,
        amount: u128,
        related_event_id: &str,
        source_chain: &str,
        source_asset: &str,
        producer_id: &str,
    ) -> Result<(BlockV1, BridgeEventV1)> {
        if related_event_id.trim().is_empty() {
            bail!("related_event_id empty");
        }
        if source_chain.trim().is_empty() {
            bail!("source_chain empty");
        }
        if source_asset.trim().is_empty() {
            bail!("source_asset empty");
        }

        let bridge_path = bridge_events_path_for_db_root(self.store.root());
        let events = read_bridge_events(&bridge_path)?;
        let lock_event = events
            .iter()
            .find(|ev| ev.event_id == related_event_id)
            .ok_or_else(|| anyhow!("bridge event not found: {}", related_event_id))?;

        if lock_event.event_type != BridgeEventTypeV1::Lock {
            bail!("related_event_id {} is not a LOCK event", related_event_id);
        }

        let lock_amount = lock_event
            .amount
            .parse::<u128>()
            .with_context(|| format!("parse bridge lock amount for {}", related_event_id))?;
        if lock_amount != amount {
            bail!(
                "unlock amount mismatch expected={} got={}",
                lock_amount,
                amount
            );
        }

        let lock_owner = AddressV1::parse(&lock_event.from)?.to_string();
        let unlock_to = AddressV1::parse(to)?.to_string();
        if lock_owner != unlock_to {
            bail!(
                "minimal unlock_pusdc_on_chain requires to == lock owner; expected={} got={}",
                lock_owner,
                unlock_to
            );
        }

        let ev = build_bridge_unlock_pusdc_event(
            to,
            amount,
            related_event_id,
            source_chain,
            source_asset,
        )?;
        let epoch_id = format!("manual-bridge-unlock-pusdc:{}", util::now_unix());

        let blk = self.make_block_on_best(producer_id, &epoch_id, Vec::new(), vec![ev])?;
        self.import_block(&blk)?;

        update_bridge_event_status(
            &bridge_path,
            related_event_id,
            BRIDGE_STATUS_UNLOCKED_ON_POP,
        )?;

        let existing = read_bridge_events(&bridge_path)?;
        let unlock_event_id = next_bridge_event_id(&existing, "unlock")?;

        let bridge_event = make_unlock_event(
            unlock_event_id,
            lock_owner,
            unlock_to,
            amount,
            related_event_id.to_string(),
            source_chain.to_string(),
            source_asset.to_string(),
        );

        append_bridge_event(&bridge_path, &bridge_event)?;
        update_bridge_event_status(&bridge_path, related_event_id, BRIDGE_STATUS_DONE)?;

        Ok((blk, bridge_event))
    }

    pub fn amm_reserves(&self) -> Result<(u128, u128)> {
        let st = self.read_state()?;
        Ok((st.amm_bincoin_reserve, st.amm_pusdc_reserve))
    }

    pub fn amm_add_liquidity(
        &mut self,
        provider: &str,
        bincoin_amount: u128,
        pusdc_amount: u128,
    ) -> Result<()> {
        let provider_addr = AddressV1::parse(provider)?;
        if bincoin_amount == 0 || pusdc_amount == 0 {
            return Err(anyhow!("liquidity amounts must be > 0"));
        }

        let provider_key = provider_addr.to_string();
        let mut st = self.read_state()?;

        transfer_in_map(
            &mut st.balances,
            &provider_key,
            AMM_POOL_ACCOUNT,
            bincoin_amount,
        )?;
        transfer_in_map(
            &mut st.pusdc_balances,
            &provider_key,
            AMM_POOL_ACCOUNT,
            pusdc_amount,
        )?;

        st.amm_bincoin_reserve = st
            .amm_bincoin_reserve
            .checked_add(bincoin_amount)
            .ok_or_else(|| anyhow!("amm_bincoin_reserve overflow"))?;
        st.amm_pusdc_reserve = st
            .amm_pusdc_reserve
            .checked_add(pusdc_amount)
            .ok_or_else(|| anyhow!("amm_pusdc_reserve overflow"))?;

        st.state_root_hex = compute_state_root_hex(&st);
        self.store.write_state(&st)?;
        Ok(())
    }

    pub fn amm_quote_bincoin_to_pusdc(&self, amount_in: u128) -> Result<u128> {
        if amount_in == 0 {
            return Err(anyhow!("amount_in must be > 0"));
        }
        let st = self.read_state()?;
        cpmm_quote_out(st.amm_bincoin_reserve, st.amm_pusdc_reserve, amount_in)
    }

    pub fn amm_quote_pusdc_to_bincoin(&self, amount_in: u128) -> Result<u128> {
        if amount_in == 0 {
            return Err(anyhow!("amount_in must be > 0"));
        }
        let st = self.read_state()?;
        cpmm_quote_out(st.amm_pusdc_reserve, st.amm_bincoin_reserve, amount_in)
    }

    pub fn amm_swap_bincoin_to_pusdc(&mut self, user: &str, amount_in: u128) -> Result<u128> {
        let user_addr = AddressV1::parse(user)?;
        if amount_in == 0 {
            return Err(anyhow!("amount_in must be > 0"));
        }

        let user_key = user_addr.to_string();
        let mut st = self.read_state()?;

        let x = st.amm_bincoin_reserve;
        let y = st.amm_pusdc_reserve;
        let amount_out = cpmm_quote_out(x, y, amount_in)?;

        transfer_in_map(&mut st.balances, &user_key, AMM_POOL_ACCOUNT, amount_in)?;
        transfer_in_map(
            &mut st.pusdc_balances,
            AMM_POOL_ACCOUNT,
            &user_key,
            amount_out,
        )?;

        st.amm_bincoin_reserve = st
            .amm_bincoin_reserve
            .checked_add(amount_in)
            .ok_or_else(|| anyhow!("amm_bincoin_reserve overflow"))?;
        st.amm_pusdc_reserve = st
            .amm_pusdc_reserve
            .checked_sub(amount_out)
            .ok_or_else(|| anyhow!("amm_pusdc_reserve underflow"))?;

        st.state_root_hex = compute_state_root_hex(&st);
        self.store.write_state(&st)?;
        Ok(amount_out)
    }

    pub fn amm_swap_pusdc_to_bincoin(&mut self, user: &str, amount_in: u128) -> Result<u128> {
        let user_addr = AddressV1::parse(user)?;
        if amount_in == 0 {
            return Err(anyhow!("amount_in must be > 0"));
        }

        let user_key = user_addr.to_string();
        let mut st = self.read_state()?;

        let x = st.amm_pusdc_reserve;
        let y = st.amm_bincoin_reserve;
        let amount_out = cpmm_quote_out(x, y, amount_in)?;

        transfer_in_map(
            &mut st.pusdc_balances,
            &user_key,
            AMM_POOL_ACCOUNT,
            amount_in,
        )?;
        transfer_in_map(&mut st.balances, AMM_POOL_ACCOUNT, &user_key, amount_out)?;

        st.amm_pusdc_reserve = st
            .amm_pusdc_reserve
            .checked_add(amount_in)
            .ok_or_else(|| anyhow!("amm_pusdc_reserve overflow"))?;
        st.amm_bincoin_reserve = st
            .amm_bincoin_reserve
            .checked_sub(amount_out)
            .ok_or_else(|| anyhow!("amm_bincoin_reserve underflow"))?;

        st.state_root_hex = compute_state_root_hex(&st);
        self.store.write_state(&st)?;
        Ok(amount_out)
    }

    pub fn slot_duration_secs(&self) -> Result<u64> {
        Ok(self.read_genesis()?.slot_duration_secs.max(1))
    }

    pub fn validators_len(&self) -> Result<usize> {
        Ok(self.read_genesis()?.validators.len())
    }

    pub fn validator_wots_root_hex(&self, validator_id: &str) -> Result<Option<String>> {
        let g = self.read_genesis()?;
        Ok(g.validator_wots_roots_hex.get(validator_id).cloned())
    }

    pub fn has_validator_wots_root(&self, validator_id: &str) -> Result<bool> {
        Ok(self.validator_wots_root_hex(validator_id)?.is_some())
    }

    pub fn reward_owner_for_producer(&self, producer_id: &str) -> Result<String> {
        let g = self.read_genesis()?;
        Ok(g.validator_reward_addresses
            .get(producer_id)
            .cloned()
            .unwrap_or_else(|| producer_id.to_string()))
    }

    pub fn leader_vid_for_slot(&self, slot: u64) -> Result<u32> {
        let g = self.read_genesis()?;
        leader_for_slot(&g.validators, g.chain_id.as_bytes(), slot)
    }

    pub fn has_block(&self, h: &BlockHash) -> Result<bool> {
        self.store.has_block(h)
    }

    pub fn read_block_by_hash(&self, h: &BlockHash) -> Result<BlockV1> {
        self.store.read_block_by_hash(h)
    }

    pub fn read_block_by_height(&self, height: u64) -> Result<BlockV1> {
        let hashes = self.store.read_height_index(height)?;
        if hashes.is_empty() {
            return Err(anyhow!("no block at height {}", height));
        }
        self.store.read_block_by_hash(&hashes[0])
    }

    pub fn make_block_from_mempool(
        &self,
        producer_id: &str,
        epoch_id: &str,
        proofs: Vec<ProofV0>,
    ) -> Result<BlockV1> {
        let selected = self.mempool.select_for_block();
        self.make_block_internal(producer_id, epoch_id, proofs, selected, true)
    }

    pub fn make_block_on_best(
        &self,
        producer_id: &str,
        epoch_id: &str,
        proofs: Vec<ProofV0>,
        app_events: Vec<AppEventV0>,
    ) -> Result<BlockV1> {
        self.make_block_internal(producer_id, epoch_id, proofs, app_events, true)
    }

    pub fn make_block_internal(
        &self,
        producer_id: &str,
        epoch_id: &str,
        proofs: Vec<ProofV0>,
        app_events: Vec<AppEventV0>,
        enforce_replay: bool,
    ) -> Result<BlockV1> {
        if producer_id.is_empty() {
            return Err(anyhow!("producer_id empty"));
        }
        if epoch_id.is_empty() {
            return Err(anyhow!("epoch_id empty"));
        }

        let g = self.read_genesis()?;
        let st = self.read_state()?;

        if app_events.len() > MAX_APP_EVENTS_PER_BLOCK {
            return Err(anyhow!("too many app events"));
        }
        for ev in &app_events {
            verify_event(ev)?;
        }
        let tab = total_app_bytes(&app_events);
        if tab > MAX_APP_BYTES_PER_BLOCK {
            return Err(anyhow!("app bytes too large"));
        }

        if proofs.len() > 1024 {
            return Err(anyhow!("too many proofs"));
        }
        for p in &proofs {
            verify_proof_canonical(p)?;
        }

        if enforce_replay {
            let mut expected_prev: HashMap<String, String> = st.machine_last_capture_hash.clone();
            for p in &proofs {
                let exp = expected_prev
                    .get(&p.machine_id)
                    .cloned()
                    .unwrap_or_else(util::zero_hash32_hex);

                if p.prev_capture_hash_hex != exp {
                    return Err(anyhow!(
                        "replay/prev mismatch for machine_id={} expected_prev={} got_prev={}",
                        p.machine_id,
                        exp,
                        p.prev_capture_hash_hex
                    ));
                }
                expected_prev.insert(p.machine_id.clone(), p.metrics.sha256_hex.clone());
            }
        }

        let prev_hash = Hash32::from_hex(&st.best_tip_hash_hex)?;
        let height = st.best_height.saturating_add(1);

        let app_hash = app_events_hash_hex(&app_events);
        let proofs_hash = proof_hashes_hex(&proofs);

        let projected_state =
            apply_block_inputs_to_state(&g, &st, producer_id, &proofs, &app_events, height)?;

        let header = BlockHeaderV1 {
            version: BLOCK_VERSION,
            height,
            prev_block_hash_hex: prev_hash.to_hex(),
            chain_id: g.chain_id,
            epoch_id: epoch_id.to_string(),
            producer_id: producer_id.to_string(),
            timestamp_unix: util::now_unix(),
            app_events_hash_hex: app_hash,
            total_app_bytes: tab,
            proofs_hash_hex: proofs_hash,
            chain_mbw_v0: projected_state.chain_mbw_v0,
            state_root_hex: projected_state.state_root_hex.clone(),
        };

        let bh = block_hash(&header, &proofs, &app_events);

        Ok(BlockV1 {
            header,
            proofs,
            app_events,
            block_hash_hex: bh.to_hex(),
            block_signature: None,
        })
    }

    pub fn import_block(&mut self, blk: &BlockV1) -> Result<()> {
        self.verify_block(blk)?;

        // Preflight state-apply before any persistence.
        // This prevents a block/index from being written to disk when applying
        // the block to canonical parent state would fail during recompute.
        let g = self.read_genesis()?;
        if blk.header.height == 1 {
            let parent_state = self.read_state_for_parent_of_height_one()?;
            let _ = apply_block_to_state(&g, &parent_state, blk)?;
        } else {
            let parent = Hash32::from_hex(&blk.header.prev_block_hash_hex)?;
            if self.has_block(&parent)? {
                let parent_state = self.compute_canonical_state_at_hash(parent)?;
                let _ = apply_block_to_state(&g, &parent_state, blk)?;
            }
        }

        let hash = Hash32::from_hex(&blk.block_hash_hex)?;
        let parent = Hash32::from_hex(&blk.header.prev_block_hash_hex)?;

        self.store.write_block_by_hash(&hash, blk)?;
        self.store.append_height_index(blk.header.height, &hash)?;

        let parent_height = self.graph.height_of(&parent);
        let connected = self.graph.insert(hash, parent, parent_height);

        if connected {
            self.recompute_best_and_state()?;
        }

        self.mempool.remove_events(&blk.app_events);

        Ok(())
    }

    pub fn finalize_latest_complete_epoch(&mut self) -> Result<u64> {
        let st = self.read_state()?;
        let best_height = st.best_height;

        if best_height < DEFAULT_EPOCH_LEN {
            return Err(anyhow!(
                "no complete non-genesis epoch available to finalize"
            ));
        }

        let latest_complete_epoch = best_height / DEFAULT_EPOCH_LEN;
        if latest_complete_epoch == 0 {
            return Err(anyhow!(
                "no complete non-genesis epoch available to finalize"
            ));
        }

        let best_tip = Hash32::from_hex(&st.best_tip_hash_hex)?;
        let chain_hashes = self.canonical_chain_hashes_to_tip(best_tip)?;

        let start_height = ((latest_complete_epoch - 1) * DEFAULT_EPOCH_LEN) + 1;
        let end_height = latest_complete_epoch * DEFAULT_EPOCH_LEN;

        let mut epoch_blocks = Vec::with_capacity(DEFAULT_EPOCH_LEN as usize);
        for height in start_height..=end_height {
            let idx = (height - 1) as usize;
            let h = chain_hashes
                .get(idx)
                .ok_or_else(|| anyhow!("missing canonical block for height {}", height))?;
            let blk = self.store.read_block_by_hash(h)?;
            epoch_blocks.push(blk);
        }

        let fin = finalize_epoch_from_blocks(
            latest_complete_epoch,
            DEFAULT_EPOCH_LEN,
            &epoch_blocks,
            deterministic_finality_time_from_blocks(&epoch_blocks),
        )?;
        verify_epoch_finality_record(&fin, &epoch_blocks)?;

        self.store
            .write_finality_record(latest_complete_epoch, &fin)?;

        let mut new_state = st;
        new_state.latest_finalized_epoch = fin.epoch_id;
        new_state.latest_finalized_epoch_hash_hex = fin.finality_hash_hex.clone();
        new_state.state_root_hex = compute_state_root_hex(&new_state);
        self.store.write_state(&new_state)?;

        Ok(latest_complete_epoch)
    }

    fn bootstrap_graph_from_disk(&mut self) -> Result<()> {
        let _st: StateV1 = match self.store.read_state() {
            Ok(s) => s,
            Err(_) => {
                self.graph = BlockGraph::new();
                return Ok(());
            }
        };

        self.graph = BlockGraph::new();
        self.graph.set_genesis(genesis_hash());

        let mut h = 1u64;
        loop {
            let hashes = self.store.read_height_index(h)?;
            if hashes.is_empty() {
                break;
            }
            for bh in hashes {
                let blk: BlockV1 = match self.store.read_block_by_hash(&bh) {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                let parent = Hash32::from_hex(&blk.header.prev_block_hash_hex)?;
                let ph = self.graph.height_of(&parent);
                self.graph.insert(bh, parent, ph);
            }
            h = h.saturating_add(1);
        }

        Ok(())
    }

    fn canonical_chain_hashes_to_tip(&self, tip: Hash32) -> Result<Vec<Hash32>> {
        if tip == genesis_hash() {
            return Ok(Vec::new());
        }

        let mut chain_hashes: Vec<Hash32> = Vec::new();
        let mut cur = tip;

        while cur != genesis_hash() {
            let blk: BlockV1 = self.store.read_block_by_hash(&cur)?;
            chain_hashes.push(cur);
            cur = Hash32::from_hex(&blk.header.prev_block_hash_hex)?;
        }

        chain_hashes.reverse();
        Ok(chain_hashes)
    }

    fn recompute_best_and_state(&mut self) -> Result<()> {
        let tips = self.graph.tips();
        if tips.is_empty() {
            return Ok(());
        }

        let mut best_tip = genesis_hash();
        let mut best_height = 0u64;
        let mut best_mbw = 0u128;

        for tip in tips {
            if self.graph.is_orphan(&tip) {
                continue;
            }
            let height = self.graph.height_of(&tip).unwrap_or(0);
            let blk: BlockV1 = match self.store.read_block_by_hash(&tip) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let mbw = blk.header.chain_mbw_v0;

            if mbw > best_mbw
                || (mbw == best_mbw && height > best_height)
                || (mbw == best_mbw && height == best_height && tip > best_tip)
            {
                best_tip = tip;
                best_height = height;
                best_mbw = mbw;
            }
        }

        let chain_hashes = self.canonical_chain_hashes_to_tip(best_tip)?;
        let g = self.read_genesis()?;

        let mut st = self.read_state_for_parent_of_height_one()?;

        for h in &chain_hashes {
            let blk: BlockV1 = self.store.read_block_by_hash(h)?;
            st = apply_block_to_state(&g, &st, &blk)?;
        }

        let genesis_blk: BlockV1 = self.store.read_block_by_hash(&genesis_hash())?;
        let genesis_fin = finalize_epoch_from_blocks(
            0,
            DEFAULT_EPOCH_LEN,
            &[genesis_blk.clone()],
            deterministic_finality_time_from_blocks(&[genesis_blk.clone()]),
        )?;
        verify_epoch_finality_record(&genesis_fin, &[genesis_blk])?;

        st.best_tip_hash_hex = best_tip.to_hex();
        st.best_height = best_height;
        st.chain_mbw_v0 = best_mbw;
        st.latest_finalized_epoch = genesis_fin.epoch_id;
        st.latest_finalized_epoch_hash_hex = genesis_fin.finality_hash_hex.clone();

        if best_height >= DEFAULT_EPOCH_LEN {
            let latest_complete_epoch = best_height / DEFAULT_EPOCH_LEN;
            if latest_complete_epoch > 0 {
                let start_height = ((latest_complete_epoch - 1) * DEFAULT_EPOCH_LEN) + 1;
                let end_height = latest_complete_epoch * DEFAULT_EPOCH_LEN;

                let mut epoch_blocks = Vec::with_capacity(DEFAULT_EPOCH_LEN as usize);
                for height in start_height..=end_height {
                    let idx = (height - 1) as usize;
                    let h = chain_hashes
                        .get(idx)
                        .ok_or_else(|| anyhow!("missing canonical block for height {}", height))?;
                    let blk = self.store.read_block_by_hash(h)?;
                    epoch_blocks.push(blk);
                }

                let fin = finalize_epoch_from_blocks(
                    latest_complete_epoch,
                    DEFAULT_EPOCH_LEN,
                    &epoch_blocks,
                    deterministic_finality_time_from_blocks(&epoch_blocks),
                )?;
                verify_epoch_finality_record(&fin, &epoch_blocks)?;

                st.latest_finalized_epoch = fin.epoch_id;
                st.latest_finalized_epoch_hash_hex = fin.finality_hash_hex;
            }
        }

        st.state_root_hex = compute_state_root_hex(&st);
        self.store.write_state(&st)?;
        Ok(())
    }

    pub fn verify_block(&self, blk: &BlockV1) -> Result<()> {
        verify_block_commitments(blk)?;

        if blk.block_signature.is_some()
            && !self.verify_block_signature_against_genesis_root(blk)?
        {
            return Err(anyhow!("block_signature invalid against genesis root"));
        }

        let g = self.read_genesis()?;

        if blk.header.height == 1 {
            let parent_state = self.read_state_for_parent_of_height_one()?;
            let projected = apply_block_to_state(&g, &parent_state, blk)?;

            if projected.chain_mbw_v0 != blk.header.chain_mbw_v0 {
                return Err(anyhow!(
                    "chain_mbw_v0 mismatch expected={} got={}",
                    projected.chain_mbw_v0,
                    blk.header.chain_mbw_v0
                ));
            }

            if projected.state_root_hex != blk.header.state_root_hex {
                return Err(anyhow!(
                    "state_root_hex mismatch expected={} got={}",
                    projected.state_root_hex,
                    blk.header.state_root_hex
                ));
            }
        } else {
            let parent_hash = Hash32::from_hex(&blk.header.prev_block_hash_hex)?;
            if self.has_block(&parent_hash)? {
                let parent_state = self.compute_canonical_state_at_hash(parent_hash)?;
                let projected = apply_block_to_state(&g, &parent_state, blk)?;

                if projected.chain_mbw_v0 != blk.header.chain_mbw_v0 {
                    return Err(anyhow!(
                        "chain_mbw_v0 mismatch expected={} got={}",
                        projected.chain_mbw_v0,
                        blk.header.chain_mbw_v0
                    ));
                }

                if projected.state_root_hex != blk.header.state_root_hex {
                    return Err(anyhow!(
                        "state_root_hex mismatch expected={} got={}",
                        projected.state_root_hex,
                        blk.header.state_root_hex
                    ));
                }
            }
        }

        Ok(())
    }

    pub fn verify_block_signature_against_genesis_root(&self, blk: &BlockV1) -> Result<bool> {
        let sig = match &blk.block_signature {
            Some(s) => s,
            None => return Ok(false),
        };

        if sig.validator_id.is_empty() {
            return Ok(false);
        }

        let expected_root_hex = match self.validator_wots_root_hex(&sig.validator_id)? {
            Some(v) => v,
            None => return Ok(false),
        };

        let pk = pk_from_hex(&sig.wots_public_key_hex)?;
        let wsig = sig_from_hex(&sig.wots_signature_hex)?;
        let msg = block_signing_message(blk);

        if !verify_wots(&msg, &wsig, &pk) {
            return Ok(false);
        }

        let root = pseudo_root_from_pk(&pk);
        let root_hex = hex::encode(root);

        Ok(root_hex == expected_root_hex)
    }

    fn read_state_for_parent_of_height_one(&self) -> Result<StateV1> {
        let g = self.read_genesis()?;

        let genesis_block: BlockV1 = self.store.read_block_by_hash(&genesis_hash())?;
        let genesis_fin = finalize_epoch_from_blocks(
            0,
            DEFAULT_EPOCH_LEN,
            &[genesis_block.clone()],
            deterministic_finality_time_from_blocks(&[genesis_block]),
        )?;

        let mut st = StateV1 {
            version: 1,
            best_tip_hash_hex: genesis_hash().to_hex(),
            best_height: 0,
            chain_mbw_v0: 0,
            machine_last_capture_hash: HashMap::new(),
            validator_stake_credit: HashMap::new(),
            validator_minted_bincoin: HashMap::new(),
            balances: g.initial_balances.clone(),
            pusdc_balances: g.initial_pusdc_balances.clone(),
            pusdc_locked: HashMap::new(),
            amm_bincoin_reserve: 0,
            amm_pusdc_reserve: 0,
            latest_finalized_epoch: genesis_fin.epoch_id,
            latest_finalized_epoch_hash_hex: genesis_fin.finality_hash_hex,
            state_root_hex: default_state_root_hex(),
        };
        st.state_root_hex = compute_state_root_hex(&st);
        Ok(st)
    }

    fn compute_canonical_state_at_hash(&self, tip: Hash32) -> Result<StateV1> {
        if tip == genesis_hash() {
            return self.read_state_for_parent_of_height_one();
        }

        let chain_hashes = self.canonical_chain_hashes_to_tip(tip)?;
        let g = self.read_genesis()?;

        let mut st = self.read_state_for_parent_of_height_one()?;
        for h in &chain_hashes {
            let blk: BlockV1 = self.store.read_block_by_hash(h)?;
            st = apply_block_to_state(&g, &st, &blk)?;
        }

        let best_height = st.best_height;

        let genesis_blk: BlockV1 = self.store.read_block_by_hash(&genesis_hash())?;
        let genesis_fin = finalize_epoch_from_blocks(
            0,
            DEFAULT_EPOCH_LEN,
            &[genesis_blk.clone()],
            deterministic_finality_time_from_blocks(&[genesis_blk.clone()]),
        )?;
        verify_epoch_finality_record(&genesis_fin, &[genesis_blk])?;

        st.latest_finalized_epoch = genesis_fin.epoch_id;
        st.latest_finalized_epoch_hash_hex = genesis_fin.finality_hash_hex.clone();

        if best_height >= DEFAULT_EPOCH_LEN {
            let latest_complete_epoch = best_height / DEFAULT_EPOCH_LEN;
            if latest_complete_epoch > 0 {
                let start_height = ((latest_complete_epoch - 1) * DEFAULT_EPOCH_LEN) + 1;
                let end_height = latest_complete_epoch * DEFAULT_EPOCH_LEN;

                let mut epoch_blocks = Vec::with_capacity(DEFAULT_EPOCH_LEN as usize);
                for height in start_height..=end_height {
                    let idx = (height - 1) as usize;
                    let h = chain_hashes
                        .get(idx)
                        .ok_or_else(|| anyhow!("missing canonical block for height {}", height))?;
                    let blk = self.store.read_block_by_hash(h)?;
                    epoch_blocks.push(blk);
                }

                let fin = finalize_epoch_from_blocks(
                    latest_complete_epoch,
                    DEFAULT_EPOCH_LEN,
                    &epoch_blocks,
                    deterministic_finality_time_from_blocks(&epoch_blocks),
                )?;
                verify_epoch_finality_record(&fin, &epoch_blocks)?;

                st.latest_finalized_epoch = fin.epoch_id;
                st.latest_finalized_epoch_hash_hex = fin.finality_hash_hex;
            }
        }

        st.state_root_hex = compute_state_root_hex(&st);
        Ok(st)
    }
}

fn verify_proof_canonical(p: &ProofV0) -> Result<()> {
    verify_proof_basic(p)?;

    let pop1 = proof_v0_to_pop1(p)?;
    validate_pop1_container_basic(&pop1)?;

    let pop2 = proof_v0_to_pop2(p)?;
    validate_pop2_against_pop1(&pop2, &pop1, &ScoringParamsV0::default())?;

    Ok(())
}

fn deterministic_finality_time_from_blocks(blocks: &[BlockV1]) -> u64 {
    blocks.last().map(|b| b.header.timestamp_unix).unwrap_or(0)
}

/// Verify public block/payload commitments only. This does not validate parent
/// state, consensus, or an outer validator signature and never opens a database.
pub fn verify_block_commitments(blk: &BlockV1) -> Result<()> {
        if blk.header.version != BLOCK_VERSION {
            return Err(anyhow!("bad block version"));
        }
        if blk.header.height == 0 {
            return Err(anyhow!("height 0 reserved"));
        }
        if blk.app_events.len() > MAX_APP_EVENTS_PER_BLOCK {
            return Err(anyhow!("too many app events"));
        }
        if blk.proofs.len() > 1024 {
            return Err(anyhow!("too many proofs"));
        }

        for ev in &blk.app_events {
            verify_event(ev)?;
        }
        let tab = total_app_bytes(&blk.app_events);
        if tab != blk.header.total_app_bytes {
            return Err(anyhow!("total_app_bytes mismatch"));
        }
        if tab > MAX_APP_BYTES_PER_BLOCK {
            return Err(anyhow!("app bytes too large"));
        }

        for p in &blk.proofs {
            verify_proof_canonical(p)?;
        }

        let app_hash = app_events_hash_hex(&blk.app_events);
        if app_hash != blk.header.app_events_hash_hex {
            return Err(anyhow!("app_events_hash mismatch"));
        }

        let proofs_hash = proof_hashes_hex(&blk.proofs);
        if proofs_hash != blk.header.proofs_hash_hex {
            return Err(anyhow!("proofs_hash mismatch"));
        }

        let expect_hash = block_hash(&blk.header, &blk.proofs, &blk.app_events);
        if expect_hash.to_hex() != blk.block_hash_hex {
            return Err(anyhow!("block_hash mismatch"));
        }

    Ok(())
}

fn block_hash(header: &BlockHeaderV1, proofs: &[ProofV0], app_events: &[AppEventV0]) -> BlockHash {
    let mut h = Sha256::new();

    h.update(header.version.to_le_bytes());
    h.update(header.height.to_le_bytes());
    h.update(header.prev_block_hash_hex.as_bytes());
    h.update(header.chain_id.as_bytes());
    h.update(header.epoch_id.as_bytes());
    h.update(header.producer_id.as_bytes());
    h.update(header.timestamp_unix.to_le_bytes());
    h.update(header.app_events_hash_hex.as_bytes());
    h.update(header.total_app_bytes.to_le_bytes());
    h.update(header.proofs_hash_hex.as_bytes());
    h.update(header.chain_mbw_v0.to_le_bytes());
    h.update(header.state_root_hex.as_bytes());

    for p in proofs {
        h.update(p.proof_hash_hex.as_bytes());
    }
    for e in app_events {
        h.update(e.kind.as_bytes());
        h.update(e.payload_sha256_hex.as_bytes());
        h.update(e.payload_len.to_le_bytes());
    }

    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    Hash32(arr)
}

pub fn block_signing_message(blk: &BlockV1) -> Vec<u8> {
    let mut out = Vec::with_capacity(320);

    out.extend_from_slice(b"popchain:block-signature:v1");
    out.push(0xff);

    out.extend_from_slice(&blk.header.version.to_le_bytes());
    out.extend_from_slice(&blk.header.height.to_le_bytes());
    out.extend_from_slice(blk.header.prev_block_hash_hex.as_bytes());
    out.push(0x00);

    out.extend_from_slice(blk.header.chain_id.as_bytes());
    out.push(0x00);

    out.extend_from_slice(blk.header.epoch_id.as_bytes());
    out.push(0x00);

    out.extend_from_slice(blk.header.producer_id.as_bytes());
    out.push(0x00);

    out.extend_from_slice(&blk.header.timestamp_unix.to_le_bytes());
    out.extend_from_slice(blk.header.app_events_hash_hex.as_bytes());
    out.push(0x00);

    out.extend_from_slice(&blk.header.total_app_bytes.to_le_bytes());
    out.extend_from_slice(blk.header.proofs_hash_hex.as_bytes());
    out.push(0x00);

    out.extend_from_slice(&blk.header.chain_mbw_v0.to_le_bytes());
    out.extend_from_slice(blk.header.state_root_hex.as_bytes());
    out.push(0x00);

    out.extend_from_slice(blk.block_hash_hex.as_bytes());

    out
}

pub fn attach_block_signature_wots(
    blk: &mut BlockV1,
    validator_id: &str,
    kp: &WotsKeypair,
) -> Result<()> {
    if validator_id.is_empty() {
        return Err(anyhow!("validator_id empty"));
    }

    let msg = block_signing_message(blk);
    let sig = sign_wots(&msg, kp);

    blk.block_signature = Some(BlockSignatureV1 {
        validator_id: validator_id.to_string(),
        wots_public_key_hex: pk_to_hex(&kp.pk),
        wots_signature_hex: sig_to_hex(&sig),
    });

    Ok(())
}

pub fn verify_block_signature_wots(blk: &BlockV1) -> Result<bool> {
    let sig = match &blk.block_signature {
        Some(s) => s,
        None => return Ok(false),
    };

    if sig.validator_id.is_empty() {
        return Ok(false);
    }

    let pk = pk_from_hex(&sig.wots_public_key_hex)?;
    let wsig = sig_from_hex(&sig.wots_signature_hex)?;
    let msg = block_signing_message(blk);

    Ok(verify_wots(&msg, &wsig, &pk))
}

pub fn slot_of_unix(now_unix: u64, slot_secs: u64) -> u64 {
    let s = slot_secs.max(1);
    now_unix / s
}

pub fn leader_for_slot(validators: &[String], chain_id: &[u8], slot: u64) -> Result<u32> {
    if validators.is_empty() {
        return Err(anyhow!("validators empty"));
    }

    let mut h = Sha256::new();
    h.update(chain_id);
    h.update(slot.to_le_bytes());

    for v in validators {
        h.update(v.as_bytes());
        h.update([0u8]);
    }

    let out = h.finalize();
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&out[..8]);
    let x = u64::from_le_bytes(arr);

    Ok((x % (validators.len() as u64)) as u32)
}

pub fn block_mbw_u64(blk: &BlockV1) -> u64 {
    blk.proofs
        .iter()
        .fold(0u64, |acc, p| acc.saturating_add(p.mbw_u64))
}

pub fn raw_mbw_to_economic_units_u64(raw_block_mbw: u64) -> u64 {
    if raw_block_mbw == 0 {
        0
    } else {
        1 + floor_log2_u64(raw_block_mbw) as u64
    }
}

pub fn mint_reward_u128(raw_block_mbw: u64) -> u128 {
    raw_mbw_to_economic_units_u64(raw_block_mbw) as u128
}

pub fn stake_credit_reward_u128(raw_block_mbw: u64) -> u128 {
    if raw_block_mbw == 0 {
        1
    } else {
        2 + raw_mbw_to_economic_units_u64(raw_block_mbw) as u128
    }
}

fn floor_log2_u64(x: u64) -> u32 {
    debug_assert!(x > 0);
    63 - x.leading_zeros()
}

fn apply_block_to_state(
    genesis: &GenesisV1,
    parent_state: &StateV1,
    blk: &BlockV1,
) -> Result<StateV1> {
    apply_block_inputs_to_state(
        genesis,
        parent_state,
        &blk.header.producer_id,
        &blk.proofs,
        &blk.app_events,
        blk.header.height,
    )
}

fn apply_block_inputs_to_state(
    genesis: &GenesisV1,
    parent_state: &StateV1,
    producer_id: &str,
    proofs: &[ProofV0],
    app_events: &[AppEventV0],
    new_height: u64,
) -> Result<StateV1> {
    let mut st = parent_state.clone();

    st.best_height = new_height;
    st.chain_mbw_v0 = st
        .chain_mbw_v0
        .saturating_add(proofs.iter().map(|p| p.mbw_u64 as u128).sum::<u128>());

    let block_raw_mbw = proofs
        .iter()
        .fold(0u64, |acc, p| acc.saturating_add(p.mbw_u64));

    let minted = mint_reward_u128(block_raw_mbw);
    let stake_credit = stake_credit_reward_u128(block_raw_mbw);
    let reward_owner = genesis
        .validator_reward_addresses
        .get(producer_id)
        .cloned()
        .unwrap_or_else(|| producer_id.to_string());

    *st.validator_minted_bincoin
        .entry(producer_id.to_string())
        .or_insert(0) += minted;
    *st.validator_stake_credit
        .entry(producer_id.to_string())
        .or_insert(0) += stake_credit;
    *st.balances.entry(reward_owner).or_insert(0) += minted;

    for p in proofs {
        let exp = st
            .machine_last_capture_hash
            .get(&p.machine_id)
            .cloned()
            .unwrap_or_else(util::zero_hash32_hex);

        if p.prev_capture_hash_hex != exp {
            return Err(anyhow!(
                "project_state_after_block replay mismatch for machine_id={} expected_prev={} got_prev={}",
                p.machine_id,
                exp,
                p.prev_capture_hash_hex
            ));
        }

        st.machine_last_capture_hash
            .insert(p.machine_id.clone(), p.metrics.sha256_hex.clone());
    }

    apply_app_events_to_state(&mut st, app_events)?;

    st.state_root_hex = compute_state_root_hex(&st);
    Ok(st)
}

fn apply_app_events_to_state(st: &mut StateV1, app_events: &[AppEventV0]) -> Result<()> {
    for ev in app_events {
        match ev.kind.as_str() {
            APP_KIND_TRANSFER_V0 => {
                let transfer = decode_transfer_event(ev)?;
                apply_transfer_in_state(
                    st,
                    &transfer.from,
                    &transfer.to,
                    transfer.amount.parse::<u128>()?,
                )?;
            }
            APP_KIND_PUSDC_TRANSFER_V0 => {
                let transfer = decode_pusdc_transfer_event(ev)?;
                apply_pusdc_transfer_in_state(
                    st,
                    &transfer.from,
                    &transfer.to,
                    transfer.amount.parse::<u128>()?,
                )?;
            }
            APP_KIND_BRIDGE_LOCK_PUSDC_V0 => {
                let lock = decode_bridge_lock_pusdc_event(ev)?;
                apply_bridge_lock_pusdc_in_state(st, &lock.from, lock.amount.parse::<u128>()?)?;
            }
            APP_KIND_BRIDGE_UNLOCK_PUSDC_V0 => {
                let unlock = decode_bridge_unlock_pusdc_event(ev)?;
                apply_bridge_unlock_pusdc_in_state(st, &unlock.to, unlock.amount.parse::<u128>()?)?;
            }
            APP_KIND_AMM_ADD_LIQUIDITY_V0 => {
                let add = decode_amm_add_liquidity_event(ev)?;
                apply_amm_add_liquidity_in_state(
                    st,
                    &add.provider,
                    add.bincoin_amount.parse::<u128>()?,
                    add.pusdc_amount.parse::<u128>()?,
                )?;
            }
            APP_KIND_AMM_SWAP_BINCOIN_TO_PUSDC_V0 => {
                let swap = decode_amm_swap_bincoin_to_pusdc_event(ev)?;
                apply_amm_swap_bincoin_to_pusdc_in_state(
                    st,
                    &swap.user,
                    swap.amount_in.parse::<u128>()?,
                )?;
            }
            APP_KIND_AMM_SWAP_PUSDC_TO_BINCOIN_V0 => {
                let swap = decode_amm_swap_pusdc_to_bincoin_event(ev)?;
                apply_amm_swap_pusdc_to_bincoin_in_state(
                    st,
                    &swap.user,
                    swap.amount_in.parse::<u128>()?,
                )?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn apply_transfer_in_state(st: &mut StateV1, from: &str, to: &str, amount: u128) -> Result<()> {
    let from_addr = AddressV1::parse(from)?;
    let to_addr = AddressV1::parse(to)?;

    if amount == 0 {
        return Err(anyhow!("amount must be > 0"));
    }
    if from_addr == to_addr {
        return Err(anyhow!("from and to must differ"));
    }

    transfer_in_map(
        &mut st.balances,
        &from_addr.to_string(),
        &to_addr.to_string(),
        amount,
    )
}

fn apply_pusdc_transfer_in_state(
    st: &mut StateV1,
    from: &str,
    to: &str,
    amount: u128,
) -> Result<()> {
    let from_addr = AddressV1::parse(from)?;
    let to_addr = AddressV1::parse(to)?;

    if amount == 0 {
        return Err(anyhow!("amount must be > 0"));
    }
    if from_addr == to_addr {
        return Err(anyhow!("from and to must differ"));
    }

    transfer_in_map(
        &mut st.pusdc_balances,
        &from_addr.to_string(),
        &to_addr.to_string(),
        amount,
    )
}

fn apply_bridge_lock_pusdc_in_state(st: &mut StateV1, from: &str, amount: u128) -> Result<()> {
    let from_addr = AddressV1::parse(from)?;
    if amount == 0 {
        bail!("amount must be > 0");
    }

    let key = from_addr.to_string();

    move_between_maps(
        &mut st.pusdc_balances,
        &mut st.pusdc_locked,
        &key,
        &key,
        amount,
    )
}

fn apply_bridge_unlock_pusdc_in_state(st: &mut StateV1, to: &str, amount: u128) -> Result<()> {
    let to_addr = AddressV1::parse(to)?;
    if amount == 0 {
        bail!("amount must be > 0");
    }

    let key = to_addr.to_string();

    move_between_maps(
        &mut st.pusdc_locked,
        &mut st.pusdc_balances,
        &key,
        &key,
        amount,
    )
}

fn apply_amm_add_liquidity_in_state(
    st: &mut StateV1,
    provider: &str,
    bincoin_amount: u128,
    pusdc_amount: u128,
) -> Result<()> {
    let provider_addr = AddressV1::parse(provider)?;
    if bincoin_amount == 0 || pusdc_amount == 0 {
        bail!("liquidity amounts must be > 0");
    }

    let provider_key = provider_addr.to_string();

    transfer_in_map(
        &mut st.balances,
        &provider_key,
        AMM_POOL_ACCOUNT,
        bincoin_amount,
    )?;
    transfer_in_map(
        &mut st.pusdc_balances,
        &provider_key,
        AMM_POOL_ACCOUNT,
        pusdc_amount,
    )?;

    st.amm_bincoin_reserve = st
        .amm_bincoin_reserve
        .checked_add(bincoin_amount)
        .ok_or_else(|| anyhow!("amm_bincoin_reserve overflow"))?;
    st.amm_pusdc_reserve = st
        .amm_pusdc_reserve
        .checked_add(pusdc_amount)
        .ok_or_else(|| anyhow!("amm_pusdc_reserve overflow"))?;

    Ok(())
}

fn apply_amm_swap_bincoin_to_pusdc_in_state(
    st: &mut StateV1,
    user: &str,
    amount_in: u128,
) -> Result<()> {
    let user_addr = AddressV1::parse(user)?;
    if amount_in == 0 {
        bail!("amount_in must be > 0");
    }

    let user_key = user_addr.to_string();
    let amount_out = cpmm_quote_out(st.amm_bincoin_reserve, st.amm_pusdc_reserve, amount_in)?;

    transfer_in_map(&mut st.balances, &user_key, AMM_POOL_ACCOUNT, amount_in)?;
    transfer_in_map(
        &mut st.pusdc_balances,
        AMM_POOL_ACCOUNT,
        &user_key,
        amount_out,
    )?;

    st.amm_bincoin_reserve = st
        .amm_bincoin_reserve
        .checked_add(amount_in)
        .ok_or_else(|| anyhow!("amm_bincoin_reserve overflow"))?;
    st.amm_pusdc_reserve = st
        .amm_pusdc_reserve
        .checked_sub(amount_out)
        .ok_or_else(|| anyhow!("amm_pusdc_reserve underflow"))?;

    Ok(())
}

fn apply_amm_swap_pusdc_to_bincoin_in_state(
    st: &mut StateV1,
    user: &str,
    amount_in: u128,
) -> Result<()> {
    let user_addr = AddressV1::parse(user)?;
    if amount_in == 0 {
        bail!("amount_in must be > 0");
    }

    let user_key = user_addr.to_string();
    let amount_out = cpmm_quote_out(st.amm_pusdc_reserve, st.amm_bincoin_reserve, amount_in)?;

    transfer_in_map(
        &mut st.pusdc_balances,
        &user_key,
        AMM_POOL_ACCOUNT,
        amount_in,
    )?;
    transfer_in_map(&mut st.balances, AMM_POOL_ACCOUNT, &user_key, amount_out)?;

    st.amm_pusdc_reserve = st
        .amm_pusdc_reserve
        .checked_add(amount_in)
        .ok_or_else(|| anyhow!("amm_pusdc_reserve overflow"))?;
    st.amm_bincoin_reserve = st
        .amm_bincoin_reserve
        .checked_sub(amount_out)
        .ok_or_else(|| anyhow!("amm_bincoin_reserve underflow"))?;

    Ok(())
}

fn transfer_in_map(
    balances: &mut HashMap<String, u128>,
    from_key: &str,
    to_key: &str,
    amount: u128,
) -> Result<()> {
    let from_balance = balances.get(from_key).copied().unwrap_or(0);
    if from_balance < amount {
        return Err(anyhow!(
            "insufficient funds: balance={} amount={}",
            from_balance,
            amount
        ));
    }

    let remaining = from_balance - amount;
    if remaining == 0 {
        balances.remove(from_key);
    } else {
        balances.insert(from_key.to_string(), remaining);
    }

    checked_add_to_map(balances, to_key, amount)
}

fn checked_add_to_map(map: &mut HashMap<String, u128>, key: &str, amount: u128) -> Result<()> {
    let current = map.get(key).copied().unwrap_or(0);
    let updated = current
        .checked_add(amount)
        .ok_or_else(|| anyhow!("balance overflow on recipient"))?;
    map.insert(key.to_string(), updated);
    Ok(())
}

fn move_between_maps(
    src: &mut HashMap<String, u128>,
    dst: &mut HashMap<String, u128>,
    src_key: &str,
    dst_key: &str,
    amount: u128,
) -> Result<()> {
    let src_balance = src.get(src_key).copied().unwrap_or(0);
    if src_balance < amount {
        return Err(anyhow!(
            "insufficient funds: balance={} amount={}",
            src_balance,
            amount
        ));
    }

    let remaining = src_balance - amount;
    if remaining == 0 {
        src.remove(src_key);
    } else {
        src.insert(src_key.to_string(), remaining);
    }

    checked_add_to_map(dst, dst_key, amount)
}

fn cpmm_quote_out(reserve_in: u128, reserve_out: u128, amount_in: u128) -> Result<u128> {
    if reserve_in == 0 || reserve_out == 0 {
        bail!("amm empty");
    }
    if amount_in == 0 {
        bail!("amount_in must be > 0");
    }

    let numerator = amount_in
        .checked_mul(reserve_out)
        .ok_or_else(|| anyhow!("amm quote overflow numerator"))?;
    let denominator = reserve_in
        .checked_add(amount_in)
        .ok_or_else(|| anyhow!("amm quote overflow denominator"))?;

    let amount_out = numerator / denominator;
    if amount_out == 0 {
        bail!("amount_out is zero");
    }
    if amount_out >= reserve_out {
        bail!("amount_out exceeds reserve_out");
    }

    Ok(amount_out)
}

pub fn compute_state_root_hex(st: &StateV1) -> String {
    let mut h = Sha256::new();

    h.update(b"popchain:state-root:v3");
    h.update([0xff]);

    h.update(st.version.to_le_bytes());
    h.update(st.best_height.to_le_bytes());
    h.update(st.chain_mbw_v0.to_le_bytes());

    let mut machine_rows: Vec<_> = st.machine_last_capture_hash.iter().collect();
    machine_rows.sort_by(|a, b| a.0.cmp(b.0));
    h.update((machine_rows.len() as u64).to_le_bytes());
    for (k, v) in machine_rows {
        h.update(k.as_bytes());
        h.update([0x00]);
        h.update(v.as_bytes());
        h.update([0x00]);
    }

    let mut stake_rows: Vec<_> = st.validator_stake_credit.iter().collect();
    stake_rows.sort_by(|a, b| a.0.cmp(b.0));
    h.update((stake_rows.len() as u64).to_le_bytes());
    for (k, v) in stake_rows {
        h.update(k.as_bytes());
        h.update([0x00]);
        h.update(v.to_le_bytes());
    }

    let mut mint_rows: Vec<_> = st.validator_minted_bincoin.iter().collect();
    mint_rows.sort_by(|a, b| a.0.cmp(b.0));
    h.update((mint_rows.len() as u64).to_le_bytes());
    for (k, v) in mint_rows {
        h.update(k.as_bytes());
        h.update([0x00]);
        h.update(v.to_le_bytes());
    }

    let mut balance_rows: Vec<_> = st.balances.iter().collect();
    balance_rows.sort_by(|a, b| a.0.cmp(b.0));
    h.update((balance_rows.len() as u64).to_le_bytes());
    for (k, v) in balance_rows {
        h.update(k.as_bytes());
        h.update([0x00]);
        h.update(v.to_le_bytes());
    }

    let mut pusdc_rows: Vec<_> = st.pusdc_balances.iter().collect();
    pusdc_rows.sort_by(|a, b| a.0.cmp(b.0));
    h.update((pusdc_rows.len() as u64).to_le_bytes());
    for (k, v) in pusdc_rows {
        h.update(k.as_bytes());
        h.update([0x00]);
        h.update(v.to_le_bytes());
    }

    let mut pusdc_locked_rows: Vec<_> = st.pusdc_locked.iter().collect();
    pusdc_locked_rows.sort_by(|a, b| a.0.cmp(b.0));
    h.update((pusdc_locked_rows.len() as u64).to_le_bytes());
    for (k, v) in pusdc_locked_rows {
        h.update(k.as_bytes());
        h.update([0x00]);
        h.update(v.to_le_bytes());
    }

    h.update(st.amm_bincoin_reserve.to_le_bytes());
    h.update(st.amm_pusdc_reserve.to_le_bytes());

    h.update(st.latest_finalized_epoch.to_le_bytes());
    h.update(st.latest_finalized_epoch_hash_hex.as_bytes());
    h.update([0x00]);

    hex::encode(h.finalize())
}
