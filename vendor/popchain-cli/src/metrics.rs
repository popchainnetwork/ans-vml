#![forbid(unsafe_code)]

use crate::types::{
    Hash32, Pop1ContainerV1, Pop1HeaderV1, Pop1IntegrityV1, Pop1MetricsV1, Pop2ProofV1,
};
use anyhow::{anyhow, Context, Result};
use blake3::Hasher as B3;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

const SCORE_SCALE_PPM: u64 = 1_000_000;
const MAX_MBW_U64: u64 = 4_000_000;
const SIZE_BONUS_CAP: u64 = 1_000_000;
const DURATION_BONUS_CAP: u64 = 250_000;

const POP1_VERSION_V1: u32 = 1;
const POP2_VERSION_V1: u32 = 1;
const LEGACY_PROOF_VERSION_V0: u32 = 0;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringParamsV0 {
    pub entropy_target_q32: u64,
    pub compression_target_ppm: u64,
    pub mad_target_q32: u64,
}

impl Default for ScoringParamsV0 {
    fn default() -> Self {
        Self {
            entropy_target_q32: (0.75_f64 * (u32::MAX as f64)) as u64,
            compression_target_ppm: 500_000,
            mad_target_q32: (0.10_f64 * (u32::MAX as f64)) as u64,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsV0 {
    pub bytes_len: u64,
    pub sha256_hex: String,
    pub blake3_hex: String,
    pub entropy_q32: u64,
    pub compression_ppm: u64,
    pub mad_q32: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofV0 {
    pub version: u32,
    pub machine_id: String,
    pub capture_start_unix: u64,
    pub capture_end_unix: u64,
    pub prev_capture_hash_hex: String,
    pub metrics: MetricsV0,
    pub score_u64: u64,
    pub mbw_u64: u64,
    pub proof_hash_hex: String,
}

fn entropy_q32(bytes: &[u8]) -> u64 {
    if bytes.is_empty() {
        return 0;
    }

    let mut freq = [0u32; 256];
    for &b in bytes {
        freq[b as usize] += 1;
    }

    let n = bytes.len() as f64;
    let mut h = 0.0_f64;

    for &c in &freq {
        if c == 0 {
            continue;
        }
        let p = (c as f64) / n;
        h -= p * p.log2();
    }

    let normalized = (h / 8.0).clamp(0.0, 1.0);
    (normalized * (u32::MAX as f64)) as u64
}

fn mad_q32(bytes: &[u8]) -> u64 {
    if bytes.is_empty() {
        return 0;
    }

    let n = bytes.len() as f64;
    let mean = bytes.iter().map(|&b| b as f64).sum::<f64>() / n;

    let mad = bytes.iter().map(|&b| (b as f64 - mean).abs()).sum::<f64>() / n;

    let norm = (mad / 128.0).clamp(0.0, 1.0);
    (norm * (u32::MAX as f64)) as u64
}

fn compression_ppm(bytes: &[u8]) -> u64 {
    if bytes.is_empty() {
        return 0;
    }

    let mut runs = 0u64;
    let mut last = bytes[0];

    for &b in &bytes[1..] {
        if b == last {
            runs += 1;
        }
        last = b;
    }

    let n = bytes.len() as u64;
    let denom = n.saturating_sub(1).max(1);
    let compressible = (runs as f64) / (denom as f64);
    let ratio = (1.0 - compressible).clamp(0.0, 1.0);

    (ratio * SCORE_SCALE_PPM as f64) as u64
}

fn ppm_closeness_u64(x: u64, target: u64, max_domain: u64) -> u64 {
    if max_domain == 0 {
        return 0;
    }

    let dx = x.abs_diff(target).min(max_domain);
    let remain = max_domain.saturating_sub(dx);

    ((remain as u128) * (SCORE_SCALE_PPM as u128) / (max_domain as u128)) as u64
}

fn score(params: &ScoringParamsV0, m: &Pop1MetricsV1) -> u64 {
    let e = ppm_closeness_u64(m.entropy_q32, params.entropy_target_q32, u32::MAX as u64);
    let c = ppm_closeness_u64(
        m.compression_ppm,
        params.compression_target_ppm,
        SCORE_SCALE_PPM,
    );
    let mad = ppm_closeness_u64(m.mad_q32, params.mad_target_q32, u32::MAX as u64);

    let weighted = (e as u128) * 4 + (c as u128) * 3 + (mad as u128) * 3;
    (weighted / 10) as u64
}

fn floor_log2_u64(x: u64) -> u32 {
    debug_assert!(x > 0);
    63 - x.leading_zeros()
}

fn bounded_size_bonus(bytes_len: u64) -> u64 {
    if bytes_len == 0 {
        return 0;
    }

    let lg = floor_log2_u64(bytes_len.saturating_add(1)) as u64;
    (lg.saturating_mul(32_000)).min(SIZE_BONUS_CAP)
}

fn bounded_duration_bonus(capture_start_unix: u64, capture_end_unix: u64) -> u64 {
    let dur = capture_end_unix.saturating_sub(capture_start_unix);
    if dur == 0 {
        return 0;
    }

    let lg = floor_log2_u64(dur.saturating_add(1)) as u64;
    (lg.saturating_mul(8_000)).min(DURATION_BONUS_CAP)
}

fn raw_mbw_u64(
    score_u64: u64,
    bytes_len: u64,
    capture_start_unix: u64,
    capture_end_unix: u64,
) -> u64 {
    let size_bonus = bounded_size_bonus(bytes_len);
    let duration_bonus = bounded_duration_bonus(capture_start_unix, capture_end_unix);

    score_u64
        .saturating_add(size_bonus)
        .saturating_add(duration_bonus)
        .min(MAX_MBW_U64)
}

fn sha256_hash32(bytes: &[u8]) -> Hash32 {
    let mut s = Sha256::new();
    s.update(bytes);
    let out = s.finalize();

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    Hash32(arr)
}

fn blake3_hash32(bytes: &[u8]) -> Hash32 {
    let mut b3 = B3::new();
    b3.update(bytes);
    let out = b3.finalize();

    let mut arr = [0u8; 32];
    arr.copy_from_slice(out.as_bytes());
    Hash32(arr)
}

fn hash32_from_hex(s: &str, label: &str) -> Result<Hash32> {
    Hash32::from_hex(s).with_context(|| format!("parse {}", label))
}

fn validate_machine_id(machine_id: &str) -> Result<()> {
    if machine_id.trim().is_empty() {
        return Err(anyhow!("machine_id empty"));
    }
    Ok(())
}

fn validate_capture_interval(capture_start_unix: u64, capture_end_unix: u64) -> Result<()> {
    if capture_end_unix < capture_start_unix {
        return Err(anyhow!("capture_end_unix < capture_start_unix"));
    }
    Ok(())
}

pub fn compute_pop1_metrics_from_bytes(bytes: &[u8]) -> Pop1MetricsV1 {
    Pop1MetricsV1 {
        entropy_q32: entropy_q32(bytes),
        compression_ppm: compression_ppm(bytes),
        mad_q32: mad_q32(bytes),
    }
}

pub fn build_pop1_container_from_bytes(
    machine_id: &str,
    bytes: &[u8],
    capture_start_unix: u64,
    capture_end_unix: u64,
    prev_capture_hash: Hash32,
) -> Result<Pop1ContainerV1> {
    validate_machine_id(machine_id)?;
    validate_capture_interval(capture_start_unix, capture_end_unix)?;

    let header = Pop1HeaderV1 {
        version: POP1_VERSION_V1,
        machine_id: machine_id.to_string(),
        capture_start_unix,
        capture_end_unix,
        prev_capture_hash,
    };

    let integrity = Pop1IntegrityV1 {
        payload_size_bytes: bytes.len() as u64,
        sha256: sha256_hash32(bytes),
        blake3: blake3_hash32(bytes),
    };

    let metrics = compute_pop1_metrics_from_bytes(bytes);

    Ok(Pop1ContainerV1 {
        header,
        integrity,
        metrics,
    })
}

pub fn validate_pop1_container_basic(pop1: &Pop1ContainerV1) -> Result<()> {
    if pop1.header.version != POP1_VERSION_V1 {
        return Err(anyhow!("unsupported POP-1 version {}", pop1.header.version));
    }

    validate_machine_id(&pop1.header.machine_id)?;
    validate_capture_interval(pop1.header.capture_start_unix, pop1.header.capture_end_unix)?;

    if pop1.integrity.sha256 == Hash32::zero() {
        return Err(anyhow!("POP-1 sha256 is zero"));
    }
    if pop1.integrity.blake3 == Hash32::zero() {
        return Err(anyhow!("POP-1 blake3 is zero"));
    }

    if pop1.metrics.compression_ppm > SCORE_SCALE_PPM {
        return Err(anyhow!("POP-1 compression_ppm out of range"));
    }

    Ok(())
}

pub fn validate_pop1_container_against_bytes(pop1: &Pop1ContainerV1, bytes: &[u8]) -> Result<()> {
    validate_pop1_container_basic(pop1)?;

    let expected = build_pop1_container_from_bytes(
        &pop1.header.machine_id,
        bytes,
        pop1.header.capture_start_unix,
        pop1.header.capture_end_unix,
        pop1.header.prev_capture_hash,
    )?;

    if &expected != pop1 {
        return Err(anyhow!("POP-1 recomputation mismatch"));
    }

    Ok(())
}

pub fn encode_pop1_canonical(pop1: &Pop1ContainerV1) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + pop1.header.machine_id.len() + 8 * 6 + 32 * 3);

    out.extend_from_slice(b"POP1");
    out.extend_from_slice(&pop1.header.version.to_le_bytes());

    let machine_id_bytes = pop1.header.machine_id.as_bytes();
    out.extend_from_slice(&(machine_id_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(machine_id_bytes);

    out.extend_from_slice(&pop1.header.capture_start_unix.to_le_bytes());
    out.extend_from_slice(&pop1.header.capture_end_unix.to_le_bytes());
    out.extend_from_slice(pop1.header.prev_capture_hash.as_bytes());

    out.extend_from_slice(&pop1.integrity.payload_size_bytes.to_le_bytes());
    out.extend_from_slice(pop1.integrity.sha256.as_bytes());
    out.extend_from_slice(pop1.integrity.blake3.as_bytes());

    out.extend_from_slice(&pop1.metrics.entropy_q32.to_le_bytes());
    out.extend_from_slice(&pop1.metrics.compression_ppm.to_le_bytes());
    out.extend_from_slice(&pop1.metrics.mad_q32.to_le_bytes());

    out
}

pub fn pop1_container_hash(pop1: &Pop1ContainerV1) -> Hash32 {
    sha256_hash32(&encode_pop1_canonical(pop1))
}

pub fn derive_pop2_proof(pop1: &Pop1ContainerV1, params: &ScoringParamsV0) -> Result<Pop2ProofV1> {
    validate_pop1_container_basic(pop1)?;

    let score_u64 = score(params, &pop1.metrics);
    let mbw_u64 = raw_mbw_u64(
        score_u64,
        pop1.integrity.payload_size_bytes,
        pop1.header.capture_start_unix,
        pop1.header.capture_end_unix,
    );

    let container_hash = pop1_container_hash(pop1);

    let mut ph = Sha256::new();
    ph.update(b"POP2");
    ph.update(POP2_VERSION_V1.to_le_bytes());
    ph.update(container_hash.as_bytes());
    ph.update(pop1.header.machine_id.as_bytes());
    ph.update(pop1.header.capture_start_unix.to_le_bytes());
    ph.update(pop1.header.capture_end_unix.to_le_bytes());
    ph.update(score_u64.to_le_bytes());
    ph.update(mbw_u64.to_le_bytes());

    let proof_hash = {
        let out = ph.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&out);
        Hash32(arr)
    };

    Ok(Pop2ProofV1 {
        version: POP2_VERSION_V1,
        container_hash,
        machine_id: pop1.header.machine_id.clone(),
        capture_start_unix: pop1.header.capture_start_unix,
        capture_end_unix: pop1.header.capture_end_unix,
        score_u64,
        mbw_u64,
        proof_hash,
    })
}

pub fn validate_pop2_basic(pop2: &Pop2ProofV1) -> Result<()> {
    if pop2.version != POP2_VERSION_V1 {
        return Err(anyhow!("unsupported POP-2 version {}", pop2.version));
    }

    validate_machine_id(&pop2.machine_id)?;
    validate_capture_interval(pop2.capture_start_unix, pop2.capture_end_unix)?;

    if pop2.score_u64 > SCORE_SCALE_PPM {
        return Err(anyhow!("POP-2 score_u64 out of range"));
    }
    if pop2.mbw_u64 > MAX_MBW_U64 {
        return Err(anyhow!("POP-2 mbw_u64 out of range"));
    }
    if pop2.container_hash == Hash32::zero() {
        return Err(anyhow!("POP-2 container_hash is zero"));
    }
    if pop2.proof_hash == Hash32::zero() {
        return Err(anyhow!("POP-2 proof_hash is zero"));
    }

    Ok(())
}

pub fn validate_pop2_against_pop1(
    pop2: &Pop2ProofV1,
    pop1: &Pop1ContainerV1,
    params: &ScoringParamsV0,
) -> Result<()> {
    validate_pop2_basic(pop2)?;
    validate_pop1_container_basic(pop1)?;

    let expected = derive_pop2_proof(pop1, params)?;
    if &expected != pop2 {
        return Err(anyhow!("POP-2 recomputation mismatch"));
    }

    Ok(())
}

fn metrics_v0_from_pop1(pop1: &Pop1ContainerV1) -> MetricsV0 {
    MetricsV0 {
        bytes_len: pop1.integrity.payload_size_bytes,
        sha256_hex: pop1.integrity.sha256.to_hex(),
        blake3_hex: pop1.integrity.blake3.to_hex(),
        entropy_q32: pop1.metrics.entropy_q32,
        compression_ppm: pop1.metrics.compression_ppm,
        mad_q32: pop1.metrics.mad_q32,
    }
}

fn proof_v0_from_pop(pop1: &Pop1ContainerV1, pop2: &Pop2ProofV1) -> ProofV0 {
    ProofV0 {
        version: LEGACY_PROOF_VERSION_V0,
        machine_id: pop1.header.machine_id.clone(),
        capture_start_unix: pop1.header.capture_start_unix,
        capture_end_unix: pop1.header.capture_end_unix,
        prev_capture_hash_hex: pop1.header.prev_capture_hash.to_hex(),
        metrics: metrics_v0_from_pop1(pop1),
        score_u64: pop2.score_u64,
        mbw_u64: pop2.mbw_u64,
        proof_hash_hex: pop2.proof_hash.to_hex(),
    }
}

pub fn compute_proof_from_file(
    machine_id: &str,
    input: &Path,
    params: &ScoringParamsV0,
    capture_start_unix: u64,
    capture_end_unix: u64,
    prev_capture_hash_hex: &str,
) -> Result<ProofV0> {
    let bytes = fs::read(input).with_context(|| format!("read {}", input.display()))?;

    compute_proof_from_bytes(
        machine_id,
        &bytes,
        params,
        capture_start_unix,
        capture_end_unix,
        prev_capture_hash_hex,
    )
}

pub fn compute_proof_from_bytes(
    machine_id: &str,
    bytes: &[u8],
    params: &ScoringParamsV0,
    capture_start_unix: u64,
    capture_end_unix: u64,
    prev_capture_hash_hex: &str,
) -> Result<ProofV0> {
    let prev_capture_hash = hash32_from_hex(prev_capture_hash_hex, "prev_capture_hash_hex")?;

    let pop1 = build_pop1_container_from_bytes(
        machine_id,
        bytes,
        capture_start_unix,
        capture_end_unix,
        prev_capture_hash,
    )?;

    let pop2 = derive_pop2_proof(&pop1, params)?;

    Ok(proof_v0_from_pop(&pop1, &pop2))
}

pub fn proof_hashes_hex(proofs: &[ProofV0]) -> String {
    let mut h = Sha256::new();
    for p in proofs {
        h.update(p.proof_hash_hex.as_bytes());
    }
    hex::encode(h.finalize())
}

pub fn verify_proof_basic(p: &ProofV0) -> Result<()> {
    if p.version != LEGACY_PROOF_VERSION_V0 {
        return Err(anyhow!("unsupported proof version"));
    }

    validate_machine_id(&p.machine_id)?;
    validate_capture_interval(p.capture_start_unix, p.capture_end_unix)?;

    let prev_capture_hash = hash32_from_hex(&p.prev_capture_hash_hex, "prev_capture_hash_hex")?;
    let sha256 = hash32_from_hex(&p.metrics.sha256_hex, "metrics.sha256_hex")?;
    let blake3 = hash32_from_hex(&p.metrics.blake3_hex, "metrics.blake3_hex")?;
    let proof_hash = hash32_from_hex(&p.proof_hash_hex, "proof_hash_hex")?;

    if p.metrics.compression_ppm > SCORE_SCALE_PPM {
        return Err(anyhow!("compression_ppm out of range"));
    }
    if p.score_u64 > SCORE_SCALE_PPM {
        return Err(anyhow!("score_u64 out of range"));
    }
    if p.mbw_u64 > MAX_MBW_U64 {
        return Err(anyhow!("mbw_u64 out of range"));
    }

    let pop1 = Pop1ContainerV1 {
        header: Pop1HeaderV1 {
            version: POP1_VERSION_V1,
            machine_id: p.machine_id.clone(),
            capture_start_unix: p.capture_start_unix,
            capture_end_unix: p.capture_end_unix,
            prev_capture_hash,
        },
        integrity: Pop1IntegrityV1 {
            payload_size_bytes: p.metrics.bytes_len,
            sha256,
            blake3,
        },
        metrics: Pop1MetricsV1 {
            entropy_q32: p.metrics.entropy_q32,
            compression_ppm: p.metrics.compression_ppm,
            mad_q32: p.metrics.mad_q32,
        },
    };

    validate_pop1_container_basic(&pop1)?;

    let container_hash = pop1_container_hash(&pop1);
    let mut ph = Sha256::new();
    ph.update(b"POP2");
    ph.update(POP2_VERSION_V1.to_le_bytes());
    ph.update(container_hash.as_bytes());
    ph.update(p.machine_id.as_bytes());
    ph.update(p.capture_start_unix.to_le_bytes());
    ph.update(p.capture_end_unix.to_le_bytes());
    ph.update(p.score_u64.to_le_bytes());
    ph.update(p.mbw_u64.to_le_bytes());

    let recomputed = {
        let out = ph.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&out);
        Hash32(arr)
    };

    if proof_hash != recomputed {
        return Err(anyhow!("proof_hash_hex mismatch"));
    }

    Ok(())
}

pub fn proof_v0_to_pop1(p: &ProofV0) -> Result<Pop1ContainerV1> {
    Ok(Pop1ContainerV1 {
        header: Pop1HeaderV1 {
            version: POP1_VERSION_V1,
            machine_id: p.machine_id.clone(),
            capture_start_unix: p.capture_start_unix,
            capture_end_unix: p.capture_end_unix,
            prev_capture_hash: hash32_from_hex(&p.prev_capture_hash_hex, "prev_capture_hash_hex")?,
        },
        integrity: Pop1IntegrityV1 {
            payload_size_bytes: p.metrics.bytes_len,
            sha256: hash32_from_hex(&p.metrics.sha256_hex, "metrics.sha256_hex")?,
            blake3: hash32_from_hex(&p.metrics.blake3_hex, "metrics.blake3_hex")?,
        },
        metrics: Pop1MetricsV1 {
            entropy_q32: p.metrics.entropy_q32,
            compression_ppm: p.metrics.compression_ppm,
            mad_q32: p.metrics.mad_q32,
        },
    })
}

pub fn proof_v0_to_pop2(p: &ProofV0) -> Result<Pop2ProofV1> {
    let pop1 = proof_v0_to_pop1(p)?;
    Ok(Pop2ProofV1 {
        version: POP2_VERSION_V1,
        container_hash: pop1_container_hash(&pop1),
        machine_id: p.machine_id.clone(),
        capture_start_unix: p.capture_start_unix,
        capture_end_unix: p.capture_end_unix,
        score_u64: p.score_u64,
        mbw_u64: p.mbw_u64,
        proof_hash: hash32_from_hex(&p.proof_hash_hex, "proof_hash_hex")?,
    })
}
