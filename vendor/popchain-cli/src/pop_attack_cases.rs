#![forbid(unsafe_code)]

use anyhow::Result;
use popchain_cli::{
    metrics::{
        build_pop1_container_from_bytes, derive_pop2_proof, proof_v0_to_pop1, proof_v0_to_pop2,
        validate_pop1_container_against_bytes, validate_pop2_basic, verify_proof_basic,
        compute_proof_from_bytes, ScoringParamsV0,
    },
    types::Hash32,
};

fn hash_a() -> Hash32 {
    Hash32::from_hex("4444444444444444444444444444444444444444444444444444444444444444")
        .expect("valid hex")
}

fn hash_b() -> Hash32 {
    Hash32::from_hex("5555555555555555555555555555555555555555555555555555555555555555")
        .expect("valid hex")
}

#[test]
fn replay_same_payload_with_different_prev_capture_hash_produces_distinct_pop1() -> Result<()> {
    let bytes = b"same-payload-replay-test-\x01\x02\x03";

    let pop1_a = build_pop1_container_from_bytes(
        "machine-replay",
        bytes,
        1_760_000_000,
        1_760_000_060,
        hash_a(),
    )?;

    let pop1_b = build_pop1_container_from_bytes(
        "machine-replay",
        bytes,
        1_760_000_000,
        1_760_000_060,
        hash_b(),
    )?;

    assert_ne!(pop1_a.header.prev_capture_hash, pop1_b.header.prev_capture_hash);
    assert_ne!(pop1_a, pop1_b);

    Ok(())
}

#[test]
fn legacy_proof_rejects_metric_spoof_attempt() -> Result<()> {
    let bytes = b"legacy-proof-metric-spoof";
    let params = ScoringParamsV0::default();

    let mut proof = compute_proof_from_bytes(
        "machine-legacy-spoof",
        bytes,
        &params,
        1_761_000_000,
        1_761_000_030,
        "6666666666666666666666666666666666666666666666666666666666666666",
    )?;

    proof.metrics.entropy_q32 = proof.metrics.entropy_q32.saturating_add(1);

    let err = verify_proof_basic(&proof).expect_err("spoofed metrics must fail");
    assert!(err.to_string().contains("proof_hash_hex mismatch"));

    Ok(())
}

#[test]
fn legacy_proof_rejects_size_inflation_attempt() -> Result<()> {
    let bytes = b"legacy-proof-size-inflation";
    let params = ScoringParamsV0::default();

    let mut proof = compute_proof_from_bytes(
        "machine-size-inflation",
        bytes,
        &params,
        1_762_000_000,
        1_762_000_090,
        "7777777777777777777777777777777777777777777777777777777777777777",
    )?;

    proof.metrics.bytes_len = proof.metrics.bytes_len.saturating_add(10_000);

    let err = verify_proof_basic(&proof).expect_err("inflated size must fail");
    assert!(err.to_string().contains("proof_hash_hex mismatch"));

    Ok(())
}

#[test]
fn legacy_proof_rejects_duration_inflation_attempt() -> Result<()> {
    let bytes = b"legacy-proof-duration-inflation";
    let params = ScoringParamsV0::default();

    let mut proof = compute_proof_from_bytes(
        "machine-duration-inflation",
        bytes,
        &params,
        1_763_000_000,
        1_763_000_010,
        "8888888888888888888888888888888888888888888888888888888888888888",
    )?;

    proof.capture_end_unix = proof.capture_end_unix.saturating_add(1_000_000);

    let err = verify_proof_basic(&proof).expect_err("inflated duration must fail");
    assert!(err.to_string().contains("proof_hash_hex mismatch"));

    Ok(())
}

#[test]
fn pop1_recomputation_rejects_payload_replacement_attack() -> Result<()> {
    let original = b"original-pop1-payload-attack-case";
    let replacement = b"replacement-pop1-payload-attack-ca";

    let pop1 = build_pop1_container_from_bytes(
        "machine-pop1-attack",
        original,
        1_764_000_000,
        1_764_000_120,
        hash_a(),
    )?;

    let err = validate_pop1_container_against_bytes(&pop1, replacement)
        .expect_err("payload replacement must fail");

    assert!(err.to_string().contains("POP-1 recomputation mismatch"));
    Ok(())
}

#[test]
fn pop2_basic_validation_rejects_zero_container_hash() -> Result<()> {
    let bytes = b"pop2-zero-container-hash";
    let params = ScoringParamsV0::default();

    let pop1 = build_pop1_container_from_bytes(
        "machine-pop2-zero-container",
        bytes,
        1_765_000_000,
        1_765_000_040,
        hash_b(),
    )?;

    let mut pop2 = derive_pop2_proof(&pop1, &params)?;
    pop2.container_hash = Hash32::zero();

    let err = validate_pop2_basic(&pop2).expect_err("zero container hash must fail");
    assert!(err.to_string().contains("POP-2 container_hash is zero"));

    Ok(())
}

#[test]
fn legacy_proof_conversion_preserves_machine_identity() -> Result<()> {
    let bytes = b"legacy-conversion-machine-identity";
    let params = ScoringParamsV0::default();

    let proof = compute_proof_from_bytes(
        "machine-conversion",
        bytes,
        &params,
        1_766_000_000,
        1_766_000_050,
        "9999999999999999999999999999999999999999999999999999999999999999",
    )?;

    let pop1 = proof_v0_to_pop1(&proof)?;
    let pop2 = proof_v0_to_pop2(&proof)?;

    assert_eq!(proof.machine_id, pop1.header.machine_id);
    assert_eq!(proof.machine_id, pop2.machine_id);

    Ok(())
}
