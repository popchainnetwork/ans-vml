#![forbid(unsafe_code)]

use anyhow::{anyhow, Result};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// 32-byte hash wrapper used across the system.
/// Canonical internal representation for block hashes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Hash32(pub [u8; 32]);

pub type BlockHash = Hash32;

impl Hash32 {
    pub fn zero() -> Self {
        Self([0u8; 32])
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        if s.len() != 64 {
            return Err(anyhow!("hex length must be 64"));
        }

        let bytes = hex::decode(s).map_err(|e| anyhow!("hex decode: {e}"))?;

        if bytes.len() != 32 {
            return Err(anyhow!("decoded hash must be 32 bytes"));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);

        Ok(Self(arr))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Canonical PopChain address.
///
/// Current canonical text form:
/// `pop1_<64 hex chars>`
///
/// Example:
/// `pop1_0123abcd...`
///
/// Rules:
/// - fixed `pop1_` prefix
/// - 32 raw bytes encoded as lowercase hex
/// - deterministic display
/// - serde as canonical string form
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AddressV1(pub [u8; 32]);

impl AddressV1 {
    pub const PREFIX: &'static str = "pop1_";

    pub fn zero() -> Self {
        Self([0u8; 32])
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        if s.len() != 64 {
            return Err(anyhow!("address hex length must be 64"));
        }

        let bytes = hex::decode(s).map_err(|e| anyhow!("address hex decode: {e}"))?;
        if bytes.len() != 32 {
            return Err(anyhow!("decoded address must be 32 bytes"));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn to_canonical_string(&self) -> String {
        format!("{}{}", Self::PREFIX, self.to_hex())
    }

    pub fn from_canonical_str(s: &str) -> Result<Self> {
        let hex_part = s
            .strip_prefix(Self::PREFIX)
            .ok_or_else(|| anyhow!("address must start with {}", Self::PREFIX))?;

        Self::from_hex(hex_part)
    }

    pub fn parse(s: &str) -> Result<Self> {
        if s.starts_with(Self::PREFIX) {
            Self::from_canonical_str(s)
        } else {
            Self::from_hex(s)
        }
    }

    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|b| *b == 0)
    }
}

impl fmt::Display for AddressV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_canonical_string())
    }
}

impl Serialize for AddressV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_canonical_string())
    }
}

impl<'de> Deserialize<'de> for AddressV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        AddressV1::parse(&raw).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockSignatureV1 {
    pub validator_id: String,
    pub wots_public_key_hex: String,
    pub wots_signature_hex: String,
}

/// POP-1 canonical input container header.
/// This object identifies the capture context and the process interval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pop1HeaderV1 {
    pub version: u32,
    pub machine_id: String,
    pub capture_start_unix: u64,
    pub capture_end_unix: u64,
    pub prev_capture_hash: Hash32,
}

/// POP-1 integrity section.
/// This binds the raw payload to canonical content hashes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pop1IntegrityV1 {
    pub payload_size_bytes: u64,
    pub sha256: Hash32,
    pub blake3: Hash32,
}

/// POP-1 canonical metrics section.
/// These are consensus-relevant derived measurements of the payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pop1MetricsV1 {
    pub entropy_q32: u64,
    pub compression_ppm: u64,
    pub mad_q32: u64,
}

/// POP-1 canonical container.
/// This is the canonical input object from which POP-2 proofs are derived.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pop1ContainerV1 {
    pub header: Pop1HeaderV1,
    pub integrity: Pop1IntegrityV1,
    pub metrics: Pop1MetricsV1,
}

/// POP-2 canonical proof object.
/// This references POP-1 and carries deterministic protocol-level scoring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pop2ProofV1 {
    pub version: u32,
    pub container_hash: Hash32,
    pub machine_id: String,
    pub capture_start_unix: u64,
    pub capture_end_unix: u64,
    pub score_u64: u64,
    pub mbw_u64: u64,
    pub proof_hash: Hash32,
}
