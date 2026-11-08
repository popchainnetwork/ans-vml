#![forbid(unsafe_code)]

use crate::types::AddressV1;
use anyhow::{anyhow, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Simple wallet structure.
///
/// For now:
/// - only address
/// - no private key persistence (intentionally)
/// - used as identity layer for balances in next steps
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletV1 {
    pub address: AddressV1,
}

impl WalletV1 {
    /// Generate new random wallet.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);

        let address = AddressV1::from_bytes(bytes);

        Self { address }
    }

    /// Create wallet from existing address string.
    pub fn from_address_str(s: &str) -> Result<Self> {
        let addr = AddressV1::parse(s)?;
        Ok(Self { address: addr })
    }

    /// Return canonical string form.
    pub fn address_string(&self) -> String {
        self.address.to_string()
    }

    /// Basic sanity check.
    pub fn validate(&self) -> Result<()> {
        if self.address.is_zero() {
            return Err(anyhow!("wallet address cannot be zero"));
        }
        Ok(())
    }
}
