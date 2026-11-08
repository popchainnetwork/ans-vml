// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Paweł Piekut / Pplastechniek
//! Open primitives reused by the separately licensed product adapter.
#[allow(dead_code)] // retained bounded reference VM scaffolding
pub mod chip;
pub mod pq;
pub use ans_xmss;
pub use popchain_cli as kernel;

/// Public known-answer reference fixture, not a custodian key.
pub const XMSSMT_KAT: &str = include_str!("../vendor/ans-xmss/kat/xmssmt_sha2_20_2_256.txt");
