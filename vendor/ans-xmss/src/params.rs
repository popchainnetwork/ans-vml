// SPDX-License-Identifier: Apache-2.0
// Product-copy relicensing authorised by Paweł Piekut / Pplastechniek, 2026-11-08.
//! XMSS-SHA2_10_256 — SP 800-208 / RFC 8391.
//! n=32, w=16, len=67, h=10. Not a toy height.

pub const N: usize = 32;
pub const W: usize = 16;
pub const LOG_W: usize = 4;
pub const LEN1: usize = 64;
pub const LEN2: usize = 3;
pub const LEN: usize = 67;
pub const H: usize = 10;
pub const LEAVES: usize = 1 << H;

pub const PARAM_NAME: &str = "XMSS-SHA2_10_256";

pub type NBytes = [u8; N];
