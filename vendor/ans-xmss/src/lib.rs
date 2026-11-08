// SPDX-License-Identifier: Apache-2.0
// Product-copy relicensing authorised by Paweł Piekut / Pplastechniek, 2026-11-08.
//! ans-xmss: XMSS-SHA2_10_256 per RFC 8391 / NIST SP 800-208.
//! Ported from bxb-xmss (grok-team/bitxbit-l0), validated by the official IETF vectors.
//! No BLAKE3 inside XMSS: standard parameter set only.
#![forbid(unsafe_code)]

pub mod adrs;
pub mod hash;
pub mod kat;
pub mod keystore;
pub mod params;
pub mod wots;
pub mod xmss;
pub mod xmssmt;

pub use keystore::{MtStatefulSigner, Reservation, Scheme, Stateful, StatefulSigner, StoreError, Xmss, XmssMt};
pub use xmssmt::{mt_keygen, mt_keygen_from_seed, mt_verify, MtPk, MtSig, MtSk, MT_LIMIT, MT_OID, MT_PK_BYTES, MT_SIG_BYTES};
pub use params::PARAM_NAME;
pub use xmss::{keygen, keygen_from_seed, verify, TreeCache, XmssError, XmssPk, XmssSig, XmssSk, INDEX_BYTES, OID, PK_BYTES, SIG_BYTES};
/// Stateless reference signer (mutates sk.idx in memory only). Prefer StatefulSigner.
pub use xmss::sign as sign_in_memory;
