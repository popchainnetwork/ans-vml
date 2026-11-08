// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Paweł Piekut / Pplastechniek
//! Pluggable signer interface. Only XMSSMT is implemented; future algorithms fail closed.
use ans_xmss::{mt_verify, MtPk, MtSig, MtStatefulSigner};
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
pub struct Signature {
    pub idx: u64,
    pub bytes: Vec<u8>,
}
impl Signature {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}
pub trait PqSigner: Send {
    fn scheme(&self) -> &'static str;
    fn sign(&mut self, message: &[u8]) -> Result<Signature>;
}
pub struct XmssMtSigner(pub MtStatefulSigner);
impl PqSigner for XmssMtSigner {
    fn scheme(&self) -> &'static str {
        "XMSSMT-SHA2_20/2_256 (WOTS+)"
    }
    fn sign(&mut self, message: &[u8]) -> Result<Signature> {
        let s = self.0.sign(message)?;
        Ok(Signature {
            idx: s.idx,
            bytes: s.to_bytes(),
        })
    }
}
pub fn verify(scheme: &str, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool> {
    if !scheme.starts_with("XMSSMT-SHA2_20/2_256") {
        return Err(anyhow!(
            "Unsupported PQ scheme; SLH-DSA/ML-DSA adapters are not implemented"
        ));
    }
    let pk = MtPk::from_bytes(pk).map_err(|_| anyhow!("public key"))?;
    let sig = MtSig::from_bytes(sig).map_err(|_| anyhow!("signature"))?;
    Ok(mt_verify(&pk, msg, &sig))
}
pub fn schemes() -> Value {
    json!([{"scheme":"XMSSMT-SHA2_20/2_256","implemented":true,"stateful":true},{"scheme":"SLH-DSA","implemented":false},{"scheme":"ML-DSA","implemented":false}])
}
