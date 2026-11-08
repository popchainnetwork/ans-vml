# PopChain (popchain-cli) — L1 Kernel v0.6

PopChain is a deterministic Rust-built L1 kernel prototype designed around **Proof-of-Process (PoP)**: real-world binary captures (“BINs”) are scored into **MBW** and accumulate into chain weight, enabling fork-choice and convergence in LAN-grade deployments.

This repository (`popchain-cli`) is a **production-style kernel demo**:
- deterministic block hashing
- fork graph (tips, orphans, common ancestor, walk-back)
- persistent store with atomic writes + cross-process file locks
- NDJSON P2P sync (Hello / Inv / GetBlock / Block)
- anti-replay per `machine_id` (prev-capture link)
- slot loop demo (5s default)

> **Status:** v0.6.0 is a kernel-grade demo baseline. PQ signatures, key rotation, equivocation evidence, and mempool are planned for v0.6.x+ milestones.

---

## Build

```bash
cargo build
cargo test
