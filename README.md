<!-- SPDX-License-Identifier: Apache-2.0 -->
# ANS VML — experimental Rust dictionary runtime

Copyright 2026 Paweł Piekut / Pplastechniek.

**Real CLI and local prototype, not a production OS, hardware VM, public mesh or payment service.**
ANS VML reuses the ANS dictionary crate, local custodian journal and PopChain database projection. It reads content-addressed word/letter crystals, checks SHA3 Merkle roots, and exposes dictionary operations over CLI and local MCP stdio. This baseline is the existing core, not the finished transactional dictionary writer.

## Build and test

Linux x86_64 was the baseline build platform. Install a Rust toolchain and C linker using their official instructions. The exact minimum supported Rust/glibc version is not established. Cargo downloads locked registry dependencies; the three local crates are included. No account, fee, Pro module or production key is needed.

```sh
export CARGO_HOME="$(mktemp -d)"
export CARGO_TARGET_DIR="$(mktemp -d)"
cargo build --release --locked -j2
cargo test --release --locked -j2
ANS="$CARGO_TARGET_DIR/release/ans"
"$ANS" --help
```

## First demonstration — no signing or payments

After building, use a fresh temporary directory, never your existing identity directory:

```sh
export ANS_HOME="$(mktemp -d)"
"$ANS" book seed
"$ANS" word rdzeń --crystal
"$ANS" word rdzeń --lang pl
"$ANS" book list
# This refusal is intentional: imported content is not an authorized executable.
if "$ANS" run hash abc; then
  echo 'ERROR: expected refusal' >&2; exit 1
fi
```

`book seed` installs the finite sample data, not all languages and not a private seed. It does not mint. The pinned rdzeń root is `a8e5657614f0a4721d298b03d9f897bc64e3c4937059ea7a3393b90367a20b52`. A Merkle root binds leaf bytes, not linguistic truth. Wrapper metadata is not root-bound.

## MCP

Configure an MCP-capable local client to run the absolute path to `ans mcp` with an `ANS_HOME` environment pointing at its isolated demo directory. Transport is stdio. Tools include `word`, `list_words`, `mint_request`, `run_plan`, `run`; a mint request is not a signature or automatic approval. The integration test `tests/mcp_words.rs` exercises initialization, tool listing, lookup and unminted-run refusal. No model is bundled, loaded or remotely connected by this project.

## Local minting and boundaries

The inherited CLI also has `init`, `alphabet mint`, `mint`, `delegate`, `revoke` and `run` paths. Signing must use fresh disposable test identities only. Existing tests exercise local journal/rule behavior; do not import production identities. Linux processes and localhost services are not hardware-isolated VMs. Local signatures authenticate bytes under keys, not their truth or legal ownership.

Known limitations before a secure public service:
- XMSSMT is stateful. The current journal/counter does not establish multi-process locking or protection against restoring both counter and journal. Never clone a signing identity between nodes.
- Journal append and PopChain projection are separate steps; crash recovery and operation-level idempotency need further work.
- CLI imports, sync logs and builtin runs are not yet a complete mandatory operation-ledger service. Draft/validated/executable lifecycle needs strengthening.
- Peer identity binding is local-demo only; no production ANS PKI, authenticated global DNS registration, hardware attestation or E2EE claim. Stored messages are plaintext.
- Remote mesh/cloud/SSH placement, BLE, Pi5/aarch64 distribution, iOS/Android, VR, live Stripe and commercial connectors are not delivered by this baseline. Offline revocation cannot be instant.
- Passing tests is not certification, a security audit, proof of consensus, NLnet funding or endorsement. No revenue is promised.

## Licenses and reference provenance

Core and copied owned ans-xmss/bxb-chip code: Apache-2.0; see `LICENSE`, `NOTICE`. PopChain remains MIT. Three.js remains MIT. Lexical data is CC-BY-SA; Unicode tables retain Unicode-3.0. Preserve `THIRD_PARTY`, `assets/third-party.txt`, `assets/crystals/NOTICE-crystal.md`, `assets/crystals/UNICODE-LICENSE.txt` and sidecar notices. Public KAT fixture provenance is in `vendor/ans-xmss/kat/SOURCE.txt`; deterministic reference fixtures must never become production secrets.

Only the reviewed core is exported. No Pro, private state, identities, backups or user keys are included. The proprietary commercial layer is not licensed by this repository. Paid support/integration, if separately agreed, does not restrict Apache rights.

Related references: https://bitxbit.io/ and its linked profile https://x.com/encodenote . `assets/gen002-reference.json` contains public NOTE/GEN002 reference metadata. No exact X post or cryptographic binding between that NOTE and the website has been verified. These links are context, not deployment endpoints for this CLI.

## Baseline verification

On Linux x86_64 with rustc 1.99.1, the locked release build succeeded and the standalone workspace test command passed 17 tests (0 failures, 0 ignored). Coverage includes pinned roots, tampering, UCD forms, reproducible import, local rule/mint/delegation/revocation behavior, localhost two-book sync, and MCP lookup/refusal. Vendored cryptography is not independently certified by this count.

A fresh-directory CLI smoke confirmed `book seed` returns `minted: false`, the pinned word root matches, `book list` contains seven sample crystals, and `run hash abc` exits 1 with `letter 'h' (U+0068) is not minted`. This smoke creates no signing identity. It does not establish global mesh, a payment product or production signing safety.
