<!-- SPDX-License-Identifier: Apache-2.0 -->
# ANS VML — experimental Rust dictionary runtime

Copyright 2026 Paweł Piekut / Pplastechniek.

**Real CLI and local prototype, not a production OS, hardware VM, public mesh or payment service.**
ANS VML reuses the ANS dictionary crate, local custodian journal and PopChain database projection. It reads content-addressed word/letter crystals, checks SHA3 Merkle roots, and exposes dictionary operations over CLI and local MCP stdio. The dictionary lifecycle service adds an experimental offline draft → validate → mint flow over that same journal; it is not a finished production writer.

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
- XMSSMT is stateful. This application now holds an exclusive OS file lock while a custodian is open, and dictionary transactions have a separate cooperative lock. This does not protect direct vendor signer use, copied identity directories or restoration of both counter and journal. Never clone a signing identity between nodes.
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

## Offline dictionary lifecycle service

`ans --as alice dictionary apply REQUEST.json` is the new shared typed service entry point. Use a fresh test directory and stop `ans up` before offline writes. An existing local test custodian is required; the service does not initialize one. Do not use real identities or restore old signing state.

An admitted operation is a parseable request with a 1–128 byte `op_id` and an available, explicitly named custodian. JSON/schema errors, unavailable identities and lock contention fail before admission because no safe signer is available; these are not claimed to have ledger receipts. Every admitted invocation, including rejection, inspection and retry, records a signed `dictionary.intent` and `dictionary.outcome` through the existing journal/PopChain projection. Receipt status, not process exit 0, determines domain acceptance. Responses include the signed outcome event, binding the intent hash, command digest and receipt; signature validity does not prove factual truth.

Commands are tagged JSON: `draft` (with `word` and `crystal`), `validate`, `mint`, `inspect`, `run` (with `root`). `word` has `language` and `spelling`; root-bound identity leaves must agree. `validate` means structural checks, not factual truth or legal rights. Blank drafts can be retained but cannot validate. Asset/font adapters are not introduced; asset/font leaves fail validation rather than imply verified external bytes.

Example using the existing public character fixture (Python is only a request-file helper, not the runtime):

```sh
export ANS_HOME="$(mktemp -d)"
export ANS_WEB_PORT=37120
"$ANS" init alice
python3 - <<'PYREQ'
import json, os
from pathlib import Path
c = json.loads(Path("assets/crystals/u0072.crystal.json").read_text())
commands = {
    "draft": {"kind": "draft", "word": {"language": "und", "spelling": "r"}, "crystal": c},
    "validate": {"kind": "validate", "root": c["root"]},
    "mint": {"kind": "mint", "root": c["root"]},
    "inspect": {"kind": "inspect", "root": c["root"]},
    "run": {"kind": "run", "root": c["root"]},
}
for op, command in commands.items():
    Path(os.environ["ANS_HOME"], op + ".json").write_text(json.dumps({"op_id": op, "command": command}))
PYREQ
for op in draft validate mint inspect run; do
  "$ANS" --as alice dictionary apply "$ANS_HOME/$op.json"
done
# Exact same operation ID and command: returns its previous receipt; no second mint.
"$ANS" --as alice dictionary apply "$ANS_HOME/mint.json"
```

The first four receipts are accepted; `run` is rejected. This service intentionally has **no executable-permission approval adapter** yet: even a minted entry cannot execute through it. Legacy `ans run`/delegation remain separate older interfaces and are NOT claimed to enforce this new lifecycle. For word minting, every referenced character must already have a native mint in the same local journal. Golden word roots and fixtures remain unchanged.

Same ID + same command replays the original receipt while recording a new attempt; same ID + a different command is rejected. A new ID does not authorize repeating a mint. If an intent lacks a durable outcome on restart, it is closed as `interrupted`, not resumed. If a native mint reached the journal before a crash, the service refuses automatic reconciliation or another mint: manual test-state review is required. No claim of atomicity between journal and kernel, backup rollback resistance or external exactly-once effects is made.

Accepted entry state is replayed from signed outcomes. Book files are a rebuildable cache; missing files are restored on subsequent admitted operations, while corrupt/conflicting files fail closed rather than being overwritten.

MCP `dictionary_propose` parses the **same Request type** and returns an unsigned, unexecuted envelope for explicit custodian CLI review. It never invokes the signer or silently approves a model request. Existing lookup/planning tools are retained.

All new documentation is English. Existing inherited localized messages are not broadly rewritten. Stripe remains deferred until product testing; no Stripe integration is included.
