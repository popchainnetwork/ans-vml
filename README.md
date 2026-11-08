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

`book seed` installs the finite sample data, not all languages and not a private seed. It does not mint. The pinned rdzeń root is `a8e5657614f0a4721d298b03d9f897bc64e3c4937059ea7a3393b90367a20b52`. A Merkle root binds leaf bytes, not linguistic truth. Wrapper identity must match a single root-bound identity leaf; an identity-level schema, when present, must match the wrapper schema. Legacy identities without a schema do not independently bind their type; the signed lifecycle snapshot and cache comparison preserve the accepted type.

## Read-only dictionary browsing and public dependency proofs

No request JSON, identity initialization or signer is needed to browse imported
content. These commands never repair a cache, create configuration, reserve a key
index, or append to the journal:

```sh
"$ANS" dictionary list
"$ANS" dictionary show rdzen
"$ANS" word rdzen --lang en
"$ANS" book list
```

`cache_only_imported` means Merkle-checked content, **not a lifecycle or mint**.
With an explicit existing custodian, the reader verifies its public journal and
PopChain payload commitments and independently checks the signed lifecycle path:

```sh
"$ANS" --as alice dictionary list
"$ANS" --as alice dictionary show r
# EXPECTED_PK must come independently from the custodian you intend to trust.
# Do not trust a key merely because it appears in a downloaded proof or list.
"$ANS" --as alice dictionary show r --expect-key "$EXPECTED_PK"
"$ANS" --as alice dictionary export r --expect-key "$EXPECTED_PK" > r.proof.json
# Can run on a separate machine with only ans, this public file and the anchor:
"$ANS" dictionary verify r.proof.json --expect-key "$EXPECTED_PK"
```

Export/verification supports minted **characters and words with a minimal public
character-dependency closure under the same expected signer**. Each required
lowercased character must have a verified Draft → Validated → Minted lifecycle
completed before the word-mint intent, with its exact native mint sequence and root.
The existing native `letters_of` rule determines character order, repeated letters
and pinned `character_reference` roots; it is not replaced by an ad-hoc spelling
rule. The native word event must match the exact ordered character/root/block list,
word identity, root, filename, layer and operation. Both writer admission/replay and
public reading use the same strict semantic engine and public kernel commitment
checks. Invalid signed receipts or incomplete/mismatched dependencies fail closed.
Imported content can still be viewed without `--as`. Legacy/peer native mint claims
alone are not promoted to verified lifecycle state or word dependencies. Existing `book list`/MCP `list_words` response keys are retained,
but `minted_block` now means an independently checked lifecycle native mint;
cache-only/legacy claims remain null. An absent node ID stays null rather than
being created by a read. CLI/MCP word lookup keeps form/translation folding and
exposes provenance. Legacy JSON fallback is explicitly unsigned/unverified.

The reader does not open a signer or PopChain database. It reads public files
only: the journal, kernel state/height index/block files, and cache crystals.
It works without signer seed/counter files and while a writer lock is held, if
journal/projection bytes are stable for the read. An in-flight append, incomplete
operation/projection, ambiguous block height, or inconsistent tip produces a
snapshot/retry error, never cache repair or a guessed state. This is a stable
local snapshot, not a promise of latest state after the read returns.

A character proof contains its three selected intent/outcome pairs and native mint
event. A word proof additionally includes that same seven-event path for each
unique required character, in original sequence order. Repeated characters share
a dependency path while retaining every ordered position in the native word event.
Only relevant accepted lifecycle paths, their public single-event blocks and the
target entry are included; rejected/retried attempts and unrelated entries are not
exported. The pinned `rdzeń` fixture needs five characters and produces 42 selected
events, not merely a character proof labeled as a word proof. Whole signed
envelopes necessarily include selected crystal fields, timestamps and source
metadata; review them before sharing. No unrelated journal records, seed files or
signer counter files are exported. Secrets accidentally embedded in the selected
content/metadata cannot be redacted while preserving its original signature.

Verification checks the external signer anchor, XMSSMT/WOTS+ signatures and index
metadata, identity/schema/leaves/root, exact command/intent linkage, ordered
Draft → Validated → Minted transitions, exactly one native mint per selected entry,
prior completed character dependencies, and block payload commitments/references. It rejects omitted native mints, duplicate effects,
reordering, changed content/signatures and wrong anchors. A selective dependency proof attests
a path **at its signed sequence**, not complete/latest history, absence of later
conflicts, global name ownership, consensus or linguistic truth. Outer blocks are
not authenticated by the event signer: commitment checks are not an outer-block
signature or independent proof of public-chain placement. No execution permission
is enabled.

## Local read-only visitor UI

The visitor is a separate loopback-only mode, **not** the legacy `ans up` web
runtime. It never opens an identity, signer, runtime configuration, cache or raw
journal. Supply one reviewed exported public proof and its independently expected
signer key:

```sh
"$ANS" dictionary serve rdzen.proof.json --expect-key "$EXPECTED_PK" --port 37121
# Open http://127.0.0.1:37121/ in a browser on the same machine.
# Stop with Ctrl-C. Startup prints the exact process PID and loopback URL.
```

The default port is 37121. Binding is hard-coded to `127.0.0.1`; there is no public
bind flag. A missing, invalid or wrong-signer proof aborts startup, with no fallback
sample data. Verification uses the shared Rust reader/protocol engine. Startup
loads a single immutable public snapshot into memory. Editing the file later does
not change the running snapshot; stop, review and restart explicitly.

The English black/gold phone-responsive explorer shows the actual selected word
and character entries, minted state, language, content roots, ordered dependencies,
native block/event references, signed outcome sequences, and the pinned signer.
Expandable technical details include source leaves. Search and character links
inspect real entries; no mint, run, microphone, payment or invented live activity
controls are present. This mode accepts verified minted proofs only: imported and
draft entries are not loaded or mislabeled as minted. Selected proof source and
timestamp metadata remain public in downloads; review them before sharing.

Only these GET routes exist: `/`, `/app.css`, `/app.js`, `/favicon.svg`,
`/api/entries`, `/api/entry/CONTENT_ROOT`, `/api/verification`, `/proof.json`.
The proof download is normalized public proof JSON, not a directory/file-serving
endpoint. Other paths return 404; traversal, malformed/oversized requests, request
bodies, non-loopback Host/foreign Origin and non-GET methods are refused. In
particular, POST `/api/exploit` is unavailable. Request headers are limited to
8192 bytes, sockets have bounded timeouts, and responses close the connection.
CSP, nosniff, no-referrer, same-origin resource policy and frame denial are set.
Assets are embedded locally; there are no CDN scripts, analytics or external
fonts. Dictionary strings use DOM text nodes, never HTML interpolation.

The HTTP tests exercise real verified character and pinned-word proofs, list and
entry results, proof download, security headers, POST/unknown/traversal/oversized
request refusal and unchanged public input bytes. These are protocol/source tests,
not a claim that a browser layout or phone screenshot has been visually checked.
Do not expose the older mutation-capable web runtime as this visitor service.

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

## Friendly owner commands — no handwritten request JSON

Owner commands explicitly sign intent/outcome events using an existing selected
local test custodian. They use the **same typed apply engine**, transaction lock,
strict replay, native mint events and operation-ID rules as `dictionary apply`.
There is no second ledger or signing engine.

```sh
"$ANS" dictionary --help
"$ANS" --as alice dictionary draft assets/crystals/rdzen.crystal.json --operation-id word-draft
"$ANS" --as alice dictionary validate rdzen --operation-id word-validate
"$ANS" --as alice dictionary mint rdzen --operation-id word-mint
"$ANS" --as alice dictionary inspect rdzen
```

The short example assumes its character dependencies are already minted; use the
complete fresh bootstrap below when starting from nothing.

Draft reads one regular crystal file (at most 8 MiB), checks its Merkle root and
root-bound identity, and derives the spelling/language from that identity. It stays
Draft; validation and mint remain separate explicit steps. Invalid files/arguments
are rejected before signing or identity creation. Queries accept a word, character,
translation/form or exact content root; ambiguous names require a root. Resolution
runs against the authoritative lifecycle **after recovery**, never a cache-only
claim. Unknown literal roots can receive signed rejection receipts; unknown names
fail before new admission because no unique command root can be prepared.

Omitting `--operation-id` generates a fresh 128-bit OS-random `cli-…` ID, printed
in `op_id`. Keep it to retry exactly that operation. Same ID + same typed command
returns the original receipt without repeating effects; a different command is a
signed rejection. A retry can show an old Draft receipt after the entry has since
minted: use read-only `show` for current state. As with the existing apply engine,
exit 0 means the invocation was admitted; **check `receipt.status` for acceptance**.
Pre-admission parse/signer errors exit nonzero. Public signatures/keys are included
for verification; secret seed/counter data is never printed.

`inspect` is an owner operation and signs a receipt. `show`, `list`, `export`,
`verify` and the isolated `serve` mode remain read-only and never open a signer.
Mint does not enable execution. The legacy top-level `ans mint`, `mint-alphabet`,
`delegate`, `run`, and related mutation paths have not been silently redefined or
migrated; do not use them as substitutes for this lifecycle walkthrough.

### Fresh disposable bootstrap and the native rdzeń flow

From the repository root after building, this uses only direct commands and public
fixtures. The loop is the finite five-character demo alphabet needed by `rdzeń`,
not a claim to mint all languages or the entire Unicode alphabet. No JSON request
file or private identity import is needed.

```sh
export ANS_HOME="$(mktemp -d)"
export ANS_WEB_PORT=43170
"$ANS" init alice
"$ANS" --as alice dictionary draft assets/crystals/rdzen.crystal.json --operation-id word-draft
"$ANS" --as alice dictionary validate rdzen --operation-id word-validate
# Expected signed rejection: its characters have not yet completed their lifecycles.
"$ANS" --as alice dictionary mint rdzen --operation-id word-before-letters
for spec in r:u0072 d:u0064 z:u007a e:u0065 ń:u0144; do
  character="${spec%%:*}"
  file="${spec#*:}"
  "$ANS" --as alice dictionary draft "assets/crystals/$file.crystal.json" --operation-id "$file-draft"
  "$ANS" --as alice dictionary validate "$character" --operation-id "$file-validate"
  "$ANS" --as alice dictionary mint "$character" --operation-id "$file-mint"
done
"$ANS" --as alice dictionary mint rdzen --operation-id word-mint
"$ANS" --as alice dictionary inspect rdzen
# Exact retry: same original receipt, no second word mint.
"$ANS" --as alice dictionary mint rdzen --operation-id word-mint
"$ANS" --as alice dictionary show rdzen
"$ANS" --as alice dictionary list
# Pin the independently obtained public signer key before exporting/verifying.
"$ANS" --as alice dictionary export rdzen --expect-key "$EXPECTED_PK" > rdzen.proof.json
"$ANS" dictionary verify rdzen.proof.json --expect-key "$EXPECTED_PK"
```

The pinned word root remains
`a8e5657614f0a4721d298b03d9f897bc64e3c4937059ea7a3393b90367a20b52`.
All five character roots are unchanged. This bootstraps only a disposable local
experimental custodian; it is not production XMSS backup/rollback safety.

## Offline dictionary lifecycle service

`ans --as alice dictionary apply REQUEST.json` remains the advanced typed service entry point; the friendly commands above prepare that same request type. Use a fresh test directory and stop `ans up` before offline writes. An existing local test custodian is required; the service does not initialize one. Do not use real identities or restore old signing state.

An admitted operation is a parseable request with a 1–128 byte `op_id` and an available, explicitly named custodian. JSON/schema errors, unavailable identities, lock contention and canonical outcomes without matching preceding intents fail before admission because no safe signer is available; these are not claimed to have ledger receipts. Every admitted invocation, including rejection, inspection and retry, records a signed `dictionary.intent` and `dictionary.outcome` through the existing journal/PopChain projection. Receipt status, not process exit 0, determines domain acceptance. Responses include the signed outcome event, binding the intent hash, command digest and receipt; signature validity does not prove factual truth.

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

Same ID + same command replays the original receipt while recording a new attempt; same ID + a different command is rejected. A new ID does not authorize repeating a mint. If a canonical first intent lacks a durable outcome on restart, it is closed as `interrupted`, not resumed. An unfinished same-command retry instead receives the completed original receipt (Accepted, Rejected or Interrupted); an unfinished conflicting retry is Rejected. Recovery validates the original completed prefix and never repeats native effects. Already-signed incompatible historical recovery outcomes are not rewritten or automatically repaired; strict replay still refuses them. If a native mint reached the journal before a crash, the service refuses automatic reconciliation or another mint: manual test-state review is required. No claim of atomicity between journal and kernel, backup rollback resistance or external exactly-once effects is made.

Accepted entry state is replayed from signed outcomes. Writer admission and public snapshots now share strict semantic replay: accepted receipt state is independently re-evaluated against command/intent linkage, immutable content, legal transitions and exact native mint effects. Word dependencies must already be verified minted in the same custodian history before the word-mint intent. Legacy signed receipts that lack these dependencies are refused, not silently migrated or granted authority. The service emits linked native mint/outcome events; tests verify their XMSSMT/WOTS+ signatures and exact PopChain application payload binding. The outer PopChain block is not separately signed by this writer. Do not expose generic legacy signed-event admission as a lifecycle bypass.

Book files are a rebuildable cache; missing files are restored on subsequent admitted operations. Existing files must match the signed snapshot's identity, type and root, and reads must match the requested filename. Same-root wrapper identity/schema corruption fails closed: inspection receives a signed rejection and `book list` refuses the corrupt cache. Damaged files are not silently overwritten; preserve for diagnosis, then explicitly remove a damaged test cache file so the next operation can rebuild it from the signed snapshot.

MCP `dictionary_propose` parses the **same Request type** and returns an unsigned, unexecuted envelope for explicit custodian CLI review. It never invokes the signer or silently approves a model request. Existing lookup/planning tools are retained.

All new documentation is English. Existing inherited localized messages are not broadly rewritten. Stripe remains deferred until product testing; no Stripe integration is included.

### Read-only increment verification

The locked release build and workspace suite pass 30 tests (0 failures). Reader
tests include anchored public-only proof verification, signed but invalid state
transitions/native effects, duplicates, content/signature/block tampering, missing
cache without repair and incomplete projections. Byte-for-byte snapshot assertions
run after signer files are removed and the existing writer lock is held. A CLI/MCP
smoke browses seven public fixtures, verifies a seven-event character proof in a
separate public-only directory, rejects a wrong anchor and creates no missing data
directory during read-only startup. These checks are not a cryptographic audit.

### Word dependency proof increment

The existing pinned `rdzeń` word and five pinned Unicode character roots are admitted
by the native protocol unchanged. A typed word mint before the characters is rejected;
after their verified lifecycles complete, its native layer-2 mint records the ordered
`r`, `d`, `z`, `e`, `ń` roots and native block sequences. Public `dictionary show rdzen`,
`dictionary export rdzen --expect-key HEX` and standalone `dictionary verify` need
no signer files. Word proofs use `ans-word-dependency-path-v1`; existing character
proofs retain `ans-character-path-v1`. All selected paths must use the one externally
expected signer; cross-custodian/peer dependency certification is not implemented.
Export is a snapshot attestation, not proof that later competing history cannot exist.

Verification for this increment: the locked release build succeeds and the workspace
suite passes **32 tests**, preserving all previous 30. The pinned-word test covers
pre-dependency rejection, five real character lifecycles, the native word mint,
retry/duplicate refusal, 42-event closure export, omitted/altered dependency failures,
wrong anchors, native payload tampering, and byte-identical public-only verification
with signer files removed and the writer lock held. Another test records genuinely
signed word-mint receipts before later character lifecycles and confirms both the
reader and writer reject that history without a new admitted operation.

### Visitor increment verification

The locked release build succeeds and the workspace passes **35 tests**, preserving
all previous 32. Existing real character/word lifecycle tests now also exercise the
visitor through TCP: list/detail/verification routes, normalized proof download,
embedded assets, security headers, blocked POST/unknown/private-file/traversal and
oversized requests, wrong anchors and unchanged public input bytes. Additional
parser/source tests cover rebinding/cross-origin/body refusal and safe local DOM
rendering. `node --check assets/dictionary-visitor.js` succeeds. These checks do not
replace the separately pending browser/phone visual review.

### Owner CLI and recovery increment verification

Locked release build succeeds and **39 tests pass**, preserving all previous 35.
New tests cover direct owner lifecycle commands, early mint refusal, retry/conflict
receipts, OS-random unique IDs, malformed arguments/files and absent signers without
identity creation, read-only invariance, and the interrupted-retry regression.

The retry contradiction was actually reproduced on baseline `7c5abed`: unfinished
noncanonical accepted/rejected retries recovered as Interrupted, then strict replay
refused their changed receipts; an unfinished conflicting retry likewise recovered
incorrectly. The fix was exercised on fresh signed intent-only crash prefixes in
separate CLI processes: exact retries preserve their Accepted/Rejected original
receipts, conflicting retries become Rejected, subsequent operations work, and native
mint counts do not change. A rejected original remains rejected even after its entry
later becomes minted. Canonical first-attempt interruption remains conservative.

A separate fresh bootstrap smoke uses zero JSON request files: direct commands mint
the five pinned characters and `rdzeń`, reject early mint/conflicting IDs, replay
exact IDs, print distinct automatic IDs and export a 42-event word proof that verifies
with five dependencies. Read-only commands work with signer files removed and writer
lock held, leaving files byte-identical. No visitor/networking change is included.
