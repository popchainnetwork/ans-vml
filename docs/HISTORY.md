# Dictionary lifecycle evolution history

Chronological archive of every commit on `feat/dictionary-lifecycle` since it
diverged from `main` (`414a8e7` — Publish tested standalone ANS VML experimental
core baseline). Times below are Europe/Amsterdam (UTC+1). Authors are as recorded
in git.

This file documents evolution only. It does not claim production readiness,
mainnet readiness, audit completeness, or income. Existing docs (`README.md`,
`MAINNET-READINESS.md`, `LICENSE`, `NOTICE`, `THIRD_PARTY`) are left unchanged.

## Archive tags (immutable snapshots)

| Tag | Points at | Meaning |
|---|---|---|
| `archive/main-before-pr1` | `414a8e702d4811c546a4d0c69fcb87af136ec1a7` | `main` tip before PR #1 merge |
| `archive/pre-merge-dictionary-lifecycle` | `c5bfeff55c711ec98489d8a7650a5178f53b4e93` | Full branch history tip before PR #1 merge |

PR: https://github.com/popchainnetwork/ans-vml/pull/1

## Phase 1 — Initial lifecycle (draft / validate / mint / inspect)

| When (Europe/Amsterdam) | Hash | What changed | Tests (when known) |
|---|---|---|---|
| 2026-11-09 00:05 | `4938f07` | Journal-backed offline dictionary lifecycle and signed receipts. First draft→validate→mint→inspect path with operation IDs and typed receipts. | 22 PASS |

## Phase 2 — Review and cache / identity fix

| When (Europe/Amsterdam) | Hash | What changed | Tests (when known) |
|---|---|---|---|
| 2026-11-09 00:16 | `c085e1d` | Reject same-root cache identity spoofing and unbound outcomes. Intent/outcome binding hardened; cache cannot treat a colliding root as authority. | 26 PASS |

## Phase 3 — Reader, export, verify

| When (Europe/Amsterdam) | Hash | What changed | Tests (when known) |
|---|---|---|---|
| 2026-11-09 00:27 | `d721815` | Public dictionary snapshots and anchored character path proofs. Read-only list/show plus export/verify with an external expect-key; no signer required for reads. | 30 PASS |

## Phase 4 — Word proofs and strict replay

| When (Europe/Amsterdam) | Hash | What changed | Tests (when known) |
|---|---|---|---|
| 2026-11-09 00:35 | `a5d2351` | Verify word dependency closures and share strict replay with the writer. Independent word/letter proofs; offline verified core. | 32 PASS |

## Phase 5 — Visitor page (first loopback demo)

| When (Europe/Amsterdam) | Hash | What changed | Tests (when known) |
|---|---|---|---|
| 2026-11-09 00:42 | `7c5abed` | Isolated read-only Genesis proof visitor on loopback (`dictionary_web`, HTML/CSS/JS assets). | — |

## Phase 6 — Owner CLI and interrupted retry recovery

| When (Europe/Amsterdam) | Hash | What changed | Tests (when known) |
|---|---|---|---|
| 2026-11-09 00:56 | `6277ce2` | Fix interrupted retry recovery and add friendly dictionary owner commands (draft/validate/mint without hand-written JSON). | 39 PASS |

## Phase 7 — Authoring (characters and words without JSON)

| When (Europe/Amsterdam) | Hash | What changed | Tests (when known) |
|---|---|---|---|
| 2026-11-09 01:09 | `511dd9b` | CLI dictionary write authoring for new words and characters. Root-bound crystals from explicit text; draft via typed apply; validate/mint stay separate. Multilingual collision explicitly rejected. | 40 PASS |

## Phase 8 — Legacy migration: mint / mint-alphabet

| When (Europe/Amsterdam) | Hash | What changed | Tests (when known) |
|---|---|---|---|
| 2026-11-09 03:18 | `cc31483` | Route legacy `mint` CLI through the typed dictionary lifecycle. Book/UCD crystals adopt draft→validate→mint with deterministic legacy operation IDs so `ans mint` shares one ledger and native mint path. | 41 PASS |

## Phase 9 — Signer locks and crash recovery

| When (Europe/Amsterdam) | Hash | What changed | Tests (when known) |
|---|---|---|---|
| 2026-11-09 03:30 | `0192b26` | Harden dictionary mint recovery and document signer lock scope. Recover accepted lifecycle when native `word.mint` for the same `op_id` is already durable; serialize writers with `dictionary.lock`; keep XMSS indices unique under `writer.lock`. Does **not** claim power-loss atomicity. | 44 PASS |
| 2026-11-09 03:44 | `c80b9d9` | Refuse interleaved legacy writes and retry legacy mint after dependency rejection. Block unrelated signed mutations while a dictionary intent lacks its outcome so intent→native→outcome stays contiguous; recovery fails closed if foreign events already interleaved. Attempt-scoped IDs after rejected/interrupted attempts. | — |
| 2026-11-09 03:50 | `c0c5077` | Enforce dictionary pending gate at the `Exploit::record` choke point (local CLI and online `/api` paths). Dictionary intent/outcome and in-flight `word.mint` still proceed for recovery. Online-style contact/login/skill.list regression added. | — |
| 2026-11-09 04:01 | `b859a2f` | Attempt-scope all legacy draft/validate/mint IDs after interrupt (`legacy-{stage}-{root}-retry-{seq}`). Explicit dictionary `--operation-id` semantics stay receipt-stable. | 50 PASS |

## Phase 10 — Visitor product page (mobile + pixel restyle)

| When (Europe/Amsterdam) | Hash | What changed | Tests (when known) |
|---|---|---|---|
| 2026-11-09 07:39 | `66ea7ad` | Mobile-first visitor product page with proof verifier and package download. `POST /api/verify` (stateless, JSON only, 8 MiB); `/api/package` and `/download/package.tar.gz` via `--package` with `.sha256` match at startup; `/manifest.webmanifest`; `tools/visitor_mobile_check.py`. | 51 PASS |
| 2026-11-09 12:45 | `3466377` | Visitor page pixel/terminal style matching the bitxbit.io homepage (`#03020a`, cyan/magenta, monospace, canvas pixel starfield respecting reduced motion, 16×16 pixel crystal logo, boot-log from real server status). Dark only. Functionality and honesty banner unchanged. | 51 PASS |

## Phase 11 — Meaning / delegate / revoke migration and run gating

| When (Europe/Amsterdam) | Hash | What changed | Tests (when known) |
|---|---|---|---|
| 2026-11-09 15:39 | `4bf4865` | Route `mint-meaning` / `delegate` / `revoke` through typed dictionary lifecycle (`word.meaning` / `word.delegate` / `word.revoke`); fail closed on `run` / `skill_run`. Grant counter `-g0`, `-g1`, …; crash recovery mirrors mint. `ans run` / MCP run require a minted lifecycle and an active dictionary delegation; `skill_run` disabled on CLI, MCP and `/api/exploit`. | — |

## Phase 12 — Network profiles and mainnet rehearsal (signing still compiled out)

| When (Europe/Amsterdam) | Hash | What changed | Tests (when known) |
|---|---|---|---|
| 2026-11-09 15:55 | `3ee46a0` | Mainnet readiness: signed network profiles (`devnet` / `testnet` / `rehearsal` / `mainnet`), protected-profile gates (`--network` / `--confirm-network` / `--custodian-key`), local rehearsal (`tools/mainnet-rehearsal.sh`, `tests/network_profiles.rs`). `MAINNET_SIGNING_ENABLED = false`. Adds `MAINNET-READINESS.md`. | — |

## Phase 13 — Review P3 fixes (pre-merge tip)

| When (Europe/Amsterdam) | Hash | What changed | Tests (when known) |
|---|---|---|---|
| 2026-11-09 16:24 | `c5bfeff` | Review P3 fixes: refuse repeated global flags; guard init over protected dirs; report signed network on legacy commands; translate Polish runtime/UI strings to English (test-guarded). | 60 PASS (full suite on this tip before merge) |

## Known limits / not done

Recorded from `MAINNET-READINESS.md`, commit messages, and the pre-merge tip. Not invented:

- **Not ready for mainnet.** `MAINNET_SIGNING_ENABLED = false` in `src/network.rs`. No mainnet event has been signed.
- **No independent security audit** of XMSSMT/WOTS+, stateful signer, replay engine, or gates.
- **No power-loss durability guarantee.** Process exit/SIGKILL after `sync_data` is tested; power loss, disk write caches, partial writes, and restore-from-copied-backup are not. Reusing XMSS state after a bad restore can reuse one-time leaves.
- **No key ceremony** designed (offline generation, escrow, rotation, revocation, HSM).
- **No real key generator** for testnet/mainnet (only `network throwaway-key` for rehearsal).
- **No multi-custodian / consensus**; outer PopChain blocks are not separately signed.
- **No global naming authority** claim; proofs show one expected key signed a path.
- **No ARM64 / Raspberry Pi build** tested (Linux x86_64 only so far).
- **No monitoring / alerting** for signer state or index exhaustion.
- **Payments (Stripe)** out of scope; scheduled last, after product tests.
- **Not yet in the dictionary lifecycle:** exploit chat/contact paths beyond the pending gate, skill install/add/remove, and `grow_record` (and related non-dictionary signed mutations) are still outside typed dictionary commands — only gated or refused where the commits above say so.
- **No public deploy** to bitxbit.io or any cloud from this archive step.

## License / CLA / notice files

Unchanged by this history commit: `LICENSE`, `NOTICE`, `THIRD_PARTY`, and crystal notices under `assets/`. Do not delete or rewrite them when extending this log.
