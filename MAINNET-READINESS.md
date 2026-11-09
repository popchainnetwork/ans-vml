# Mainnet readiness: status

**Status: not ready for mainnet.** This build is a readiness build. Mainnet signing is
compiled out (`MAINNET_SIGNING_ENABLED = false` in `src/network.rs`). No mainnet event has
been signed, no live network is used, and no real custodian key has been created or loaded.
Everything below was tested locally on one Linux x86_64 machine.

## Done in this build

| Area | What exists | Evidence |
|---|---|---|
| Network profiles | `devnet` (default local demo), `testnet`, `rehearsal` (throwaway), `mainnet`. Every new signed event carries `body.network` inside the signed body. Events written before profiles existed have no field and count as `devnet`. | `src/network.rs`, unit test `legacy_events_are_devnet_and_profiles_never_mix` |
| Cross-network refusal | A journal must use one profile. The writer refuses events whose profile differs from the custodian's. Public proofs verify only under the profile their signed events carry (`--network`, default `devnet`). Changing the field breaks the XMSSMT signature. A devnet proof is refused as rehearsal or mainnet, and the reverse. | `tests/network_profiles.rs::mainnet_rehearsal_full_flow_and_cross_network_refusal` |
| Kernel chain ID | Protected profiles use `ans-product-<owner>-417696-<network>` as the PopChain genesis ID. Devnet keeps the old `-demo` ID. | `src/exploit.rs` |
| Protected-profile gates | A non-devnet signer opens only when the same invocation passes `--network N --confirm-network N --custodian-key /abs/path`, and the key path matches the one bound at `network init`. The key must be a regular 96-byte file (no symlink), mode 0600, outside the custodian data directory, and not named like a demo key. Throwaway keys are refused on mainnet. Rehearsal accepts only throwaway keys. The test crash hook (`ANS_TEST_CRASH_AFTER` or `allow-test-crash`) is refused and never fires. Identities are never created implicitly: there is no demo key, no automatic genesis, and `ans init` refuses protected profiles. | `tests/network_profiles.rs::protected_profiles_refuse_without_every_gate` |
| Mainnet refusal | Mainnet passes the gates above and is then refused with "Mainnet signing is not enabled in this build". | same test |
| Rehearsal | `tools/mainnet-rehearsal.sh` and the integration test run the full flow on the throwaway `rehearsal` profile in a temp dir: explicit init, characters o/a/k, word oak, mint, meaning, delegate, revoke, export, and verify. They also show the rehearsal proof is refused as devnet and as mainnet. | `tools/mainnet-rehearsal.sh` |
| One ledger path | `mint`, `mint-alphabet`, `mint-meaning`, `delegate` and `revoke` all go through the typed dictionary lifecycle: signed intent, one bound native effect, outcome, strict replay, and attempt-scoped retry IDs. `run` needs a minted lifecycle and an active dictionary delegation. `skill_run` is disabled. | `src/dictionary.rs` tests |

## Missing before any mainnet use

| Item | Status |
|---|---|
| Independent security audit (XMSSMT/WOTS+ implementation, stateful signer, replay engine, gates) | **Not done.** No audit has been commissioned. |
| Power-loss durability | **Not proven.** Tests cover process exit/SIGKILL after `sync_data`. They do not cover power loss, filesystem or disk write caches, partial writes, or restoring from a copied backup. Reusing XMSS state after a restore can reuse one-time signature leaves. That is catastrophic for hash-based signatures and is not prevented. |
| Backups and key ceremony | **Not designed.** There is no documented ceremony, offline generation, escrow, rotation or revocation. There is no state-safe backup procedure for stateful XMSS keys. There is no HSM or hardware support. |
| Real key generation for testnet/mainnet | **Not implemented.** The only key generator is `network throwaway-key`, which is rehearsal-only. A mainnet key would have to come from a separate, reviewed ceremony. |
| Multi-custodian / consensus | **Not implemented.** There is one custodian per journal. Outer PopChain blocks are not separately signed. There is no validator set, finality, fork choice or peer sync for dictionary state. |
| Global naming authority | **None.** Proofs show that one expected key signed a path. They do not show global uniqueness, ownership or legal rights. |
| ARM64 / Raspberry Pi builds | **Not built or tested.** Only Linux x86_64 release builds have been tested. |
| Monitoring and alerting | **None.** There are no metrics, health checks for the signer state, alerts on index exhaustion, or log shipping. |
| Long-running services under protected profiles | **Fail closed / untested.** `ans up` (chat corridors) does not pass operator confirmation to its threads, so protected custodians do not serve there. |
| Demo key detection | **Heuristic.** It uses file name, location, permissions and the `.throwaway` marker. It does not compare the derived public key against known demo keys. |
| Asset/font verification, revisions, multilingual identities | **Not implemented.** Validation refuses these. |
| Payments (Stripe) | **Out of scope.** Not connected. Scheduled last, after product tests. |

## Operator rules (unchanged)

- Nothing from this repository is deployed. Mainnet signing stays disabled until every
  "Missing" row is closed and an operator explicitly enables it in a reviewed change.
- Never point `--custodian-key` at a real key while testing. Use `ans network throwaway-key`
  and the `rehearsal` profile.
