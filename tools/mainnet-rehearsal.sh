#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Local dry-run "mainnet rehearsal" on the throwaway `rehearsal` network profile.
# Exercises the protected-profile gates (explicit confirmation, external key path, no demo key,
# no test crash hook, no implicit identity) and the full dictionary flow, then shows that the
# rehearsal proof is refused as devnet/mainnet. Everything lives in a temp dir that is removed
# at the end. No network access, no real keys, no mainnet signing (compiled out in this build).
set -euo pipefail
ANS="${ANS:-/workspace/ans-vml-build-target/release/ans}"
[[ -x "$ANS" ]] || { echo "error: set ANS to the ans binary" >&2; exit 2; }
WORK="$(mktemp -d "${TMPDIR:-/tmp}/ans-rehearsal-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
export ANS_HOME="$WORK/home"
unset ANS_TEST_CRASH_AFTER
KEY="$WORK/rehearsal.seed"
P=(--network rehearsal --confirm-network rehearsal --custodian-key "$KEY")
step() { printf '\n== %s\n' "$*"; }
expect_fail() { local why="$1"; shift; if "$ANS" "$@" >/dev/null 2>"$WORK/err"; then echo "UNEXPECTED SUCCESS: $why" >&2; exit 1; fi; printf 'refused (%s): %s\n' "$why" "$(cat "$WORK/err")"; }

step "throwaway key (0600, marked .throwaway, never printed)"
"$ANS" network throwaway-key "$KEY" >/dev/null && echo "created $KEY"
step "gates"
expect_fail "no confirmation" --network rehearsal --custodian-key "$KEY" network init alice
expect_fail "no key path" --network rehearsal --confirm-network rehearsal network init alice
expect_fail "legacy init on protected profile" --network mainnet --confirm-network mainnet init alice
expect_fail "throwaway key on mainnet" --network mainnet --confirm-network mainnet --custodian-key "$KEY" network init alice
step "explicit identity creation"
"$ANS" "${P[@]}" network init alice | python3 -c 'import json,sys; v=json.load(sys.stdin); print("network:", v["network"], "height:", v["verification"]["height"])'
expect_fail "signer without operator flags" --as alice dictionary write character o --unverified
step "full flow: characters o a k, word oak, meaning, delegate, revoke"
for ch in o a k; do
  "$ANS" "${P[@]}" --as alice dictionary write character "$ch" --unverified --operation-id "c-$ch" >/dev/null
  "$ANS" "${P[@]}" --as alice dictionary validate "$ch" --operation-id "c-$ch-v" >/dev/null
  "$ANS" "${P[@]}" --as alice dictionary mint "$ch" --operation-id "c-$ch-m" >/dev/null
done
"$ANS" "${P[@]}" --as alice dictionary write word oak --lang en --meaning "a tree" --license CC0-1.0 \
  --source rehearsal --attribution "throwaway rehearsal; not a rights claim" --operation-id w >/dev/null
"$ANS" "${P[@]}" --as alice dictionary validate oak --operation-id w-v >/dev/null
PK="$("$ANS" "${P[@]}" --as alice dictionary mint oak --operation-id w-m | python3 -c 'import json,sys; v=json.load(sys.stdin); assert v["receipt"]["status"]=="accepted"; print(v["outcome"]["xmss"]["pk"])')"
"$ANS" "${P[@]}" --as alice mint-meaning oak en "a large tree" >/dev/null
"$ANS" "${P[@]}" --as alice delegate oak review >/dev/null
"$ANS" "${P[@]}" --as alice revoke oak review >/dev/null
python3 - "$ANS_HOME/custodians/alice/chain.ndjson" <<'PY'
import json, sys
ev = [json.loads(l) for l in open(sys.argv[1])]
nets = {e["body"].get("network") for e in ev}
assert nets == {"rehearsal"}, nets
print(f"{len(ev)} signed events, all bound to network=rehearsal")
PY
step "proof: valid only under rehearsal"
"$ANS" "${P[@]}" --as alice dictionary export oak --expect-key "$PK" > "$WORK/oak.proof.json"
"$ANS" --network rehearsal dictionary verify "$WORK/oak.proof.json" --expect-key "$PK" \
  | python3 -c 'import json,sys; v=json.load(sys.stdin); print("verified:", v["network"], v["word_dependency_path_verified"])'
expect_fail "rehearsal proof as devnet" dictionary verify "$WORK/oak.proof.json" --expect-key "$PK"
expect_fail "rehearsal proof as mainnet" --network mainnet dictionary verify "$WORK/oak.proof.json" --expect-key "$PK"
step "REHEARSAL OK (local only; temp dir removed; mainnet signing remains disabled)"
