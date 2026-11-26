# Oasis reports — verified proof and PoC (2026-11-27)

This file records the completed tests against the exact affected revisions. It separates the demonstrated behavior from assumptions that the tests did not establish.

## Executive outcome

| Report | What the tests establish | Assessment |
|---|---|---|
| #4199683 — ROFL Market expired top-up | Native-payment runtime accepts top-up after expiry while status remains Accepted; the old expiry timestamp is extended; 600 seconds of unserved time contributes 2 fixture units to the provider's later claim. The actual Scheduler process can execute a previously queued stop through RHP after the renewal time in the harness. | **Reproducible accounting bug.** Impact is limited by the scheduler's expiry/cleanup lifecycle. RHP backend is simulated, not physical storage or a live network. |
| #4201931 — host-supplied RoundResults | Runtime financial state differs when the host-supplied result differs from the authenticated consensus MKVS value. Core's commitment pool then rejects one forged vote in Sapphire's 5/7/1 committee configuration when honest backup votes arrive. | **Authenticity gap exists, but single-host chain-level theft is not demonstrated and is blocked by Sapphire's quorum.** Do not describe this PoC as a Mainnet asset-theft exploit. |

## #4199683 — ROFL Market expired-instance top-up

### Affected revision and code path

- Repository: `oasisprotocol/oasis-sdk`
- Affected commit: `beae84eac81e67a5134825eb192496c5af079cae`
- Runtime handler: `runtime-sdk/modules/rofl-market/src/lib.rs`, `tx_instance_topup`
- Payment method: `runtime-sdk/modules/rofl-market/src/payment.rs`, `PaymentMethod::pay` and `PaymentMethod::claim`
- Scheduler: `rofl-scheduler/src/manager.rs`, `discover`, `process_jobs`, `maybe_remove_instance`, and `stop_instance`

### Verified result

GitHub Actions run: https://github.com/yunshingng/node/actions/runs/45878991717

Actual test output:

```text
ROFL_PROOF topup_gap_seconds=600 tenant_fee=20000 provider_claim=430 counterfactual_no_gap_claim=428 expired_gap_fee_delta=2
test test::test_expired_topup_charges_full_fee_and_claims_expired_gap ... ok
test result: ok. 1 passed; 0 failed
test manager::test::test_ten_minute_expired_topup_is_before_minimum_removal_delay ... ok
test result: ok. 10 passed; 0 failed
test scheduler_process_uses_real_rhp_host_rpc_for_expiry_cleanup ... ok
test result: ok. 1 passed; 0 failed
```

The corrected scenario uses a 600-second post-expiry top-up, not the earlier 2,400-second run. The manager test separately verifies this is below the 1,350-second minimum randomized removal delay (75% of the 1,800-second base delay). The native-payment transaction is dispatched through the actual Runtime test harness. It charges 20,000, and the later provider claim is 430 versus a 428 counterfactual that excludes the expired gap.

The host-protocol test starts the Scheduler process and exchanges Runtime Host Protocol messages over a Unix socket. It observes `volume-manager.VolumeRemove` followed by `bundle-manager.BundleRemove` for the same instance labels, after the test fixture has made the renewed lease valid. The Host backend applies a simulated volume/bundle state change; this is not a test against physical storage or a live Oasis node.

### Reproduction

Use the harness branch `repro/oasis-rofl-expired-topup-e2e-20261115`.

Patcher: https://github.com/yunshingng/node/blob/repro/oasis-rofl-expired-topup-e2e-20261115/.github/scripts/patch-oasis-rofl-e2e.mjs

RHP process test: https://github.com/yunshingng/node/blob/repro/oasis-rofl-expired-topup-e2e-20261115/rofl-scheduler/tests/host_protocol_e2e.rs

Workflow: https://github.com/yunshingng/node/blob/repro/oasis-rofl-expired-topup-e2e-20261115/.github/workflows/oasis-rofl-expired-topup-e2e.yml

From an Oasis SDK checkout at the affected commit, the workflow runs:

```bash
node .github/scripts/patch-oasis-rofl-e2e.mjs oasis-sdk/runtime-sdk/modules/rofl-market/src/test.rs
cargo test --manifest-path runtime-sdk/modules/rofl-market/Cargo.toml test_expired_topup_charges_full_fee_and_claims_expired_gap -- --nocapture
cargo test --manifest-path rofl-scheduler/Cargo.toml 'manager::test::' -- --nocapture
cargo test --manifest-path rofl-scheduler/Cargo.toml --test host_protocol_e2e -- --nocapture
```

Machine-readable result: https://github.com/yunshingng/node/blob/repro/oasis-rofl-expired-topup-e2e-20261115/.github/test-results/oasis-rofl-expired-topup-e2e-20261127.txt

### Report wording recommendation

Claim the expired-top-up billing/claim mismatch and describe the queued-stop race as a separate scheduler race with the stated harness limitation. Do not claim that a normal top-up always triggers permanent deletion: the RHP test proves the stale stop path can execute after renewal once a stop was already queued; it does not prove that every post-expiry top-up encounters that timing window.

---

## #4201931 — host-supplied Runtime RoundResults

### Affected revisions and code path

- Core repository: `oasisprotocol/oasis-core`
- Core commit: `ffc7dfc9c5f8ce6505f0ccf151e13d087c1c5d5b`
- SDK repository: `oasisprotocol/oasis-sdk`
- SDK commit: `beae84eac81e67a5134825eb192496c5af079cae`
- Core passes `RoundResults` in `RuntimeExecuteTxBatchRequest`.
- SDK `Dispatcher::execute_batch_common` constructs `RuntimeBatchContext` with `rt_ctx.round_results` and calls `handle_last_round_messages`.
- The runtime's message-result handler can change consensus-account state based on those supplied events.
- Core's finalization path only finalizes a commitment after `Pool.ProcessCommitments` succeeds and then places the accepted commitment's roots in the finalized block.

### Verified result

GitHub Actions run: https://github.com/yunshingng/node/actions/runs/45878473085

The run passed four Core host-boundary helper tests, three consensus commitment-pool PoC cases, and one SDK financial state-transition regression.

Core quorum outputs:

```text
2 workers / 1 backup / 1 allowed straggler:
  one primary vote accepted after timeout

3 workers / 5 backups / 1 allowed straggler:
  one forged primary rejected; three honest backup votes -> ErrBadSchedulerCommitment

Sapphire Mainnet 5 workers / 7 backups / 1 allowed straggler:
  one forged primary rejected; four honest backup votes -> ErrBadSchedulerCommitment
```

The Sapphire 5/7/1 parameters are not guessed: the official Oasis CLI documentation's example of the Mainnet Sapphire registry descriptor lists `group_size: 5`, `group_backup_size: 7`, and `allowed_stragglers: 1` (see https://docs.oasis.io/build/tools/cli/network/, section showing the Sapphire Mainnet registry descriptor).

SDK financial regression output:

```text
authoritative_code=1 host_forged_code=0
honest_alice=1000 forged_alice=0
honest_supply=1000 forged_supply=0
honest_state_root=ccf53b2b7cb26b155e36be11063e5a8c63bb41535d115536c107618d34bd0db3
forged_state_root=e9b29c0df70fa60614d3f6679b3124429069433f5e40c80743e502e040867308
test result: ok. 1 passed; 0 failed
```

This proves a host-supplied result can cause a different *local runtime execution* and state root. It does **not** prove that one malicious Sapphire compute host can make that forged root become the finalized chain state. The Core consensus pool test shows the opposite under the 5/7/1 configuration: an isolated forged primary is insufficient, and the honest backup majority causes the forged scheduler commitment to be rejected.

### Reproduction

Use branch `repro/oasis-round-results-e2e-20261116`.

Core host-boundary patcher: https://github.com/yunshingng/node/blob/repro/oasis-round-results-e2e-20261116/.github/scripts/patch-oasis-core-round-results-e2e.mjs

Core quorum patcher: https://github.com/yunshingng/node/blob/repro/oasis-round-results-e2e-20261116/.github/scripts/patch-oasis-core-quorum-e2e.mjs

SDK financial regression patcher: https://github.com/yunshingng/node/blob/repro/oasis-round-results-e2e-20261116/.github/scripts/patch-oasis-round-results-e2e.mjs

Workflow: https://github.com/yunshingng/node/blob/repro/oasis-round-results-e2e-20261116/.github/workflows/oasis-round-results-e2e.yml

From the repository root, after checking out the exact Core and SDK commits in the workflow, execute:

```bash
node .github/scripts/patch-oasis-core-round-results-e2e.mjs oasis-core/go/worker/compute/executor/committee/node.go
cd oasis-core/go
gofmt -w worker/compute/executor/committee/round_results_poc.go worker/compute/executor/committee/round_results_poc_test.go
go test ./worker/compute/executor/committee -count=1 -v
cd ../..

node .github/scripts/patch-oasis-core-quorum-e2e.mjs oasis-core/go/roothash/api/commitment/pool_test.go
cd oasis-core/go
gofmt -w roothash/api/commitment/pool_test.go
go test ./roothash/api/commitment -run '^TestPoC' -count=1 -v
cd ../..

node .github/scripts/patch-oasis-round-results-e2e.mjs oasis-sdk/runtime-sdk/src/dispatcher.rs
cd oasis-sdk
cargo fmt --manifest-path runtime-sdk/Cargo.toml
cargo test --manifest-path runtime-sdk/Cargo.toml test_host_forged_round_results_change_consensus_accounts_state -- --nocapture
```

Machine-readable result: https://github.com/yunshingng/node/blob/repro/oasis-round-results-e2e-20261116/.github/test-results/oasis-round-results-e2e-20261127.txt

### Report wording recommendation

The implementation-level authenticity gap is reproducible. However, the evidence does not justify a claim of unilateral asset theft or finalized state corruption on Sapphire Mainnet. Based on the tested quorum, the current report's high-impact single-host attack narrative should be withdrawn or materially narrowed unless an additional path is demonstrated that makes honest committee members accept the same forged result.

## Final triage recommendation

- **#4199683:** Keep as a bounded billing/accounting bug. Report the exact 600-second fixture result and be transparent that the scheduler host backend is simulated. The stale-stop race should be described as conditional on a stop job already having been queued before renewal.
- **#4201931:** Do not submit a high-severity theft/CVE claim on the current evidence. It is an enclave input-authenticity issue, but Sapphire's production 5/7/1 commitment quorum blocks the demonstrated single-host path. A multi-node attack would need to defeat the committee threshold, which this PoC does not establish.

