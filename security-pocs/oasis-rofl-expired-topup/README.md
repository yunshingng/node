# Oasis ROFL Market expired-instance top-up PoC

This harness targets the reported source revision:

- Repository: `oasisprotocol/oasis-sdk`
- Commit: `beae84eac81e67a5134825eb192496c5af079cae`
- Crate: `oasis-runtime-sdk-rofl-market`

## What it tests

The harness injects one additional Rust test into the existing ROFL Market test module, then runs the real runtime mock through the `roflmarket.InstanceTopUp` transaction dispatcher.

The test creates a provider and Native-paid instance, accepts the instance through the scheduler authorization path, advances mock time to 30 minutes after `paid_until`, and attempts a one-month top-up. It checks:

1. The expired instance remains in `Accepted` state.
2. The real top-up transaction succeeds.
3. The tenant loses the full Native fee and the payment address receives it.
4. `paid_until` is extended from the old expiry, leaving the 30-minute gap unrecovered.

This is a runtime-level mock test, not a live-chain transaction. The GitHub Actions workflow compiles and executes the test against the pinned source commit.

## Run locally

Install the pinned Rust toolchain from the SDK's `rust-toolchain.toml`, then run:

```sh
git clone https://github.com/oasisprotocol/oasis-sdk.git
git -C oasis-sdk checkout beae84eac81e67a5134825eb192496c5af079cae
node security-pocs/oasis-rofl-expired-topup/run.mjs oasis-sdk
```

The harness temporarily modifies only the checked-out SDK test file. Use a disposable checkout.
