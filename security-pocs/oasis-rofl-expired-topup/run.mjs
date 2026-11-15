import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";

const oasisRoot = resolve(process.argv[2] ?? "oasis-sdk");
const testPath = resolve(oasisRoot, "runtime-sdk/modules/rofl-market/src/test.rs");
const marker = "#[test]\nfn test_provider_stake_pool_address()";
const testName = "test_instance_topup_after_expiration_charges_full_fee_without_restoring_gap";

let source = readFileSync(testPath, "utf8");
if (source.includes(testName)) {
  throw new Error("The PoC test is already present; refusing to inject it twice.");
}
if (!source.includes(marker)) {
  throw new Error("Could not find the expected insertion point in rofl-market/src/test.rs.");
}

const rustTest = String.raw`
#[test]
fn test_instance_topup_after_expiration_charges_full_fee_without_restoring_gap() {
    const START_TIME: u64 = 1_741_778_021;
    const MONTH_SECONDS: u64 = 30 * 24 * 60 * 60;
    const GAP_SECONDS: u64 = 1_800;
    const MONTH_PRICE: u128 = 10_000;

    let mut mock = mock::Mock {
        epoch: 42,
        runtime_header: Header {
            timestamp: START_TIME,
            ..Default::default()
        },
        ..Default::default()
    };
    let ctx = mock.create_ctx_for_runtime::<TestRuntime>(true);
    TestRuntime::migrate(&ctx);

    // Create a scheduler app and provider using the existing ROFL Market test runtime.
    let create_app = rofl::types::Create {
        scheme: rofl::types::IdentifierScheme::CreatorNonce,
        ..Default::default()
    };
    let mut signer_alice = mock::Signer::new(0, keys::alice::sigspec());
    let dispatch_result = signer_alice.call(&ctx, "rofl.Create", create_app);
    assert!(dispatch_result.result.is_success(), "scheduler app creation failed");
    let scheduler_app: rofl::app_id::AppId =
        cbor::from_value(dispatch_result.result.unwrap()).unwrap();

    let create_provider = types::ProviderCreate {
        nodes: vec![keys::bob::pk_ed25519().into()],
        scheduler_app,
        payment_address: types::PaymentAddress::Native(keys::alice::address()),
        offers: vec![types::Offer {
            payment: types::Payment::Native {
                denomination: Denomination::NATIVE,
                terms: BTreeMap::from([(types::Term::Month, MONTH_PRICE)]),
            },
            resources: types::Resources {
                tee: types::TeeType::TDX,
                memory: 512,
                cpus: 1,
                storage: 1024,
                gpu: None,
            },
            capacity: 1,
            ..Default::default()
        }],
        metadata: Default::default(),
    };
    let dispatch_result = signer_alice.call(&ctx, "roflmarket.ProviderCreate", create_provider);
    assert!(dispatch_result.result.is_success(), "provider creation failed");

    // Authorize Dave as the scheduler app, endorsed by the provider's Bob node.
    let registration = rofl::types::Registration {
        app: scheduler_app,
        extra_keys: vec![keys::dave::pk()],
        ..Default::default()
    };
    rofl::state::update_registration(registration.clone()).unwrap();
    let registration = rofl::types::Registration {
        node_id: keys::bob::pk_ed25519().into(),
        ..registration
    };
    rofl::state::update_registration(registration).unwrap();

    // Charlie creates an instance and the scheduler accepts it.
    let mut signer_charlie = mock::Signer::new(0, keys::charlie::sigspec());
    let create_instance = types::InstanceCreate {
        provider: keys::alice::address(),
        offer: 0.into(),
        admin: None,
        deployment: Some(Default::default()),
        term: types::Term::Month,
        term_count: 1,
    };
    let dispatch_result =
        signer_charlie.call(&ctx, "roflmarket.InstanceCreate", create_instance);
    assert!(dispatch_result.result.is_success(), "instance creation failed");

    let mut signer_dave = mock::Signer::new(0, keys::dave::sigspec());
    let accept = types::InstanceAccept {
        provider: keys::alice::address(),
        ids: vec![0.into()],
        metadata: Default::default(),
    };
    let dispatch_result = signer_dave.call(&ctx, "roflmarket.InstanceAccept", accept);
    assert!(dispatch_result.result.is_success(), "instance acceptance failed");

    let initial: types::Instance = signer_alice
        .query(
            &ctx,
            "roflmarket.Instance",
            types::InstanceQuery {
                provider: keys::alice::address(),
                id: 0.into(),
            },
        )
        .unwrap();
    assert_eq!(initial.status, types::InstanceStatus::Accepted);
    assert_eq!(initial.paid_until, START_TIME + MONTH_SECONDS);
    let old_paid_until = initial.paid_until;

    // Simulate the tenant renewing 30 minutes after service has expired.
    mock.runtime_header.timestamp = old_paid_until + GAP_SECONDS;
    let now = mock.runtime_header.timestamp;
    let expired_ctx = mock.create_ctx_for_runtime::<TestRuntime>(true);
    let expired: types::Instance = signer_alice
        .query(
            &expired_ctx,
            "roflmarket.Instance",
            types::InstanceQuery {
                provider: keys::alice::address(),
                id: 0.into(),
            },
        )
        .unwrap();
    assert_eq!(expired.status, types::InstanceStatus::Accepted);
    assert!(now > expired.paid_until, "the test must exercise an expired instance");

    let payment_address = Address::from_eth(&expired.payment_address);
    let tenant_before =
        Accounts::get_balance(keys::charlie::address(), Denomination::NATIVE).unwrap();
    let escrow_before =
        Accounts::get_balance(payment_address, Denomination::NATIVE).unwrap();

    // Invoke the real transaction handler through the mock runtime dispatcher.
    let topup = types::InstanceTopUp {
        provider: keys::alice::address(),
        id: 0.into(),
        term: types::Term::Month,
        term_count: 1,
    };
    let dispatch_result =
        signer_charlie.call(&expired_ctx, "roflmarket.InstanceTopUp", topup);
    assert!(
        dispatch_result.result.is_success(),
        "InstanceTopUp unexpectedly rejected an expired Accepted instance"
    );

    let tenant_after =
        Accounts::get_balance(keys::charlie::address(), Denomination::NATIVE).unwrap();
    let escrow_after =
        Accounts::get_balance(payment_address, Denomination::NATIVE).unwrap();
    let renewed: types::Instance = signer_alice
        .query(
            &expired_ctx,
            "roflmarket.Instance",
            types::InstanceQuery {
                provider: keys::alice::address(),
                id: 0.into(),
            },
        )
        .unwrap();

    // Full fee is charged, but the new paid term is appended to the expired timestamp.
    assert_eq!(tenant_before - tenant_after, MONTH_PRICE);
    assert_eq!(escrow_after - escrow_before, MONTH_PRICE);
    assert_eq!(renewed.paid_until, old_paid_until + MONTH_SECONDS);
    assert_eq!(
        now + MONTH_SECONDS - renewed.paid_until,
        GAP_SECONDS,
        "the full renewal fee was charged while the 30-minute expired gap remained unpaid"
    );
}
`;

source = source.replace(marker, rustTest + "\n" + marker);
writeFileSync(testPath, source, "utf8");
console.log(`Injected ${testName} into ${testPath}`);
console.log("Pinned source commit: beae84eac81e67a5134825eb192496c5af079cae");

const result = spawnSync(
  "cargo",
  [
    "test",
    "-p",
    "oasis-runtime-sdk-rofl-market",
    testName,
    "--",
    "--nocapture",
    "--test-threads=1",
  ],
  {
    cwd: oasisRoot,
    stdio: "inherit",
    env: {
      ...process.env,
      CARGO_TERM_COLOR: "always",
      LIBCLANG_PATH: process.env.LIBCLANG_PATH ?? "/usr/lib/llvm-21/lib",
    },
  },
);

if (result.error) throw result.error;
if (result.status !== 0) {
  process.exitCode = result.status ?? 1;
} else {
  console.log("PASS: expired-instance native top-up runtime regression test.");
}
