import fs from "node:fs";

const file = process.argv[2];
if (!file) { console.error("Usage: node patch-oasis-rofl-e2e.mjs <path-to-test.rs>"); process.exit(2); }
const source = fs.readFileSync(file, "utf8");
const anchor = "#[test]\nfn test_provider_management()";
if (source.split(anchor).length !== 2) throw new Error("Expected exactly one insertion point; refusing to patch unexpected source.");
const regressionTest = "#[test]\nfn test_expired_topup_charges_full_fee_and_claims_expired_gap() {\n    let initial_time = 1_741_778_021;\n    let mut mock = mock::Mock {\n        epoch: 42,\n        runtime_header: Header {\n            timestamp: initial_time,\n            ..Default::default()\n        },\n        ..Default::default()\n    };\n    let ctx = mock.create_ctx_for_runtime::<TestRuntime>(true);\n    TestRuntime::migrate(&ctx);\n\n    let mut signer_alice = mock::Signer::new(0, keys::alice::sigspec());\n    let mut signer_charlie = mock::Signer::new(0, keys::charlie::sigspec());\n    let mut signer_dave = mock::Signer::new(0, keys::dave::sigspec());\n\n    // Create the provider's scheduler ROFL app.\n    let app_create = rofl::types::Create {\n        scheme: rofl::types::IdentifierScheme::CreatorNonce,\n        ..Default::default()\n    };\n    let dispatch_result = signer_alice.call(&ctx, \"rofl.Create\", app_create);\n    assert!(dispatch_result.result.is_success(), \"scheduler app creation should succeed\");\n    let scheduler_app: rofl::app_id::AppId =\n        cbor::from_value(dispatch_result.result.unwrap()).unwrap();\n\n    // Create a provider offering native monthly payments.\n    let provider_create = types::ProviderCreate {\n        nodes: vec![keys::bob::pk_ed25519().into()],\n        scheduler_app,\n        payment_address: types::PaymentAddress::Native(keys::dave::address()),\n        offers: vec![types::Offer {\n            payment: types::Payment::Native {\n                denomination: Denomination::NATIVE,\n                terms: BTreeMap::from([(types::Term::Month, 10_000)]),\n            },\n            resources: types::Resources {\n                tee: types::TeeType::TDX,\n                memory: 512,\n                cpus: 1,\n                storage: 1024,\n                gpu: None,\n            },\n            capacity: 1,\n            ..Default::default()\n        }],\n        metadata: Default::default(),\n    };\n    let dispatch_result = signer_alice.call(&ctx, \"roflmarket.ProviderCreate\", provider_create);\n    assert!(dispatch_result.result.is_success(), \"provider creation should succeed\");\n\n    // Register the scheduler app and authorize Dave's key.\n    let fake_registration = rofl::types::Registration {\n        app: scheduler_app,\n        extra_keys: vec![keys::dave::pk()],\n        ..Default::default()\n    };\n    rofl::state::update_registration(fake_registration.clone()).unwrap();\n\n    // Create a one-month instance as Charlie.\n    let instance_create = types::InstanceCreate {\n        provider: keys::alice::address(),\n        offer: 0.into(),\n        admin: None,\n        deployment: Some(Default::default()),\n        term: types::Term::Month,\n        term_count: 1,\n    };\n    let dispatch_result =\n        signer_charlie.call(&ctx, \"roflmarket.InstanceCreate\", instance_create);\n    assert!(dispatch_result.result.is_success(), \"instance creation should succeed\");\n    let instance_id: types::InstanceId =\n        cbor::from_value(dispatch_result.result.unwrap()).unwrap();\n\n    // Bind the scheduler app registration to the provider's authorized node.\n    let fake_registration = rofl::types::Registration {\n        node_id: keys::bob::pk_ed25519().into(),\n        ..fake_registration\n    };\n    rofl::state::update_registration(fake_registration).unwrap();\n\n    let accept = types::InstanceAccept {\n        provider: keys::alice::address(),\n        ids: vec![instance_id],\n        metadata: Default::default(),\n    };\n    let dispatch_result = signer_dave.call(&ctx, \"roflmarket.InstanceAccept\", accept);\n    assert!(dispatch_result.result.is_success(), \"provider scheduler should accept the instance\");\n\n    let instance: types::Instance = signer_alice\n        .query(\n            &ctx,\n            \"roflmarket.Instance\",\n            types::InstanceQuery {\n                provider: keys::alice::address(),\n                id: instance_id,\n            },\n        )\n        .unwrap();\n    assert_eq!(instance.status, types::InstanceStatus::Accepted);\n\n    let old_paid_until = instance.paid_until;\n    assert_eq!(old_paid_until, 1_744_370_021);\n    let topup_time = old_paid_until + 600;\n    let renewal_duration = 2 * types::Term::Month.as_secs();\n    let expected_fee = 20_000u128;\n    let payment_address = Address::from_eth(&instance.payment_address);\n    let tenant_balance_before =\n        Accounts::get_balance(keys::charlie::address(), Denomination::NATIVE).unwrap();\n\n    // Simulate the scheduler's normal payment claim shortly before expiry.\n    // The default 24-hour claim interval (randomized to 18-30 hours) is already due.\n    let pre_expiry_claim_time = old_paid_until - 12 * 3600;\n    mock.runtime_header.timestamp = pre_expiry_claim_time;\n    let ctx = mock.create_ctx_for_runtime::<TestRuntime>(true);\n    let pre_expiry_claim = types::InstanceClaimPayment {\n        provider: keys::alice::address(),\n        instances: vec![instance_id],\n    };\n    let dispatch_result = signer_dave.call(&ctx, \"roflmarket.InstanceClaimPayment\", pre_expiry_claim);\n    assert!(dispatch_result.result.is_success(), \"pre-expiry scheduler claim should succeed\");\n    let preclaimed: types::Instance = signer_alice\n        .query(\n            &ctx,\n            \"roflmarket.Instance\",\n            types::InstanceQuery {\n                provider: keys::alice::address(),\n                id: instance_id,\n            },\n        )\n        .unwrap();\n    assert_eq!(preclaimed.paid_from, pre_expiry_claim_time);\n    let payment_balance_before =\n        Accounts::get_balance(payment_address, Denomination::NATIVE).unwrap();\n    let provider_balance_before_claim =\n        Accounts::get_balance(keys::dave::address(), Denomination::NATIVE).unwrap();\n\n    // Move chain time 10 minutes beyond expiry, before the 22.5-minute minimum removal delay.\n    mock.runtime_header.timestamp = topup_time;\n    let ctx = mock.create_ctx_for_runtime::<TestRuntime>(true);\n    let topup = types::InstanceTopUp {\n        provider: keys::alice::address(),\n        id: instance_id,\n        term: types::Term::Month,\n        term_count: 2,\n    };\n    let dispatch_result = signer_charlie.call(&ctx, \"roflmarket.InstanceTopUp\", topup);\n    assert!(\n        dispatch_result.result.is_success(),\n        \"InstanceTopUp should currently accept an expired-but-Accepted instance\"\n    );\n\n    let tenant_balance_after =\n        Accounts::get_balance(keys::charlie::address(), Denomination::NATIVE).unwrap();\n    let payment_balance_after =\n        Accounts::get_balance(payment_address, Denomination::NATIVE).unwrap();\n    assert_eq!(\n        tenant_balance_before - tenant_balance_after,\n        expected_fee,\n        \"tenant must be charged the complete two-month fee\"\n    );\n    assert_eq!(\n        payment_balance_after - payment_balance_before,\n        expected_fee,\n        \"instance payment address must receive the complete two-month fee\"\n    );\n\n    let renewed: types::Instance = signer_alice\n        .query(\n            &ctx,\n            \"roflmarket.Instance\",\n            types::InstanceQuery {\n                provider: keys::alice::address(),\n                id: instance_id,\n            },\n        )\n        .unwrap();\n    assert_eq!(renewed.status, types::InstanceStatus::Accepted);\n    assert_eq!(\n        renewed.paid_until,\n        old_paid_until + renewal_duration,\n        \"current implementation extends from the stale expiry timestamp\"\n    );\n    assert_eq!(\n        renewed.paid_until,\n        topup_time + renewal_duration - 600,\n        \"the paid term must remain 600 seconds shorter than a term starting now\"\n    );\n\n    // The scheduler will claim again after its maximum randomized interval (30 hours).\n    // The 10-minute expired gap is included in the next scheduler-eligible Runtime claim.\n    let post_topup_claim_time = pre_expiry_claim_time + 31 * 3600;\n    assert!(post_topup_claim_time > preclaimed.paid_from + 30 * 3600);\n    mock.runtime_header.timestamp = post_topup_claim_time;\n    let ctx = mock.create_ctx_for_runtime::<TestRuntime>(true);\n    let claim = types::InstanceClaimPayment {\n        provider: keys::alice::address(),\n        instances: vec![instance_id],\n    };\n    let dispatch_result = signer_dave.call(&ctx, \"roflmarket.InstanceClaimPayment\", claim);\n    assert!(dispatch_result.result.is_success(), \"post-top-up scheduler claim should succeed\");\n    let provider_balance_after_claim =\n        Accounts::get_balance(keys::dave::address(), Denomination::NATIVE).unwrap();\n    let provider_claim = provider_balance_after_claim - provider_balance_before_claim;\n    let total_escrow = payment_balance_before + expected_fee;\n    let paid_duration = renewed.paid_until - preclaimed.paid_from;\n    let elapsed_including_expired_gap = post_topup_claim_time - preclaimed.paid_from;\n    let elapsed_without_gap = elapsed_including_expired_gap - 600;\n    let claim_with_gap =\n        (u128::from(elapsed_including_expired_gap) * total_escrow) / u128::from(paid_duration);\n    let claim_without_gap =\n        (u128::from(elapsed_without_gap) * total_escrow) / u128::from(paid_duration);\n    assert_eq!(provider_claim, claim_with_gap, \"provider claim must use elapsed wall-clock time including the expired gap\");\n    assert_eq!(provider_claim - claim_without_gap, 2, \"the expired 600-second gap contributes 2 fixture units to this scheduler-eligible claim\");\n    let remaining_after_claim =\n        Accounts::get_balance(payment_address, Denomination::NATIVE).unwrap();\n\n}";
fs.writeFileSync(file, source.replace(anchor, regressionTest + "\n\n" + anchor));

// Match the test-only SDK feature used by sibling modules (contracts and EVM).
const manifest = file.replace(/src\/test\.rs$/, "Cargo.toml");
const manifestContent = fs.readFileSync(manifest, "utf8");
if (!manifestContent.includes('[dev-dependencies]')) {
  fs.writeFileSync(manifest, manifestContent.trimEnd() + '\n\n[dev-dependencies]\noasis-runtime-sdk = { path = "../..", features = ["test"] }\n');
} else if (!manifestContent.includes('oasis-runtime-sdk = { path = "../..", features = ["test"] }')) {
  throw new Error("Unexpected dev-dependencies section; refusing to rewrite the manifest automatically.");
}

const managerFile = file.replace(
  "runtime-sdk/modules/rofl-market/src/test.rs",
  "rofl-scheduler/src/manager.rs",
);
let managerSource = fs.readFileSync(managerFile, "utf8");

const helperAnchor = "impl Manager {\n";
const managerHelpers = [
  "fn instance_expired(paid_until: u64, now: u64) -> bool {",
  "    paid_until < now",
  "}",
  "",
  "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
  "struct ExpiredInstanceActions {",
  "    stop_running: bool,",
  "    removal_timestamp: u64,",
  "}",
  "",
  "fn removal_delay_elapsed(ts: u64, now: u64, max_delta: u64) -> bool {",
  "    now.saturating_sub(ts) >= max_delta",
  "}",
  "",
  "fn expired_instance_actions(",
  "    paid_until: u64,",
  "    now: u64,",
  "    is_running: bool,",
  ") -> Option<ExpiredInstanceActions> {",
  "    instance_expired(paid_until, now).then_some(ExpiredInstanceActions {",
  "        stop_running: is_running,",
  "        removal_timestamp: paid_until,",
  "    })",
  "}",
  "",
  "fn spawn_pending_stop_jobs<F, Fut>(",
  "    jobs: &mut tokio::task::JoinSet<Result<()>>," ,
  "    pending_stop: &[(InstanceId, bool)],",
  "    stop: F,",
  ")",
  "where",
  "    F: Fn(InstanceId, bool) -> Fut,",
  "    Fut: std::future::Future<Output = Result<()>> + Send + 'static,",
  "{",
  "    for (id, wipe_storage) in pending_stop.iter().copied() {",
  "        jobs.spawn(stop(id, wipe_storage));",
  "    }",
  "}",
  "",
  "async fn stop_instance_host_resources<VolumeRemove, VolumeFuture, BundleRemove, BundleFuture>(",
  "    instance_id: InstanceId,",
  "    wipe_storage: bool,",
  "    volume_remove: VolumeRemove,",
  "    bundle_remove: BundleRemove,",
  ") -> Result<()>",
  "where",
  "    VolumeRemove: FnOnce(BTreeMap<String, String>) -> VolumeFuture,",
  "    VolumeFuture: std::future::Future<Output = Result<()>>,",
  "    BundleRemove: FnOnce(BTreeMap<String, String>) -> BundleFuture,",
  "    BundleFuture: std::future::Future<Output = Result<()>>,",
  "{",
  "    if wipe_storage {",
  "        volume_remove(labels_for_instance(instance_id))",
  "            .await",
  "            .context(\"failed to wipe instance storage\")?;",
  "    }",
  "    bundle_remove(labels_for_instance(instance_id)).await?;",
  "    Ok(())",
  "}",
  "",
].join("\n");
if (!managerSource.includes("async fn stop_instance_host_resources")) {
  if (managerSource.split(helperAnchor).length !== 2) {
    throw new Error("Expected exactly one Manager impl insertion point.");
  }
  managerSource = managerSource.replace(helperAnchor, managerHelpers + helperAnchor);
}

const oldExpiry = [
  "            if instance.paid_until < now {",
  "                slog::info!(self.logger, \"instance not paid for, stopping\";",
  "                    \"id\" => ?instance.id,",
  "                );",
  "",
  "                if local_state.running.contains_key(&instance.id) {",
  "                    local_state.pending_stop.push((instance.id, true));",
  "                }",
  "                local_state",
  "                    .maybe_remove",
  "                    .push((instance.id, instance.paid_until));",
  "                continue;",
  "            }",
].join("\n");
const newExpiry = [
  "            if let Some(actions) = expired_instance_actions(",
  "                instance.paid_until,",
  "                now,",
  "                local_state.running.contains_key(&instance.id),",
  "            ) {",
  "                slog::info!(self.logger, \"instance not paid for, stopping\";",
  "                    \"id\" => ?instance.id,",
  "                );",
  "                if actions.stop_running {",
  "                    local_state.pending_stop.push((instance.id, true));",
  "                }",
  "                local_state",
  "                    .maybe_remove",
  "                    .push((instance.id, actions.removal_timestamp));",
  "                continue;",
  "            }",
].join("\n");
if (managerSource.includes(oldExpiry)) {
  managerSource = managerSource.replace(oldExpiry, newExpiry);
} else if (!managerSource.includes("expired_instance_actions(\n                instance.paid_until")) {
  throw new Error("Could not patch scheduler expiry discovery branch.");
}

const oldRemovalDelay = [
  "        if now.saturating_sub(ts) < max_delta {",
  "            return Ok(());",
  "        }",
].join("\n");
const newRemovalDelay = [
  "        if !removal_delay_elapsed(ts, now, max_delta) {",
  "            return Ok(());",
  "        }",
].join("\n");
if (managerSource.includes(oldRemovalDelay)) {
  managerSource = managerSource.replace(oldRemovalDelay, newRemovalDelay);
} else if (!managerSource.includes("if !removal_delay_elapsed(ts, now, max_delta)")) {
  throw new Error("Could not route production removal-delay check through the testable helper.");
}

const oldStop = [
  "    /// Wipe storage of the given instance.",
  "    async fn wipe_instance_storage(&self, instance_id: InstanceId) -> Result<()> {",
  "        let _ = self",
  "            .env",
  "            .host()",
  "            .volume_manager()",
  "            .volume_remove(volume_manager::VolumeRemoveRequest {",
  "                labels: labels_for_instance(instance_id),",
  "            })",
  "            .await?;",
  "",
  "        Ok(())",
  "    }",
  "",
  "    /// Stop an instance, removing all bundles associated with it.",
  "    async fn stop_instance(",
  "        self: Arc<Self>,",
  "        instance_id: InstanceId,",
  "        wipe_storage: bool,",
  "    ) -> Result<()> {",
  "        // Deprovision instance in the proxy.",
  "        if let Some(proxy) = self.proxy.as_ref() {",
  "            if let Err(err) = proxy.deprovision_instance(instance_id).await {",
  "                slog::error!(self.logger, \"failed to deprovision instance in proxy\"; \"err\" => ?err);",
  "            }",
  "        }",
  "",
  "        // Wipe storage if needed.",
  "        if wipe_storage {",
  "            self.wipe_instance_storage(instance_id)",
  "                .await",
  "                .context(\"failed to wipe instance storage\")?;",
  "        }",
  "",
  "        let _ = self",
  "            .env",
  "            .host()",
  "            .bundle_manager()",
  "            .bundle_remove(bundle_manager::BundleRemoveRequest {",
  "                labels: labels_for_instance(instance_id),",
  "            })",
  "            .await?;",
  "",
  "        Ok(())",
  "    }",
].join("\n");
const newStop = [
  "    /// Stop an instance, removing all bundles associated with it.",
  "    async fn stop_instance(",
  "        self: Arc<Self>,",
  "        instance_id: InstanceId,",
  "        wipe_storage: bool,",
  "    ) -> Result<()> {",
  "        // Deprovision instance in the proxy.",
  "        if let Some(proxy) = self.proxy.as_ref() {",
  "            if let Err(err) = proxy.deprovision_instance(instance_id).await {",
  "                slog::error!(self.logger, \"failed to deprovision instance in proxy\"; \"err\" => ?err);",
  "            }",
  "        }",
  "",
  "        // Use the same host cleanup sequence in production and in the mock-host regression test.",
  "        let host = self.env.host();",
  "        let volume_host = host.clone();",
  "        let bundle_host = host;",
  "        stop_instance_host_resources(",
  "            instance_id,",
  "            wipe_storage,",
  "            move |labels| async move {",
  "                let _ = volume_host",
  "                    .volume_manager()",
  "                    .volume_remove(volume_manager::VolumeRemoveRequest { labels })",
  "                    .await?;",
  "                Ok(())",
  "            },",
  "            move |labels| async move {",
  "                let _ = bundle_host",
  "                    .bundle_manager()",
  "                    .bundle_remove(bundle_manager::BundleRemoveRequest { labels })",
  "                    .await?;",
  "                Ok(())",
  "            },",
  "        )",
  "        .await?;",
  "",
  "        Ok(())",
  "    }",
].join("\n");
if (managerSource.includes(oldStop)) {
  managerSource = managerSource.replace(oldStop, newStop);
} else if (!managerSource.includes("stop_instance_host_resources(\n            instance_id,")) {
  throw new Error("Could not refactor scheduler host cleanup sequence.");
}


const oldStopJobs = [
  "        // Prepare jobs to stop instances.",
  "        let stop_jobs: Vec<_> = local_state",
  "            .pending_stop",
  "            .iter()",
  "            .map(|(id, wipe_storage)| self.clone().stop_instance(*id, *wipe_storage))",
  "            .collect();",
].join("\n");
if (managerSource.includes(oldStopJobs)) {
  managerSource = managerSource.replace(oldStopJobs + "\n\n", "");
} else if (!managerSource.includes("spawn_pending_stop_jobs(&mut jobs, &local_state.pending_stop")) {
  throw new Error("Could not locate production pending-stop job construction.");
}
const oldStopSpawn = [
  "        for job in stop_jobs {",
  "            jobs.spawn(job);",
  "        }",
].join("\n");
const newStopSpawn = [
  "        let manager = self.clone();",
  "        spawn_pending_stop_jobs(&mut jobs, &local_state.pending_stop, move |id, wipe_storage| {",
  "            manager.clone().stop_instance(id, wipe_storage)",
  "        });",
].join("\n");
if (managerSource.includes(oldStopSpawn)) {
  managerSource = managerSource.replace(oldStopSpawn, newStopSpawn);
} else if (!managerSource.includes("spawn_pending_stop_jobs(&mut jobs, &local_state.pending_stop")) {
  throw new Error("Could not wire pending-stop executor into process_jobs.");
}

const managerTestAnchor = "    #[test]\n    fn test_offer_policy_absent()";
const managerTests = [
  "    #[test]",
  "    fn test_expiry_discovery_queues_wipe_and_delayed_removal_only_when_expired() {",
  "        let paid_until = 10_000;",
  "        assert_eq!(expired_instance_actions(paid_until, paid_until, true), None);",
  "        assert_eq!(",
  "            expired_instance_actions(paid_until, paid_until + 1, true),",
  "            Some(ExpiredInstanceActions {",
  "                stop_running: true,",
  "                removal_timestamp: paid_until,",
  "            })",
  "        );",
  "        assert_eq!(",
  "            expired_instance_actions(paid_until, paid_until + 1, false),",
  "            Some(ExpiredInstanceActions {",
  "                stop_running: false,",
  "                removal_timestamp: paid_until,",
  "            })",
  "        );",
  "    }",
  "",
  "    #[test]",
  "    fn test_ten_minute_expired_topup_is_before_minimum_removal_delay() {",
  "        let paid_until = 10_000;",
  "        let topup_time = paid_until + 600;",
  "        let actions = expired_instance_actions(paid_until, topup_time, true).unwrap();",
  "        assert!(actions.stop_running, \"scheduler must stop an expired instance\");",
  "        assert!(!removal_delay_elapsed(paid_until, topup_time, 1_350), \"no instance removal is eligible before the minimum 22.5-minute delay\");",
  "        let renewed_paid_until = topup_time + 2_592_000;",
  "        assert!(expired_instance_actions(renewed_paid_until, topup_time, false).is_none(), \"the next discovery pass must observe the renewed lease\");",
  "    }",
  "",
  "    #[tokio::test]",
  "    async fn test_expired_scheduler_host_cleanup_wipes_volume_then_bundle() {",
  "        use std::sync::Mutex;",
  "",
  "        let instance_id = InstanceId::default();",
  "        let actions = expired_instance_actions(100, 101, true).unwrap();",
  "        assert!(actions.stop_running);",
  "",
  "        let volume_exists = Arc::new(Mutex::new(true));",
  "        let bundle_exists = Arc::new(Mutex::new(true));",
  "        let calls = Arc::new(Mutex::new(Vec::<String>::new()));",
  "",
  "        let volume_state = volume_exists.clone();",
  "        let volume_calls = calls.clone();",
  "        let volume_remove = move |labels| {",
  "            let volume_state = volume_state.clone();",
  "            let volume_calls = volume_calls.clone();",
  "            async move {",
  "                assert_eq!(labels, labels_for_instance(instance_id));",
  "                *volume_state.lock().unwrap() = false;",
  "                volume_calls.lock().unwrap().push(\"volume_remove\".to_string());",
  "                Ok::<(), anyhow::Error>(())",
  "            }",
  "        };",
  "",
  "        let bundle_state = bundle_exists.clone();",
  "        let bundle_calls = calls.clone();",
  "        let bundle_remove = move |labels| {",
  "            let bundle_state = bundle_state.clone();",
  "            let bundle_calls = bundle_calls.clone();",
  "            async move {",
  "                assert_eq!(labels, labels_for_instance(instance_id));",
  "                bundle_state.lock().unwrap().clone_from(&false);",
  "                bundle_calls.lock().unwrap().push(\"bundle_remove\".to_string());",
  "                Ok::<(), anyhow::Error>(())",
  "            }",
  "        };",
  "",
  "        stop_instance_host_resources(instance_id, true, volume_remove, bundle_remove)",
  "            .await",
  "            .unwrap();",
  "",
  "        assert!(!*volume_exists.lock().unwrap());",
  "        assert!(!*bundle_exists.lock().unwrap());",
  "        assert_eq!(",
  "            *calls.lock().unwrap(),",
  "            vec![\"volume_remove\".to_string(), \"bundle_remove\".to_string()]",
  "        );",
  "    }",
  "",
  "    #[tokio::test]",
  "    async fn test_expired_scheduler_without_wipe_preserves_volume_but_removes_bundle() {",
  "        use std::sync::Mutex;",
  "",
  "        let instance_id = InstanceId::default();",
  "        let volume_exists = Arc::new(Mutex::new(true));",
  "        let bundle_exists = Arc::new(Mutex::new(true));",
  "        let calls = Arc::new(Mutex::new(Vec::<String>::new()));",
  "",
  "        let volume_calls = calls.clone();",
  "        let volume_remove = move |_labels| {",
  "            let volume_calls = volume_calls.clone();",
  "            async move {",
  "                volume_calls.lock().unwrap().push(\"volume_remove\".to_string());",
  "                Ok::<(), anyhow::Error>(())",
  "            }",
  "        };",
  "        let bundle_state = bundle_exists.clone();",
  "        let bundle_calls = calls.clone();",
  "        let bundle_remove = move |_labels| {",
  "            let bundle_state = bundle_state.clone();",
  "            let bundle_calls = bundle_calls.clone();",
  "            async move {",
  "                *bundle_state.lock().unwrap() = false;",
  "                bundle_calls.lock().unwrap().push(\"bundle_remove\".to_string());",
  "                Ok::<(), anyhow::Error>(())",
  "            }",
  "        };",
  "",
  "        stop_instance_host_resources(instance_id, false, volume_remove, bundle_remove)",
  "            .await",
  "            .unwrap();",
  "        assert!(*volume_exists.lock().unwrap());",
  "        assert!(!*bundle_exists.lock().unwrap());",
  "        assert_eq!(*calls.lock().unwrap(), vec![\"bundle_remove\".to_string()]);",
  "    }",
  "",
].join("\n");
if (!managerSource.includes("test_expired_scheduler_host_cleanup_wipes_volume_then_bundle")) {
  if (managerSource.split(managerTestAnchor).length !== 2) {
    throw new Error("Expected exactly one manager test insertion point.");
  }
  managerSource = managerSource.replace(managerTestAnchor, managerTests + managerTestAnchor);
}
fs.writeFileSync(managerFile, managerSource);


const hostE2EFlag = "ROFL_SCHEDULER_HOST_E2E";

const managerProbeAnchor = "    /// Main loop of the ROFL scheduler.\n";
const managerProbe = [
    "    /// Reproduce the expiry-snapshot race after a successful top-up.",
    "    pub(crate) async fn host_cleanup_e2e(self: Arc<Self>, paid_until_snapshot: u64, now: u64, renewed_paid_until: u64) -> Result<()> {",
    "        anyhow::ensure!(renewed_paid_until > now, \"fixture must represent a successfully renewed lease\");",
    "        let actions = expired_instance_actions(paid_until_snapshot, now, true);",
    "        let Some(actions) = actions else { return Ok(()); };",
    "        let pending_stop = if actions.stop_running { vec![(InstanceId::from(4242u64), true)] } else { Vec::new() };",
    "        let mut jobs = tokio::task::JoinSet::new();",
    "        let manager = self.clone();",
    "        spawn_pending_stop_jobs(&mut jobs, &pending_stop, move |id, wipe_storage| manager.clone().stop_instance(id, wipe_storage));",
    "        while let Some(result) = jobs.join_next().await { result??; }",
    "        Ok(())",
    "    }",
    "",
].join("\n");
if (!managerSource.includes("pub(crate) async fn host_cleanup_e2e")) {
    if (!managerSource.includes(managerProbeAnchor)) throw new Error("Cannot locate manager probe insertion point.");
    managerSource = managerSource.replace(managerProbeAnchor, managerProbe + managerProbeAnchor);
}
fs.writeFileSync(managerFile, managerSource);

const mainFile = file.replace("runtime-sdk/modules/rofl-market/src/test.rs", "rofl-scheduler/src/main.rs");
let mainSource = fs.readFileSync(mainFile, "utf8");
const initAnchor = "    fn init(&mut self, host: Arc<Protocol>) {\n        let logger = get_logger(\"scheduler\");\n";
const initReplacement = [
    "    fn init(&mut self, host: Arc<Protocol>) {",
    "        if std::env::var_os(\"" + hostE2EFlag + "\").is_some() {",
    "            self.cfg = Some(Arc::new(config::LocalConfig {",
    "                provider_address: oasis_runtime_sdk::types::address::Address::default(),",
    "                offers: Default::default(),",
    "                capacity: config::Resources::default(),",
    "                processing_interval_secs: 1,",
    "                claim_payment_interval_secs: 24 * 3600,",
    "                deploy_pull_timeout: 60,",
    "                transfer_instances_from: Default::default(),",
    "                api_domain: None,",
    "                api_token_lifetime: 3600,",
    "                proxy: None,",
    "            }));",
    "            return;",
    "        }",
    "        let logger = get_logger(\"scheduler\");",
].join("\n") + "\n";
if (mainSource.includes(initAnchor)) {
    mainSource = mainSource.replace(initAnchor, initReplacement);
} else if (!mainSource.includes("ROFL_SCHEDULER_HOST_E2E")) {
    throw new Error("Cannot insert direct host-protocol configuration in SchedulerApp::init.");
}

const runAnchor = "    async fn run(self: Arc<Self>, env: Environment<Self>) {\n        let logger = get_logger(\"scheduler\");\n        let cfg = self.cfg.as_ref().unwrap();\n";
const runReplacement = runAnchor + [
    "        if std::env::var_os(\"" + hostE2EFlag + "\").is_some() {",
    "            let manager = manager::Manager::new(env, cfg.clone(), None);",
        "            let paid_until_snapshot: u64 = std::env::var(\"ROFL_SCHEDULER_PAID_UNTIL_SNAPSHOT\").unwrap().parse().unwrap();",
    "            let now: u64 = std::env::var(\"ROFL_SCHEDULER_NOW\").unwrap().parse().unwrap();",
    "            let renewed_paid_until: u64 = std::env::var(\"ROFL_SCHEDULER_RENEWED_PAID_UNTIL\").unwrap().parse().unwrap();",
    "            manager.host_cleanup_e2e(paid_until_snapshot, now, renewed_paid_until).await.expect(\"Scheduler expiry/top-up race cleanup probe failed\");",
    "            return;",
    "        }",
].join("\n") + "\n";
if (mainSource.includes(runAnchor)) {
    mainSource = mainSource.replace(runAnchor, runReplacement);
} else if (!mainSource.includes("manager.host_cleanup_e2e()")) {
    throw new Error("Cannot insert direct host-protocol execution in SchedulerApp::run.");
}
fs.writeFileSync(mainFile, mainSource);

const processorFile = file.replace("runtime-sdk/modules/rofl-market/src/test.rs", "rofl-app-core/src/processor.rs");
let processorSource = fs.readFileSync(processorFile, "utf8");
const processorAnchor = "        tokio::spawn(processor.run());\n";
const processorReplacement = [
    "        if std::env::var_os(\"" + hostE2EFlag + "\").is_some() {",
    "            tokio::spawn(processor.state.app.clone().run(processor.env.clone()));",
    "        }",
    "        tokio::spawn(processor.run());",
].join("\n") + "\n";
if (processorSource.includes(processorAnchor)) {
    processorSource = processorSource.replace(processorAnchor, processorReplacement);
} else if (!processorSource.includes("processor.state.app.clone().run(processor.env.clone())")) {
    throw new Error("Cannot insert direct Scheduler app start in ROFL processor.");
}
fs.writeFileSync(processorFile, processorSource);



const schedulerCargoFile = file.replace(
  "runtime-sdk/modules/rofl-market/src/test.rs",
  "rofl-scheduler/Cargo.toml",
);
let schedulerCargo = fs.readFileSync(schedulerCargoFile, "utf8");
// The test runner has no TDX device. Build the same Scheduler source in native
// (TEE=None) mode so it can connect to the RHP Unix socket and exercise host RPC.
schedulerCargo = schedulerCargo.replace(
  'oasis-runtime-sdk = { path = "../runtime-sdk", features = ["tdx"] }',
  'oasis-runtime-sdk = { path = "../runtime-sdk" }',
);
schedulerCargo = schedulerCargo.replace(
  'rofl-app-core = { path = "../rofl-app-core", features = ["tdx"] }',
  'rofl-app-core = { path = "../rofl-app-core" }',
);
if (schedulerCargo.includes('features = ["tdx"]')) {
  throw new Error("Failed to disable TDX-only build requirements for native RHP integration test.");
}
fs.writeFileSync(schedulerCargoFile, schedulerCargo);

const hostProtocolTestSource = "rofl-scheduler/tests/host_protocol_e2e.rs";
const hostProtocolTestTarget = file.replace(
  "runtime-sdk/modules/rofl-market/src/test.rs",
  "rofl-scheduler/tests/host_protocol_e2e.rs",
);
if (!fs.existsSync(hostProtocolTestSource)) {
  throw new Error("RHP integration test source is missing from the harness repository.");
}
fs.mkdirSync(hostProtocolTestTarget.slice(0, hostProtocolTestTarget.lastIndexOf("/")), {
  recursive: true,
});
fs.writeFileSync(hostProtocolTestTarget, fs.readFileSync(hostProtocolTestSource, "utf8"));

console.log("Injected the isolated runtime regression test and enabled SDK test helpers.");
