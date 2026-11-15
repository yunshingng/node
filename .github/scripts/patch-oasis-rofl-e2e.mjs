import fs from "node:fs";

const file = process.argv[2];
if (!file) { console.error("Usage: node patch-oasis-rofl-e2e.mjs <path-to-test.rs>"); process.exit(2); }
const source = fs.readFileSync(file, "utf8");
const anchor = "#[test]\nfn test_provider_management()";
if (source.split(anchor).length !== 2) throw new Error("Expected exactly one insertion point; refusing to patch unexpected source.");
const regressionTest = "#[test]\nfn test_expired_topup_charges_full_fee_and_stale_remove_can_delete_renewed_instance() {\n    let initial_time = 1_741_778_021;\n    let mut mock = mock::Mock {\n        epoch: 42,\n        runtime_header: Header {\n            timestamp: initial_time,\n            ..Default::default()\n        },\n        ..Default::default()\n    };\n    let ctx = mock.create_ctx_for_runtime::<TestRuntime>(true);\n    TestRuntime::migrate(&ctx);\n\n    let mut signer_alice = mock::Signer::new(0, keys::alice::sigspec());\n    let mut signer_charlie = mock::Signer::new(0, keys::charlie::sigspec());\n    let mut signer_dave = mock::Signer::new(0, keys::dave::sigspec());\n\n    // Create the provider's scheduler ROFL app.\n    let app_create = rofl::types::Create {\n        scheme: rofl::types::IdentifierScheme::CreatorNonce,\n        ..Default::default()\n    };\n    let dispatch_result = signer_alice.call(&ctx, \"rofl.Create\", app_create);\n    assert!(dispatch_result.result.is_success(), \"scheduler app creation should succeed\");\n    let scheduler_app: rofl::app_id::AppId =\n        cbor::from_value(dispatch_result.result.unwrap()).unwrap();\n\n    // Create a provider offering native monthly payments.\n    let provider_create = types::ProviderCreate {\n        nodes: vec![keys::bob::pk_ed25519().into()],\n        scheduler_app,\n        payment_address: types::PaymentAddress::Native(keys::dave::address()),\n        offers: vec![types::Offer {\n            payment: types::Payment::Native {\n                denomination: Denomination::NATIVE,\n                terms: BTreeMap::from([(types::Term::Month, 10_000)]),\n            },\n            resources: types::Resources {\n                tee: types::TeeType::TDX,\n                memory: 512,\n                cpus: 1,\n                storage: 1024,\n                gpu: None,\n            },\n            capacity: 1,\n            ..Default::default()\n        }],\n        metadata: Default::default(),\n    };\n    let dispatch_result = signer_alice.call(&ctx, \"roflmarket.ProviderCreate\", provider_create);\n    assert!(dispatch_result.result.is_success(), \"provider creation should succeed\");\n\n    // Register the scheduler app and authorize Dave's key.\n    let fake_registration = rofl::types::Registration {\n        app: scheduler_app,\n        extra_keys: vec![keys::dave::pk()],\n        ..Default::default()\n    };\n    rofl::state::update_registration(fake_registration.clone()).unwrap();\n\n    // Create a one-month instance as Charlie.\n    let instance_create = types::InstanceCreate {\n        provider: keys::alice::address(),\n        offer: 0.into(),\n        admin: None,\n        deployment: Some(Default::default()),\n        term: types::Term::Month,\n        term_count: 1,\n    };\n    let dispatch_result =\n        signer_charlie.call(&ctx, \"roflmarket.InstanceCreate\", instance_create);\n    assert!(dispatch_result.result.is_success(), \"instance creation should succeed\");\n    let instance_id: types::InstanceId =\n        cbor::from_value(dispatch_result.result.unwrap()).unwrap();\n\n    // Bind the scheduler app registration to the provider's authorized node.\n    let fake_registration = rofl::types::Registration {\n        node_id: keys::bob::pk_ed25519().into(),\n        ..fake_registration\n    };\n    rofl::state::update_registration(fake_registration).unwrap();\n\n    let accept = types::InstanceAccept {\n        provider: keys::alice::address(),\n        ids: vec![instance_id],\n        metadata: Default::default(),\n    };\n    let dispatch_result = signer_dave.call(&ctx, \"roflmarket.InstanceAccept\", accept);\n    assert!(dispatch_result.result.is_success(), \"provider scheduler should accept the instance\");\n\n    let instance: types::Instance = signer_alice\n        .query(\n            &ctx,\n            \"roflmarket.Instance\",\n            types::InstanceQuery {\n                provider: keys::alice::address(),\n                id: instance_id,\n            },\n        )\n        .unwrap();\n    assert_eq!(instance.status, types::InstanceStatus::Accepted);\n\n    let old_paid_until = instance.paid_until;\n    let topup_time = old_paid_until + 1_800;\n    let renewal_duration = 2 * types::Term::Month.as_secs();\n    let expected_fee = 20_000u128;\n    let payment_address = Address::from_eth(&instance.payment_address);\n    let tenant_balance_before =\n        Accounts::get_balance(keys::charlie::address(), Denomination::NATIVE).unwrap();\n\n    // Simulate the scheduler's normal payment claim shortly before expiry.\n    // The default 24-hour claim interval (randomized to 18-30 hours) is already due.\n    let pre_expiry_claim_time = old_paid_until - 12 * 3600;\n    mock.runtime_header.timestamp = pre_expiry_claim_time;\n    let ctx = mock.create_ctx_for_runtime::<TestRuntime>(true);\n    let pre_expiry_claim = types::InstanceClaimPayment {\n        provider: keys::alice::address(),\n        instances: vec![instance_id],\n    };\n    let dispatch_result = signer_dave.call(&ctx, \"roflmarket.InstanceClaimPayment\", pre_expiry_claim);\n    assert!(dispatch_result.result.is_success(), \"pre-expiry scheduler claim should succeed\");\n    let preclaimed: types::Instance = signer_alice\n        .query(\n            &ctx,\n            \"roflmarket.Instance\",\n            types::InstanceQuery {\n                provider: keys::alice::address(),\n                id: instance_id,\n            },\n        )\n        .unwrap();\n    assert_eq!(preclaimed.paid_from, pre_expiry_claim_time);\n    let payment_balance_before =\n        Accounts::get_balance(payment_address, Denomination::NATIVE).unwrap();\n    let provider_balance_before_claim =\n        Accounts::get_balance(keys::dave::address(), Denomination::NATIVE).unwrap();\n\n    // Move chain time 30 minutes beyond expiry, then dispatch the real runtime call.\n    mock.runtime_header.timestamp = topup_time;\n    let ctx = mock.create_ctx_for_runtime::<TestRuntime>(true);\n    let topup = types::InstanceTopUp {\n        provider: keys::alice::address(),\n        id: instance_id,\n        term: types::Term::Month,\n        term_count: 2,\n    };\n    let dispatch_result = signer_charlie.call(&ctx, \"roflmarket.InstanceTopUp\", topup);\n    assert!(\n        dispatch_result.result.is_success(),\n        \"InstanceTopUp should currently accept an expired-but-Accepted instance\"\n    );\n\n    let tenant_balance_after =\n        Accounts::get_balance(keys::charlie::address(), Denomination::NATIVE).unwrap();\n    let payment_balance_after =\n        Accounts::get_balance(payment_address, Denomination::NATIVE).unwrap();\n    assert_eq!(\n        tenant_balance_before - tenant_balance_after,\n        expected_fee,\n        \"tenant must be charged the complete two-month fee\"\n    );\n    assert_eq!(\n        payment_balance_after - payment_balance_before,\n        expected_fee,\n        \"instance payment address must receive the complete two-month fee\"\n    );\n\n    let renewed: types::Instance = signer_alice\n        .query(\n            &ctx,\n            \"roflmarket.Instance\",\n            types::InstanceQuery {\n                provider: keys::alice::address(),\n                id: instance_id,\n            },\n        )\n        .unwrap();\n    assert_eq!(renewed.status, types::InstanceStatus::Accepted);\n    assert_eq!(\n        renewed.paid_until,\n        old_paid_until + renewal_duration,\n        \"current implementation extends from the stale expiry timestamp\"\n    );\n    assert_eq!(\n        renewed.paid_until,\n        topup_time + renewal_duration - 1_800,\n        \"the paid term must remain 1,800 seconds shorter than a term starting now\"\n    );\n\n    // The scheduler will claim again after its maximum randomized interval (30 hours).\n    // At that point the 30-minute expired gap is inside the Runtime claim interval.\n    let post_topup_claim_time = pre_expiry_claim_time + 31 * 3600;\n    assert!(post_topup_claim_time > preclaimed.paid_from + 30 * 3600);\n    mock.runtime_header.timestamp = post_topup_claim_time;\n    let ctx = mock.create_ctx_for_runtime::<TestRuntime>(true);\n    let claim = types::InstanceClaimPayment {\n        provider: keys::alice::address(),\n        instances: vec![instance_id],\n    };\n    let dispatch_result = signer_dave.call(&ctx, \"roflmarket.InstanceClaimPayment\", claim);\n    assert!(dispatch_result.result.is_success(), \"post-top-up scheduler claim should succeed\");\n    let provider_balance_after_claim =\n        Accounts::get_balance(keys::dave::address(), Denomination::NATIVE).unwrap();\n    let provider_claim = provider_balance_after_claim - provider_balance_before_claim;\n    let total_escrow = payment_balance_before + expected_fee;\n    let paid_duration = renewed.paid_until - preclaimed.paid_from;\n    let elapsed_including_expired_gap = post_topup_claim_time - preclaimed.paid_from;\n    let elapsed_without_gap = elapsed_including_expired_gap - 1_800;\n    let claim_with_gap =\n        (u128::from(elapsed_including_expired_gap) * total_escrow) / u128::from(paid_duration);\n    let claim_without_gap =\n        (u128::from(elapsed_without_gap) * total_escrow) / u128::from(paid_duration);\n    assert_eq!(provider_claim, claim_with_gap, \"provider claim must use elapsed wall-clock time including the expired gap\");\n    assert_eq!(provider_claim - claim_without_gap, 7, \"the expired 1,800-second gap contributes 7 fixture units to this scheduler-eligible claim\");\n    let remaining_after_claim =\n        Accounts::get_balance(payment_address, Denomination::NATIVE).unwrap();\n\n    // Simulate a stale scheduler removal job queued from the expired-state discovery.\n    // The on-chain remove handler does not re-check the expiry snapshot before deleting.\n    let remove = types::InstanceRemove {\n        provider: keys::alice::address(),\n        id: instance_id,\n    };\n    let dispatch_result = signer_dave.call(&ctx, \"roflmarket.InstanceRemove\", remove);\n    assert!(dispatch_result.result.is_success(), \"a stale remove call should still succeed after the instance was topped up\");\n\n    let tenant_balance_after_remove =\n        Accounts::get_balance(keys::charlie::address(), Denomination::NATIVE).unwrap();\n    let payment_balance_after_remove =\n        Accounts::get_balance(payment_address, Denomination::NATIVE).unwrap();\n    assert_eq!(tenant_balance_after_remove, tenant_balance_after + remaining_after_claim, \"removal should refund only the remaining escrow after the provider claim\");\n    assert_eq!(payment_balance_after_remove, 0, \"payment address should be emptied by the refund\");\n    let removed: Result<types::Instance, _> = signer_alice.query(\n        &ctx,\n        \"roflmarket.Instance\",\n        types::InstanceQuery {\n            provider: keys::alice::address(),\n            id: instance_id,\n        },\n    );\n    assert!(removed.is_err(), \"the newly topped-up instance should nevertheless be removed\");\n}";
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
  "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
  "struct ExpiredInstanceActions {",
  "    stop_running: bool,",
  "    removal_timestamp: u64,",
  "}",
  "",
  "fn expired_instance_actions(",
  "    paid_until: u64,",
  "    now: u64,",
  "    is_running: bool,",
  ") -> Option<ExpiredInstanceActions> {",
  "    (paid_until < now).then_some(ExpiredInstanceActions {",
  "        stop_running: is_running,",
  "        removal_timestamp: paid_until,",
  "    })",
  "}",
  "",
  "fn removal_delay_elapsed(now: u64, timestamp: u64, max_delta: u64) -> bool {",
  "    now.saturating_sub(timestamp) >= max_delta",
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

const oldRemoval = [
  "        if now.saturating_sub(ts) < max_delta {",
  "            return Ok(());",
  "        }",
].join("\n");
const newRemoval = [
  "        if !removal_delay_elapsed(now, ts, max_delta) {",
  "            return Ok(());",
  "        }",
].join("\n");
if (managerSource.includes(oldRemoval)) {
  managerSource = managerSource.replace(oldRemoval, newRemoval);
} else if (!managerSource.includes("if !removal_delay_elapsed(now, ts, max_delta)")) {
  throw new Error("Could not patch scheduler removal delay predicate.");
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
  "    #[test]",
  "    fn test_stale_removal_delay_is_based_on_expiry_snapshot() {",
  "        let expired_at = 1_000;",
  "        assert!(!removal_delay_elapsed(expired_at + 1_800, expired_at, 2_250));",
  "        assert!(removal_delay_elapsed(expired_at + 2_250, expired_at, 2_250));",
  "        // The check has no input for a renewed paid_until value: the queued snapshot timestamp",
  "        // alone determines whether the removal job submits InstanceRemove.",
  "        assert!(removal_delay_elapsed(expired_at + 2_250, expired_at, 2_250));",
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

console.log("Injected the isolated runtime regression test and enabled SDK test helpers.");
