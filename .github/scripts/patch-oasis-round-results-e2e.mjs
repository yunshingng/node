import fs from "node:fs";

const file = process.argv[2];
if (!file) {
  console.error("Usage: node patch-oasis-round-results-e2e.mjs <path-to-runtime-sdk/src/dispatcher.rs>");
  process.exit(2);
}

const source = fs.readFileSync(file, "utf8");
const anchor = ["    #[test]", "    fn test_allowed_queries_defaults()"].join("\n");
if (source.split(anchor).length !== 2) {
  throw new Error("Expected exactly one dispatcher test insertion point; refusing to patch unexpected source.");
}

const regressionTest = String.raw`
    // Exercises the actual SDK block-begin message-result dispatcher.
    // The consensus MKVS is fixed to a failed staking transfer (code=1), while
    // the independently supplied RuntimeBatchContext.round_results can be changed.
    type RoundResultsAccounts = Accounts;
    type RoundResultsConsensus = crate::modules::consensus::Module;
    type RoundResultsConsensusAccounts =
        crate::modules::consensus_accounts::Module<RoundResultsConsensus>;

    struct RoundResultsRuntime;

    impl crate::runtime::Runtime for RoundResultsRuntime {
        const VERSION: Version = Version::new(0, 0, 0);

        type Core = Core;
        type Accounts = Accounts;
        type Modules = (
            Core,
            Accounts,
            RoundResultsConsensus,
            RoundResultsConsensusAccounts,
        );

        fn genesis_state() -> <Self::Modules as crate::module::MigrationHandler>::Genesis {
            (
                crate::modules::core::Genesis::default(),
                crate::modules::accounts::Genesis::default(),
                crate::modules::consensus::Genesis::default(),
                crate::modules::consensus_accounts::Genesis::default(),
            )
        }
    }

    fn round_results_test_event(
        code: u32,
    ) -> oasis_core_runtime::consensus::roothash::MessageEvent {
        oasis_core_runtime::consensus::roothash::MessageEvent {
            module: "staking".to_string(),
            code,
            index: 0,
            result: None,
        }
    }

    fn run_round_results_financial_case(
        host_supplied_code: u32,
    ) -> (
        u128,
        u128,
        u128,
        oasis_core_runtime::common::crypto::hash::Hash,
    ) {
        use oasis_core_runtime::{
            common::{crypto::hash::Hash, namespace::Namespace},
            consensus::{
                roothash,
                state::{roothash::ImmutableState, ConsensusState},
            },
            storage::mkvs::{self, MKVS as _},
        };
        use crate::{
            modules::accounts::API as _,
            state::{CurrentState, Options, TransactionResult},
            storage::MKVSStore,
            testing::mock::Mock,
            types::{
                message::MessageEventHookInvocation,
                token::{BaseUnits, Denomination},
            },
        };
        use std::str::FromStr;

        let mut mock = Mock::default();
        let runtime_id = mock.host_info.runtime_id;

        // Build a real MKVS fixture containing the authoritative value under
        // 0x27 || SHA256(runtime_id), the key used by Core LastRoundResultsKeyFmt.
        let authoritative = roothash::RoundResults {
            messages: vec![round_results_test_event(1)], // consensus says failure.
            ..Default::default()
        };
        let mut consensus_tree = mkvs::Tree::builder()
            .with_root_type(mkvs::RootType::State)
            .build(Box::new(mkvs::sync::NoopReadSyncer));
        let mut authoritative_key = vec![0x27];
        authoritative_key.extend_from_slice(
            Hash::digest_bytes(runtime_id.as_ref()).as_ref(),
        );
        consensus_tree
            .insert(&authoritative_key, &cbor::to_vec(authoritative.clone()))
            .expect("insert authoritative last_round_results");
        let _consensus_root = consensus_tree
            .commit(Namespace::default(), 1)
            .expect("commit authoritative consensus MKVS");
        mock.consensus_state = ConsensusState::new(1, consensus_tree);

        // Read the stored value back using Core's actual RoothashState accessor.
        let authenticated = ImmutableState::new(&mock.consensus_state)
            .last_round_results(runtime_id)
            .expect("read authoritative last_round_results");
        assert_eq!(authenticated, authoritative);

        // This is the independent value passed to the SDK through RuntimeExecuteTxBatchRequest.
        // For the forged run, only MessageEvent.code changes from failure to success.
        mock.runtime_round_results = roothash::RoundResults {
            messages: vec![round_results_test_event(host_supplied_code)],
            ..Default::default()
        };
        assert_ne!(
            mock.runtime_round_results,
            authenticated,
            "host input must differ from the authoritative consensus-state value"
        );

        let ctx = mock.create_ctx_for_runtime::<RoundResultsRuntime>(false);
        let denomination = Denomination::from_str("TEST").unwrap();
        let amount = BaseUnits::new(1_000, denomination.clone());
        let pending = *crate::modules::consensus_accounts::ADDRESS_PENDING_WITHDRAWAL;
        let alice = crate::testing::keys::alice::address();
        let bob = crate::testing::keys::bob::address();

        let transfer_context =
            crate::modules::consensus_accounts::types::ConsensusTransferContext {
                to: bob,
                nonce: 77,
                address: alice,
                amount: amount.clone(),
            };
        let hook = MessageEventHookInvocation::new(
            "consensus.TransferFromRuntime".to_string(),
            transfer_context,
        );

        // Run against an isolated real Runtime MKVS overlay.
        let runtime_tree = mkvs::Tree::builder()
            .with_root_type(mkvs::RootType::State)
            .build(Box::new(mkvs::sync::NoopReadSyncer));
        let mut runtime_overlay = mkvs::OverlayTree::new(runtime_tree);
        let mut runtime_store = MKVSStore::new(&mut runtime_overlay);

        let (alice_balance, pending_balance, total_supply) =
            CurrentState::enter(&mut runtime_store, || {
                RoundResultsRuntime::migrate(&ctx);

                // Set up a prior-round withdrawal: Alice's 1,000 TEST is escrowed
                // in the pending-withdrawal module account and the result hook is stored.
                CurrentState::with_transaction_opts(Options::new(), || {
                    RoundResultsAccounts::mint(alice, &amount)
                        .expect("fund Alice");
                    RoundResultsAccounts::transfer(alice, pending, &amount)
                        .expect("lock pending withdrawal");
                    Dispatcher::<RoundResultsRuntime>::save_emitted_message_handlers(vec![hook]);
                    TransactionResult::Commit(())
                });

                // Execute the same internal result-dispatch method called at batch start.
                CurrentState::with_transaction_opts(Options::new(), || {
                    Dispatcher::<RoundResultsRuntime>::handle_last_round_messages(&ctx)
                        .expect("dispatch previous-round message result");
                    TransactionResult::Commit(())
                });

                let alice_balance = RoundResultsAccounts::get_balance(alice, denomination.clone())
                    .expect("read Alice balance");
                let pending_balance =
                    RoundResultsAccounts::get_balance(pending, denomination.clone())
                        .expect("read pending-withdrawal balance");
                let total_supply = RoundResultsAccounts::get_total_supplies()
                    .expect("read total supplies")
                    .get(&denomination)
                    .copied()
                    .unwrap_or_default();

                (alice_balance, pending_balance, total_supply)
            });

        // Commit and hash the post-execution Runtime state.
        drop(runtime_store);
        let (_write_log, runtime_state_root) = runtime_overlay
            .commit(Namespace::default(), 2)
            .expect("commit post-execution Runtime MKVS");

        // The authenticated consensus value must remain unchanged by Runtime execution.
        assert_eq!(
            ImmutableState::new(&mock.consensus_state)
                .last_round_results(runtime_id)
                .expect("re-read authoritative results"),
            authoritative
        );

        (
            alice_balance,
            pending_balance,
            total_supply,
            runtime_state_root,
        )
    }

    #[test]
    fn test_host_forged_round_results_change_consensus_accounts_state() {
        // Honest execution: host-supplied event matches the authoritative failure.
        let honest = run_round_results_financial_case(1);

        // Forged execution: same consensus MKVS, but host-supplied event says success.
        let forged = run_round_results_financial_case(0);

        // The failure path refunds Alice's locked withdrawal.
        assert_eq!(honest.0, 1_000, "authoritative failure must refund Alice");
        assert_eq!(honest.1, 0, "failure must clear pending-withdrawal balance");
        assert_eq!(honest.2, 1_000, "failure must preserve total supply");

        // The forged success path burns the pending withdrawal instead of refunding it.
        assert_eq!(forged.0, 0, "forged success must leave Alice without her refund");
        assert_eq!(forged.1, 0, "forged success must burn pending withdrawal");
        assert_eq!(forged.2, 0, "forged success must burn 1,000 TEST from supply");

        assert_ne!(
            honest.3,
            forged.3,
            "different financial transitions must produce different Runtime state roots"
        );

        println!(
            "authoritative_code=1 host_forged_code=0 honest_alice={} forged_alice={} honest_supply={} forged_supply={} honest_state_root={:?} forged_state_root={:?}",
            honest.0, forged.0, honest.2, forged.2, honest.3, forged.3
        );
    }

`;

fs.writeFileSync(file, source.replace(anchor, regressionTest + "\n" + anchor));
console.log("Injected round-results consensus-MKVS and financial state-root regression test.");
