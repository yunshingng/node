import fs from "node:fs";

const file = process.argv[2];
if (!file) {
  console.error("Usage: node patch-oasis-core-quorum-e2e.mjs <path-to-pool_test.go>");
  process.exit(2);
}

let source = fs.readFileSync(file, "utf8");
const importAnchor = '\t"github.com/oasisprotocol/oasis-core/go/common"\n';
if (!source.includes(importAnchor)) {
  throw new Error("Expected common import anchor was not found.");
}
if (!source.includes('\t"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"\n')) {
  source = source.replace(importAnchor, importAnchor + '\t"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"\n');
}

const anchor = "func TestVerify(t *testing.T) {";
if (source.split(anchor).length !== 2) {
  throw new Error("Expected exactly one TestVerify insertion point; refusing to patch unexpected source.");
}

const tests = [
  "func TestPoCOneCompromisedSchedulerCanFinalizeWithOneAllowedStraggler(t *testing.T) {",
  "    // Valid config: GroupSize 2, one backup, one allowed straggler.",
  "    params := registry.ExecutorParameters{GroupSize: 2, GroupBackupSize: 1, AllowedStragglers: 1, RoundTimeout: 1}",
  "    require.NoError(t, params.ValidateBasic())",
  "    committee, err := generateCommittee(3, 2, 1)",
  "    require.NoError(t, err)",
  "    var id common.Namespace",
  "    lastBlock := block.NewGenesisBlock(id, 0)",
  "    // Round 1 primary scheduler is worker index 1: (1 + 1) % 2 == 0.",
  "    schedulerID := committee.Members[1].PublicKey",
  "    rank, ok := committee.SchedulerRank(1, schedulerID)",
  "    require.True(t, ok)",
  "    require.Equal(t, uint64(0), rank)",
  "    forgedStateRoot := hash.NewFromBytes([]byte(\"forged-state-root-from-host-supplied-round-results\"))",
  "    forged := generateMemberCommitment(committee, lastBlock, 1, 1)",
  "    forged.Header.Header.StateRoot = &forgedStateRoot",
  "    pool := NewPool()",
  "    require.NoError(t, pool.AddVerifiedExecutorCommitment(committee, forged))",
  "    // The other worker is the allowed straggler: the lone scheduler commitment is accepted.",
  "    accepted, err := pool.ProcessCommitments(committee, params.AllowedStragglers, true)",
  "    require.NoError(t, err)",
  "    require.NotNil(t, accepted)",
  "    require.Equal(t, forged, accepted.Commitment)",
  "    require.Equal(t, forgedStateRoot, *accepted.Commitment.Header.Header.StateRoot)",
  "    require.Len(t, accepted.Votes, 1)",
  "    t.Logf(\"accepted_state_root=%s votes=%d group_size=%d allowed_stragglers=%d\", accepted.Commitment.Header.Header.StateRoot, len(accepted.Votes), params.GroupSize, params.AllowedStragglers)",
  "}",
  "",
  "func TestPoCSingleForgedSchedulerDoesNotFinalizeWithThreeWorkersOneStraggler(t *testing.T) {",
  "    // This uses the 3-worker / 5-backup / 1-straggler fixture pattern in Core tests.",
  "    params := registry.ExecutorParameters{GroupSize: 3, GroupBackupSize: 5, AllowedStragglers: 1, RoundTimeout: 1}",
  "    require.NoError(t, params.ValidateBasic())",
  "    committee, err := generateCommittee(8, 3, 5)",
  "    require.NoError(t, err)",
  "    var id common.Namespace",
  "    lastBlock := block.NewGenesisBlock(id, 0)",
  "    lastBlock.Header.Round = 2 // Next round is 3; worker index 0 is primary scheduler.",
  "    forgedRoot := hash.NewFromBytes([]byte(\"forged-state-root-from-compromised-host\"))",
  "    forged := generateMemberCommitment(committee, lastBlock, 0, 0)",
  "    forged.Header.Header.StateRoot = &forgedRoot",
  "    pool := NewPool()",
  "    require.NoError(t, pool.AddVerifiedExecutorCommitment(committee, forged))",
  "    accepted, err := pool.ProcessCommitments(committee, params.AllowedStragglers, true)",
  "    require.ErrorIs(t, err, ErrDiscrepancyDetected)",
  "    require.Nil(t, accepted)",
  "    require.True(t, pool.Discrepancy)",
  "    // Three honest backups submit the same authenticated-root result.",
  "    honestRoot := hash.NewFromBytes([]byte(\"honest-state-root-from-authenticated-round-results\"))",
  "    for i := 3; i < 6; i++ {",
  "        honest := generateMemberCommitment(committee, lastBlock, i, 0)",
  "        honest.Header.Header.StateRoot = &honestRoot",
  "        require.NoError(t, pool.AddVerifiedExecutorCommitment(committee, honest))",
  "    }",
  "    accepted, err = pool.ProcessCommitments(committee, params.AllowedStragglers, false)",
  "    require.ErrorIs(t, err, ErrBadSchedulerCommitment)",
  "    require.Nil(t, accepted)",
  "    t.Logf(\"forged_root=%s honest_backup_root=%s backup_votes=3 result=ErrBadSchedulerCommitment\", forged.Header.Header.StateRoot, honestRoot)",
  "}",
  "func TestPoCSingleForgedSchedulerDoesNotFinalizeWithSapphireMainnetCommittee(t *testing.T) {",
  "    // Sapphire Mainnet example descriptor: 5 workers, 7 backups, 1 allowed straggler.",
  "    params := registry.ExecutorParameters{GroupSize: 5, GroupBackupSize: 7, AllowedStragglers: 1, RoundTimeout: 2}",
  "    require.NoError(t, params.ValidateBasic())",
  "    committee, err := generateCommittee(12, 5, 7)",
  "    require.NoError(t, err)",
  "    var id common.Namespace",
  "    lastBlock := block.NewGenesisBlock(id, 0)",
  "    lastBlock.Header.Round = 4 // Next round is 5; worker index 0 is the primary scheduler.",
  "    forgedRoot := hash.NewFromBytes([]byte(\"forged-root-from-one-compromised-Sapphire-worker\"))",
  "    forged := generateMemberCommitment(committee, lastBlock, 0, 0)",
  "    forged.Header.Header.StateRoot = &forgedRoot",
  "    pool := NewPool()",
  "    require.NoError(t, pool.AddVerifiedExecutorCommitment(committee, forged))",
  "    accepted, err := pool.ProcessCommitments(committee, params.AllowedStragglers, true)",
  "    require.ErrorIs(t, err, ErrDiscrepancyDetected)",
  "    require.Nil(t, accepted)",
  "    require.True(t, pool.Discrepancy)",
  "    // Four honest backup votes meet the 7-member backup majority (4/7).",
  "    honestRoot := hash.NewFromBytes([]byte(\"honest-root-from-authenticated-RoundResults\"))",
  "    for i := 5; i < 9; i++ {",
  "        honest := generateMemberCommitment(committee, lastBlock, i, 0)",
  "        honest.Header.Header.StateRoot = &honestRoot",
  "        require.NoError(t, pool.AddVerifiedExecutorCommitment(committee, honest))",
  "    }",
  "    accepted, err = pool.ProcessCommitments(committee, params.AllowedStragglers, false)",
  "    require.ErrorIs(t, err, ErrBadSchedulerCommitment)",
  "    require.Nil(t, accepted)",
  "    t.Logf(\"Sapphire 5/7/1: one forged primary rejected by 4 honest backups; forged_root=%s honest_root=%s\", forged.Header.Header.StateRoot, honestRoot)",
  "}",
  ""
].join("\n");

fs.writeFileSync(file, source.replace(anchor, tests + "\n" + anchor));
console.log("Injected Core commitment-pool acceptance/rejection tests for forged Runtime roots.");
