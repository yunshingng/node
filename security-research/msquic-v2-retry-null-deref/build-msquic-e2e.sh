#!/usr/bin/env bash
set -Eeuo pipefail
sudo apt-get update
sudo apt-get install -y build-essential cmake perl zlib1g-dev libnuma-dev openssl python3 gdb tcpdump curl jq
curl -fsSL https://dot.net/v1/dotnet-install.sh -o "$RUNNER_TEMP/dotnet-install.sh"
bash "$RUNNER_TEMP/dotnet-install.sh" --runtime dotnet --version 10.0.15 --install-dir "$DOTNET_ROOT"
git clone --depth 1 --branch main --recurse-submodules https://github.com/microsoft/msquic.git "$RUNNER_TEMP/msquic"
test "$(git -C "$RUNNER_TEMP/msquic" rev-parse HEAD)" = "aa31c3f8641934653a8acfe5f4d22b2465b7d509"
cmake -S "$RUNNER_TEMP/msquic" -B "$RUNNER_TEMP/msquic/build" \
  -DCMAKE_BUILD_TYPE=Release -DQUIC_BUILD_SHARED=ON \
  -DQUIC_BUILD_TOOLS=OFF -DQUIC_BUILD_TEST=OFF -DQUIC_ENABLE_LOGGING=OFF
cmake --build "$RUNNER_TEMP/msquic/build" --parallel 2
echo "MSQUIC_LIB_DIR=$RUNNER_TEMP/msquic/build/bin/Release" >> "$GITHUB_ENV"
echo "DOTNET_ROLL_FORWARD=LatestPatch" >> "$GITHUB_ENV"
dotnet build security-research/msquic-v2-retry-null-deref/MsQuicRetryE2E.csproj --configuration Release
dotnet --list-runtimes
dotnet security-research/msquic-v2-retry-null-deref/bin/Release/net10.0/MsQuicRetryE2E.dll --check-runtime
