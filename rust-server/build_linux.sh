#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 amurcanov
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
RUN_CHECKS=""
DIAGNOSTICS=0
while (($#)); do
  case "$1" in
    --tests) RUN_CHECKS=1 ;;
    --no-tests) RUN_CHECKS=0 ;;
    --diagnostics) DIAGNOSTICS=1 ;;
    *) echo "Usage: $0 [--tests|--no-tests] [--diagnostics]" >&2; exit 2 ;;
  esac
  shift
done
if [[ -z "$RUN_CHECKS" ]]; then
  if [[ -t 0 ]]; then
    read -rp "Запустить проверки и тесты (или их кросс-компиляцию) перед сборкой? [Y/n]: " REPLY
    case "$REPLY" in
      [nN]|[nN][oO]|[нН]|[нН][eE][тТ]) RUN_CHECKS=0 ;;
      *) RUN_CHECKS=1 ;;
    esac
  else
    RUN_CHECKS=1
  fi
fi
FEATURE_ARGS=()
if [[ "$DIAGNOSTICS" == 1 ]]; then
  FEATURE_ARGS=(--features diagnostics)
fi
command -v cargo >/dev/null
command -v rustup >/dev/null
command -v zig >/dev/null
cargo zigbuild --help >/dev/null
rustup toolchain install 1.97.1 --profile minimal --component rustfmt --component clippy
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl armv7-unknown-linux-musleabihf --toolchain 1.97.1
rustc +1.97.1 --version
zig version
WRAP="$ROOT/build/zig-wrappers"
mkdir -p "$WRAP"
HOST="$(rustc +1.97.1 -vV | sed -n 's/^host: //p')"
if [[ "$HOST" == *windows* ]]; then
cat > "$WRAP/zigcc.ps1" <<'PS1'
$filtered = @($args | Where-Object { $_ -notlike "--target=*" })
& zig cc -target $env:CSQTT_ZIG_TARGET @filtered
exit $LASTEXITCODE
PS1
cat > "$WRAP/zigcxx.ps1" <<'PS1'
$filtered = @($args | Where-Object { $_ -notlike "--target=*" })
& zig c++ -target $env:CSQTT_ZIG_TARGET @filtered
exit $LASTEXITCODE
PS1
cat > "$WRAP/zigcc.cmd" <<'CMD'
@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0zigcc.ps1" %*
CMD
cat > "$WRAP/zigcxx.cmd" <<'CMD'
@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0zigcxx.ps1" %*
CMD
cat > "$WRAP/zigar.cmd" <<'CMD'
@echo off
zig ar %*
CMD
CC_WRAPPER="$WRAP/zigcc.cmd"
CXX_WRAPPER="$WRAP/zigcxx.cmd"
AR_WRAPPER="$WRAP/zigar.cmd"
else
cat > "$WRAP/zigcc" <<'SH'
#!/usr/bin/env bash
args=()
for arg in "$@"; do
  [[ "$arg" == --target=* ]] || args+=("$arg")
done
exec zig cc -target "$CSQTT_ZIG_TARGET" "${args[@]}"
SH
cat > "$WRAP/zigcxx" <<'SH'
#!/usr/bin/env bash
args=()
for arg in "$@"; do
  [[ "$arg" == --target=* ]] || args+=("$arg")
done
exec zig c++ -target "$CSQTT_ZIG_TARGET" "${args[@]}"
SH
cat > "$WRAP/zigar" <<'SH'
#!/usr/bin/env bash
exec zig ar "$@"
SH
chmod +x "$WRAP/zigcc" "$WRAP/zigcxx" "$WRAP/zigar"
CC_WRAPPER="$WRAP/zigcc"
CXX_WRAPPER="$WRAP/zigcxx"
AR_WRAPPER="$WRAP/zigar"
fi
export CC_x86_64_unknown_linux_musl="$CC_WRAPPER"
export CXX_x86_64_unknown_linux_musl="$CXX_WRAPPER"
export AR_x86_64_unknown_linux_musl="$AR_WRAPPER"
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="$CC_WRAPPER"
export CC_aarch64_unknown_linux_musl="$CC_WRAPPER"
export CXX_aarch64_unknown_linux_musl="$CXX_WRAPPER"
export AR_aarch64_unknown_linux_musl="$AR_WRAPPER"
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$CC_WRAPPER"
export CC_armv7_unknown_linux_musleabihf="$CC_WRAPPER"
export CXX_armv7_unknown_linux_musleabihf="$CXX_WRAPPER"
export AR_armv7_unknown_linux_musleabihf="$AR_WRAPPER"
export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_LINKER="$CC_WRAPPER"
export CSQTT_ZIG_TARGET=x86_64-linux-musl
if [[ "$RUN_CHECKS" == 1 ]]; then
  cargo +1.97.1 fmt --all -- --check
  cargo +1.97.1 zigbuild --all-targets --target x86_64-unknown-linux-musl "${FEATURE_ARGS[@]}"
  CARGO_TARGET_DIR="$ROOT/build/linux-musl-check" cargo +1.97.1 clippy --release --target x86_64-unknown-linux-musl "${FEATURE_ARGS[@]}" --all-targets -- -D warnings
  if [[ "$HOST" == *linux* ]]; then
    echo "Running Linux musl tests..."
    CARGO_TARGET_DIR="$ROOT/build/linux-musl-tests" cargo +1.97.1 test --target x86_64-unknown-linux-musl "${FEATURE_ARGS[@]}" --all-targets
  else
    echo "Compiling Linux musl test binaries (they cannot run on this non-Linux host)..."
    CARGO_TARGET_DIR="$ROOT/build/linux-musl-tests" cargo +1.97.1 zigbuild --target x86_64-unknown-linux-musl "${FEATURE_ARGS[@]}" --tests
  fi
fi
build_variant() {
  local target="$1" zig_target="$2" asset="$3"
  CSQTT_ZIG_TARGET="$zig_target" \
    ZIG_GLOBAL_CACHE_DIR="$ROOT/build/zig-cache/$asset/global" \
    ZIG_LOCAL_CACHE_DIR="$ROOT/build/zig-cache/$asset/local" \
    CARGO_TARGET_DIR="$ROOT/build/linux-musl" \
    cargo +1.97.1 zigbuild --release --target "$target" "${FEATURE_ARGS[@]}"
  mkdir -p "$ROOT/dist" "$ROOT/../app/src/main/assets"
  cp "$ROOT/build/linux-musl/$target/release/csqtt" "$ROOT/dist/$asset"
  cp "$ROOT/build/linux-musl/$target/release/csqtt" "$ROOT/../app/src/main/assets/$asset"
  ls -lh "$ROOT/dist/$asset"
}
build_variant x86_64-unknown-linux-musl x86_64-linux-musl csqtt-linux-amd64
build_variant aarch64-unknown-linux-musl aarch64-linux-musl csqtt-linux-arm64
build_variant armv7-unknown-linux-musleabihf armv7-linux-musleabihf csqtt-linux-armv7
rm -f "$ROOT/../app/src/main/assets/csqtt"
if command -v pwsh >/dev/null; then
  pwsh -NoProfile -File "$ROOT/../scripts/server_asset_provenance.ps1" -Mode Write
  pwsh -NoProfile -File "$ROOT/../scripts/server_asset_provenance.ps1" -Mode Verify
elif command -v powershell.exe >/dev/null; then
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$(wslpath -w "$ROOT/../scripts/server_asset_provenance.ps1")" -Mode Write
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$(wslpath -w "$ROOT/../scripts/server_asset_provenance.ps1")" -Mode Verify
else
  echo "Server assets built. Run scripts/server_asset_provenance.ps1 -Mode Write and -Mode Verify before packaging an APK." >&2
  exit 1
fi
