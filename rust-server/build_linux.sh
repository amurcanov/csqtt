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
rustup target add x86_64-unknown-linux-musl --toolchain 1.97.1
rustc +1.97.1 --version
zig version
WRAP="$ROOT/build/zig-wrappers"
mkdir -p "$WRAP"
HOST="$(rustc +1.97.1 -vV | sed -n 's/^host: //p')"
if [[ "$HOST" == *windows* ]]; then
cat > "$WRAP/zigcc.ps1" <<'PS1'
$filtered = @($args | Where-Object { $_ -ne "--target=x86_64-unknown-linux-musl" })
& zig cc -target x86_64-linux-musl @filtered
exit $LASTEXITCODE
PS1
cat > "$WRAP/zigcxx.ps1" <<'PS1'
$filtered = @($args | Where-Object { $_ -ne "--target=x86_64-unknown-linux-musl" })
& zig c++ -target x86_64-linux-musl @filtered
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
  [[ "$arg" == "--target=x86_64-unknown-linux-musl" ]] || args+=("$arg")
done
exec zig cc -target x86_64-linux-musl "${args[@]}"
SH
cat > "$WRAP/zigcxx" <<'SH'
#!/usr/bin/env bash
args=()
for arg in "$@"; do
  [[ "$arg" == "--target=x86_64-unknown-linux-musl" ]] || args+=("$arg")
done
exec zig c++ -target x86_64-linux-musl "${args[@]}"
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
CARGO_TARGET_DIR="$ROOT/build/linux-musl" cargo +1.97.1 zigbuild --release --target x86_64-unknown-linux-musl "${FEATURE_ARGS[@]}"
mkdir -p "$ROOT/dist"
cp "$ROOT/build/linux-musl/x86_64-unknown-linux-musl/release/csqtt" "$ROOT/dist/csqtt"
ls -lh "$ROOT/dist/csqtt"
