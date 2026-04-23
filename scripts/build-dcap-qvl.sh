#!/usr/bin/env bash
# Build a local dcap-qvl binary from a pinned upstream commit and install it
# into ./bin/<platform>-<arch>/.
#
# Why from source?  The extension's `tdx` facet goes ✓ only when dcap-qvl
# verifies the TDX quote locally against Intel's root of trust (baked into
# the dcap-qvl binary). If we shipped a pre-built binary in the repo, an
# attacker who tampered with the repo could replace it with a backdoor that
# outputs "Quote verified" for any quote — silently faking ✓ on `tdx`, the
# single largest attack surface of this extension. By building from a
# pinned upstream source commit, trust reduces to:
#   1. your Rust toolchain
#   2. the pinned Phala-Network/dcap-qvl commit (shown below — verify on GitHub)
#   3. the crates.io dependencies resolved by Cargo.lock in that commit
#
# Reference: https://github.com/nicola/pi-phala-tee/issues/2

set -euo pipefail

# Pinned to dcap-qvl v0.4.0 + one post-release patch that was active when the
# extension was last audited. Bump intentionally after reviewing the diff.
DCAP_QVL_REPO="https://github.com/Phala-Network/dcap-qvl.git"
DCAP_QVL_COMMIT="c5990615c01ae77fd2f6981f1f8c6b7c7ae9bdb9"

# Resolve paths
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXT_ROOT="$(cd "$HERE/.." && pwd)"
BIN_DIR_ROOT="$EXT_ROOT/bin"

# Detect platform/arch in the same keys src/tdxLocal.ts uses.
case "$(uname -s)" in
	Darwin) plat="darwin" ;;
	Linux)  plat="linux" ;;
	MINGW*|MSYS*|CYGWIN*) plat="win32" ;;
	*) echo "unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
	arm64|aarch64) arch="arm64" ;;
	x86_64|amd64)  arch="x64" ;;
	*) echo "unsupported arch: $(uname -m)" >&2; exit 1 ;;
esac

target_dir="$BIN_DIR_ROOT/${plat}-${arch}"
target_bin="$target_dir/dcap-qvl"
[ "$plat" = "win32" ] && target_bin="$target_dir/dcap-qvl.exe"

echo "==> Building dcap-qvl for ${plat}-${arch}"
echo "    commit: $DCAP_QVL_COMMIT"
echo "    dest:   $target_bin"
echo

if ! command -v cargo >/dev/null 2>&1; then
	echo "error: cargo not found. Install Rust: https://rustup.rs/" >&2
	exit 1
fi

# Work in a clean temp dir so we never contaminate extension state.
work="$(mktemp -d -t phala-tee-dcap-qvl-XXXXXX)"
trap 'rm -rf "$work"' EXIT

echo "==> Cloning $DCAP_QVL_REPO"
git -C "$work" init -q
git -C "$work" remote add origin "$DCAP_QVL_REPO"
git -C "$work" fetch -q --depth 1 origin "$DCAP_QVL_COMMIT"
git -C "$work" -c advice.detachedHead=false checkout -q FETCH_HEAD

echo "==> cargo build --release (this takes 1-2 minutes)"
# Stay inside the CLI workspace to avoid pulling non-CLI targets.
(cd "$work/cli" && cargo build --release --quiet)

src="$work/cli/target/release/dcap-qvl"
[ "$plat" = "win32" ] && src="$work/cli/target/release/dcap-qvl.exe"
if [ ! -f "$src" ]; then
	echo "error: build succeeded but $src is missing" >&2
	exit 1
fi

mkdir -p "$target_dir"
cp "$src" "$target_bin"
chmod 755 "$target_bin"

# Emit the SHA-256 so users can record / compare across builds.
if command -v shasum >/dev/null 2>&1; then
	digest="$(shasum -a 256 "$target_bin" | awk '{print $1}')"
elif command -v sha256sum >/dev/null 2>&1; then
	digest="$(sha256sum "$target_bin" | awk '{print $1}')"
else
	digest="(no sha256 tool found)"
fi

echo
echo "==> Installed: $target_bin"
echo "    sha256:    $digest"
echo
echo "Now (re)start pi or run /reload. The 'tdx' facet should show ✓ on"
echo "verified Phala turns."
