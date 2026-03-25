#!/bin/sh
set -eu

ROOT_DIR=$(
  CDPATH= cd -- "$(dirname -- "$0")/.." && pwd
)
cd "$ROOT_DIR"

if [ "${1:-}" = "" ]; then
  echo "Usage: scripts/release.sh <version>"
  echo "Example: scripts/release.sh 1.1.0-beta.49"
  exit 1
fi

VERSION="${1#v}"
TAG="v${VERSION}"
REPO="iylmwysst/CodeWebway"
TOOLCHAIN="stable-x86_64-apple-darwin"
RUSTC_BIN="$(rustup which rustc --toolchain "$TOOLCHAIN")"
ZIG_LOCAL_CACHE_DIR="$ROOT_DIR/dist/.zig-cache"
ZIG_GLOBAL_CACHE_DIR="$ROOT_DIR/dist/.zig-global-cache"
APPLE_TARGETS="aarch64-apple-darwin x86_64-apple-darwin"
MUSL_TARGETS="aarch64-unknown-linux-musl x86_64-unknown-linux-musl"

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is required"
  exit 1
fi

if ! command -v rustup >/dev/null 2>&1; then
  echo "rustup is required"
  exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "gh is required"
  exit 1
fi

if ! command -v cargo-zigbuild >/dev/null 2>&1; then
  echo "cargo-zigbuild is required for linux-musl release assets"
  exit 1
fi

if git rev-parse "$TAG" >/dev/null 2>&1; then
  echo "Tag already exists: $TAG"
  exit 1
fi

run_cargo() {
  RUSTC="$RUSTC_BIN" rustup run "$TOOLCHAIN" cargo "$@"
}

run_zigbuild() {
  target="$1"
  RUSTC="$RUSTC_BIN" \
  ZIG_LOCAL_CACHE_DIR="$ZIG_LOCAL_CACHE_DIR" \
  ZIG_GLOBAL_CACHE_DIR="$ZIG_GLOBAL_CACHE_DIR" \
  cargo-zigbuild zigbuild --release --target "$target"
}

perl -0pi -e 's/^version = ".*?"$/version = "'"$VERSION"'"/m' Cargo.toml

run_cargo fmt --all
run_cargo test
run_cargo clippy --all-targets -- -D warnings

mkdir -p dist
mkdir -p "$ZIG_LOCAL_CACHE_DIR" "$ZIG_GLOBAL_CACHE_DIR"

for target in $APPLE_TARGETS; do
  run_cargo build --release --target "$target"
  cp "target/$target/release/codewebway" "dist/codewebway-$target"
done

for target in $MUSL_TARGETS; do
  run_zigbuild "$target"
  cp "target/$target/release/codewebway" "dist/codewebway-$target"
done

git add -u
git add Cargo.toml README.md scripts/release.sh

if git diff --cached --quiet; then
  echo "No tracked changes staged for release."
  exit 1
fi

git commit -m "build: release $TAG"
git tag -a "$TAG" -m "$TAG"
git push origin main
git push origin "$TAG"
gh release create "$TAG" \
  dist/codewebway-aarch64-apple-darwin \
  dist/codewebway-x86_64-apple-darwin \
  dist/codewebway-aarch64-unknown-linux-musl \
  dist/codewebway-x86_64-unknown-linux-musl \
  --repo "$REPO" \
  --title "$TAG" \
  --generate-notes
