#!/bin/sh
set -e

REPO="iylmwysst/CodeWebway"
BIN="codewebway"
INSTALL_DIR="${HOME}/.local/bin"

# Detect OS and arch
OS="$(uname -s)"
ARCH="$(uname -m)"

case "${OS}" in
  Darwin)
    case "${ARCH}" in
      arm64)  TARGET="aarch64-apple-darwin" ;;
      x86_64) TARGET="x86_64-apple-darwin" ;;
      *) echo "Unsupported architecture: ${ARCH}"; exit 1 ;;
    esac
    ;;
  Linux)
    case "${ARCH}" in
      x86_64)  TARGET="x86_64-unknown-linux-musl" ;;
      aarch64) TARGET="aarch64-unknown-linux-musl" ;;
      *) echo "Unsupported architecture: ${ARCH}"; exit 1 ;;
    esac
    ;;
  *)
    echo "Unsupported OS: ${OS}"
    echo "Windows users: download the .exe from https://github.com/${REPO}/releases"
    exit 1
    ;;
esac

# Get latest release metadata
echo "Fetching latest release..."
RELEASE_JSON=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest")
TAG=$(printf "%s\n" "${RELEASE_JSON}" \
  | grep '"tag_name"' | head -n1 | sed 's/.*"tag_name": "\(.*\)".*/\1/')

if [ -z "$TAG" ]; then
  echo "Could not find a release. Make sure the repo has published releases."
  exit 1
fi

ASSET_NAME="${BIN}-${TARGET}"
ASSET_ID=$(printf "%s\n" "${RELEASE_JSON}" | awk -v target="\"name\": \"${ASSET_NAME}\"" '
  /"id":/ { line=$0; gsub(/[^0-9]/, "", line); if (line != "") id=line }
  $0 ~ target { print id; exit }
')

if [ -z "${ASSET_ID}" ]; then
  echo "Error: release ${TAG} does not contain asset ${ASSET_NAME}"
  echo "Please check: https://github.com/${REPO}/releases/tag/${TAG}"
  exit 1
fi

DOWNLOAD_URL="https://api.github.com/repos/${REPO}/releases/assets/${ASSET_ID}"

echo "Installing ${BIN} ${TAG} for ${TARGET}..."

# Create install dir
mkdir -p "${INSTALL_DIR}"

# Download binary (via API asset endpoint -> redirect to CDN)
curl -fsSL --retry 3 --retry-delay 2 \
  -H "Accept: application/octet-stream" \
  "${DOWNLOAD_URL}" -o "${INSTALL_DIR}/${BIN}"

if [ ! -s "${INSTALL_DIR}/${BIN}" ]; then
  echo "Error: Download failed or file is empty."
  echo "Try manually from: https://github.com/${REPO}/releases/tag/${TAG}"
  exit 1
fi

if head -c 9 "${INSTALL_DIR}/${BIN}" 2>/dev/null | grep -q "Not Found"; then
  echo "Error: downloaded content is not a binary (got Not Found)."
  echo "Release may be missing asset ${ASSET_NAME}."
  exit 1
fi

chmod +x "${INSTALL_DIR}/${BIN}"

echo ""
echo "  Installed: ${INSTALL_DIR}/${BIN}"
echo ""

# Check PATH
case ":${PATH}:" in
  *":${INSTALL_DIR}:"*)
    echo "  Run:  ${BIN}"
    ;;
  *)
    echo "  Add this to your shell profile (~/.zshrc or ~/.bashrc):"
    echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
    echo ""
    echo "  Then run:  ${BIN}"
    ;;
esac
echo ""
