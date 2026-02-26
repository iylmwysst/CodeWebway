#!/bin/sh
set -e

REPO="iylmwysst/remote-CLI-for-AI-Agent"
BIN="rust-webtty"
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

# Get latest release tag
echo "Fetching latest release..."
TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep '"tag_name"' | sed 's/.*"tag_name": "\(.*\)".*/\1/')

if [ -z "$TAG" ]; then
  echo "Could not find a release. Make sure the repo has published releases."
  exit 1
fi

DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${TAG}/${BIN}-${TARGET}"

echo "Installing ${BIN} ${TAG} for ${TARGET}..."

# Create install dir
mkdir -p "${INSTALL_DIR}"

# Download binary (GitHub redirects to signed CDN URL, use -L without -f)
curl -sSL --retry 3 --retry-delay 2 "${DOWNLOAD_URL}" -o "${INSTALL_DIR}/${BIN}"

if [ ! -s "${INSTALL_DIR}/${BIN}" ]; then
  echo "Error: Download failed or file is empty."
  echo "Try manually: ${DOWNLOAD_URL}"
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
