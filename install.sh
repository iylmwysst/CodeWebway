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
      armv7l)  TARGET="aarch64-unknown-linux-musl" ;;
      *) echo "Unsupported architecture: ${ARCH}"; exit 1 ;;
    esac
    ;;
  *)
    echo "Unsupported OS: ${OS}"
    echo "Download manually from: https://github.com/${REPO}/releases"
    exit 1
    ;;
esac

# Get latest published release
echo "Fetching latest release..."
RELEASE_JSON=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest")
TAG=$(printf "%s\n" "${RELEASE_JSON}" \
  | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' \
  | head -n1 \
  | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)"/\1/')

if [ -z "$TAG" ]; then
  echo "Error: could not find any release."
  echo "Check: https://github.com/${REPO}/releases"
  exit 1
fi

DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${TAG}/${BIN}-${TARGET}"

echo "Installing ${BIN} ${TAG} for ${TARGET}..."

# Create install dir
mkdir -p "${INSTALL_DIR}"

# Download binary
curl -fsSL --retry 3 --retry-delay 2 \
  -L "${DOWNLOAD_URL}" -o "${INSTALL_DIR}/${BIN}"

if [ ! -s "${INSTALL_DIR}/${BIN}" ]; then
  echo "Error: download failed or file is empty."
  echo "Try manually: ${DOWNLOAD_URL}"
  exit 1
fi

chmod +x "${INSTALL_DIR}/${BIN}"

# macOS: remove Gatekeeper quarantine
if [ "${OS}" = "Darwin" ]; then
  xattr -dr com.apple.quarantine "${INSTALL_DIR}/${BIN}" 2>/dev/null || true
fi

echo ""
echo "  ✓ Installed ${BIN} ${TAG} → ${INSTALL_DIR}/${BIN}"
echo ""

# Ensure INSTALL_DIR is in PATH
case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) ;;
  *)
    case "${SHELL}" in
      */zsh)  PROFILE="${HOME}/.zshrc" ;;
      */bash) PROFILE="${HOME}/.bashrc" ;;
      *)      PROFILE="${HOME}/.profile" ;;
    esac

    EXPORT_LINE="export PATH=\"\$HOME/.local/bin:\$PATH\""

    if ! grep -qF '.local/bin' "${PROFILE}" 2>/dev/null; then
      printf '\n# codewebway\n%s\n' "${EXPORT_LINE}" >> "${PROFILE}" 2>/dev/null && \
        echo "  PATH updated in ${PROFILE} — run: source ${PROFILE}" || \
        echo "  Add to your shell profile: ${EXPORT_LINE}"
    fi
    ;;
esac

echo "  Next steps:"
echo "    codewebway enable <token-from-dashboard>"
echo "    codewebway fleet"
echo ""
