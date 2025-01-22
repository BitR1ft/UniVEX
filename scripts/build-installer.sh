#!/usr/bin/env bash
# build-installer.sh — Bundle install.sh and install-podman.sh with version metadata
# and SHA256 checksums for GitHub Release attachments.
#
# Usage:
#   bash scripts/build-installer.sh [--version <semver>] [--out-dir <path>]
#
# Output files (written to OUT_DIR, default: dist/):
#   install.sh            — Docker-based installer
#   install-podman.sh     — Podman-based installer
#   install.sh.sha256     — SHA256 checksum of install.sh
#   install-podman.sh.sha256 — SHA256 checksum of install-podman.sh
#   checksums.txt         — Combined checksum file (both installers)

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VERSION="${UNIVEX_VERSION:-}"
OUT_DIR="${UNIVEX_OUT_DIR:-${REPO_ROOT}/dist}"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)  VERSION="$2"; shift 2 ;;
        --out-dir)  OUT_DIR="$2";  shift 2 ;;
        -h|--help)
            grep '^#' "${BASH_SOURCE[0]}" | sed 's/^# \?//'
            exit 0
            ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Resolve version from git tag if not provided
# ---------------------------------------------------------------------------
if [[ -z "${VERSION}" ]]; then
    if command -v git &>/dev/null && git -C "${REPO_ROOT}" rev-parse --git-dir &>/dev/null; then
        VERSION="$(git -C "${REPO_ROOT}" describe --tags --abbrev=0 2>/dev/null || echo "dev")"
    else
        VERSION="dev"
    fi
fi

echo "==> Building UniVex installers version=${VERSION}"
echo "    Source: ${REPO_ROOT}/scripts/"
echo "    Output: ${OUT_DIR}/"

# ---------------------------------------------------------------------------
# Create output directory
# ---------------------------------------------------------------------------
mkdir -p "${OUT_DIR}"

# ---------------------------------------------------------------------------
# Helper: embed version and copy installer
# ---------------------------------------------------------------------------
embed_and_copy() {
    local src="$1"
    local dst="$2"
    local name
    name="$(basename "${src}")"

    if [[ ! -f "${src}" ]]; then
        echo "ERROR: source installer not found: ${src}" >&2
        exit 1
    fi

    echo "--> Embedding version ${VERSION} into ${name}"

    # Insert/replace UNIVEX_VERSION variable near the top of the script
    # (after the shebang line) so the installer can self-report its version.
    awk -v ver="${VERSION}" '
        NR == 1 { print; next }
        /^UNIVEX_VERSION=/ { found=1; print "UNIVEX_VERSION=\"" ver "\""; next }
        NR == 2 && !found {
            print "UNIVEX_VERSION=\"" ver "\""
        }
        { print }
    ' "${src}" > "${dst}"

    chmod +x "${dst}"
    echo "    Written: ${dst}"
}

# ---------------------------------------------------------------------------
# Process installers
# ---------------------------------------------------------------------------
embed_and_copy \
    "${REPO_ROOT}/scripts/install.sh" \
    "${OUT_DIR}/install.sh"

embed_and_copy \
    "${REPO_ROOT}/scripts/install-podman.sh" \
    "${OUT_DIR}/install-podman.sh"

# ---------------------------------------------------------------------------
# Generate checksums
# ---------------------------------------------------------------------------
echo "--> Generating SHA256 checksums"

generate_checksum() {
    local file="$1"
    local name
    name="$(basename "${file}")"
    local checksum

    if command -v sha256sum &>/dev/null; then
        checksum="$(sha256sum "${file}" | awk '{print $1}')"
    elif command -v shasum &>/dev/null; then
        checksum="$(shasum -a 256 "${file}" | awk '{print $1}')"
    else
        echo "ERROR: neither sha256sum nor shasum found on PATH" >&2
        exit 1
    fi

    echo "${checksum}  ${name}" > "${file}.sha256"
    echo "    ${name}.sha256: ${checksum}"
    echo "${checksum}  ${name}"
}

# Build combined checksums.txt
{
    generate_checksum "${OUT_DIR}/install.sh"
    generate_checksum "${OUT_DIR}/install-podman.sh"
} > "${OUT_DIR}/checksums.txt"

echo "    Written: ${OUT_DIR}/checksums.txt"

# ---------------------------------------------------------------------------
# Print install instruction that should appear in the GitHub Release body
# ---------------------------------------------------------------------------
cat <<EOF

==> Build complete. Attach the following files to the GitHub Release:
      dist/install.sh
      dist/install.sh.sha256
      dist/install-podman.sh
      dist/install-podman.sh.sha256
      dist/checksums.txt

==> Recommended install command (copy into Release body and README):

    curl -LO https://github.com/BitR1ft/UniVex/releases/latest/download/install.sh
    curl -LO https://github.com/BitR1ft/UniVex/releases/latest/download/install.sh.sha256
    sha256sum -c install.sh.sha256
    bash install.sh

  ⚠️  Do NOT pipe directly to bash without checksum verification.

EOF
