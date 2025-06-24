# UniVex — Package Distribution Guide

This guide explains how UniVex can be made available as a system package (apt/deb, rpm/yum) and as a CLI wrapper via npm. It also covers what is needed to obtain the MIT licence and to publish to the npm registry.

---

## Table of Contents

1. [MIT Licence](#1-mit-licence)
2. [npm — Publishing the CLI Wrapper](#2-npm--publishing-the-cli-wrapper)
3. [apt/deb — Debian/Ubuntu Package](#3-aptdeb--debianubuntu-package)
4. [rpm/yum — RHEL/CentOS/Fedora Package](#4-rpmyum--rhelcentosfedora-package)
5. [Homebrew — macOS](#5-homebrew--macos)
6. [Snap — Universal Linux Package](#6-snap--universal-linux-package)
7. [Release Automation](#7-release-automation)

---

## 1. MIT Licence

The MIT Licence is already included in the repository root as `LICENSE`. No further action is required — the licence is already applied.

If you ever need to re-generate or verify it:
- The [choosealicense.com](https://choosealicense.com/licenses/mit/) template is the standard reference.
- Replace `<year>` and `<author>` placeholders with the current year and "BitR1FT".
- The `LICENSE` file in this repository already contains the correct text.

---

## 2. npm — Publishing the CLI Wrapper

UniVex is a server-side platform (Python + Docker), not a Node.js package. However, you can publish a thin CLI wrapper on npm that downloads and starts the Docker stack.

### 2.1 Prerequisites

- An [npmjs.com](https://www.npmjs.com/) account.
- `npm` installed locally.
- A `package.json` with `"name": "univex"` and `"bin"` entries (see below).

### 2.2 Create the npm package

Create the following files at the repository root:

**`bin/univex.js`** — CLI entry point:

```js
#!/usr/bin/env node
'use strict';

const { execSync } = require('child_process');
const path = require('path');
const os = require('os');

const REPO = 'https://github.com/BitR1ft/UniVex';
const command = process.argv[2];

const commands = {
  start: () => execSync('docker compose up -d', { stdio: 'inherit', cwd: process.cwd() }),
  stop:  () => execSync('docker compose down', { stdio: 'inherit', cwd: process.cwd() }),
  logs:  () => execSync('docker compose logs -f', { stdio: 'inherit', cwd: process.cwd() }),
  help:  () => {
    console.log(`
UniVex CLI

Usage:
  univex start     Start the UniVex stack
  univex stop      Stop the UniVex stack
  univex logs      Follow container logs
  univex help      Show this help
`);
  },
};

if (!command || !commands[command]) {
  commands.help();
  process.exit(command ? 1 : 0);
}

commands[command]();
```

**Root `package.json`** additions:

```json
{
  "name": "univex",
  "version": "1.0.0",
  "description": "AI-powered autonomous penetration testing platform",
  "keywords": ["pentest", "security", "ai", "agent", "recon"],
  "homepage": "https://github.com/BitR1ft/UniVex",
  "repository": {
    "type": "git",
    "url": "git+https://github.com/BitR1ft/UniVex.git"
  },
  "license": "MIT",
  "bin": {
    "univex": "./bin/univex.js"
  },
  "engines": {
    "node": ">=18"
  },
  "os": ["linux", "darwin"],
  "cpu": ["x64", "arm64"]
}
```

### 2.3 Publish to npm

```bash
# Log in (one-time)
npm login

# Publish (from repository root)
npm publish --access public
```

After publishing, users can install with:

```bash
npm install -g univex
univex start
```

### 2.4 Scoped package (optional)

If the `univex` name is taken on npm, use a scoped name:

```json
"name": "@bitr1ft/univex"
```

Then publish with:

```bash
npm publish --access public
```

Users install with:

```bash
npm install -g @bitr1ft/univex
```

---

## 3. apt/deb — Debian/Ubuntu Package

### 3.1 Overview

A `.deb` package lets users install UniVex with `apt install univex`. The package itself is a thin wrapper that installs Docker Compose files and the installer script — the actual services run in containers.

### 3.2 Package structure

```
univex_1.0.0_amd64/
├── DEBIAN/
│   ├── control          # Package metadata
│   ├── postinst         # Post-installation script
│   └── prerm            # Pre-removal script
└── usr/
    ├── bin/
    │   └── univex       # CLI wrapper script
    └── share/
        └── univex/
            ├── docker-compose.yml
            ├── .env.example
            └── scripts/
                └── install.sh
```

### 3.3 DEBIAN/control

```
Package: univex
Version: 1.0.0
Section: net
Priority: optional
Architecture: amd64
Depends: docker-ce (>= 24.0) | docker.io (>= 24.0), docker-compose-plugin
Maintainer: BitR1FT <contact@bitr1ft.dev>
Description: AI-powered autonomous penetration testing platform
 UniVex is a production-grade security automation platform combining
 13 AI agent roles, 90+ security tools, and full kill-chain automation
 from recon through exploitation to compliance reporting.
Homepage: https://github.com/BitR1ft/UniVex
```

### 3.4 Build the .deb package

```bash
# Create directory structure
mkdir -p univex_1.0.0_amd64/{DEBIAN,usr/bin,usr/share/univex/scripts}

# Copy files
cp scripts/install.sh  univex_1.0.0_amd64/usr/share/univex/scripts/
cp docker-compose.yml  univex_1.0.0_amd64/usr/share/univex/
cp .env.example        univex_1.0.0_amd64/usr/share/univex/

# Create DEBIAN/control (see above)

# Create the CLI wrapper
cat > univex_1.0.0_amd64/usr/bin/univex << 'EOF'
#!/bin/bash
set -e
UNIVEX_HOME="${UNIVEX_HOME:-/usr/share/univex}"
exec docker compose -f "$UNIVEX_HOME/docker-compose.yml" "$@"
EOF
chmod +x univex_1.0.0_amd64/usr/bin/univex

# Build
dpkg-deb --build univex_1.0.0_amd64
```

### 3.5 Distribute via GitHub Releases

Attach the `.deb` file to the GitHub release. Users install with:

```bash
curl -LO https://github.com/BitR1ft/UniVex/releases/latest/download/univex_1.0.0_amd64.deb
sudo dpkg -i univex_1.0.0_amd64.deb
univex up -d
```

### 3.6 Personal Package Archive (PPA — Ubuntu)

To enable `apt install univex` without manually downloading:

1. Create a [Launchpad](https://launchpad.net/) account.
2. Create a PPA (e.g. `ppa:bitr1ft/univex`).
3. Upload the `.deb` source package to Launchpad using `dput`.
4. Users add the PPA and install:

```bash
sudo add-apt-repository ppa:bitr1ft/univex
sudo apt update
sudo apt install univex
```

Full Launchpad PPA guide: https://help.launchpad.net/Packaging/PPA

---

## 4. rpm/yum — RHEL/CentOS/Fedora Package

### 4.1 Build an RPM

```bash
# Install build tools
sudo dnf install rpmdevtools

# Set up build tree
rpmdev-setuptree

# Create spec file at ~/rpmbuild/SPECS/univex.spec
```

**univex.spec**:

```spec
Name:       univex
Version:    1.0.0
Release:    1%{?dist}
Summary:    AI-powered autonomous penetration testing platform
License:    MIT
URL:        https://github.com/BitR1ft/UniVex
BuildArch:  noarch
Requires:   docker-ce >= 24.0, docker-compose-plugin

%description
UniVex is a production-grade security automation platform combining
13 AI agent roles, 90+ security tools, and full kill-chain automation.

%install
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/usr/share/univex
install -m 755 univex %{buildroot}/usr/bin/univex

%files
/usr/bin/univex
/usr/share/univex/

%changelog
* March 2026 BitR1FT <contact@bitr1ft.dev> - 1.0.0-1
- Initial release
```

```bash
# Build
rpmbuild -bb ~/rpmbuild/SPECS/univex.spec
```

### 4.2 COPR (Fedora Community Build Service)

To enable `dnf install univex`:

1. Create an account on [copr.fedorainfracloud.org](https://copr.fedorainfracloud.org/).
2. Create a new project (e.g. `bitr1ft/univex`).
3. Upload the `.spec` file and source tarball.
4. Users enable and install:

```bash
sudo dnf copr enable bitr1ft/univex
sudo dnf install univex
```

---

## 5. Homebrew — macOS

### 5.1 Create a Formula

Create `Formula/univex.rb` in a Homebrew tap repository (e.g. `homebrew-univex`):

```ruby
class Univex < Formula
  desc "AI-powered autonomous penetration testing platform"
  homepage "https://github.com/BitR1ft/UniVex"
  url "https://github.com/BitR1ft/UniVex/archive/refs/tags/v1.0.0.tar.gz"
  sha256 "<sha256 of tarball>"
  license "MIT"
  version "1.0.0"

  depends_on "docker"
  depends_on "docker-compose"

  def install
    bin.install "scripts/install.sh" => "univex-install"
    (share/"univex").install "docker-compose.yml", ".env.example"
    
    (bin/"univex").write <<~EOS
      #!/bin/bash
      exec docker compose -f "#{share}/univex/docker-compose.yml" "$@"
    EOS
  end

  test do
    system "#{bin}/univex", "--version"
  end
end
```

### 5.2 Users install with

```bash
brew tap bitr1ft/univex
brew install univex
```

---

## 6. Snap — Universal Linux Package

### 6.1 snapcraft.yaml

```yaml
name: univex
version: '1.0.0'
summary: AI-powered autonomous penetration testing platform
description: |
  UniVex is a production-grade security automation platform combining
  13 AI agent roles, 90+ security tools, and full kill-chain automation
  from recon through exploitation to compliance reporting.
grade: stable
confinement: classic
base: core22

apps:
  univex:
    command: bin/univex
    plugs:
      - network
      - home
      - docker

parts:
  univex:
    plugin: dump
    source: .
    organize:
      scripts/install.sh: bin/univex
```

### 6.2 Build and publish

```bash
# Build
snapcraft

# Publish to Snap Store
snapcraft upload univex_1.0.0_amd64.snap --release stable
```

Users install with:

```bash
sudo snap install univex --classic
```

---

## 7. Release Automation

The `.github/workflows/release-installer.yml` workflow already builds and attaches `install.sh` to GitHub Releases.

To extend it for package distribution, add steps to:

1. Build the `.deb` package
2. Sign it with GPG
3. Upload to the GitHub Release using `gh release upload`

**Example workflow step:**

```yaml
- name: Build deb package
  run: |
    bash scripts/build-deb.sh
    gh release upload "$GITHUB_REF_NAME" \
      univex_${{ github.ref_name }}_amd64.deb \
      --clobber
  env:
    GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

Once published to npm, PyPI, apt, or Snap, update the README with the installation badge and one-liner.

---

*UniVex v1.0.0 | BitR1FT*
