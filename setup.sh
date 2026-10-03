#!/bin/bash
# ──────────────────────────────────────────────────────────────
# AutoVulnScan – Tool Installer
# Installs Go-based and apt-based security tools.
# Run: chmod +x setup.sh && sudo ./setup.sh
# ──────────────────────────────────────────────────────────────
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }

echo "================================================"
echo "  AutoVulnScan – Tool Installer"
echo "================================================"

# ── Detect package manager ────────────────────────────────────
if command -v apt-get &>/dev/null; then
    PM="apt"
elif command -v yum &>/dev/null; then
    PM="yum"
else
    warn "Unknown package manager – install tools manually"
    PM="none"
fi

# ── System packages ───────────────────────────────────────────
if [ "$PM" = "apt" ]; then
    echo "[*] Updating apt cache..."
    apt-get update -qq
    PKGS="nmap nikto whois dnsutils curl openssl python3 python3-pip"
    for pkg in $PKGS; do
        if dpkg -s "$pkg" &>/dev/null; then
            ok "$pkg already installed"
        else
            apt-get install -y -qq "$pkg" && ok "$pkg installed" || warn "$pkg failed"
        fi
    done
fi

# ── Python deps ───────────────────────────────────────────────
echo "[*] Python dependencies..."
pip3 install -q requests jinja2 click 2>/dev/null && ok "Python deps" || warn "pip install failed"

# ── Go (needed for many tools) ────────────────────────────────
install_go() {
    if command -v go &>/dev/null; then
        ok "Go already installed ($(go version))"
        return
    fi
    echo "[*] Installing Go..."
    GO_VER="1.22.5"
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  GA="amd64" ;;
        aarch64) GA="arm64" ;;
        *)       warn "Unknown arch $ARCH"; return ;;
    esac
    curl -sLO "https://go.dev/dl/go${GO_VER}.linux-${GA}.tar.gz"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "go${GO_VER}.linux-${GA}.tar.gz"
    rm "go${GO_VER}.linux-${GA}.tar.gz"
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
    ok "Go ${GO_VER} installed"
}
install_go

export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
export GOPATH=$HOME/go

# ── Go tools ──────────────────────────────────────────────────
go_install() {
    local name=$1 pkg=$2
    if command -v "$name" &>/dev/null; then
        ok "$name already installed"
        return
    fi
    echo "[*] Installing $name..."
    go install "$pkg" 2>/dev/null && ok "$name installed" || warn "$name failed"
}

go_install subfinder    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
go_install httpx        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
go_install nuclei       "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
go_install katana       "github.com/projectdiscovery/katana/cmd/katana@latest"
go_install dnsx         "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
go_install gau          "github.com/lc/gau/v2/cmd/gau@latest"
go_install hakrawler    "github.com/hakluke/hakrawler@latest"
go_install assetfinder  "github.com/tomnomnom/assetfinder@latest"
go_install gobuster     "github.com/OJ/gobuster/v3@latest"
go_install ffuf         "github.com/ffuf/ffuf/v2@latest"
go_install gospider     "github.com/jaeles-project/gospider@latest"
go_install subjack      "github.com/haccer/subjack@latest"
go_install gowitness    "github.com/sensepost/gowitness@latest"

# ── Python-based tools ───────────────────────────────────────
pip_install() {
    local name=$1 pkg=${2:-$1}
    if command -v "$name" &>/dev/null; then
        ok "$name already installed"
        return
    fi
    echo "[*] Installing $name..."
    pip3 install -q "$pkg" 2>/dev/null && ok "$name installed" || warn "$name failed"
}

pip_install arjun
pip_install paramspider

# ── Nuclei templates ─────────────────────────────────────────
if command -v nuclei &>/dev/null; then
    echo "[*] Updating nuclei templates..."
    nuclei -update-templates -silent 2>/dev/null && ok "nuclei templates updated" || warn "template update failed"
fi

# ── Wordlists ─────────────────────────────────────────────────
if [ ! -d "/usr/share/seclists" ]; then
    echo "[*] Installing SecLists (takes a minute)..."
    if [ "$PM" = "apt" ]; then
        apt-get install -y -qq seclists 2>/dev/null && ok "SecLists" || warn "SecLists failed (try: git clone)"
    fi
fi

# ── wafw00f ───────────────────────────────────────────────────
if ! command -v wafw00f &>/dev/null; then
    echo "[*] Installing wafw00f..."
    pip3 install -q wafw00f 2>/dev/null && ok "wafw00f" || warn "wafw00f failed"
fi

# ── Summary ───────────────────────────────────────────────────
echo ""
echo "================================================"
echo "  Installation complete. Run:"
echo "    python3 autoscan.py -t example.com --confirm"
echo "================================================"
