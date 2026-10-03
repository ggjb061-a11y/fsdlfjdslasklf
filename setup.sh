#!/bin/bash
# ──────────────────────────────────────────────────────────────
# AutoVulnScan - Bulletproof Installer
# Installs every tool AutoVulnScan can use, with retry logic,
# multiple fallback sources, and a final verification report.
#
# Usage: chmod +x setup.sh && sudo ./setup.sh
# ──────────────────────────────────────────────────────────────

# Do NOT use `set -e` - we want to keep going on failures and
# report them at the end rather than die on the first missing dep.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

ok()    { echo -e "${GREEN}[✓]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
err()   { echo -e "${RED}[✗]${NC} $1"; }
info()  { echo -e "${CYAN}[*]${NC} $1"; }

# Track outcomes so the final report tells the operator what works.
INSTALLED=()
FAILED=()

mark_installed() { INSTALLED+=("$1"); }
mark_failed()    { FAILED+=("$1"); }

# ────────────────────────────────────────────────────────────────────
# Retry wrapper: run a command up to 3 times with exponential backoff.
# ────────────────────────────────────────────────────────────────────
retry() {
    local max_attempts=3
    local delay=2
    local attempt=1
    while [ $attempt -le $max_attempts ]; do
        if "$@"; then
            return 0
        fi
        warn "attempt $attempt/$max_attempts failed for: $*"
        sleep $delay
        delay=$((delay * 2))
        attempt=$((attempt + 1))
    done
    return 1
}

# Install one apt package, swallow errors.
apt_install() {
    local pkg="$1"
    if dpkg -s "$pkg" &>/dev/null; then
        ok "$pkg already installed"
        mark_installed "$pkg"
        return 0
    fi
    if retry apt-get install -y -qq "$pkg" 2>/dev/null; then
        ok "$pkg installed via apt"
        mark_installed "$pkg"
        return 0
    fi
    mark_failed "$pkg"
    return 1
}

# Install one pip package, swallow errors.
pip_install() {
    local pkg="$1"
    if retry pip3 install -q --upgrade "$pkg" 2>/dev/null; then
        ok "$pkg installed via pip"
        mark_installed "pip:$pkg"
        return 0
    fi
    # Some environments require --break-system-packages
    if retry pip3 install -q --upgrade --break-system-packages "$pkg" 2>/dev/null; then
        ok "$pkg installed via pip (--break-system-packages)"
        mark_installed "pip:$pkg"
        return 0
    fi
    mark_failed "pip:$pkg"
    return 1
}

# Install a Go-based tool: `go install` first, then a direct-binary
# fallback via a GitHub release URL template.
go_install() {
    local name="$1"
    local pkg="$2"
    local release_url="$3"  # optional: GitHub release URL template
    if command -v "$name" &>/dev/null; then
        ok "$name already installed"
        mark_installed "$name"
        return 0
    fi
    if command -v go &>/dev/null; then
        info "Installing $name via go install..."
        if retry go install -v "$pkg" 2>&1 | tail -2; then
            if command -v "$name" &>/dev/null; then
                ok "$name installed via Go"
                mark_installed "$name"
                return 0
            fi
        fi
    fi
    # Fallback: direct binary download
    if [ -n "$release_url" ]; then
        info "Trying direct binary download for $name..."
        local tmp
        tmp="$(mktemp -d)"
        local arch
        arch="$(uname -m)"
        case "$arch" in
            x86_64)  arch=amd64 ;;
            aarch64) arch=arm64 ;;
            *) warn "Unknown arch $arch for $name"; mark_failed "$name"; return 1 ;;
        esac
        local url
        url="${release_url/\{arch\}/$arch}"
        if retry curl -sSL "$url" -o "$tmp/pkg" 2>/dev/null; then
            file "$tmp/pkg" | grep -qi "zip" && unzip -q -o "$tmp/pkg" -d "$tmp"
            file "$tmp/pkg" | grep -qi "tar" && tar -C "$tmp" -xzf "$tmp/pkg"
            local bin
            bin="$(find "$tmp" -type f -name "$name" -executable 2>/dev/null | head -1)"
            if [ -n "$bin" ]; then
                install -m 0755 "$bin" /usr/local/bin/"$name" 2>/dev/null
                if command -v "$name" &>/dev/null; then
                    ok "$name installed via direct binary"
                    rm -rf "$tmp"
                    mark_installed "$name"
                    return 0
                fi
            fi
        fi
        rm -rf "$tmp"
    fi
    mark_failed "$name"
    warn "$name NOT installed (optional - scanner degrades gracefully)"
    return 1
}

echo "================================================"
echo "  AutoVulnScan - Bulletproof Installer"
echo "================================================"

# ── Detect package manager ─────────────────────────────────────
PM=none
if command -v apt-get &>/dev/null; then
    PM=apt
elif command -v yum &>/dev/null; then
    PM=yum
elif command -v dnf &>/dev/null; then
    PM=dnf
elif command -v pacman &>/dev/null; then
    PM=pacman
elif command -v brew &>/dev/null; then
    PM=brew
else
    warn "Unknown package manager - will try to install only via Go / pip / direct binary."
fi
info "Package manager detected: $PM"

# ── Base system packages (apt) ──────────────────────────────────
if [ "$PM" = "apt" ]; then
    info "Updating apt cache..."
    retry apt-get update -qq 2>/dev/null || warn "apt update failed (continuing)"
    for pkg in curl wget unzip git ca-certificates jq \
               nmap nikto whois dnsutils openssl \
               python3 python3-pip python3-venv \
               sqlmap masscan hydra; do
        apt_install "$pkg"
    done
elif [ "$PM" = "yum" ] || [ "$PM" = "dnf" ]; then
    info "Installing via $PM..."
    for pkg in curl wget unzip git jq nmap nikto whois bind-utils openssl \
               python3 python3-pip sqlmap; do
        $PM install -y "$pkg" 2>/dev/null && mark_installed "$pkg" || mark_failed "$pkg"
    done
elif [ "$PM" = "brew" ]; then
    info "Installing via brew..."
    for pkg in curl wget unzip git jq nmap nikto whois openssl \
               python3 sqlmap masscan; do
        brew install "$pkg" 2>/dev/null && mark_installed "$pkg" || mark_failed "$pkg"
    done
fi

# ── Python dependencies (always try) ────────────────────────────
info "Installing Python dependencies..."
pip_install "requests"
pip_install "Jinja2"
pip_install "click"
pip_install "defusedxml"
pip_install "wafw00f"

# Optional Python-based tools
pip_install "arjun" || warn "arjun optional"
pip_install "paramspider" || warn "paramspider optional"
pip_install "sublist3r" || warn "sublist3r optional"
pip_install "dnsrecon" || warn "dnsrecon optional"

# ── Install Go (needed for many tools) ──────────────────────────
install_go() {
    if command -v go &>/dev/null; then
        ok "Go already installed ($(go version))"
        mark_installed "go"
        return 0
    fi
    info "Installing Go..."
    local GO_VER="1.22.5"
    local ARCH
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  local GA="amd64" ;;
        aarch64) local GA="arm64" ;;
        armv7l)  local GA="armv6l" ;;
        *) warn "Unknown arch $ARCH for Go"; mark_failed "go"; return 1 ;;
    esac
    local url="https://go.dev/dl/go${GO_VER}.linux-${GA}.tar.gz"
    if retry curl -sSLO "$url" 2>/dev/null; then
        rm -rf /usr/local/go
        tar -C /usr/local -xzf "go${GO_VER}.linux-${GA}.tar.gz"
        rm "go${GO_VER}.linux-${GA}.tar.gz"
        export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
        grep -q '/usr/local/go/bin' ~/.bashrc 2>/dev/null || \
            echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
        ok "Go $GO_VER installed"
        mark_installed "go"
        return 0
    fi
    mark_failed "go"
    warn "Go installation failed - Go-based tools will be skipped"
    return 1
}
install_go

export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
export GOPATH=$HOME/go

# ── Go-based tools (with GitHub release fallback where known) ──
info "Installing Go-based tools..."
go_install subfinder   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
go_install httpx       "github.com/projectdiscovery/httpx/cmd/httpx@latest"
go_install nuclei      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
go_install katana      "github.com/projectdiscovery/katana/cmd/katana@latest"
go_install dnsx        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
go_install gau         "github.com/lc/gau/v2/cmd/gau@latest"
go_install hakrawler   "github.com/hakluke/hakrawler@latest"
go_install assetfinder "github.com/tomnomnom/assetfinder@latest"
go_install gobuster    "github.com/OJ/gobuster/v3@latest"
go_install ffuf        "github.com/ffuf/ffuf/v2@latest"
go_install gospider    "github.com/jaeles-project/gospider@latest"
go_install subjack     "github.com/haccer/subjack@latest"
go_install gowitness   "github.com/sensepost/gowitness@latest"
go_install waybackurls "github.com/tomnomnom/waybackurls@latest"
go_install anew        "github.com/tomnomnom/anew@latest"
go_install qsreplace   "github.com/tomnomnom/qsreplace@latest"
go_install unfurl      "github.com/tomnomnom/unfurl@latest"
go_install meg         "github.com/tomnomnom/meg@latest"
go_install amass       "github.com/owasp-amass/amass/v4/...@master"

# ── Nuclei templates ────────────────────────────────────────────
if command -v nuclei &>/dev/null; then
    info "Updating nuclei templates..."
    retry nuclei -update-templates -silent 2>/dev/null && \
        ok "nuclei templates updated" || warn "nuclei template update failed"
fi

# ── Wordlists ───────────────────────────────────────────────────
install_seclists() {
    if [ -d "/usr/share/seclists" ] || [ -d "/opt/SecLists" ]; then
        ok "SecLists already installed"
        mark_installed "seclists"
        return 0
    fi
    info "Installing SecLists (this takes a minute)..."
    if [ "$PM" = "apt" ] && apt_install "seclists"; then
        return 0
    fi
    # Fallback: clone directly
    if retry git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/SecLists 2>/dev/null; then
        ok "SecLists cloned to /opt/SecLists"
        mark_installed "seclists"
        return 0
    fi
    mark_failed "seclists"
    warn "SecLists not installed - DirBruteCheck will try alternate wordlists."
    return 1
}
install_seclists

# ── Additional tools that are useful but often missing ─────────
install_findomain() {
    if command -v findomain &>/dev/null; then
        ok "findomain already installed"
        mark_installed "findomain"
        return
    fi
    info "Installing findomain..."
    local url="https://github.com/findomain/findomain/releases/latest/download/findomain-linux"
    if retry curl -sSL -o /tmp/findomain "$url"; then
        chmod +x /tmp/findomain
        mv /tmp/findomain /usr/local/bin/findomain
        ok "findomain installed"
        mark_installed "findomain"
    else
        mark_failed "findomain"
    fi
}
install_findomain

install_feroxbuster() {
    if command -v feroxbuster &>/dev/null; then
        ok "feroxbuster already installed"
        mark_installed "feroxbuster"
        return
    fi
    info "Installing feroxbuster..."
    local url="https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.zip"
    local tmp
    tmp="$(mktemp -d)"
    if retry curl -sSL -o "$tmp/f.zip" "$url"; then
        unzip -q "$tmp/f.zip" -d "$tmp" 2>/dev/null
        if [ -f "$tmp/feroxbuster" ]; then
            install -m 0755 "$tmp/feroxbuster" /usr/local/bin/feroxbuster
            ok "feroxbuster installed"
            mark_installed "feroxbuster"
        else
            mark_failed "feroxbuster"
        fi
    else
        mark_failed "feroxbuster"
    fi
    rm -rf "$tmp"
}
install_feroxbuster

install_testssl() {
    if command -v testssl.sh &>/dev/null || command -v testssl &>/dev/null; then
        ok "testssl.sh already installed"
        mark_installed "testssl.sh"
        return
    fi
    info "Installing testssl.sh..."
    if retry git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh 2>/dev/null; then
        ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh
        ok "testssl.sh installed"
        mark_installed "testssl.sh"
    else
        mark_failed "testssl.sh"
    fi
}
install_testssl

install_whatweb() {
    if command -v whatweb &>/dev/null; then
        ok "whatweb already installed"
        mark_installed "whatweb"
        return
    fi
    if [ "$PM" = "apt" ]; then
        apt_install "whatweb" && return
    fi
    info "Installing whatweb from source..."
    if retry git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/WhatWeb 2>/dev/null; then
        ln -sf /opt/WhatWeb/whatweb /usr/local/bin/whatweb
        ok "whatweb installed"
        mark_installed "whatweb"
    else
        mark_failed "whatweb"
    fi
}
install_whatweb

# ── Final verification pass ─────────────────────────────────────
echo ""
echo "================================================"
echo "  Verification"
echo "================================================"

CORE_TOOLS=(curl wget nmap nikto whois dig openssl python3 sqlmap)
GO_TOOLS=(subfinder httpx nuclei katana gau hakrawler assetfinder
          gobuster ffuf gospider subjack gowitness waybackurls dnsx amass)
EXTRA_TOOLS=(findomain feroxbuster testssl.sh whatweb masscan wafw00f)

check_tool() {
    local t="$1"
    if command -v "$t" &>/dev/null; then
        ok "$t ($(which $t))"
    else
        warn "$t MISSING"
    fi
}

echo ""
echo "-- Core tools --"
for t in "${CORE_TOOLS[@]}"; do check_tool "$t"; done
echo ""
echo "-- Go-based tools --"
for t in "${GO_TOOLS[@]}"; do check_tool "$t"; done
echo ""
echo "-- Extra tools --"
for t in "${EXTRA_TOOLS[@]}"; do check_tool "$t"; done

# ── Summary ─────────────────────────────────────────────────────
echo ""
echo "================================================"
echo "  Summary"
echo "================================================"
echo "Installed: ${#INSTALLED[@]} items"
echo "Failed:    ${#FAILED[@]} items"
if [ ${#FAILED[@]} -gt 0 ]; then
    echo ""
    warn "The following items did NOT install:"
    for f in "${FAILED[@]}"; do
        echo "  - $f"
    done
    echo ""
    info "This is normally non-fatal - the scanner degrades gracefully"
    info "when a tool is missing. Re-run setup.sh after fixing network"
    info "issues to try again."
fi
echo ""
ok "Setup done. Run: python3 autoscan.py -t example.com --confirm"
echo "================================================"
