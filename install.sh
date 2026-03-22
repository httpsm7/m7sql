#!/usr/bin/env bash
# ============================================================
#  m7sql v4.0 Brain Edition — Installer
#  Author : Sharlix / Milkyway Intelligence
#  Usage  : sudo bash install.sh
# ============================================================

R='\033[31m'; G='\033[32m'; Y='\033[33m'; C='\033[36m'; W='\033[0m'; BOLD='\033[1m'

INSTALL_DIR="/opt/m7sql"
BIN_PATH="/usr/local/bin/m7sql"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

banner() {
printf "${G}
 ███╗   ███╗███████╗███████╗ ██████╗ ██╗     
 ██╔████╔██║    ██╔╝███████╗██║   ██║██║     
 ██║ ╚═╝ ██║   ██║  ███████║╚██████╔╝███████╗
${W} v4.0 Brain Edition | Milkyway Intelligence\n\n"
}

ok()   { echo -e "${G}[+]${W} $1"; }
info() { echo -e "${C}[*]${W} $1"; }
warn() { echo -e "${Y}[!]${W} $1"; }
err()  { echo -e "${R}[x]${W} $1"; }
step() { echo -e "\n${BOLD}${C}==> $1${W}"; }

[[ $EUID -ne 0 ]] && err "Run as root: sudo bash install.sh" && exit 1

detect_pm() {
    if   command -v apt-get &>/dev/null; then PI="apt-get install -y -q"; PU="apt-get update -q"
    elif command -v apt     &>/dev/null; then PI="apt install -y -q";     PU="apt update -q"
    elif command -v dnf     &>/dev/null; then PI="dnf install -y -q";     PU="true"
    else PI="true"; PU="true"; fi
}

ensure() {
    command -v "$1" &>/dev/null && ok "$1 already installed" && return
    warn "Installing $1..."
    $PI "$2" 2>/dev/null
    command -v "$1" &>/dev/null && ok "$1 done" || warn "$1 failed (continuing)"
}

pip_install() {
    python3 -c "import $2" &>/dev/null 2>&1 && ok "$1 available" && return
    pip3 install "$1" --break-system-packages -q 2>/dev/null || \
    pip3 install "$1" -q 2>/dev/null || true
    python3 -c "import $2" &>/dev/null 2>&1 && ok "$1 installed" || warn "$1 unavailable"
}

install_ghauri() {
    command -v ghauri &>/dev/null && ok "ghauri installed" && return
    warn "Installing ghauri from GitHub..."
    tmp="/tmp/_ghauri_$$"
    git clone -q https://github.com/r0oth3x49/ghauri.git "$tmp" 2>/dev/null && {
        cd "$tmp" && pip3 install . --break-system-packages -q 2>/dev/null; cd "$SCRIPT_DIR"
    }
    rm -rf "$tmp"
    command -v ghauri &>/dev/null && ok "ghauri installed" || warn "ghauri unavailable — sqlmap primary"
}

install_tool() {
    step "Installing m7sql v4.0 to $INSTALL_DIR"
    rm -rf "$INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"
    cp -r "$SCRIPT_DIR/." "$INSTALL_DIR/"
    chmod -R 755 "$INSTALL_DIR"

    # Launcher — printf avoids heredoc variable expansion bug
    printf '#!/usr/bin/env python3\nimport sys, os\nsys.path.insert(0, "%s")\nfrom m7sql.cli import main\nmain()\n' \
        "$INSTALL_DIR" > "$BIN_PATH"
    chmod +x "$BIN_PATH"

    mkdir -p "$INSTALL_DIR/logs" "$INSTALL_DIR/m7sql_reports"
    chmod 777 "$INSTALL_DIR/logs" "$INSTALL_DIR/m7sql_reports"
    ok "Installed → $INSTALL_DIR"
    ok "Command  → $BIN_PATH"
}

verify() {
    step "Verifying"
    python3 "$BIN_PATH" --help > /dev/null 2>&1 && ok "m7sql v4.0 works!" || \
        err "Verification failed — try: python3 $BIN_PATH --help"
}

clear; banner
detect_pm

step "System packages"
$PU 2>/dev/null || true
ensure python3  python3
ensure pip3     python3-pip
ensure git      git
ensure sqlmap   sqlmap
ensure nmap     nmap

step "Python packages"
pip_install requests requests

step "Ghauri"
install_ghauri

install_tool
verify

echo ""
echo -e "${G}${BOLD}+--------------------------------------------+${W}"
echo -e "${G}${BOLD}|  m7sql v4.0 Brain Edition installed! ✓    |${W}"
echo -e "${G}${BOLD}+--------------------------------------------+${W}"
echo ""
echo -e "  ${C}Usage:${W}"
echo -e "  ${Y}m7sql --help${W}"
echo -e "  ${Y}m7sql -u \"http://testphp.vulnweb.com/listproducts.php?cat=1\"${W}"
echo -e "  ${Y}m7sql -f urls.txt --threads 10 --output all${W}"
echo ""
