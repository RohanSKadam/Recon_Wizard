#!/usr/bin/env bash
# =============================================================================
# install.sh - installs and verifies everything the recon tools need.
#
#   ./install.sh              install what is missing, then verify
#   ./install.sh --check      only check, install nothing
#   ./install.sh -y           no prompts (assume "yes")
#   ./install.sh --weasyprint also install WeasyPrint (nicer PDFs, needs Pango)
#   ./install.sh --system     install Python libs system-wide instead of ./.venv
#
# Installs: nmap, nikto, gobuster, a wordlist, Python >= 3.10 (+venv),
#           and the pip packages in requirements.txt.
# Supports: apt (Debian/Ubuntu/Kali), dnf (Fedora/RHEL), pacman (Arch), brew (macOS).
# Authorized security testing only.
# =============================================================================
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1

VENV_DIR=".venv"
DEFAULT_WORDLIST="/usr/share/wordlists/dirb/common.txt"
VULNERS_URL="https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse"
NMAP_SCRIPT_DIRS=(/usr/share/nmap/scripts /usr/local/share/nmap/scripts /opt/homebrew/share/nmap/scripts)

MODE="install"; ASSUME_YES=0; USE_VENV=1; WITH_WEASY=0
PM=""; APT_UPDATED=0; PY="python3"
MISSING_REQ=0; MISSING_OPT=0
NEED=()

usage() { sed -n '2,13p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

for arg in "$@"; do
  case "$arg" in
    --check) MODE="check" ;;
    -y|--yes) ASSUME_YES=1 ;;
    --system) USE_VENV=0 ;;
    --weasyprint) WITH_WEASY=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $arg"; usage; exit 2 ;;
  esac
done

if [ -t 1 ]; then G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; B=$'\e[1m'; N=$'\e[0m'
else G=""; R=""; Y=""; B=""; N=""; fi

info()    { printf "%s\n" "$*"; }
head_()   { printf "\n%s%s%s\n" "$B" "$*" "$N"; }
pass()    { printf "  %s[ OK ]%s %-24s %s\n" "$G" "$N" "$1" "${2:-}"; }
failreq() { printf "  %s[MISS]%s %-24s %s\n" "$R" "$N" "$1" "${2:-}"; MISSING_REQ=$((MISSING_REQ+1)); }
failopt() { printf "  %s[warn]%s %-24s %s\n" "$Y" "$N" "$1" "${2:-}"; MISSING_OPT=$((MISSING_OPT+1)); }
note()    { printf "  [info] %-24s %s\n" "$1" "${2:-}"; }

ask_yes() {
  [ "$ASSUME_YES" -eq 1 ] && return 0
  local a; read -r -p "$1 [y/N] " a || return 1
  [[ "$a" =~ ^[Yy] ]]
}

# ---------------------------------------------------------------- helpers
detect_pm() {
  for pm in apt-get dnf pacman brew; do
    if command -v "$pm" >/dev/null 2>&1; then PM="$pm"; return; fi
  done
}

run_priv() {
  if [ "$PM" = "brew" ] || [ "$(id -u)" -eq 0 ]; then "$@"
  elif command -v sudo >/dev/null 2>&1; then sudo "$@"
  else echo "    root needed for: $*  (run as root or install sudo)"; return 1; fi
}

pkg_for() {   # logical name -> package name for the detected package manager
  case "$PM:$1" in
    apt-get:python3) echo python3 ;;  apt-get:venv) echo python3-venv ;;
    apt-get:pip)     echo python3-pip ;; apt-get:wordlist) echo dirb ;;
    apt-get:*)       echo "$1" ;;
    dnf:python3)     echo python3 ;;  dnf:pip) echo python3-pip ;;
    pacman:python3)  echo python ;;   pacman:pip) echo python-pip ;;
    brew:python3)    echo python3 ;;
    *:nmap|*:nikto|*:gobuster) echo "$1" ;;
    *) echo "" ;;
  esac
}

install_pkg() {
  local pkg; pkg="$(pkg_for "$1")"
  if [ -z "$pkg" ]; then echo "    no package mapping for '$1' on $PM"; return 1; fi
  case "$PM" in
    apt-get) run_priv apt-get install -y "$pkg" ;;
    dnf)     run_priv dnf install -y "$pkg" ;;
    pacman)  run_priv pacman -S --needed --noconfirm "$pkg" ;;
    brew)    brew install "$pkg" ;;
  esac
}

py_ok() { command -v python3 >/dev/null 2>&1 && python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' 2>/dev/null; }

find_missing() {
  NEED=()
  py_ok || NEED+=(python3)
  if [ "$USE_VENV" -eq 1 ]; then
    python3 -c 'import venv, ensurepip' >/dev/null 2>&1 || NEED+=(venv)
  else
    python3 -m pip --version >/dev/null 2>&1 || NEED+=(pip)
  fi
  for t in nmap nikto gobuster; do command -v "$t" >/dev/null 2>&1 || NEED+=("$t"); done
  [ -f "$DEFAULT_WORDLIST" ] || [ -f /usr/share/dirb/wordlists/common.txt ] || NEED+=(wordlist)
}

# ------------------------------------------------------- install actions
install_system() {
  head_ "1/5  System packages"
  find_missing
  if [ "${#NEED[@]}" -eq 0 ]; then info "  Nothing to install."; return; fi
  if [ -z "$PM" ]; then
    info "  No supported package manager found (apt/dnf/pacman/brew)."
    info "  Please install manually: ${NEED[*]}"; return
  fi
  info "  Missing: ${NEED[*]}   (using $PM)"
  ask_yes "  Install them now?" || { info "  Skipped."; return; }
  if [ "$PM" = "apt-get" ] && [ "$APT_UPDATED" -eq 0 ]; then run_priv apt-get update; APT_UPDATED=1; fi
  for n in "${NEED[@]}"; do
    info "  -> installing $n"
    install_pkg "$n" || info "     could not install '$n' automatically"
  done
}

resolve_py() {
  if [ "$USE_VENV" -eq 1 ] && [ -x "$VENV_DIR/bin/python" ]; then PY="$VENV_DIR/bin/python"; else PY="python3"; fi
}

setup_python() {
  head_ "2/5  Python environment"
  if ! py_ok; then info "  Python >= 3.10 not available - cannot continue this step."; return; fi
  local flags=""
  if [ "$USE_VENV" -eq 1 ]; then
    if [ ! -x "$VENV_DIR/bin/python" ]; then
      info "  Creating virtualenv in $VENV_DIR ..."
      python3 -m venv "$VENV_DIR" || { info "  venv creation failed (install python3-venv)"; return; }
    fi
    "$VENV_DIR/bin/python" -m pip install --quiet --upgrade pip >/dev/null 2>&1
  else
    flags="--user"
  fi
  resolve_py
  info "  Installing requirements.txt ..."
  if ! "$PY" -m pip install $flags -r requirements.txt; then
    if [ "$USE_VENV" -eq 0 ]; then
      info "  Retrying with --break-system-packages (PEP 668 system) ..."
      "$PY" -m pip install --user --break-system-packages -r requirements.txt \
        || info "  pip install failed - check your network connection."
    else
      info "  pip install failed - check your network connection."
    fi
  fi
  if [ "$WITH_WEASY" -eq 1 ]; then
    info "  Installing WeasyPrint (optional) ..."
    if [ "$PM" = "apt-get" ]; then run_priv apt-get install -y libpango-1.0-0 libpangoft2-1.0-0 || true; fi
    "$PY" -m pip install $flags weasyprint || "$PY" -m pip install --user --break-system-packages weasyprint \
      || info "  WeasyPrint failed; reportlab will be used for PDFs instead."
  fi
}

fix_wordlist() {
  head_ "3/5  Wordlist for Gobuster"
  if [ -f "$DEFAULT_WORDLIST" ]; then info "  Found $DEFAULT_WORDLIST"; return; fi
  if [ -f /usr/share/dirb/wordlists/common.txt ]; then
    info "  Linking dirb wordlists to $DEFAULT_WORDLIST ..."
    run_priv mkdir -p /usr/share/wordlists && run_priv ln -sfn /usr/share/dirb/wordlists /usr/share/wordlists/dirb \
      && return
  fi
  info "  No system wordlist available - creating a small built-in one at wordlists/mini.txt"
  mkdir -p wordlists
  printf '%s\n' admin login logout register dashboard panel manager console backup backups old \
    config conf configuration setup install uploads upload files images img css js static assets \
    api v1 v2 test tests dev staging tmp temp logs log db database dump sql phpmyadmin pma \
    wp-admin wp-login.php wp-content cgi-bin server-status robots.txt sitemap.xml .git .env \
    .htaccess .svn index.php index.html readme.txt license.txt > wordlists/mini.txt
  info "  The wizard detects it automatically (change it in Step 1 > Settings > General)."
}

install_vulners() {
  head_ "4/5  Nmap 'vulners' CVE script (optional)"
  command -v nmap >/dev/null 2>&1 || { info "  nmap not installed - skipped."; return; }
  local dir="" d
  for d in "${NMAP_SCRIPT_DIRS[@]}"; do [ -d "$d" ] && { dir="$d"; break; }; done
  [ -z "$dir" ] && { info "  Could not find the Nmap scripts directory - skipped."; return; }
  if [ -f "$dir/vulners.nse" ]; then info "  Already installed."; return; fi
  ask_yes "  Download vulners.nse from github.com/vulnersCom/nmap-vulners?" || { info "  Skipped."; return; }
  local tmp; tmp="$(mktemp)"
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$VULNERS_URL" -o "$tmp"
  elif command -v wget >/dev/null 2>&1; then wget -q "$VULNERS_URL" -O "$tmp"
  else info "  curl/wget not found - skipped."; rm -f "$tmp"; return; fi
  if [ -s "$tmp" ] && run_priv install -m 644 "$tmp" "$dir/vulners.nse"; then
    run_priv nmap --script-updatedb >/dev/null 2>&1; info "  Installed to $dir"
  else info "  Download or install failed (network/permissions)."; fi
  rm -f "$tmp"
}

write_launcher() {
  head_ "5/5  Launcher"
  local py="python3"
  [ "$USE_VENV" -eq 1 ] && py="\"\$DIR/$VENV_DIR/bin/python\""
  cat > run.sh <<EOF
#!/usr/bin/env bash
# Starts the recon wizard using the right Python. Use: ./run.sh   (or: sudo ./run.sh)
DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
cd "\$DIR" || exit 1
exec $py recon_wizard.py "\$@"
EOF
  chmod +x run.sh
  info "  Created run.sh"
}

# ------------------------------------------------------------- the check
py_has() { "$PY" -c "import importlib.util,sys; sys.exit(0 if importlib.util.find_spec('$1') else 1)" 2>/dev/null; }

run_checks() {
  MISSING_REQ=0; MISSING_OPT=0
  resolve_py
  head_ "Requirement check"

  info " System tools"
  if py_ok; then pass "python3 >= 3.10" "$(python3 --version 2>&1)"
  else failreq "python3 >= 3.10" "install Python 3.10 or newer"; fi
  local t p
  for t in nmap nikto gobuster; do
    if p="$(command -v "$t")"; then pass "$t" "$p"
    else failreq "$t" "not on PATH (re-run ./install.sh)"; fi
  done
  if [ -f "$DEFAULT_WORDLIST" ]; then pass "wordlist" "$DEFAULT_WORDLIST"
  elif [ -f wordlists/mini.txt ]; then pass "wordlist" "$(pwd)/wordlists/mini.txt (wizard uses it automatically)"
  else failopt "wordlist" "missing - Gobuster needs one"; fi
  local found=0 d
  for d in "${NMAP_SCRIPT_DIRS[@]}"; do [ -f "$d/vulners.nse" ] && found=1; done
  if [ "$found" -eq 1 ]; then pass "nmap vulners script" "CVE lookup available"
  else failopt "nmap vulners script" "optional - enables --vulners CVE lookup"; fi
  if [ "$(id -u)" -eq 0 ]; then note "root privileges" "yes (SYN/UDP/OS scans work)"
  else note "root privileges" "no - use 'sudo ./run.sh' for -sS, -sU, -O"; fi

  info ""; info " Python libraries (using: $PY)"
  if py_ok; then
    if py_has jinja2; then pass "jinja2" "HTML reports"; else failreq "jinja2" "pip install jinja2"; fi
    if py_has docx; then pass "python-docx" "Word reports"; else failopt "python-docx" "pip install python-docx"; fi
    local pdf=""
    if py_has reportlab; then pass "reportlab" "PDF reports"; pdf="reportlab"
    else failopt "reportlab" "pip install reportlab"; fi
    if py_has weasyprint; then
      if "$PY" -c "import weasyprint" >/dev/null 2>&1; then pass "weasyprint" "optional PDF engine"; pdf="weasyprint"
      else failopt "weasyprint" "installed but system libraries (Pango) missing"; fi
    else note "weasyprint" "not installed (optional)"; fi
    [ -z "$pdf" ] && failopt "PDF export" "needs reportlab or weasyprint"
  else
    failreq "python libraries" "cannot check without Python >= 3.10"
  fi

  info ""; info " Project files"
  for f in recon_pipeline.py recon_wizard.py; do
    if [ -f "$f" ]; then pass "$f"; else failreq "$f" "missing from $(pwd)"; fi
  done
  for f in recon_menu.py recon.py; do
    if [ -f "$f" ]; then pass "$f"; else note "$f" "not present (optional)"; fi
  done

  head_ "Summary"
  if [ "$MISSING_REQ" -eq 0 ]; then
    info "  ${G}All required components are available.${N} (optional warnings: $MISSING_OPT)"
    if [ -f run.sh ]; then info "  Start the wizard with:  ./run.sh   (or: sudo ./run.sh)"
    else info "  Start the wizard with:  python3 recon_wizard.py"; fi
    return 0
  fi
  info "  ${R}$MISSING_REQ required component(s) missing.${N} Optional warnings: $MISSING_OPT"
  [ "$MODE" = "check" ] && info "  Run ./install.sh to install what is missing."
  info "  If nikto/gobuster are not packaged for your OS:"
  info "    nikto    : git clone https://github.com/sullo/nikto && sudo ln -s \$PWD/nikto/program/nikto.pl /usr/local/bin/nikto"
  info "    gobuster : go install github.com/OJ/gobuster/v3@latest"
  return 1
}

# ------------------------------------------------------------------ main
detect_pm
info "${B}Recon tools - installer${N}   (mode: $MODE, package manager: ${PM:-none detected})"

if [ "$MODE" = "install" ]; then
  install_system
  setup_python
  fix_wordlist
  install_vulners
  write_launcher
fi
run_checks
exit $?
