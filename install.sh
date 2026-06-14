#!/usr/bin/env bash
#
# install.sh - installs the `pcscan` command (macOS + Linux) and, optionally,
#              the ClamAV antivirus engine + virus signatures (freshclam).
#
#   ./install.sh             install pcscan + ClamAV (recommended)
#   ./install.sh --no-av     install pcscan only, skip ClamAV
#
set -uo pipefail
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$SRC_DIR/pcscan.sh"
WITH_AV=1
[ "${1:-}" = "--no-av" ] && WITH_AV=0

BOLD=$'\033[1m'; GRN=$'\033[32m'; YEL=$'\033[33m'; RED=$'\033[31m'; DIM=$'\033[2m'; RST=$'\033[0m'
say()  { printf "%s==>%s %s\n" "$GRN$BOLD" "$RST" "$1"; }
warn() { printf "%s[!]%s %s\n" "$YEL" "$RST" "$1"; }
err()  { printf "%s[x]%s %s\n" "$RED" "$RST" "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }

[ -f "$SCRIPT" ] || { err "pcscan.sh not found next to this installer ($SCRIPT)"; exit 1; }
chmod +x "$SCRIPT"

case "$(uname -s)" in Darwin) OS=macos ;; Linux) OS=linux ;; *) err "Unsupported OS (this installer is macOS/Linux; use install.ps1 on Windows)"; exit 1 ;; esac

# ---------------------------------------------------------------------
# 1. Install the `pcscan` command onto PATH
# ---------------------------------------------------------------------
say "Installing the 'pcscan' command..."
INSTALLED=""
for d in /usr/local/bin "$HOME/.local/bin"; do
  mkdir -p "$d" 2>/dev/null || continue
  if cp "$SCRIPT" "$d/pcscan" 2>/dev/null; then chmod +x "$d/pcscan"; INSTALLED="$d/pcscan"; break; fi
done
if [ -z "$INSTALLED" ] && have sudo; then
  if sudo mkdir -p /usr/local/bin && sudo cp "$SCRIPT" /usr/local/bin/pcscan && sudo chmod +x /usr/local/bin/pcscan; then
    INSTALLED="/usr/local/bin/pcscan"
  fi
fi
[ -z "$INSTALLED" ] && { err "Could not install the command. Run pcscan.sh directly from $SRC_DIR."; exit 1; }
say "Installed: ${BOLD}$INSTALLED${RST}"

# ensure its dir is on PATH (add to shell rc if needed)
BIN_DIR="$(dirname "$INSTALLED")"
case ":$PATH:" in
  *":$BIN_DIR:"*) : ;;
  *)
    for rc in "$HOME/.zshrc" "$HOME/.bashrc"; do
      [ -f "$rc" ] || continue
      grep -q "$BIN_DIR" "$rc" 2>/dev/null && continue
      printf '\nexport PATH="%s:$PATH"   # added by pcscan installer\n' "$BIN_DIR" >> "$rc"
      warn "Added $BIN_DIR to PATH in $rc - open a new terminal (or 'source $rc') to use 'pcscan'."
    done
    ;;
esac

# ---------------------------------------------------------------------
# 2. Install ClamAV + signatures (freshclam)
# ---------------------------------------------------------------------
if [ "$WITH_AV" -eq 1 ]; then
  if have clamscan || have clamdscan; then
    say "ClamAV already installed - refreshing signatures."
  else
    say "Installing ClamAV antivirus engine..."
    if [ "$OS" = macos ]; then
      if have brew; then
        brew install clamav || warn "brew install clamav failed - install manually later."
      else
        warn "Homebrew not found. Install it from https://brew.sh then re-run, or run './install.sh --no-av'."
      fi
    else
      if   have apt-get; then sudo apt-get update -y && sudo apt-get install -y clamav clamav-freshclam
      elif have dnf;     then sudo dnf install -y clamav clamav-update
      elif have yum;     then sudo yum install -y clamav clamav-update
      elif have pacman;  then sudo pacman -S --noconfirm clamav
      elif have zypper;  then sudo zypper install -y clamav
      else warn "No supported package manager found - install ClamAV manually."; fi
    fi
  fi

  # configure + fetch signatures
  if have freshclam; then
    say "Fetching virus signatures (freshclam)..."
    if [ "$OS" = macos ] && have brew; then
      CONF_DIR="$(brew --prefix)/etc/clamav"
      DB_DIR="$(brew --prefix)/var/lib/clamav"
      mkdir -p "$DB_DIR" "$CONF_DIR" 2>/dev/null
      if [ ! -f "$CONF_DIR/freshclam.conf" ] && [ -f "$CONF_DIR/freshclam.conf.sample" ]; then
        cp "$CONF_DIR/freshclam.conf.sample" "$CONF_DIR/freshclam.conf"
        sed -i '' '/^Example/d' "$CONF_DIR/freshclam.conf" 2>/dev/null
      fi
      freshclam || warn "freshclam failed - run it again later: freshclam"
    else
      # Linux: the freshclam service may hold a lock; stop it briefly if present
      sudo systemctl stop clamav-freshclam 2>/dev/null
      sudo freshclam || warn "freshclam failed - run 'sudo freshclam' later."
      sudo systemctl start clamav-freshclam 2>/dev/null
    fi
  else
    warn "freshclam not available yet - after ClamAV installs, run 'freshclam' to download signatures."
  fi
fi

# ---------------------------------------------------------------------
# 3. Done
# ---------------------------------------------------------------------
echo
say "${BOLD}Done.${RST}"
echo "  Run it now:        ${BOLD}pcscan${RST}              ${DIM}(interactive menu)${RST}"
echo "  Quick check:       ${BOLD}pcscan --diff${RST}       ${DIM}(what changed since baseline)${RST}"
echo "  Deep virus scan:   ${BOLD}pcscan --malware${RST}    ${DIM}(uses ClamAV)${RST}"
echo "  First-time setup:  ${BOLD}pcscan --save-baseline${RST}"
have clamscan && echo "  ${GRN}ClamAV ready.${RST}" || warn "ClamAV not active yet - see messages above."
