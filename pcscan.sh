#!/usr/bin/env bash
#
# pcscan - portable defensive PC health, security & investigation scan
#          (macOS + Linux)
#
# Read-only investigation of YOUR OWN machine: network, system hardening,
# persistence, browser extensions, malware heuristics + AV, a forensic
# quick-look, and a baseline/diff to catch anything new since last time.
#
# Interactive:   ./pcscan.sh                 (banner + menu)
# Direct flags:  ./pcscan.sh --full | --quick | --net | --system | --persist
#                            --browser | --malware | --forensics
#                            --diff | --save-baseline | --report
#                ./pcscan.sh --no-color       plain output (for files/pipes)
#
# Nothing here modifies the system. sudo is optional (lets it read system
# LaunchDaemons / full firewall rules / all processes) but never required.

set -uo pipefail

PCDIR="$HOME/pcscan"
BASELINE="$PCDIR/baseline.txt"

# ---------- options ----------
QUICK=0; DEEP=0; USE_COLOR=1; ACTION=""
for a in "$@"; do
  case "$a" in
    --quick)         ACTION="quick" ;;
    --full)          ACTION="full" ;;
    --net)           ACTION="net" ;;
    --system)        ACTION="system" ;;
    --persist)       ACTION="persist" ;;
    --browser)       ACTION="browser" ;;
    --malware)       ACTION="malware" ;;
    --forensics)     ACTION="forensics" ;;
    --diff)          ACTION="diff" ;;
    --save-baseline) ACTION="baseline" ;;
    --report)        ACTION="report" ;;
    --no-color)      USE_COLOR=0 ;;
    -h|--help)       grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -24; exit 0 ;;
  esac
done
[ -t 1 ] || USE_COLOR=0

# ---------- colors ----------
if [ "$USE_COLOR" -eq 1 ]; then
  BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; YEL=$'\033[33m'
  GRN=$'\033[32m'; BLU=$'\033[36m'; MAG=$'\033[35m'; RST=$'\033[0m'
else
  BOLD=""; DIM=""; RED=""; YEL=""; GRN=""; BLU=""; MAG=""; RST=""
fi

# ---------- findings engine ----------
FINDINGS=()
reset_findings() { FINDINGS=(); }
crit() { FINDINGS+=("CRIT|$1"); }
warn() { FINDINGS+=("WARN|$1"); }
info() { FINDINGS+=("INFO|$1"); }

section() { printf "\n%s== %s ==%s\n" "$BOLD$BLU" "$1" "$RST"; }
line()    { printf "  %s\n" "$1"; }
have()    { command -v "$1" >/dev/null 2>&1; }

# private/local IP test (for C2 heuristics)
is_private_ip() {
  case "$1" in
    10.*|192.168.*|127.*|169.254.*|::1|fe80:*|fd*) return 0 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
    *) return 1 ;;
  esac
}

case "$(uname -s)" in
  Darwin) PLATFORM="macos" ;;
  Linux)  PLATFORM="linux" ;;
  *)      PLATFORM="unknown" ;;
esac

# =====================================================================
# BANNER
# =====================================================================
banner() {
  printf "%s\n" "$BOLD$MAG"
  cat <<'EOF'
   ████ ████ ████ ████ ████ █  █
   █  █ █    █    █    █  █ ██ █
   ████ █    ████ █    ████ █ ██
   █    █       █ █    █  █ █  █
   █    ████ ████ ████ █  █ █  █
EOF
  printf "%s" "$RST"
  printf "   %sdefensive health · security · investigation%s\n" "$DIM" "$RST"
  printf "   %s%s · %s · %s%s\n\n" "$GRN" "$(hostname 2>/dev/null)" "$PLATFORM" "$(date '+%Y-%m-%d %H:%M')" "$RST"
}

# =====================================================================
# 1. NETWORK
# =====================================================================
scan_network() {
  section "Network: interfaces & gateway"
  if [ "$PLATFORM" = macos ]; then
    ifconfig 2>/dev/null | awk '/^[a-z].*flags=/{i=$1} /inet /{print i, $2}' | grep -v '127.0.0.1' | while read -r i ip; do line "$i  $ip"; done
    GW=$(route -n get default 2>/dev/null | awk '/gateway/{print $2}')
  else
    ip -brief addr 2>/dev/null | awk '$3!=""{print "  "$1"  "$3}' || ifconfig 2>/dev/null | grep 'inet '
    GW=$(ip route show default 2>/dev/null | awk '/default/{print $3; exit}')
  fi
  [ -n "${GW:-}" ] && line "gateway: $GW"

  section "Network: DNS resolvers"
  DNS=""
  if [ "$PLATFORM" = macos ]; then
    DNS=$(scutil --dns 2>/dev/null | awk '/nameserver\[/{print $3}' | sort -u)
  elif have resolvectl; then
    DNS=$(resolvectl status 2>/dev/null | awk '/DNS Servers/{$1=$2="";print}' | tr -s ' ')
  fi
  [ -z "$DNS" ] && DNS=$(awk '/^nameserver/{print $2}' /etc/resolv.conf 2>/dev/null | sort -u)
  for d in $DNS; do
    line "$d"
    case "$d" in
      45.90.28.*|45.90.30.*)   info "DNS via NextDNS ($d) - filtering/privacy service. Fine if you set it up." ;;
      1.1.1.*|1.0.0.*)         info "DNS via Cloudflare ($d)." ;;
      8.8.8.*|8.8.4.*)         info "DNS via Google ($d)." ;;
      9.9.9.*)                 info "DNS via Quad9 ($d)." ;;
      127.0.0.1|::1|"${GW:-}") : ;;
      *)                       info "DNS resolver $d - confirm this is one you configured." ;;
    esac
  done

  section "Network: /etc/hosts overrides"
  HOSTS_EXTRA=$(grep -vE '^\s*#|^\s*$|^\s*(127\.0\.0\.1|::1|255\.255\.255\.255|fe80::|ff02::)\s' /etc/hosts 2>/dev/null)
  if [ -n "$HOSTS_EXTRA" ]; then
    echo "$HOSTS_EXTRA" | while read -r l; do line "$l"; done
    if echo "$HOSTS_EXTRA" | grep -qiE 'mdmenrollment|deviceenrollment|iprofiles\.apple'; then
      info "/etc/hosts blocks Apple MDM enrollment - common & intentional on ex-enterprise Macs to suppress the enrollment popup. Benign if you added it. NOTE: an OS reinstall wipes /etc/hosts and the popup returns."
    fi
    if echo "$HOSTS_EXTRA" | grep -qvE 'mdmenrollment|deviceenrollment|iprofiles\.apple'; then
      warn "/etc/hosts has custom redirects. Verify each line - attackers use this to redirect banking/update domains. (Ad-block lists are also common & benign.)"
    fi
  else
    line "(none - default file)"
  fi

  section "Network: listening ports"
  LISTEN=""
  if [ "$PLATFORM" = macos ]; then
    LISTEN=$(lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1{print $1"\t"$9}' | sort -u)
  elif have ss; then
    LISTEN=$(ss -tlnp 2>/dev/null | awk 'NR>1{print $6"\t"$4}')
  elif have netstat; then
    LISTEN=$(netstat -tlnp 2>/dev/null | awk 'NR>2{print $7"\t"$4}')
  fi
  if [ -n "$LISTEN" ]; then
    echo "$LISTEN" | while IFS=$'\t' read -r proc addr; do line "$(printf '%-22s %s' "$proc" "$addr")"; done
    if echo "$LISTEN" | grep -qE '(\*:|0\.0\.0\.0:|\[::\]:)'; then
      EXT=$(echo "$LISTEN" | grep -E '(\*:|0\.0\.0\.0:|\[::\]:)' | grep -vE '127\.0\.0\.1|\[::1\]' | grep -c '.')
      [ "$EXT" -gt 0 ] && info "$EXT service(s) listen on all interfaces (reachable from the LAN). On macOS *:5000/*:7000 = AirPlay, rapportd = Handoff - normal. Investigate anything you don't recognize."
    fi
  else
    line "(could not enumerate - try with sudo)"
  fi

  if [ "$QUICK" -eq 0 ]; then
    section "Network: LAN neighbors"
    if [ "$PLATFORM" = macos ]; then
      arp -a -n 2>/dev/null | awk '{print $2, $4}' | tr -d '()' | while read -r ip mac; do line "$(printf '%-16s %s' "$ip" "$mac")"; done
    elif have ip; then
      ip neigh 2>/dev/null | awk '$1!~/:/{print $1, $5}' | while read -r ip mac; do line "$(printf '%-16s %s' "$ip" "$mac")"; done
    fi

    section "Network: established outbound connections"
    CONNS=""
    if [ "$PLATFORM" = macos ]; then
      CONNS=$(lsof -nP -iTCP -sTCP:ESTABLISHED 2>/dev/null | awk 'NR>1{print $1"\t"$9}' | sort -u)
    elif have ss; then
      CONNS=$(ss -tnp state established 2>/dev/null | awk 'NR>1{print $6"\t"$5}')
    fi
    UNUSUAL=0
    if [ -n "$CONNS" ]; then
      echo "$CONNS" | head -40 | while IFS=$'\t' read -r p c; do line "$(printf '%-18s %s' "$p" "$c")"; done
      # C2 heuristic: established to a PUBLIC ip on a non-web port
      while IFS=$'\t' read -r p c; do
        rip="${c##*>}"; rip="${rip%:*}"; rip="${rip#*>}"
        rport="${c##*:}"
        [ -z "$rport" ] && continue
        case "$rport" in 80|443|53|0) continue ;; esac
        is_private_ip "$rip" && continue
        UNUSUAL=$((UNUSUAL+1))
      done <<< "$(echo "$CONNS" | sed 's/.*\t//')"
    fi
  fi

  section "Network: proxy configuration"
  PROXY_FOUND=0
  if [ "$PLATFORM" = macos ]; then
    for svc in "Wi-Fi" "Ethernet"; do
      for kind in getwebproxy getsecurewebproxy getsocksfirewallproxy; do
        out=$(networksetup -$kind "$svc" 2>/dev/null)
        if echo "$out" | grep -q "Enabled: Yes"; then
          srv=$(echo "$out" | awk '/Server/{print $2}')
          line "$svc $kind -> $srv"; PROXY_FOUND=1
        fi
      done
    done
  else
    for v in http_proxy https_proxy all_proxy; do
      [ -n "${!v:-}" ] && { line "$v=${!v}"; PROXY_FOUND=1; }
    done
  fi
  if [ "$PROXY_FOUND" -eq 1 ]; then
    warn "A network proxy is ACTIVE. If you didn't set this, it can intercept your traffic (MITM). Verify it."
  else
    line "(no proxy set)"
  fi
}

# =====================================================================
# 2. SYSTEM HARDENING
# =====================================================================
scan_system() {
  section "System: security protections"
  if [ "$PLATFORM" = macos ]; then
    /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | grep -q "enabled" \
      && line "Firewall: ${GRN}ON${RST}" || { line "Firewall: ${RED}OFF${RST}"; warn "Application firewall is OFF. Enable in System Settings > Network > Firewall."; }
    csrutil status 2>/dev/null | grep -q "enabled" \
      && line "SIP: ${GRN}enabled${RST}" || { line "SIP: ${RED}disabled${RST}"; crit "System Integrity Protection is DISABLED. Re-enable from Recovery (csrutil enable) unless you knowingly need it off."; }
    spctl --status 2>/dev/null | grep -q "enabled" \
      && line "Gatekeeper: ${GRN}enabled${RST}" || { line "Gatekeeper: ${RED}disabled${RST}"; warn "Gatekeeper is disabled - unsigned apps run without checks."; }
    fdesetup status 2>/dev/null | grep -q "On" \
      && line "FileVault: ${GRN}on${RST}" || { line "FileVault: ${YEL}off${RST}"; warn "FileVault disk encryption is OFF. Enable it to protect data if the Mac is lost/stolen."; }
  else
    if have ufw && ufw status 2>/dev/null | grep -qi active; then line "Firewall: ${GRN}ufw active${RST}"
    elif have firewall-cmd && firewall-cmd --state 2>/dev/null | grep -qi running; then line "Firewall: ${GRN}firewalld running${RST}"
    elif have nft && [ -n "$(nft list ruleset 2>/dev/null)" ]; then line "Firewall: ${GRN}nftables rules present${RST}"
    else line "Firewall: ${YEL}none detected${RST}"; warn "No active firewall detected (ufw/firewalld/nftables). Consider 'sudo ufw enable'."; fi
    if have getenforce; then
      st=$(getenforce 2>/dev/null)
      [ "$st" = Enforcing ] && line "SELinux: ${GRN}enforcing${RST}" || { line "SELinux: ${YEL}$st${RST}"; [ "$st" = Disabled ] && warn "SELinux disabled."; }
    elif have aa-status; then
      aa-status --enabled 2>/dev/null && line "AppArmor: ${GRN}enabled${RST}" || line "AppArmor: ${YEL}not enabled${RST}"
    fi
    if have lsblk && lsblk -o TYPE 2>/dev/null | grep -q crypt; then line "Disk encryption: ${GRN}LUKS present${RST}"; else line "Disk encryption: ${YEL}no LUKS volume detected${RST}"; fi
  fi
}

# =====================================================================
# 3. PERSISTENCE
# =====================================================================
scan_persistence() {
  section "Persistence: startup & background items"
  if [ "$PLATFORM" = macos ]; then
    for d in "$HOME/Library/LaunchAgents" "/Library/LaunchAgents" "/Library/LaunchDaemons"; do
      if [ -d "$d" ]; then
        items=$(ls -1 "$d" 2>/dev/null | grep -viE '^com\.apple\.')
        [ -n "$items" ] && { line "${DIM}$d${RST}"; echo "$items" | while read -r f; do line "  $f"; done; }
      fi
    done
    LI=$(osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null)
    [ -n "$LI" ] && line "Login items: $LI"
    info "Review the list above - persistence is the #1 place malware hides. Anything you don't recognize, look it up before trusting it."
  else
    for d in "$HOME/.config/autostart" "$HOME/.config/systemd/user"; do
      [ -d "$d" ] && { line "${DIM}$d${RST}"; ls -1 "$d" 2>/dev/null | while read -r f; do line "  $f"; done; }
    done
    cron=$(crontab -l 2>/dev/null)
    [ -n "$cron" ] && { line "${DIM}user crontab:${RST}"; echo "$cron" | grep -vE '^\s*#' | while read -r l; do line "  $l"; done; }
    info "Review autostart/systemd-user/cron above. Persistence is the #1 place malware hides."
  fi
}

# =====================================================================
# 4. BROWSERS
# =====================================================================
scan_mozilla() {
  local base="$1" label="$2" prof n
  [ -d "$base" ] || return
  for prof in "$base"/*/; do
    [ -d "${prof}extensions" ] || continue
    n=$(ls -1 "${prof}extensions" 2>/dev/null | grep -c '.')
    line "${label} [$(basename "$prof")]: $n extension(s)"
    ls -1 "${prof}extensions" 2>/dev/null | sed 's/\.xpi$//' | while read -r ext; do line "  - $ext"; done
  done
}
scan_chromium() {
  local base="$1" label="$2" extdir d name
  for extdir in "$base"/*/Extensions "$base"/Extensions; do
    [ -d "$extdir" ] || continue
    for d in "$extdir"/*/; do
      [ -d "$d" ] || continue
      name=$(basename "$d"); [ "$name" = "Temp" ] && continue
      line "$label: $name"
    done
  done
}
scan_browsers() {
  section "Browsers: installed extensions"
  if [ "$PLATFORM" = macos ]; then
    APPSUP="$HOME/Library/Application Support"
    scan_mozilla "$APPSUP/zen/Profiles" "Zen"
    scan_mozilla "$APPSUP/Firefox/Profiles" "Firefox"
    scan_chromium "$APPSUP/Google/Chrome" "Chrome"
    scan_chromium "$APPSUP/BraveSoftware/Brave-Browser" "Brave"
    scan_chromium "$APPSUP/Microsoft Edge" "Edge"
  else
    scan_mozilla "$HOME/.zen" "Zen"
    scan_mozilla "$HOME/.mozilla/firefox" "Firefox"
    scan_chromium "$HOME/.config/google-chrome" "Chrome"
    scan_chromium "$HOME/.config/chromium" "Chromium"
    scan_chromium "$HOME/.config/BraveSoftware/Brave-Browser" "Brave"
  fi
  info "Cross-check every extension against the official store listing. Unknown/sideloaded extensions are a top vector for data theft & ad injection. Keep the list short."
}

# =====================================================================
# 5. MALWARE / VIRUS
# =====================================================================
SUSPECT_DIRS_MAC="/tmp /private/tmp /var/tmp /Users/Shared $HOME/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons"
SUSPECT_DIRS_LIN="/tmp /var/tmp /dev/shm $HOME/.config/autostart"
BAD_PATTERN='curl |wget |base64 |bash -i|/dev/tcp/|nc -e|ncat |python -c|osascript -e .*do shell|eval(|launchctl load.*tmp'

scan_malware() {
  section "Malware: built-in protections"
  if [ "$PLATFORM" = macos ]; then
    xp=$(defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info CFBundleShortVersionString 2>/dev/null)
    [ -z "$xp" ] && xp=$(defaults read /System/Library/CoreServices/XProtect.bundle/Contents/Info CFBundleShortVersionString 2>/dev/null)
    [ -n "$xp" ] && line "XProtect (Apple AV) signature version: $xp" || line "XProtect: version not readable"
    mr=$(defaults read /Library/Apple/System/Library/CoreServices/MRT.app/Contents/Info CFBundleShortVersionString 2>/dev/null)
    [ -n "$mr" ] && line "MRT (Malware Removal Tool) version: $mr"
  else
    line "(Linux has no built-in AV; relying on ClamAV/rkhunter if installed)"
  fi

  section "Malware: AV / rootkit tools available"
  for t in clamscan clamdscan freshclam rkhunter chkrootkit; do
    have "$t" && line "${GRN}found${RST}: $t" || line "${DIM}missing${RST}: $t"
  done
  if ! have clamscan && ! have clamdscan; then
    info "No on-demand AV engine installed. To enable deep scans: macOS 'brew install clamav', Debian/Ubuntu 'sudo apt install clamav', then run 'freshclam' to fetch signatures."
  fi

  if [ "$PLATFORM" = macos ]; then
    section "Malware: recently downloaded / quarantined files (last 7 days)"
    n=0
    while IFS= read -r f; do
      [ -z "$f" ] && continue
      n=$((n+1)); [ "$n" -le 25 ] && line "$f"
    done <<< "$(find "$HOME/Downloads" "$HOME/Desktop" -type f -mtime -7 2>/dev/null)"
    [ "$n" -eq 0 ] && line "(none in the last 7 days)"
    [ "$n" -gt 25 ] && line "...(+$((n-25)) more)"
  fi

  section "Malware: executables in temp / shared dirs"
  dirs="$SUSPECT_DIRS_MAC"; [ "$PLATFORM" = linux ] && dirs="$SUSPECT_DIRS_LIN"
  found_tmp=0
  for d in $dirs; do
    [ -d "$d" ] || continue
    while IFS= read -r f; do
      [ -z "$f" ] && continue
      line "${YEL}exec${RST}: $f"; found_tmp=$((found_tmp+1))
    done <<< "$(find "$d" -maxdepth 2 -type f -perm -u+x 2>/dev/null | head -15)"
  done
  if [ "$found_tmp" -gt 0 ]; then
    warn "$found_tmp executable file(s) found in temp/shared dirs. Legit installers use these too, but malware loves them - verify any you don't recognize."
  else
    line "(none)"
  fi

  section "Malware: suspicious persistence content"
  hits=0
  if [ "$PLATFORM" = macos ]; then
    for d in "$HOME/Library/LaunchAgents" "/Library/LaunchAgents" "/Library/LaunchDaemons"; do
      [ -d "$d" ] || continue
      for f in "$d"/*.plist; do
        [ -f "$f" ] || continue
        body=$(plutil -p "$f" 2>/dev/null)
        if echo "$body" | grep -qiE "$BAD_PATTERN"; then line "${RED}suspect${RST}: $f"; hits=$((hits+1)); fi
      done
    done
  else
    for f in "$HOME/.config/autostart"/*.desktop; do
      [ -f "$f" ] || continue
      if grep -qiE "$BAD_PATTERN" "$f"; then line "${RED}suspect${RST}: $f"; hits=$((hits+1)); fi
    done
    crontab -l 2>/dev/null | grep -iE "$BAD_PATTERN" >/dev/null && { line "${RED}suspect${RST}: user crontab"; hits=$((hits+1)); }
  fi
  if [ "$hits" -gt 0 ]; then
    crit "$hits persistence item(s) contain downloader/reverse-shell patterns (curl|base64|/dev/tcp|nc -e ...). Inspect them now - this is a classic infection signature."
  else
    line "(no suspicious patterns in startup items)"
  fi

  if [ "$DEEP" -eq 1 ] && { have clamscan || have clamdscan; }; then
    section "Malware: ClamAV deep scan (Downloads, Desktop, /tmp)"
    eng="clamscan"; have clamdscan && eng="clamdscan"
    line "${DIM}running $eng (this can take a while)...${RST}"
    targets=""
    for t in "$HOME/Downloads" "$HOME/Desktop" "/tmp"; do [ -d "$t" ] && targets="$targets $t"; done
    out=$("$eng" -r --infected --no-summary $targets 2>/dev/null)
    if [ -n "$out" ]; then
      echo "$out" | while read -r l; do line "${RED}$l${RST}"; done
      crit "ClamAV flagged infected file(s) above. Quarantine/delete them and investigate how they arrived."
    else
      line "${GRN}ClamAV: no infections found in scanned paths.${RST}"
    fi
  elif [ "$DEEP" -eq 1 ]; then
    line "(deep scan requested but no ClamAV engine installed - see note above)"
  fi
}

# =====================================================================
# 6. FORENSIC QUICK-LOOK
# =====================================================================
scan_forensics() {
  section "Forensics: files modified in sensitive dirs (last 3 days)"
  sdirs="$HOME/Library/LaunchAgents /usr/local/bin /usr/local/sbin $HOME/bin /tmp"
  [ "$PLATFORM" = linux ] && sdirs="$HOME/.config/autostart /usr/local/bin $HOME/bin /etc/cron.d /tmp"
  cnt=0
  for d in $sdirs; do
    [ -d "$d" ] || continue
    while IFS= read -r f; do
      [ -z "$f" ] && continue
      line "$f"; cnt=$((cnt+1))
    done <<< "$(find "$d" -maxdepth 2 -type f -mtime -3 2>/dev/null | head -20)"
  done
  [ "$cnt" -eq 0 ] && line "(nothing changed recently)"

  section "Forensics: processes running from unusual paths"
  bad=0
  if [ "$PLATFORM" = macos ]; then
    procs=$(ps -axo pid=,comm= 2>/dev/null)
  else
    procs=$(ps -eo pid=,args= 2>/dev/null)
  fi
  while read -r pid path; do
    case "$path" in
      /tmp/*|/private/tmp/*|/var/tmp/*|/dev/shm/*|/Users/Shared/*|*/.hidden/*)
        line "${RED}PID $pid${RST} $path"; bad=$((bad+1)) ;;
    esac
  done <<< "$procs"
  if [ "$bad" -gt 0 ]; then
    crit "$bad process(es) running from temp/shared/hidden paths. Legit software does not normally do this - investigate."
  else
    line "(none - no processes from temp/shared/hidden paths)"
  fi

  section "Forensics: shell startup files"
  for rc in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile"; do
    [ -f "$rc" ] || continue
    mt=$(stat -f "%Sm" "$rc" 2>/dev/null || stat -c "%y" "$rc" 2>/dev/null)
    line "$(printf '%-28s last modified %s' "$rc" "$mt")"
    if grep -qiE "$BAD_PATTERN" "$rc" 2>/dev/null; then
      warn "$rc contains a downloader/reverse-shell-like pattern. Open it and verify the line is yours."
    fi
  done

  section "Forensics: SSH authorized_keys"
  if [ -f "$HOME/.ssh/authorized_keys" ]; then
    k=$(grep -cvE '^\s*#|^\s*$' "$HOME/.ssh/authorized_keys" 2>/dev/null)
    line "$k key(s) authorized to log into THIS account via SSH:"
    awk '{print "  - "$3" ("$1")"}' "$HOME/.ssh/authorized_keys" 2>/dev/null | while read -r l; do line "$l"; done
    warn "Every key here can log in as you. Remove any you don't recognize ($HOME/.ssh/authorized_keys)."
  else
    line "(no authorized_keys - no key-based SSH access configured)"
  fi

  section "Forensics: user accounts & sudoers"
  if [ "$PLATFORM" = macos ]; then
    dscl . list /Users 2>/dev/null | grep -vE '^_|daemon|nobody|root|Guest' | tr '\n' ' ' | sed 's/^/  human users: /'; echo
  else
    awk -F: '$3>=1000 && $3<65534{print $1}' /etc/passwd 2>/dev/null | tr '\n' ' ' | sed 's/^/  human users: /'; echo
  fi
  if [ -d /etc/sudoers.d ]; then
    extra=$(ls -1 /etc/sudoers.d 2>/dev/null | grep -vE '^README$')
    [ -n "$extra" ] && { line "/etc/sudoers.d entries:"; echo "$extra" | while read -r f; do line "  $f"; done; }
  fi

  section "Forensics: recent logins"
  if have last; then
    last 2>/dev/null | grep -vE '^$|wtmp' | head -8 | while read -r l; do line "$l"; done
  fi
  if [ "$PLATFORM" = linux ] && [ -r /var/log/auth.log ]; then
    fp=$(grep -c "Failed password" /var/log/auth.log 2>/dev/null)
    [ "${fp:-0}" -gt 0 ] && warn "$fp 'Failed password' entries in /var/log/auth.log - possible brute-force attempts."
  fi
  info "Forensic quick-look complete. None of these alone proves compromise - they're leads. Cross-check anything flagged."
}

# =====================================================================
# SNAPSHOT / DIFF  (deterministic, color-free, sorted)
# =====================================================================
snapshot() {
  {
    # DNS
    if [ "$PLATFORM" = macos ]; then
      scutil --dns 2>/dev/null | awk '/nameserver\[/{print "DNS "$3}'
    else
      awk '/^nameserver/{print "DNS "$2}' /etc/resolv.conf 2>/dev/null
    fi
    # hosts overrides
    grep -vE '^\s*#|^\s*$|^\s*(127\.0\.0\.1|::1|255\.255\.255\.255|fe80::|ff02::)\s' /etc/hosts 2>/dev/null | sed 's/^/HOSTS /'
    # listening ports
    if [ "$PLATFORM" = macos ]; then
      lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1{print "PORT "$1" "$9}'
    elif have ss; then
      ss -tlnp 2>/dev/null | awk 'NR>1{print "PORT "$4}'
    fi
    # persistence
    if [ "$PLATFORM" = macos ]; then
      for d in "$HOME/Library/LaunchAgents" "/Library/LaunchAgents" "/Library/LaunchDaemons"; do
        [ -d "$d" ] && ls -1 "$d" 2>/dev/null | grep -viE '^com\.apple\.' | sed "s|^|PERSIST $d/|"
      done
      osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null | tr ',' '\n' | sed 's/^ *//; s/^/LOGINITEM /'
    else
      for d in "$HOME/.config/autostart" "$HOME/.config/systemd/user"; do
        [ -d "$d" ] && ls -1 "$d" 2>/dev/null | sed "s|^|PERSIST $d/|"
      done
      crontab -l 2>/dev/null | grep -vE '^\s*#|^\s*$' | sed 's/^/CRON /'
    fi
    # browser extensions
    if [ "$PLATFORM" = macos ]; then
      for b in "$HOME/Library/Application Support/zen/Profiles" "$HOME/Library/Application Support/Firefox/Profiles"; do
        [ -d "$b" ] && find "$b" -path '*/extensions/*' -maxdepth 3 -name '*.xpi' 2>/dev/null | sed 's|.*/||; s/^/EXT /'
      done
    else
      for b in "$HOME/.zen" "$HOME/.mozilla/firefox"; do
        [ -d "$b" ] && find "$b" -path '*/extensions/*' -maxdepth 3 -name '*.xpi' 2>/dev/null | sed 's|.*/||; s/^/EXT /'
      done
    fi
  } 2>/dev/null | sort -u
}

save_baseline() {
  mkdir -p "$PCDIR"
  snapshot > "$BASELINE"
  printf "%sBaseline saved:%s %s  %s(%s lines)%s\n" "$GRN$BOLD" "$RST" "$BASELINE" "$DIM" "$(grep -c . "$BASELINE")" "$RST"
}

run_diff() {
  mkdir -p "$PCDIR"
  if [ ! -f "$BASELINE" ]; then
    save_baseline
    printf "%sNo baseline existed - created one now. Run --diff again later to see what changed.%s\n" "$YEL" "$RST"
    return
  fi
  local when cur
  when=$(stat -f "%Sm" "$BASELINE" 2>/dev/null || stat -c "%y" "$BASELINE" 2>/dev/null)
  cur=$(mktemp); snapshot > "$cur"
  section "Diff vs baseline (taken $when)"
  local added removed
  added=$(comm -13 "$BASELINE" "$cur")
  removed=$(comm -23 "$BASELINE" "$cur")
  if [ -z "$added" ] && [ -z "$removed" ]; then
    printf "  %sNo changes since baseline.%s\n" "$GRN" "$RST"
  else
    [ -n "$added" ]   && echo "$added"   | while read -r l; do printf "  %s+ %s%s\n" "$GRN" "$l" "$RST"; done
    [ -n "$removed" ] && echo "$removed" | while read -r l; do printf "  %s- %s%s\n" "$RED" "$l" "$RST"; done
    info "NEW (+) items are the priority - a new listening port, extension, or startup item you didn't add is the strongest single signal something changed. (-) items just went away (uninstalled/closed)."
  fi
  rm -f "$cur"
  reset_findings; [ -n "$added$removed" ] && info "Diff complete. To accept the current state as the new normal, choose 'Save baseline'."
  print_summary
}

# =====================================================================
# SUMMARY
# =====================================================================
print_summary() {
  local nc=0 nw=0 ni=0 f
  for f in "${FINDINGS[@]:-}"; do case "$f" in CRIT*) nc=$((nc+1));; WARN*) nw=$((nw+1));; INFO*) ni=$((ni+1));; esac; done
  printf "\n%s== Findings summary ==%s\n" "$BOLD$BLU" "$RST"
  printf "  %s%d critical%s  %s%d warnings%s  %s%d info%s\n\n" "$RED" "$nc" "$RST" "$YEL" "$nw" "$RST" "$DIM" "$ni" "$RST"
  local sev msg
  for sev in CRIT WARN INFO; do
    for f in "${FINDINGS[@]:-}"; do
      [ "${f%%|*}" = "$sev" ] || continue
      msg="${f#*|}"
      case "$sev" in
        CRIT) printf "  %s[CRIT]%s %s\n" "$RED$BOLD" "$RST" "$msg" ;;
        WARN) printf "  %s[WARN]%s %s\n" "$YEL" "$RST" "$msg" ;;
        INFO) printf "  %s[info]%s %s\n" "$DIM" "$RST" "$msg" ;;
      esac
    done
  done
  echo
  if [ "$nc" -gt 0 ]; then printf "%sResult: review the CRITICAL items above.%s\n" "$RED$BOLD" "$RST"
  elif [ "$nw" -gt 0 ]; then printf "%sResult: no critical issues; check the warnings.%s\n" "$YEL" "$RST"
  else printf "%sResult: clean - no critical or warning findings.%s\n" "$GRN$BOLD" "$RST"; fi
}

# ---------- run helpers ----------
run_full()    { QUICK=0; reset_findings; scan_network; scan_system; scan_persistence; scan_browsers; scan_malware; scan_forensics; print_summary; }
run_quick()   { QUICK=1; reset_findings; scan_network; scan_system; scan_persistence; scan_browsers; scan_malware; print_summary; }
run_section() { reset_findings; "$1"; print_summary; }
run_report()  {
  mkdir -p "$PCDIR"
  local f="$PCDIR/report-$(date +%F_%H%M).txt"
  ( USE_COLOR=0; BOLD=""; DIM=""; RED=""; YEL=""; GRN=""; BLU=""; MAG=""; RST=""; run_full ) > "$f"
  printf "%sReport saved:%s %s\n" "$GRN$BOLD" "$RST" "$f"
}

# =====================================================================
# MENU
# =====================================================================
menu() {
  while true; do
    clear 2>/dev/null
    banner
    printf "  %s%sMENU%s\n" "$BOLD" "$BLU" "$RST"
    printf "    %s[1]%s Full scan            %s(everything below + forensics)%s\n" "$GRN" "$RST" "$DIM" "$RST"
    printf "    %s[2]%s Quick scan           %s(skips LAN + deep forensics)%s\n" "$GRN" "$RST" "$DIM" "$RST"
    printf "    %s[3]%s Network              %s(interfaces, DNS, hosts, ports, C2 check)%s\n" "$GRN" "$RST" "$DIM" "$RST"
    printf "    %s[4]%s System hardening     %s(firewall, SIP/SELinux, encryption)%s\n" "$GRN" "$RST" "$DIM" "$RST"
    printf "    %s[5]%s Persistence          %s(startup items, agents, cron)%s\n" "$GRN" "$RST" "$DIM" "$RST"
    printf "    %s[6]%s Browser extensions   %s(Zen, Firefox, Chrome, Brave, Edge)%s\n" "$GRN" "$RST" "$DIM" "$RST"
    printf "    %s[7]%s Malware / virus scan %s(AV + heuristics; runs ClamAV if installed)%s\n" "$MAG" "$RST" "$DIM" "$RST"
    printf "    %s[8]%s Forensic quick-look  %s(recent files, rogue procs, SSH keys, logins)%s\n" "$MAG" "$RST" "$DIM" "$RST"
    printf "    %s[9]%s Diff vs baseline     %s(what changed since last baseline)%s\n" "$BLU" "$RST" "$DIM" "$RST"
    printf "    %s[s]%s Save / update baseline\n" "$BLU" "$RST"
    printf "    %s[r]%s Save full report to file\n" "$BLU" "$RST"
    printf "    %s[0]%s Exit\n\n" "$RED" "$RST"
    printf "  %sChoose >%s " "$BOLD" "$RST"
    read -r choice
    echo
    case "$choice" in
      1) run_full ;;
      2) run_quick ;;
      3) run_section scan_network ;;
      4) run_section scan_system ;;
      5) run_section scan_persistence ;;
      6) run_section scan_browsers ;;
      7) DEEP=1; run_section scan_malware; DEEP=0 ;;
      8) run_section scan_forensics ;;
      9) run_diff ;;
      s|S) save_baseline ;;
      r|R) run_report ;;
      0|q|Q) printf "%sbye.%s\n" "$DIM" "$RST"; exit 0 ;;
      *) printf "  %sinvalid choice%s\n" "$RED" "$RST" ;;
    esac
    printf "\n  %spress Enter to return to the menu...%s" "$DIM" "$RST"
    read -r _
  done
}

# =====================================================================
# DISPATCH
# =====================================================================
case "$ACTION" in
  full)      banner; run_full ;;
  quick)     banner; run_quick ;;
  net)       banner; run_section scan_network ;;
  system)    banner; run_section scan_system ;;
  persist)   banner; run_section scan_persistence ;;
  browser)   banner; run_section scan_browsers ;;
  malware)   banner; DEEP=1; run_section scan_malware ;;
  forensics) banner; run_section scan_forensics ;;
  diff)      banner; run_diff ;;
  baseline)  save_baseline ;;
  report)    run_report ;;
  "")        if [ -t 0 ] && [ -t 1 ]; then menu; else banner; run_full; fi ;;
esac
