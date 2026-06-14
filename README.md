# pcscan

A portable, **read-only** defensive PC health, security & investigation scanner for **macOS, Linux, and Windows**.

It checks your own machine across:

- **Network** — interfaces, gateway, DNS resolvers, `/etc/hosts` overrides, listening ports, LAN neighbors, outbound connections (with a C2 heuristic), proxy
- **System hardening** — firewall, SIP / SELinux / AppArmor / Defender, Gatekeeper, FileVault / LUKS / BitLocker, UAC
- **Persistence** — launch agents/daemons, login items, autostart, cron, registry Run keys, scheduled tasks
- **Browsers** — installed extensions (Zen, Firefox, Chrome, Brave, Edge)
- **Malware** — ClamAV (macOS/Linux) or Microsoft Defender (Windows) + heuristics for downloader/reverse-shell persistence
- **Forensic quick-look** — recently modified files, processes from temp/hidden paths, shell-rc tampering, SSH keys, user accounts, recent logins
- **Baseline / diff** — snapshot your clean state, then see exactly what changed since

Every check is read-only. `sudo`/Administrator is optional (reveals more) but never required.

## Install

### macOS / Linux
```bash
git clone <your-repo-url> pcscan && cd pcscan
./install.sh            # installs the `pcscan` command + ClamAV + signatures
./install.sh --no-av    # script only, skip ClamAV
```

### Windows (PowerShell)
```powershell
git clone <your-repo-url> pcscan; cd pcscan
powershell -ExecutionPolicy Bypass -File .\install.ps1              # pcscan + update Defender
powershell -ExecutionPolicy Bypass -File .\install.ps1 -WithClamAV  # also install ClamAV via winget
```

## Usage

```bash
pcscan                  # interactive banner + menu
pcscan --save-baseline  # run once: record your current clean state
pcscan --diff           # fast "what changed since baseline?"
pcscan --malware        # deep virus scan
pcscan --full           # everything incl. forensics
pcscan --report         # timestamped report to ~/pcscan/
```

Windows uses PowerShell-style flags: `pcscan -Diff`, `pcscan -Malware`, `pcscan -SaveBaseline`, etc.

## Privacy

`baseline.txt` and `report-*.txt` contain details about your machine and are **git-ignored** — they never leave your computer.

## Files

| File | Purpose |
|------|---------|
| `pcscan.sh` | Scanner (macOS + Linux) |
| `install.sh` | Installer (command + ClamAV + freshclam) |
| `pcscan.ps1` | Scanner (Windows / PowerShell) |
| `install.ps1` | Installer (Windows) |
