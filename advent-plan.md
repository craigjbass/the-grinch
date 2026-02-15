# Advent Calendar Plan: 25 Days of macOS Protection

Plan for implementing each day from the [North Pole Security 2025 Advent Calendar](https://northpole.security/blog/2025-advent-calendar) using this santa-config project.

## Status Legend

- **FAP** = File Access Policy (watch_item) — fits the existing DSL directly
- **CEL** = Requires CEL rule support (may need DSL extension for static_rules / binary rules)
- **DSL Extension** = Requires adding new capabilities to `santa_config.rb`
- **Already Done** = Fully or partially covered by existing config

---

## Day 1: Electron Apps on a Short Fuse

**Type:** FAP
**Threat:** Unauthorized modification of Electron app heap snapshot files (`.heapsnapshot`, resources in `.app` bundles).
**Approach:**
- Add a new file_access_policy file `file_access_policy/electron_apps.rb`.
- Create watch_items for common Electron app resource directories (e.g. `/Applications/*.app/Contents/Resources/`).
- Allow only the owning app's signing ID / TeamID to write to its own resources.
- Research common Electron apps to build the process allowlist (Slack, VS Code, Discord, 1Password, etc.).

**Research needed:** Exact paths for heap snapshot files and which signing IDs to allowlist per app.

---

## Day 2: Block Old Browsers

**Type:** CEL / DSL Extension
**Threat:** Running outdated browser versions with known vulnerabilities.
**Approach:**
- This requires CEL rules that inspect the cryptographic signing timestamp of browser binaries.
- The current DSL supports `static_rules` as a raw array — populate it with CEL-based rules checking signing timestamps.
- May need to extend the DSL to support a `binary_rule` or `cel_rule` builder for cleaner config.
- Target Chrome (`EQHXZ8M8AV`), Firefox (`43AQ936H96`), and other browsers already in config.

**Research needed:** Santa CEL rule syntax for signing timestamp inspection; how to determine an appropriate age threshold.

---

## Day 3: Keep Your iMessages to Yourself

**Type:** FAP
**Threat:** Infostealers reading `~/Library/Messages/chat.db`.
**Approach:**
- Add `file_access_policy/imessage.rb`.
- Watch path: `/Users/*/Library/Messages/` (prefix).
- Allowlist: `com.apple.MobileSMS` (platform binary), `com.apple.iChat`, `com.apple.mdworker_shared`.
- Block all other processes from reading the Messages database.

---

## Day 4: No Touching the Timestamps

**Type:** CEL / DSL Extension
**Threat:** Attackers using `touch -t` / `touch -d` to modify timestamps on LaunchAgent/LaunchDaemon plists to hide persistence.
**Approach:**
- Requires a CEL rule that matches the `touch` binary when invoked with timestamp flags (`-t`, `-d`, `-r`, `-A`) targeting persistence directories.
- Target directories: `/Library/LaunchAgents/`, `/Library/LaunchDaemons/`, `~/Library/LaunchAgents/`.
- May need to extend the DSL to add a `cel_rule` or `exec_rule` builder within static_rules.

**Research needed:** Santa CEL rule syntax for matching process arguments.

---

## Day 5: Stop Fake Password Popups

**Type:** CEL / DSL Extension
**Threat:** `osascript` commands generating fake system password dialogs for credential theft.
**Approach:**
- CEL rule to detect and block `osascript` (or `osascript -e`) when the command arguments contain `display dialog` with `hidden answer` (fake password prompt pattern).
- Add as a static rule / binary rule.

**Research needed:** Exact CEL syntax for matching command-line arguments in Santa rules.

---

## Day 6: Hands Out of the Cookie Jar

**Type:** FAP — **Already Done**
**Threat:** Infostealers accessing browser cookie files.
**Approach:**
- This is already implemented across all six browser configs (`chrome.rb`, `safari.rb`, `firefox.rb`, `edge.rb`, `brave.rb`, `arc.rb`).
- Each config protects Cookies files and restricts access to the browser's own signing ID/TeamID.
- **No further work needed** — review existing rules for completeness and accuracy.

---

## Day 7: Gatekeep the Gatekeeper

**Type:** CEL / DSL Extension
**Threat:** Attackers running `spctl --master-disable` or similar to turn off Gatekeeper.
**Approach:**
- CEL rule to block execution of `spctl` with dangerous flags (`--master-disable`, `--disable`, `--global-disable`).
- Add as a static rule.

**Research needed:** Full list of dangerous `spctl` subcommands/flags.

---

## Day 8: Hide Your Hashes

**Type:** FAP + CEL
**Threat:** Reading password hash files or using `dscl` to dump hashes.
**Approach:**
- **FAP:** Add `file_access_policy/password_hashes.rb`. Watch `/var/db/dslocal/nodes/Default/users/` (prefix). Allowlist only `com.apple.opendirectoryd` (platform binary) and similar system processes.
- **CEL:** Block `dscl` commands containing hash-dumping arguments (e.g. `dscl . -read /Users/*/dsAttrTypeNative:ShadowHashData`).

---

## Day 9: Watch Your Keychain

**Type:** FAP
**Threat:** Unauthorized processes accessing Keychain database files.
**Approach:**
- Add `file_access_policy/keychain.rb`.
- Watch paths: `/Users/*/Library/Keychains/` (prefix), `/Library/Keychains/` (prefix).
- Set `audit_only true` (monitoring mode, not blocking) to create telemetry without breaking legitimate apps.
- Allowlist known legitimate processes: `com.apple.securityd`, `com.apple.SecurityAgent`, etc.

---

## Day 10: One Flag to Rule Them All

**Type:** CEL / DSL Extension
**Threat:** Infostealers using `dscl -authonly` to validate stolen passwords.
**Approach:**
- CEL rule blocking `dscl` when arguments contain `-authonly`.
- Can be combined with Day 8's `dscl` blocking rules in a single policy file.

---

## Day 11: Protect Against PAM Bypasses

**Type:** FAP
**Threat:** Modification of `/etc/pam.d/` files to inject malicious PAM modules.
**Approach:**
- Add `file_access_policy/pam.rb`.
- Watch path: `/etc/pam.d/` (prefix).
- Use `allow_read_access true` (reading is fine, writing is not).
- Allowlist: no processes allowed to write (or only allow OS update processes if needed).

---

## Day 12: Keep Track of Launch Items

**Type:** FAP
**Threat:** Malware creating persistence via LaunchAgents/LaunchDaemons.
**Approach:**
- Add `file_access_policy/launch_items.rb`.
- Watch paths:
  - `/Library/LaunchAgents/` (prefix)
  - `/Library/LaunchDaemons/` (prefix)
  - `/Users/*/Library/LaunchAgents/` (prefix)
- Set `audit_only true` for telemetry on all creation/modification events.
- Optionally allow known management tools (MDM agents, Munki, etc.) as allowlisted processes.

---

## Day 13: Not on My Schedule

**Type:** FAP
**Threat:** Persistence via `cron` and `at` job schedulers.
**Approach:**
- Add `file_access_policy/scheduled_tasks.rb`.
- Watch paths:
  - `/private/var/at/` (prefix)
  - `/usr/lib/cron/` (prefix)
  - `/var/at/tabs/` (prefix)
- Block or audit all modifications. Allowlist `com.apple.cron` (platform binary) if needed.

---

## Day 14: The Gates are Wide Open

**Type:** CEL / DSL Extension
**Threat:** `xattr -d com.apple.quarantine` stripping the quarantine flag from downloads.
**Approach:**
- CEL rule to block `xattr` when arguments contain `-d` and `com.apple.quarantine`.
- Add as a static rule.

---

## Day 15: In Memoriam

**Type:** FAP
**Threat:** Reflective code injection via `NSCreateObjectFileImageFromMemory` temp files.
**Approach:**
- Add `file_access_policy/in_memory_loading.rb`.
- Watch path pattern for temp files matching `NSCreateObjectFileImageFromMemory-*` in `/tmp/` or `/private/tmp/`.
- Block creation of these files by non-system processes.

**Research needed:** Exact temp file paths used by this API on modern macOS.

---

## Day 16: Whale Watching

**Type:** FAP
**Threat:** Attackers modifying Docker configs to run malicious containers.
**Approach:**
- Add `file_access_policy/docker.rb`.
- Watch paths:
  - `/Users/*/Library/Group Containers/group.com.docker/` (prefix)
  - `/Users/*/.docker/` (prefix)
- Allowlist only Docker's signing ID (`com.docker.docker`, TeamID `9BNSXJN65R`).

---

## Day 17: Protect 1Password

**Type:** FAP
**Threat:** Unauthorized access to 1Password database files.
**Approach:**
- Add `file_access_policy/1password.rb`.
- Watch paths for 1Password data directories:
  - `/Users/*/Library/Group Containers/*.com.1password/` (prefix)
  - `/Users/*/Library/Application Support/1Password/` (prefix)
- Allowlist only `com.1password.1password` (TeamID `2BUA8C4S2C`).

---

## Day 18: Stay out of the Spotlight

**Type:** FAP
**Threat:** TCC bypass via Spotlight importer directories and Apple Intelligence databases.
**Approach:**
- Add `file_access_policy/spotlight.rb`.
- Watch paths:
  - `/Library/Spotlight/` (prefix)
  - `/Users/*/Library/Metadata/CoreSpotlight/` (prefix)
  - Apple Intelligence DB paths (research needed).
- Allowlist: `com.apple.Spotlight`, `com.apple.mdworker_shared` (platform binaries).

---

## Day 19: Better Than a Fake Rock

**Type:** FAP
**Threat:** Infostealers reading SSH private keys.
**Approach:**
- Add `file_access_policy/ssh_keys.rb`.
- Watch path: `/Users/*/.ssh/` (prefix).
- Use longest-prefix matching for granular control.
- Allowlist: `com.apple.openssh` (platform binary), `com.apple.Terminal`, known SSH clients, Git clients.
- Block all other reads.

---

## Day 20: Where's the Remote?

**Type:** CEL / DSL Extension
**Threat:** `systemsetup` commands enabling SSH or Remote Apple Events for persistence.
**Approach:**
- CEL rule blocking `systemsetup` with subcommands like `-setremotelogin on`, `-setremoteappleevents on`.
- Add as a static rule.

---

## Day 21: macOS Insecurity

**Type:** CEL / DSL Extension
**Threat:** Abuse of the `security` command to dump Keychains, manipulate certificates.
**Approach:**
- CEL rules blocking dangerous `security` subcommands:
  - `security dump-keychain`
  - `security export`
  - `security find-generic-password -w`
  - `security find-internet-password -w`
  - `security delete-certificate`
- Add as static rules.

---

## Day 22: Drop the Bass, Not the Payload

**Type:** FAP
**Threat:** Malicious audio plugins loading with elevated privileges.
**Approach:**
- Add `file_access_policy/audio_plugins.rb`.
- Watch paths:
  - `/Library/Audio/Plug-Ins/` (prefix)
  - `/Users/*/Library/Audio/Plug-Ins/` (prefix)
- Audit or block unsigned/unexpected writes to audio plugin directories.

---

## Day 23: Caution, Tunnel Ahead

**Type:** DSL Extension (Risk Engine / Blockable Rules)
**Threat:** Unauthorized VPN applications being installed.
**Approach:**
- This uses Santa's Risk Engine with blockable rules targeting apps by code signature entitlements (specifically VPN entitlements like `com.apple.developer.networking.vpn.api`).
- Likely requires extending the DSL to support Risk Engine configuration and blockable rules.
- Implementation: block VPN apps unless approved by admin.

**Research needed:** Santa Risk Engine configuration schema; how blockable rules interact with entitlements.

---

## Day 24: Failed Inspections

**Type:** CEL / DSL Extension
**Threat:** Chromium remote debugging (`--remote-debugging-port`) and Electron debugging env vars (`ELECTRON_RUN_AS_NODE`) enabling code injection.
**Approach:**
- CEL rule blocking Chrome/Electron apps launched with `--remote-debugging-port` flag.
- CEL rule blocking processes with `ELECTRON_RUN_AS_NODE` environment variable set.
- Add as static rules.

**Research needed:** Whether Santa CEL rules can inspect environment variables.

---

## Day 25: Prompt Injection

**Type:** FAP
**Threat:** AI coding tools (Copilot, Cursor, Claude Code, etc.) being tricked via prompt injection into exfiltrating credential files.
**Approach:**
- Add `file_access_policy/ai_tools.rb`.
- Watch sensitive credential paths:
  - `/Users/*/.aws/credentials` (exact)
  - `/Users/*/.aws/config` (exact)
  - `/Users/*/.ssh/` (prefix) — may overlap with Day 19
  - `/Users/*/.gnupg/` (prefix)
  - `/Users/*/.config/gh/` (prefix)
  - `/Users/*/.npmrc` (exact)
  - `/Users/*/.pypirc` (exact)
- Allowlist: Only the specific tools that legitimately need each file (e.g. `com.amazon.aws.cli2` for AWS credentials).
- Block AI coding tools by their signing IDs from reading these files.

---

## Implementation Order

Recommended order, starting with the easiest wins (pure FAP rules using the existing DSL) before tackling DSL extensions:

### Phase 1: File Access Policies (existing DSL, no changes needed)

| Priority | Day | Name | File |
|----------|-----|------|------|
| 1 | 6 | Cookie Jar | **Already done** |
| 2 | 3 | iMessages | `file_access_policy/imessage.rb` |
| 3 | 19 | SSH Keys | `file_access_policy/ssh_keys.rb` |
| 4 | 11 | PAM Bypasses | `file_access_policy/pam.rb` |
| 5 | 8 | Password Hashes (FAP part) | `file_access_policy/password_hashes.rb` |
| 6 | 12 | Launch Items | `file_access_policy/launch_items.rb` |
| 7 | 13 | Scheduled Tasks | `file_access_policy/scheduled_tasks.rb` |
| 8 | 9 | Keychain | `file_access_policy/keychain.rb` |
| 9 | 17 | 1Password | `file_access_policy/1password.rb` |
| 10 | 16 | Docker | `file_access_policy/docker.rb` |
| 11 | 25 | AI Tool Credentials | `file_access_policy/ai_tools.rb` |
| 12 | 18 | Spotlight | `file_access_policy/spotlight.rb` |
| 13 | 22 | Audio Plugins | `file_access_policy/audio_plugins.rb` |
| 14 | 15 | In-Memory Loading | `file_access_policy/in_memory_loading.rb` |
| 15 | 1 | Electron Apps | `file_access_policy/electron_apps.rb` |

### Phase 2: CEL / Binary Rules (requires DSL extension for static_rules)

| Priority | Day | Name | Notes |
|----------|-----|------|-------|
| 1 | 7 | Gatekeeper (`spctl`) | Block dangerous flags |
| 2 | 14 | Quarantine (`xattr`) | Block quarantine removal |
| 3 | 5 | Fake Passwords (`osascript`) | Block fake dialogs |
| 4 | 10 | `dscl -authonly` | Block credential validation |
| 5 | 8 | `dscl` hash dumping (CEL part) | Block hash reads |
| 6 | 21 | `security` command | Block keychain dumping |
| 7 | 20 | `systemsetup` | Block remote access enablement |
| 8 | 4 | Timestamp tampering (`touch`) | Block timestamp modification |
| 9 | 24 | Remote debugging | Block debug flags/env vars |

### Phase 3: Advanced Features (requires significant DSL work)

| Priority | Day | Name | Notes |
|----------|-----|------|-------|
| 1 | 2 | Block Old Browsers | Signing timestamp CEL rules |
| 2 | 23 | VPN Tunnel Control | Risk Engine / blockable rules |

### DSL Extensions Needed

1. **CEL rule builder** — A `cel_rule` DSL method within `static_rules` that generates binary/execution rules with CEL expressions for matching process arguments and flags.
2. **Risk Engine config** — Support for Santa's Risk Engine configuration (Day 23).
3. **Signing timestamp checks** — CEL expressions that can evaluate code signing timestamps (Day 2).

Each of these needs research into the Santa configuration schema before implementation.
