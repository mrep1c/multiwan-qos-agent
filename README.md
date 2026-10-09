# MultiWAN QoS Agent

MultiWAN QoS Agent is a Windows companion app for OpenWrt MultiWAN QoS. It
detects active game traffic on the PC, applies Windows DSCP policy tagging,
and syncs live game connection metadata to the router.

The router endpoint is:

```text
/cgi-bin/multiwan-qos-agent
```

## Features

- Detects active game processes from the built-in game database and custom
  user entries.
- Applies Windows QoS policies for local DSCP tagging. The default marks all
  UDP traffic from detected game executables, with an optional stricter mode for
  selected live flows.
- Uses Windows ETW UDP telemetry to identify remote game endpoints, with
  automatic retries after telemetry failures.
- Syncs active game connection metadata to the OpenWrt router.
- Signals new live-flow sessions to the router's Adaptive controller.
- Scans for games every 2 seconds while idle, wakes on new ETW game flows, and
  uses 5-second active synchronization with a slower idle heartbeat.
- Clears router-side agent rules when games stop or the app exits.
- Provides a tray app, live dashboard, settings dialog, and custom game editor.
- Supports Start with Windows through Task Scheduler.
- Stores config and logs under the current Windows user profile.

Local tagging covers every detected executable belonging to a game. Selected
live-flow policies use the executable that owns each flow. Windows policy
state is verified after changes and checked every 60 seconds to repair missing
or changed policies. Changing the router address, credentials, TLS setting or
PC address forces a fresh router synchronization.

Flow selection ranks recent bandwidth over a 45-second window. A flow needs
three packets, three seconds of observation and at least 4,094 bytes/second.
Additional selected flows must reach at least 50% of the busiest eligible flow's
bandwidth. Up to three flows per game are selected. ETW retries use delays bounded
between 5 and 60 seconds. Windows psutil UDP tables cannot provide remote
endpoints, so router flow detection requires working ETW telemetry; default
all-UDP local tagging still works when ETW is unavailable.

The throughput minimum, bandwidth ranking, 50% cutoff and three-flow cap are
intentional selection rules. Game process ownership alone does not qualify a
connection. Audits and refactors must preserve these rules unless a selection
design change is explicitly requested. The dashboard may show ignored
candidates for diagnosis; only selected flows reach the router report and
exact-flow policy builder. See [AGENTS.md](AGENTS.md).

The agent sends connection metadata needed for router QoS rules. It does not
inspect packet payloads.

## Requirements

- Windows 10 or Windows 11 x64.
- Administrator rights for Windows QoS policy management.
- OpenWrt router with `multiwan-qos` installed.
- `luci-app-multiwan-qos` for web-based agent setup.
- Router and PC reachable on the same LAN or routed network.

## Router Setup

Install the router packages first:

```sh
uclient-fetch -O /tmp/setup-multiwan-feed.sh https://raw.githubusercontent.com/mrep1c/openwrt-multiwan/main/setup-feed.sh
sh /tmp/setup-multiwan-feed.sh install
```

If the feed is already configured:

```sh
apk update
apk add multiwan-qos luci-app-multiwan-qos
```

On OPKG systems:

```sh
opkg update
opkg install multiwan-qos luci-app-multiwan-qos
```

Enable the agent endpoint:

1. Open LuCI.
2. Go to Network > MultiWAN QoS > Agent.
3. Enable the endpoint.
4. Copy the API key.
5. Save and apply.

Endpoint check from the router:

```sh
ls -l /www/cgi-bin/multiwan-qos-agent
/etc/init.d/uhttpd restart
```

## Download And Install

Download the Windows release from:

```text
https://github.com/mrep1c/multiwan-qos-agent/releases
```

App changes pushed to `main` automatically bump the version, run the regression
tests, build the Windows EXE and publish a GitHub Release at the exact bumped
commit. Explicit version updates also publish automatically. Non-release builds
still upload the EXE as a workflow artifact.

Release asset naming:

```text
MultiWAN-QoS-Agent-v<version>-windows-x64.exe
```

Run the EXE as administrator. Windows may show a SmartScreen warning because
the build is unsigned; run it only if it was downloaded from the official
release page.

First setup:

1. Enter the router IP address, for example `192.168.1.1`.
2. Paste the API key from LuCI.
3. Choose the DSCP class.
4. Set `Enable local Windows DSCP tagging` and the local tagging mode. Use the
   default all-UDP mode for the most stable local game tagging.
5. Save settings.
6. Start a supported game and check the Live Dashboard.

HTTPS certificate verification is enabled by default. If a trusted router uses
a self-signed certificate, explicitly select `Allow insecure HTTPS certificates`;
this skips verification of the router's identity. Entering an HTTPS address does
not enable that option automatically. Redirects and invalid agent JSON replies
are rejected. Older valid agent JSON responses remain supported.

## Config And Logs

Main config:

```text
%APPDATA%\MultiWAN QoS Agent\config.json
```

Custom games:

```text
%APPDATA%\MultiWAN QoS Agent\user_games.json
```

Game rule overrides:

```text
%APPDATA%\MultiWAN QoS Agent\game_rules.json
```

Log file:

```text
%APPDATA%\MultiWAN QoS Agent\agent.log
```

Settings, custom games and overrides are written to a temporary file and
atomically replaced only after a complete write. A failed save keeps the previous
file and reports the error. API keys require successful Windows DPAPI encryption
before saving; encryption failures never save the key as plaintext. Old plaintext
keys can still be read and are encrypted on the next successful save.

Malformed settings load safe defaults or skip invalid entries and show a startup
warning. The original file stays in place until an explicit repair saves a copy
as `<filename>.invalid-<id>` before replacement. An unreadable encrypted key also
raises a warning and requires re-entry in Settings.

## Game Rules

Use the Game Rules editor to control local Windows DSCP tagging for built-in
and custom games. Built-in games are read-only but can still have rule
overrides. Custom entries should include:

- display name,
- executable name,
- expected protocol.

Names must contain 1–64 ASCII letters, numbers, spaces, hyphens, underscores,
colons or dots so the router can accept them. Paste executable basenames such as
`game.exe` or Windows paths; paths are normalized to basenames before saving.
Duplicate display names are rejected by the editor. Traffic remains UDP-only.

Each game can use the global local-tagging setting, explicitly enable local
tagging, or disable local tagging. `Disable local tagging` only removes the
Windows policy; detection and router rule sync continue. Use `Disable program
(local + router)` to suppress both the Windows policy and that program's live
router rule synchronization while keeping detection visible. If global local
tagging is disabled in Settings, no per-game rule creates local Windows QoS
policies.

Select `Use global setting` and save to remove a per-game override. `Delete
Game` removes a custom game definition and its override; built-in games remain
available.

Saved changes wake detection automatically.

## Run From Source

Create a virtual environment, install dependencies, and start the app:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run_agent.py
```

Run PowerShell as administrator when testing DSCP policy creation.

Run the regression checks without administrator rights or installed app dependencies:

```powershell
python -m unittest discover -s tests -v
```

The tests replace Windows APIs, HTTP, credentials and UI dependencies with mocks.
They do not launch ETW, alter policies or scheduled tasks, contact a router, or
open the UI. CI runs them before packaging. See `docs/pc-agent-audit-fixes.md` for
the audit resolution and remaining live checks.

## Build From Source

```powershell
.\build.bat
```

The Windows build output is created under `dist\`.

GitHub Actions also builds the EXE automatically on pushes to `main`, on
manual workflow runs, and on version tags such as `v1.0.4`. Version tags attach
the EXE to the matching GitHub Release. The version workflow directly calls the
same tested build workflow after a successful bump; it does not depend on the
bot's push triggering another workflow. Releases publish only after tests and
packaging succeed. Documentation-only changes do not publish a new version, and
existing release assets are preserved on reruns.
To publish the current version without another bump, run `Auto Bump Version`
manually from GitHub Actions. The same test and build gates apply.

## Troubleshooting

If the agent cannot connect to the router:

- Confirm the router IP address is correct.
- Confirm the API key matches the value in LuCI.
- Confirm `/www/cgi-bin/multiwan-qos-agent` exists on the router.
- Restart `uhttpd` on the router.
- Check Windows firewall rules.

If DSCP policies are not applied:

- Run the app as administrator.
- Confirm the selected game process is detected.
- If exact live-flow marking is enabled, confirm the Live Dashboard shows
  selected UDP flows for the game.
- Check the app log file.
- Check Windows policy state with PowerShell.

If the Live Dashboard is empty:

- Start a supported game.
- Confirm the game is using network traffic.
- Add the game manually in Game Rules if needed.
- Confirm the router can receive agent updates.
- Check the ETW status. Failed telemetry retries automatically; Windows UDP
  endpoint detection has no psutil fallback.

## Uninstall

1. Exit the tray app.
2. Remove the Windows app files.
3. Remove the config folder if you no longer need it:

```text
%APPDATA%\MultiWAN QoS Agent
```

Normal exit waits for accepted rule writes before cleanup and rejects further
writes. Slow Windows policy commands can delay exit; check the log if cleanup
fails. Router-side agent cleanup uses the last contacted router and PC address.
Restart
MultiWAN QoS if you want to clear router-side state manually:

```sh
/etc/init.d/multiwan-qos restart
```
