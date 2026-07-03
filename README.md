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
- Applies Windows QoS policies for selected DSCP tagging.
- Uses UDP flow telemetry and psutil connection inspection to identify live
  remote game endpoints.
- Syncs active game connection metadata to the OpenWrt router.
- Clears router-side agent rules when games stop or the app exits.
- Provides a tray app, live dashboard, settings dialog, and custom game editor.
- Supports Start with Windows through Task Scheduler.
- Stores config and logs under the current Windows user profile.

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

Current asset:

```text
MultiWAN-QoS-Agent-v1.0.1-windows-x64.exe
```

Run the EXE as administrator. Windows may show a SmartScreen warning because
the build is unsigned; run it only if it was downloaded from the official
release page.

First setup:

1. Enter the router IP address, for example `192.168.1.1`.
2. Paste the API key from LuCI.
3. Choose the DSCP class.
4. Save settings.
5. Start a supported game and check the Live Dashboard.

## Config And Logs

Main config:

```text
%APPDATA%\MultiWAN QoS Agent\config.json
```

Custom games:

```text
%APPDATA%\MultiWAN QoS Agent\user_games.json
```

Log file:

```text
%APPDATA%\MultiWAN QoS Agent\agent.log
```

## Custom Games

Use the Custom Games editor to add processes that are not in the built-in game
database. Each entry should include:

- display name,
- executable name,
- expected protocol,
- optional local or remote ports.

After saving custom games, restart detection from the tray app or restart the
agent.

## Run From Source

Create a virtual environment, install dependencies, and start the app:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run_agent.py
```

Run PowerShell as administrator when testing DSCP policy creation.

## Build From Source

```powershell
.\build.bat
```

The Windows build output is created under `dist\`.

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
- Check the app log file.
- Check Windows policy state with PowerShell.

If the Live Dashboard is empty:

- Start a supported game.
- Confirm the game is using network traffic.
- Add the game manually in Custom Games if needed.
- Confirm the router can receive agent updates.

## Uninstall

1. Exit the tray app.
2. Remove the Windows app files.
3. Remove the config folder if you no longer need it:

```text
%APPDATA%\MultiWAN QoS Agent
```

Router-side agent rules are cleared when the app exits normally. Restart
MultiWAN QoS if you want to clear router-side state manually:

```sh
/etc/init.d/multiwan-qos restart
```
