"""
Windows QoS Policy management.

Creates hidden UDP-only Windows QoS policies using PowerShell's NetQos cmdlets.
Policies tag matching game traffic with the selected DSCP value on the PC
before it reaches the router.
"""

import hashlib
import json
import logging
import re
import subprocess

from . import config as cfg

logger = logging.getLogger("multiwan_qos_agent.qos")

POLICY_PREFIX = "MultiWANQoSAgent_"
POLICY_STORE = "ActiveStore"


def _run_powershell(command):
    """Run a hidden PowerShell command and return (success, output)."""
    startupinfo = None
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    if hasattr(subprocess, "STARTUPINFO"):
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= getattr(subprocess, "STARTF_USESHOWWINDOW", 0)
        startupinfo.wShowWindow = 0

    try:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-WindowStyle",
                "Hidden",
                "-Command",
                command,
            ],
            capture_output=True,
            text=True,
            timeout=15,
            creationflags=creationflags,
            startupinfo=startupinfo,
        )
        if result.returncode == 0:
            return True, result.stdout.strip()

        logger.warning(
            "PowerShell command failed: %s\nStderr: %s",
            command,
            result.stderr.strip(),
        )
        return False, result.stderr.strip()
    except subprocess.TimeoutExpired:
        logger.error("PowerShell command timed out: %s", command)
        return False, "timeout"
    except FileNotFoundError:
        logger.error("PowerShell not found")
        return False, "powershell not found"


def _ps_quote(value):
    """Quote a PowerShell string literal."""
    return "'" + str(value).replace("'", "''") + "'"


def _sanitize_policy_name(game_name):
    safe = "".join(c if c.isalnum() or c in "_-" else "_" for c in str(game_name))
    return f"{POLICY_PREFIX}{safe[:32]}"


def _is_multiwan_qos_policy_name(policy_name):
    return str(policy_name or "").lower().startswith(POLICY_PREFIX.lower())


def _policy_key(policy_name):
    return str(policy_name or "").lower()


def _validate_dscp_value(dscp_value):
    try:
        dscp_value = int(dscp_value)
        if dscp_value not in cfg.SUPPORTED_DSCP_VALUES:
            raise ValueError()
        return dscp_value
    except (ValueError, TypeError):
        logger.error("Invalid DSCP value: %s", dscp_value)
        return cfg.DEFAULT_DSCP_VALUE


def _validate_exe_name(exe_name):
    return bool(re.match(r"^[\w\-. ]+\.exe$", exe_name or "", re.IGNORECASE))


def _exe_matches_policy(policy_app, exe_name):
    policy_app = str(policy_app or "").replace("/", "\\").lower()
    exe_name = str(exe_name or "").lower()
    policy_exe = policy_app.rsplit("\\", 1)[-1]
    return policy_app == exe_name or policy_exe == exe_name


def _policy_matches_spec(policy, spec, dscp_value):
    if not policy:
        return False

    protocol = str(policy.get("protocol") or "").lower()
    try:
        active_dscp = int(policy.get("dscp"))
    except (TypeError, ValueError):
        active_dscp = None

    return (
        _exe_matches_policy(policy.get("app"), spec.get("exe"))
        and protocol in ("udp", "17")
        and active_dscp == int(dscp_value)
    )


def normalize_ports(ports):
    """Normalize port/range input to a sorted list of UDP destination ports."""
    normalized = set()

    if ports is None:
        return []

    if isinstance(ports, str):
        items = re.split(r"[\s,]+", ports.strip())
    else:
        items = ports

    for item in items:
        if item is None or item == "":
            continue

        if isinstance(item, str) and "-" in item:
            start_s, end_s = item.split("-", 1)
            try:
                start, end = int(start_s.strip()), int(end_s.strip())
            except ValueError:
                continue
            if 1 <= start <= end <= 65535:
                normalized.update(range(start, end + 1))
            continue

        try:
            port = int(item)
        except (TypeError, ValueError):
            continue

        if 1 <= port <= 65535:
            normalized.add(port)

    return sorted(normalized)


def ports_to_ranges(ports):
    """Compress individual ports to contiguous ranges."""
    ports = normalize_ports(ports)
    if not ports:
        return []

    ranges = []
    start = prev = ports[0]
    for port in ports[1:]:
        if port == prev + 1:
            prev = port
            continue
        ranges.append((start, prev))
        start = prev = port
    ranges.append((start, prev))
    return ranges


def _policy_name(game_name, exe_name, start_port=None, end_port=None):
    safe_game = _sanitize_policy_name(game_name)
    key = f"{game_name}|{exe_name}|udp"
    if start_port and end_port:
        key = f"{key}|{start_port}-{end_port}"
    digest = hashlib.sha1(key.encode("utf-8")).hexdigest()[:10]
    return f"{safe_game}_{digest}"


def build_policy_specs(game_name, exe_name, ports):
    """Create a desired UDP-only QoS policy spec for one game executable."""
    if not _validate_exe_name(exe_name):
        logger.error("Invalid executable name: %s", exe_name)
        return []

    return [{
        "name": _policy_name(game_name, exe_name),
        "game": game_name,
        "exe": exe_name,
        "start_port": None,
        "end_port": None,
    }]


def _create_policy(spec, dscp_value):
    policy_name = spec["name"]
    exe_name = spec["exe"]

    create_cmd = (
        f"New-NetQosPolicy -Name {_ps_quote(policy_name)} "
        f"-AppPathNameMatchCondition {_ps_quote(exe_name)} "
        f"-IPProtocolMatchCondition UDP "
        f"-DSCPAction {dscp_value} "
        f"-NetworkProfile All "
        f"-PolicyStore {POLICY_STORE} "
        f"-Confirm:$false"
    )

    success, output = _run_powershell(create_cmd)
    if success:
        logger.info(
            "Created UDP QoS policy: %s (exe=%s, all UDP, DSCP=%d)",
            policy_name,
            exe_name,
            dscp_value,
        )
        return True

    if "already exists" in (output or "").lower():
        active_details = {_policy_key(policy["name"]): policy for policy in get_active_policies()}
        active_policy = active_details.get(_policy_key(policy_name))
        if _policy_matches_spec(active_policy, spec, dscp_value):
            logger.info("QoS policy already exists and matches desired state: %s", policy_name)
            return True

        logger.warning("QoS policy already exists but does not match desired state; recreating: %s", policy_name)
        remove_name = active_policy.get("name", policy_name) if active_policy else policy_name
        if remove_qos_policy_by_name(remove_name):
            retry_success, retry_output = _run_powershell(create_cmd)
            if retry_success:
                logger.info(
                    "Recreated UDP QoS policy: %s (exe=%s, all UDP, DSCP=%d)",
                    policy_name,
                    exe_name,
                    dscp_value,
                )
                return True
            output = retry_output

    logger.error("Failed to create QoS policy: %s - %s", policy_name, output)
    return False


def get_multiwan_qos_policy_names():
    """List MultiWAN QoS-managed Windows QoS policy names."""
    list_cmd = (
        f'Get-NetQosPolicy -PolicyStore {POLICY_STORE} | '
        f'Where-Object {{ $_.Name -like "{POLICY_PREFIX}*" }} '
        f"| Select-Object -ExpandProperty Name"
    )

    success, output = _run_powershell(list_cmd)
    if not success or not output:
        return set()

    return {line.strip() for line in output.strip().splitlines() if line.strip()}


def remove_qos_policy_by_name(policy_name):
    """Remove one MultiWAN QoS-managed policy by exact name."""
    if not _is_multiwan_qos_policy_name(policy_name):
        logger.error("Refusing to remove non-MultiWAN QoS policy: %s", policy_name)
        return False

    remove_cmd = (
        f"Remove-NetQosPolicy -Name {_ps_quote(policy_name)} "
        f"-PolicyStore {POLICY_STORE} "
        f"-Confirm:$false -ErrorAction SilentlyContinue"
    )

    success, output = _run_powershell(remove_cmd)
    if success:
        logger.info("Removed QoS policy: %s", policy_name)
    else:
        logger.warning("Remove QoS policy '%s' failed: %s", policy_name, output)

    return success


def sync_qos_policies(desired_specs, dscp_value=46):
    """Make Windows QoS policies match the desired UDP-only policy specs."""
    dscp_value = _validate_dscp_value(dscp_value)

    desired_by_key = {_policy_key(spec["name"]): spec for spec in desired_specs}
    active_details = {_policy_key(policy["name"]): policy for policy in get_active_policies()}
    active_keys = set(active_details.keys())

    ok = True
    for policy_key in sorted(active_keys - set(desired_by_key.keys())):
        policy_name = active_details[policy_key]["name"]
        if not remove_qos_policy_by_name(policy_name):
            ok = False

    active_details = {_policy_key(policy["name"]): policy for policy in get_active_policies()}
    active_keys = set(active_details.keys())
    for policy_key, spec in sorted(desired_by_key.items()):
        policy_name = spec["name"]
        if policy_key in active_keys:
            active_policy = active_details.get(policy_key)
            if _policy_matches_spec(active_policy, spec, dscp_value):
                continue
            logger.info(
                "Recreating QoS policy %s because existing policy does not match desired exe/protocol/DSCP",
                policy_name,
            )
            if not remove_qos_policy_by_name(active_policy.get("name", policy_name)):
                ok = False
                continue
        if not _create_policy(spec, dscp_value):
            ok = False

    remaining = {
        name for name in get_multiwan_qos_policy_names()
        if _policy_key(name) not in set(desired_by_key.keys())
    }
    if remaining:
        logger.warning("Stale MultiWAN QoS Agent QoS policies remain after sync: %s", ", ".join(sorted(remaining)))
        ok = False

    return ok


def create_qos_policy(game_name, exe_name, dscp_value=46):
    """Backward-compatible UDP-only policy entry point."""
    specs = build_policy_specs(game_name, exe_name, None)
    return sync_qos_policies(specs, dscp_value) if specs else False


def remove_qos_policy(game_name):
    """Backward-compatible cleanup by old broad game policy name."""
    return remove_qos_policy_by_name(_sanitize_policy_name(game_name))


def cleanup_all_policies():
    """Remove all MultiWAN QoS Agent policies."""
    logger.info("Cleaning up all MultiWAN QoS Agent QoS policies...")

    policy_names = get_multiwan_qos_policy_names()
    if not policy_names:
        logger.debug("No MultiWAN QoS Agent policies found to clean up")
        return {"removed": 0, "remaining": [], "failed": []}

    removed = 0
    failed = []
    for policy_name in sorted(policy_names):
        if remove_qos_policy_by_name(policy_name):
            removed += 1
        else:
            failed.append(policy_name)

    remaining = sorted(get_multiwan_qos_policy_names())
    if remaining:
        logger.warning("QoS cleanup removed %d policy/policies; remaining stale policies: %s", removed, ", ".join(remaining))
    else:
        logger.info("QoS cleanup removed %d policy/policies; no stale policies remain", removed)

    return {"removed": removed, "remaining": remaining, "failed": failed}


def get_active_policies():
    """List all active MultiWAN QoS Agent QoS policies."""
    list_cmd = (
        f'Get-NetQosPolicy -PolicyStore {POLICY_STORE} | '
        f'Where-Object {{ $_.Name -like "{POLICY_PREFIX}*" }} '
        f"| Select-Object Name, AppPathNameMatchCondition, IPProtocolMatchCondition, "
        f"IPDstPortMatchCondition, IPDstPortStartMatchCondition, "
        f"IPDstPortEndMatchCondition, DSCPAction | ConvertTo-Json -Compress"
    )

    success, output = _run_powershell(list_cmd)
    if not success or not output:
        return []

    try:
        data = json.loads(output)
        if isinstance(data, dict):
            data = [data]
        return [
            {
                "name": p.get("Name", ""),
                "app": p.get("AppPathNameMatchCondition", ""),
                "protocol": p.get("IPProtocolMatchCondition", ""),
                "dst_port": p.get("IPDstPortMatchCondition", ""),
                "dst_port_start": p.get("IPDstPortStartMatchCondition", ""),
                "dst_port_end": p.get("IPDstPortEndMatchCondition", ""),
                "dscp": p.get("DSCPAction", 0),
            }
            for p in data
        ]
    except (json.JSONDecodeError, TypeError):
        return []
