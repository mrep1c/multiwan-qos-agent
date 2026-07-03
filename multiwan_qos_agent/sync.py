"""
Router API synchronization.

Sends heartbeat updates to the OpenWrt MultiWAN QoS CGI endpoint with
active game connection data. The router uses this to dynamically
create nftables rules in the multiwan_qos_agent chain.
"""

import logging
import re
import requests
from dataclasses import dataclass

logger = logging.getLogger("multiwan_qos_agent.sync")

# Timeout for HTTP requests to the router
REQUEST_TIMEOUT = 10  # seconds


@dataclass
class SyncResult:
    ok: bool
    message: str
    rule_count: int = None
    detail: str = ""
    endpoint: str = ""
    status_code: int = None

    def __iter__(self):
        yield self.ok
        yield self.message


def _endpoint_urls(router_ip):
    """Build candidate MultiWAN QoS Agent CGI URLs."""
    ip = router_ip.strip().rstrip("/")
    if not ip:
        return []

    if ip.startswith(("http://", "https://")):
        if "/cgi-bin/multiwan-qos-agent" in ip:
            return [ip]
        return [f"{ip}/cgi-bin/multiwan-qos-agent"]

    return [f"https://{ip}/cgi-bin/multiwan-qos-agent"]


def _response_message(response, default=None):
    """Extract a useful message from a router response."""
    fallback = default or f"HTTP {response.status_code}"
    try:
        return response.json().get("message", fallback)
    except ValueError:
        if response.status_code == 404:
            return (
                "MultiWAN QoS Agent endpoint was not found on the router. "
                "Upgrade or reinstall the multiwan-qos package."
            )
        text = _compact_router_text(_strip_html(response.text), limit=160)
        return text if text else fallback


def _response_json(response):
    try:
        return response.json()
    except ValueError:
        return {}


def _to_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _effective_status_code(response):
    data = _response_json(response)
    status = _to_int(data.get("status"))
    if status is not None:
        return status
    if str(data.get("message", "")).lower() == "too many requests":
        return 429
    return response.status_code


def _compact_router_text(value, limit=220):
    text = " ".join(str(value or "").split())
    if len(text) > limit:
        return text[:limit] + "..."
    return text


def _strip_html(value):
    return re.sub(r"<[^>]+>", " ", str(value or ""))


def _response_rule_count(response, message):
    data = _response_json(response)
    for key in ("rule_count", "agent_rule_count", "agent_comment_count", "rules_applied", "rules"):
        value = data.get(key)
        parsed = _to_int(value)
        if parsed is not None:
            return parsed

    try:
        import re
        match = re.search(r"(\d+)\s+rules?\s+applied", message or "", re.IGNORECASE)
    except Exception:
        match = None

    if match:
        return int(match.group(1))
    return None


def _structured_update_validation(response, message):
    """Return (ok, detail) for router verification metadata when present."""
    data = _response_json(response)
    if not data:
        return True, "legacy response"

    verification_present = (
        "verification_ok" in data or
        "verification_status" in data or
        "rules_expected" in data or
        "agent_comment_count" in data or
        "dscp_rule_count" in data or
        "rule_shape" in data
    )
    if not verification_present:
        return True, "legacy json response"

    endpoint_version = _to_int(data.get("endpoint_version"))
    expected = _to_int(data.get("rules_expected"))
    rule_count = _to_int(data.get("rule_count"))
    agent_rule_count = _to_int(data.get("agent_rule_count"))
    dscp_count = _to_int(data.get("dscp_rule_count"))
    verification_ok = data.get("verification_ok")
    verification_status = data.get("verification_status") or "unknown"

    if endpoint_version is not None and endpoint_version < 2:
        return False, f"router agent endpoint is too old (version {endpoint_version})"

    if verification_ok is False or str(verification_ok).lower() == "false":
        counts = (
            f"expected={expected}, rule_count={rule_count}, "
            f"agent_rule_count={agent_rule_count}, "
            f"dscp_rule_count={dscp_count}, "
            f"raw_rule_count={_to_int(data.get('raw_rule_count'))}, "
            f"non_agent_rule_count={_to_int(data.get('non_agent_rule_count'))}"
        )
        preview = _compact_router_text(data.get("nft_output"))
        if preview:
            return False, f"router verification failed: {verification_status} ({counts}; nft={preview})"
        return False, f"router verification failed: {verification_status} ({counts})"

    if expected is not None:
        for label, value in (
            ("verified rules", rule_count),
            ("agent rules", agent_rule_count),
            ("DSCP setters", dscp_count),
        ):
            if value is not None and value != expected:
                return False, f"router verification mismatch: {label}={value}, expected={expected}"

    if expected and (rule_count is None or agent_rule_count is None or dscp_count is None):
        return False, "router verification response is missing expected rule metadata"

    return True, (
        "verified rules=%s dscp=%s shape=%s" %
        (rule_count if rule_count is not None else "unknown",
          data.get("dscp_class", "unknown"),
          data.get("rule_shape", "dscp_only"))
    )


def _do_request(router_ip, payload, timeout=REQUEST_TIMEOUT, insecure_tls=False):
    """Try router endpoint candidates. Return (response, error_msg)."""
    urls = _endpoint_urls(router_ip)
    if not urls:
        return None, "Router IP is not configured"

    last_error = ""
    for url in urls:
        try:
            response = requests.post(
                url,
                json=payload,
                timeout=timeout,
                headers={"Content-Type": "application/json"},
                verify=not (url.startswith("https://") and insecure_tls)
            )
            response.multiwan_qos_url = url
            return response, ""
        except requests.ConnectionError:
            last_error = f"Cannot connect to router at {url}"
            continue
        except requests.Timeout:
            last_error = f"Request to router timed out ({timeout}s)"
            continue
        except requests.RequestException as e:
            last_error = f"Request error: {e}"
            break
            
    return None, last_error


def _sync_result(ok, message, response=None, rule_count=None, detail=""):
    endpoint = getattr(response, "multiwan_qos_url", "") if response is not None else ""
    status_code = _effective_status_code(response) if response is not None else None
    return SyncResult(ok, message, rule_count, detail, endpoint, status_code)


def send_update(router_ip, api_key, pc_ip, connections, dscp_value=46, insecure_tls=False):
    payload = {
        "api_key": api_key,
        "action": "update",
        "pc_ip": pc_ip,
        "connections": connections,
        "dscp": int(dscp_value),
    }
    
    # Don't log connections list to avoid leaking info in debug
    response, err = _do_request(router_ip, payload, insecure_tls=insecure_tls)
    
    if response is None:
        logger.warning(err)
        return _sync_result(False, err, detail=err)

    status_code = _effective_status_code(response)
    if status_code == 200:
        msg = _response_message(response, "OK")
        rule_count = _response_rule_count(response, msg)
        endpoint = getattr(response, "multiwan_qos_url", "unknown endpoint")
        verified, detail = _structured_update_validation(response, msg)
        if not verified:
            logger.warning("Router sync failed verification via %s: %s (%s)", endpoint, msg, detail)
            return _sync_result(False, detail, response, rule_count, detail)
        if rule_count is None:
            logger.warning("Router sync OK via %s but rule count was not reported: %s", endpoint, msg)
        else:
            logger.info("Router sync OK via %s: %s (rules=%d, %s)", endpoint, msg, rule_count, detail)
        return _sync_result(True, msg, response, rule_count, detail)
    else:
        msg = _response_message(response)
        logger.warning("Router sync failed: %s", msg)
        return _sync_result(False, msg, response, detail=msg)


def send_clear(router_ip, api_key, pc_ip, insecure_tls=False):
    payload = {
        "api_key": api_key,
        "action": "clear",
        "pc_ip": pc_ip,
    }
    
    response, err = _do_request(router_ip, payload, insecure_tls=insecure_tls)
    if response is None:
        logger.warning("Failed to clear router rules: %s", err)
        return _sync_result(False, err, detail=err)

    status_code = _effective_status_code(response)
    if status_code == 200:
        msg = _response_message(response, "Rules cleared")
        logger.info("Router rules cleared: %s", msg)
        return _sync_result(True, msg, response, rule_count=0)
    else:
        msg = _response_message(response)
        logger.warning("Failed to clear router rules: %s", msg)
        return _sync_result(False, msg, response, detail=msg)


def send_disconnect(router_ip, api_key, pc_ip, timeout=REQUEST_TIMEOUT, insecure_tls=False):
    payload = {
        "api_key": api_key,
        "action": "disconnect",
        "pc_ip": pc_ip,
    }

    response, err = _do_request(router_ip, payload, timeout=timeout, insecure_tls=insecure_tls)
    if response is None:
        logger.debug("Disconnect failed: %s", err)
        return _sync_result(False, err, detail=err)

    success = _effective_status_code(response) == 200
    msg = _response_message(response, "Disconnected" if success else None)
    if success:
        logger.info("Router agent disconnected: %s", msg)
    else:
        logger.debug("Disconnect failed: %s", msg)
    return _sync_result(success, msg, response, detail="" if success else msg)


def send_heartbeat(router_ip, api_key, pc_ip, insecure_tls=False):
    payload = {
        "api_key": api_key,
        "action": "heartbeat",
        "pc_ip": pc_ip,
    }
    
    response, err = _do_request(router_ip, payload, insecure_tls=insecure_tls)
    if response is None:
        logger.debug("Heartbeat failed: %s", err)
        return _sync_result(False, err, detail=err)

    success = _effective_status_code(response) == 200
    rule_count = None
    if success:
        msg = _response_message(response, "Heartbeat OK")
        data = _response_json(response)
        rule_count = _response_rule_count(response, msg)
        if rule_count is not None:
            msg = f"{msg} (rule_count={rule_count})"
        if "chain_exists" in data:
            msg = f"{msg} chain_exists={str(data.get('chain_exists')).lower()}"
        logger.debug("Heartbeat sent OK: %s", msg)
    else:
        msg = _response_message(response)
        logger.debug("Heartbeat failed: %s", msg)
    return _sync_result(success, msg, response, rule_count, "" if success else msg)


def test_connection(router_ip, api_key, pc_ip=None, insecure_tls=False):
    payload = {
        "api_key": api_key,
        "action": "heartbeat",
        "pc_ip": pc_ip or "192.168.1.2",
    }

    if not router_ip or not router_ip.strip():
        return False, "Router IP is required"

    if not api_key or not api_key.strip():
        return False, "API key is required"
    
    response, err = _do_request(router_ip, payload, insecure_tls=insecure_tls)
    if response is None:
        return False, err

    status_code = _effective_status_code(response)
    if status_code == 200:
        return True, "Connection successful"
    elif status_code == 401:
        return False, "Invalid API key"
    elif status_code == 403:
        return False, "Agent is disabled on the router"
    elif status_code == 503:
        return False, "MultiWAN QoS is restarting on the router"
    elif status_code == 429:
        return False, "Router agent is busy; try again"
    elif status_code == 404:
        return False, _response_message(response)
    else:
        return False, _response_message(response, f"Router returned HTTP {status_code}")
