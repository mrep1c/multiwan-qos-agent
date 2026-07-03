"""
MultiWAN QoS Agent — Unified single-process application.

Replaces the separate service + tray + IPC architecture with one app that:
- Runs in the system tray
- Monitors game processes in a background thread
- Manages Windows QoS policies (requires admin)
- Syncs with the router via HTTP
- Shows a live dashboard with real-time connection data
- Auto-starts via Task Scheduler
"""

import ctypes
from ctypes import wintypes
import json
import logging
import os
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox

import pystray
from PIL import Image, ImageDraw, ImageFont

from . import config as cfg
from . import flow_etw
from . import monitor
from . import qos
from . import sync

logger = logging.getLogger("multiwan_qos_agent")
TASK_NAME = "MultiWAN QoS Agent"
SINGLE_INSTANCE_MUTEX = "Local\\MultiWANQoSAgentSingleInstance"
ERROR_ALREADY_EXISTS = 183
ROUTER_RULE_REASSERT_SECONDS = 60
ROUTER_FAST_RECOVERY_SECONDS = 60
ROUTER_FAST_RECOVERY_INTERVAL_SECONDS = 2
ROUTER_NO_FLOW_GRACE_SECONDS = 120
ROUTER_SHUTDOWN_TIMEOUT_SECONDS = 3
_single_instance_handle = None

# ── State ────────────────────────────────────────────────────────────────────

class AgentState:
    """Shared state between background thread and UI."""
    def __init__(self):
        self.lock = threading.Lock()
        self.active_games = {}        # {game_name: {pids, exe_name, ...}}
        self.live_connections = []     # Current connection report sent to router
        self.flow_candidates = []      # ETW flows shown in dashboard but not necessarily sent
        self.flow_status = {"available": False, "message": "ETW flow telemetry not started"}
        self.last_sync_time = None
        self.last_sync_ok = False
        self.last_sync_msg = ""
        self.rules_count = 0
        self.running = True
        self.config = cfg.load_config()
        self.game_db = monitor.load_game_database()
        self.user_games = cfg.load_user_games()
        self.game_rules = cfg.load_game_rules()
        self.settings_open = False
        self.shutdown_cleanup_done = False

    def get_snapshot(self):
        with self.lock:
            return {
                "active_games": dict(self.active_games),
                "live_connections": list(self.live_connections),
                "flow_candidates": list(self.flow_candidates),
                "flow_status": dict(self.flow_status),
                "last_sync_time": self.last_sync_time,
                "last_sync_ok": self.last_sync_ok,
                "last_sync_msg": self.last_sync_msg,
                "rules_count": self.rules_count,
                "configured": cfg.is_configured(self.config),
                "dscp_value": cfg.normalize_dscp_value(self.config.get("dscp_value")),
                "local_tagging_enabled": bool(self.config.get("local_tagging_enabled", True)),
                "local_tagging_mode": cfg.normalize_local_tagging_mode(self.config.get("local_tagging_mode")),
            }


def _local_tagging_rule(game_data, game_rules):
    game_info = game_data.get("game_info", {})
    game_key = cfg.game_id(game_info, "builtin")
    rule = game_rules.get(game_key, {})
    return cfg.normalize_local_tagging_rule(rule.get("local_tagging") if isinstance(rule, dict) else rule)


def _game_allows_local_tagging(game_data, game_rules, local_tagging_enabled):
    if not local_tagging_enabled:
        return False
    rule = _local_tagging_rule(game_data, game_rules)
    return rule != cfg.LOCAL_TAGGING_RULE_DISABLED


def _build_policy_specs(
    detected,
    connections,
    local_tagging_enabled=True,
    local_tagging_mode=cfg.LOCAL_TAGGING_MODE_LIVE_FLOWS,
    game_rules=None,
):
    specs = []
    game_rules = game_rules or {}
    local_tagging_mode = cfg.normalize_local_tagging_mode(local_tagging_mode)

    if not local_tagging_enabled:
        return specs

    if local_tagging_mode == cfg.LOCAL_TAGGING_MODE_LIVE_FLOWS:
        for conn in connections:
            if not conn.get("selected", True):
                continue
            if str(conn.get("proto") or "udp").lower() != "udp":
                continue

            game_name = conn.get("game")
            game_data = detected.get(game_name)
            if not game_data:
                continue
            if not _game_allows_local_tagging(game_data, game_rules, local_tagging_enabled):
                continue

            remote_ip = conn.get("remote_ip")
            remote_port = conn.get("remote_port")
            if not remote_ip or not remote_port:
                continue

            specs.extend(qos.build_policy_specs(
                game_name,
                game_data["exe_name"],
                None,
                remote_ip=remote_ip,
                remote_port=remote_port,
                local_port=conn.get("local_port"),
            ))

        return specs

    for game_name, game_data in detected.items():
        if not _game_allows_local_tagging(game_data, game_rules, local_tagging_enabled):
            continue
        specs.extend(qos.build_policy_specs(game_name, game_data["exe_name"], None))

    return specs


def _policy_signature(specs, dscp_value):
    data = [
        (
            spec["name"],
            spec["exe"],
            spec.get("start_port"),
            spec.get("end_port"),
            spec.get("dst_prefix"),
            spec.get("dst_port"),
            spec.get("src_port"),
            dscp_value,
        )
        for spec in specs
    ]
    return json.dumps(sorted(data), sort_keys=True)


def _router_rule_connections(connections):
    """Return only fields that affect router nft rules."""
    rule_connections = []
    for conn in connections:
        if conn.get("remote_ip") and conn.get("remote_port"):
            item = {
                "game": conn.get("game"),
                "proto": conn.get("proto"),
            }
            item["remote_ip"] = conn.get("remote_ip")
            item["remote_port"] = conn.get("remote_port")
            if conn.get("local_port"):
                item["local_port"] = conn.get("local_port")
            rule_connections.append(item)
    return rule_connections


def _router_rule_signature(connections, dscp_value):
    return json.dumps({
        "connections": _router_rule_connections(connections),
        "dscp": dscp_value,
    }, sort_keys=True)


def _message_needs_router_clear(message):
    message = str(message or "").lower()
    return any(token in message for token in (
        "unexpected_rules",
        "unexpected_agent_rules",
        "raw_count_mismatch",
        "agent_count_mismatch",
        "non_agent_rule",
        "rule count",
        "verification mismatch",
    ))

# ── Background Monitor ──────────────────────────────────────────────────────

def _message_is_router_restarting(message):
    message = str(message or "").lower()
    return (
        "multiwan-qos is restarting" in message or
        "multiwan qos is restarting" in message or
        "router is restarting" in message
    )


def _message_triggers_fast_recovery(message):
    message = str(message or "").lower()
    return _message_is_router_restarting(message) or any(token in message for token in (
        "too many requests",
        "already in progress",
        "busy",
        "not found",
        "chain missing",
        "missing_chain",
        "agent nft chain not found",
    ))


def _acquire_single_instance_mutex():
    global _single_instance_handle

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.CreateMutexW.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    handle = kernel32.CreateMutexW(None, False, SINGLE_INSTANCE_MUTEX)
    if not handle:
        logger.warning("Could not create single-instance mutex; continuing")
        return True

    if ctypes.get_last_error() == ERROR_ALREADY_EXISTS:
        kernel32.CloseHandle(handle)
        return False

    _single_instance_handle = handle
    return True


def _release_single_instance_mutex():
    global _single_instance_handle
    if not _single_instance_handle:
        return

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle(_single_instance_handle)
    _single_instance_handle = None


def _sync_windows_policies(desired_specs, dscp_value, reason):
    try:
        ok = qos.sync_qos_policies(desired_specs, dscp_value)
        if ok:
            logger.info(
                "Windows QoS policy sync OK (%s): desired=%d",
                reason,
                len(desired_specs),
            )
        else:
            logger.warning("Windows QoS policy sync incomplete (%s)", reason)
        return ok
    except Exception:
        logger.exception("Windows QoS policy sync failed (%s)", reason)
        return False


def _cleanup_windows_policies(reason):
    try:
        result = qos.cleanup_all_policies()
        logger.info(
            "Windows QoS cleanup (%s): removed=%d remaining=%d",
            reason,
            result.get("removed", 0),
            len(result.get("remaining", [])),
        )
        return result
    except Exception:
        logger.exception("Windows QoS cleanup failed (%s)", reason)
        return {"removed": 0, "remaining": [], "failed": []}


def _cleanup_router_rules(config, reason, disconnect=False):
    if not cfg.is_configured(config):
        logger.debug("Router cleanup skipped (%s): agent is not configured", reason)
        return False, "agent is not configured"

    pc_ip = monitor.get_local_ip(config.get("router_ip"))
    if not pc_ip:
        logger.warning("Router cleanup skipped (%s): could not determine PC IP", reason)
        return False, "could not determine PC IP"

    if disconnect:
        ok, msg = sync.send_disconnect(
            config["router_ip"],
            config["api_key"],
            pc_ip,
            timeout=ROUTER_SHUTDOWN_TIMEOUT_SECONDS,
            insecure_tls=bool(config.get("insecure_tls", False)),
        )
    else:
        ok, msg = sync.send_clear(
            config["router_ip"],
            config["api_key"],
            pc_ip,
            insecure_tls=bool(config.get("insecure_tls", False)),
        )

    logger.info(
        "Router cleanup (%s): %s - %s",
        reason,
        "OK" if ok else "failed",
        msg,
    )
    return ok, msg


def _shutdown_cleanup(state, reason):
    with state.lock:
        if state.shutdown_cleanup_done:
            return
        state.shutdown_cleanup_done = True
        state.running = False
        current_config = dict(state.config)

    _cleanup_windows_policies(reason)
    ok, _msg = _cleanup_router_rules(current_config, reason, disconnect=True)

    if ok:
        with state.lock:
            state.rules_count = 0


def monitor_loop(state):
    """Background thread: detect games → QoS policies → sync router."""
    prev_games = set()
    last_conns_json = None
    last_router_update_time = 0
    last_policy_signature = None
    router_clear_pending = False
    fast_recovery_until = 0
    no_flow_started_at = None
    no_flow_clear_sent = False
    exe_map = monitor.get_all_game_executables(state.game_db, state.user_games)
    interval = state.config.get("heartbeat_interval", 30)
    flow_collector = flow_etw.EtwFlowCollector()
    flow_collector.start()
    with state.lock:
        state.flow_status = flow_collector.status()

    logger.info("Monitor started — tracking %d executables, interval %ds", len(exe_map), interval)

    while state.running:
        next_sleep = interval
        try:
            with state.lock:
                current_config = dict(state.config)
                user_games = list(state.user_games)
                game_rules = dict(state.game_rules)

            interval = current_config.get("heartbeat_interval", 30)
            next_sleep = interval
            dscp_value = cfg.normalize_dscp_value(current_config.get("dscp_value"))
            local_tagging_enabled = bool(current_config.get("local_tagging_enabled", True))
            local_tagging_mode = cfg.normalize_local_tagging_mode(current_config.get("local_tagging_mode"))
            insecure_tls = bool(current_config.get("insecure_tls", False))

            if not cfg.is_configured(current_config):
                time.sleep(5)
                continue

            exe_map = monitor.get_all_game_executables(state.game_db, user_games)

            # Detect games
            detected = monitor.find_running_games(exe_map)
            current_names = set(detected.keys())
            started_games = current_names - prev_games
            stopped_games = prev_games - current_names
            transitioned_to_idle = bool(prev_games) and not current_names

            # QoS policies: add new, remove stopped
            for name in started_games:
                logger.info("Game started: %s", name)

            for name in stopped_games:
                logger.info("Game stopped: %s", name)

            prev_games = current_names

            # Build connections
            if detected:
                connections, flow_candidates = monitor.build_connection_report(
                    detected,
                    flow_collector,
                )
            else:
                connections, flow_candidates = [], []
            router_connections = _router_rule_connections(connections)
            conns_json = _router_rule_signature(connections, dscp_value)

            # Update shared state
            with state.lock:
                state.active_games = detected
                state.live_connections = connections
                state.flow_candidates = flow_candidates
                state.flow_status = flow_collector.status()

            desired_specs = _build_policy_specs(
                detected,
                connections,
                local_tagging_enabled,
                local_tagging_mode,
                game_rules,
            )
            desired_signature = _policy_signature(desired_specs, dscp_value)
            if transitioned_to_idle or desired_signature != last_policy_signature:
                policy_reason = "game stop" if transitioned_to_idle else (
                    ("live-flow update" if local_tagging_mode == cfg.LOCAL_TAGGING_MODE_LIVE_FLOWS else "game update")
                    if desired_specs else
                    ("local-tagging cleanup" if detected else "startup cleanup")
                )
                if _sync_windows_policies(desired_specs, dscp_value, policy_reason):
                    last_policy_signature = desired_signature

            # Sync to router
            pc_ip = monitor.get_local_ip(current_config.get("router_ip"))
            if pc_ip and detected:
                now = time.monotonic()
                preserve_router_rules = False
                sync_result = None
                if not router_connections:
                    fast_recovery_until = 0
                    if no_flow_started_at is None:
                        no_flow_started_at = now
                    no_flow_age = now - no_flow_started_at
                    should_clear_no_flow = (
                        no_flow_age >= ROUTER_NO_FLOW_GRACE_SECONDS and
                        not no_flow_clear_sent
                    )

                    if should_clear_no_flow or router_clear_pending:
                        sync_result = sync.send_clear(
                            current_config["router_ip"], current_config["api_key"], pc_ip,
                            insecure_tls=insecure_tls)
                        ok, msg = sync_result
                        logger.info(
                            "Router agent clear after %.0fs without selected live UDP: %s - %s",
                            no_flow_age,
                            "OK" if ok else "failed",
                            msg,
                        )
                        if ok:
                            last_conns_json = None
                            last_router_update_time = 0
                            router_clear_pending = False
                            no_flow_clear_sent = True
                    else:
                        preserve_router_rules = last_conns_json is not None
                        sync_result = sync.send_heartbeat(
                            current_config["router_ip"], current_config["api_key"], pc_ip,
                            insecure_tls=insecure_tls)
                        ok, msg = sync_result
                        if ok:
                            if preserve_router_rules:
                                msg = (
                                    "Connected; waiting for live UDP "
                                    f"(preserving game rules, {int(no_flow_age)}s/"
                                    f"{ROUTER_NO_FLOW_GRACE_SECONDS}s)"
                                )
                            else:
                                msg = "Connected; waiting for live UDP"
                else:
                    no_flow_started_at = None
                    no_flow_clear_sent = False
                    if fast_recovery_until and now >= fast_recovery_until:
                        logger.warning("Router fast recovery window expired; returning to normal sync cadence.")
                        fast_recovery_until = 0
                    fast_recovery_active = fast_recovery_until > now
                    should_reassert = (
                        last_conns_json is not None and
                        (now - last_router_update_time) >= ROUTER_RULE_REASSERT_SECONDS
                    )
                    if fast_recovery_active:
                        next_sleep = ROUTER_FAST_RECOVERY_INTERVAL_SECONDS
                    if conns_json != last_conns_json or should_reassert or fast_recovery_active:
                        if should_reassert and conns_json == last_conns_json:
                            logger.info("Reasserting router agent rules")
                        elif fast_recovery_active and conns_json == last_conns_json:
                            logger.info("Fast recovery: retrying router agent update")
                        sync_result = sync.send_update(
                            current_config["router_ip"], current_config["api_key"],
                            pc_ip, router_connections, dscp_value,
                            insecure_tls=insecure_tls)
                        ok, msg = sync_result
                        if ok:
                            synced_rule_count = sync_result.rule_count
                            if router_connections and synced_rule_count == 0:
                                logger.warning(
                                    "Router update returned zero active rules while live flows exist. Scheduling re-sync."
                                )
                                last_conns_json = None
                                last_router_update_time = 0
                                router_clear_pending = False
                                fast_recovery_until = time.monotonic() + ROUTER_FAST_RECOVERY_SECONDS
                                next_sleep = ROUTER_FAST_RECOVERY_INTERVAL_SECONDS
                            else:
                                last_conns_json = conns_json
                                last_router_update_time = now
                                router_clear_pending = False
                                fast_recovery_until = 0
                        elif _message_triggers_fast_recovery(msg):
                            logger.info("Router not ready for agent update; keeping live flows and retrying fast: %s", msg)
                            last_conns_json = None
                            last_router_update_time = 0
                            router_clear_pending = False
                            fast_recovery_until = time.monotonic() + ROUTER_FAST_RECOVERY_SECONDS
                            next_sleep = ROUTER_FAST_RECOVERY_INTERVAL_SECONDS
                        elif _message_needs_router_clear(msg):
                            router_clear_pending = True
                    else:
                        sync_result = sync.send_heartbeat(
                            current_config["router_ip"], current_config["api_key"], pc_ip,
                            insecure_tls=insecure_tls)
                        ok, msg = sync_result
                        heartbeat_rule_count = sync_result.rule_count if ok else None
                        if ok and heartbeat_rule_count == 0:
                            logger.warning(
                                "Router heartbeat reports zero active rules while live flows exist. Scheduling update."
                            )
                            last_conns_json = None
                            last_router_update_time = 0
                            router_clear_pending = False
                            fast_recovery_until = time.monotonic() + ROUTER_FAST_RECOVERY_SECONDS
                            next_sleep = ROUTER_FAST_RECOVERY_INTERVAL_SECONDS
                        if not ok and _message_triggers_fast_recovery(msg):
                            logger.info("Router not ready; keeping live flows and retrying fast: %s", msg)
                            last_conns_json = None
                            last_router_update_time = 0
                            router_clear_pending = False
                            fast_recovery_until = time.monotonic() + ROUTER_FAST_RECOVERY_SECONDS
                            next_sleep = ROUTER_FAST_RECOVERY_INTERVAL_SECONDS
                        elif not ok and msg and "not found" in str(msg).lower():
                            logger.warning("Heartbeat failed (chain missing). Scheduling re-sync.")
                            last_conns_json = None

                with state.lock:
                    state.last_sync_time = time.strftime("%H:%M:%S")
                    state.last_sync_ok = ok
                    state.last_sync_msg = msg
                    parsed_rule_count = sync_result.rule_count if ok and sync_result else None
                    if parsed_rule_count is not None:
                        state.rules_count = parsed_rule_count
                    elif not router_connections and ok and not preserve_router_rules:
                        state.rules_count = 0

            elif pc_ip and not detected:
                fast_recovery_until = 0
                no_flow_started_at = None
                no_flow_clear_sent = False
                if transitioned_to_idle or last_conns_json is not None:
                    router_clear_pending = True
                    last_conns_json = None

                if router_clear_pending:
                    ok, msg = sync.send_clear(
                        current_config["router_ip"], current_config["api_key"], pc_ip,
                        insecure_tls=insecure_tls)
                    logger.info(
                        "Router agent clear after game stop: %s - %s",
                        "OK" if ok else "failed",
                        msg,
                    )
                    if ok:
                        router_clear_pending = False
                        last_router_update_time = 0
                else:
                    ok, msg = sync.send_heartbeat(
                        current_config["router_ip"], current_config["api_key"], pc_ip,
                        insecure_tls=insecure_tls)

                with state.lock:
                    state.last_sync_time = time.strftime("%H:%M:%S")
                    state.last_sync_ok = ok
                    state.last_sync_msg = msg or ("Connected" if ok else "")
                    if not router_clear_pending:
                        state.rules_count = 0

        except Exception as e:
            logger.error("Monitor error: %s", e)

        # Sleep in small increments so we can stop quickly
        sleep_ticks = max(1, int(next_sleep * 2))
        for _ in range(sleep_ticks):
            if not state.running:
                break
            time.sleep(0.5)

    flow_collector.stop()

# ── Tray Icon ────────────────────────────────────────────────────────────────

def create_icon(color="gray"):
    size = 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    colors = {"green": (76, 175, 80), "yellow": (255, 193, 7),
              "red": (244, 67, 54), "gray": (158, 158, 158)}
    fill = colors.get(color, colors["gray"])
    draw.rounded_rectangle([4, 4, size-4, size-4], radius=12, fill=fill)
    try:
        draw.text((18, 12), "Q", fill="white", font=ImageFont.truetype("arial.ttf", 32))
    except Exception:
        draw.text((20, 14), "Q", fill="white")
    return img


def show_custom_games(state, parent):
    """Show the unified game rules and custom game editor."""
    def _run():
        root = tk.Toplevel(parent)
        root.title("MultiWAN QoS Agent - Game Rules")
        root.geometry("820x480")
        root.resizable(True, True)

        main = ttk.Frame(root, padding=12)
        main.pack(fill="both", expand=True)

        left = ttk.Frame(main)
        left.pack(side="left", fill="both", expand=True, padx=(0, 10))

        right = ttk.Frame(main)
        right.pack(side="right", fill="both", expand=True)

        ttk.Label(left, text="Game Rules").pack(anchor="w")
        game_list = tk.Listbox(left, height=16, width=34)
        game_list.pack(fill="both", expand=True, pady=(4, 0))

        source_var = tk.StringVar()
        name_var = tk.StringVar()
        exe_var = tk.StringVar()
        rule_var = tk.StringVar(master=root, value=cfg.local_tagging_rule_label(cfg.LOCAL_TAGGING_RULE_GLOBAL))
        status_var = tk.StringVar()
        entries_state = {"items": [], "selected": None}

        ttk.Label(right, text="Type").pack(anchor="w")
        source_entry = ttk.Entry(right, textvariable=source_var)
        source_entry.pack(fill="x", pady=(2, 8))
        source_entry.configure(state="disabled")
        ttk.Label(right, text="Name").pack(anchor="w")
        name_entry = ttk.Entry(right, textvariable=name_var)
        name_entry.pack(fill="x", pady=(2, 8))

        ttk.Label(right, text="Executable names").pack(anchor="w")
        exe_entry = ttk.Entry(right, textvariable=exe_var)
        exe_entry.pack(fill="x", pady=(2, 4))
        ttk.Label(right, text="Comma-separated, e.g. game.exe, launcher.exe").pack(anchor="w")

        ttk.Label(right, text="Local Windows DSCP tagging").pack(anchor="w", pady=(10, 0))
        rule_combo = ttk.Combobox(
            right,
            textvariable=rule_var,
            values=cfg.local_tagging_rule_options(),
            state="readonly",
        )
        rule_combo.pack(fill="x", pady=(2, 0))

        ttk.Label(right, textvariable=status_var, foreground="gray").pack(anchor="w", pady=(12, 4))

        def get_games():
            with state.lock:
                return list(state.user_games)

        def set_games(games):
            with state.lock:
                state.user_games = games
            cfg.save_user_games(games)

        def get_rules():
            with state.lock:
                return dict(state.game_rules)

        def set_rules(rules):
            sanitized = cfg.sanitize_game_rules(rules)
            with state.lock:
                state.game_rules = sanitized
            cfg.save_game_rules(sanitized)

        def game_entries():
            entries = []
            with state.lock:
                builtin_games = list(state.game_db)
            for game in builtin_games:
                entries.append({
                    "id": cfg.game_id(game, "builtin"),
                    "source": "builtin",
                    "index": None,
                    "game": game,
                })
            for index, game in enumerate(get_games()):
                entries.append({
                    "id": cfg.game_id(game, "custom"),
                    "source": "custom",
                    "index": index,
                    "game": game,
                })
            return entries

        def rule_for(game_key):
            rule = get_rules().get(game_key, {})
            return cfg.normalize_local_tagging_rule(rule.get("local_tagging") if isinstance(rule, dict) else rule)

        def entry_label(entry):
            game = entry["game"]
            source = "Built-in" if entry["source"] == "builtin" else "Custom"
            rule = rule_for(entry["id"])
            suffix = ""
            if rule != cfg.LOCAL_TAGGING_RULE_GLOBAL:
                suffix = f" - {cfg.local_tagging_rule_label(rule)}"
            return f"{game.get('name', 'Game')} [{source}]{suffix}"

        def set_custom_editable(enabled):
            state_name = "normal" if enabled else "disabled"
            name_entry.configure(state=state_name)
            exe_entry.configure(state=state_name)
            delete_button.configure(state=state_name if enabled else "disabled")

        def refresh_list(selected_id=None):
            entries = game_entries()
            entries_state["items"] = entries
            game_list.delete(0, tk.END)
            selected_index = None
            for index, entry in enumerate(entries):
                game_list.insert(tk.END, entry_label(entry))
                if selected_id is not None and entry["id"] == selected_id:
                    selected_index = index
            if selected_index is not None:
                game_list.selection_set(selected_index)
                game_list.activate(selected_index)
                load_selected()
            elif selected_id is None:
                new_entry()

        def load_selected(_event=None):
            selection = game_list.curselection()
            if not selection:
                return
            entry = entries_state["items"][selection[0]]
            entries_state["selected"] = entry
            game = entry["game"]
            source_var.set("Built-in game" if entry["source"] == "builtin" else "Custom game")
            name_var.set(game.get("name", ""))
            exe_var.set(", ".join(game.get("executables", [])))
            rule_var.set(cfg.local_tagging_rule_label(rule_for(entry["id"])))
            set_custom_editable(entry["source"] == "custom")
            status_var.set("")

        def validate_form(existing_id=None):
            name = name_var.get().strip()
            executables = [
                exe.strip()
                for exe in exe_var.get().split(",")
                if exe.strip()
            ]

            if not name:
                return None, "Name is required"
            if not executables:
                return None, "At least one executable is required"
            for exe in executables:
                if not exe.lower().endswith(".exe"):
                    return None, f"Executable must end with .exe: {exe}"

            entry = {
                "name": name,
                "executables": executables,
                "proto": "udp",
            }
            if existing_id:
                entry["id"] = existing_id
            else:
                entry["id"] = cfg.game_id(entry, "custom")
            return entry, ""

        def save_rule(game_key):
            rules = get_rules()
            rule = cfg.local_tagging_rule_from_label(rule_var.get())
            if rule == cfg.LOCAL_TAGGING_RULE_GLOBAL:
                rules.pop(game_key, None)
            else:
                rules[game_key] = {"local_tagging": rule}
            set_rules(rules)

        def save_entry():
            current = entries_state.get("selected")

            if current and current["source"] == "builtin":
                save_rule(current["id"])
                refresh_list(current["id"])
                status_var.set("Saved")
                return

            existing_id = current["id"] if current and current["source"] == "custom" else None
            entry, error = validate_form(existing_id)
            if error:
                status_var.set(error)
                return

            games = get_games()
            if current and current["source"] == "custom" and current["index"] is not None:
                games[current["index"]] = entry
            else:
                games.append(entry)

            set_games(games)
            save_rule(entry["id"])
            refresh_list(entry["id"])
            status_var.set("Saved")

        def new_entry():
            game_list.selection_clear(0, tk.END)
            entries_state["selected"] = {"id": None, "source": "custom", "index": None, "game": {}}
            source_var.set("Custom game")
            name_var.set("")
            exe_var.set("")
            rule_var.set(cfg.local_tagging_rule_label(cfg.LOCAL_TAGGING_RULE_GLOBAL))
            set_custom_editable(True)
            status_var.set("")

        def delete_entry():
            current = entries_state.get("selected")
            if not current or current["source"] != "custom" or current["index"] is None:
                status_var.set("Select a custom entry to delete")
                return
            games = get_games()
            del games[current["index"]]
            set_games(games)
            rules = get_rules()
            if current["id"]:
                rules.pop(current["id"], None)
            set_rules(rules)
            new_entry()
            refresh_list()
            status_var.set("Deleted")

        buttons = ttk.Frame(right)
        buttons.pack(fill="x", pady=(12, 0))
        ttk.Button(buttons, text="New Custom", command=new_entry).pack(side="left", padx=(0, 6))
        ttk.Button(buttons, text="Save", command=save_entry).pack(side="left", padx=(0, 6))
        delete_button = ttk.Button(buttons, text="Delete", command=delete_entry)
        delete_button.pack(side="left", padx=(0, 6))
        ttk.Button(buttons, text="Close", command=root.destroy).pack(side="right")

        game_list.bind("<<ListboxSelect>>", load_selected)
        refresh_list()
        root.lift()
        return root

    return _run()

# ── Live Dashboard ───────────────────────────────────────────────────────────

class DashboardWindow:
    """Real-time dashboard showing games, connections, IPs, ports, sync status."""

    def __init__(self, state, parent, on_custom_games=None):
        self.state = state
        self.parent = parent
        self.on_custom_games = on_custom_games
        self.root = None
        self.dscp_var = None
        self.dscp_combo = None

    def _is_open(self):
        if not self.root:
            return False
        try:
            return bool(self.root.winfo_exists())
        except tk.TclError:
            self.root = None
            return False

    def show(self):
        if self._is_open():
            self.root.lift()
            self.root.focus_force()
            return
        return self._create()

    def _close(self):
        root = self.root
        self.root = None
        if root:
            root.destroy()

    def _save_dscp_selection(self, _event=None):
        if not self.dscp_var:
            return

        new_value = cfg.dscp_value_from_label(self.dscp_var.get())
        with self.state.lock:
            current_value = cfg.normalize_dscp_value(self.state.config.get("dscp_value"))
            if new_value == current_value:
                return
            new_config = dict(self.state.config)
            new_config["dscp_value"] = new_value
            self.state.config = new_config
            self.state.last_sync_msg = "DSCP changed; syncing"

        if cfg.save_config(new_config):
            with self.state.lock:
                self.state.config = cfg.load_config()
        else:
            logger.error("Failed to save DSCP selection")

    def _refresh_dscp_selection(self, dscp_value):
        if not self.dscp_var:
            return
        label = cfg.dscp_label(dscp_value)
        if self.dscp_var.get() != label:
            self.dscp_var.set(label)

    def _create(self):
        self.root = tk.Toplevel(self.parent)
        self.root.title("MultiWAN QoS Agent — Live Dashboard")
        self.root.geometry("820x650")
        self.root.configure(bg="#1e1e2e")
        self.root.resizable(True, True)
        self.root.protocol("WM_DELETE_WINDOW", self._close)

        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("Dark.TFrame", background="#1e1e2e")
        style.configure("Dark.TLabel", background="#1e1e2e", foreground="#cdd6f4",
                         font=("Segoe UI", 10))
        style.configure("Title.TLabel", background="#1e1e2e", foreground="#89b4fa",
                         font=("Segoe UI", 14, "bold"))
        style.configure("Status.TLabel", background="#1e1e2e", foreground="#a6e3a1",
                         font=("Segoe UI", 10))
        style.configure("Warn.TLabel", background="#1e1e2e", foreground="#f38ba8",
                         font=("Segoe UI", 10))
        style.configure("Dark.Treeview", background="#313244", foreground="#cdd6f4",
                         fieldbackground="#313244", font=("Consolas", 9),
                         rowheight=22)
        style.configure("Dark.Treeview.Heading", background="#45475a",
                         foreground="#cdd6f4", font=("Segoe UI", 9, "bold"))
        style.map("Dark.Treeview", background=[("selected", "#585b70")])

        main = ttk.Frame(self.root, style="Dark.TFrame", padding=15)
        main.pack(fill="both", expand=True)

        # Header
        ttk.Label(main, text="🎮 MultiWAN QoS Agent — Live Traffic", style="Title.TLabel").pack(anchor="w")

        # Status bar
        status_frame = ttk.Frame(main, style="Dark.TFrame")
        status_frame.pack(fill="x", pady=(8, 4))

        self.lbl_games = ttk.Label(status_frame, text="Games: 0", style="Dark.TLabel")
        self.lbl_games.pack(side="left", padx=(0, 20))
        self.lbl_sync = ttk.Label(status_frame, text="Router: ●", style="Dark.TLabel")
        self.lbl_sync.pack(side="left", padx=(0, 20))
        self.lbl_rules = ttk.Label(status_frame, text="Rules: 0", style="Dark.TLabel")
        self.lbl_rules.pack(side="left", padx=(0, 20))
        self.lbl_detector = ttk.Label(status_frame, text="Detector: starting", style="Dark.TLabel")
        self.lbl_detector.pack(side="left", padx=(0, 20))
        ttk.Button(status_frame, text="Game Rules",
                   command=self.on_custom_games).pack(side="left", padx=(0, 20))
        self.lbl_time = ttk.Label(status_frame, text="", style="Dark.TLabel")
        self.lbl_time.pack(side="right")

        # Active Games section
        ttk.Label(main, text="Active Games", style="Dark.TLabel").pack(anchor="w", pady=(10, 2))
        game_frame = ttk.Frame(main, style="Dark.TFrame")
        game_frame.pack(fill="x")

        self.game_tree = ttk.Treeview(game_frame, columns=("exe", "pids", "mode"),
                                       show="headings", height=3, style="Dark.Treeview")
        self.game_tree.heading("exe", text="Game")
        self.game_tree.heading("pids", text="Process (PID)")
        self.game_tree.heading("mode", text="Detection Mode")
        self.game_tree.column("exe", width=200)
        self.game_tree.column("pids", width=200)
        self.game_tree.column("mode", width=120)
        self.game_tree.pack(fill="x")

        # Connections section
        ttk.Label(main, text="Live Connections", style="Dark.TLabel").pack(anchor="w", pady=(10, 2))
        conn_frame = ttk.Frame(main, style="Dark.TFrame")
        conn_frame.pack(fill="both", expand=True)

        self.conn_tree = ttk.Treeview(conn_frame,
                                       columns=("game", "proto", "remote_ip", "remote_port", "type"),
                                       show="headings", style="Dark.Treeview")
        self.conn_tree.heading("game", text="Game")
        self.conn_tree.heading("proto", text="Proto")
        self.conn_tree.heading("remote_ip", text="Remote IP")
        self.conn_tree.heading("remote_port", text="Port")
        self.conn_tree.heading("type", text="Match Type")
        self.conn_tree.column("game", width=150)
        self.conn_tree.column("proto", width=60)
        self.conn_tree.column("remote_ip", width=180)
        self.conn_tree.column("remote_port", width=80)
        self.conn_tree.column("type", width=150)

        scroll = ttk.Scrollbar(conn_frame, orient="vertical", command=self.conn_tree.yview)
        self.conn_tree.configure(yscrollcommand=scroll.set)
        self.conn_tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        # DSCP info bar
        dscp_frame = ttk.Frame(main, style="Dark.TFrame")
        dscp_frame.pack(fill="x", pady=(8, 0))
        ttk.Label(dscp_frame, text="DSCP:", style="Dark.TLabel").pack(side="left", padx=(0, 6))
        self.dscp_var = tk.StringVar(master=self.root, value=cfg.dscp_label(self.state.config.get("dscp_value")))
        self.dscp_combo = ttk.Combobox(
            dscp_frame,
            textvariable=self.dscp_var,
            values=cfg.dscp_options(),
            state="readonly",
            width=22,
        )
        self.dscp_combo.pack(side="left")
        self.dscp_combo.bind("<<ComboboxSelected>>", self._save_dscp_selection)
        self.lbl_pc_ip = ttk.Label(dscp_frame, text="", style="Dark.TLabel")
        self.lbl_pc_ip.pack(side="right")

        self._refresh()
        self.root.lift()
        return self.root

    def _refresh(self):
        if not self._is_open():
            return

        snap = self.state.get_snapshot()

        # Status bar
        n_games = len(snap["active_games"])
        self.lbl_games.config(text=f"Games: {n_games}")
        self.lbl_rules.config(text=f"Router Rules: {snap['rules_count']}")
        self._refresh_dscp_selection(snap.get("dscp_value"))
        flow_status = snap.get("flow_status", {})
        detector_style = "Status.TLabel" if flow_status.get("available") else "Warn.TLabel"
        self.lbl_detector.config(
            text=f"Detector: {flow_status.get('message', 'unknown')}",
            style=detector_style,
        )

        if not snap["configured"]:
            self.lbl_sync.config(text="Router: ⚠ Not configured", style="Warn.TLabel")
        elif snap["last_sync_ok"]:
            self.lbl_sync.config(text="Router: ● Connected", style="Status.TLabel")
        elif snap["last_sync_time"]:
            self.lbl_sync.config(text=f"Router: ✕ {snap['last_sync_msg']}", style="Warn.TLabel")
        else:
            self.lbl_sync.config(text="Router: ○ Idle", style="Dark.TLabel")

        if snap["last_sync_time"]:
            self.lbl_time.config(text=f"Last sync: {snap['last_sync_time']}")

        router_ip = ""
        with self.state.lock:
            router_ip = self.state.config.get("router_ip", "")
        pc_ip = monitor.get_local_ip(router_ip)
        if pc_ip:
            self.lbl_pc_ip.config(text=f"PC IP: {pc_ip}")

        # Games table
        self.game_tree.delete(*self.game_tree.get_children())
        for name, data in snap["active_games"].items():
            pids = ", ".join(str(p) for p in data.get("pids", []))
            game_connections = [
                c for c in snap["live_connections"]
                if c.get("game") == name
            ]
            if any(c.get("source") == "ETW flow telemetry" for c in game_connections):
                mode = "ETW flow telemetry"
            elif any(c.get("remote_ip") for c in game_connections):
                mode = "psutil live"
            else:
                mode = "waiting for live UDP"
            self.game_tree.insert("", "end", values=(name, f"{data.get('exe_name', '?')} ({pids})", mode))

        # Connections table
        self.conn_tree.delete(*self.conn_tree.get_children())
        ignored_flows = [
            flow for flow in snap.get("flow_candidates", [])
            if not flow.get("selected")
        ]
        for conn in snap["live_connections"] + ignored_flows:
            game = conn.get("game", "?")
            proto = conn.get("proto", "?").upper()
            if conn.get("remote_ip"):
                ip = conn["remote_ip"]
                port = str(conn.get("remote_port", ""))
                bps = int(conn.get("throughput_bps") or 0)
                if bps:
                    port = f"{port} ({bps // 1024} KB/s)"
                match_type = conn.get("source", "Live")
                if not conn.get("selected", True):
                    match_type = f"Ignored: {conn.get('ignored_reason', 'ignored')}"
            else:
                ip = "—"
                port = ""
                match_type = conn.get("source", "waiting")
            self.conn_tree.insert("", "end", values=(game, proto, ip, port, match_type))

        # Schedule next refresh
        if self._is_open():
            self.root.after(2000, self._refresh)

# ── Settings Dialog ──────────────────────────────────────────────────────────

def show_settings(state, parent):
    if getattr(state, "settings_open", False):
        return
    state.settings_open = True

    def _router_uses_https(value):
        return str(value or "").strip().lower().startswith("https://")

    def _run():
        root = tk.Toplevel(parent)
        root.title("MultiWAN QoS Agent — Settings")
        root.geometry("460x430")
        root.resizable(False, False)
        root.update_idletasks()
        root.tk.call("tk::PlaceWindow", root._w, "center")

        frame = ttk.Frame(root, padding=20)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="MultiWAN QoS Agent Settings", font=("Segoe UI", 14, "bold")).pack(anchor="w")
        ttk.Label(frame, text="Connect to your OpenWrt router.").pack(anchor="w", pady=(0, 15))

        # Router IP
        ip_f = ttk.Frame(frame)
        ip_f.pack(fill="x", pady=4)
        ttk.Label(ip_f, text="Router IP:", width=14).pack(side="left")
        ip_var = tk.StringVar(master=root, value=state.config.get("router_ip", ""))
        ip_entry = ttk.Entry(ip_f, textvariable=ip_var, width=28)
        ip_entry.pack(side="left", fill="x", expand=True)

        # API Key
        key_f = ttk.Frame(frame)
        key_f.pack(fill="x", pady=4)
        ttk.Label(key_f, text="API Key:", width=14).pack(side="left")
        key_var = tk.StringVar(master=root, value=state.config.get("api_key", ""))
        key_entry = ttk.Entry(key_f, textvariable=key_var, width=28, show="*")
        key_entry.pack(side="left", fill="x", expand=True)

        show_var = tk.BooleanVar(master=root)
        ttk.Checkbutton(frame, text="Show key", variable=show_var,
                         command=lambda: key_entry.config(show="" if show_var.get() else "*")
                         ).pack(anchor="w")

        tls_var = tk.BooleanVar(master=root, value=bool(state.config.get("insecure_tls", False)))
        tls_manual = {
            "value": (
                _router_uses_https(ip_var.get()) and
                not bool(state.config.get("insecure_tls", False))
            )
        }

        def mark_tls_manual():
            tls_manual["value"] = True

        def auto_enable_tls_for_https(*_args):
            if _router_uses_https(ip_var.get()) and not tls_manual["value"]:
                tls_var.set(True)

        ip_var.trace_add("write", auto_enable_tls_for_https)
        ttk.Checkbutton(
            frame,
            text="Allow insecure HTTPS certificates",
            variable=tls_var,
            command=mark_tls_manual,
        ).pack(anchor="w", pady=(6, 0))

        tagging_enabled_var = tk.BooleanVar(
            master=root,
            value=bool(state.config.get("local_tagging_enabled", True)),
        )
        ttk.Checkbutton(
            frame,
            text="Enable local Windows DSCP tagging",
            variable=tagging_enabled_var,
        ).pack(anchor="w", pady=(8, 0))

        mode_f = ttk.Frame(frame)
        mode_f.pack(fill="x", pady=(8, 0))
        ttk.Label(mode_f, text="Local tagging mode:", width=18).pack(side="left")
        mode_var = tk.StringVar(
            master=root,
            value=cfg.local_tagging_mode_label(state.config.get("local_tagging_mode")),
        )
        ttk.Combobox(
            mode_f,
            textvariable=mode_var,
            values=cfg.local_tagging_mode_options(),
            state="readonly",
            width=28,
        ).pack(side="left", fill="x", expand=True)

        # Auto-start
        auto_start_value = is_autostart_enabled()
        with state.lock:
            state.config["auto_start"] = auto_start_value
        auto_var = tk.BooleanVar(master=root, value=auto_start_value)
        ttk.Checkbutton(frame, text="Start automatically on Windows login", variable=auto_var
                         ).pack(anchor="w", pady=(8, 0))

        status_var = tk.StringVar(master=root)
        status_lbl = ttk.Label(frame, textvariable=status_var, foreground="gray")
        status_lbl.pack(pady=8)
        ttk.Label(frame, text=f"Config: {cfg.get_config_path()}", foreground="gray",
                  wraplength=410).pack(anchor="w")

        btn_f = ttk.Frame(frame)
        btn_f.pack(fill="x", pady=8)

        def on_test():
            router_ip = ip_entry.get().strip()
            api_key = key_entry.get().strip()
            status_var.set("Testing...")
            root.update()
            ok, msg = sync.test_connection(
                router_ip,
                api_key,
                monitor.get_local_ip(router_ip),
                insecure_tls=tls_var.get(),
            )
            status_var.set(f"✓ {msg}" if ok else f"✕ {msg}")
            status_lbl.config(foreground="green" if ok else "red")

        def on_save():
            new_config = dict(state.config)
            router_ip = ip_entry.get().strip()
            api_key = key_entry.get().strip()
            auto_start = auto_var.get()

            if not router_ip or not api_key:
                messagebox.showerror("MultiWAN QoS Agent", "Router IP and API key are required.", parent=root)
                return

            if not setup_autostart(auto_start):
                messagebox.showerror("MultiWAN QoS Agent", "Failed to update Start with Windows. Check the agent log.", parent=root)
                return

            new_config["router_ip"] = router_ip
            new_config["api_key"] = api_key
            new_config["insecure_tls"] = bool(tls_var.get())
            new_config["local_tagging_enabled"] = bool(tagging_enabled_var.get())
            new_config["local_tagging_mode"] = cfg.local_tagging_mode_from_label(mode_var.get())
            new_config["auto_start"] = auto_start
            new_config["setup_complete"] = True

            if not cfg.save_config(new_config):
                messagebox.showerror("MultiWAN QoS Agent", "Failed to save settings. Check file permissions.", parent=root)
                return

            with state.lock:
                state.config = cfg.load_config()

            status_var.set(f"Saved to {cfg.get_config_path()}")
            messagebox.showinfo("MultiWAN QoS Agent", "Settings saved!", parent=root)
            close_settings()

        def close_settings():
            state.settings_open = False
            root.destroy()

        root.protocol("WM_DELETE_WINDOW", close_settings)

        ttk.Button(btn_f, text="Test", command=on_test).pack(side="left", padx=4)
        ttk.Button(btn_f, text="Cancel", command=close_settings).pack(side="right", padx=4)
        ttk.Button(btn_f, text="Save", command=on_save).pack(side="right", padx=4)

        root.lift()
        return root

    return _run()

# ── Auto-Start ───────────────────────────────────────────────────────────────

class UIManager:
    """Owns the single Tk root and routes all UI work onto Tk's thread."""

    def __init__(self, state):
        self.state = state
        self.root = tk.Tk()
        self.root.withdraw()
        self.root.title("MultiWAN QoS Agent")
        self.dashboard = DashboardWindow(state, self.root, self.show_custom_games)
        self.settings_window = None
        self.custom_games_window = None
        self.icon = None

    def call(self, name, func):
        def _wrapped():
            try:
                func()
            except Exception:
                logger.exception("%s UI action failed", name)
                self.show_error(f"{name} failed. Check agent.log for details.")

        try:
            self.root.after(0, _wrapped)
        except tk.TclError:
            logger.exception("Failed to schedule %s UI action", name)

    def show_error(self, message):
        try:
            messagebox.showerror("MultiWAN QoS Agent", message, parent=self.root)
        except Exception:
            logger.exception("Failed to show UI error dialog")

    def _is_open(self, window):
        if not window:
            return False
        try:
            return bool(window.winfo_exists())
        except tk.TclError:
            return False

    def _raise(self, window):
        window.deiconify()
        window.lift()
        window.focus_force()

    def _track(self, attr, window):
        def _on_destroy(event):
            if event.widget is window:
                setattr(self, attr, None)
                if attr == "settings_window":
                    self.state.settings_open = False

        window.bind("<Destroy>", _on_destroy, add="+")
        setattr(self, attr, window)
        self._raise(window)

    def show_dashboard(self):
        self.dashboard.show()

    def show_settings(self):
        if self._is_open(self.settings_window):
            self._raise(self.settings_window)
            return
        window = show_settings(self.state, self.root)
        if window:
            self._track("settings_window", window)

    def show_custom_games(self):
        if self._is_open(self.custom_games_window):
            self._raise(self.custom_games_window)
            return
        window = show_custom_games(self.state, self.root)
        if window:
            self._track("custom_games_window", window)

    def set_icon(self, icon):
        self.icon = icon

    def quit(self):
        try:
            if self.icon:
                self.icon.stop()
        except Exception:
            logger.exception("Failed to stop tray icon")
        try:
            self.root.quit()
            self.root.destroy()
        except tk.TclError:
            pass

    def mainloop(self):
        self.root.mainloop()


def get_exe_path():
    """Get the path to the current executable (works for both .py and .exe)."""
    if getattr(sys, 'frozen', False):
        return sys.executable  # PyInstaller .exe
    return os.path.abspath(sys.argv[0])

def should_start_in_tray():
    """Return true for scheduled/autostart launches."""
    return any(arg in ("--tray", "--minimized", "--silent") for arg in sys.argv[1:])

def hidden_subprocess_kwargs():
    startupinfo = None
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    if hasattr(subprocess, "STARTUPINFO"):
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= getattr(subprocess, "STARTF_USESHOWWINDOW", 0)
        startupinfo.wShowWindow = 0

    return {
        "creationflags": creationflags,
        "startupinfo": startupinfo,
    }

def _task_output(result):
    output = (result.stdout or "") + (result.stderr or "")
    return output.strip()


def is_autostart_enabled():
    """Return true when the Task Scheduler autostart task exists."""
    cmd = ["schtasks", "/query", "/tn", TASK_NAME]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
            **hidden_subprocess_kwargs(),
        )
        return result.returncode == 0
    except Exception as e:
        logger.error("Failed to query auto-start: %s", e)
        return False


def setup_autostart(enabled):
    """Create/remove a Task Scheduler task for auto-start with admin privileges."""
    exe_path = get_exe_path()

    if enabled:
        # Create task that runs at logon with highest privileges
        cmd = ["schtasks", "/create", "/tn", TASK_NAME, "/tr", f'"{exe_path}" --tray', "/sc", "onlogon", "/rl", "highest", "/f"]
    else:
        cmd = ["schtasks", "/delete", "/tn", TASK_NAME, "/f"]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
            **hidden_subprocess_kwargs(),
        )
        if result.returncode == 0:
            logger.info("Auto-start %s", "enabled" if enabled else "disabled")
            return True
        if is_autostart_enabled() == enabled:
            logger.info("Auto-start already %s", "enabled" if enabled else "disabled")
            return True
        logger.error("Failed to set auto-start: %s", _task_output(result))
        return False
    except Exception as e:
        logger.error("Failed to set auto-start: %s", e)
        return False


def sync_autostart_config(state):
    """Mirror the real Task Scheduler state into the in-memory and saved config."""
    actual = is_autostart_enabled()
    with state.lock:
        if state.config.get("auto_start") == actual:
            return actual
        new_config = dict(state.config)
        new_config["auto_start"] = actual
        state.config = new_config

    if cfg.save_config(new_config):
        with state.lock:
            state.config = cfg.load_config()
    else:
        logger.error("Failed to save auto-start sync state")

    return actual

# ── Admin Check ──────────────────────────────────────────────────────────────

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def restart_as_admin():
    """Re-launch this process with admin privileges via UAC."""
    if getattr(sys, 'frozen', False):
        exe = sys.executable
        params = subprocess.list2cmdline(sys.argv[1:])
    else:
        exe = sys.executable
        params = subprocess.list2cmdline([os.path.abspath(sys.argv[0])] + sys.argv[1:])

    ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
    sys.exit(0)

# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    # Request admin if needed (for QoS policies)
    if not is_admin():
        restart_as_admin()
        return

    # Setup logging
    log_dir = cfg.get_config_dir()
    log_file = os.path.join(log_dir, "agent.log")
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.FileHandler(log_file), logging.StreamHandler()],
    )
    logger.info("MultiWAN QoS Agent starting")

    if not _acquire_single_instance_mutex():
        logger.warning("Another MultiWAN QoS Agent instance is already running; exiting")
        return

    state = AgentState()
    sync_autostart_config(state)
    ui = UIManager(state)
    start_in_tray = should_start_in_tray()

    # First/manual launch should show a real window. Scheduled autostart uses --tray.
    if not start_in_tray and not cfg.is_configured(state.config):
        ui.show_settings()
    elif not start_in_tray:
        ui.show_dashboard()

    # Start background monitor
    mon_thread = threading.Thread(target=monitor_loop, args=(state,), daemon=True)
    mon_thread.start()

    # Build tray menu
    shutdown_requested = threading.Event()

    def safe_callback(name, func):
        def _wrapped(icon, item):
            try:
                return func(icon, item)
            except Exception:
                logger.exception("%s callback failed", name)
                return None
        return _wrapped

    def on_dashboard(icon, item):
        ui.call("dashboard", ui.show_dashboard)

    def on_settings(icon, item):
        ui.call("settings", ui.show_settings)

    def on_custom_games(icon, item):
        ui.call("game rules", ui.show_custom_games)

    def on_quit(icon, item):
        if shutdown_requested.is_set():
            return

        shutdown_requested.set()
        logger.info("Tray quit requested")
        with state.lock:
            state.running = False

        try:
            icon.stop()
        except Exception:
            logger.debug("Tray icon already stopped", exc_info=True)

        ui.call("quit", ui.quit)

    def on_autostart(icon, item):
        desired = not is_autostart_enabled()
        if not setup_autostart(desired):
            return

        with state.lock:
            new_config = dict(state.config)
            new_config["auto_start"] = desired
            state.config = new_config

        if cfg.save_config(new_config):
            with state.lock:
                state.config = cfg.load_config()
        else:
            logger.error("Failed to save auto-start setting")

        try:
            icon.update_menu()
        except Exception:
            logger.debug("Tray menu refresh is not supported", exc_info=True)

    def autostart_checked(item):
        actual = is_autostart_enabled()
        with state.lock:
            state.config["auto_start"] = actual
        return actual

    menu = pystray.Menu(
        pystray.MenuItem("MultiWAN QoS Agent", None, enabled=False),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Live Dashboard", safe_callback("dashboard", on_dashboard), default=True),
        pystray.MenuItem("Game Rules", safe_callback("game rules", on_custom_games)),
        pystray.MenuItem("Settings", safe_callback("settings", on_settings)),
        pystray.MenuItem("Start with Windows", safe_callback("auto-start", on_autostart), checked=autostart_checked),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Quit", safe_callback("quit", on_quit)),
    )

    # Icon color update thread
    def update_icon(icon):
        while state.running:
            snap = state.get_snapshot()
            if snap["active_games"]:
                color = "green"
            elif snap["configured"]:
                color = "gray"
            else:
                color = "yellow"
            try:
                icon.icon = create_icon(color)
            except Exception:
                pass
            time.sleep(5)

    icon = pystray.Icon("MultiWAN QoS Agent", create_icon("gray"), "MultiWAN QoS Agent", menu)
    ui.set_icon(icon)
    threading.Thread(target=update_icon, args=(icon,), daemon=True).start()
    icon.run_detached()
    try:
        ui.mainloop()
    finally:
        with state.lock:
            state.running = False
        try:
            icon.stop()
        except Exception:
            logger.debug("Tray icon already stopped", exc_info=True)
        mon_thread.join(timeout=3)
        if mon_thread.is_alive():
            logger.warning("Monitor thread did not stop before shutdown cleanup")
        _shutdown_cleanup(state, "app shutdown")
        _release_single_instance_mutex()


if __name__ == "__main__":
    main()
