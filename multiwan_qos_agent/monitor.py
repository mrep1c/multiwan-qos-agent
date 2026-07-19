"""
Process and network connection monitor.

Detects running game processes and captures their active UDP connections.
Router rules are created only for live flows with an exact remote IP and port.
"""

import json
import logging
import os
import socket
from urllib.parse import urlparse

import psutil

logger = logging.getLogger("multiwan_qos_agent.monitor")


def load_game_database():
    """Load the built-in game database."""
    games = []
    db_path = os.path.join(os.path.dirname(__file__), "games_db.json")

    if os.path.exists(db_path):
        try:
            with open(db_path, "r") as f:
                data = json.load(f)
                games.extend(data.get("games", []))
        except (json.JSONDecodeError, OSError) as e:
            logger.error("Failed to load built-in game database: %s", e)

    return games


def get_all_game_executables(game_db, user_games):
    """Build a lookup dict: lowercase exe name -> game info."""
    exe_map = {}
    for game in game_db + user_games:
        for exe in game.get("executables", []):
            exe_map[exe.lower()] = game
    return exe_map


def find_running_games(exe_map):
    """Scan running processes and return detected games by game name."""
    detected = {}

    for proc in psutil.process_iter(["pid", "name"]):
        try:
            proc_name = proc.info["name"]
            if not proc_name:
                continue

            game_info = exe_map.get(proc_name.lower())
            if not game_info:
                continue

            game_name = game_info["name"]
            if game_name not in detected:
                detected[game_name] = {
                    "pids": [],
                    "game_info": game_info,
                    "exe_name": proc_name,
                }
            detected[game_name]["pids"].append(proc.info["pid"])
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return detected


def _router_host(router_ip):
    if not router_ip:
        return None

    value = router_ip.strip().rstrip("/")
    if not value:
        return None

    if "://" not in value:
        value = "http://" + value

    parsed = urlparse(value)
    return parsed.hostname


def _local_ip_for_target(host, port):
    if not host:
        return None

    infos = []
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)
    except socket.gaierror:
        try:
            socket.inet_aton(host)
            infos = [(socket.AF_INET, socket.SOCK_DGRAM, 0, "", (host, port))]
        except OSError:
            return None

    for family, socktype, proto, _canon, sockaddr in infos:
        try:
            s = socket.socket(family, socktype, proto)
            s.settimeout(0.2)
            s.connect(sockaddr)
            local_ip = s.getsockname()[0]
            s.close()
            if local_ip and not local_ip.startswith("127."):
                return local_ip
        except (socket.error, OSError):
            continue

    return None


def get_local_ip(router_ip=None):
    """Get the local LAN IP address this PC uses to reach the router."""
    router_host = _router_host(router_ip)
    if router_host:
        local_ip = _local_ip_for_target(router_host, 80)
        if local_ip:
            return local_ip

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.1)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except (socket.error, OSError):
        return None


def get_process_connections(pids):
    """Get active UDP network connections for given process IDs."""
    connections = []
    seen = set()

    for pid in pids:
        try:
            proc = psutil.Process(pid)
            for conn in proc.net_connections(kind="inet"):
                if conn.type != socket.SOCK_DGRAM:
                    continue
                if not (conn.raddr and conn.raddr.ip and conn.raddr.port):
                    continue

                remote_ip = conn.raddr.ip
                if remote_ip.startswith("127.") or remote_ip == "0.0.0.0":
                    continue

                local_port = conn.laddr.port if conn.laddr else None
                key = ("udp", remote_ip, conn.raddr.port, local_port)
                if key in seen:
                    continue
                seen.add(key)

                connections.append({
                    "proto": "udp",
                    "remote_ip": remote_ip,
                    "remote_port": conn.raddr.port,
                    "local_port": local_port,
                    "source": "psutil live",
                    "selected": True,
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return connections


def _etw_connection_entry(game_name, flow):
    return {
        "game": game_name,
        "proto": "udp",
        "remote_ip": flow["remote_ip"],
        "remote_port": flow["remote_port"],
        "local_port": flow.get("local_port"),
        "source": flow.get("source", "ETW flow telemetry"),
        "throughput_bps": int(flow.get("bytes_per_sec", 0)),
        "last_packet_age": max(0.0, float(flow.get("idle", 0.0))),
        "selected": True,
    }


def _ignored_flow_entry(game_name, flow):
    return {
        "game": game_name,
        "proto": "udp",
        "remote_ip": flow.get("remote_ip", ""),
        "remote_port": flow.get("remote_port", ""),
        "local_port": flow.get("local_port"),
        "source": "ETW flow ignored",
        "throughput_bps": int(flow.get("bytes_per_sec", 0)),
        "last_packet_age": max(0.0, float(flow.get("idle", 0.0))),
        "selected": False,
        "ignored_reason": flow.get("ignored_reason", "ignored"),
    }


def build_connection_report(detected_games, flow_collector=None):
    """Build UDP-only connection report for the router API."""
    report = []
    candidates = []

    for game_name, game_data in detected_games.items():
        pids = game_data["pids"]
        etw_selected = []
        etw_ignored = []

        if flow_collector and getattr(flow_collector, "available", False):
            etw_selected, etw_ignored = flow_collector.select_for_pids(pids)
            for flow in etw_ignored:
                candidates.append(_ignored_flow_entry(game_name, flow))

        if etw_selected:
            logger.info(
                "Game '%s': selected %d ETW UDP telemetry flow(s)",
                game_name,
                len(etw_selected),
            )
            for flow in etw_selected:
                entry = _etw_connection_entry(game_name, flow)
                report.append(entry)
                candidates.append(entry)
            continue

        live_conns = get_process_connections(pids)

        if etw_ignored:
            stale_flow_keys = {
                (
                    str(flow.get("remote_ip") or ""),
                    int(flow.get("remote_port") or 0),
                    int(flow.get("local_port") or 0),
                )
                for flow in etw_ignored
                if flow.get("ignored_reason") == "stale"
            }
            live_conns = [
                conn for conn in live_conns
                if (
                    str(conn.get("remote_ip") or ""),
                    int(conn.get("remote_port") or 0),
                    int(conn.get("local_port") or 0),
                ) not in stale_flow_keys
            ]

        if live_conns:
            logger.info(
                "Game '%s': found %d live UDP connections",
                game_name,
                len(live_conns),
            )
            for conn in live_conns:
                report.append({
                    "game": game_name,
                    "proto": "udp",
                    "remote_ip": conn["remote_ip"],
                    "remote_port": conn["remote_port"],
                    "local_port": conn.get("local_port"),
                    "source": conn.get("source", "psutil live"),
                    "selected": True,
                })
            continue

        logger.debug("Game '%s': waiting for live UDP connections", game_name)

    return report, candidates


def get_running_processes():
    """Get a list of all running processes for UI selection."""
    processes = []
    seen_names = set()

    for proc in psutil.process_iter(["pid", "name", "exe"]):
        try:
            name = proc.info["name"]
            if not name or name.lower() in seen_names:
                continue

            seen_names.add(name.lower())
            processes.append({
                "pid": proc.info["pid"],
                "name": name,
                "path": proc.info.get("exe", ""),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    processes.sort(key=lambda p: p["name"].lower())
    return processes
