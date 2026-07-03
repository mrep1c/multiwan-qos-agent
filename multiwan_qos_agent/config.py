"""Configuration management for MultiWAN QoS Agent."""

import logging
import base64
import json
import os
import shutil

try:
    import win32crypt
    HAS_WIN32CRYPT = True
except ImportError:
    HAS_WIN32CRYPT = False

logger = logging.getLogger("multiwan_qos_agent.config")

APP_NAME = "MultiWAN QoS Agent"
LEGACY_APP_NAME = "Qo" + "Smate Agent"
DPAPI_DESCRIPTION = "MultiWAN QoS"

DSCP_CLASSES = [
    {"name": "EF", "value": 46, "token": "ef", "queue": "Realtime"},
    {"name": "CS5", "value": 40, "token": "cs5", "queue": "Realtime"},
    {"name": "CS6", "value": 48, "token": "cs6", "queue": "Realtime"},
    {"name": "CS7", "value": 56, "token": "cs7", "queue": "Realtime"},
    {"name": "CS4", "value": 32, "token": "cs4", "queue": "Video"},
    {"name": "AF41", "value": 34, "token": "af41", "queue": "Video"},
    {"name": "AF42", "value": 36, "token": "af42", "queue": "Video"},
    {"name": "CS1", "value": 8, "token": "cs1", "queue": "Bulk"},
    {"name": "CS0", "value": 0, "token": "cs0", "queue": "Default"},
]
DEFAULT_DSCP_VALUE = 46
SUPPORTED_DSCP_VALUES = {item["value"] for item in DSCP_CLASSES}

DEFAULT_CONFIG = {
    "router_ip": "",
    "api_key": "",
    "insecure_tls": False,
    "setup_complete": False,
    "heartbeat_interval": 30,  # seconds
    "dscp_value": DEFAULT_DSCP_VALUE,  # EF (Expedited Forwarding)
    "local_live_flow_policies": True,
    "auto_start": True,
    "log_level": "INFO",
}


def normalize_dscp_value(value):
    """Return a MultiWAN QoS-supported DSCP value, defaulting to EF."""
    try:
        value = int(value)
    except (TypeError, ValueError):
        return DEFAULT_DSCP_VALUE
    if value in SUPPORTED_DSCP_VALUES:
        return value
    return DEFAULT_DSCP_VALUE


def dscp_label(value):
    value = normalize_dscp_value(value)
    for item in DSCP_CLASSES:
        if item["value"] == value:
            return f"{item['name']} ({item['value']}) - {item['queue']}"
    return "EF (46) - Realtime"


def dscp_value_from_label(label):
    for item in DSCP_CLASSES:
        if label == dscp_label(item["value"]):
            return item["value"]
    return normalize_dscp_value(label)


def dscp_options():
    return [dscp_label(item["value"]) for item in DSCP_CLASSES]


def get_config_dir():
    """Get the agent directory used for config, logs, and custom game data."""
    appdata = os.environ.get("APPDATA", os.path.expanduser("~"))
    config_dir = os.path.join(appdata, APP_NAME)
    os.makedirs(config_dir, exist_ok=True)
    return config_dir


def get_legacy_config_dir():
    """Get the compatibility AppData directory for one-way reads."""
    appdata = os.environ.get("APPDATA", os.path.expanduser("~"))
    return os.path.join(appdata, LEGACY_APP_NAME)


def get_config_path():
    """Get the path to the main config file."""
    return os.path.join(get_config_dir(), "config.json")


def _encrypt_api_key(api_key):
    if not api_key or not HAS_WIN32CRYPT:
        return api_key
    if api_key.startswith("dpapi:"):
        return api_key
    try:
        encrypted = win32crypt.CryptProtectData(api_key.encode('utf-8'), DPAPI_DESCRIPTION)
        return "dpapi:" + base64.b64encode(encrypted).decode('utf-8')
    except Exception as e:
        logger.error("Failed to encrypt API key: %s", e)
        return api_key


def _decrypt_api_key(encrypted_key):
    if not encrypted_key:
        return encrypted_key
    if not encrypted_key.startswith("dpapi:"):
        return encrypted_key
    if not HAS_WIN32CRYPT:
        logger.warning("Cannot decrypt DPAPI API key because Windows DPAPI support is unavailable")
        return ""
    try:
        decoded = base64.b64decode(encrypted_key[6:])
        _, decrypted = win32crypt.CryptUnprotectData(decoded, None, None, None, 0)
        return decrypted.decode('utf-8')
    except Exception as e:
        logger.warning("Failed to decrypt DPAPI API key: %s", e)
        return ""


def get_user_games_path():
    """Get the path to the user's custom game list."""
    return os.path.join(get_config_dir(), "user_games.json")


def get_legacy_config_path():
    """Get the previous AppData config path."""
    return os.path.join(get_legacy_config_dir(), "config.json")


def get_legacy_user_games_path():
    """Get the previous AppData custom game list path."""
    return os.path.join(get_legacy_config_dir(), "user_games.json")


def _copy_legacy_file(legacy_path, new_path):
    if os.path.exists(new_path) or not os.path.exists(legacy_path):
        return

    try:
        os.makedirs(os.path.dirname(new_path), exist_ok=True)
        shutil.copy2(legacy_path, new_path)
        logger.info("Migrated legacy settings to %s", new_path)
    except OSError as e:
        logger.warning("Failed to migrate legacy settings from %s: %s", legacy_path, e)


def migrate_legacy_files():
    """Copy compatibility settings into the current AppData folder once."""
    _copy_legacy_file(get_legacy_config_path(), get_config_path())
    _copy_legacy_file(get_legacy_user_games_path(), get_user_games_path())


def _read_json_file(path):
    with open(path, "r") as f:
        return json.load(f)


def load_config():
    """Load config from disk, merging with defaults for missing keys."""
    migrate_legacy_files()
    config_path = get_config_path()
    config = dict(DEFAULT_CONFIG)

    if os.path.exists(config_path):
        try:
            saved = _read_json_file(config_path)
            legacy_https_without_tls_flag = (
                "insecure_tls" not in saved and
                str(saved.get("router_ip", "")).strip().startswith("https://")
            )
            if "api_key" in saved:
                saved["api_key"] = _decrypt_api_key(saved["api_key"])
            config.update(saved)
            if legacy_https_without_tls_flag:
                config["insecure_tls"] = True
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to load config, using defaults: %s", e)

    config["dscp_value"] = normalize_dscp_value(config.get("dscp_value"))
    config["local_live_flow_policies"] = bool(config.get("local_live_flow_policies", True))
    return config


def save_config(config):
    """Save config to disk."""
    config_path = get_config_path()
    
    config_to_save = dict(config)
    config_to_save["dscp_value"] = normalize_dscp_value(config_to_save.get("dscp_value"))
    config_to_save["local_live_flow_policies"] = bool(config_to_save.get("local_live_flow_policies", True))
    if "api_key" in config_to_save and config_to_save["api_key"]:
        config_to_save["api_key"] = _encrypt_api_key(config_to_save["api_key"])
        
    try:
        with open(config_path, "w") as f:
            json.dump(config_to_save, f, indent=2)
        logger.info("Config saved to %s", config_path)
        return True
    except OSError as e:
        logger.error("Failed to save config: %s", e)
        return False


def load_user_games():
    """Load user's custom game list."""
    migrate_legacy_files()
    path = get_user_games_path()

    if os.path.exists(path):
        try:
            return sanitize_user_games(_read_json_file(path))
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to load user games: %s", e)
    return []


def sanitize_user_games(games):
    """Return custom games without legacy fallback-port fields."""
    sanitized = []
    if not isinstance(games, list):
        return sanitized

    for game in games:
        if not isinstance(game, dict):
            continue
        executables = game.get("executables", [])
        if isinstance(executables, str):
            executables = [item.strip() for item in executables.split(",") if item.strip()]
        entry = {
            "name": game.get("name", "Custom"),
            "executables": list(executables),
            "proto": "udp",
        }
        sanitized.append(entry)

    return sanitized


def save_user_games(games):
    """Save user's custom game list."""
    path = get_user_games_path()
    sanitized = sanitize_user_games(games)
    try:
        with open(path, "w") as f:
            json.dump(sanitized, f, indent=2)
        logger.info("User games saved (%d entries)", len(sanitized))
        return True
    except OSError as e:
        logger.error("Failed to save user games: %s", e)
        return False


def is_configured(config):
    """Check if the agent has been configured with router IP and API key."""
    return (
        bool(config.get("setup_complete"))
        and bool(config.get("router_ip"))
        and bool(config.get("api_key"))
    )
