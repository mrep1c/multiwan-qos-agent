"""Configuration management for MultiWAN QoS Agent."""

import logging
import base64
import hashlib
import json
import ntpath
import os
import re
import shutil
import tempfile
import threading
import uuid

try:
    import win32crypt
    HAS_WIN32CRYPT = True
except ImportError:
    win32crypt = None
    HAS_WIN32CRYPT = False

logger = logging.getLogger("multiwan_qos_agent.config")

APP_NAME = "MultiWAN QoS Agent"
LEGACY_APP_NAME = "Qo" + "Smate Agent"
DPAPI_DESCRIPTION = "MultiWAN QoS"
LOAD_WARNINGS = []
LAST_SAVE_ERROR = ""
_invalid_files = set()
_file_lock = threading.RLock()

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
LOCAL_TAGGING_MODE_LIVE_FLOWS = "live_flows"
LOCAL_TAGGING_MODE_ALL_UDP = "all_udp"
LOCAL_TAGGING_MODES = {LOCAL_TAGGING_MODE_LIVE_FLOWS, LOCAL_TAGGING_MODE_ALL_UDP}
LOCAL_TAGGING_MODE_MIGRATION_VERSION = 1
LOCAL_TAGGING_RULE_GLOBAL = "global"
LOCAL_TAGGING_RULE_ENABLED = "enabled"
LOCAL_TAGGING_RULE_DISABLED = "disabled"
LOCAL_TAGGING_RULE_PROGRAM_DISABLED = "program_disabled"
LOCAL_TAGGING_RULES = {
    LOCAL_TAGGING_RULE_GLOBAL,
    LOCAL_TAGGING_RULE_ENABLED,
    LOCAL_TAGGING_RULE_DISABLED,
    LOCAL_TAGGING_RULE_PROGRAM_DISABLED,
}

DEFAULT_CONFIG = {
    "router_ip": "",
    "api_key": "",
    "insecure_tls": False,
    "setup_complete": False,
    "heartbeat_interval": 30,  # seconds
    "dscp_value": DEFAULT_DSCP_VALUE,  # EF (Expedited Forwarding)
    "local_tagging_enabled": True,
    "local_tagging_mode": LOCAL_TAGGING_MODE_ALL_UDP,
    "local_tagging_mode_migration": LOCAL_TAGGING_MODE_MIGRATION_VERSION,
    "auto_start": True,
    "log_level": "INFO",
}


def normalize_dscp_value(value):
    """Return a MultiWAN QoS-supported DSCP value, defaulting to EF."""
    try:
        value = int(value)
    except (TypeError, ValueError, OverflowError):
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


def normalize_local_tagging_mode(value):
    if isinstance(value, bool):
        return LOCAL_TAGGING_MODE_LIVE_FLOWS if value else LOCAL_TAGGING_MODE_ALL_UDP
    value = str(value or "").strip().lower()
    if value in LOCAL_TAGGING_MODES:
        return value
    return LOCAL_TAGGING_MODE_ALL_UDP


def local_tagging_mode_label(value):
    value = normalize_local_tagging_mode(value)
    if value == LOCAL_TAGGING_MODE_ALL_UDP:
        return "All UDP from detected game executable"
    return "Selected live flows only"


def local_tagging_mode_from_label(label):
    for value in (LOCAL_TAGGING_MODE_ALL_UDP, LOCAL_TAGGING_MODE_LIVE_FLOWS):
        if label == local_tagging_mode_label(value):
            return value
    return normalize_local_tagging_mode(label)


def local_tagging_mode_options():
    return [
        local_tagging_mode_label(LOCAL_TAGGING_MODE_ALL_UDP),
        local_tagging_mode_label(LOCAL_TAGGING_MODE_LIVE_FLOWS),
    ]


def normalize_local_tagging_rule(value):
    value = str(value or "").strip().lower()
    if value in LOCAL_TAGGING_RULES:
        return value
    return LOCAL_TAGGING_RULE_GLOBAL


def local_tagging_rule_label(value):
    value = normalize_local_tagging_rule(value)
    if value == LOCAL_TAGGING_RULE_ENABLED:
        return "Enable local tagging"
    if value == LOCAL_TAGGING_RULE_DISABLED:
        return "Disable local tagging"
    if value == LOCAL_TAGGING_RULE_PROGRAM_DISABLED:
        return "Disable program (local + router)"
    return "Use global setting"


def local_tagging_rule_from_label(label):
    for value in (
        LOCAL_TAGGING_RULE_GLOBAL,
        LOCAL_TAGGING_RULE_ENABLED,
        LOCAL_TAGGING_RULE_DISABLED,
        LOCAL_TAGGING_RULE_PROGRAM_DISABLED,
    ):
        if label == local_tagging_rule_label(value):
            return value
    return normalize_local_tagging_rule(label)


def local_tagging_rule_options():
    return [
        local_tagging_rule_label(LOCAL_TAGGING_RULE_GLOBAL),
        local_tagging_rule_label(LOCAL_TAGGING_RULE_ENABLED),
        local_tagging_rule_label(LOCAL_TAGGING_RULE_DISABLED),
        local_tagging_rule_label(LOCAL_TAGGING_RULE_PROGRAM_DISABLED),
    ]


def _slug(value):
    value = re.sub(r"[^a-z0-9]+", "_", str(value or "").lower()).strip("_")
    return value or "game"


def game_id(game, source="game"):
    explicit = game.get("id", "") if isinstance(game, dict) else ""
    explicit = explicit.strip().lower() if isinstance(explicit, str) else ""
    if explicit:
        return explicit
    if not isinstance(game, dict):
        game = {}
    executables = game.get("executables", [])
    if isinstance(executables, str):
        executables = [executables]
    if not isinstance(executables, list):
        executables = []
    seed_items = [item.strip().lower() for item in executables if isinstance(item, str) and item.strip()]
    seed = "|".join(sorted(seed_items)) or str(game.get("name", "game")).strip().lower()
    digest = hashlib.sha1(seed.encode("utf-8")).hexdigest()[:10]
    return f"{_slug(source)}_{digest}"


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
    if not api_key:
        return api_key
    if not HAS_WIN32CRYPT:
        raise ValueError("Windows DPAPI support is unavailable; the API key was not saved")
    try:
        encrypted = win32crypt.CryptProtectData(api_key.encode('utf-8'), DPAPI_DESCRIPTION)
        return "dpapi:" + base64.b64encode(encrypted).decode('utf-8')
    except Exception as e:
        raise ValueError("API key encryption failed; the API key was not saved") from e


def _decrypt_api_key(encrypted_key):
    if not isinstance(encrypted_key, str):
        raise ValueError("API key must be a string")
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


def get_game_rules_path():
    """Get the path to per-game local tagging overrides."""
    return os.path.join(get_config_dir(), "game_rules.json")


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


def _read_json_file(path, expected_type=None):
    with _file_lock, open(path, "r", encoding="utf-8-sig") as f:
        data = json.load(f)
    if expected_type is not None and not isinstance(data, expected_type):
        raise ValueError(f"Expected a JSON {expected_type.__name__}")
    return data


def _load_warning(path, error):
    message = f"{os.path.basename(path)}: {error}"
    with _file_lock:
        _invalid_files.add(path)
        if message not in LOAD_WARNINGS:
            LOAD_WARNINGS.append(message)
    logger.warning("Settings could not be fully loaded: %s", message)


def _save_error(error):
    global LAST_SAVE_ERROR
    LAST_SAVE_ERROR = str(error)
    logger.error("Settings were not saved: %s", error)
    return False


def _write_json_file(path, data):
    """Replace only complete files; retain malformed originals before repair."""
    global LAST_SAVE_ERROR
    temporary = None
    with _file_lock:
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=os.path.dirname(path),
                                             prefix=os.path.basename(path) + ".", suffix=".tmp", delete=False) as f:
                temporary = f.name
                json.dump(data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            if path in _invalid_files and os.path.exists(path):
                backup = path + ".invalid-" + uuid.uuid4().hex[:8]
                shutil.copy2(path, backup)
                logger.warning("Preserved malformed settings in %s", backup)
            os.replace(temporary, path)
            temporary = None
            _invalid_files.discard(path)
            LAST_SAVE_ERROR = ""
            return True
        except (OSError, ValueError, TypeError) as e:
            return _save_error(e)
        finally:
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    logger.warning("Could not remove temporary settings file %s", temporary)


def valid_game_name(name):
    return isinstance(name, str) and bool(re.fullmatch(r"[A-Za-z0-9 ._:\-]{1,64}", name))


def normalize_executable_name(value):
    if not isinstance(value, str):
        return None
    value = ntpath.basename(value.strip().strip('"'))
    return value if re.fullmatch(r"[\w.\- ]+\.exe", value, re.IGNORECASE) else None


def load_config():
    """Load config from disk, merging with defaults for missing keys."""
    migrate_legacy_files()
    config_path = get_config_path()
    config = dict(DEFAULT_CONFIG)
    loaded_saved_config = False
    saved_has_local_tagging_mode = False
    saved_has_local_tagging_mode_migration = False

    if os.path.exists(config_path):
        try:
            saved = _read_json_file(config_path, dict)
            for field in ("router_ip", "api_key", "log_level"):
                if field in saved and not isinstance(saved[field], str):
                    _load_warning(config_path, f"{field} must be a string")
                    saved[field] = DEFAULT_CONFIG[field]
            for field in ("insecure_tls", "setup_complete", "local_tagging_enabled", "auto_start"):
                if field in saved and not isinstance(saved[field], bool):
                    _load_warning(config_path, f"{field} must be a boolean")
                    saved[field] = DEFAULT_CONFIG[field]
            loaded_saved_config = True
            saved_has_local_tagging_mode = "local_tagging_mode" in saved
            saved_has_local_tagging_mode_migration = "local_tagging_mode_migration" in saved
            if "api_key" in saved:
                encrypted_key = saved["api_key"]
                saved["api_key"] = _decrypt_api_key(encrypted_key)
                if encrypted_key.startswith("dpapi:") and not saved["api_key"]:
                    _load_warning(config_path, "API key could not be decrypted; re-enter it in Settings")
            config.update(saved)
        except (ValueError, UnicodeError, OSError) as e:
            _load_warning(config_path, e)

    legacy_live_flow_mode = config.get("local_live_flow_policies")
    config["dscp_value"] = normalize_dscp_value(config.get("dscp_value"))
    config["local_tagging_enabled"] = bool(config.get("local_tagging_enabled", True))
    if not saved_has_local_tagging_mode and legacy_live_flow_mode is not None:
        config["local_tagging_mode"] = normalize_local_tagging_mode(bool(legacy_live_flow_mode))
    config["local_tagging_mode"] = normalize_local_tagging_mode(config.get("local_tagging_mode"))
    try:
        config["heartbeat_interval"] = max(1, int(config.get("heartbeat_interval", 30)))
    except (TypeError, ValueError, OverflowError):
        _load_warning(config_path, "heartbeat_interval must be a number")
        config["heartbeat_interval"] = 30
    if loaded_saved_config and not saved_has_local_tagging_mode_migration:
        if config["local_tagging_mode"] == LOCAL_TAGGING_MODE_LIVE_FLOWS:
            logger.info("Migrating local Windows DSCP tagging default to all-UDP mode")
            config["local_tagging_mode"] = LOCAL_TAGGING_MODE_ALL_UDP
        config["local_tagging_mode_migration"] = LOCAL_TAGGING_MODE_MIGRATION_VERSION
    return config


def save_config(config):
    """Save config to disk."""
    try:
        config_to_save = dict(config)
        config_to_save["dscp_value"] = normalize_dscp_value(config_to_save.get("dscp_value"))
        config_to_save["local_tagging_enabled"] = bool(config_to_save.get("local_tagging_enabled", True))
        config_to_save["local_tagging_mode"] = normalize_local_tagging_mode(config_to_save.get("local_tagging_mode"))
        config_to_save["local_tagging_mode_migration"] = LOCAL_TAGGING_MODE_MIGRATION_VERSION
        config_to_save.pop("local_live_flow_policies", None)
        if not isinstance(config_to_save.get("api_key", ""), str):
            raise ValueError("API key must be a string")
        if config_to_save.get("api_key"):
            config_to_save["api_key"] = _encrypt_api_key(config_to_save["api_key"])
        return _write_json_file(get_config_path(), config_to_save)
    except (OSError, ValueError, TypeError) as e:
        return _save_error(e)


def load_user_games():
    """Load user's custom game list."""
    migrate_legacy_files()
    path = get_user_games_path()

    if os.path.exists(path):
        try:
            games = _read_json_file(path, list)
            sanitized = sanitize_user_games(games)
            if len(games) != len(sanitized):
                _load_warning(path, "Invalid custom game entries were skipped")
            return sanitized
        except (ValueError, UnicodeError, OSError) as e:
            _load_warning(path, e)
    return []


def sanitize_user_games(games):
    """Return custom games without legacy fallback-port or rule fields."""
    sanitized = []
    if not isinstance(games, list):
        return sanitized

    for game in games:
        if not isinstance(game, dict):
            continue
        executables = game.get("executables", [])
        if isinstance(executables, str):
            executables = [item.strip() for item in executables.split(",") if item.strip()]
        if not isinstance(executables, list) or not executables:
            continue
        executables = [normalize_executable_name(item) for item in executables]
        if not all(executables) or not valid_game_name(game.get("name")):
            continue
        entry = {
            "id": game_id(game, "custom"),
            "name": game.get("name", "Custom"),
            "executables": list(executables),
            "proto": "udp",
        }
        sanitized.append(entry)

    return sanitized


def sanitize_game_rules(rules):
    """Return per-game rule overrides keyed by stable game id."""
    sanitized = {}
    if not isinstance(rules, dict):
        return sanitized

    for raw_game_id, raw_rule in rules.items():
        game_key = str(raw_game_id or "").strip().lower()
        if not game_key:
            continue
        if isinstance(raw_rule, dict):
            local_tagging = raw_rule.get("local_tagging", LOCAL_TAGGING_RULE_GLOBAL)
        else:
            local_tagging = raw_rule
        local_tagging = normalize_local_tagging_rule(local_tagging)
        if local_tagging == LOCAL_TAGGING_RULE_GLOBAL:
            continue
        sanitized[game_key] = {"local_tagging": local_tagging}

    return sanitized


def load_game_rules():
    """Load per-game local tagging rule overrides."""
    path = get_game_rules_path()
    if os.path.exists(path):
        try:
            return sanitize_game_rules(_read_json_file(path, dict))
        except (ValueError, UnicodeError, OSError) as e:
            _load_warning(path, e)
    return {}


def save_game_rules(rules):
    """Save per-game local tagging rule overrides."""
    try:
        if not isinstance(rules, dict):
            raise ValueError("Game rules must be an object")
        return _write_json_file(get_game_rules_path(), sanitize_game_rules(rules))
    except (OSError, ValueError, TypeError) as e:
        return _save_error(e)


def save_user_games(games):
    """Save user's custom game list."""
    try:
        sanitized = sanitize_user_games(games)
        if not isinstance(games, list) or len(sanitized) != len(games):
            raise ValueError("Custom games contain invalid names or executables")
        return _write_json_file(get_user_games_path(), sanitized)
    except (OSError, ValueError, TypeError) as e:
        return _save_error(e)


def is_configured(config):
    """Check if the agent has been configured with router IP and API key."""
    return (
        bool(config.get("setup_complete"))
        and bool(config.get("router_ip"))
        and bool(config.get("api_key"))
    )
