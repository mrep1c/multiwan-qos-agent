"""Regression checks with no live Windows, UI, credential or router operations."""
import ast
import ctypes
import json
import logging
import socket
import sys
import tempfile
import threading
import types
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True

def forbidden(*args, **kwargs):
    raise AssertionError("Unmocked external operation")

# Tests do not require GUI or network packages, and cannot use them accidentally.
for name in ("requests", "psutil", "pystray", "tkinter", "PIL", "win32crypt"):
    sys.modules[name] = types.ModuleType(name)
for name in ("ttk", "messagebox"):
    setattr(sys.modules["tkinter"], name, types.ModuleType(name))
sys.modules["tkinter"].TclError = type("TclError", (Exception,), {})
for name in ("Image", "ImageDraw", "ImageFont"):
    setattr(sys.modules["PIL"], name, types.ModuleType(name))
for name in ("NoSuchProcess", "AccessDenied", "ZombieProcess"):
    setattr(sys.modules["psutil"], name, type(name, (Exception,), {}))
sys.modules["psutil"].process_iter = forbidden
sys.modules["psutil"].Process = forbidden
sys.modules["requests"].RequestException = type("RequestException", (Exception,), {})
for name in ("ConnectionError", "Timeout"):
    setattr(sys.modules["requests"], name, type(name, (sys.modules["requests"].RequestException,), {}))
sys.modules["requests"].post = forbidden
sys.modules["win32crypt"].CryptProtectData = forbidden
sys.modules["win32crypt"].CryptUnprotectData = forbidden

from multiwan_qos_agent import app, config as cfg, flow_etw, monitor, qos, sync

GAME = {"name": "Test Game", "executables": ["game.exe"]}
DETECTED = {GAME["name"]: {"game_info": GAME, "exe_name": "game.exe",
    "exe_names": ["game.exe"], "pids": [102], "pid_exes": {102: "game.exe"}}}
CONNECTION = {"game": GAME["name"], "pid": 102, "proto": "udp", "remote_ip": "8.8.8.8",
    "remote_port": 27015, "local_port": 50000, "selected": True, "last_packet_age": 0}

class Response:
    def __init__(self, data=None, status=200, text=""):
        self.data, self.status_code, self.text = data, status, text
        self.multiwan_qos_url = "https://test.invalid/cgi-bin/multiwan-qos-agent"
    def json(self):
        if self.data is ...:
            raise ValueError("Not JSON")
        return self.data

class Clock:
    def __init__(self, value=100): self.value = value
    def monotonic(self): return self.value
    def strftime(self, pattern): return "test-time"
    def sleep(self, seconds): self.value += seconds

class FakeCollector:
    def ensure_running(self): return True
    def stop(self): return True
    def status(self): return {"available": True, "message": "mocked"}
    def consume_activity(self): return False
    def set_tracked_pids(self, pids): pass

class AgentTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.temporary = tempfile.TemporaryDirectory(prefix="agent-test-", dir=ROOT)
        self.directory = Path(self.temporary.name).resolve()
        self.assertTrue(self.directory.is_relative_to(ROOT))
        self.addCleanup(self.temporary.cleanup)
        self.stack.enter_context(patch.object(cfg, "get_config_dir", return_value=str(self.directory)))
        self.stack.enter_context(patch.object(cfg, "migrate_legacy_files"))
        self.stack.enter_context(patch.object(qos.subprocess, "run", side_effect=forbidden))
        self.stack.enter_context(patch.object(flow_etw, "_configure_etw_apis", side_effect=forbidden))
        self.stack.enter_context(patch.object(flow_etw, "_configure_ip_helper", side_effect=forbidden))
        previous_logging_level = logging.root.manager.disable
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, previous_logging_level)
        cfg.LOAD_WARNINGS.clear()
        cfg._invalid_files.clear()
        cfg.LAST_SAVE_ERROR = ""

    def state(self):
        config = {**cfg.DEFAULT_CONFIG, "router_ip": "router-a", "api_key": "test-key", "setup_complete": True}
        with patch.object(cfg, "load_config", return_value=config), patch.object(cfg, "load_user_games", return_value=[]), \
                patch.object(cfg, "load_game_rules", return_value={}), patch.object(monitor, "load_game_database", return_value=[GAME]):
            return app.AgentState()

    def extracted(self, name, globals_dict):
        tree = ast.parse((ROOT / "multiwan_qos_agent/app.py").read_text(encoding="utf-8"))
        function = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name)
        exec(compile(ast.Module(body=[function], type_ignores=[]), "ui-handler", "exec"), globals_dict)
        return globals_dict[name]

    def loop(self, cycles=3, on_cycle=None, update=None, policy=None):
        state, calls, clock = self.state(), [], Clock()
        count = 0
        def detect(_map):
            nonlocal count
            count += 1
            if count > cycles:
                raise AssertionError("Monitor did not stop")
            clock.value += 5
            if on_cycle: on_cycle(count, state, clock)
            return DETECTED
        def sleep(seconds):
            clock.value += seconds
            if count >= cycles: state.running = False
        clock.sleep = sleep
        def request(action, *args, **kwargs):
            calls.append((action, args[0], args[2]))
            if action == "update" and update: return update()
            return sync.SyncResult(True, "OK", rule_count=0 if action == "clear" else 2)
        def policies(*args):
            calls.append(("policy", clock.value))
            return policy() if policy else True
        with ExitStack() as stack:
            for obj, name, value in [
                (app, "time", clock), (flow_etw, "EtwFlowCollector", FakeCollector),
                (monitor, "find_running_games", detect),
                (monitor, "build_connection_report", lambda *a: ([dict(CONNECTION)], [])),
                (monitor, "get_local_ip", lambda *a: state.config.get("test_pc_ip", "192.168.1.2")),
                (qos, "sync_qos_policies", policies),
                (sync, "send_update", lambda *a, **k: request("update", *a, **k)),
                (sync, "send_clear", lambda *a, **k: request("clear", *a, **k)),
                (sync, "send_heartbeat", lambda *a, **k: request("heartbeat", *a, **k)),
            ]:
                stack.enter_context(patch.object(obj, name, value))
            app.monitor_loop(state)
        self.assertEqual(count, cycles)
        return calls, state

    def collector(self, clock):
        collector = flow_etw.EtwFlowCollector()
        collector.local_ips = {"192.168.1.2"}
        collector.set_tracked_pids([102])
        collector.owner_map = types.SimpleNamespace(refresh=lambda: None,
            pids_for_port=lambda port: {102} if port == 50000 else set())
        self.stack.enter_context(patch.object(flow_etw, "time", clock))
        return collector

    def packet(self, collector, size=200, remote="8.8.8.8", pid=102):
        collector.record(pid, 42, size, "192.168.1.2", 50000, remote, 27015)

    def test_all_executables_get_policies(self):
        game = {"name": "Multi Game", "executables": ["launcher.exe", "game.exe"]}
        processes = [types.SimpleNamespace(info={"pid": pid, "name": exe})
                     for pid, exe in ((101, "launcher.exe"), (102, "game.exe"))]
        with patch.object(monitor.psutil, "process_iter", return_value=processes):
            detected = monitor.find_running_games(monitor.get_all_game_executables([game], []))
        self.assertEqual({s["exe"] for s in app._build_policy_specs(detected, [])}, {"launcher.exe", "game.exe"})
        connection = {**CONNECTION, "game": "Multi Game"}
        specs = app._build_policy_specs(detected, [connection], local_tagging_mode=cfg.LOCAL_TAGGING_MODE_LIVE_FLOWS)
        self.assertEqual([s["exe"] for s in specs], ["game.exe"])

    def test_flow_report_retains_owner(self):
        collector = Mock(available=True)
        collector.select_for_pids.return_value = ([{**CONNECTION, "bytes_per_sec": 200, "idle": 0}], [])
        selected, _ = monitor.build_connection_report(DETECTED, collector)
        self.assertEqual(selected[0]["pid"], 102)

    def test_unknown_policy_state_fails_without_mutating(self):
        spec = qos.build_policy_specs("Test Game", "game.exe", None)[0]
        with patch.object(qos, "_run_powershell", return_value=(False, "query failed")), \
                patch.object(qos, "_create_policy") as create:
            self.assertFalse(qos.sync_qos_policies([spec]))
            create.assert_not_called()
            self.assertTrue(qos.cleanup_all_policies()["failed"])

    def test_missing_desired_policy_fails_postcondition(self):
        spec = qos.build_policy_specs("Test Game", "game.exe", None)[0]
        with patch.object(qos, "get_active_policies", return_value=[]), patch.object(qos, "_create_policy", return_value=True):
            self.assertFalse(qos.sync_qos_policies([spec]))

    def test_verified_policy_sync_and_periodic_fast_path(self):
        spec = qos.build_policy_specs("Test Game", "game.exe", None)[0]
        actual = {"name": spec["name"], "app": "game.exe", "protocol": "UDP", "dscp": 46}
        with patch.object(qos, "get_active_policies", side_effect=[[], [actual]]), \
                patch.object(qos, "_create_policy", return_value=True):
            self.assertTrue(qos.sync_qos_policies([spec]))
        with patch.object(qos, "get_active_policies", return_value=[actual]) as query, patch.object(qos, "_create_policy") as create:
            self.assertTrue(qos.sync_qos_policies([spec]))
            self.assertEqual(query.call_count, 1)
            create.assert_not_called()

    def test_corrupt_policy_query_is_not_an_empty_store(self):
        for output in ("not JSON", '[7]', '{}', '{"Name":"someone-else"}'):
            with self.subTest(output=output), patch.object(qos, "_run_powershell", return_value=(True, output)):
                with self.assertRaises(RuntimeError): qos.get_active_policies()

    def test_powershell_errors_terminate(self):
        with patch.object(qos.subprocess, "run", return_value=types.SimpleNamespace(returncode=0, stdout="", stderr="")) as run:
            qos._run_powershell("Get-NetQosPolicy | ConvertTo-Json")
            self.assertIn("$ErrorActionPreference = 'Stop'", run.call_args.args[0][-1])

    def test_bad_router_responses_fail_every_action(self):
        for data in (..., None, [], {}, {"message": "Welcome"}):
            with self.subTest(data=data), patch.object(sync, "_do_request", return_value=(Response(data, text="<html>login</html>"), "")):
                self.assertFalse(sync.send_update("router", "key", "192.168.1.2", [CONNECTION]).ok)
                self.assertFalse(sync.send_clear("router", "key", "192.168.1.2").ok)
                self.assertFalse(sync.send_disconnect("router", "key", "192.168.1.2").ok)
                self.assertFalse(sync.send_heartbeat("router", "key", "192.168.1.2").ok)
                self.assertFalse(sync.test_connection("router", "key")[0])

    def test_http_failure_cannot_be_overridden_by_json(self):
        response = Response({"status": 200, "message": "OK"}, status=401)
        self.assertEqual(sync._effective_status_code(response), 401)

    def test_legacy_and_verified_router_updates(self):
        bodies = [{"status": 200, "message": "OK: 2 rules applied"},
            {"status": 200, "message": "OK: 2 rules applied", "endpoint_version": 2, "action": "update",
             "verification_ok": True, "rules_expected": 2, "rule_count": 2, "agent_rule_count": 2, "dscp_rule_count": 2}]
        for body in bodies:
            with self.subTest(body=body), patch.object(sync, "_do_request", return_value=(Response(body), "")):
                self.assertTrue(sync.send_update("router", "key", "192.168.1.2", [CONNECTION]).ok)
        with patch.object(sync, "_do_request", return_value=(Response({**bodies[1], "dscp_rule_count": 0}), "")):
            self.assertFalse(sync.send_update("router", "key", "192.168.1.2", [CONNECTION]).ok)

    def test_wrong_action_and_incomplete_verification_fail(self):
        for data in ({"endpoint_version": 2, "action": "heartbeat", "message": "OK"},
                     {"endpoint_version": 2, "action": "update", "message": "OK"}):
            with patch.object(sync, "_do_request", return_value=(Response(data), "")):
                self.assertFalse(sync.send_update("router", "key", "192.168.1.2", [CONNECTION]).ok)

    def test_clear_requires_zero_reported_rules(self):
        with patch.object(sync, "_do_request", return_value=(Response({"status": 200, "message": "OK", "rule_count": 2}), "")):
            self.assertFalse(sync.send_clear("router", "key", "192.168.1.2").ok)

    def test_tls_verification_is_explicit_and_redirects_are_disabled(self):
        for insecure in (False, True):
            with patch.object(sync.requests, "post", return_value=Response({"status": 200, "message": "OK"})) as post:
                sync._do_request("https://test.invalid", {}, insecure_tls=insecure)
                self.assertEqual(post.call_args.kwargs["verify"], not insecure)
                self.assertFalse(post.call_args.kwargs["allow_redirects"])
        Path(cfg.get_config_path()).write_text('{"router_ip":"https://test.invalid"}', encoding="utf-8")
        self.assertFalse(cfg.load_config()["insecure_tls"])

    def test_atomic_saves_preserve_old_files_on_write_or_replace_failure(self):
        path = Path(cfg.get_config_path())
        old = '{"router_ip":"original"}'
        path.write_text(old, encoding="utf-8")
        def broken_dump(data, f, **kwargs):
            f.write('{"router_ip":')
            raise OSError("disk full")
        for target, replacement in (("dump", broken_dump), ("replace", Mock(side_effect=OSError("locked")))):
            obj = cfg.json if target == "dump" else cfg.os
            with self.subTest(target=target), patch.object(obj, target, replacement):
                self.assertFalse(cfg.save_config(dict(cfg.DEFAULT_CONFIG)))
            self.assertEqual(path.read_text(encoding="utf-8"), old)
            self.assertEqual(list(self.directory.glob("*.tmp")), [])

    def test_encryption_failures_preserve_existing_file(self):
        path = Path(cfg.get_config_path())
        path.write_text("old config", encoding="utf-8")
        config = {**cfg.DEFAULT_CONFIG, "api_key": "test-key"}
        for available in (False, True):
            with self.subTest(available=available), patch.object(cfg, "HAS_WIN32CRYPT", available), \
                    patch.object(cfg.win32crypt, "CryptProtectData", side_effect=OSError("DPAPI failed")):
                self.assertFalse(cfg.save_config(config))
                self.assertEqual(path.read_text(encoding="utf-8"), "old config")
                self.assertNotIn("test-key", cfg.LAST_SAVE_ERROR)

    def test_key_is_encrypted_before_successful_save(self):
        with patch.object(cfg.win32crypt, "CryptProtectData", return_value=b"protected"):
            self.assertTrue(cfg.save_config({**cfg.DEFAULT_CONFIG, "api_key": "test-key"}))
        text = Path(cfg.get_config_path()).read_text(encoding="utf-8")
        self.assertNotIn("test-key", text)
        self.assertTrue(json.loads(text)["api_key"].startswith("dpapi:"))

    def test_unreadable_key_is_not_overwritten_during_startup(self):
        path = Path(cfg.get_config_path())
        original = json.dumps({**cfg.DEFAULT_CONFIG, "api_key": "dpapi:cHJvdGVjdGVk"})
        path.write_text(original, encoding="utf-8")
        with patch.object(cfg.win32crypt, "CryptUnprotectData", side_effect=OSError("DPAPI failed")):
            config = cfg.load_config()
        self.assertEqual(config["api_key"], "")
        self.assertTrue(cfg.LOAD_WARNINGS)
        state = self.state()
        state.config = config
        state.startup_warnings = list(cfg.LOAD_WARNINGS)
        with patch.object(app, "is_autostart_enabled", return_value=False), patch.object(cfg, "save_config") as save:
            app.sync_autostart_config(state)
            save.assert_not_called()
        self.assertEqual(path.read_text(encoding="utf-8"), original)

    def test_invalid_config_schema_recovers_and_is_backed_up_on_repair(self):
        path = Path(cfg.get_config_path())
        path.write_text("[]", encoding="utf-8")
        self.assertEqual(cfg.load_config()["router_ip"], "")
        self.assertTrue(cfg.LOAD_WARNINGS)
        self.assertEqual(path.read_text(encoding="utf-8"), "[]")
        self.assertTrue(cfg.save_config(dict(cfg.DEFAULT_CONFIG)))
        backups = list(self.directory.glob("config.json.invalid-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(encoding="utf-8"), "[]")

    def test_config_field_types_are_safe(self):
        path = Path(cfg.get_config_path())
        path.write_text(json.dumps({"router_ip": [], "api_key": 12, "setup_complete": "false", "heartbeat_interval": None}), encoding="utf-8")
        config = cfg.load_config()
        self.assertFalse(cfg.is_configured(config))
        self.assertEqual(config["heartbeat_interval"], 30)
        self.assertTrue(cfg.LOAD_WARNINGS)

    def test_nonfinite_numeric_values_do_not_crash_parsers(self):
        path = Path(cfg.get_config_path())
        path.write_text('{"heartbeat_interval":1e999,"dscp_value":1e999}', encoding="utf-8")
        config = cfg.load_config()
        self.assertEqual(config["heartbeat_interval"], 30)
        self.assertEqual(config["dscp_value"], cfg.DEFAULT_DSCP_VALUE)
        for value in (float("inf"), float("nan"), True, 1.5):
            self.assertIsNone(sync._to_int(value))

    def test_invalid_builtin_schema_skips_bad_executables(self):
        data = {"games": [GAME, {"name": "Invalid", "executables": [None]}]}
        with patch.object(monitor.json, "load", return_value=data):
            self.assertEqual(monitor.load_game_database(), [GAME])
        self.assertTrue(cfg.LOAD_WARNINGS)

    def test_invalid_custom_entries_do_not_crash_or_replace_good_data(self):
        invalid = [{"name": "Bad", "executables": None}, {"name": "Bad", "executables": [7]}]
        self.assertEqual(cfg.sanitize_user_games(invalid), [])
        self.assertIsInstance(cfg.game_id(invalid[0]), str)
        path = Path(cfg.get_user_games_path())
        path.write_text(json.dumps(invalid), encoding="utf-8")
        self.assertEqual(cfg.load_user_games(), [])
        self.assertTrue(cfg.LOAD_WARNINGS)
        old = path.read_text(encoding="utf-8")
        self.assertFalse(cfg.save_user_games(invalid))
        self.assertEqual(path.read_text(encoding="utf-8"), old)

    def test_user_games_and_rules_use_atomic_writes(self):
        for save, path, data in ((cfg.save_user_games, cfg.get_user_games_path(), [GAME]),
                                 (cfg.save_game_rules, cfg.get_game_rules_path(), {"test": {"local_tagging": "disabled"}})):
            with self.subTest(path=path):
                Path(path).write_text("original", encoding="utf-8")
                with patch.object(cfg.os, "replace", side_effect=OSError("replace failed")):
                    self.assertFalse(save(data))
                self.assertEqual(Path(path).read_text(encoding="utf-8"), "original")

    def test_settings_commit_only_on_save_success(self):
        state = self.state()
        with patch.object(cfg, "save_config", return_value=False):
            self.assertFalse(state.save_config({"dscp_value": 40}))
        self.assertEqual(state.config["dscp_value"], 46)
        with patch.object(cfg, "save_config", return_value=True):
            self.assertTrue(state.save_config({"dscp_value": 40}))
            self.assertTrue(state.save_config({"router_ip": "router-b"}))
        self.assertEqual(state.config["dscp_value"], 40)

    def test_custom_ui_save_failure_keeps_state(self):
        state = self.state()
        for function, save, field, data in (("set_games", "save_user_games", "user_games", [GAME]),
                                           ("set_rules", "save_game_rules", "game_rules", {"test": {"local_tagging": "disabled"}})):
            before = getattr(state, field)
            with patch.object(cfg, save, return_value=False):
                handler = self.extracted(function, {"state": state, "cfg": cfg})
                self.assertFalse(handler(data))
            self.assertEqual(getattr(state, field), before)
            self.assertFalse(state.sync_requested)

    def test_custom_form_validates_names_and_normalizes_paths(self):
        values = {"cfg": cfg, "name_var": Mock(), "exe_var": Mock(), "game_entries": lambda: []}
        values["name_var"].get.return_value = "Tom Clancy's Game"
        values["exe_var"].get.return_value = r"C:\Games\game.exe"
        validate = self.extracted("validate_form", values)
        self.assertIsNone(validate()[0])
        values["name_var"].get.return_value = "Test Game"
        entry, error = validate()
        self.assertEqual(error, "")
        self.assertEqual(entry["executables"], ["game.exe"])
        self.assertTrue(qos.build_policy_specs(entry["name"], entry["executables"][0], None))

    def test_etw_exit_marks_unavailable_and_retries_with_backoff(self):
        clock = Clock()
        collector = self.collector(clock)
        collector.running = collector.available = True
        collector.trace_handle_type = ctypes.c_ulonglong
        collector.consumer_handle = 1
        collector.advapi = types.SimpleNamespace(ProcessTrace=lambda *a: 5)
        collector._process()
        self.assertFalse(collector.available)
        with patch.object(collector, "stop", return_value=True), patch.object(collector, "start", return_value=False) as start:
            clock.value = 104
            self.assertFalse(collector.ensure_running())
            start.assert_not_called()
            clock.value = 105
            self.assertFalse(collector.ensure_running())
            self.assertEqual(collector.next_start_at, 115)
            clock.value = 106
            collector.ensure_running()
            self.assertEqual(start.call_count, 1)

    def test_etw_successful_retry_recovers(self):
        clock = Clock()
        collector = self.collector(clock)
        def start():
            collector.available = collector.running = True
            collector.started_at = clock.value
            return True
        with patch.object(collector, "stop", return_value=True), patch.object(collector, "start", side_effect=start) as starting:
            self.assertTrue(collector.ensure_running())
            self.assertTrue(collector.ensure_running())
            self.assertEqual(starting.call_count, 1)

    def test_etw_retry_waits_for_old_consumer_to_stop(self):
        clock = Clock()
        collector = self.collector(clock)
        with patch.object(collector, "stop", return_value=False), patch.object(collector, "start") as start:
            self.assertFalse(collector.ensure_running())
            self.assertEqual(collector.next_start_at, 105)
            start.assert_not_called()

    def test_unexpected_clean_etw_exit_is_unavailable(self):
        clock = Clock()
        collector = self.collector(clock)
        collector.running = collector.available = True
        collector.trace_handle_type = ctypes.c_ulonglong
        collector.consumer_handle = 1
        collector.advapi = types.SimpleNamespace(ProcessTrace=lambda *a: 0)
        collector._process()
        self.assertFalse(collector.available)
        self.assertFalse(collector.running)
        self.assertEqual(collector.next_start_at, 105)

    def test_settings_save_failure_rolls_back_autostart(self):
        state = self.state()
        messages, setup, close = Mock(), Mock(return_value=True), Mock()
        fields = {"state": state, "cfg": cfg, "messagebox": messages, "root": Mock(),
                  "is_autostart_enabled": lambda: False, "setup_autostart": setup,
                  "close_settings": close, "status_var": Mock()}
        for name, value in (("ip_entry", "router-a"), ("key_entry", "test-key"), ("auto_var", True),
                            ("tls_var", False), ("tagging_enabled_var", True),
                            ("mode_var", cfg.local_tagging_mode_label(cfg.LOCAL_TAGGING_MODE_ALL_UDP))):
            fields[name] = Mock()
            fields[name].get.return_value = value
        # Both settings and dashboard use on_save; select the settings handler by scope.
        tree = ast.parse((ROOT / "multiwan_qos_agent/app.py").read_text(encoding="utf-8"))
        settings = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "show_settings")
        handler = next(n for n in ast.walk(settings) if isinstance(n, ast.FunctionDef) and n.name == "on_save")
        exec(compile(ast.Module(body=[handler], type_ignores=[]), "settings-handler", "exec"), fields)
        with patch.object(cfg, "save_config", return_value=False):
            fields["on_save"]()
        self.assertEqual(setup.call_args_list, [unittest.mock.call(True), unittest.mock.call(False)])
        messages.showerror.assert_called_once()
        messages.showinfo.assert_not_called()
        close.assert_not_called()

    def test_windows_does_not_claim_a_psutil_udp_fallback(self):
        with patch.object(monitor.os, "name", "nt"), patch.object(monitor.psutil, "Process") as process:
            self.assertEqual(monitor.get_process_connections([102]), [])
            process.assert_not_called()

    def test_low_bandwidth_active_flow_is_selected(self):
        clock = Clock(0)
        collector = self.collector(clock)
        for second in (0, 1, 3):
            clock.value = second
            self.packet(collector)
        selected, ignored = collector.select_for_pids([102])
        self.assertEqual(len(selected), 1)
        self.assertLess(selected[0]["bytes_per_sec"], 4094)
        self.assertEqual(ignored, [])

    def test_recent_rate_does_not_include_old_bursts(self):
        clock = Clock(0)
        collector = self.collector(clock)
        for second in (0, 1, 2):
            clock.value = second
            for _ in range(100): self.packet(collector, 1000)
        for second in (46, 47, 50):
            clock.value = second
            self.packet(collector, 200)
        selected, _ = collector.select_for_pids([102])
        self.assertEqual(len(selected), 1)
        self.assertAlmostEqual(selected[0]["bytes_per_sec"], 600 / 45)

    def test_recent_activity_admits_small_flow_beside_large_flow(self):
        clock = Clock(0)
        collector = self.collector(clock)
        for second in (0, 1, 3):
            clock.value = second
            self.packet(collector, 200)
            self.packet(collector, 1200, remote="1.1.1.1")
        selected, _ = collector.select_for_pids([102])
        self.assertEqual({f["remote_ip"] for f in selected}, {"8.8.8.8", "1.1.1.1"})

    def test_stale_flows_are_not_selected(self):
        clock = Clock(0)
        collector = self.collector(clock)
        for second in (0, 1, 3):
            clock.value = second
            self.packet(collector)
        clock.value = 20
        selected, ignored = collector.select_for_pids([102])
        self.assertEqual(selected, [])
        self.assertEqual(ignored[0]["ignored_reason"], "stale")

    def test_untracked_traffic_is_not_retained(self):
        clock = Clock()
        collector = self.collector(clock)
        collector.owner_map = types.SimpleNamespace(refresh=lambda: None,
            pids_for_port=lambda port: {777} if port == 50000 else set())
        self.packet(collector, pid=777)
        self.assertEqual(collector.flows, {})

    def test_idle_and_untracked_events_skip_property_decoding(self):
        collector = self.collector(Clock())
        collector.running = True
        event = flow_etw.EVENT_RECORD()
        event.EventHeader.EventDescriptor.Id = 42
        with patch.object(collector, "_property_raw", return_value=(777).to_bytes(4, "little")) as raw:
            collector._on_event(ctypes.pointer(event))
            self.assertEqual(raw.call_count, 1)
            collector.set_tracked_pids([])
            raw.reset_mock()
            collector._on_event(ctypes.pointer(event))
            raw.assert_not_called()

    def test_missing_payload_pid_uses_tracked_port_owner(self):
        collector = self.collector(Clock())
        self.packet(collector, pid=0)
        self.assertEqual({f["pid"] for f in collector.flows.values()}, {102})

    def test_flow_pruning_is_bounded_and_port_changes_use_index(self):
        clock = Clock()
        collector = self.collector(clock)
        class CountedDict(dict):
            scans = 0
            def items(self):
                self.scans += 1
                return super().items()
        collector.flows = CountedDict()
        for _ in range(1000): self.packet(collector)
        self.assertEqual(collector.flows.scans, 1)
        self.assertEqual(len(next(iter(collector.flows.values()))["samples"]), 1)

    def test_active_verification_failure_clears_then_republishes(self):
        replies = iter([sync.SyncResult(False, "router verification mismatch"), sync.SyncResult(True, "OK", rule_count=2)])
        calls, _ = self.loop(update=lambda: next(replies))
        self.assertEqual([c[0] for c in calls if c[0] != "policy"], ["update", "clear", "update"])

    def test_target_change_clears_old_target_and_updates_immediately(self):
        def change(count, state, clock):
            if count == 2: state.config["router_ip"] = "router-b"
        calls, _ = self.loop(on_cycle=change)
        self.assertIn(("clear", "router-a", "192.168.1.2"), calls)
        self.assertIn(("update", "router-b", "192.168.1.2"), calls)

    def test_pc_address_change_republishes_current_flows(self):
        def change(count, state, clock):
            if count == 2: state.config["test_pc_ip"] = "192.168.1.3"
        calls, _ = self.loop(on_cycle=change)
        self.assertIn(("update", "router-a", "192.168.1.3"), calls)

    def test_local_policy_audit_is_periodic_not_every_scan(self):
        def advance(count, state, clock):
            if count == 3: clock.value += 60
        calls, _ = self.loop(on_cycle=advance)
        self.assertEqual(sum(c[0] == "policy" for c in calls), 2)

    def test_failed_local_policy_verification_is_retried(self):
        replies = iter([False, True])
        calls, _ = self.loop(cycles=2, policy=lambda: next(replies))
        self.assertEqual(sum(c[0] == "policy" for c in calls), 2)

    def test_shutdown_uses_last_contacted_router_and_pc_address(self):
        state = self.state()
        state.router_target = ("router-old", "old-key", "192.168.1.9", True)
        state.config.update(router_ip="router-new", api_key="new-key")
        with patch.object(app, "_cleanup_windows_policies"), \
                patch.object(app, "_cleanup_router_rules", return_value=(True, "OK")) as cleanup:
            app._shutdown_cleanup(state, "test")
        config = cleanup.call_args.args[0]
        self.assertEqual((config["router_ip"], config["api_key"], config["insecure_tls"]),
                         ("router-old", "old-key", True))
        self.assertEqual(cleanup.call_args.kwargs["pc_ip"], "192.168.1.9")

    def test_shutdown_waits_for_rule_write_and_blocks_later_requests(self):
        state = self.state()
        blocked, release = threading.Event(), threading.Event()
        calls = []
        def slow_policy(*args):
            blocked.set()
            if not release.wait(2): raise AssertionError("Worker was not released")
            calls.append("policy-created")
            return True
        with ExitStack() as stack:
            for obj, name, value in [
                (flow_etw, "EtwFlowCollector", FakeCollector), (monitor, "find_running_games", lambda *a: DETECTED),
                (monitor, "build_connection_report", lambda *a: ([dict(CONNECTION)], [])),
                (qos, "sync_qos_policies", slow_policy),
                (app, "_cleanup_windows_policies", lambda *a: calls.append("cleanup-windows")),
                (app, "_cleanup_router_rules", lambda *a, **k: (calls.append("disconnect") or True, "OK")),
            ]:
                stack.enter_context(patch.object(obj, name, value))
            worker = threading.Thread(target=app.monitor_loop, args=(state,), daemon=True)
            cleanup = threading.Thread(target=app._shutdown_cleanup, args=(state, "test"), daemon=True)
            worker.start()
            self.assertTrue(blocked.wait(2))
            cleanup.start()
            for _ in range(1000):
                if not state.running: break
                threading.Event().wait(0.001)
            self.assertFalse(state.running)
            self.assertNotIn("cleanup-windows", calls)
            release.set()
            worker.join(2)
            cleanup.join(2)
            self.assertFalse(worker.is_alive())
            self.assertFalse(cleanup.is_alive())
            app._shutdown_cleanup(state, "again")
        self.assertEqual(calls, ["policy-created", "cleanup-windows", "disconnect"])
        request = Mock()
        self.assertFalse(app._sync_router(state, request, "router-a", "key", "192.168.1.2").ok)
        request.assert_not_called()

if __name__ == "__main__":
    unittest.main()
