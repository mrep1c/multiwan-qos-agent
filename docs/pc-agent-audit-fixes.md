# PC agent audit resolution

All 16 findings have source fixes and regression coverage. Local verification on
2026-10-10: 47 standard-library tests passed with native Windows, HTTP, credential
and UI calls mocked. These results verify application logic, not live packet
marking or hardware performance. No deployment or release was performed.

| Audit # | Fix | Regression coverage in `tests/test_agent.py` |
| --- | --- | --- |
| 1 | Windows policy writes and router requests share a shutdown boundary. Cleanup waits for accepted writes; new writes are rejected after stopping starts. | `test_shutdown_waits_for_rule_write_and_blocks_later_requests` |
| 2 | Detection retains all executables and PID ownership. All-UDP policies cover each executable; exact-flow policies use the owning executable. | `test_all_executables_get_policies`, `test_flow_report_retains_owner` |
| 3 | Policy queries distinguish failure from an empty store. A successful sync requires matching names, conditions and DSCP; PowerShell errors terminate. | `test_unknown_policy_state_fails_without_mutating`, `test_missing_desired_policy_fails_postcondition`, `test_corrupt_policy_query_is_not_an_empty_store`, `test_powershell_errors_terminate` |
| 4 | Router replies require recognized JSON object responses. HTTP failures, redirects, wrong actions, invalid JSON and incomplete version-2 verification cannot count as success. | `test_bad_router_responses_fail_every_action`, `test_http_failure_cannot_be_overridden_by_json`, `test_legacy_and_verified_router_updates`, `test_wrong_action_and_incomplete_verification_fail` |
| 5 | Certificate verification stays enabled unless explicitly disabled. HTTPS entry and migration no longer silently opt out. | `test_tls_verification_is_explicit_and_redirects_are_disabled` |
| 6 | All JSON saves use complete sibling temporary files and atomic replacement. UI commits memory only after a successful save and reports partial custom-game/override saves. Failed settings saves restore changed autostart state where possible. | `test_atomic_saves_preserve_old_files_on_write_or_replace_failure`, `test_user_games_and_rules_use_atomic_writes`, `test_settings_commit_only_on_save_success`, `test_custom_ui_save_failure_keeps_state`, `test_settings_save_failure_rolls_back_autostart` |
| 7 | DPAPI is required to save nonempty credentials. Failure preserves the previous config and reports an error. Unreadable encrypted keys generate startup warnings and prevent automatic overwrite. | `test_encryption_failures_preserve_existing_file`, `test_key_is_encrypted_before_successful_save`, `test_unreadable_key_is_not_overwritten_during_startup` |
| 8 | Custom labels meet router constraints, duplicate names are rejected, and executable paths become validated basenames. | `test_custom_form_validates_names_and_normalizes_paths`, `test_invalid_custom_entries_do_not_crash_or_replace_good_data` |
| 9 | Unexpected ETW consumer exits mark telemetry unavailable. Automatic retries use bounded backoff and wait for the old consumer to stop. Windows no longer claims a psutil remote-UDP fallback. | `test_etw_exit_marks_unavailable_and_retries_with_backoff`, `test_etw_successful_retry_recovers`, `test_etw_retry_waits_for_old_consumer_to_stop`, `test_unexpected_clean_etw_exit_is_unavailable`, `test_windows_does_not_claim_a_psutil_udp_fallback` |
| 10 | Per-second buckets measure recent traffic within 45 seconds. At the user's request, bandwidth ranking and the original 4,094 bytes/second minimum and 50% largest-flow cutoff are restored. Three-packet/three-second warmup, staleness checks and the three-flow cap remain. | `test_low_bandwidth_active_flow_is_ignored_by_default`, `test_recent_rate_does_not_include_old_bursts`, `test_default_selection_filters_auxiliary_flows`, `test_default_selection_ranks_bandwidth_before_packet_rate`, `test_stale_flows_are_not_selected` |
| 11 | A pending verification-recovery clear is serviced with active flows, then current flows are republished. | `test_active_verification_failure_clears_then_republishes` |
| 12 | Router address, credentials, TLS choice and PC address invalidate cached success. Address changes attempt cleanup at the previous destination before publishing current flows. Shutdown remembers the last contacted destination. | `test_target_change_clears_old_target_and_updates_immediately`, `test_pc_address_change_republishes_current_flows`, `test_shutdown_uses_last_contacted_router_and_pc_address` |
| 13 | Actual Windows policies are checked every 60 seconds and repaired if missing or changed. A verified unchanged set needs one query; failed verification retries. | `test_local_policy_audit_is_periodic_not_every_scan`, `test_verified_policy_sync_and_periodic_fast_path`, `test_failed_local_policy_verification_is_retried` |
| 14 | JSON roots and required fields are validated before use. Invalid entries and nonfinite numbers recover safely; malformed files stay intact and are backed up before repair. | `test_invalid_config_schema_recovers_and_is_backed_up_on_repair`, `test_config_field_types_are_safe`, `test_nonfinite_numeric_values_do_not_crash_parsers`, `test_invalid_builtin_schema_skips_bad_executables` |
| 15 | Added a standard-library regression suite and a Windows build CI gate before packaging. | `python -m unittest discover -s tests -v`; `.github/workflows/build-windows.yml` |
| 16 | Idle/unrelated events skip decoding early; only tracked process flows are retained, with port-owner fallback for missing payload PIDs. Endpoint changes use an index, and full pruning runs at most once per second. Recent-flow snapshots are copied under the collector lock. | `test_untracked_traffic_is_not_retained`, `test_idle_and_untracked_events_skip_property_decoding`, `test_missing_payload_pid_uses_tracked_port_owner`, `test_flow_pruning_is_bounded_and_port_changes_use_index` |

## Live checks still required

- Run the packaged app on an administrator Windows account. Confirm startup,
  settings/game-editor errors, tray exit and Task Scheduler rollback behavior.
- Confirm ETW PID attribution and corrected port decoding on real game traffic.
  Interrupt telemetry and confirm recovery.
- Capture packets to verify DSCP marking for multiple executables and exact
  flows. Remove a managed policy during a game and confirm repair after the
  periodic check; exercise actual native query failures and slow exit cleanup.
- Switch router/PC address during active traffic, induce router verification
  failure, and confirm clear then republish. Old destinations that cannot be
  reached still depend on their router expiry mechanism.
- Measure flow selection with real games and heavy unrelated UDP traffic. CPU
  savings, WAN latency and Adaptive-controller stability remain unmeasured.

Each JSON file is replaced atomically; custom definitions and overrides remain
two separate files. A successful first save with a failed second save is reported
as partial. Forced process termination and unavailable native/router cleanup can
still leave rules until another cleanup or router expiry. Live multi-user and
multi-PC concurrency, dependency vulnerability scans and EXE packaging were not
tested locally.

## Flow-detection follow-up

The v1.0.11 Valorant log showed destination ports 35945 and 30236 and repeated
policy recreation. Two bugs were reproduced and fixed:

- ETW network ports were read as little-endian. They now use network byte order,
  consistent with Microsoft's UDP trace decoder. Regression cases reproduce
  27020 becoming 35945 and 7286 becoming 30236 before the fix. Raw IPv4 and IPv6
  send/receive events now preserve the same remote endpoint and local port
  through the collector, connection report and exact-flow policy builder.
- Windows NetQos serializes `Protocol.UDP` as `2`, while verification accepted
  the IP protocol number `17`. The installed Windows module independently
  produced `{"IPProtocolMatchCondition":2}`. Verification now accepts the native
  UDP enum and rejects TCP, Both and invalid values, preventing false repair
  loops for valid policies.

All 58 tests passed locally on 2026-10-10. The existing installed agent was not
restarted or modified. Live `Get-NetQosPolicy` access required an elevated Windows
administrator process, so actual policy and DSCP packet checks remain pending.

## Selection rollback

The audit's relaxed default selection admitted auxiliary game connections that
the user expected to be filtered. The original minimum of 4,094 bytes/second,
50% of the busiest eligible flow and bandwidth ranking are restored. The
45-second recent-rate measurement and the v1.0.12 decoder and policy fixes are
preserved. Regression coverage verifies that excluded auxiliary endpoints do
not reach the router report or exact-flow policy builder. All 59 tests passed
locally on 2026-10-10; live match-server selection remains unchecked.

These filters are intentional design, not defects. Repository `AGENTS.md`,
selection comments and regression tests now record that audits and refactors
must preserve them unless the user explicitly requests a selection change.

## Temporary Windows policy compatibility

The user's v1.0.13 ActiveStore output showed the correct executable, native UDP
enum `2`, selected destination port `7114` and DSCP `46`, but an empty destination
IP prefix. Desired policies still required the server IP, so verification failed
and removed/recreated the policy about every ten seconds. This matches the
[reported NetQos ActiveStore limitation](https://github.com/PowerShell/PowerShell/issues/25486).

At the user's request, selected-port mode now creates temporary ActiveStore
policies matching the owning game executable and selected UDP destination port.
It does not request a server IP condition. Settings, the live dashboard and the
README explain that other UDP traffic from that executable to the same port can
also receive Windows tagging. Router rules retain exact selected IP addresses
and ports. The all-UDP default, selection thresholds, ranking, warmup and
three-flow cap are unchanged.

Policy names reflect the actual executable/port match, so selected flows sharing
that match reuse one policy. Existing managed IP-based names are removed during
the next synchronization. Verification still checks the executable, UDP, DSCP,
destination port and absence of unintended IP/source-port restrictions. The
user's empty-IP/native-port output verifies repeatedly without policy churn.

All 63 tests passed locally on 2026-10-10, including IPv4/IPv6 command generation,
repeated native verification, one-time migration, invalid endpoint rejection,
and preservation of exact router metadata and selection filters. Live native
creation, packet DSCP capture and GUI layout still require the packaged app.
This fixes the confirmed verification loop; it does not establish the cause of
the reported hit-registration problem.

## Socket ownership and policy validation follow-up — 2026-10-16

The four findings in [the flow follow-up audit](pc-agent-flow-followup-audit.md)
are fixed. Concurrent sockets retain their histories; local addresses determine
direction before ownership heuristics; missing payload PID requires a unique
family/address/port owner rather than header PID or every numeric-port owner.
Policy verification now checks source-prefix and all-profile conditions and
rejects malformed or conflicting native port restrictions.

All 72 local tests pass, including mocked native UDP table decoding and the
existing release-workflow tests. Intentional flow selection is unchanged.
Policies remain temporary executable-plus-selected-port policies in strict
mode, or executable-plus-UDP policies in default mode. No port-only fallback is
permitted. No running installation or native policy was changed for this work.
