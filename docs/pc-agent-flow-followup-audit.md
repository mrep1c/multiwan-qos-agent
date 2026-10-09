# PC agent flow and policy follow-up audit

Reviewed on 2026-10-10 against v1.0.12, commit
`eb4439ab3b0425d174c9090037945fa908f948e8`. This review covers endpoint decoding,
direction, PID fallback, simultaneous sockets, selection and native policy
verification. The additional findings below remain unfixed; no running agent,
Windows policy or router configuration was changed during this audit.

The earlier ETW port byte-order and NetQos UDP enum fixes are published in
v1.0.12. Its release workflow succeeded, including all 58 regression tests.
Those tests did not cover the additional cases below.

## Reproduced findings

### 1. P1: Concurrent sockets erase each other's flow history

`multiwan_qos_agent/flow_etw.py:860` indexes only PID, remote IP and remote port,
then deletes the previous flow when another local port uses that endpoint.
Two simultaneous sockets are treated as a replacement socket. Repeated traffic
from local ports 50000 and 50001 to the same server for 11 seconds leaves one
flow with one packet, continually marked `warming up`; zero flows are selected.

Preserve histories for each complete socket tuple. Expire old sockets by
inactivity rather than deleting them when another socket sends a packet.

### 2. P1: A remote-port collision can hide a valid game flow

`multiwan_qos_agent/flow_etw.py:812` uses the port-owner table before known local
addresses. During its two-second refresh gap, a new game source port may be
missing while the server's numeric port happens to be owned by another local
application. The collector reverses the endpoint, then rejects the PC's address
as noise. A reproduced send event with an explicit local source IP retained
zero flows instead of one.

Prefer known local addresses when determining direction. Use owner information
only when addresses do not resolve the direction, and never let an unrelated
port owner override an unambiguous local address.

### 3. P2: Missing payload PID can assign traffic to the wrong game

`multiwan_qos_agent/flow_etw.py:790` replaces missing payload PID with the event
header PID. At line 850, a tracked header PID then overrides the UDP socket
owner. A reproduced event whose socket belonged to PID 102 was assigned to
tracked header PID 103.

The fallback is also ambiguous: `UdpOwnerMap` merges IPv4, IPv6 and different
local addresses by numeric port alone (`flow_etw.py:518`). A port-owner set of
102 and 103 duplicates a missing-PID event into both games. These cases depend
on missing payload PID; they do not establish that normal current provider
events lack that property.

Keep payload identity separate from header context. For fallback, resolve the
local family/address/port to a unique owner; reject unresolved ambiguity rather
than assigning the event to every tracked owner.

### 4. P2: Policy verification accepts restrictive or malformed state

`multiwan_qos_agent/qos.py:483` does not query source-address restrictions or
network profile. A mock native policy with source prefix `10.42.0.0/24` and
Domain-only profile verifies as matching an all-UDP policy intended for every
source address and every profile. No repair is attempted, although it will not
match an ordinary Private-profile LAN session.

At lines 132 and 144, invalid prefix/port values normalize to `None`, the same
value used for an unrestricted match. Reproduced malformed prefix and port
responses therefore verify as matching an unrestricted policy. Malformed
values were synthetic; they were not observed in the installed Windows store.

Verify the restrictions that affect the generated policy, including source
address and network profile. Distinguish supported wildcard values from invalid
native data and fail verification on invalid values.

## Existing selection limits

These filters and the cap are intentional design, not audit defects. The user
also confirmed that the original 4,094 bytes/second minimum, 50% busiest-flow
cutoff and bandwidth ranking must be preserved. The subsequent selection
rollback restores those defaults while retaining recent-rate measurement.
Future audits must follow repository `AGENTS.md` and must not relax selection
without an explicit user request.

- `flow_etw.py:961`: The three-flow cap uses recent packet rate and bandwidth.
  Three more-active auxiliary UDP flows from the same game process can exclude
  its gameplay flow. Without traffic classification or session evidence,
  activity alone cannot guarantee which endpoint is the match server.
- `flow_etw.py:436`: Private remote addresses are rejected. This excludes LAN
  and VPN game servers that use private addresses. This is an existing filter
  policy; changing it needs a decision about which local traffic to admit.

## Evidence and limits

Small offline probes used the existing mocked test fixtures and exercised the
collector, connection report and policy verifier. They reproduced the results
above without network requests or native policy writes. Native Windows module
metadata confirms that Domain is profile 1, Private is 4 and All is 7.

These additional cases have not been tested during a live game. Administrator
access to the actual Windows policy store and DSCP packet capture remain
unchecked. No claim is made that these findings explain the user's entire live
symptom; the expected match-server endpoint was not supplied.
