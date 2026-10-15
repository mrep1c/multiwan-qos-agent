# Agent design instructions

## Preserve intentional flow selection

The agent collects UDP metadata from game processes, but it must select only
significant eligible flows. Process ownership alone must not make every game
connection eligible for router rules or selected-port Windows tagging.

The following defaults are intentional product behavior:

- Minimum throughput: 4,094 bytes/second.
- Rank eligible flows by bandwidth, highest first.
- Additional selected flows need at least 50% of the busiest eligible flow's
  bandwidth.
- Select at most three flows per game.
- Keep the warmup, stale-flow and UDP noise filters.

Do not remove, relax or replace these rules as an audit fix, refactor or
low-bandwidth optimization. Change selection behavior only when the user
explicitly requests that design change. Preserve these defaults when fixing
ETW decoding, PID ownership, policy verification or recent-rate measurement.

The dashboard may show ignored candidates for diagnosis. Only selected flows
belong in the router report and selected-port policy specs. Preserve regression
coverage for that boundary.

## Preserve temporary Windows policy compatibility

Selected-port Windows tagging uses the owning executable and selected UDP
destination port. ActiveStore drops destination IP filters on affected Windows
systems; the UI must state that Windows cannot match the server IP. Other UDP
traffic from the same executable to that port can also be tagged. Router rules
must retain the exact selected endpoints, including IP addresses and ports.

Never create a port-only Windows policy. The executable condition is mandatory
in every agent policy, including fallback behavior and diagnostic fixes.

Keep Windows policies temporary in ActiveStore. Do not add an IP condition that
causes repeated failed verification, silently accept an unmet desired condition,
or switch to persistent policies without an explicit user request. Flows sharing
an executable and destination port share one Windows policy.
