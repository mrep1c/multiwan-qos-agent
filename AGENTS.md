# Agent design instructions

## Preserve intentional flow selection

The agent collects UDP metadata from game processes, but it must select only
significant eligible flows. Process ownership alone must not make every game
connection eligible for router rules or exact-flow Windows tagging.

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
belong in the router report and exact-flow policy specs. Preserve regression
coverage for that boundary.
