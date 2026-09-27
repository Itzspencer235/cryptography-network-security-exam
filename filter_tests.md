# Network Traffic Filtering — Test Evidence

## Note on environment

No physical or virtual lab network was available for this exam. The
rules in `firewall_rules.sh` are the actual `iptables` commands that
would be applied on the records server (or its gateway) in a real
deployment. To still produce genuine, reproducible test evidence,
`firewall_simulator.py` re-implements the exact same rule logic —
evaluated in the same top-to-bottom order as `iptables` — and runs
real connection-attempt tests against it in software.

## Network assumptions

| Item | Value |
|---|---|
| Records server | 10.0.0.10 |
| Service port | 8443 |
| Staff network (authorised) | 10.0.1.0/24 |
| Guest network (blocked) | 10.0.2.0/24 |
| Suspicious external address (from scenario) | 203.0.113.50 |

## Rules applied (see `firewall_rules.sh`)

1. Allow established/related connections
2. **(a)** Drop all traffic from guest network (10.0.2.0/24) to the server
3. **(b)** Accept traffic from staff network (10.0.1.0/24) to the server on port 8443
4. **(c)** Drop all other traffic to port 8443
5. Default policy: DROP

## Tests

Run with: `python3 firewall_simulator.py`

| # | Test | Command (simulated connection) | Expected | Actual | Result |
|---|------|-------|----------|--------|--------|
| 1 | Staff → records service | source `10.0.1.50` → `10.0.0.10:8443` | ACCEPT | ACCEPT | **PASS** |
| 2 | Guest → records service | source `10.0.2.75` → `10.0.0.10:8443` | DROP | DROP | **PASS** |
| 3 | Unknown external host → records service | source `203.0.113.50` → `10.0.0.10:8443` | DROP | DROP | **PASS** |

Full console output:

```
Simulated firewall test run
========================================
[PASS] Test 1: Staff -> records service (should be PERMITTED)
    source=10.0.1.50 -> 10.0.0.10:8443
    expected=ACCEPT  actual=ACCEPT  (Staff network, correct service port (rule b))

[PASS] Test 2: Guest -> records service (should be BLOCKED)
    source=10.0.2.75 -> 10.0.0.10:8443
    expected=DROP  actual=DROP  (Source is in guest network (rule a))

[PASS] Test 3: Unknown external host -> records service (should be BLOCKED)
    source=203.0.113.50 -> 10.0.0.10:8443
    expected=DROP  actual=DROP  (Not staff, not guest — blocked from service (rule c))

========================================
All 3 tests passed.
```

## If real lab access becomes available

Run `firewall_rules.sh` on the actual server, then test with real
tools instead of the simulator, e.g.:

```bash
# from a staff-network host (should succeed)
nc -zv 10.0.0.10 8443

# from a guest-network host (should time out / be blocked)
nc -zv 10.0.0.10 8443

# from an external host (should time out / be blocked)
nc -zv 10.0.0.10 8443
```
