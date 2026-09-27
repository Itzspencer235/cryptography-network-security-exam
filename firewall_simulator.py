#!/usr/bin/env python3
"""
firewall_simulator.py

No physical or virtual lab network was available for this exam, so this
script simulates the SAME rule logic as firewall_rules.sh (the real
iptables rules that would be deployed on the actual server), evaluated
top-to-bottom exactly like iptables does, and reports ACCEPT/DROP for
each test connection. This produces genuine, reproducible test evidence
for filter_tests.md even without real lab hardware.

Rules simulated (matching firewall_rules.sh):
  1. Guest network (10.0.2.0/24) -> server: DROP (any port)
  2. Staff network (10.0.1.0/24) -> server, port 8443: ACCEPT
  3. Anyone else -> server, port 8443: DROP
  4. Default policy: DROP
"""

import ipaddress
import sys

SERVER_IP = ipaddress.ip_address("10.0.0.10")
SERVICE_PORT = 8443

GUEST_NET = ipaddress.ip_network("10.0.2.0/24")
STAFF_NET = ipaddress.ip_network("10.0.1.0/24")


def evaluate(source_ip: str, dest_ip: str, dest_port: int) -> tuple[str, str]:
    """
    Evaluate a connection attempt against the rule set, in the same
    top-to-bottom order as firewall_rules.sh. Returns (verdict, reason).
    """
    try:
        src = ipaddress.ip_address(source_ip)
        dst = ipaddress.ip_address(dest_ip)
    except ValueError as exc:
        return "DROP", f"Invalid address: {exc}"

    if dst != SERVER_IP:
        return "DROP", "Not destined for the records server (default policy)"

    # Rule (a): guest network is blocked outright, any port
    if src in GUEST_NET:
        return "DROP", "Source is in guest network (rule a)"

    # Rule (b): staff network allowed, but only on the service port
    if src in STAFF_NET:
        if dest_port == SERVICE_PORT:
            return "ACCEPT", "Staff network, correct service port (rule b)"
        else:
            return "DROP", "Staff network, but wrong port (not explicitly allowed)"

    # Rule (c): anyone else hitting the service port is blocked
    if dest_port == SERVICE_PORT:
        return "DROP", "Not staff, not guest — blocked from service (rule c)"

    return "DROP", "Default policy DROP"


def run_test(name: str, source_ip: str, dest_port: int, expected: str) -> bool:
    verdict, reason = evaluate(source_ip, str(SERVER_IP), dest_port)
    passed = verdict == expected
    status = "PASS" if passed else "FAIL"
    print(f"[{status}] {name}")
    print(f"    source={source_ip} -> {SERVER_IP}:{dest_port}")
    print(f"    expected={expected}  actual={verdict}  ({reason})")
    return passed


if __name__ == "__main__":
    print("Simulated firewall test run\n" + "=" * 40)

    results = []

    # Test 1: PERMITTED — staff network reaching the records service
    results.append(run_test(
        "Test 1: Staff -> records service (should be PERMITTED)",
        source_ip="10.0.1.50",
        dest_port=SERVICE_PORT,
        expected="ACCEPT",
    ))
    print()

    # Test 2: BLOCKED — guest network trying to reach the server
    results.append(run_test(
        "Test 2: Guest -> records service (should be BLOCKED)",
        source_ip="10.0.2.75",
        dest_port=SERVICE_PORT,
        expected="DROP",
    ))
    print()

    # Test 3: BLOCKED — the unfamiliar external address from the scenario
    results.append(run_test(
        "Test 3: Unknown external host -> records service (should be BLOCKED)",
        source_ip="203.0.113.50",
        dest_port=SERVICE_PORT,
        expected="DROP",
    ))
    print()

    print("=" * 40)
    if all(results):
        print(f"All {len(results)} tests passed.")
        sys.exit(0)
    else:
        print(f"{results.count(False)} of {len(results)} tests FAILED.")
        sys.exit(1)
