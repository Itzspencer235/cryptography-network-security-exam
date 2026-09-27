#!/bin/bash
# firewall_rules.sh
#
# Firewall configuration for the student records server.
# Intended for a Linux host using iptables, applied on the server itself
# (or on the gateway/router in front of it).
#
# Network layout assumed for this exam (adjust to match real lab values
# if your assessor provides them):
#   Records server   : 10.0.0.10
#   Service port     : 8443   (the student records application)
#   Staff network     : 10.0.1.0/24   (authorised)
#   Guest network      : 10.0.2.0/24   (must be blocked)
#
# Rules are evaluated top-to-bottom; the first match wins. That is why the
# ACCEPT rule for staff must come BEFORE the general DROP rules.

set -e

echo "Applying firewall rules for student records server (10.0.0.10)..."

# --- 0. Always allow already-established connections (replies to our own
#         outbound traffic) so the server itself keeps working normally.
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# --- (a) Block guest network access to the student records server ---------
# Drop ALL traffic from the guest subnet to the server, on any port.
iptables -A INPUT -s 10.0.2.0/24 -d 10.0.0.10 -j DROP

# --- (b) Permit authorised staff network access to the service ------------
# Allow staff subnet to reach the records service on its port.
iptables -A INPUT -s 10.0.1.0/24 -d 10.0.0.10 -p tcp --dport 8443 -j ACCEPT

# --- (c) Block other inbound access to that service ------------------------
# Anyone else (not staff, not already dropped as guest) trying to reach
# the service port is blocked. This also covers the unfamiliar external
# address (203.0.113.50) observed making repeated connection attempts.
iptables -A INPUT -d 10.0.0.10 -p tcp --dport 8443 -j DROP

# --- Default policy: drop anything not explicitly allowed -----------------
iptables -P INPUT DROP

echo "Firewall rules applied."
iptables -L INPUT -v -n --line-numbers
