"""
enforcement.py - pluggable response/enforcement layer for the admin
console. Mirrors dashboard/enforcement.py's pattern: every function
here is a stub today, reporting back what WOULD happen. Swap the body
of each apply_* function for a real backend later (SSH into a bridge
host and push an nftables/iptables rule, a firewall/SDN controller
API call, etc.) - main.py never needs to change, since it only depends
on the EnforcementResult shape below.

SAFETY NOTE: this console may eventually point at a real college
gateway/firewall carrying live production traffic. Do not wire a real
enforcement backend into apply_ip_policy() without: (1) testing against
non-production traffic first, (2) a deliberate, separate "arm live
enforcement" configuration step - not just deploying this code, and
(3) sign-off from whoever actually administers that network.
"""

from dataclasses import dataclass


@dataclass
class EnforcementResult:
    status: str    # "stubbed" | "applied" | "failed" | "not_applicable"
    detail: str


def apply_alert_block(src_h: str, dst_h: str) -> EnforcementResult:
    return EnforcementResult(
        status="stubbed",
        detail=f"No live enforcement backend configured yet - would block traffic from {src_h} to {dst_h}.",
    )


def apply_alert_allow(src_h: str, dst_h: str) -> EnforcementResult:
    return EnforcementResult(
        status="not_applicable",
        detail=f"No enforcement backend configured for allow - recorded as decision only ({src_h} -> {dst_h}).",
    )


def apply_ip_policy(ip: str, policy: str) -> EnforcementResult:
    """Called when an admin sets a global policy on an asset's IP."""
    if policy == "blacklist":
        return EnforcementResult(
            status="stubbed",
            detail=f"No live enforcement backend configured yet - would block ALL traffic to/from {ip}.",
        )
    if policy == "quarantine":
        return EnforcementResult(
            status="stubbed",
            detail=f"No live enforcement backend configured yet - would isolate {ip} from the network entirely.",
        )
    if policy == "whitelist":
        return EnforcementResult(
            status="not_applicable",
            detail=f"{ip} recorded as explicitly whitelisted - no block to remove, decision only.",
        )
    return EnforcementResult(status="not_applicable", detail=f"Policy for {ip} cleared - recorded only.")
