"""
enforcement.py - pluggable response/enforcement layer.

This is the seam between "the dashboard recorded an analyst decision"
and "something in the network actually changed." Today it's a stub:
apply_block() and apply_allow() just report back what WOULD happen,
so the full response workflow (audit trail, UI, status tracking) can
be built and demoed before a real enforcement backend exists.

TO GO LIVE LATER: replace the body of apply_block() with a real call -
for example, SSH into the bridge host set up by setup_bridge.sh and
run an nftables/iptables rule to drop traffic from the offending
source, or call a firewall/SDN controller's API. app.py never needs
to change - it only depends on the EnforcementResult shape below, so
swapping the backend here is a self-contained change.
"""

from dataclasses import dataclass


@dataclass
class EnforcementResult:
    status: str    # "stubbed" | "applied" | "failed" | "not_applicable"
    detail: str


def apply_block(src_h: str, dst_h: str) -> EnforcementResult:
    """
    Called when an analyst clicks BLOCK on an alert.

    TODO (productionization): replace this stub with a real call, e.g.:
      - SSH into the bridge host (see setup_bridge.sh) and run
        `nft add rule inet filter forward ip saddr {src_h} drop`
      - or POST to a firewall/SDN controller's block-IP API
      - or push a rule via a cloud security-group API
    """
    return EnforcementResult(
        status="stubbed",
        detail=f"No live enforcement backend configured yet - "
               f"would block traffic from {src_h} to {dst_h}.",
    )


def apply_allow(src_h: str, dst_h: str) -> EnforcementResult:
    """
    Called when an analyst clicks ALLOW - either clearing an alert as
    a false positive, or reversing an earlier BLOCK.

    TODO (productionization): if a block rule exists for this pair,
    remove it here (e.g. `nft delete rule ...`); otherwise this stays
    a pure record-keeping action with no enforcement backend to call.
    """
    return EnforcementResult(
        status="not_applicable",
        detail=f"No enforcement backend configured for allow - recorded as decision only "
               f"({src_h} -> {dst_h}).",
    )
