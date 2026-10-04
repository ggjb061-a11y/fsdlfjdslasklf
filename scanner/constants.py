"""Project-wide constants (centralized to allow override in one place)."""

# Canary host used by CORS, open-redirect, and host-header injection probes.
# Must be a reserved domain so a probe redirect/callback cannot be weaponized
# by a third party. RFC 2606 reserves .example / example.{com,net,org} for
# documentation and testing - they will never resolve on the public internet.
# Override via AUTOSCAN_CANARY env var if you control a sinkhole domain.
import os as _os
ATTACKER_CANARY = _os.environ.get("AUTOSCAN_CANARY", "attacker.example")

# Default timeout for individual HTTP probes.
DEFAULT_PROBE_TIMEOUT = 8

# Severity order (most severe first).
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
