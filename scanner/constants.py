"""Project-wide constants (centralized to allow override in one place)."""

# Canary host used by CORS, open-redirect, and host-header injection probes.
# Change this to a sinkhole domain you control if desired.
ATTACKER_CANARY = "evil-attacker.com"

# Default timeout for individual HTTP probes.
DEFAULT_PROBE_TIMEOUT = 8

# Severity order (most severe first).
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
