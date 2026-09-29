from scanner.intelligence.baseline import BaselineManager, save_baseline
from scanner.intelligence.correlator import CorrelationGroup, correlate
from scanner.intelligence.deduplicator import deduplicate, fingerprint

__all__ = [
    "deduplicate", "fingerprint",
    "correlate", "CorrelationGroup",
    "BaselineManager", "save_baseline",
]
