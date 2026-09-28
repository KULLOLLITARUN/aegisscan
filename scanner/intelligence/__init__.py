from scanner.intelligence.deduplicator import deduplicate, fingerprint
from scanner.intelligence.correlator import correlate, CorrelationGroup
from scanner.intelligence.baseline import BaselineManager, save_baseline

__all__ = [
    "deduplicate", "fingerprint",
    "correlate", "CorrelationGroup",
    "BaselineManager", "save_baseline",
]
