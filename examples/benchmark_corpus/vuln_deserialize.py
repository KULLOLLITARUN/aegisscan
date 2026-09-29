"""Benchmark corpus: unsafe deserialization (CWE-502). Intentionally vulnerable."""
import marshal
import pickle

import yaml


def load_session(blob: bytes):
    return pickle.loads(blob)


def load_cache(fp):
    return pickle.load(fp)


def load_config(text: str):
    return yaml.load(text)


def load_code(blob: bytes):
    return marshal.loads(blob)
