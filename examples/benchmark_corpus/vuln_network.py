"""Benchmark corpus: TLS and HTTP client misuse (CWE-295 / CWE-400). Intentionally vulnerable."""
import ssl
import urllib.request

import requests


def fetch(url):
    return requests.get(url, verify=False, timeout=5)


def fetch_any(url):
    return urllib.request.urlopen(url)


def insecure_context():
    return ssl._create_unverified_context()


def download(url):
    return requests.get(url)
