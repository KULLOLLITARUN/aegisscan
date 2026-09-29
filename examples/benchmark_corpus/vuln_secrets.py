"""Benchmark corpus: hardcoded credentials (CWE-798). Intentionally vulnerable; all values are fake."""

DB_PASSWORD = "Sup3rS3cret!pw"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
PAYMENT_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dcXXXX"
SIGNING_KEY = """-----BEGIN PRIVATE KEY-----
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEA
-----END PRIVATE KEY-----"""


def connect(host, password="admin-pass-123"):
    return f"postgres://admin:{password}@{host}/app"
