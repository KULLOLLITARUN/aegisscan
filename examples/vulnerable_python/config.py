"""
Vulnerable Python config — intentional issues for benchmark testing.

DO NOT deploy this code.

Expected Bandit findings:
  B110 - try_except_pass (bare except: pass swallows all errors)
"""

DEBUG = True
TESTING = True
LOG_LEVEL = "DEBUG"

# Broad exception handling — swallows errors silently
def load_config(path):
    try:
        with open(path) as f:
            return f.read()
    except:  # B110: try_except_pass / broad exception
        pass


def connect_db(host, port):
    try:
        import socket
        s = socket.create_connection((host, port))
        return s
    except:  # B110: broad exception
        pass
