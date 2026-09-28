"""
Vulnerable Python example — intentional security issues for benchmark testing.

DO NOT deploy this code. It contains deliberate vulnerabilities to validate
that AegisScan's static analysis layer (Bandit/Semgrep) detects real issues.

Expected Bandit findings:
  B608 - hardcoded_sql_expressions (SQL injection in get_user, search_products)
  B602 - subprocess_popen_with_shell_equals_true (run_system_command)
  B301 - pickle (deserialize_session)
  B105 - hardcoded_password_string (DB_PASSWORD, API_SECRET)
"""
import pickle
import sqlite3
import subprocess

# B105: hardcoded_password_string
DB_PASSWORD = "admin123"
API_SECRET = "sk-prod-xxxxxxxxxxxxxxxx"


def get_db():
    return sqlite3.connect("app.db")


def get_user(user_id):
    """B608: SQL injection — user_id is concatenated directly."""
    conn = get_db()
    query = "SELECT * FROM users WHERE id = " + str(user_id)
    return conn.execute(query).fetchone()


def search_products(keyword):
    """B608: SQL injection — keyword is concatenated directly."""
    conn = get_db()
    query = "SELECT * FROM products WHERE name LIKE '%" + keyword + "%'"
    return conn.execute(query).fetchall()


def run_system_command(path):
    """B602: subprocess with shell=True — allows shell injection."""
    subprocess.call("ls -la " + path, shell=True)


def deserialize_session(data: bytes):
    """B301: pickle.loads — arbitrary code execution risk."""
    return pickle.loads(data)


def update_user_email(user_id, new_email):
    """B608: SQL injection in UPDATE statement."""
    conn = get_db()
    conn.execute(
        "UPDATE users SET email = '" + new_email + "' WHERE id = " + str(user_id)
    )
    conn.commit()
