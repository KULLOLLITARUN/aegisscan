"""Safe configuration for scanner testing."""

import os

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///pipeline.db")
JWT_SECRET = os.environ.get("JWT_SECRET", "")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
