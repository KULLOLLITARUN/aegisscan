"""Benchmark corpus: safe process and expression handling. Nothing here should be flagged."""
import ast
import shlex
import subprocess


def ping(host: str) -> int:
    return subprocess.run(["ping", "-c", "1", host], check=False, timeout=10).returncode


def parse_command(line: str) -> list[str]:
    return shlex.split(line)


def calc(expr: str):
    return ast.literal_eval(expr)
