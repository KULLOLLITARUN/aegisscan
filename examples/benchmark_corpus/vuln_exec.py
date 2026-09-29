"""Benchmark corpus: OS command and code injection (CWE-78 / CWE-94). Intentionally vulnerable."""
import os
import subprocess


def ping(host):
    os.system("ping -c 1 " + host)


def archive(path):
    subprocess.Popen("tar czf out.tgz " + path, shell=True)


def lookup(host):
    return subprocess.check_output(f"nslookup {host}", shell=True)


def calc(expr):
    return eval(expr)


def run_snippet(code):
    exec(code)
