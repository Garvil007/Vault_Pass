"""VaultPass crypto package.

Ensures the locally-built liboqs shared library is discoverable before any
oqs-backed module (kyber, dilithium) is imported. liboqs-python searches
``~/_oqs`` by default, but a stale PATH (e.g. an old 32-bit MinGW) or a
non-default install can shadow it — so we prepend the known bin dir defensively
and only if it exists. No-op when liboqs is already on the path.
"""
import os

_OQS_BIN = os.path.join(os.path.expanduser("~"), "_oqs", "bin")
if os.path.isdir(_OQS_BIN) and _OQS_BIN not in os.environ.get("PATH", ""):
    os.environ["PATH"] = _OQS_BIN + os.pathsep + os.environ.get("PATH", "")
