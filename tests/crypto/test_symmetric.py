import json
import os

import pytest
from cryptography.exceptions import InvalidTag

from crypto import symmetric


def _key():
    return os.urandom(32)


def test_round_trip():
    key = _key()
    data = {"url": "example.com", "username": "alice", "password": "s3cret"}
    assert symmetric.decrypt(key, symmetric.encrypt(key, data)) == data


def test_tamper_detection():
    key = _key()
    blob = bytearray(symmetric.encrypt(key, {"a": 1}))
    blob[-1] ^= 0x01
    with pytest.raises(InvalidTag):
        symmetric.decrypt(key, bytes(blob))


def test_unique_nonce():
    key = _key()
    data = {"a": 1}
    assert symmetric.encrypt(key, data) != symmetric.encrypt(key, data)


def test_min_length():
    key = _key()
    data = {"a": 1}
    blob = symmetric.encrypt(key, data)
    json_len = len(json.dumps(data).encode())
    assert len(blob) >= 12 + json_len + 16


def test_associated_data_mismatch():
    key = _key()
    blob = symmetric.encrypt(key, {"a": 1}, associated_data=b"user-1")
    with pytest.raises(InvalidTag):
        symmetric.decrypt(key, blob, associated_data=b"user-2")
