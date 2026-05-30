from crypto import kdf


def test_deterministic():
    salt = kdf.generate_salt()
    assert kdf.derive_key("hunter2", salt) == kdf.derive_key("hunter2", salt)


def test_different_passwords_differ():
    salt = kdf.generate_salt()
    assert kdf.derive_key("alpha", salt) != kdf.derive_key("beta", salt)


def test_output_length_32():
    salt = kdf.generate_salt()
    assert len(kdf.derive_key("pw", salt)) == 32


def test_salt_sensitivity():
    k1 = kdf.derive_key("pw", kdf.generate_salt())
    k2 = kdf.derive_key("pw", kdf.generate_salt())
    assert k1 != k2


def test_salt_length():
    assert len(kdf.generate_salt()) == 16
