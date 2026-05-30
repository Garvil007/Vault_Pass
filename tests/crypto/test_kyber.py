from crypto import kyber


def test_encap_decap_match():
    pub, sec = kyber.generate_keypair()
    ct, ss_server = kyber.encapsulate(pub)
    ss_client = kyber.decapsulate(sec, ct)
    assert ss_server == ss_client


def test_wrong_secret_key_differs():
    pub, _ = kyber.generate_keypair()
    _, wrong_sec = kyber.generate_keypair()
    ct, ss_server = kyber.encapsulate(pub)
    assert kyber.decapsulate(wrong_sec, ct) != ss_server


def test_keys_nonempty():
    pub, sec = kyber.generate_keypair()
    assert isinstance(pub, bytes) and len(pub) > 0
    assert isinstance(sec, bytes) and len(sec) > 0
