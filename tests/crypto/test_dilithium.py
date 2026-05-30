from crypto import dilithium


def test_sign_verify():
    pub, sec = dilithium.generate_keypair()
    msg = b"audit-event-payload"
    sig = dilithium.sign(sec, msg)
    assert dilithium.verify(pub, msg, sig) is True


def test_verify_rejects_tampered_message():
    pub, sec = dilithium.generate_keypair()
    sig = dilithium.sign(sec, b"original")
    assert dilithium.verify(pub, b"tampered", sig) is False
