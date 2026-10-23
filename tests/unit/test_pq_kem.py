import pytest

from qguards.security.pq_kem import (
    decapsulate,
    derive_aes256_key,
    encapsulate,
    generate_keypair,
)


def test_mlkem_shared_secrets_match():
    private_key, public_key = generate_keypair()
    ciphertext, sender_secret = encapsulate(public_key)
    receiver_secret = decapsulate(private_key, ciphertext)

    assert sender_secret == receiver_secret
    assert len(sender_secret) == 32


def test_both_parties_derive_same_aes_key():
    private_key, public_key = generate_keypair()
    ciphertext, sender_secret = encapsulate(public_key)
    receiver_secret = decapsulate(private_key, ciphertext)
    salt = b"qguards-test-salt-01"

    sender_key = derive_aes256_key(sender_secret, salt)
    receiver_key = derive_aes256_key(receiver_secret, salt)

    assert len(sender_key) == 32
    assert sender_key == receiver_key


def test_invalid_ciphertext_type_is_rejected():
    private_key, _ = generate_keypair()

    with pytest.raises(TypeError):
        decapsulate(private_key, "not-bytes")


def test_invalid_ciphertext_length_is_rejected():
    private_key, _ = generate_keypair()

    with pytest.raises(ValueError):
        decapsulate(private_key, b"short")


def test_invalid_salt_is_rejected():
    with pytest.raises(ValueError):
        derive_aes256_key(b"example-secret", b"short")