
from qguards.security.key_exchange import (
    establish_gateway_keypair,
    establish_receiver_session_key,
    establish_sender_session_key,
)


def test_sender_and_gateway_derive_same_session_key():
    gateway_private, gateway_public = establish_gateway_keypair()

    kem_ciphertext, salt, sender_key = establish_sender_session_key(
        gateway_public
    )

    receiver_key = establish_receiver_session_key(
        gateway_private,
        kem_ciphertext,
        salt,
    )

    assert len(sender_key) == 32
    assert sender_key == receiver_key
