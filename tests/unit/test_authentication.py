
import pytest

from qguards.security.authentication import (
    create_tag,
    generate_auth_key,
    verify_tag,
)


def test_valid_message_authenticates():
    key = generate_auth_key()
    message = b"temperature=25.4"
    tag = create_tag(key, message)

    assert verify_tag(key, message, tag)


def test_modified_message_is_rejected():
    key = generate_auth_key()
    message = b"temperature=25.4"
    tag = create_tag(key, message)

    assert not verify_tag(key, b"temperature=99.9", tag)


def test_wrong_key_is_rejected():
    message = b"sensor telemetry"
    tag = create_tag(generate_auth_key(), message)

    assert not verify_tag(generate_auth_key(), message, tag)


def test_malformed_tag_is_rejected():
    key = generate_auth_key()

    assert not verify_tag(key, b"message", b"short")


def test_short_key_is_rejected():
    with pytest.raises(ValueError, match="at least 32 bytes"):
        create_tag(b"short", b"message")


def test_non_bytes_message_is_rejected():
    with pytest.raises(ValueError, match="Message must be bytes"):
        create_tag(generate_auth_key(), "message")
