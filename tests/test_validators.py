from utils.validators import (
    is_ip_address,
    validate_target
)


def test_valid_ip():
    assert is_ip_address("127.0.0.1") is True


def test_invalid_ip():
    assert is_ip_address("hello") is False


def test_valid_target_ip():
    assert validate_target("127.0.0.1") is True


def test_valid_target_domain():
    assert validate_target("example.com") is True
