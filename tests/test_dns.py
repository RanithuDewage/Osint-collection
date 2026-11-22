from modules.reconnaissance.dns import (
    resolve_domain,
    get_dns_info
)


def test_resolve_valid_domain():
    ip = resolve_domain("example.com")

    assert ip is not None


def test_get_dns_info():
    result = get_dns_info("example.com")

    assert result["domain"] == "example.com"
    assert result["resolved"] is True
    assert result["ip"] is not None


def test_get_dns_info_invalid_domain():
    result = get_dns_info("this-domain-does-not-exist.invalid")

    assert result["domain"] == "this-domain-does-not-exist.invalid"
    assert result["resolved"] is False
    assert result["ip"] is None

from modules.reconnaissance.dns import DNSRecon


def test_dns_recon_module():
    module = DNSRecon()

    result = module.run("example.com")

    assert result["domain"] == "example.com"
    assert result["resolved"] is True
    assert result["ip"] is not None
