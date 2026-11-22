from utils.formatter import (
    format_dns_result,
    format_port_results,
)


def test_format_resolved_dns():
    result = {
        "domain": "example.com",
        "resolved": True,
        "ip": "93.184.216.34",
    }

    output = format_dns_result(result)

    assert "Target: example.com" in output
    assert "Resolved IP: 93.184.216.34" in output


def test_format_failed_dns():
    result = {
        "domain": "invalid.example",
        "resolved": False,
        "ip": None,
    }

    output = format_dns_result(result)

    assert "Target: invalid.example" in output
    assert "DNS Resolution Failed" in output


def test_format_missing_dns_data():
    result = {}

    output = format_dns_result(result)

    assert "Target: Unknown" in output
    assert "DNS Resolution Failed" in output


def test_format_port_results():
    results = {
        80: True,
        22: False,
        443: True,
    }

    output = format_port_results(results)

    assert "PORT ASSESSMENT" in output
    assert "22    CLOSED" in output
    assert "80    OPEN" in output
    assert "443   OPEN" in output