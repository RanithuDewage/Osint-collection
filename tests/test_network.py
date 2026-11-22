from modules.reconnaissance.network import (
    discover_hosts,
    get_network_hosts,
)


def test_get_network_hosts():
    hosts = get_network_hosts("127.0.0.0/30")

    assert hosts == [
        "127.0.0.1",
        "127.0.0.2",
    ]


def test_discover_localhost():
    hosts = discover_hosts("127.0.0.1/32")

    assert "127.0.0.1" in hosts
