import ipaddress
import os
import platform
import subprocess
from concurrent.futures import ThreadPoolExecutor


def _ping_command(host, timeout=1):
    """
    Build the ping command for the current platform.

    Uses the explicit full path to the OS's native ping
    binary on Windows (System32\\PING.EXE), so any other
    'ping' earlier in PATH (e.g. a Unix-style ping from
    Git Bash/WSL that requires administrator privileges
    for raw sockets) is bypassed.
    """
    system = platform.system().lower()

    if system == "windows":
        system_root = os.environ.get(
            "SystemRoot",
            "C:\\Windows",
        )

        ping_path = os.path.join(
            system_root,
            "System32",
            "PING.EXE",
        )

        return [
            ping_path,
            "-n", "1",
            "-w", str(int(timeout * 1000)),
            host,
        ]

    if system == "darwin":
        return [
            "ping",
            "-c", "1",
            "-W", str(int(timeout * 1000)),
            host,
        ]

    return [
        "ping",
        "-c", "1",
        "-W", str(int(timeout)),
        host,
    ]


def get_network_hosts(network):
    """
    Return hosts for either:

    Single IP:
        192.168.1.7

    CIDR:
        192.168.1.0/24
    """

    parsed = ipaddress.ip_network(
        network,
        strict=False,
    )

    # Single IPv4/IPv6 address
    if parsed.prefixlen == parsed.max_prefixlen:
        return [
            str(parsed.network_address)
        ]

    # Network range
    return [
        str(host)
        for host in parsed.hosts()
    ]


def is_reachable(host, timeout=1):
    """
    Check whether a single IP responds to ICMP ping.

    Windows:
        Uses the full path to the native System32
        PING.EXE (see _ping_command), so it works
        without administrator privileges regardless of
        what else is on PATH.

    Linux/Kali:
        ping -c 1 -W 1

    macOS:
        ping -c 1 -W 1000
    """

    command = _ping_command(host, timeout)

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=timeout + 2,
        )

        return result.returncode == 0

    except (
        subprocess.TimeoutExpired,
        OSError,
        subprocess.SubprocessError,
    ):
        return False


def ping_discover(hosts):
    """
    Discover reachable hosts using ICMP.

    The function uses multiple workers so a CIDR
    network can be scanned efficiently.
    """

    if not hosts:
        return []

    max_workers = min(
        32,
        len(hosts),
    )

    reachable = []

    with ThreadPoolExecutor(
        max_workers=max_workers
    ) as executor:

        results = executor.map(
            is_reachable,
            hosts,
        )

        for host, status in zip(
            hosts,
            results,
        ):
            if status:
                reachable.append(host)

    return reachable


def discover_hosts(target):
    """
    Discover reachable hosts.

    Single IP:
        192.168.1.4
        -> checks only 192.168.1.4

    CIDR:
        192.168.1.0/24
        -> checks all usable hosts.

    No Scapy / libpcap dependency is used.
    """

    try:
        parsed = ipaddress.ip_network(
            target,
            strict=False,
        )

    except ValueError:
        return []

    # -------------------------------------------------
    # SINGLE IP
    # -------------------------------------------------

    if parsed.prefixlen == parsed.max_prefixlen:

        host = str(
            parsed.network_address
        )

        if is_reachable(host):
            return [host]

        return []

    # -------------------------------------------------
    # CIDR NETWORK
    # -------------------------------------------------

    hosts = get_network_hosts(
        target
    )

    if not hosts:
        return []

    discovered = ping_discover(
        hosts
    )

    # -------------------------------------------------
    # SORT RESULTS
    # -------------------------------------------------

    return sorted(
        discovered,
        key=lambda ip: ipaddress.ip_address(ip),
    )