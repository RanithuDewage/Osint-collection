import socket
from concurrent.futures import ThreadPoolExecutor

from config.settings import DEFAULT_TIMEOUT


def check_port(host, port, timeout=DEFAULT_TIMEOUT):
    """
    Check whether a specific TCP port is reachable on an authorized host.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((host, port))
        return result == 0

    finally:
        sock.close()


def assess_ports(host, ports, timeout=DEFAULT_TIMEOUT):
    """
    Assess a supplied list of TCP ports in parallel.

    Previously this scanned ports one at a time, so N ports
    could take up to N * timeout seconds if they were all
    closed/filtered. Now up to 32 ports are checked at once,
    so the whole scan takes roughly one timeout's worth of
    time regardless of how many ports are requested.

    Returns the same {port: bool} shape as before, in the
    same order as the `ports` argument (dict order is
    preserved even though the underlying checks finish out
    of order).
    """
    if not ports:
        return {}

    results = {port: False for port in ports}

    max_workers = min(32, len(ports))

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(check_port, host, port, timeout): port
            for port in ports
        }

        for future in future_to_port:
            port = future_to_port[future]

            try:
                results[port] = future.result()
            except Exception:
                results[port] = False

    return results