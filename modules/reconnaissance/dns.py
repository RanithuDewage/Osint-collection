import socket

from modules.core.base import ReconModule


def resolve_domain(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip

    except socket.gaierror:
        return None


def get_dns_info(domain):
    ip = resolve_domain(domain)

    return {
        "domain": domain,
        "ip": ip,
        "resolved": ip is not None,
    }


class DNSRecon(ReconModule):
    """DNS reconnaissance module."""

    def run(self, target):
        return get_dns_info(target)
