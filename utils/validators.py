import ipaddress
import re
import socket

from utils.errors import TargetValidationError


def is_ip_address(target):
    try:
        ipaddress.ip_address(target)
        return True

    except ValueError:
        return False


def is_network(target):
    try:
        ipaddress.ip_network(
            target,
            strict=False,
        )
        return "/" in target

    except ValueError:
        return False


_DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[A-Za-z0-9]"
    r"(?:[A-Za-z0-9-]{0,61}"
    r"[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)


def validate_domain(target):
    """
    A real domain check: rejects plain IP addresses (an IP
    has dots too, but isn't a domain), and requires a
    well-formed label/TLD structure instead of just
    counting dots.
    """
    target = target.strip()

    if is_ip_address(target):
        return False

    return bool(
        _DOMAIN_PATTERN.fullmatch(target)
    )


def validate_target(target):
    if is_ip_address(target):
        return True

    if is_network(target):
        return True

    return validate_domain(target)


# ----------------------------------------------------------
# Parsing helpers (return the parsed object, or None if the
# target doesn't match that kind). Kept alongside the
# boolean validators above so callers can pick whichever
# style fits — main.py uses these directly.
# ----------------------------------------------------------

def parse_network_target(target):
    try:
        return ipaddress.ip_network(
            target.strip(),
            strict=False,
        )
    except ValueError:
        return None


def parse_single_ip(target):
    try:
        return ipaddress.ip_address(
            target.strip()
        )
    except ValueError:
        return None


def is_domain_target(target):
    return bool(
        _DOMAIN_PATTERN.fullmatch(
            target.strip()
        )
    )


def validate_target_or_raise(target):
    """
    Same check as validate_target(), but raises
    TargetValidationError with a helpful message instead of
    returning False. Not used by main.py yet (main.py's
    flow currently expects None/False on invalid input at
    each call site) — available for callers that prefer
    exception-based error handling, e.g. new modules.
    """
    if validate_target(target):
        return True

    raise TargetValidationError(
        f"'{target}' is not a valid IP, network, or domain."
    )