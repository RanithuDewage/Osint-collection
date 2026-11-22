import ipaddress
import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

from config.settings import APP_NAME, VERSION

try:
    import dns.resolver
except ImportError:
    dns = None


COMMON_SUBDOMAINS = [
    "www",
    "mail",
    "api",
    "dev",
    "test",
    "staging",
    "admin",
    "portal",
    "app",
    "blog",
    "cdn",
    "static",
    "support",
    "docs",
    "shop",
]


def normalize_target(target):
    target = target.strip()

    if "://" in target:
        target = target.split("://", 1)[1]

    target = target.split("/", 1)[0]
    target = target.split(":", 1)[0]

    return target.lower()


def resolve_a(domain):
    try:
        answers = dns.resolver.resolve(
            domain,
            "A",
            lifetime=4,
        )
        return sorted(
            {answer.to_text() for answer in answers}
        )
    except Exception:
        return []


def resolve_aaaa(domain):
    try:
        answers = dns.resolver.resolve(
            domain,
            "AAAA",
            lifetime=4,
        )
        return sorted(
            {answer.to_text() for answer in answers}
        )
    except Exception:
        return []


def resolve_mx(domain):
    try:
        answers = dns.resolver.resolve(
            domain,
            "MX",
            lifetime=4,
        )

        return sorted(
            {
                answer.exchange.to_text().rstrip(".")
                for answer in answers
            }
        )
    except Exception:
        return []


def resolve_ns(domain):
    try:
        answers = dns.resolver.resolve(
            domain,
            "NS",
            lifetime=4,
        )

        return sorted(
            {
                answer.to_text().rstrip(".")
                for answer in answers
            }
        )
    except Exception:
        return []


def get_rdap(domain):
    url = (
        "https://rdap.org/domain/"
        + urllib.parse.quote(domain)
    )

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": f"{APP_NAME}/{VERSION}",
            "Accept": "application/rdap+json",
        },
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=6,
        ) as response:
            return json.loads(
                response.read().decode(
                    "utf-8",
                    errors="ignore",
                )
            )
    except (
        urllib.error.HTTPError,
        urllib.error.URLError,
        TimeoutError,
        OSError,
        ValueError,
    ):
        return {}


def parse_rdap(rdap):
    result = {
        "registrar": "Not Found",
        "created": "Not Found",
        "expires": "Not Found",
        "status": "Unknown",
    }

    for entity in rdap.get("entities", []):
        roles = entity.get("roles", [])

        if "registrar" not in roles:
            continue

        vcard = entity.get(
            "vcardArray",
            [None, []],
        )

        if len(vcard) < 2:
            continue

        for item in vcard[1]:
            if (
                isinstance(item, list)
                and len(item) >= 4
                and item[0] == "fn"
            ):
                result["registrar"] = str(item[3])
                break

    for event in rdap.get("events", []):
        action = event.get("eventAction")
        date = event.get(
            "eventDate",
            "Not Found",
        )

        if action == "registration":
            result["created"] = date

        elif action == "expiration":
            result["expires"] = date

    statuses = rdap.get("status", [])

    if statuses:
        result["status"] = ", ".join(statuses)
    elif rdap:
        result["status"] = "Active"

    return result


def geolocate(ip):
    if not ip:
        return {
            "country": "Not Found",
            "city": "Not Found",
            "isp": "Not Found",
            "asn": "Not Found",
        }

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {
            "country": "Not Found",
            "city": "Not Found",
            "isp": "Not Found",
            "asn": "Not Found",
        }

    url = (
        "http://ip-api.com/json/"
        f"{urllib.parse.quote(ip)}"
        "?fields=status,country,city,isp,as"
    )

    try:
        with urllib.request.urlopen(
            url,
            timeout=5,
        ) as response:
            data = json.loads(
                response.read().decode(
                    "utf-8",
                    errors="ignore",
                )
            )

        if data.get("status") != "success":
            raise ValueError("Geolocation failed")

        return {
            "country": data.get(
                "country",
                "Not Found",
            ),
            "city": data.get(
                "city",
                "Not Found",
            ),
            "isp": data.get(
                "isp",
                "Not Found",
            ),
            "asn": (
                f"AS{data['as'].split(' ', 1)[0].replace('AS', '')}"
                if data.get("as")
                else "Not Found"
            ),
        }

    except Exception:
        return {
            "country": "Not Found",
            "city": "Not Found",
            "isp": "Not Found",
            "asn": "Not Found",
        }


def fetch_web(url):
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": f"{APP_NAME}/{VERSION}",
        },
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=6,
            context=ssl.create_default_context(),
        ) as response:
            body = response.read(
                32768
            ).decode(
                "utf-8",
                errors="ignore",
            )

            return {
                "status": response.status,
                "headers": dict(response.headers),
                "body": body,
            }

    except urllib.error.HTTPError as error:
        return {
            "status": error.code,
            "headers": dict(error.headers),
            "body": "",
        }

    except (
        urllib.error.URLError,
        TimeoutError,
        OSError,
    ):
        return None


def extract_title(html):
    if not html:
        return "Not Found"

    match = re.search(
        r"<title[^>]*>(.*?)</title>",
        html,
        re.IGNORECASE | re.DOTALL,
    )

    if not match:
        return "Not Found"

    return re.sub(
        r"\s+",
        " ",
        match.group(1),
    ).strip() or "Not Found"


def detect_technologies(data):
    if not data:
        return []

    headers = {
        key.lower(): value
        for key, value in data["headers"].items()
    }

    body = data["body"].lower()

    found = set()

    server = headers.get(
        "server",
        "",
    ).lower()

    powered_by = headers.get(
        "x-powered-by",
        "",
    ).lower()

    if "cloudflare" in server:
        found.add("Cloudflare")

    if "nginx" in server:
        found.add("Nginx")

    if "apache" in server:
        found.add("Apache")

    if "php" in powered_by or "php" in body:
        found.add("PHP")

    if "bootstrap" in body:
        found.add("Bootstrap")

    if "jquery" in body:
        found.add("jQuery")

    if "react" in body:
        found.add("React")

    if "vue" in body:
        found.add("Vue")

    if "wordpress" in body:
        found.add("WordPress")

    return sorted(found)


def extract_security_headers(data):
    headers = {}

    if data:
        headers = {
            key.lower(): value
            for key, value in data["headers"].items()
        }

    return {
        "HSTS": (
            "Present"
            if "strict-transport-security" in headers
            else "Missing"
        ),
        "CSP": (
            "Present"
            if "content-security-policy" in headers
            else "Missing"
        ),
        "X-Frame-Options": (
            "Present"
            if "x-frame-options" in headers
            else "Missing"
        ),
        "X-Content-Type": (
            "Present"
            if "x-content-type-options" in headers
            else "Missing"
        ),
    }


def enumerate_subdomains(domain):
    found = []

    for prefix in COMMON_SUBDOMAINS:
        hostname = f"{prefix}.{domain}"

        try:
            socket.gethostbyname(hostname)
            found.append(hostname)
        except socket.gaierror:
            continue

    return sorted(set(found))


def inspect_ssl(domain):
    result = {
        "issuer": "Not Found",
        "valid_until": "Not Found",
    }

    try:
        context = ssl.create_default_context()

        with socket.create_connection(
            (domain, 443),
            timeout=5,
        ) as raw_socket:

            with context.wrap_socket(
                raw_socket,
                server_hostname=domain,
            ) as ssl_socket:

                certificate = ssl_socket.getpeercert()

                issuer = []

                for item in certificate.get(
                    "issuer",
                    [],
                ):
                    for key, value in item:
                        if key == "organizationName":
                            issuer.append(str(value))

                result["issuer"] = (
                    ", ".join(issuer)
                    if issuer
                    else "Not Found"
                )

                result["valid_until"] = (
                    certificate.get(
                        "notAfter",
                        "Not Found",
                    )
                )

    except (
        OSError,
        ssl.SSLError,
        socket.timeout,
    ):
        pass

    return result


def collect_osint(target, progress=None):
    """
    Collect public OSINT information.

    progress(message) is called for each visible step.
    """

    def emit(message):
        if progress:
            progress(message)

    domain = normalize_target(target)

    report = {
        "target": domain,
        "ip_address": "Not Found",
        "status": "Unreachable",
        "whois": {
            "registrar": "Not Found",
            "created": "Not Found",
            "expires": "Not Found",
            "status": "Unknown",
        },
        "geolocation": {
            "country": "Not Found",
            "city": "Not Found",
            "isp": "Not Found",
            "asn": "Not Found",
        },
        "dns": {
            "a": [],
            "aaaa": [],
            "mx": [],
            "ns": [],
        },
        "subdomains": [],
        "web": {
            "server": "Not Found",
            "powered_by": "Not Found",
            "http_status": "Not Found",
            "title": "Not Found",
        },
        "security": {
            "HSTS": "Missing",
            "CSP": "Missing",
            "X-Frame-Options": "Missing",
            "X-Content-Type": "Missing",
        },
        "ssl": {
            "issuer": "Not Found",
            "valid_until": "Not Found",
        },
        "technologies": [],
    }

    # 1. Resolving domain
    emit("[*] Resolving domain...")

    a_records = resolve_a(domain)
    aaaa_records = resolve_aaaa(domain)

    report["dns"]["a"] = a_records
    report["dns"]["aaaa"] = aaaa_records

    if a_records:
        report["ip_address"] = a_records[0]
        report["status"] = "Reachable"

    emit("[✓] Domain resolved")

    # 2. WHOIS
    emit("[*] Collecting WHOIS...")

    rdap = get_rdap(domain)
    report["whois"] = parse_rdap(rdap)

    emit("[✓] Done")

    # 3. DNS
    emit("[*] Enumerating DNS...")

    report["dns"]["mx"] = resolve_mx(domain)
    report["dns"]["ns"] = resolve_ns(domain)

    emit("[✓] Done")

    # 4. Subdomains
    emit("[*] Searching subdomains...")

    report["subdomains"] = enumerate_subdomains(
        domain
    )

    emit("[✓] Done")

    # 5. Web technologies
    emit("[*] Checking web technologies...")

    https_data = fetch_web(
        f"https://{domain}"
    )

    http_data = None

    if https_data is None:
        http_data = fetch_web(
            f"http://{domain}"
        )

    web_data = (
        https_data
        if https_data is not None
        else http_data
    )

    if web_data:
        headers = {
            key.lower(): value
            for key, value in web_data["headers"].items()
        }

        report["web"] = {
            "server": headers.get(
                "server",
                "Not Found",
            ),
            "powered_by": headers.get(
                "x-powered-by",
                "Not Found",
            ),
            "http_status": str(
                web_data["status"]
            ),
            "title": extract_title(
                web_data["body"]
            ),
        }

        report["security"] = (
            extract_security_headers(
                web_data
            )
        )

        report["technologies"] = (
            detect_technologies(
                web_data
            )
        )

    emit("[✓] Done")

    # 6. SSL
    emit("[*] Analyzing SSL certificate...")

    report["ssl"] = inspect_ssl(domain)

    emit("[✓] Done")

    # 7. Geolocation
    if report["ip_address"] != "Not Found":
        report["geolocation"] = geolocate(
            report["ip_address"]
        )

    # 8. Report
    emit("[*] Generating report...")
    emit("[✓] Complete")

    return report
