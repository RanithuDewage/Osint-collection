import os
import platform
import re
import socket
import subprocess

from config.settings import APP_NAME


def format_dns_result(result):
    domain = result.get("domain", "Unknown")
    resolved = result.get("resolved", False)
    ip = result.get("ip")

    if resolved and ip:
        return (
            f"Target: {domain}\n"
            f"Resolved IP: {ip}"
        )

    return (
        f"Target: {domain}\n"
        "DNS Resolution Failed"
    )


def get_hostname(ip):
    """
    Try to resolve an IP address to a hostname.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname

    except (
        socket.herror,
        socket.gaierror,
        OSError,
    ):
        return ip


def _force_arp_resolution(ip, timeout=1):
    """
    Send a single ordinary ping to the target. This makes
    the operating system's own network stack resolve the
    target's MAC address and store it in its ARP/neighbour
    table — no scapy, no libpcap/Npcap, no root/admin needed,
    since it uses the standard 'ping' utility rather than a
    raw socket.
    """
    system = platform.system()

    try:
        if system == "Windows":
            system_root = os.environ.get(
                "SystemRoot",
                "C:\\Windows",
            )

            ping_path = os.path.join(
                system_root,
                "System32",
                "PING.EXE",
            )

            command = [
                ping_path,
                "-n", "1",
                "-w", str(int(timeout * 1000)),
                ip,
            ]
        else:
            command = [
                "ping",
                "-c", "1",
                "-W", str(int(timeout)),
                ip,
            ]

        subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout + 1,
        )

    except (
        subprocess.TimeoutExpired,
        OSError,
        subprocess.SubprocessError,
    ):
        pass

    # Also attempt a raw TCP connect. This uses only the
    # standard 'socket' module (no external binary needed,
    # so it still works if 'ping' isn't installed/available),
    # and it forces the same kernel-level ARP resolution even
    # if the target's firewall blocks ICMP (ping).
    for port in (443, 80, 445, 139):
        try:
            probe = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM,
            )
            probe.settimeout(timeout)

            try:
                probe.connect((ip, port))
            except OSError:
                pass
            finally:
                probe.close()

            break

        except Exception:
            continue


def _get_mac_via_scapy(ip, timeout=2):
    """
    Actively resolve the MAC address by sending a real
    ARP request via scapy. Requires libpcap/Npcap to be
    installed and root/administrator privileges to send
    raw layer-2 frames — used only as a last resort, since
    it isn't available in every environment.

    Only works for hosts on the same local network segment
    (ARP does not cross routers) — this is a networking
    limitation, not a bug.
    """
    try:
        import logging

        logging.getLogger("scapy.runtime").setLevel(
            logging.ERROR
        )

        from scapy.all import ARP, Ether, srp

        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request

        answered, _ = srp(
            packet,
            timeout=timeout,
            verbose=False,
        )

        if answered:
            return answered[0][1].hwsrc.upper()

    except Exception:
        pass

    return None


def _read_proc_net_arp(ip):
    """
    Read the MAC address directly from /proc/net/arp. This
    is a plain file read — no external binary, no PATH
    dependency, works inside containers/WSL as long as
    procfs is mounted (virtually always the case on Linux).
    """
    try:
        with open("/proc/net/arp", "r") as arp_file:
            lines = arp_file.readlines()[1:]

        for line in lines:
            fields = line.split()

            if len(fields) >= 4 and fields[0] == ip:
                mac = fields[3]

                if mac and mac != "00:00:00:00:00:00":
                    return mac.upper()

    except (FileNotFoundError, OSError):
        pass

    return None


def _get_mac_via_os_table(ip):
    """
    Fallback: read the MAC address from the OS neighbour
    table, if an entry already exists there. Cross-platform
    (Linux / macOS / Windows), unlike relying on 'ip neigh'
    alone which only exists on Linux.
    """
    system = platform.system()

    try:
        if system == "Linux":

            mac = _read_proc_net_arp(ip)

            if mac:
                return mac

            result = subprocess.run(
                ["ip", "neigh", "show", ip],
                capture_output=True,
                text=True,
                check=False,
                timeout=2,
            )

            parts = result.stdout.split()

            if "lladdr" in parts:
                index = parts.index("lladdr")

                if index + 1 < len(parts):
                    return parts[index + 1].upper()

        elif system in ("Darwin", "Windows"):

            if system == "Windows":
                system_root = os.environ.get(
                    "SystemRoot",
                    "C:\\Windows",
                )

                arp_path = os.path.join(
                    system_root,
                    "System32",
                    "ARP.EXE",
                )

                arp_command = [arp_path, "-a", ip]

            else:
                arp_command = ["arp", "-n", ip]

            result = subprocess.run(
                arp_command,
                capture_output=True,
                text=True,
                check=False,
                timeout=2,
            )

            match = re.search(
                r"([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}",
                result.stdout,
            )

            if match:
                return match.group(0).upper().replace("-", ":")

    except (
        subprocess.TimeoutExpired,
        OSError,
        subprocess.SubprocessError,
    ):
        pass

    return None


def get_mac_address(ip):
    """
    Try to get the MAC address of a host on the local
    network. First sends a plain ping to force the OS to
    resolve the target's MAC into its own ARP table, then
    reads it from there (works everywhere, no extra
    dependencies). Falls back to an active scapy ARP
    request only if that fails and scapy/libpcap happen to
    be available.

    Returns "Unknown" if the host is not on the local
    network segment, or if no reply/entry is found.
    """
    _force_arp_resolution(ip)

    mac = _get_mac_via_os_table(ip)

    if mac:
        return mac

    mac = _get_mac_via_scapy(ip)

    if mac:
        return mac

    if mac:
        return mac

    return "Unknown"


def format_single_host_result(ip, status="ONLINE"):
    """
    Format single-host information with dynamically
    calculated column widths.
    """
    hostname = get_hostname(ip)

    rows = [
        ("Device", hostname),
        ("IP Address", ip),
        ("Network Status", status),
    ]

    label_width = max(
        len("Field"),
        max(
            len(label)
            for label, _ in rows
        ),
    )

    value_width = max(
        len("Value"),
        max(
            len(str(value))
            for _, value in rows
        ),
    )

    padding = 2

    label_width += padding
    value_width += padding

    table_width = (
        label_width
        + value_width
        + 1
    )

    top = "┌" + "─" * table_width + "┐"

    bottom = (
        "└"
        + "─" * label_width
        + "┴"
        + "─" * value_width
        + "┘"
    )

    separator = (
        "├"
        + "─" * label_width
        + "┼"
        + "─" * value_width
        + "┤"
    )

    title = (
        "│"
        + "HOST INFORMATION".center(table_width)
        + "│"
    )

    lines = [
        "",
        top,
        title,
        separator,
    ]

    for label, value in rows:
        lines.append(
            "│"
            + label.ljust(label_width)
            + "│"
            + str(value).ljust(value_width)
            + "│"
        )

    lines.extend(
        [
            bottom,
            "",
        ]
    )

    return "\n".join(lines)


def format_port_results(
    results,
    include_legacy=True,
    target=None,
    hostname=None,
    mac=None,
):
    """
    Format device information and port assessment
    side-by-side when target information is available.

    include_legacy=True keeps compatibility with
    existing tests.
    """

    services = {
        21: "FTP",
        22: "SSH",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        3306: "MySQL",
        8080: "HTTP-ALT",
    }

    rows = []

    for port, is_open in sorted(results.items()):
        rows.append(
            {
                "port": str(port),
                "status": (
                    "OPEN"
                    if is_open
                    else "CLOSED"
                ),
                "service": services.get(
                    port,
                    "Unknown",
                ),
            }
        )

    if not rows:
        rows.append(
            {
                "port": "-",
                "status": "UNKNOWN",
                "service": "No ports",
            }
        )

    # -----------------------------
    # PORT TABLE
    # -----------------------------

    port_width = max(
        len("Port"),
        max(
            len(row["port"])
            for row in rows
        ),
    ) + 2

    status_width = max(
        len("Status"),
        max(
            len(row["status"])
            for row in rows
        ),
    ) + 2

    service_width = max(
        len("Service"),
        max(
            len(row["service"])
            for row in rows
        ),
    ) + 2

    port_total_width = (
        port_width
        + status_width
        + service_width
        + 2
    )

    port_top = (
        "┌"
        + "─" * port_total_width
        + "┐"
    )

    port_title = (
        "│"
        + "PORT ASSESSMENT".center(
            port_total_width
        )
        + "│"
    )

    port_separator = (
        "├"
        + "─" * port_width
        + "┬"
        + "─" * status_width
        + "┬"
        + "─" * service_width
        + "┤"
    )

    port_row_separator = (
        "├"
        + "─" * port_width
        + "┼"
        + "─" * status_width
        + "┼"
        + "─" * service_width
        + "┤"
    )

    port_header = (
        "│"
        + "Port".center(port_width)
        + "│"
        + "Status".center(status_width)
        + "│"
        + "Service".center(service_width)
        + "│"
    )

    port_bottom = (
        "└"
        + "─" * port_width
        + "┴"
        + "─" * status_width
        + "┴"
        + "─" * service_width
        + "┘"
    )

    port_lines = [
        port_top,
        port_title,
        port_separator,
        port_header,
        port_row_separator,
    ]

    for row in rows:
        port_lines.append(
            "│"
            + row["port"].center(port_width)
            + "│"
            + row["status"].center(status_width)
            + "│"
            + row["service"].ljust(service_width)
            + "│"
        )

    port_lines.append(port_bottom)

    # -----------------------------
    # DEVICE TABLE
    # -----------------------------

    if target is not None:
        device_name = (
            hostname
            if hostname
            else get_hostname(target)
        )

        device_mac = (
            mac
            if mac
            else get_mac_address(target)
        )

        device_rows = [
            ("Target IP", str(target)),
            ("Hostname", str(device_name)),
            ("MAC Address", str(device_mac)),
        ]

        label_width = max(
            len("Field"),
            max(
                len(label)
                for label, _ in device_rows
            ),
        ) + 2

        value_width = max(
            len("Value"),
            max(
                len(str(value))
                for _, value in device_rows
            ),
        ) + 2

        device_total_width = (
            label_width
            + value_width
            + 1
        )

        device_top = (
            "┌"
            + "─" * device_total_width
            + "┐"
        )

        device_title = (
            "│"
            + "DEVICE INFORMATION".center(
                device_total_width
            )
            + "│"
        )

        device_separator = (
            "├"
            + "─" * label_width
            + "┼"
            + "─" * value_width
            + "┤"
        )

        device_bottom = (
            "└"
            + "─" * label_width
            + "┴"
            + "─" * value_width
            + "┘"
        )

        device_lines = [
            device_top,
            device_title,
            device_separator,
        ]

        for label, value in device_rows:
            device_lines.append(
                "│"
                + label.ljust(label_width)
                + "│"
                + str(value).ljust(value_width)
                + "│"
            )

        device_lines.append(device_bottom)

    else:
        device_lines = []

    # -----------------------------
    # SIDE-BY-SIDE DISPLAY
    # -----------------------------

    if device_lines:
        device_height = len(device_lines)
        port_height = len(port_lines)

        device_width = max(
            len(line)
            for line in device_lines
        )

        port_width_total = max(
            len(line)
            for line in port_lines
        )

        if device_height < port_height:
            device_lines.extend(
                [
                    " " * device_width
                    for _ in range(
                        port_height - device_height
                    )
                ]
            )

        elif port_height < device_height:
            port_lines.extend(
                [
                    " " * port_width_total
                    for _ in range(
                        device_height - port_height
                    )
                ]
            )

        gap = "   "

        output = [
            "",
            *[
                left.ljust(device_width)
                + gap
                + right.ljust(port_width_total)
                for left, right in zip(
                    device_lines,
                    port_lines,
                )
            ],
        ]

    else:
        output = [
            "",
            *port_lines,
        ]

    # -----------------------------
    # LEGACY TEST OUTPUT
    # -----------------------------

    if include_legacy:
        output.append("")

        for port, is_open in sorted(
            results.items()
        ):
            status = (
                "OPEN"
                if is_open
                else "CLOSED"
            )

            output.append(
                f"{port:<5} {status}"
            )

    return "\n".join(output)


def format_network_results(hosts, target):
    """
    Format CIDR network discovery results
    with dynamically calculated widths.
    """

    rows = []

    for host in hosts:
        rows.append(
            {
                "ip": str(host),
                "hostname": str(
                    get_hostname(host)
                ),
                "status": "ONLINE",
            }
        )

    if not rows:
        rows.append(
            {
                "ip": "No hosts found",
                "hostname": "-",
                "status": "OFFLINE",
            }
        )

    padding = 2

    ip_width = max(
        len("IP Address"),
        max(
            len(row["ip"])
            for row in rows
        ),
    ) + padding

    hostname_width = max(
        len("Hostname"),
        max(
            len(row["hostname"])
            for row in rows
        ),
    ) + padding

    status_width = max(
        len("Status"),
        max(
            len(row["status"])
            for row in rows
        ),
    ) + padding

    table_width = (
        ip_width
        + hostname_width
        + status_width
        + 2
    )

    top = "┌" + "─" * table_width + "┐"

    bottom = (
        "└"
        + "─" * ip_width
        + "┴"
        + "─" * hostname_width
        + "┴"
        + "─" * status_width
        + "┘"
    )

    title = (
        "│"
        + "NETWORK DISCOVERY".center(
            table_width
        )
        + "│"
    )

    separator = (
        "├"
        + "─" * ip_width
        + "┬"
        + "─" * hostname_width
        + "┬"
        + "─" * status_width
        + "┤"
    )

    row_separator = (
        "├"
        + "─" * ip_width
        + "┼"
        + "─" * hostname_width
        + "┼"
        + "─" * status_width
        + "┤"
    )

    header = (
        "│"
        + "IP Address".center(ip_width)
        + "│"
        + "Hostname".center(
            hostname_width
        )
        + "│"
        + "Status".center(status_width)
        + "│"
    )

    lines = [
        "",
        top,
        title,
        separator,
        header,
        row_separator,
    ]

    for row in rows:
        lines.append(
            "│"
            + row["ip"].ljust(ip_width)
            + "│"
            + row["hostname"].ljust(
                hostname_width
            )
            + "│"
            + row["status"].center(
                status_width
            )
            + "│"
        )

    summary_separator = (
        "├"
        + "─" * table_width
        + "┤"
    )

    target_text = (
        f"Target      : {target}"
    )

    hosts_text = (
        f"Hosts found : {len(hosts)}"
    )

    lines.extend(
        [
            summary_separator,
            "│"
            + target_text.ljust(
                table_width
            )
            + "│",
            "│"
            + hosts_text.ljust(
                table_width
            )
            + "│",
            bottom,
            "",
        ]
    )

    return "\n".join(lines)


def format_osint_result(result):
    """
    Format OSINT information as a dynamic terminal box.
    """

    ips = result.get("ips", [])
    reverse_dns = result.get(
        "reverse_dns",
        [],
    )

    ip_text = ", ".join(ips) if ips else "Unknown"
    reverse_text = (
        ", ".join(reverse_dns)
        if reverse_dns
        else "Unknown"
    )

    rows = [
        ("Target", result.get("target", "Unknown")),
        ("IP Addresses", ip_text),
        ("Reverse DNS", reverse_text),
        ("HTTPS", result.get("https_status", "Unknown")),
        ("HTTP", result.get("http_status", "Unknown")),
        ("Page Title", result.get("title", "Unknown")),
        ("Server", result.get("server", "Unknown")),
        ("Powered By", result.get("powered_by", "Unknown")),
        ("robots.txt", result.get("robots", "Unknown")),
    ]

    label_width = max(
        len(label)
        for label, _ in rows
    ) + 2

    value_width = max(
        len(str(value))
        for _, value in rows
    ) + 2

    table_width = (
        label_width
        + value_width
        + 1
    )

    top = "┌" + "─" * table_width + "┐"

    separator = (
        "├"
        + "─" * label_width
        + "┼"
        + "─" * value_width
        + "┤"
    )

    bottom = (
        "└"
        + "─" * label_width
        + "┴"
        + "─" * value_width
        + "┘"
    )

    lines = [
        "",
        top,
        "│"
        + "OSINT INFORMATION".center(table_width)
        + "│",
        separator,
    ]

    for label, value in rows:
        lines.append(
            "│"
            + label.ljust(label_width)
            + "│"
            + str(value).ljust(value_width)
            + "│"
        )

    lines.extend(
        [
            bottom,
            "",
        ]
    )

    return "\n".join(lines)
def format_osint_report(report):
    target = report.get("target", "Unknown")
    ip = report.get("ip_address", "Not Found")
    status = report.get("status", "Unknown")

    whois = report.get("whois", {})
    geo = report.get("geolocation", {})
    dns = report.get("dns", {})
    web = report.get("web", {})
    security = report.get("security", {})
    ssl_data = report.get("ssl", {})
    subdomains = report.get("subdomains", [])
    technologies = report.get("technologies", [])

    width = 52

    lines = [
        "",
        "╔" + "═" * width + "╗",
        "║"
        + f"{APP_NAME.upper()} OSINT REPORT".center(width)
        + "║",
        "╚" + "═" * width + "╝",
        "",
        f"Target      : {target}",
        f"IP Address  : {ip}",
        f"Status      : {status}",
        "",
        "─" * width,
        "",
        "[ WHOIS ]",
        "",
        f"Registrar      : {whois.get('registrar', 'Not Found')}",
        f"Created        : {whois.get('created', 'Not Found')}",
        f"Expires        : {whois.get('expires', 'Not Found')}",
        f"Status         : {whois.get('status', 'Unknown')}",
        "",
        "─" * width,
        "",
        "[ GEOLOCATION ]",
        "",
        f"Country         : {geo.get('country', 'Not Found')}",
        f"City            : {geo.get('city', 'Not Found')}",
        f"ISP             : {geo.get('isp', 'Not Found')}",
        f"ASN             : {geo.get('asn', 'Not Found')}",
        "",
        "─" * width,
        "",
        "[ DNS RECORDS ]",
        "",
        "A Record        : "
        + (
            ", ".join(dns.get("a", []))
            if dns.get("a")
            else "Not Found"
        ),
        "AAAA Record     : "
        + (
            ", ".join(dns.get("aaaa", []))
            if dns.get("aaaa")
            else "Not Found"
        ),
        "MX Record       : "
        + (
            ", ".join(dns.get("mx", []))
            if dns.get("mx")
            else "Not Found"
        ),
        "NS Records      :",
    ]

    ns_records = dns.get("ns", [])

    if ns_records:
        lines.extend(
            f"    {record}"
            for record in ns_records
        )
    else:
        lines.append("    Not Found")

    lines.extend(
        [
            "",
            "─" * width,
            "",
            "[ SUBDOMAINS ]",
            "",
        ]
    )

    if subdomains:
        lines.extend(
            f"✓ {subdomain}"
            for subdomain in subdomains
        )
    else:
        lines.append("None found")

    lines.extend(
        [
            "",
            f"Total : {len(subdomains)}",
            "",
            "─" * width,
            "",
            "[ WEB SERVER ]",
            "",
            f"Server          : {web.get('server', 'Not Found')}",
            f"Powered By      : {web.get('powered_by', 'Not Found')}",
            f"HTTP Status     : {web.get('http_status', 'Not Found')}",
            f"Title           : {web.get('title', 'Not Found')}",
            "",
            "─" * width,
            "",
            "[ SECURITY HEADERS ]",
            "",
            f"HSTS            : {security.get('HSTS', 'Missing')}",
            f"CSP             : {security.get('CSP', 'Missing')}",
            f"X-Frame-Options : {security.get('X-Frame-Options', 'Missing')}",
            f"X-Content-Type  : {security.get('X-Content-Type', 'Missing')}",
            "",
            "─" * width,
            "",
            "[ SSL CERTIFICATE ]",
            "",
            f"Issuer          : {ssl_data.get('issuer', 'Not Found')}",
            f"Valid Until     : {ssl_data.get('valid_until', 'Not Found')}",
            "",
            "─" * width,
            "",
            "[ TECHNOLOGIES ]",
            "",
        ]
    )

    if technologies:
        lines.extend(
            f"• {technology}"
            for technology in technologies
        )
    else:
        lines.append("None detected")

    lines.extend(
        [
            "",
            "─" * width,
            "",
            "Scan Finished Successfully",
            "",
        ]
    )

    return "\n".join(lines)