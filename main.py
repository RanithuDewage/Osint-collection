import argparse
import os
import sys

from config.settings import APP_NAME, VERSION, DESCRIPTION

from modules.core.runner import ModuleRunner
from modules.reconnaissance.network import discover_hosts
from modules.reconnaissance.osint import collect_osint
from modules.reconnaissance.ports import assess_ports

from utils.formatter import (
    format_network_results,
    format_osint_report,
    format_port_results,
    format_single_host_result,
    get_hostname,
    get_mac_address,
)

from utils.logger import get_logger

from utils.report_export import (
    save_pdf,
    save_txt,
)

from utils.spinner import (
    boot_animation,
    run_with_spinner,
)

from utils.validators import (
    is_domain_target,
    parse_network_target,
    parse_single_ip,
)

logger = get_logger(f"{APP_NAME.lower()}.main")


# ============================================================
# SCREEN
# ============================================================

def clear_screen():
    os.system(
        "cls" if os.name == "nt" else "clear"
    )


# ============================================================
# BANNER
# ============================================================

def print_banner():
    width = 54
    title = " ".join(list(APP_NAME.upper()))

    print()
    print("╔" + "═" * width + "╗")
    print("║" + " " * width + "║")
    print(
        "║"
        + title.center(width)
        + "║"
    )
    print("║" + " " * width + "║")
    print(
        "║"
        + "Network Recon Framework".center(width)
        + "║"
    )
    print(
        "║"
        + f"Version {VERSION}".center(width)
        + "║"
    )
    print("║" + " " * width + "║")
    print("╚" + "═" * width + "╝")
    print()


# ============================================================
# SECTION
# ============================================================

def print_section(title):
    width = 54

    print()
    print("╭" + "─" * width + "╮")
    print(
        "│"
        + title.center(width)
        + "│"
    )
    print("╰" + "─" * width + "╯")
    print()


# ============================================================
# MAIN MENU
# ============================================================

def print_main_menu():

    width = 54

    title = "MAIN MENU"

    items = [
        "[1]  Discover Network",
        "[2]  Scan Ports",
        "[3]  OSINT",
        "[4]  Launch Graphical UI (GUI)",
        "[5]  Exit",
    ]

    print("┌" + "─" * width + "┐")

    print(
        "│"
        + title.center(width)
        + "│"
    )

    print("├" + "─" * width + "┤")

    print("│" + " " * width + "│")

    for item in items:
        print(
            "│   "
            + item.ljust(width - 3)
            + "│"
        )

    print("│" + " " * width + "│")

    print("└" + "─" * width + "┘")

    print()


# ============================================================
# MENU NAVIGATION
# ============================================================

def return_to_menu_now():

    clear_screen()
    print_banner()
    print_main_menu()


def wait_and_return_to_menu():

    try:
        input(
            "\nPress Enter to continue..."
        )
    except EOFError:
        pass

    return_to_menu_now()


# ============================================================
# TARGET VALIDATION
# ============================================================
#
# parse_network_target / parse_single_ip / is_domain_target
# now live in utils/validators.py to avoid having two
# separate (and inconsistent) copies of the same logic.



# ============================================================
# INVALID IP
# ============================================================

def print_same_line_invalid_ip(
    prompt,
    target,
):

    print(
        f"{prompt}{target} => Invalid IP"
    )


# ============================================================
# NETWORK DISCOVERY
# ============================================================

def run_network(runner):

    print_section(
        "NETWORK DISCOVERY"
    )

    prompt = "Target Network: "

    target = input(
        prompt
    ).strip()

    parsed_target = parse_network_target(
        target
    )

    if parsed_target is None:

        print_same_line_invalid_ip(
            "",
            f"{prompt}{target}"
        )

        try:
            input(
                "\nPress Enter to continue..."
            )
        except EOFError:
            pass

        return

    print()

    try:

        result = run_with_spinner(
            "Scanning network...",
            discover_hosts,
            target,
        )

        if result is None:
            result = []

        if not isinstance(
            result,
            (list, tuple, set),
        ):
            result = list(result)

        # ----------------------------------------------------
        # SINGLE IP
        # ----------------------------------------------------

        if parsed_target.prefixlen == 32:

            host = str(
                parsed_target.network_address
            )

            status = (
                "ONLINE"
                if host in result
                else "OFFLINE"
            )

            print(
                format_single_host_result(
                    host,
                    status=status,
                )
            )

        # ----------------------------------------------------
        # CIDR NETWORK
        # ----------------------------------------------------

        else:

            print(
                format_network_results(
                    result,
                    target,
                )
            )

    except Exception as error:

        logger.error(
            "Network scan failed for target=%s: %s",
            target,
            error,
        )

        print()
        print(
            "Network scan failed."
        )
        print(
            f"Error: {error}"
        )
        print()

    try:

        input(
            "\nPress Enter to return to Main Menu..."
        )

    except EOFError:

        pass


# ============================================================
# PORT SCANNING
# ============================================================

def run_ports(runner):

    print_section(
        "PORT ASSESSMENT"
    )

    prompt = "Target IP: "

    target_input = input(
        prompt
    ).strip()

    target_ip = parse_single_ip(
        target_input
    )

    if target_ip is None:

        print_same_line_invalid_ip(
            prompt,
            target_input,
        )

        try:
            input(
                "\nPress Enter to continue..."
            )
        except EOFError:
            pass

        return

    target = str(
        target_ip
    )

    ports_input = input(
        "Ports: "
    ).strip()

    if not ports_input:

        print(
            " => Invalid port list"
        )

        wait_and_return_to_menu()
        return

    try:

        selected_ports = [
            int(port.strip())
            for port in ports_input.split(",")
        ]

    except ValueError:

        print(
            " => Invalid port list"
        )

        wait_and_return_to_menu()
        return

    selected_ports = [
        port
        for port in selected_ports
        if 1 <= port <= 65535
    ]

    if not selected_ports:

        print(
            " => Invalid port list"
        )

        wait_and_return_to_menu()
        return

    selected_ports = list(
        dict.fromkeys(
            selected_ports
        )
    )

    print()

    try:

        selected_results = run_with_spinner(
            "Scanning selected ports...",
            assess_ports,
            target,
            selected_ports,
        )

        hostname = run_with_spinner(
            "Resolving hostname...",
            get_hostname,
            target,
        )

        mac = run_with_spinner(
            "Resolving MAC address...",
            get_mac_address,
            target,
        )

        print(
            format_port_results(
                selected_results,
                include_legacy=False,
                target=target,
                hostname=hostname,
                mac=mac,
            )
        )

    except Exception as error:

        logger.error(
            "Port scan failed for target=%s ports=%s: %s",
            target,
            selected_ports,
            error,
        )

        print(
            f"\nError: {error}"
        )

        wait_and_return_to_menu()
        return

    common_ports = [
        21,
        22,
        25,
        53,
        80,
        110,
        143,
        443,
        3306,
        8080,
    ]

    remaining_ports = [
        port
        for port in common_ports
        if port not in selected_ports
    ]

    if not remaining_ports:

        wait_and_return_to_menu()
        return

    print()

    try:

        answer = input(
            "Scan remaining common ports? [Y/N]: "
        ).strip().lower()

    except EOFError:

        return

    if answer == "y":

        print()

        try:

            remaining_results = run_with_spinner(
                "Scanning remaining common ports...",
                assess_ports,
                target,
                remaining_ports,
            )

            print(
                format_port_results(
                    remaining_results,
                    include_legacy=False,
                )
            )

        except Exception as error:

            logger.error(
                "Remaining ports scan failed for target=%s ports=%s: %s",
                target,
                remaining_ports,
                error,
            )

            print(
                f"\nError: {error}"
            )

        wait_and_return_to_menu()
        return

    if answer == "n":

        return

    return


# ============================================================
# OSINT
# ============================================================

def run_osint():

    print_section(
        "OSINT INFORMATION"
    )

    prompt = "Domain: "

    target = input(
        prompt
    ).strip()

    if not target:

        print(
            " => Invalid Domain"
        )

        wait_and_return_to_menu()
        return False

    if not is_domain_target(
        target
    ):

        print(
            " => Invalid Domain"
        )

        wait_and_return_to_menu()
        return False

    clear_screen()

    # ========================================================
    # OSINT SCAN HEADER
    # ========================================================

    width = 54

    print()

    print(
        "╭" + "─" * width + "╮"
    )

    print(
        "│"
        + "B L A C K B O X".center(width)
        + "│"
    )

    print(
        "│"
        + "OSINT RECONNAISSANCE".center(width)
        + "│"
    )

    print(
        "│"
        + "Open Source Intelligence".center(width)
        + "│"
    )

    print(
        "╰" + "─" * width + "╯"
    )

    print()

    try:

        report = collect_osint(
            target,
            progress=print,
        )

    except Exception as error:

        logger.error(
            "OSINT collection failed for target=%s: %s",
            target,
            error,
        )

        print(
            f"\nError: {error}"
        )

        wait_and_return_to_menu()
        return False

    clear_screen()

    report_text = format_osint_report(
        report
    )

    print(
        report_text
    )

    print(
        "────────────────────────────────────────────────────"
    )

    print()

    print(
        "[1] Save Report (.txt)"
    )

    print(
        "[2] Save Report (.pdf)"
    )

    print(
        "[3] Return to Main Menu"
    )

    print(
        "[4] Exit"
    )

    print()

    while True:

        try:

            choice = input(
                "Choice: "
            ).strip()

        except EOFError:

            return False

        if choice == "1":

            try:

                path = save_txt(
                    report
                )

                print(
                    f"\nReport saved: {path}"
                )

            except Exception as error:

                logger.error(
                    "Saving TXT report failed: %s",
                    error,
                )

                print(
                    f"\nError saving report: {error}"
                )

            continue

        if choice == "2":

            try:

                path = save_pdf(
                    report
                )

                print(
                    f"\nReport saved: {path}"
                )

            except Exception as error:

                logger.error(
                    "Saving PDF report failed: %s",
                    error,
                )

                print(
                    f"\nError saving PDF: {error}"
                )

            continue

        if choice == "3":

            return False

        if choice == "4":

            clear_screen()

            print(
                "Goodbye!"
            )

            print()

            return True

        print(
            "\nInvalid choice."
        )


# ============================================================
# INTERACTIVE MENU
# ============================================================

def interactive_menu(runner):

    clear_screen()
    boot_animation()

    while True:

        clear_screen()

        print_banner()

        print_main_menu()

        try:

            choice = input(
                "Select option: "
            ).strip()

        except EOFError:

            return 0

        if choice == "1":

            run_network(
                runner
            )

        elif choice == "2":

            run_ports(
                runner
            )

        elif choice == "3":

            should_exit = run_osint()

            if should_exit:
                return 0

        elif choice in ("4", "g", "G"):

            try:
                from gui import launch_gui
                launch_gui()
            except Exception as e:
                print(f"\nFailed to launch GUI: {e}")
                input("\nPress Enter to continue...")

        elif choice in ("5", "q", "Q"):

            clear_screen()

            print(
                "Goodbye!"
            )

            print()

            return 0

        else:

            print()
            print(
                "Invalid choice."
            )

            try:

                input(
                    "\nPress Enter to continue..."
                )

            except EOFError:

                return 0


# ============================================================
# ARGUMENT PARSER
# ============================================================

def build_parser():

    parser = argparse.ArgumentParser(
        description=f"{APP_NAME} Framework"
    )

    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch the Modern Desktop Graphical Interface (GUI)",
    )

    parser.add_argument(
        "--target",
        required=False,
        help=(
            "IP address, CIDR network, "
            "or domain"
        ),
    )

    parser.add_argument(
        "--module",
        choices=[
            "network",
            "ports",
            "osint",
        ],
        help="Reconnaissance module",
    )

    parser.add_argument(
        "--list-modules",
        action="store_true",
        help=(
            "List available reconnaissance modules"
        ),
    )

    return parser


# ============================================================
# MAIN
# ============================================================

def main():

    parser = build_parser()

    args = parser.parse_args()

    if args.gui:
        from gui import launch_gui
        launch_gui()
        return 0

    runner = ModuleRunner()

    # ========================================================
    # LIST MODULES
    # ========================================================

    if args.list_modules:

        print_banner()

        print(
            "Available modules:"
        )

        for module in runner.list_modules():

            print(
                f"- {module}"
            )

        return 0

    # ========================================================
    # DIRECT CLI MODE
    # ========================================================

    if args.target is not None:

        print_banner()

        # ----------------------------------------------------
        # TARGET WITHOUT MODULE
        # ----------------------------------------------------

        if args.module is None:

            target = args.target.strip()

            if parse_single_ip(
                target
            ) is not None:

                print(
                    "Valid Target"
                )

                print(
                    f"Target: {target}"
                )

                print(
                    "No module selected."
                )

                return 0

            if parse_network_target(
                target
            ) is not None:

                print(
                    "Valid Target"
                )

                print(
                    f"Target: {target}"
                )

                print(
                    "No module selected."
                )

                return 0

            if is_domain_target(
                target
            ):

                print(
                    "Valid Target"
                )

                print(
                    f"Target: {target}"
                )

                print(
                    "No module selected."
                )

                return 0

            print(
                "Invalid Target"
            )

            return 0

        try:

            # =================================================
            # NETWORK MODULE
            # =================================================

            if args.module == "network":

                parsed_target = (
                    parse_network_target(
                        args.target
                    )
                )

                if parsed_target is None:

                    print(
                        "Invalid Target"
                    )

                    return 0

                print(
                    "Valid Target"
                )

                print(
                    f"Target: {args.target}"
                )

                print(
                    "Network module selected."
                )

                print()

                print(
                    "[*] Scanning network..."
                )

                print()

                result = discover_hosts(
                    args.target
                )

                if result is None:
                    result = []

                if not isinstance(
                    result,
                    (list, tuple, set),
                ):

                    result = list(result)

                if parsed_target.prefixlen == 32:

                    host = str(
                        parsed_target.network_address
                    )

                    status = (
                        "ONLINE"
                        if host in result
                        else "OFFLINE"
                    )

                    print(
                        format_single_host_result(
                            host,
                            status=status,
                        )
                    )

                else:

                    print(
                        format_network_results(
                            result,
                            args.target,
                        )
                    )

                return 0

            # =================================================
            # PORT MODULE
            # =================================================

            if args.module == "ports":

                target_ip = parse_single_ip(
                    args.target
                )

                if target_ip is None:

                    print(
                        "Invalid Target"
                    )

                    return 0

                result = runner.run(
                    "ports",
                    str(target_ip),
                )

                print(
                    "Valid Target"
                )

                print(
                    f"Target: {target_ip}"
                )

                print(
                    "Ports module selected."
                )

                print()

                hostname = get_hostname(
                    str(target_ip)
                )

                mac = get_mac_address(
                    str(target_ip)
                )

                print(
                    format_port_results(
                        result,
                        include_legacy=False,
                        target=str(target_ip),
                        hostname=hostname,
                        mac=mac,
                    )
                )

                return 0

            # =================================================
            # OSINT MODULE
            # =================================================

            if args.module == "osint":

                if not is_domain_target(
                    args.target
                ):

                    print(
                        "Invalid Target"
                    )

                    return 0

                report = collect_osint(
                    args.target
                )

                print(
                    "Valid Target"
                )

                print(
                    f"Target: {args.target}"
                )

                print(
                    "OSINT module selected."
                )

                print()

                print(
                    format_osint_report(
                        report
                    )
                )

                return 0

        except ValueError:

            print(
                "Invalid Target"
            )

            return 0

        except Exception as error:

            logger.error(
                "CLI run failed for target=%s module=%s: %s",
                args.target,
                args.module,
                error,
            )

            print(
                f"Error: {error}",
                file=sys.stderr,
            )

            return 1

        return 0

    # ========================================================
    # INTERACTIVE MODE
    # ========================================================

    return interactive_menu(
        runner
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    raise SystemExit(
        main()
    )