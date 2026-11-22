from modules.reconnaissance.dns import get_dns_info
from modules.reconnaissance.network import discover_hosts
from modules.reconnaissance.ports import assess_ports


class ModuleRegistry:
    def __init__(self):
        self._modules = {
            "dns": get_dns_info,
            "network": self._run_network,
            "ports": self._run_ports,
        }

    def _run_network(self, target):
        if "/" not in target:
            import ipaddress

            address = ipaddress.ip_address(target)

            if address.version == 4 and address.is_private:
                target = str(
                    ipaddress.ip_network(
                        f"{target}/24",
                        strict=False,
                    )
                )

        return discover_hosts(target)

    def _run_ports(self, target):
        default_ports = [
            21, 22, 25, 53, 80,
            110, 143, 443, 3306, 8080
        ]

        return assess_ports(target, default_ports)

    def get(self, name):
        if name not in self._modules:
            raise ValueError(f"Unknown module: {name}")

        return self._modules[name]

    def list_modules(self):
        return list(self._modules.keys())
