import pytest

from modules.core.base import ReconModule


def test_recon_module_requires_run():
    with pytest.raises(TypeError):
        ReconModule()
from modules.core.runner import ModuleRunner


def test_module_runner_register_and_run():
    runner = ModuleRunner()

    def fake_module(target):
        return {
            "target": target,
            "status": "success",
        }

    runner.register("fake", fake_module)

    result = runner.run("fake", "127.0.0.1")

    assert result["target"] == "127.0.0.1"
    assert result["status"] == "success"


def test_module_runner_lists_modules():
    runner = ModuleRunner()

    runner.register("dns", lambda target: target)
    runner.register("network", lambda target: target)
    runner.register("ports", lambda target: target)

    assert runner.list_modules() == [
        "dns",
        "network",
        "ports",
    ]


def test_module_runner_rejects_unknown_module():
    runner = ModuleRunner()

    try:
        runner.run("unknown", "127.0.0.1")
        assert False
    except ValueError as error:
        assert "Unknown module" in str(error)


from modules.core.registry import ModuleRegistry


def test_registry_contains_recon_modules():
    registry = ModuleRegistry()

    assert registry.list_modules() == [
        "dns",
        "network",
        "ports",
    ]


def test_registry_get_dns_module():
    registry = ModuleRegistry()

    module = registry.get("dns")

    assert callable(module)


def test_registry_rejects_unknown_module():
    registry = ModuleRegistry()

    try:
        registry.get("unknown")
        assert False
    except ValueError as error:
        assert "Unknown module" in str(error)
def test_runner_uses_registry():
    registry = ModuleRegistry()

    runner = ModuleRunner(registry)

    result = runner.run("dns", "example.com")

    assert isinstance(result, dict)
    assert result["domain"] == "example.com"
