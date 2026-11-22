import subprocess
import sys


def test_cli_valid_ip():
    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "--target",
            "127.0.0.1",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Valid Target" in result.stdout


def test_cli_invalid_target():
    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "--target",
            "not-a-valid-target",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Invalid Target" in result.stdout


def test_cli_valid_domain():
    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "--target",
            "example.com",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Valid Target" in result.stdout
    assert "Target: example.com" in result.stdout

def test_cli_missing_target():
    result = subprocess.run(
        [sys.executable, "main.py"],
        input="4\n",
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Select option:" in result.stdout
    assert "Goodbye!" in result.stdout

def test_cli_list_modules():
    result = subprocess.run(
        [sys.executable, "main.py", "--list-modules"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "dns" in result.stdout
    assert "network" in result.stdout
    assert "ports" in result.stdout


def test_cli_invalid_module():
    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "--target",
            "127.0.0.1",
            "--module",
            "invalid",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "module" in result.stderr.lower()


def test_cli_network_module():
    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "--target",
            "127.0.0.1",
            "--module",
            "network",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Network module selected." in result.stdout


def test_cli_ports_module():
    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "--target",
            "127.0.0.1",
            "--module",
            "ports",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Ports module selected." in result.stdout
def test_cli_unknown_module():
    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "--target",
            "127.0.0.1",
            "--module",
            "invalid",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "invalid choice" in result.stderr.lower()
def test_cli_interactive_exit():
    result = subprocess.run(
        [sys.executable, "main.py"],
        input="4\n",
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Discover Network" in result.stdout
    assert "Scan Ports" in result.stdout
    assert "Exit" in result.stdout
