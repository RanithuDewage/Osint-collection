"""
Small terminal-animation helpers for BlackBox:

- typewriter(): reveals text character by character
- boot_animation(): short animated "initializing" sequence
  shown once when the tool starts
- run_with_spinner(): runs a blocking function in a
  background thread while showing an animated spinner,
  used during network / port / OSINT scans instead of a
  static "[*] Scanning..." line
"""

import shutil
import sys
import threading
import time

from config.settings import APP_NAME


SPINNER_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


def _term_width(default=54):
    try:
        return shutil.get_terminal_size().columns
    except Exception:
        return default


def typewriter(text, delay=0.015):
    """Print text one character at a time."""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def boot_animation():
    """
    Short animated sequence shown once when BlackBox
    starts, before the main banner/menu appears.
    """
    steps = [
        f"Initializing {APP_NAME}",
        "Loading modules",
        "Ready",
    ]

    for step in steps:
        for frame_index in range(10):
            frame = SPINNER_FRAMES[frame_index % len(SPINNER_FRAMES)]
            sys.stdout.write(f"\r{frame} {step}...")
            sys.stdout.flush()
            time.sleep(0.04)

        sys.stdout.write(f"\r[✓] {step}\n")
        sys.stdout.flush()

    time.sleep(0.15)


def run_with_spinner(message, func, *args, **kwargs):
    """
    Run func(*args, **kwargs) on a background thread while
    showing an animated spinner with `message` next to it.
    Returns func's return value, or re-raises any exception
    func raised.
    """
    stop_event = threading.Event()
    outcome = {}

    def _spin():
        index = 0
        width = _term_width()

        while not stop_event.is_set():
            frame = SPINNER_FRAMES[index % len(SPINNER_FRAMES)]
            line = f"\r{frame} {message}"
            sys.stdout.write(line[:width])
            sys.stdout.flush()
            index += 1
            time.sleep(0.08)

        # Clear the spinner line once work is done.
        sys.stdout.write("\r" + " " * min(len(message) + 4, width) + "\r")
        sys.stdout.flush()

    def _worker():
        try:
            outcome["result"] = func(*args, **kwargs)
        except BaseException as error:  # noqa: BLE001
            outcome["error"] = error

    spinner_thread = threading.Thread(target=_spin, daemon=True)
    worker_thread = threading.Thread(target=_worker)

    spinner_thread.start()
    worker_thread.start()
    worker_thread.join()

    stop_event.set()
    spinner_thread.join()

    if "error" in outcome:
        raise outcome["error"]

    return outcome.get("result")