import os

# ============================================================
# Project Branding & Configuration
# Modify these values to rebrand or customize the framework.
# ============================================================

APP_NAME = os.getenv("RECON_APP_NAME", "BlackBox")
VERSION = "2.0.0"
AUTHOR = os.getenv("RECON_AUTHOR", "Ranithu Dewage")
DESCRIPTION = f"{APP_NAME} Advanced Reconnaissance & Security Assessment Framework"
GITHUB_URL = "https://github.com/RanithuDewage/BlackBox"

DEFAULT_TIMEOUT = 5
