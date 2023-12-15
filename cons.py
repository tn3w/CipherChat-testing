# ~~~
# This is a copy of the free chat program "CipherChat" under GPL-3.0 license
# GitHub: https://github.com/tn3w/CipherChat
# ~~~

import os

CURRENT_DIR_PATH = os.path.dirname(os.path.abspath(__file__))
DATA_DIR_PATH = os.path.join(CURRENT_DIR_PATH, "data")
TEMP_DIR_PATH = os.path.join(CURRENT_DIR_PATH, "tmp")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/119.0.2151.97",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; Xbox; Xbox One) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edge/44.18363.8131",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0"
]

DISTRO_TO_PACKAGE_MANAGER = {
    "ubuntu": {"installation_command": "apt-get install", "update_command": "apt-get update; apt-get upgrade"},
    "debian": {"installation_command": "apt-get install", "update_command": "apt-get update; apt-get upgrade"},
    "fedora": {"installation_command": "dnf install", "update_command": "dnf upgrade"},
    "centos": {"installation_command": "yum install", "update_command": "yum update"},
    "arch": {"installation_command": "pacman -S", "update_command": "pacman -Syu"},
    "opensuse": {"installation_command": "zypper install", "update_command": "zypper update"},
    "linuxmint": {"installation_command": "apt-get install", "update_command": "apt-get update; apt-get upgrade"},
    "gentoo": {"installation_command": "emerge", "update_command": "emerge --sync"},
    "rhel": {"installation_command": "yum install", "update_command": "yum update"},
    "kali": {"installation_command": "apt-get install", "update_command": "apt-get update; apt-get upgrade"},
    "tails": {"installation_command": "apt-get install", "update_command": "apt-get update; apt-get upgrade"},
    "zorin": {"installation_command": "apt-get install", "update_command": "apt-get update; apt-get upgrade"},
    "mx": {"installation_command": "apt-get install", "update_command": "apt-get update; apt-get upgrade"},
    "solus": {"installation_command": "eopkg install", "update_command": "eopkg up"},
    "antergos": {"installation_command": "pacman -S", "update_command": "pacman -Syu"},
    "lubuntu": {"installation_command": "apt-get install", "update_command": "apt-get update; apt-get upgrade"},
    "xubuntu": {"installation_command": "apt-get install", "update_command": "apt-get update; apt-get upgrade"},
}
PACKAGE_MANAGERS = [
    {"version_command": "apt-get --version", "installation_command": "apt-get install", "update_command": "apt-get update; apt-get upgrade"},
    {"version_command": "dnf --version", "installation_command": "dnf install", "update_command": "dnf upgrade"},
    {"version_command": "yum --version", "installation_command": "yum install", "update_command": "yum update"},
    {"version_command": "pacman --version", "installation_command": "pacman -S", "update_command": "pacman -Syu"},
    {"version_command": "zypper --version", "installation_command": "zypper install", "update_command": "zypper update"},
    {"version_command": "emerge --version", "installation_command": "emerge", "update_command": "emerge --sync"},
    {"version_command": "eopkg --version", "installation_command": "eopkg install", "update_command": "eopkg up"}
]