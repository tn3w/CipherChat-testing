# ~~~
# This is a copy of the free chat program "CipherChat" under GPL-3.0 license
# GitHub: https://github.com/tn3w/CipherChat
# ~~~

from sys import exit

if __name__ != "__main__":
    exit(1)

from rich.console import Console
from utils import clear_console, get_system_architecture, Tor, download_file, get_gnupg_path, Linux
import os
from cons import DATA_DIR_PATH, TEMP_DIR_PATH
import subprocess

CONSOLE = Console()
SYSTEM, MACHINE = get_system_architecture()

clear_console()

if not SYSTEM in ["Windows", "Linux", "macOS"]:
    CONSOLE.print(f"[red][Critical Error] Unfortunately, there is no version of CipherChat for your operating system `{SYSTEM}`.")
    exit(1)

if not os.path.isdir(DATA_DIR_PATH):
    os.mkdir(DATA_DIR_PATH)

GNUPG_EXECUTABLE_PATH = get_gnupg_path()

if not os.path.isfile(GNUPG_EXECUTABLE_PATH):
    if SYSTEM == "Linux":
        Linux.install_package("gpg")
        GNUPG_EXECUTABLE_PATH = get_gnupg_path()
    else:
        CONSOLE.print(f"[red][Critical Error] Please install gpg on your system.")
        exit(1)

TOR_EXECUTABLE_PATH = {"Windows": os.path.join(DATA_DIR_PATH, "tor/tor/tor.exe")}.get(SYSTEM, os.path.join(DATA_DIR_PATH, "tor/tor/tor"))

if not os.path.isfile(TOR_EXECUTABLE_PATH):
    with CONSOLE.status("[bold green]Trying to get the download links for Tor..."):
        download_link, signature_link = Tor.get_download_link()
    CONSOLE.print("[green]~ Trying to get the download links for Tor... Done")
    
    if None in [download_link, signature_link]:
        CONSOLE.print("[red][Critical Error] Tor Expert Bundle could not be installed because no download link or signature link could be found, install it manually.")
        exit(1)
    
    if not os.path.isdir(TEMP_DIR_PATH):
        os.mkdir(TEMP_DIR_PATH)

    bundle_file_path = download_file(download_link, TEMP_DIR_PATH, "Tor Expert Bundle")
    bundle_signature_file_path = download_file(signature_link, TEMP_DIR_PATH, "Tor Expert Bundle Signature")

    keyring_file_path = os.path.join(TEMP_DIR_PATH, "tor.keyring")

    with CONSOLE.status("[bold green]Loading Tor Keys from keys.gnupg.net..."):
        try:
            subprocess.run([GNUPG_EXECUTABLE_PATH, "--keyserver", "keys.gnupg.net", "--recv-keys", "0xEF6E286DDA85EA2A4BA7DE684E2C6E8793298290"], check=True)
        except subprocess.CalledProcessError as e:
            CONSOLE.log(f"[red]An Error occured: `{e}`")
            CONSOLE.print("[red][Critical Error] Could not load Tor Keys from keys.gnupg.net")
            exit(1)
    CONSOLE.print("[green]~ Loading Tor Keys from keys.gnupg.net... Done")

    with CONSOLE.status("[bold green]Validating Signature..."):
        try:
            result = subprocess.run([GNUPG_EXECUTABLE_PATH, "--verify", bundle_signature_file_path, bundle_file_path], capture_output=True, check=True, text=True)
            if not result.returncode == 0:
                CONSOLE.log(f"[red]An Error occured: `{result.stderr}`")
                CONSOLE.print("[red][Critical Error] Signature is invalid.")
                exit(1)
        except subprocess.CalledProcessError as e:
            CONSOLE.log(f"[red]An Error occured: `{e}`")
            CONSOLE.print("[red][Critical Error] Signature verification failed.")
            exit(1)
    CONSOLE.print("[green]~ Validating Signature... Good Signature")