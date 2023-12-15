# ~~~
# This is a copy of the free chat program "CipherChat" under GPL-3.0 license
# GitHub: https://github.com/tn3w/CipherChat
# ~~~

from sys import exit

if __name__ == "__main__":
    print("Use `python main.py`")
    exit(1)

import os
from typing import Tuple, Optional
import platform
import requests
import random
import subprocess
from cons import USER_AGENTS, DISTRO_TO_PACKAGE_MANAGER, PACKAGE_MANAGERS
from bs4 import BeautifulSoup
from rich.progress import Progress
from rich.console import Console
import distro
from urllib.parse import urlparse

LOGO = '''
 dP""b8 88 88""Yb 88  88 888888 88""Yb  dP""b8 88  88    db    888888 
dP   `" 88 88__dP 88  88 88__   88__dP dP   `" 88  88   dPYb     88   
Yb      88 88"""  888888 88""   88"Yb  Yb      888888  dP__Yb    88   
 YboodP 88 88     88  88 888888 88  Yb  YboodP 88  88 dP""""Yb   88   

-~-    Programmed by TN3W - https://github.com/tn3w/CipherChat    -~-
'''

def clear_console():
    "Cleans the console and shows logo"

    os.system('cls' if os.name == 'nt' else 'clear')
    print(LOGO)

def get_system_architecture() -> Tuple[str, str]:
    "Function to get the correct system information"

    system = platform.system()
    if system == "Darwin":
        system = "macOS"

    machine_mappings = {
        "AMD64": "x86_64",
        "i386": "i686"
    }

    machine = platform.machine()

    machine = machine_mappings.get(machine, "x86_64")

    return system, machine

def download_file(url: str, dict_path: str, operation_name: Optional[str] = None) -> Optional[str]:
    """
    Function to download a file

    :param url: The url of the file
    :param dict_path: Specifies the directory where the file should be saved
    :param operation_name: Sets the name of the operation in the console (Optional)
    """

    parsed_url = urlparse(url)
    file_name = os.path.basename(parsed_url.path)

    save_path = os.path.join(dict_path, file_name)

    if os.path.isfile(save_path):
        return save_path
    
    progress = Progress()

    with progress:

        downloaded_bytes = 0

        with open(save_path, 'wb') as file:
            try:
                response = requests.get(url, stream=True, headers={'User-Agent': random.choice(USER_AGENTS)})
            except:
                return None

            if response.status_code == 200:
                total_length = int(response.headers.get('content-length'))

                if operation_name:
                    task = progress.add_task(f"[cyan]Downloading {operation_name}...", total=total_length)
                else:
                    task = progress.add_task(f"[cyan]Downloading...", total=total_length)

                for chunk in response.iter_content(chunk_size=1024):
                    if chunk:
                        file.write(chunk)
                        downloaded_bytes += len(chunk)

                        progress.update(task, completed=downloaded_bytes)
            else:
                return None
            
    return save_path

def get_gnupg_path() -> str:
    "Function to query the GnuPG path"

    gnupg_path = {"Windows": fr"C:\\Program Files (x86)\\GNU\\GnuPG\\gpg.exe", "macOS": "/usr/local/bin/gpg"}.get(SYSTEM, "/usr/bin/gpg")

    command = {"Windows": "where gpg"}.get(SYSTEM, "which gpg")

    try:
        result = subprocess.check_output(command, shell=True, text=True)
        gnupg_path = result.strip()
    except:
        pass
    
    return gnupg_path

SYSTEM, MACHINE = get_system_architecture()
CONSOLE = Console()

class Linux:
    "Collection of functions that have something to do with Linux"

    @staticmethod
    def get_package_manager() -> Tuple[Optional[str], Optional[str]]:
        "Returns the Packet Manager install command and the update command"

        distro_id = distro.id()

        package_manager = DISTRO_TO_PACKAGE_MANAGER.get(distro_id, {"installation_command": None, "update_command": None})

        installation_command, update_command = package_manager["installation_command"], package_manager["update_command"]
        
        if None in [installation_command, update_command]:
            for package_manager in PACKAGE_MANAGERS:
                try:
                    subprocess.check_call(package_manager["version_command"], shell=True)
                except:
                    pass
                else:
                    installation_command, update_command = package_manager["installation_command"], package_manager["update_command"]
        
        return installation_command, update_command
    
    @staticmethod
    def install_package(package_name: str) -> None:
        """
        Attempts to install a Linux package
        
        :param package_name: Name of the Linux packet
        """
        
        with CONSOLE.status("[green]Trying to get package manager..."):
            installation_command, update_command = Linux.get_package_manager()
        CONSOLE.log(f"[green]~ Package Manager is `{installation_command.split(' ')[0]}`")

        if not None in [installation_command, update_command]:
            try:
                update_process = subprocess.Popen("sudo " + update_command, shell=True)
                update_process.wait()
            except Exception as e:
                CONSOLE.log(f"[red]Error using update Command while installing linux package '{package_name}': '{e}'")
            
            install_process = subprocess.Popen(f"sudo {installation_command} {package_name} -y", shell=True)
            install_process.wait()
        
        else:
            CONSOLE.log("[red]No packet manager found for the current Linux system, you seem to use a distribution we don't know?")
            raise Exception("No package manager found!")

        return None

class Tor:

    @staticmethod
    def get_download_link() -> Tuple[Optional[str], Optional[str]]:
        "Request https://www.torproject.org to get the latest download links"

        response = requests.get("https://www.torproject.org/download/tor/", headers={'User-Agent': random.choice(USER_AGENTS)})
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')

        anchors = soup.find_all('a')

        download_url = None
        signature_url = None

        for anchor in anchors:
            href = anchor.get('href')

            if href:
                if "archive.torproject.org/tor-package-archive/torbrowser" in href:
                    if SYSTEM.lower() in href and "tor-expert-bundle" in href and MACHINE.lower() in href:
                        if href.endswith(".asc"):
                            signature_url = href
                        else:
                            download_url = href

                        if not None in [signature_url, download_url]:
                            break
        
        return (download_url, signature_url)