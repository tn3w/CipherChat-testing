""" 
~-~-~-~
This is a copy of the free chat program "CipherChat" under GPL-3.0 license
GitHub: https://github.com/tn3w/CipherChat
~-~-~-~
"""

import os
from typing import Tuple, Optional, Union
import platform
import secrets
import random
import shutil
import subprocess
import concurrent.futures
import multiprocessing
from urllib.parse import urlparse
import time
import socket
import json
import sys
import re
import hashlib
from base64 import urlsafe_b64encode, urlsafe_b64decode, b64encode, b64decode
import requests
from bs4 import BeautifulSoup
from rich.style import Style
from rich.theme import Theme
from rich.text import Text
from rich.progress import Progress
from rich.console import Console
import distro
from stem.control import Controller
from stem import Signal
import psutil
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization, padding as sym_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asy_padding
from jinja2 import Environment, select_autoescape, Undefined
from PIL import Image
from io import BytesIO
from cons import USER_AGENTS, DISTRO_TO_PACKAGE_MANAGER, PACKAGE_MANAGERS,\
                 DATA_DIR_PATH, BRIDGE_DOWNLOAD_URLS, TEMP_DIR_PATH, DEFAULT_BRIDGES,\
                 CURRENT_DIR_PATH, HTTP_PROXIES, HTTPS_PROXIES, BRIDGE_FILES

if __name__ == "__main__":
    print("Use `python main.py`")
    sys.exit(0)

LOGO_SMALL = '''
 dP""b8 88 88""Yb 88  88 888888 88""Yb  dP""b8 88  88    db    888888 
dP   `" 88 88__dP 88  88 88__   88__dP dP   `" 88  88   dPYb     88   
Yb      88 88"""  888888 88""   88"Yb  Yb      888888  dP__Yb    88   
 YboodP 88 88     88  88 888888 88  Yb  YboodP 88  88 dP""""Yb   88   

-~-    Programmed by TN3W - https://github.com/tn3w/CipherChat    -~-
'''

LOGO_BIG = '''
             @@@@@            
       @@@@@@@@@@@@@@@@@      
    @@@@@@@@@@@@@@@   @@@@@   
  @@@@@@@@@@@@@@ @@@@@@  @@@@ 
 @@@@@@@@@@@@@@@@@@  @@@@  @@@   dP""b8 88 88""Yb 88  88 888888 88""Yb  dP""b8 88  88    db    888888 
 @@@@@@@@@@@@@@@ @@@@  @@@ @@@  dP   `" 88 88__dP 88  88 88__   88__dP dP   `" 88  88   dPYb     88   
@@@@@@@@@@@@@@@@   @@  @@@  @@@ Yb      88 88"""  888888 88""   88"Yb  Yb      888888  dP__Yb    88   
 @@@@@@@@@@@@@@@ @@@@  @@@ @@@   YboodP 88 88     88  88 888888 88  Yb  YboodP 88  88 dP""""Yb   88  
 @@@@@@@@@@@@@@@@@@  @@@@ @@@@  -~-    Programmed by TN3W - https://github.com/tn3w/CipherChat    -~-
  @@@@@@@@@@@@@@@@@@@@@  @@@  
    @@@@@@@@@@@@@@@   @@@@@   
       @@@@@@@@@@@@@@@@@      
'''

styled_logo = ""
for char in LOGO_BIG:
    if char == '@':
        styled_logo += f'[purple]{char}[/purple]'
    else:
        styled_logo += f'[not bold white]{char}[/not bold white]'

custom_theme = Theme({
    "purple": "rgb(125,70,152)",
    "white": "rgb(211,215,207)"
})
CONSOLE = Console(theme=custom_theme)

def get_console_columns():
    "Returns the console columns"

    if os.name == 'nt':
        _, columns = shutil.get_terminal_size()
        return columns
    else:
        _, columns = os.popen('stty size', 'r').read().split()
        return int(columns)

def clear_console():
    "Cleans the console and shows logo"

    os.system('cls' if os.name == 'nt' else 'clear')

    console_columns = get_console_columns()

    if console_columns > 104:
        CONSOLE.print(styled_logo)
    elif console_columns > 71:
        print(LOGO_SMALL)
    else:
        print('-~- CIPHERCHAT -~-\n')


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

def shorten_text(text: str, length: int) -> str:
    """
    Function to shorten the text and append "...".

    :param text: The text to be shortened
    :param length: The length of the text
    """

    if len(text) > length:
        text = text[:length] + "..."
    return text

def atexit_terminate_tor(control_port, control_password, tor_process):
    with CONSOLE.status("[green]Terminating Tor..."):
        Tor.send_shutdown_signal(control_port, control_password)
        time.sleep(1)
        tor_process.terminate()

def generate_random_string(length: int, with_punctuation: bool = True,
                           with_letters: bool = True) -> str:
    """
    Generates a random string

    :param length: The length of the string
    :param with_punctuation: Whether to include special characters
    :param with_letters: Whether letters should be included
    """

    characters = "0123456789"

    if with_punctuation:
        characters += r"!\"#$%&'()*+,-.:;<=>?@[\]^_`{|}~"

    if with_letters:
        characters += "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

    random_string = ''.join(secrets.choice(characters) for _ in range(length))
    return random_string

def show_image_in_console(image_bytes: bytes) -> None:
    """
    Turns a given image into Ascii Art and prints it in the console

    :param image_bytes: The bytes of the image to be displayed in the console
    """

    img = Image.open(BytesIO(image_bytes))

    ascii_chars = '@%#*+=-:. '
    width, height = img.size
    aspect_ratio = height / width
    new_width = get_console_columns()
    new_height = int(aspect_ratio * new_width * 0.55)
    img = img.resize((new_width, new_height))
    img = img.convert('L')  # Convert to grayscale

    pixels = img.getdata()
    ascii_str = ''.join([ascii_chars[min(pixel // 25, len(ascii_chars) - 1)] for pixel in pixels])
    ascii_str_len = len(ascii_str)
    ascii_img = ''
    for i in range(0, ascii_str_len, new_width):
        ascii_img += ascii_str[i:i + new_width] + '\n'

    print(ascii_img)

def get_gnupg_path() -> str:
    "Function to query the GnuPG path"

    gnupg_path = {
        "Windows": r"C:\\Program Files (x86)\\GNU\\GnuPG\\gpg.exe",
        "macOS": "/usr/local/bin/gpg"
    }.get(SYSTEM, "/usr/bin/gpg")

    command = {"Windows": "where gpg"}.get(SYSTEM, "which gpg")

    try:
        result = subprocess.check_output(command, shell=True, text=True)
        gnupg_path = result.strip()
    except Exception as e:
        CONSOLE.log(f"[red][Error] Error when requesting pgp: '{e}'")

    return gnupg_path

def get_password_strength(password: str) -> int:
    """
    Function to get a password strength from 0 (bad) to 100% (good)

    :param password: The password to check
    """

    strength = (len(password) * 62.5) / 16

    if strength > 70:
        strength = 70

    if re.search(r'[A-Z]', password):
        strength += 5
    if re.search(r'[a-z]', password):
        strength += 5
    if re.search(r'[!@#$%^&*()_+{}\[\]:;<>,.?~\\]', password):
        strength += 20

    if strength > 100:
        strength = 100
    return round(strength)

class Proxy:
    "Includes all functions that have something to do with proxies"

    @staticmethod
    def _select_random(proxys: list, quantity: int = 1) -> Union[list, str]:
        """
        Selects random proxys that are online
        
        :param quantity: How many proxys should be selected
        """
        
        selected_proxies = []
        checked_proxies = []

        while len(selected_proxies) < quantity:
            if len(proxys) <= len(checked_proxies):
                break

            random_proxy = secrets.choice(proxys)
            while random_proxy in checked_proxies:
                random_proxy = secrets.choice(proxys)

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)

                ip, port = random_proxy.split(":")
                sock.connect((ip, int(port)))
            except:
                pass
            else:
                selected_proxies.append(random_proxy)

            checked_proxies.append(random_proxy)

        while len(selected_proxies) < quantity:
            random_proxy = secrets.choice(proxys)
            if not random_proxy in selected_proxies:
                selected_proxies.append(random_proxy)

        if quantity == 1:
            return selected_proxies[0]

        return selected_proxies

    @staticmethod
    def get_requests_session() -> requests.Session:
        "Returns a requests.session object with a selected proxy"

        http_proxie = Proxy._select_random(HTTP_PROXIES)
        https_proxie = Proxy._select_random(HTTPS_PROXIES)

        session = requests.Session()
        session.proxies = {
            "http": http_proxie,
            "https:": https_proxie
        }
        return session

def download_file(url: str, dict_path: str,
                  operation_name: Optional[str] = None, file_name: Optional[str] = None,
                  session: Optional[requests.Session] = None) -> Optional[str]:
    """
    Function to download a file

    :param url: The url of the file
    :param dict_path: Specifies the directory where the file should be saved
    :param operation_name: Sets the name of the operation in the console (Optional)
    :param file_name: Sets the file name (Optional)
    :param session: a requests.Session (Optional)
    """

    if session is None:
        session = Proxy.get_requests_session()

    if file_name is None:
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
                response = session.get(
                    url, stream=True, headers={'User-Agent': random.choice(USER_AGENTS)}, timeout=5
                )
                response.raise_for_status()
            except Exception as e:
                CONSOLE.log(f"[red][Error] Error downloading the file: '{e}'")
                return None

            if response.status_code == 200:
                total_length = int(response.headers.get('content-length'))

                if operation_name:
                    task = progress.add_task(
                        f"[cyan]Downloading {operation_name}...",
                        total=total_length
                    )
                else:
                    task = progress.add_task("[cyan]Downloading...", total=total_length)

                for chunk in response.iter_content(chunk_size=1024):
                    if chunk:
                        file.write(chunk)
                        downloaded_bytes += len(chunk)

                        progress.update(task, completed=downloaded_bytes)
            else:
                return None

    return save_path

def is_password_pwned(password: str, session = Optional[requests.Session]) -> bool:
    """
    Ask pwnedpasswords.com if password is available in data leak

    :param password: Password to check against
    :param session: a requests.Session Object (Optional)
    """

    if session is None:
        session = Proxy.get_requests_session()

    password_sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    hash_prefix = password_sha1_hash[:5]

    url = f"https://api.pwnedpasswords.com/range/{hash_prefix}"

    while True:
        try:
            response = requests.get(
                url,
                headers = {'User-Agent': random.choice(USER_AGENTS)},
                timeout = 5
            )
            response.raise_for_status()

            if response.status_code == 200:
                hashes = [line.split(':') for line in response.text.splitlines()]
                for hash, _ in hashes:
                    if hash == password_sha1_hash[5:]:
                        return False         
        except (requests.exceptions.ProxyError, requests.exceptions.ReadTimeout):
            session = Proxy.get_requests_session()
        else:
            break

    return True


SYSTEM, MACHINE = get_system_architecture()
CONSOLE = Console()
CPU_COUNT = multiprocessing.cpu_count()

class SecureDelete:
    "Class for secure deletion of files or folders"

    @staticmethod
    def list_files_and_directories(directory_path: str) -> Tuple[list, list]:
        """
        Function to get all files and directorys in a directory

        :param directory_path: The path to the directory
        """

        all_files = list()
        all_directories = list()

        def list_files_recursive(root, depth):
            for item in os.listdir(root):
                item_path = os.path.join(root, item)
                if os.path.isfile(item_path):
                    all_files.append((item_path, depth))
                elif os.path.isdir(item_path):
                    all_directories.append((item_path, depth))
                    list_files_recursive(item_path, depth + 1)

        list_files_recursive(directory_path, 0)

        all_files.sort(key=lambda x: x[1], reverse=True)
        all_directories.sort(key=lambda x: x[1], reverse=True)

        all_files = [path for path, _ in all_files]
        all_directories = [path for path, _ in all_directories]

        return all_files, all_directories

    @staticmethod
    def file(file_path: str, quite: bool = False) -> None:
        """
        Function to securely delete a file by replacing it first with random characters and
        then according to Gutmann patterns and DoD 5220.22-M patterns

        :param file_path: The path to the file
        :param quite: If True nothing is written to the console
        """
        if not os.path.isfile(file_path):
            return

        file_size = os.path.getsize(file_path)
        file_size_times_two = file_size * 2

        gutmann_patterns = [bytes([i % 256] * (file_size_times_two)) for i in range(35)]
        dod_patterns = [
            bytes([0x00] * file_size_times_two),
            bytes([0xFF] * file_size_times_two),
            bytes([0x00] * file_size_times_two)
        ]

        for _ in range(10):
            try:
                if os.path.isfile(file_path):
                    os.remove(file_path)

                with open(file_path, 'wb') as file:
                    file.write(os.urandom(file_size_times_two))

                if os.path.isfile(file_path):
                    os.remove(file_path)

                with open(file_path, 'ab') as file:
                    file.seek(0, os.SEEK_END)

                    # Gutmann Pattern
                    for pattern in gutmann_patterns:
                        file.write(pattern)

                    # DoD 5220.22-M Pattern
                    for pattern in dod_patterns:
                        file.write(pattern)
            except Exception as e:
                if not quite:
                    CONSOLE.log(f"[red][Error] Error deleting the file '{file_path}': {e}")

            try:
                os.remove(file_path)
            except Exception as e:
                CONSOLE.log(f"[red][Error] Error deleting the file '{file_path}': {e}")
    
    @staticmethod
    def directory(directory_path: str, quite: bool = False) -> None:
        """
        Securely deletes entire folders with files and subfolders

        :param directory_path: The path to the directory
        :param quite: If True nothing is written to the console
        """

        files, directories = SecureDelete.list_files_and_directories(directory_path)

        with concurrent.futures.ThreadPoolExecutor(max_workers=CPU_COUNT) as executor:
            file_futures = {executor.submit(SecureDelete.file, file, quite): file for file in files}

            concurrent.futures.wait(file_futures)

            for directory in directories:
                try:
                    shutil.rmtree(directory)
                except Exception as e:
                    if not quite:
                        CONSOLE.log(f"[red][Error] Error deleting directory '{directory}': {e}")

            try:
                shutil.rmtree(directory_path)
            except Exception as e:
                if not quite:
                    CONSOLE.log(f"[red][Error] Error deleting directory '{directory_path}': {e}")

class Linux:
    "Collection of functions that have something to do with Linux"

    @staticmethod
    def get_package_manager() -> Tuple[Optional[str], Optional[str]]:
        "Returns the Packet Manager install command and the update command"

        distro_id = distro.id()

        package_manager = DISTRO_TO_PACKAGE_MANAGER.get(
            distro_id, {"installation_command": None, "update_command": None}
        )

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

SYSTEM, MACHINE = get_system_architecture()
TOR_EXECUTABLE_PATH = {
    "Windows": os.path.join(DATA_DIR_PATH, "tor/tor/tor.exe")
}.get(SYSTEM, os.path.join(DATA_DIR_PATH, "tor/tor/tor"))
PLUGGABLE_TRANSPORTS_PATH = os.path.join(DATA_DIR_PATH, "tor", "tor", "pluggable_transports")
SNOWFLAKE_EXECUTABLE_PATH = os.path.join(
    PLUGGABLE_TRANSPORTS_PATH, {"Windows": "snowflake-client.exe"}.get(SYSTEM, "snowflake-client")
)
WEBTUNNEL_EXECUTABLE_PATH = os.path.join(
    PLUGGABLE_TRANSPORTS_PATH, {"Windows": "webtunnel-client.exe"}.get(SYSTEM, "webtunnel-client")
)
LYREBIRD_EXECUTABLE_PATH = os.path.join(
    PLUGGABLE_TRANSPORTS_PATH, {"Windows": "lyrebird.exe"}.get(SYSTEM, "lyrebird")
)
CONJURE_EXECUTABLE_PATH = os.path.join(
    PLUGGABLE_TRANSPORTS_PATH, {"Windows": "conjure-client.exe"}.get(SYSTEM, "lyrebird")
)
TOR_DATA_DIR2_PATH = os.path.join(DATA_DIR_PATH, "tor", "data2")

class Bridge:
    "Includes all functions that have something to do with Tor bridges"

    @staticmethod
    def _get_type(bridge: str) -> str:
        """
        Returns the type of a given bridge
        
        :param bridge: A Tor bridge
        """

        for bridge_type in ["obfs4", "webtunnel", "snowflake", "meek_lite"]:
            if bridge.startswith(bridge_type):
                return bridge_type
        return "vanilla"

    @staticmethod
    def _is_socket_bridge_online(bridge_address: str, bridge_port: int, timeout: int = 3) -> bool:
        """
        Request a bridge with socks to check that it is online

        :param bridge_address: The bridges ipv4 or ipv6 or domain
        :param bridge_port: The port of a bridge
        :param timeout: Time in seconds after which a bridge is no longer considered online if it has not responded
        """

        try:
            with socket.create_connection((bridge_address, bridge_port), timeout=timeout):
                return True
        except:
            return False

    @staticmethod
    def _is_webtunnel_bridge_online(webtunnel_url: str, timeout: int = 3) -> bool:
        """
        Requests a WebTunnel to check if it is online

        :param webtunnel_url: The url to the WebTunnel
        :param timeout: Time in seconds after which a bridge is no longer considered online if it has not responded
        """

        try:
            requests.get(webtunnel_url, timeout=timeout, headers={'User-Agent': random.choice(USER_AGENTS)})
            return True
        except:
            return False

    @staticmethod
    def download(bridge_type, session: requests.Session):
        """
        Downloads a bridge file from GitHub

        :param bridge_type: Type of bridge
        :param session: Session configured with Socks Proxy Ports
        """

        download_urls = BRIDGE_DOWNLOAD_URLS[bridge_type]
        bridge_path = os.path.join(DATA_DIR_PATH, bridge_type + ".json")

        file_path = download_file(
            download_urls["github"], TEMP_DIR_PATH,
            bridge_type.title() + " Bridges", bridge_type + ".txt", session
        )
        if file_path is None:
            file_path = download_file(
                download_urls["backup"], TEMP_DIR_PATH,
                bridge_type.title() + " Bridges", bridge_type + ".txt", session
            )

        if not os.path.isfile(file_path):
            CONSOLE.log("[red][Error] Error when downloading bridges, use of default bridges")
        else:
            with open(file_path, "r", encoding = "utf-8") as readable_file:
                unprocessed_bridges = readable_file.read()

            processed_bridges = [bridge.strip() for bridge in unprocessed_bridges.split("\n") if bridge.strip()]

            if {"vanilla": 800, "obfs4": 5000}.get(bridge_type, 20) >= len(processed_bridges):
                CONSOLE.log("[red][Error] Error when validating the bridges, bridges were either not downloaded correctly or the bridge page was compromised, use of default bridges")
            else:
                with open(bridge_path, "w", encoding = "utf-8") as writeable_file:
                    json.dump(processed_bridges, writeable_file)

    @staticmethod
    def select_random(all_bridges: list, quantity: int = 3) -> list:
        """
        Randomly selects bridges and asks them to check if they are online

        :param all_bridges: All existing bridges in one list
        :param quantity: How many bridges should be selected
        """

        if len(all_bridges) <= quantity:
            return all_bridges

        bridge_types = {}
        for bridge in all_bridges:
            bridge_type = Bridge._get_type(bridge)

            if bridge_type not in bridge_types:
                bridge_types[bridge_type] = []

            bridge_types[bridge_type].append(bridge)

        selected_bridges = []
        checked_bridges = []

        while len(selected_bridges) != quantity:
            if len(bridge_types) > 1:
                random_type = secrets.choice(list(bridge_types.keys()))
            else:
                random_type = next(iter(bridge_types))

            while True:
                if len(bridge_types[random_type]) > 1:
                    random_bridge = secrets.choice(bridge_types[random_type])

                    number_already_checked = 0
                    for bridge in bridge_types[random_type]:
                        if bridge in checked_bridges:
                            number_already_checked += 1

                    if number_already_checked >= len(bridge_types[random_type]):
                        break

                    while random_bridge in checked_bridges:
                        random_bridge = secrets.choice(bridge_types[random_type])
                else:
                    random_bridge = next(iter(bridge_types[random_type]))

                    if random_bridge in checked_bridges:
                        break

                found_bridge = False

                if random_type in ["vanilla", "obfs4"]:
                    processed_bridge = random_bridge.replace("obfs4 ", "")
                    bridge_address = processed_bridge.split(":")[0]
                    bridge_port = processed_bridge.split(":")[1].split(" ")[0]

                    if Bridge._is_socket_bridge_online(bridge_address, int(bridge_port)):
                        selected_bridges.append(random_bridge)
                        found_bridge = True
                elif random_type == "webtunnel":
                    bridge_url = random_bridge.split("url=")[1].split(" ")[0]
                    if Bridge._is_webtunnel_bridge_online(bridge_url):
                        selected_bridges.append(random_bridge)
                        found_bridge = True
                else:
                    selected_bridges.append(random_bridge)
                    found_bridge = True                

                checked_bridges.append(random_bridge)

                if found_bridge:
                    break

            if len(checked_bridges) >= len(all_bridges):
                break
        
        while (len(selected_bridges) < 3 and len(all_bridges) > 1)\
            or (len(selected_bridges) == 0 and len(all_bridges) == 1):
            random_bridge = secrets.choice(all_bridges)
            if not random_bridge in selected_bridges:
                selected_bridges.append(random_bridge)

        return selected_bridges

    @staticmethod
    def choose_buildin(bridge_type: str) -> list:
        """
        Selects Random Buildin bridges

        :param bridge_type: Type of bridge
        """

        with CONSOLE.status("[green]Bridges are selected (This may take some time)..."):
            if not bridge_type == "random":
                default_bridges = DEFAULT_BRIDGES[bridge_type]
                bridges = Bridge.select_random(default_bridges, 4)
            else:
                default_bridges = []
                for _, specific_bridges in DEFAULT_BRIDGES.items():
                    default_bridges.extend(specific_bridges)
                bridges = Bridge.select_random(default_bridges, 6)

        return bridges
    
    @staticmethod
    def choose_bridges(use_default_bridges: bool, bridge_type: str) -> list:
        """
        Choose a list of bridges based on specified criteria.

        :param use_default_bridges: Flag indicating whether to use default bridges or not.
        :param bridge_type: Type of bridges to choose.
        """

        if use_default_bridges:
            return Bridge.choose_buildin(bridge_type)
        
        with CONSOLE.status("All bridges are loaded..."):
            if bridge_type == "random":
                all_bridges = DEFAULT_BRIDGES["snowflake"] + DEFAULT_BRIDGES["meek_lite"]
                for file in BRIDGE_FILES:
                    try:
                        with open(file, "r", encoding="utf-8") as readable_file:
                            content = json.load(readable_file)
                        all_bridges.extend(content)
                    except Exception as e:
                        bridge_type = file.replace(DATA_DIR_PATH, "").replace(".json", "")
                        all_bridges.extend(DEFAULT_BRIDGES[bridge_type])
                        CONSOLE.log(f"[red][Error] Error loading the bridge file: '{file}': '{e}'")
            else:
                try:
                    bridge_file = os.path.join(DATA_DIR_PATH, bridge_type + ".json")
                    with open(bridge_file, "r", encoding="utf-8") as readable_file:
                        content = json.load(readable_file)
                    all_bridges = content
                except Exception as e:
                    all_bridges = DEFAULT_BRIDGES[bridge_type]
                    CONSOLE.log(f"[red][Error] Error loading the bridge file: '{bridge_file}': '{e}'")

        with CONSOLE.status("[green]Bridges are selected (This may take some time)..."):
            bridges = Bridge.select_random(all_bridges, 6)
        
        return bridges

class BridgeDB:
    "All functions that have something to do with requesting bridges from BridgeDB"

    @staticmethod
    def get_captcha_challenge(bridge_type: str, session: Optional[requests.Session] = None)\
        -> Tuple[Optional[bytes], Optional[str]]:
        """
        Asks for a captcha from bridges.torproject.org to get bridges
        
        :param bridge_type: The type of bridge, can be "vanilla", "obfs4" or "webtunnel"
        :param session: a requests.Session Object (Optional)
        """

        if session is None:
            session = Proxy.get_requests_session()

        captcha_image_bytes, captcha_challenge_value = None, None

        try:
            response = requests.get(
                "https://bridges.torproject.org/bridges/?transport="\
                + {"vanilla": "0"}.get(bridge_type, bridge_type),
                headers = {'User-Agent': random.choice(USER_AGENTS)},
                timeout = 5
            )
            response.raise_for_status()

            if response.status_code == 200:
                html_content = response.text
                soup = BeautifulSoup(html_content, 'html.parser')

                captcha_image_object = soup.select_one('#bridgedb-captcha img')
                if captcha_image_object:
                    captcha_image_src = captcha_image_object.get('src')

                    captcha_image_base64 = captcha_image_src.split("data:image/jpeg;base64,")[1]

                    captcha_image_bytes = b64decode(captcha_image_base64)

                captcha_form_object = soup.select_one('#bridgedb-captcha-container form')
                if captcha_form_object:
                    captcha_challenge_field_object = captcha_form_object.select_one('input[name="captcha_challenge_field"]')

                    if captcha_challenge_field_object:
                        captcha_challenge_value = captcha_challenge_field_object.get('value')
        except Exception as e:
            print(f"Error getting captcha challenge: {str(e)}")

        return captcha_image_bytes, captcha_challenge_value

    @staticmethod
    def get_bridges(bridge_type: str, captcha_input: str,
                    captcha_challenge_value: str, session: Optional[requests.Session])\
                        -> Optional[list]:
        """
        Gets the bridges after the captcha has been solved by the user
        
        :param bridge_type: The type of bridge, can be "vanilla", "obfs4" or "webtunnel"
        :param captcha_input: User input of the characters in the captcha
        :param captcha_challenge_value: Captcha Challenge Value from get_captcha_challenge
        :param session: a requests.Session Object (Optional)
        """

        if session is None:
            session = Proxy.get_requests_session()

        bridges = None

        try:
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': random.choice(USER_AGENTS)
            }

            response = requests.post(
                "https://bridges.torproject.org/bridges/?transport="\
                + {"vanilla": "0"}.get(bridge_type, bridge_type), headers = headers,
                data = {
                    "captcha_response_field": captcha_input, 
                    "captcha_challenge_field": captcha_challenge_value
                },
                timeout = 5
            )
            response.raise_for_status()

            if response.status_code == 200:
                html_content = response.text
                soup = BeautifulSoup(html_content, 'html.parser')

                bridge_lines_object = soup.select_one('#bridgelines')
                if bridge_lines_object:
                    bridge_lines = bridge_lines_object.get_text()
                    bridges = [bridge.strip() for bridge in bridge_lines.strip().split('\n')]
        except Exception as e:
            print(f"Error getting bridges: {str(e)}")

        return bridges


HIDDEN_SERVICE_CONF_FILE = os.path.join(DATA_DIR_PATH, "hidden-service.conf")

class Tor:
    "All functions that have something to do with the Tor network"

    @staticmethod
    def get_download_link(session: Optional[requests.Session] = None
        ) -> Tuple[Optional[str], Optional[str]]:
        "Request http://www.torproject.org to get the latest download links"

        if session is None:
            session = Proxy.get_requests_session()
        
        while True:
            try:
                response = session.get(
                    "http://www.torproject.org/download/tor/",
                    headers={'User-Agent': random.choice(USER_AGENTS)},
                    timeout = 5
                )
                response.raise_for_status()
            except (requests.exceptions.ProxyError, requests.exceptions.ReadTimeout):
                session = Proxy.get_requests_session()
            else:
                break

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

    @staticmethod
    def terminate_tor_processes():
        "Function to try to stop a broken Tor service"

        try:
            for process in psutil.process_iter(attrs=['pid', 'name', 'cmdline']):
                if "tor" == process.name().strip():
                    process.terminate()
        except Exception as e:
            CONSOLE.print(f"[red][Error] Error when terminating Tor: `{e}`")

    @staticmethod
    def launch_tor_with_config(control_port: int, socks_port: int, bridges: list,
                               is_service: bool = False, control_password: Optional[str] = None,
                               other_configuration: Optional[dict] = None
                               ) -> Tuple[subprocess.Popen, str]:
        """
        Starts Tor with the given configurations and bridges

        :param control_port: Tor control port to control the connection
        :param socks_port: Tor Socks Port, sets the port for Socks Proxy connections via Tor
        :param bridges: Bridges to conceal the connection to Tor from evil entities
        :param is_service: If True, use of other data directory so that two Tor clients can run in parallel
        :param control_password: Password, to control the control port (Optional)
        :param other_configuration: Other configurations for the torrc file (Optional)
        """

        if control_password is None:
            control_password = generate_random_string(16, with_punctuation=False)
        
        tor_process = subprocess.Popen(
            [TOR_EXECUTABLE_PATH, "--hash-password", control_password],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        hashed_password, _ = tor_process.communicate()
        hashed_password = hashed_password.strip().decode()

        temp_config_path = os.path.join(DATA_DIR_PATH, "torrc")

        with open(temp_config_path, 'w+', encoding = 'utf-8') as temp_config:
            temp_config.write(f"ControlPort {control_port}\n")
            temp_config.write(f"HashedControlPassword {hashed_password}\n")
            temp_config.write(f"SocksPort {socks_port}\n")

            if is_service:
                if not os.path.isdir(TOR_DATA_DIR2_PATH):
                    os.mkdir(TOR_DATA_DIR2_PATH)
                temp_config.write(f"DataDirectory {TOR_DATA_DIR2_PATH}\n")

            if not len(bridges) == 0:
                temp_config.write(f"UseBridges 1\nClientTransportPlugin obfs4 exec {LYREBIRD_EXECUTABLE_PATH}\nClientTransportPlugin snowflake exec {SNOWFLAKE_EXECUTABLE_PATH}\nClientTransportPlugin webtunnel exec {WEBTUNNEL_EXECUTABLE_PATH}\nClientTransportPlugin meek_lite exec {CONJURE_EXECUTABLE_PATH}")
            for bridge in bridges:
                temp_config.write(f"\nBridge {bridge}")

            if not other_configuration is None:
                if not other_configuration.get("hidden_service_dir") is None:
                    temp_config.write(f"HiddenServiceDir {other_configuration.get('hidden_service_dir')}\n")
                if not other_configuration.get("hidden_service_port") is None:
                    temp_config.write(f"HiddenServicePort {other_configuration.get('hidden_service_port')}\n")

        tor_process = subprocess.Popen(
            [TOR_EXECUTABLE_PATH, "-f", temp_config_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            close_fds=True
        )

        warn_time = None

        while True:
            line = tor_process.stdout.readline().decode().strip()
            if line:
                print(line)
                if "[notice] Bootstrapped 100% (done): Done" in line:
                    break

                if "Bootstrapped" in line:
                    warn_time = None

                if warn_time is None:
                    if "[err]" in line or "[warn]" in line:
                        warn_time = int(time.time())

            if not warn_time is None:
                if warn_time + 10 < int(time.time()):
                    break
        
        if os.path.isfile(temp_config_path):
            os.remove(temp_config_path)
        
        try:
            with Controller.from_port(port=control_port) as controller:
                controller.authenticate(password=control_password)

                start_time = time.time()
                while not controller.is_alive():
                    if time.time() - start_time > 20:
                        raise TimeoutError("Timeout!")
                    time.sleep(1)
        except Exception as e:
            CONSOLE.print(f"[red][Error] Error when checking whether TOR has started correctly: `{e}`")
            Tor.send_shutdown_signal(control_port, control_password)
            time.sleep(1)
            tor_process.terminate()
            return None, None

        return tor_process, control_password

    @staticmethod
    def send_shutdown_signal(control_port: int, control_password: str) -> None:
        """
        Sends the signal to terminate Tor

        :param control_port: Tor control port to control the connection
        :param control_password: Password to authorize Tor
        """

        try:
            with Controller.from_port(port=control_port) as controller:
                controller.authenticate(password=control_password)

                controller.signal(Signal.SHUTDOWN)
        except:
            Tor.terminate_tor_processes()

    @staticmethod
    def send_new_identity_signal(control_port: int, control_password: str) -> None:
        """
        Sends the signal to generate a new identity

        :param control_port: Tor control port to control the connection
        :param control_password: Password to authorize Tor
        """

        try:
            with Controller.from_port(port=control_port) as controller:
                controller.authenticate(password=control_password)

                controller.signal(Signal.NEWNYM)
        except:
            pass

    @staticmethod
    def get_requests_session(control_port: int, control_password: str,
                             socks_port: int) -> requests.Session:
        """
        Returns a requests.session object with the gate socks set

        :param control_port: Tor control port to control the connection
        :param control_password: Password to authorize Tor
        :param socks_port: Tor Socks Port, sets the port for Socks Proxy connections via Tor
        """

        if secrets.choice([True] + [False] * 8):
            Tor.send_new_identity_signal(control_port, control_password)

        session = requests.Session()

        session.proxies = {
            'http': 'socks5h://127.0.0.1:' + str(socks_port),
            'https': 'socks5h://127.0.0.1:' + str(socks_port)
        }

        return session

    @staticmethod
    def get_ports(port_range: int = 5000) -> Tuple[int, int]:
        """
        Function for getting control and socks port
        
        :param port_range: In which range the ports should be
        """

        control_port, socks_port = port_range + 30, port_range + 31

        def is_port_in_use(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(2)
                    return s.connect_ex(('127.0.0.1', port)) == 0
            except:
                return False

        def find_avaiable_port(without_port = None):
            while True:
                random_port = secrets.randbelow(port_range) + 1000
                if random_port == without_port:
                    continue
                if not is_port_in_use(random_port):
                    return random_port

        if is_port_in_use(control_port):
            control_port = find_avaiable_port(socks_port)
        if is_port_in_use(socks_port):
            socks_port = find_avaiable_port(control_port)

        return control_port, socks_port

    @staticmethod
    def get_hidden_service_config() -> dict:
        "Loads the hidden service configuration"

        hidden_service_conf = {
            "hidden_service_directory": os.path.join(DATA_DIR_PATH, "hidden_service"),
            "webservice_host": "localhost",
            "webservice_port": 8080,
            "without_ui": False
        }

        if os.path.isfile(HIDDEN_SERVICE_CONF_FILE):
            try:
                with open(HIDDEN_SERVICE_CONF_FILE, "r", encoding = "utf-8") as readable_file:
                    loaded_configuration = json.load(readable_file)
                hidden_service_conf.update(loaded_configuration)
            except:
                pass

        return hidden_service_conf

class FastHashing:
    "Implementation for fast hashing"

    def __init__(self, salt: Optional[str] = None, without_salt: bool = False):
        """
        :param salt: The salt, makes the hashing process more secure (Optional)
        :param without_salt: If True, no salt is added to the hash
        """

        self.salt = salt
        self.without_salt = without_salt

    def hash(self, plain_text: str, hash_length: int = 8) -> str:
        """
        Function to hash a plaintext

        :param plain_text: The text to be hashed
        :param hash_length: The length of the returned hashed value
        """

        if not self.without_salt:
            salt = self.salt
            if salt is None:
                salt = secrets.token_hex(hash_length)
            plain_text = salt + plain_text

        hash_object = hashlib.sha256(plain_text.encode())
        hex_dig = hash_object.hexdigest()

        if not self.without_salt:
            hex_dig += "//" + salt
        return hex_dig

    def compare(self, plain_text: str, hashed_value: str) -> bool:
        """
        Compares a plaintext with a hashed value

        :param plain_text: The text that was hashed
        :param hashed_value: The hashed value
        """

        salt = None
        if not self.without_salt:
            salt = self.salt
            if "//" in hashed_value:
                hashed_value, salt = hashed_value.split("//")

        hash_length = len(hashed_value)

        comparison_hash = FastHashing(salt=salt, without_salt = self.without_salt)\
            .hash(plain_text, hash_length = hash_length).split("//")[0]

        return comparison_hash == hashed_value


class Hashing:
    "Implementation of secure hashing with SHA256 and 200000 iterations"

    def __init__(self, salt: Optional[str] = None, without_salt: bool = False):
        """
        :param salt: The salt, makes the hashing process more secure (Optional)
        :param without_salt: If True, no salt is added to the hash
        """

        self.salt = salt
        self.without_salt = without_salt

    def hash(self, plain_text: str, hash_length: int = 32) -> str:
        """
        Function to hash a plaintext

        :param plain_text: The text to be hashed
        :param hash_length: The length of the returned hashed value
        """

        plain_text = str(plain_text).encode('utf-8')

        if not self.without_salt:
            salt = self.salt
            if salt is None:
                salt = secrets.token_bytes(32)
            else:
                if not isinstance(salt, bytes):
                    try:
                        salt = bytes.fromhex(salt)
                    except:
                        salt = salt.encode('utf-8')
        else:
            salt = None

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=hash_length,
            salt=salt,
            iterations=200000,
            backend=default_backend()
        )

        hashed_data = kdf.derive(plain_text)

        if not self.without_salt:
            hashed_value = b64encode(hashed_data).decode('utf-8') + "//" + salt.hex()
        else:
            hashed_value = b64encode(hashed_data).decode('utf-8')

        return hashed_value

    def compare(self, plain_text: str, hashed_value: str) -> bool:
        """
        Compares a plaintext with a hashed value

        :param plain_text: The text that was hashed
        :param hashed_value: The hashed value
        """

        if not self.without_salt:
            salt = self.salt
            if "//" in hashed_value:
                hashed_value, salt = hashed_value.split("//")

            if salt is None:
                raise ValueError("Salt cannot be None if there is no salt in hash")

            salt = bytes.fromhex(salt)
        else:
            salt = None

        hash_length = len(b64decode(hashed_value))

        comparison_hash = Hashing(salt=salt, without_salt = self.without_salt)\
            .hash(plain_text, hash_length = hash_length).split("//")[0]

        return comparison_hash == hashed_value


class SymmetricEncryption:
    "Implementation of symmetric encryption with AES"

    def __init__(self, password: Optional[str] = None, salt_length: int = 32):
        """
        :param password: A secure encryption password, should be at least 32 characters long
        :param salt_length: The length of the salt, should be at least 16
        """

        self.password = password.encode()
        self.salt_length = salt_length

    def encrypt(self, plain_text: str) -> str:
        """
        Encrypts a text

        :param plaintext: The text to be encrypted
        """

        salt = secrets.token_bytes(self.salt_length)

        kdf_ = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf_.derive(self.password)

        iv = secrets.token_bytes(16)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                        backend=default_backend())
        encryptor = cipher.encryptor()
        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plain_text.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return urlsafe_b64encode(salt + iv + ciphertext).decode()

    def decrypt(self, cipher_text: str) -> str:
        """
        Decrypts a text

        :param ciphertext: The encrypted text
        """

        cipher_text = urlsafe_b64decode(cipher_text.encode())

        salt, iv, cipher_text = cipher_text[:self.salt_length], cipher_text[
            self.salt_length:self.salt_length + 16], cipher_text[self.salt_length + 16:]

        kdf_ = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf_.derive(self.password)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                        backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = decryptor.update(cipher_text) + decryptor.finalize()
        plaintext = unpadder.update(decrypted_data) + unpadder.finalize()

        return plaintext.decode()


class AsymmetricEncryption:
    "Implementation of secure asymmetric encryption with RSA"

    def __init__(self, public_key: Optional[str] = None, private_key: Optional[str] = None):
        """
        :param public_key: The public key to encrypt a message / to verify a signature
        :param private_key: The private key to decrypt a message / to create a signature
        """

        self.public_key, self.private_key = public_key, private_key

        if not public_key is None:
            self.publ_key = serialization.load_der_public_key(
                b64decode(public_key.encode("utf-8")), backend=default_backend()
            )
        else:
            self.publ_key = None

        if not private_key is None:
            self.priv_key = serialization.load_der_private_key(
                b64decode(private_key.encode("utf-8")), password=None, backend=default_backend()
            )
        else:
            self.priv_key = None

    def generate_keys(self, key_size: int = 2048) -> "AsymmetricEncryption":
        """
        Generates private and public key

        :param key_size: The key size of the private key
        """
        self.priv_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        self.private_key = b64encode(self.priv_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )).decode("utf-8")

        self.publ_key = self.priv_key.public_key()
        self.public_key = b64encode(self.publ_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )).decode("utf-8")

        return self

    def encrypt(self, plain_text: str) -> Tuple[str, str]:
        """
        Encrypt the provided plain_text using asymmetric and symmetric encryption

        :param plain_text: The text to be encrypted
        """

        if self.publ_key is None:
            raise ValueError("The public key cannot be None in encode, this error occurs because no public key was specified when initializing the AsymmetricCrypto function and none was generated with generate_keys.")

        symmetric_key = secrets.token_bytes(64)

        cipher_text = SymmetricEncryption(symmetric_key).encrypt(plain_text)

        encrypted_symmetric_key = self.publ_key.encrypt(
            symmetric_key,
            asy_padding.OAEP(
                mgf = asy_padding.MGF1(
                    algorithm = hashes.SHA256()
                ),
                algorithm = hashes.SHA256(),
                label = None
            )
        )

        encrypted_key = b64encode(encrypted_symmetric_key).decode('utf-8')
        return f"{encrypted_key}//{cipher_text}", b64encode(symmetric_key).decode('utf-8')

    def decrypt(self, cipher_text: str) -> str:
        """
        Decrypt the provided cipher_text using asymmetric and symmetric decryption

        :param cipher_text: The encrypted message with the encrypted symmetric key
        """

        if self.priv_key is None:
            raise ValueError("The private key cannot be None in decode, this error occurs because no private key was specified when initializing the AsymmetricCrypto function and none was generated with generate_keys.")

        encrypted_key, cipher_text = cipher_text.split("//")[0], cipher_text.split("//")[1]
        encrypted_symmetric_key = b64decode(encrypted_key.encode('utf-8'))

        symmetric_key = self.priv_key.decrypt(
            encrypted_symmetric_key, 
            asy_padding.OAEP(
                mgf = asy_padding.MGF1(
                    algorithm=hashes.SHA256()
                ),
                algorithm = hashes.SHA256(),
                label = None
            )
        )

        plain_text = SymmetricEncryption(symmetric_key).decrypt(cipher_text)

        return plain_text

    def sign(self, plain_text: Union[str, bytes]) -> str:
        """
        Sign the provided plain_text using the private key

        :param plain_text: The text to be signed
        """

        if self.priv_key is None:
            raise ValueError("The private key cannot be None in sign, this error occurs because no private key was specified when initializing the AsymmetricCrypto function and none was generated with generate_keys.")

        if isinstance(plain_text, str):
            plain_text = plain_text.encode()

        signature = self.priv_key.sign(
            plain_text,
            asy_padding.PSS(
                mgf = asy_padding.MGF1(
                    hashes.SHA256()
                ),
                salt_length = asy_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return b64encode(signature).decode('utf-8')

    def verify_sign(self, signature: str, plain_text: Union[str, bytes]) -> bool:
        """
        Verify the signature of the provided plain_text using the public key

        :param sign_text: The signature of the plain_text with base64 encoding
        :param plain_text: The text whose signature needs to be verified
        """

        if self.publ_key is None:
            raise ValueError("The public key cannot be None in verify_sign, this error occurs because no public key was specified when initializing the AsymmetricCrypto function and none was generated with generate_keys.")

        if isinstance(plain_text, str):
            plain_text = plain_text.encode()

        signature = b64decode(signature)

        try:
            self.publ_key.verify(
                signature,
                plain_text,
                asy_padding.PSS(
                    mgf = asy_padding.MGF1(
                        hashes.SHA256()
                    ),
                    salt_length = asy_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            return True
        except:
            return False

def load_persistent_storage_file(file_name: str, persistent_storage_encryptor: SymmetricEncryption) -> Union[dict, list]:
    """
    Load encrypted persistent data from a file.

    Parameters:
    :param: file_name: The name of the file containing the encrypted data.
    :param persistent_storage_encryptor: The encryption object to decrypt the data.
    """

    with open(file_name, "r", encoding = "utf-8") as readable_file:
        encrypted_persistent_data = readable_file.read()

    persistent_data = persistent_storage_encryptor.decrypt(encrypted_persistent_data)
    loaded_persistent_data = json.loads(persistent_data)

    return loaded_persistent_data

def dump_persistent_storage_data(file_name: str, persistent_data: Union[dict, list], persistent_storage_encryptor: SymmetricEncryption) -> None:
    """
    Dump persistent data into an encrypted file.

    Parameters:
    :param file_name: The name of the file to store the encrypted data.
    :param persistent_data: The persistent data to be stored.
    :param persistent_storage_encryptor: The encryption object to encrypt the data.
    """

    dumped_persistent_data = json.dumps(persistent_data)
    encrypted_persistent_data = persistent_storage_encryptor.encrypt(dumped_persistent_data)

    with open(file_name, "w", encoding = "utf-8") as writeable_file:
        writeable_file.write(encrypted_persistent_data)

    return

class SilentUndefined(Undefined):
    "Class to not get an error when specifying a non-existent argument"

    def _fail_with_undefined_error(self, *args, **kwargs):
        return None

class WebPage:
    "Class with useful tools for WebPages"

    @staticmethod
    def _minimize_tag_content(html: str, tag: str) -> str:
        """
        Minimizes the content of a given tag
        
        :param html: The HTML page where the tag should be minimized
        :param tag: The HTML tag e.g. "script" or "style"
        """

        tag_pattern = rf'<{tag}\b[^>]*>(.*?)<\/{tag}>'

        def minimize_tag_content(match: re.Match):
            content = match.group(1)
            content = re.sub(r'\s+', ' ', content)
            return f'<{tag}>{content}</{tag}>'

        return re.sub(tag_pattern, minimize_tag_content, html, flags=re.DOTALL | re.IGNORECASE)

    @staticmethod
    def minimize(html: str) -> str:
        """
        Minimizes an HTML page

        :param html: The content of the page as html
        """

        html = re.sub(r'<!--(.*?)-->', '', html, flags=re.DOTALL)
        html = re.sub(r'\s+', ' ', html)

        html = WebPage._minimize_tag_content(html, 'script')
        html = WebPage._minimize_tag_content(html, 'style')
        return html

    @staticmethod
    def render_template(file_name: Optional[str] = None, html: Optional[str] = None, **args) -> str:
        """
        Function to render a HTML template (= insert arguments / translation / minimization)

        :param file_name: From which file HTML code should be loaded (Optional)
        :param html: The content of the page as html (Optional)
        :param args: Arguments to be inserted into the WebPage with Jinja2
        """

        if file_name is None and html is None:
            raise ValueError("Arguments 'file_path' and 'html' are None")
        
        file_path = os.path.join(CURRENT_DIR_PATH, "templates", file_name)

        if not file_path is None:
            if not os.path.isfile(file_path):
                raise FileNotFoundError(f"File `{file_path}` does not exist")

        env = Environment(
            autoescape=select_autoescape(['html', 'xml']),
            undefined=SilentUndefined
        )

        if html is None:
            with open(file_path, "r", encoding="utf-8") as file:
                html = file.read()

        template = env.from_string(html)

        html = template.render(**args)
        html = WebPage.minimize(html)

        return html
