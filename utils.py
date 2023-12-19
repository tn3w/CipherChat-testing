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
import secrets
import requests
import random
import shutil
import subprocess
import concurrent.futures
import multiprocessing
from cons import USER_AGENTS, DISTRO_TO_PACKAGE_MANAGER, PACKAGE_MANAGERS, DATA_DIR_PATH, BRIDGE_DOWNLOAD_URLS, TEMP_DIR_PATH, DEFAULT_BRIDGES
from bs4 import BeautifulSoup
from rich.progress import Progress
from rich.console import Console
import distro
from urllib.parse import urlparse
from stem.control import Controller
from stem import Signal
import time
import psutil
import socket
import json

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

def generate_random_string(length: int, with_punctuation: bool = True, with_letters: bool = True) -> str:
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

def download_file(url: str, dict_path: str, operation_name: Optional[str] = None, file_name: Optional[str] = None,\
                  session: requests.Session = requests.Session()) -> Optional[str]:
    """
    Function to download a file

    :param url: The url of the file
    :param dict_path: Specifies the directory where the file should be saved
    :param operation_name: Sets the name of the operation in the console (Optional)
    :param file_name: Sets the file name (Optional)
    :param session: a requests.Session (Optional)
    """

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
                response = session.get(url, stream=True, headers={'User-Agent': random.choice(USER_AGENTS)}, timeout=5)
                response.raise_for_status()
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
        Function to securely delete a file by replacing it first with random characters and then according to Gutmann patterns and DoD 5220.22-M patterns

        :param file_path: The path to the file
        :param quite: If True nothing is written to the console
        """
        if not os.path.isfile(file_path):
            return

        file_size = os.path.getsize(file_path)
        file_size_times_two = file_size * 2

        gutmann_patterns = [bytes([i % 256] * (file_size_times_two)) for i in range(35)]
        dod_patterns = [bytes([0x00] * file_size_times_two), bytes([0xFF] * file_size_times_two), bytes([0x00] * file_size_times_two)]

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
            except:
                pass
    
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
                        print(f"[Error] Error deleting directory '{directory}': {e}")

            try:
                shutil.rmtree(directory_path)
            except Exception as e:
                if not quite:
                    print(f"[Error] Error deleting directory '{directory_path}': {e}")

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

SYSTEM, MACHINE = get_system_architecture()
TOR_EXECUTABLE_PATH = {"Windows": os.path.join(DATA_DIR_PATH, "tor/tor/tor.exe")}.get(SYSTEM, os.path.join(DATA_DIR_PATH, "tor/tor/tor"))
PLUGGABLE_TRANSPORTS_PATH = os.path.join(DATA_DIR_PATH, "tor", "tor", "pluggable_transports")
SNOWFLAKE_EXECUTABLE_PATH = os.path.join(PLUGGABLE_TRANSPORTS_PATH, {"Windows": "snowflake-client.exe"}.get(SYSTEM, "snowflake-client"))
WEBTUNNEL_EXECUTABLE_PATH = os.path.join(PLUGGABLE_TRANSPORTS_PATH, {"Windows": "webtunnel-client.exe"}.get(SYSTEM, "webtunnel-client"))
LYREBIRD_EXECUTABLE_PATH = os.path.join(PLUGGABLE_TRANSPORTS_PATH, {"Windows": "lyrebird.exe"}.get(SYSTEM, "lyrebird"))
CONJURE_EXECUTABLE_PATH = os.path.join(PLUGGABLE_TRANSPORTS_PATH, {"Windows": "conjure-client.exe"}.get(SYSTEM, "lyrebird"))
TOR_DATA_DIR2_PATH = os.path.join(DATA_DIR_PATH, "tor", "data2")

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
    
    @staticmethod
    def terminate_tor_processes():
        try:
            for process in psutil.process_iter(attrs=['pid', 'name', 'cmdline']):
                    if "tor" == process.name().strip():
                        process.terminate()
        except:
            pass
    
    @staticmethod
    def launch_tor_with_config(control_port: int, socks_port: int, bridges: list, is_service: bool = False) -> Tuple[str, subprocess.Popen]:
        random_password = generate_random_string(16)

        tor_process = subprocess.Popen([TOR_EXECUTABLE_PATH, "--hash-password", random_password], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        hashed_password, _ = tor_process.communicate()
        hashed_password = hashed_password.strip().decode()

        temp_config_path = os.path.join(DATA_DIR_PATH, "torrc")

        with open(temp_config_path, 'w+') as temp_config:
            temp_config.write(f"ControlPort {control_port}\n")
            temp_config.write(f"HashedControlPassword {hashed_password}\n")
            temp_config.write(f"SocksPort {socks_port}\n")

            if is_service:
                if not os.path.isdir(TOR_DATA_DIR2_PATH):
                    os.mkdir(TOR_DATA_DIR2_PATH)
                temp_config.write(f"DataDirectory {TOR_DATA_DIR2_PATH}\n")

            if not len(bridges) == 0:
                temp_config.write(f"UseBridges 1\n")
                temp_config.write(f"ClientTransportPlugin obfs4 exec {LYREBIRD_EXECUTABLE_PATH}\n")
                temp_config.write(f"ClientTransportPlugin snowflake exec {SNOWFLAKE_EXECUTABLE_PATH}\n")
                temp_config.write(f"ClientTransportPlugin webtunnel exec {WEBTUNNEL_EXECUTABLE_PATH}\n")
                temp_config.write(f"ClientTransportPlugin meek_lite exec {CONJURE_EXECUTABLE_PATH}\n")

            for bridge in bridges:
                temp_config.write(f"Bridge {bridge}\n")
        
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

                if warn_time is None:
                    if "[err]" in line or "[warn]" in line:
                        warn_time = int(time.time())
                
            if not warn_time is None:
                if warn_time + 10 < int(time.time()):
                    break

        with Controller.from_port(port=control_port) as controller:
            try:
                controller.authenticate(password=random_password)
            except:
                Tor.terminate_tor_processes()
            else:
                start_time = time.time()
                while not controller.is_alive():
                    if time.time() - start_time > 30:
                        raise TimeoutError("Timeout!")
                    time.sleep(1)
        
        os.remove(temp_config_path)
        
        return random_password, tor_process
    
    @staticmethod
    def send_shutdown_signal(control_port: int, control_password: str) -> None:
        try:
            with Controller.from_port(port=control_port) as controller:
                controller.authenticate(password=control_password)

                controller.signal(Signal.SHUTDOWN)
        except:
            Tor.terminate_tor_processes()
    
    @staticmethod
    def send_new_identity_signal(control_port: int, control_password: str) -> None:
        try:
            with Controller.from_port(port=control_port) as controller:
                controller.authenticate(password=control_password)

                controller.signal(Signal.NEWNYM)
        except:
            pass
    
    @staticmethod
    def get_requests_session(control_port: int, control_password: str, socks_port: int) -> requests.Session:
        if secrets.choice([True] + [False] * 8):
            Tor.send_new_identity_signal(control_port, control_password)
        
        session = requests.Session()

        session.proxies = {
            'http': 'socks5h://127.0.0.1:' + str(socks_port),
            'https': 'socks5h://127.0.0.1:' + str(socks_port)
        }

        return session

class Bridge:

    @staticmethod
    def _get_type(bridge: str) -> str:
        for bridge_type in ["obfs4", "webtunnel", "snowflake", "meek_lite"]:
            if bridge.startswith(bridge_type):
                return bridge_type
        return "vanilla"

    @staticmethod
    def _is_socket_bridge_online(bridge_address: str, bridge_port: int, timeout: int = 3) -> bool:
        try:
            with socket.create_connection((bridge_address, bridge_port), timeout=timeout) as s:
                return True
        except:
            return False

    @staticmethod
    def _is_webtunnel_bridge_online(webtunnel_url: str, timeout: int = 3) -> bool:
        try:
            requests.get(webtunnel_url, timeout=timeout, headers={'User-Agent': random.choice(USER_AGENTS)})
            return True
        except:
            return False

    @staticmethod
    def download(bridge_type, session: requests.Session):
        download_urls = BRIDGE_DOWNLOAD_URLS[bridge_type]
        bridge_path = os.path.join(DATA_DIR_PATH, bridge_type + ".json")

        file_path = download_file(download_urls["github"], TEMP_DIR_PATH, bridge_type.title() + " Bridges", bridge_type + ".txt", session)
        if file_path is None:
            file_path = download_file(download_urls["backup"], TEMP_DIR_PATH, bridge_type.title() + " Bridges", bridge_type + ".txt", session)

        if not os.path.isfile(file_path):
            CONSOLE.log("[red][Error] Error when downloading bridges, use of default bridges")
        else:
            with open(file_path, "r") as readable_file:
                unprocessed_bridges = readable_file.read()

            processed_bridges = [bridge.strip() for bridge in unprocessed_bridges.split("\n") if bridge.strip()]

            if {"vanilla": 800, "obfs4": 5000}.get(bridge_type, 20) >= len(processed_bridges):
                CONSOLE.log("[red][Error] Error when validating the bridges, bridges were either not downloaded correctly or the bridge page was compromised, use of default bridges")
            else:
                with open(bridge_path, "w") as writeable_file:
                    json.dump(processed_bridges, writeable_file)

    @staticmethod
    def select_random(all_bridges: list, quantity: int = 3) -> list:
        if len(all_bridges) == 1:
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
                    for bridge in bridge_types[bridge_type]:
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

        return selected_bridges
    
    @staticmethod
    def choose_buildin(bridge_type):
        with CONSOLE.status("[green]Bridges are selected (this can take up to 2 minutes)..."):
            if not bridge_type == "random":
                default_bridges = DEFAULT_BRIDGES[bridge_type]
                bridges = Bridge.select_random(default_bridges, 4)
            else:
                default_bridges = []
                for _, specific_bridges in DEFAULT_BRIDGES.items():
                    default_bridges.extend(specific_bridges)
                bridges = Bridge.select_random(default_bridges, 6)
        
        return bridges