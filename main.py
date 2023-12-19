# ~~~
# This is a copy of the free chat program "CipherChat" under GPL-3.0 license
# GitHub: https://github.com/tn3w/CipherChat
# ~~~

from sys import exit

if __name__ != "__main__":
    exit(0)

from rich.console import Console
from utils import clear_console, get_system_architecture, Tor, download_file, get_gnupg_path, Linux, SecureDelete
import os
from cons import DATA_DIR_PATH, TEMP_DIR_PATH, DEFAULT_BRIDGES
import subprocess
import tarfile
import json
import secrets
import requests
import zipfile
from bs4 import BeautifulSoup

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
    CONSOLE.print("[bold yellow]~~~ Installing Tor ~~~")
    with CONSOLE.status("[green]Trying to get the download links for Tor..."):
        download_link, signature_link = Tor.get_download_link()
    CONSOLE.print("[green]~ Trying to get the download links for Tor... Done")
    
    if None in [download_link, signature_link]:
        CONSOLE.print("[red][Critical Error] Tor Expert Bundle could not be installed because no download link or signature link could be found, install it manually.")
        exit(1)
    
    if not os.path.isdir(TEMP_DIR_PATH):
        os.mkdir(TEMP_DIR_PATH)

    bundle_file_path = download_file(download_link, TEMP_DIR_PATH, "Tor Expert Bundle")
    bundle_signature_file_path = download_file(signature_link, TEMP_DIR_PATH, "Tor Expert Bundle Signature")

    with CONSOLE.status("[green]Loading Tor Keys from keys.gnupg.net..."):
        try:
            subprocess.run([GNUPG_EXECUTABLE_PATH, "--keyserver", "keys.gnupg.net", "--recv-keys", "0xEF6E286DDA85EA2A4BA7DE684E2C6E8793298290"], check=True)
        except subprocess.CalledProcessError as e:
            CONSOLE.log(f"[red]An Error occured: `{e}`")
            CONSOLE.print("[red][Critical Error] Could not load Tor Keys from keys.gnupg.net")
            exit(1)
    CONSOLE.print("[green]~ Loading Tor Keys from keys.gnupg.net... Done")

    with CONSOLE.status("[green]Validating Signature..."):
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

    with CONSOLE.status("[green]Extracting the TOR archive..."):
        ARCHIV_PATH = os.path.join(DATA_DIR_PATH, "tor")
        os.makedirs(os.path.join(DATA_DIR_PATH, "tor"), exist_ok=True)

        with tarfile.open(bundle_file_path, 'r:gz') as tar:
            tar.extractall(path=ARCHIV_PATH)
        
        if SYSTEM in ["macOS", "Linux"]:
            os.system(f"chmod +x {TOR_EXECUTABLE_PATH}")
    
    with CONSOLE.status("[green]Cleaning up (this can take up to 2 minutes)..."):
        SecureDelete.directory(TEMP_DIR_PATH)
    CONSOLE.print("[green]~ Cleaning up... Done")

BRIDGE_CONFIG_PATH = os.path.join(DATA_DIR_PATH, "bridge.conf")
bridge_type, use_default_bridge = None, None

if os.path.isfile(BRIDGE_CONFIG_PATH):
    try:
        with open(BRIDGE_CONFIG_PATH, "r") as readable_file:
            file_config = readable_file.read()
        bridge_type, use_default_bridge = file_config.split("--")[:2]
        use_default_bridge = {"true": True, "false": False}.get(use_default_bridge, True)

        if not bridge_type in ["obfs4", "webtunnel", "snowflake", "meek_lite", "vanilla", "random"]:
            bridge_type = None

        if bridge_type in ["snowflake", "meek_lite"]:
            use_default_bridge = False
    except:
        pass

if bridge_type is None:
    bridge_types = ["vanilla", "obfs4", "webtunnel", "snowflake (only buildin)", "meek_lite (only buildin)", "Random selection"]
    selected_option = 0

    while True:
        clear_console()
        CONSOLE.print("[bold yellow]~~~ Bridge selection ~~~")

        for i, option in enumerate(bridge_types):
            if i == selected_option:
                print(f"[>] {option}")
            else:
                print(f"[ ] {option}")
        
        key = input("\nChoose bridge type (c to confirm): ")

        if not key.lower() in ["c", "confirm"]:
            if len(bridge_types) < selected_option + 2:
                selected_option = 0
            else:
                selected_option += 1
        else:
            bridge_type = bridge_types[selected_option].replace(" (only buildin)", "").replace("Random selection", "random")
            break
    
    if bridge_type in ["snowflake", "meek_lite"]:
        use_default_bridge = True

if not isinstance(use_default_bridge, bool):
    use_buildin_input = input("Use buildin bridges? [y - yes, n - no]: ")
    use_default_bridge = use_buildin_input.startswith("y")

try:
    with open(BRIDGE_CONFIG_PATH, "w") as writeable_file:
        writeable_file.write('--'.join([bridge_type, {True: "true", False: "false"}.get(use_default_bridge)]))
except:
    pass

if not bridge_type == "random":
    default_bridges = DEFAULT_BRIDGES[bridge_type]
    bridges = Tor.select_random_bridges(default_bridges, 4)
else:
    default_bridges = []
    for _, specific_bridges in DEFAULT_BRIDGES.items():
        default_bridges.extend(Tor.select_random_bridges(specific_bridges, 2))
    bridges = Tor.select_random_bridges(default_bridges, 4)
    print(bridges)

clear_console()

if not use_default_bridge:
    CONSOLE.print("[bold yellow]~~~ Bridge Selection ~~~")

    is_file_missing = False
    if not bridge_type == "random":
        bridge_path = os.path.join(DATA_DIR_PATH, bridge_type + ".json")
        is_file_missing = not os.path.isfile(bridge_path)
    else:
        for specific_bridge_type in ["vanilla", "obfs4", "webtunnel"]:
            bridge_path = os.path.join(DATA_DIR_PATH, specific_bridge_type + ".json")
            is_file_missing = not os.path.isfile(bridge_path)

            if is_file_missing:
                break

    if is_file_missing:
        clear_console()
        CONSOLE.print("[bold yellow]~~~ Downloading Tor Bridges ~~~")
        with CONSOLE.status("[green]Starting Tor Executable..."):
            control_password, tor_process = Tor.launch_tor_with_config(8030, 8031, bridges)
        
        if not os.path.isdir(TEMP_DIR_PATH):
            os.mkdir(TEMP_DIR_PATH)

        session = Tor.get_requests_session(8030, control_password, 8031)

        if not bridge_type == "random":
            Tor.download_bridge(bridge_type, session)
        else:
            for specific_bridge_type in ["vanilla", "obfs4", "webtunnel"]:
                bridge_path = os.path.join(DATA_DIR_PATH, specific_bridge_type + ".json")
                if not os.path.isfile(bridge_path):
                    Tor.download_bridge(specific_bridge_type, session)
        
        with CONSOLE.status("[green]Terminating Tor..."):
            Tor.send_shutdown_signal(9010, control_password)
            tor_process.terminate()

        with CONSOLE.status("[green]Cleaning up (this can take up to 1 minute)..."):
            SecureDelete.directory(TEMP_DIR_PATH)
        CONSOLE.print("[green]~ Cleaning up... Done")

    if os.path.isfile(bridges_path):
        with open(bridges_path, "r") as readable_file:
            all_bridges = json.load(readable_file)
        
        if bridge_type in ["obfs4", "webtunnel"]:
            active_bridges = []
            checked_bridges = []
            with CONSOLE.status("[green]Bridges are selected (this can take up to 2 minutes)..."):
                while not len(active_bridges) >= 6:
                    random_bridge = secrets.choice(all_bridges)
                    while random_bridge in checked_bridges:
                        random_bridge = secrets.choice(all_bridges)
                    
                    if bridge_type == "obfs4":
                        bridge_address = random_bridge.split("obfs4 ")[1].split(":")[0]
                        bridge_port = random_bridge.split("obfs4 ")[1].split(":")[1].split(" ")[0]
                        if Tor.is_obfs4_bridge_online(bridge_address, bridge_port):
                            active_bridges.append(random_bridge)
                    else:
                        bridge_url = random_bridge.split("url=")[1].split(" ")[0]
                        if Tor.is_webtunnel_bridge_online(bridge_url):
                            active_bridges.append(random_bridge)
                    
                    checked_bridges.append(random_bridge)
            
            bridges = active_bridges
        else:
            bridges = Tor.select_random_bridges(all_bridges, {"snowflake": 2}.get(bridge_type, 1))