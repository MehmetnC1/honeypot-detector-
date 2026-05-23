import threading
import time
import random
import string
import os
import sys
import argparse
import scapy.all as scapy
from rich.console import Console
from rich.table import Table

import subprocess

# Console instance for clean terminal output
console = Console()

# Monitor-mode interface to listen on (change if needed: wlan0mon, wlan0, etc.)
INTERFACE = os.getenv("INTERFACE", "wlan0mon")
MANAGED_INTERFACE = os.getenv("MANAGED_INTERFACE", "")
TARGET_SSID = os.getenv("TARGET_SSID", "Net_Test")
TARGET_CHANNEL = os.getenv("TARGET_CHANNEL", "")
LURE_PREFIX = os.getenv("LURE_PREFIX", "Net_Test")
AUTO_CHANNEL = os.getenv("AUTO_CHANNEL", "1") not in {"0", "false", "False", "no", "No"}

# Store the fake/trap SSIDs we broadcast
sent_fake_ssids = set()
seen_ssid_bssids = {}

def generate_random_ssid():
    """Generate a unique fake network name for broadcasting."""
    prefix = LURE_PREFIX
    random_str = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    return f"{prefix}{random_str}"

def ensure_interface_ready(interface):
    """Ensure the interface exists and is ready for packet capture."""
    available_interfaces = scapy.get_if_list()
    if interface not in available_interfaces:
        console.print(f"[bold red][!][/bold red] Interface not found: {interface}")
        console.print(f"[bold yellow][i][/bold yellow] Available interfaces: {', '.join(available_interfaces)}")
        return False

    operstate_path = f"/sys/class/net/{interface}/operstate"
    if os.path.exists(operstate_path):
        try:
            with open(operstate_path, "r", encoding="utf-8") as state_file:
                state = state_file.read().strip().lower()
            if state == "down":
                console.print(f"[bold red][!][/bold red] Interface is down: {interface}")
                console.print(f"[bold yellow][i][/bold yellow] Bring it up first with: sudo ip link set {interface} up")
                return False
        except OSError:
            pass

    return True

def get_managed_interface():
    """Try to find a managed (client) wireless interface via `iw dev` output."""
    if MANAGED_INTERFACE:
        return MANAGED_INTERFACE
    try:
        out = subprocess.check_output(["iw", "dev"], text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return None

    iface = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Interface "):
            iface = line.split()[1]
        if line.startswith("type ") and "managed" in line and iface:
            return iface
    return None

def freq_to_channel(freq):
    try:
        f = int(float(freq))
    except Exception:
        return None
    if f >= 5000:
        return int((f - 5000) / 5)
    return int((f - 2407) / 5)

def find_ssid_channel(prefix, managed_iface=None, timeout=8):
    """Scan with the managed interface for SSIDs that start with `prefix` and return its channel.
    Returns (channel, freq) or (None, None).
    """
    if managed_iface is None:
        managed_iface = get_managed_interface()
    if not managed_iface:
        return None, None

    try:
        out = subprocess.check_output(["sudo", "iw", "dev", managed_iface, "scan"], text=True, timeout=timeout)
    except subprocess.CalledProcessError:
        return None, None
    except Exception:
        return None, None

    current_freq = None
    ssid_map = {}
    for line in out.splitlines():
        l = line.strip()
        if l.startswith("freq:"):
            parts = l.split()
            if len(parts) >= 2:
                current_freq = parts[1]
        if l.startswith("SSID:"):
            ssid = l.split("SSID:", 1)[1].strip()
            if ssid:
                ssid_map[ssid] = current_freq

    for ssid, freq in ssid_map.items():
        if ssid.startswith(prefix):
            return freq_to_channel(freq), freq

    return None, None

def set_monitor_channel(interface, channel):
    try:
        subprocess.check_call(["sudo", "iw", "dev", interface, "set", "channel", str(channel)])
        return True
    except Exception:
        return False

def parse_args():
    parser = argparse.ArgumentParser(
        description="Wireless honeypot detector that broadcasts lure SSIDs and watches for impersonators."
    )
    parser.add_argument("--interface", default=INTERFACE, help="Monitor-mode interface to sniff on (default: wlan0mon).")
    parser.add_argument("--managed-interface", default=MANAGED_INTERFACE, help="Managed interface used for scanning the target SSID.")
    parser.add_argument("--target-ssid", default=TARGET_SSID, help="SSID to search for and monitor.")
    parser.add_argument("--channel", default=TARGET_CHANNEL, help="Channel to tune the monitor interface to. If omitted, the tool can auto-detect it from the target SSID.")
    parser.add_argument("--lure-prefix", default=LURE_PREFIX, help="Prefix used when generating fake lure SSIDs.")
    parser.add_argument("--no-auto-channel", action="store_true", help="Disable automatic SSID scan and channel tuning.")
    parser.add_argument("--auto-channel", dest="auto_channel", action="store_true", help="Enable automatic SSID scan and channel tuning.")
    parser.set_defaults(auto_channel=AUTO_CHANNEL)
    return parser.parse_args()

def send_probe_requests():
    """Continuously broadcast fake Probe Request packets in the background."""
    console.print(f"[bold green][*][/bold green] Trap request sender started...")
    
    counter = 0
    while True:
        counter += 1
        # Occasionally send a probe for the exact target SSID to provoke impersonators
        if counter % 5 == 0:
            fake_ssid = TARGET_SSID
        else:
            fake_ssid = generate_random_ssid()
        sent_fake_ssids.add(fake_ssid)
        
        # Build an 802.11 Probe Request packet
        # RadioTap: radio metadata, Dot11: base 802.11 frame, Dot11ProbeReq: request type
        # addr1: destination (broadcast), addr2: source MAC, addr3: transmitter/SSID (randomized)
        packet = (
            scapy.RadioTap()
            / scapy.Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff", addr2=scapy.RandMAC(), addr3=scapy.RandMAC())
            / scapy.Dot11ProbeReq()
            / scapy.Dot11Elt(ID="SSID", info=fake_ssid)
        )
        
        try:
            # Send the packet over the air (verbose=False suppresses extra output)
            scapy.sendp(packet, iface=INTERFACE, verbose=False, count=2)
            # Trim old entries to avoid growing the set forever
            if len(sent_fake_ssids) > 100:
                sent_fake_ssids.pop()
        except Exception as e:
            console.print(f"[bold red][!][/bold red] Packet send error: {e}")
            
        time.sleep(3) # Add a new lure every 3 seconds

def packet_handler(pkt):
    """Inspect every packet captured from the air."""
    # Only filter 802.11 management packets that are Probe Response (Subtype 5)
    if pkt.haslayer(scapy.Dot11) and pkt.type == 0 and pkt.subtype == 5:
        try:
            bssid = pkt.addr3 # MAC address of the responding device
            
            # Try to read signal strength (RSSI) from the RadioTap layer
            try:
                rssi = pkt.dBm_AntSignal
            except AttributeError:
                rssi = "N/A"
            # Try to extract the SSID safely
            ssid = None
            if pkt.haslayer(scapy.Dot11Elt):
                try:
                    ssid = pkt[scapy.Dot11Elt].info.decode('utf-8', errors='ignore')
                except Exception:
                    ssid = None

            # Record the BSSID whenever an SSID is seen
            if ssid:
                seen = seen_ssid_bssids.get(ssid, set())
                seen.add(bssid)
                seen_ssid_bssids[ssid] = seen

            # If the response matches one of our trap SSIDs or the target SSID has multiple BSSIDs:
            if ssid and (ssid in sent_fake_ssids or (ssid == TARGET_SSID and len(seen_ssid_bssids.get(ssid, [])) > 1)):
                os.system("cls" if os.name == "nt" else "clear")
                
                # Highlight the screen and show the detected honeypot in a table
                table = Table(title="🚨 FAKE WI-FI (HONEYPOT) DETECTED! 🚨", title_style="bold red")
                table.add_column("Parameter", style="cyan")
                table.add_column("Value", style="bold yellow")
                
                table.add_row("Trap SSID", ssid)
                table.add_row("Responding Device MAC (BSSID)", str(bssid).upper())
                table.add_row("Signal Strength (RSSI)", f"{rssi} dBm")
                table.add_row("Detection Time", time.strftime('%Y-%m-%d %H:%M:%S'))
                
                console.print(table)
                console.print("\n[bold red][ALERT][/bold red] Warning! A nearby device (such as a WiFi Pineapple) responded to the fake network you broadcast.")
                
                # Write the event to the log file
                with open("honeypot_alerts.log", "a") as log_file:
                    log_file.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] HONEYPOT DETECTED! SSID: {ssid} | MAC: {bssid} | RSSI: {rssi}\n")
        except Exception as e:
            console.print(f"[bold red][!][/bold red] Packet handling error: {e}")

def main():
    args = parse_args()

    global INTERFACE, MANAGED_INTERFACE, TARGET_SSID, TARGET_CHANNEL, LURE_PREFIX, AUTO_CHANNEL
    INTERFACE = args.interface
    MANAGED_INTERFACE = args.managed_interface
    TARGET_SSID = args.target_ssid
    TARGET_CHANNEL = args.channel
    LURE_PREFIX = args.lure_prefix
    AUTO_CHANNEL = args.auto_channel and not args.no_auto_channel

    if os.getuid() != 0:
        console.print("[bold red][!][/bold red] Root (sudo) privileges are required to run this tool!")
        return

    if not ensure_interface_ready(INTERFACE):
        sys.exit(1)

    console.print("[bold blue]=========================================[/bold blue]")
    console.print("[bold white]   Wireless Honeypot Sniffer v1.0        [/bold white]")
    console.print("[bold blue]=========================================[/bold blue]")
    console.print(f"[*] Listening interface: [bold yellow]{INTERFACE}[/bold yellow]")
    console.print(f"[*] Target SSID: [bold yellow]{TARGET_SSID}[/bold yellow]")
    if TARGET_CHANNEL:
        console.print(f"[*] Requested channel: [bold yellow]{TARGET_CHANNEL}[/bold yellow]")
    console.print(f"[*] Lure prefix: [bold yellow]{LURE_PREFIX}[/bold yellow]\n")

    if TARGET_CHANNEL:
        console.print("[bold green][*][/bold green] Tuning the monitor interface to the requested channel...")
        ok = set_monitor_channel(INTERFACE, TARGET_CHANNEL)
        if ok:
            console.print(f"[bold green][*][/bold green] {INTERFACE} tuned to channel {TARGET_CHANNEL}.")
        else:
            console.print(f"[bold red][!][/bold red] Could not tune {INTERFACE} to channel {TARGET_CHANNEL}.")
    elif AUTO_CHANNEL:
        console.print("[bold green][*][/bold green] Searching for the target SSID and tuning the channel...")
        channel, freq = find_ssid_channel(TARGET_SSID)
        if channel:
            console.print(f"[*] Target SSID found: freq={freq} -> channel={channel}. Tuning monitor interface...")
            ok = set_monitor_channel(INTERFACE, channel)
            if ok:
                console.print(f"[bold green][*][/bold green] {INTERFACE} tuned to channel {channel}.")
            else:
                console.print(f"[bold red][!][/bold red] Could not tune {INTERFACE} to the channel.")
        else:
            console.print("[bold yellow][i][/bold yellow] Target SSID not found; continuing on the current channel.")
    else:
        console.print("[bold yellow][i][/bold yellow] Auto channel tuning is disabled; continuing on the current channel.")

    # Start the request-sending function in the background as a separate thread
    sender_thread = threading.Thread(target=send_probe_requests, daemon=True)
    sender_thread.start()

    # Start sniffing on the main thread
    console.print("[bold green][*][/bold green] Sniffing is active. Waiting for packets...")
    scapy.sniff(iface=INTERFACE, prn=packet_handler, store=0)

if __name__ == "__main__":
    main()