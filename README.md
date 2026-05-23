# Honeypot Detector

Lightweight wireless honeypot detector built with Scapy and Rich.

## Author

GitHub: [MehmetnC1](https://github.com/MehmetnC1)

## Quick Start

Clone the repository and run the installer (the repository for this workspace is already pushed):

```bash
git clone https://github.com/MehmetnC1/honeypot-detector-
cd honeypot-detector-
chmod +x install.sh
./install.sh
```

Activate the local virtual environment and run the detector:

```bash
source .venv/bin/activate
sudo .venv/bin/honeypot-detector --target-ssid Net_Test --channel 44
```

## Usage

Common examples:

```bash
# show help
sudo .venv/bin/honeypot-detector --help

# sniff on a specific monitor interface and managed interface
sudo .venv/bin/honeypot-detector --interface wlan0mon --managed-interface wlo1 --target-ssid Net_Test --channel 44

# disable automatic channel detection
sudo .venv/bin/honeypot-detector --no-auto-channel --target-ssid MyHotspot --channel 44
```

Environment variables (alternative):

```bash
export INTERFACE=wlan0mon
export MANAGED_INTERFACE=wlo1
export TARGET_SSID=MyHotspot
export TARGET_CHANNEL=44
export LURE_PREFIX=TrapNet
```

## Manual installation (without `install.sh`)

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
sudo .venv/bin/honeypot-detector --target-ssid MyHotspot --channel 44
```

## Notes

- The detector requires a wireless interface in monitor mode to sniff probe responses. Use a separate managed interface for active scans if available.
- Common cause of missed packets: monitor interface tuned to a different band (2.4 GHz vs 5 GHz). Use `--channel` or automatic channel detection to align interfaces.

## Repository

This repository is already pushed to your GitHub account at:

https://github.com/MehmetnC1/honeypot-detector-

If you want the repository name without the trailing hyphen, let me know and I can help rename it and fix URLs.

## Contributing

Pull requests, issues and improvements are welcome. If you add features, keep generated artifacts out of the repo and update `README.md` accordingly.

---

