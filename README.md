# Honeypot Detector

Wireless honeypot detector built with Scapy and Rich.

## Author

GitHub profile: [MehmetnC1](https://github.com/MehmetnC1)

## Quick Start

Clone the public repository, then run the installer:

```bash
git clone https://github.com/MehmetnC1/honeypot-detector.git
cd honeypot-detector
chmod +x install.sh
./install.sh
```

After installation, use the installed command from the local virtual environment:

```bash
sudo .venv/bin/honeypot-detector --target-ssid Net_Test --channel 44
```

## Configuration

The tool is designed to be used without editing the code. Pass your own values at runtime:

```bash
sudo .venv/bin/honeypot-detector --help
sudo .venv/bin/honeypot-detector --interface wlan0mon --managed-interface wlo1 --target-ssid Net_Test --channel 44
sudo .venv/bin/honeypot-detector --target-ssid MyHotspot --channel 44
sudo .venv/bin/honeypot-detector --no-auto-channel --target-ssid MyHotspot
```

Environment variables are also supported:

```bash
INTERFACE=wlan0mon
MANAGED_INTERFACE=wlo1
TARGET_SSID=MyHotspot
TARGET_CHANNEL=44
LURE_PREFIX=TrapNet
```

## Manual Run

If you prefer not to use the installer, create the virtual environment manually:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
sudo .venv/bin/honeypot-detector --target-ssid MyHotspot --channel 44
```

## Repository Cleanup

The repository is intentionally kept source-only. Generated artifacts such as packet captures, logs, caches, and virtual environments are ignored by `.gitignore` and should not be committed.

## Publish to GitHub

1. Create a public repository named `honeypot-detector` under the [MehmetnC1](https://github.com/MehmetnC1) account.
2. Push this project to that repository.
3. Keep `.gitignore` in place so generated files stay out of the repo.
4. Share the repository URL so others can clone and install it with the commands above.
