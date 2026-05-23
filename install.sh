#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e .

cat <<'EOF'
Installation complete.

Next steps:
  1. Activate the virtual environment:
     source .venv/bin/activate
  2. Run the detector:
     sudo .venv/bin/honeypot-detector --help
     sudo .venv/bin/honeypot-detector --target-ssid Net_Test --channel 44

For a different setup, pass your own interface and SSID values:
  sudo .venv/bin/honeypot-detector --interface wlan0mon --managed-interface wlo1 --target-ssid Net_Test
EOF