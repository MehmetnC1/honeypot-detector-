#!/bin/bash
# Honeypot Detector - Quick Runner Script

cd "$(dirname "$0")"

# INTERFACE environment variable takes precedence; otherwise the code default is used.
sudo INTERFACE="${INTERFACE:-wlan0mon}" .venv/bin/honeypot-detector
