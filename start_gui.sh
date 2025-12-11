#!/bin/bash

# Start GUI for Packet Guardian
# This script launches the graphical interface

echo "=================================="
echo "Packet Guardian GUI Launcher"
echo "=================================="
echo ""

cd "$(dirname "$0")/source"

# Check if running with sudo
if [ "$EUID" -ne 0 ]; then 
    echo "⚠️  WARNING: GUI is not running with sudo privileges"
    echo "   Packet capture will not work without sudo!"
    echo ""
    echo "To run with sudo:"
    echo "   sudo ./start_gui.sh"
    echo ""
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Launch GUI
echo "Starting GUI..."
/opt/anaconda3/envs/packet-guardian/bin/python gui.py