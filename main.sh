#!/bin/bash

# File: main.sh
# Author: Neo-virex

BLUE="\033[1;34m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RESET="\033[0m"

OUTPUT_DIR="/tmp/outputs"

# Create output directory if not exists
mkdir -p "$OUTPUT_DIR"

echo -e "${BLUE}====================================="
echo -e "         Neo-virex CTF Suite"
echo -e "=====================================${RESET}"

read -rp $'\033[1;33m[?] Enter target IP address or domain: \033[0m' TARGET

echo -e "${GREEN}[+] Output will be saved in: ${OUTPUT_DIR}${RESET}"

while true; do
    echo -e "${YELLOW}"
    echo "=========== MAIN MENU ==========="
    echo "1) Reconnaissance"
    echo "2) Vulnerability Scanning"
    echo "3) Exploitation"
    echo "4) Password Cracking"
    echo "5) Reverse Shell Generator"
    echo "0) Exit"
    echo -ne "${RESET}[?] Select an option: "
    read -r option

    case $option in
        1)
            echo "[*] Starting Recon Module on target: $TARGET ..."
            # Call recon script or function passing $TARGET
            ./modules/recon.sh "$TARGET" "$OUTPUT_DIR"
            ;;
        2)
            echo "[*] Starting Vulnerability Scanning on target: $TARGET ..."
            ./modules/vuln_scan.sh "$TARGET" "$OUTPUT_DIR"
            ;;
        3)
            echo "[*] Starting Exploitation module on target: $TARGET ..."
            ./modules/exploit.sh "$TARGET" "$OUTPUT_DIR"
            ;;
        4)
            echo "[*] Starting Password Cracking Suite ..."
            ./modules/crack_suite.sh
            ;;
        5)
            echo "[*] Starting Reverse Shell Generator ..."
            ./modules/rev_shell.sh "$OUTPUT_DIR"
            ;;
        0)
            echo "Exiting... Goodbye!"
            exit 0
            ;;
        *)
            echo "Invalid option, please select again."
            ;;
    esac
done
