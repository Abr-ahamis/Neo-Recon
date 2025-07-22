#!/bin/bash
# File: modules/recon.sh
# Author: Neo-virex

# Colors
RED="\e[31m"
GREEN="\e[32m"
BLUE="\e[34m"
YELLOW="\e[33m"
RESET="\e[0m"

OUTDIR="/tmp/outputs"
mkdir -p "$OUTDIR"

echo -e "${BLUE}[*] Starting Recon Module...${RESET}"
read -p "[?] Enter target IP or domain: " TARGET

# Create a unique recon directory
RECON_DIR="$OUTDIR/recon_$TARGET"
mkdir -p "$RECON_DIR"

echo -e "${YELLOW}[+] Running nmap basic scan...${RESET}"
nmap -sV -T4 "$TARGET" -oN "$RECON_DIR/nmap_basic.txt"

echo -e "${YELLOW}[+] Running nmap vulnerability scripts...${RESET}"
nmap --script vuln "$TARGET" -oN "$RECON_DIR/nmap_vuln.txt"

echo -e "${YELLOW}[+] Running whatweb...${RESET}"
whatweb "$TARGET" > "$RECON_DIR/whatweb.txt"

echo -e "${YELLOW}[+] Running nikto...${RESET}"
nikto -h "$TARGET" -output "$RECON_DIR/nikto.txt"

echo -e "${YELLOW}[+] Running wafw00f (WAF Detection)...${RESET}"
wafw00f "$TARGET" > "$RECON_DIR/waf.txt"

echo -e "${YELLOW}[+] Running gobuster directory fuzzing...${RESET}"
read -p "[?] Do you want to use the default wordlist (/usr/share/wordlists/dirb/common.txt)? [y/n]: " WORDLIST_CHOICE
if [[ "$WORDLIST_CHOICE" =~ ^[Yy]$ ]]; then
    WORDLIST="/usr/share/wordlists/dirb/common.txt"
else
    read -p "[?] Enter path to your custom wordlist: " WORDLIST
fi
gobuster dir -u "$TARGET" -w "$WORDLIST" -o "$RECON_DIR/gobuster.txt"

echo -e "${GREEN}[✓] Recon Completed. Results saved in $RECON_DIR${RESET}"
