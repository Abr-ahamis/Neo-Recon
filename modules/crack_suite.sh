#!/bin/bash
# File: modules/crack_suite.sh
# Author: Neo-virex

# Colors
RED="\e[31m"
GREEN="\e[32m"
BLUE="\e[34m"
YELLOW="\e[33m"
RESET="\e[0m"

OUTDIR="/tmp/outputs"
mkdir -p "$OUTDIR"

echo -e "${BLUE}[*] Starting Password Cracking Suite...${RESET}"

echo "Select the type of password cracking you want to perform:"
echo "1) Website login (online brute force)"
echo "2) Hash cracking (offline)"
echo "3) Zip file password cracking"
echo "4) PDF password cracking"
echo "5) SSH login brute force"
echo "6) Exit"
read -p "Enter choice [1-6]: " choice

case $choice in
    1)  # Website login brute force using Hydra
        read -p "[?] Enter target website URL (e.g., http://example.com/login): " target_url
        read -p "[?] Enter HTTP POST form parameters (e.g., user=^USER^&pass=^PASS^&submit=Login): " post_params
        read -p "[?] Enter login failure string (e.g., 'Invalid password'): " fail_str

        read -p "[?] Use default username list (/usr/share/wordlists/usernames.txt)? (y/n): " user_choice
        if [[ "$user_choice" =~ ^[Yy]$ ]]; then
            userlist="/usr/share/wordlists/usernames.txt"
        else
            read -p "[?] Enter path to username list: " userlist
        fi

        read -p "[?] Use default password list (/usr/share/wordlists/rockyou.txt)? (y/n): " pass_choice
        if [[ "$pass_choice" =~ ^[Yy]$ ]]; then
            passlist="/usr/share/wordlists/rockyou.txt"
        else
            read -p "[?] Enter path to password list: " passlist
        fi

        echo -e "${YELLOW}[+] Starting Hydra web login brute force...${RESET}"
        hydra -L "$userlist" -P "$passlist" "$target_url" http-post-form "$post_params:$fail_str" -t 4
        ;;

    2)  # Hash cracking with John the Ripper
        read -p "[?] Enter path to hash file: " hash_file
        read -p "[?] Use default wordlist (/usr/share/wordlists/rockyou.txt)? (y/n): " word_choice
        if [[ "$word_choice" =~ ^[Yy]$ ]]; then
            wordlist="/usr/share/wordlists/rockyou.txt"
        else
            read -p "[?] Enter path to wordlist: " wordlist
        fi

        echo -e "${YELLOW}[+] Starting John the Ripper...${RESET}"
        john --wordlist="$wordlist" "$hash_file"
        ;;

    3)  # Zip file password cracking with fcrackzip
        read -p "[?] Enter path to zip file: " zip_file
        read -p "[?] Use default wordlist (/usr/share/wordlists/rockyou.txt)? (y/n): " word_choice
        if [[ "$word_choice" =~ ^[Yy]$ ]]; then
            wordlist="/usr/share/wordlists/rockyou.txt"
        else
            read -p "[?] Enter path to wordlist: " wordlist
        fi

        echo -e "${YELLOW}[+] Starting fcrackzip for zip password cracking...${RESET}"
        fcrackzip -u -D -p "$wordlist" "$zip_file"
        ;;

    4)  # PDF password cracking with pdfcrack
        read -p "[?] Enter path to PDF file: " pdf_file
        read -p "[?] Use default wordlist (/usr/share/wordlists/rockyou.txt)? (y/n): " word_choice
        if [[ "$word_choice" =~ ^[Yy]$ ]]; then
            wordlist="/usr/share/wordlists/rockyou.txt"
        else
            read -p "[?] Enter path to wordlist: " wordlist
        fi

        echo -e "${YELLOW}[+] Starting pdfcrack...${RESET}"
        pdfcrack -w "$wordlist" "$pdf_file"
        ;;

    5)  # SSH login brute force with Hydra
        read -p "[?] Enter target IP or hostname: " ssh_target
        read -p "[?] Enter SSH port (default 22): " ssh_port
        ssh_port=${ssh_port:-22}

        read -p "[?] Use default username list (/usr/share/wordlists/usernames.txt)? (y/n): " user_choice
        if [[ "$user_choice" =~ ^[Yy]$ ]]; then
            userlist="/usr/share/wordlists/usernames.txt"
        else
            read -p "[?] Enter path to username list: " userlist
        fi

        read -p "[?] Use default password list (/usr/share/wordlists/rockyou.txt)? (y/n): " pass_choice
        if [[ "$pass_choice" =~ ^[Yy]$ ]]; then
            passlist="/usr/share/wordlists/rockyou.txt"
        else
            read -p "[?] Enter path to password list: " passlist
        fi

        echo -e "${YELLOW}[+] Starting Hydra SSH brute force...${RESET}"
        hydra -L "$userlist" -P "$passlist" -s "$ssh_port" ssh://"$ssh_target"
        ;;

    6)
        echo -e "${GREEN}Exiting Password Cracking Suite.${RESET}"
        exit 0
        ;;

    *)
        echo -e "${RED}Invalid choice.${RESET}"
        ;;
esac
