# Neo-Recon
Neo-Recon is a fully automated, terminal-based pentesting and CTF assistant built in Bash. It offers live recon, vuln scanning, exploitation, password cracking, and reverse shell generation—all in one modular tool. Made for ethical hackers, students, and infosec enthusiasts needing speed, automation, and results.

---

## 🚀 About

**Neo-virex CTF Suite** is an advanced, modular, and script-based pentesting framework designed to:

- **Automate reconnaissance, scanning, exploitation, and password cracking**
- Act as a **step-by-step companion** for CTF challenges
- Perform **real-world penetration testing tasks**
- Support **offline and online attacks**
- Generate ready-to-use **reverse shell payloads**

This toolkit is designed for **terminal warriors** who want speed, control, and transparency over their security testing.

---

## 📦 Features

✅ Real-time IP/domain targeting  
✅ All output saved in `/tmp/outputs` automatically  
✅ Interactive main menu with keyboard-based flow  
✅ Pure Bash — no Docker or GUI needed  
✅ Modular system — easily expandable  

---

## 🧩 Modules

| Module                | Description                                                                 |
|----------------------|-----------------------------------------------------------------------------|
| **1. Reconnaissance** | Full recon using `nmap`, `whatweb`, `gobuster`, `curl`, etc.                |
| **2. Vulnerability Scanning** | Deep scanning using `nikto`, `wpscan`, `joomscan`, `droopescan`, `searchsploit`, etc. |
| **3. Exploitation**   | Attempts known exploits via Metasploit or manual curl-based techniques       |
| **4. Password Cracking** | Online (Hydra) and offline (John the Ripper) attacks — supports hashes, PDFs, ZIPs, login forms |
| **5. Reverse Shell Generator** | Builds payloads (Bash, Python, PHP, Netcat, etc.) with IP/port config options |

---

## 🔧 Installation

Clone the repository and make the main script executable:

```bash
git clone https://github.com/yourusername/neo-virex-ctf-suite.git
cd neo-virex-ctf-suite
sudo dpkg -i neorecon-deb.deb
chmod +x main.sh
