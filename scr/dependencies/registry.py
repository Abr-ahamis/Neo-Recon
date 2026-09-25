"""Central executable-to-package registry."""

EXECUTABLE_PACKAGES = {
    "rustscan": {"apt": "rustscan", "pacman": "rustscan"},
    "nmap": {"apt": "nmap", "pacman": "nmap"},
    "smbclient": {"apt": "smbclient", "pacman": "samba"},
    "smbmap": {"apt": "smbmap", "pacman": "smbmap"},
    "rpcclient": {"apt": "samba-common-bin", "pacman": "samba"},
    "nxc": {"apt": "netexec", "pacman": "netexec"},
    "curl": {"apt": "curl", "pacman": "curl"},
    "ldapsearch": {"apt": "ldap-utils", "pacman": "openldap"},
    "dig": {"apt": "bind9-dnsutils", "pacman": "bind"},
    "ssh": {"apt": "openssh-client", "pacman": "openssh"},
    "ssh-keyscan": {"apt": "openssh-client", "pacman": "openssh"},
    "wget": {"apt": "wget", "pacman": "wget"},
    "host": {"apt": "bind9-host", "pacman": "bind"},
    "nslookup": {"apt": "bind9-dnsutils", "pacman": "bind"},
    "ffuf": {"apt": "ffuf", "pacman": "ffuf"},
    "gobuster": {"apt": "gobuster", "pacman": "gobuster"},
    "feroxbuster": {"apt": "feroxbuster", "pacman": "feroxbuster"},
    "nc": {"apt": "netcat-openbsd", "pacman": "openbsd-netcat"},
    "openssl": {"apt": "openssl", "pacman": "openssl"},
}

EXECUTABLE_FALLBACKS = {
    "curl": ("wget",),
    "dig": ("host", "nslookup"),
}
