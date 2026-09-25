"""Central executable-to-package registry."""

EXECUTABLE_PACKAGES = {
    "rustscan": {"apt": "rustscan", "pacman": "rustscan"},
    "nmap": {"apt": "nmap", "pacman": "nmap"},
    "smbclient": {"apt": "smbclient", "pacman": "smbclient"},
    "curl": {"apt": "curl", "pacman": "curl"},
    "ldapsearch": {"apt": "ldap-utils", "pacman": "openldap"},
    "dig": {"apt": "dnsutils", "pacman": "bind"},
    "ssh": {"apt": "openssh-client", "pacman": "openssh"},
    "ssh-keyscan": {"apt": "openssh-client", "pacman": "openssh"},
    "wget": {"apt": "wget", "pacman": "wget"},
    "host": {"apt": "bind9-host", "pacman": "bind"},
    "nslookup": {"apt": "bind9-dnsutils", "pacman": "bind"},
}

EXECUTABLE_FALLBACKS = {
    "curl": ("wget",),
    "dig": ("host", "nslookup"),
}
