"""SMB native executable requirements."""

REQUIRED_EXECUTABLES = ("smbclient",)
OPTIONAL_EXECUTABLES = ("nxc", "smbmap", "rpcclient")
PACKAGE_HINTS = {"smbclient": {"apt": "smbclient", "pacman": "smbclient"},
                 "nxc": {"apt": "netexec", "pacman": "netexec"}}
