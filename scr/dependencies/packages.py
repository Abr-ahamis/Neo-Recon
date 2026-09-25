"""Package-manager command prefixes used by the central installer."""

PACKAGE_MANAGER_COMMANDS = {
    "apt": ("sudo", "apt-get", "install", "-y"),
    "pacman": ("sudo", "pacman", "-S", "--needed", "--noconfirm"),
}
