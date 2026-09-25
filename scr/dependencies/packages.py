"""Package-manager command prefixes used by the central installer."""

PACKAGE_MANAGER_COMMANDS = {
    "apt": ("apt-get", "install", "-y"),
    "pacman": ("sudo", "pacman", "-S", "--needed", "--noconfirm"),
}
