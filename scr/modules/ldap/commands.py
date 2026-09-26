"""Read-only anonymous ldapsearch command definitions."""

from pathlib import Path
from scr.core.context import target_authority

RUNNER = Path(__file__).with_name("run.sh")


def root_dse(target: str, port: int, tls: bool = False) -> tuple[list[str], list[str]]:
    scheme = "ldaps" if tls else "ldap"
    display = ["ldapsearch", "-x", "-LLL", "-o", "nettimeout=5", "-H", f"{scheme}://{target_authority(target, port)}",
               "-s", "base", "-b", "", "defaultNamingContext", "namingContexts",
               "dnsHostName", "rootDomainNamingContext", "supportedSASLMechanisms"]
    return [str(RUNNER), *display], display


def children(target: str, port: int, base_dn: str, tls: bool = False) -> tuple[list[str], list[str]]:
    scheme = "ldaps" if tls else "ldap"
    display = ["ldapsearch", "-x", "-LLL", "-o", "nettimeout=5", "-l", "10", "-z", "500",
               "-H", f"{scheme}://{target_authority(target, port)}", "-s", "one", "-b", base_dn,
               "(|(objectClass=organizationalUnit)(objectClass=container)(objectClass=user)(objectClass=group)(objectClass=computer))",
               "dn", "objectClass", "cn", "name", "sAMAccountName", "userPrincipalName", "servicePrincipalName",
               "dNSHostName", "member", "memberOf"]
    return [str(RUNNER), *display], display
