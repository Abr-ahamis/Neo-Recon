"""Service classification from Nmap protocol/service/product fingerprints."""

from __future__ import annotations

import re
from typing import Any


SERVICE_MODULES = {
    "http": "http", "http-alt": "http", "https": "https",
    "ssl/http": "https", "ssl|http": "https", "httpd": "http",
    "microsoft-ds": "smb", "netbios-ssn": "smb", "smb": "smb",
    "ftp": "ftp", "ssh": "ssh", "sftp": "ssh",
    "ldap": "ldap", "ldaps": "ldap", "ssl/ldap": "ldap", "domain": "dns",
    "kerberos-sec": "kerberos", "kerberos": "kerberos", "kpasswd5": "kerberos",
    "ms-wbt-server": "rdp", "rdp": "rdp", "ms-sql-s": "mssql", "ms-sql-m": "mssql",
    "mysql": "mysql", "postgresql": "postgresql", "postgres": "postgresql",
    "nfs": "nfs", "rpcbind": "nfs", "snmp": "snmp", "redis": "redis",
    "docker": "docker", "http-json": "http", "microsoft-httpapi": "http",
    "ncacn_http": "rpc", "mc-nmf": "adws", "wsman": "winrm",
}

PRODUCT_PATTERNS = (
    (re.compile(r"\bdocker\b", re.I), "docker"),
    (re.compile(r"\bkubernetes\b|\bkubelet\b", re.I), "kubernetes"),
    (re.compile(r"\bjenkins\b", re.I), "jenkins"),
    (re.compile(r"\bgitlab\b", re.I), "gitlab"),
    (re.compile(r"\btomcat\b", re.I), "tomcat"),
    (re.compile(r"\bjetty\b", re.I), "jetty"),
    (re.compile(r"\bwebdav\b", re.I), "webdav"),
)

KNOWN_UNIMPLEMENTED = {
    "smtp", "smtps", "submission", "pop3", "pop3s", "imap", "imaps", "telnet", "vnc",
    "ms-wbt-server", "netbios-ns", "netbios-dgm", "msrpc", "rpcbind", "domain", "snmp",
    "mysql", "mariadb", "postgresql", "postgres", "ms-sql-s", "oracle-tns", "redis",
    "mongodb", "cassandra", "elasticsearch", "memcached", "nfs", "iscsi", "afp",
    "tftp", "rsync", "ntp", "amqp", "mqtt", "kafka", "activemq", "xmpp", "sip",
    "docker", "http-json", "kubernetes", "jenkins", "gitlab", "svn", "git",
    "tomcat", "jboss", "jetty", "webdav", "ipp", "ipp|http", "cups", "rtsp",
    "irc", "ircs", "nntp", "finger", "ident", "gopher", "socks", "http-proxy",
    "chargen", "echo", "daytime", "qotd", "lpd", "jetdirect", "upnp", "ssdp",
    "x11", "xdmcp", "spice", "teamcity", "bamboo", "argocd", "sonarqube", "grafana",
    "prometheus", "kibana", "splunk", "graylog", "nagios", "zabbix", "webmin", "cockpit",
}
IMPLEMENTED_MODULES = {"http", "https", "smb", "ftp", "ssh", "ldap", "dns"}
KNOWN_UNIMPLEMENTED.update({"rpc", "adws", "winrm", "kerberos"})


def classify(service: dict[str, Any]) -> dict[str, Any]:
    name = str(service.get("service", "unknown")).lower().rstrip("?")
    detail = str(service.get("details", ""))
    module = None
    evidence = "nmap-service"
    if (int(service.get("port", 0) or 0) in {5985, 5986}
            and re.search(r"microsoft[- ]httpapi|\bwsman\b|winrm", detail, re.I)):
        module = "winrm"
        evidence = "product-port-fingerprint"
    for pattern, candidate in PRODUCT_PATTERNS:
        if pattern.search(detail):
            module = candidate
            evidence = "product-fingerprint"
            break
    if module is None:
        module = SERVICE_MODULES.get(name)
    family = module or (name if name in KNOWN_UNIMPLEMENTED else None)
    known = family is not None
    implemented = family in IMPLEMENTED_MODULES
    return {**service, "module": family if implemented else ("unimplemented" if known else "unknown"),
            "classification": "known" if known else "unknown",
            "service_family": family or "unknown",
            "implementation": "available" if implemented else "not-implemented" if known else "unknown",
            "confidence": "fingerprint" if family and "fingerprint" in evidence else "service-name" if known else "unknown",
            "classification_evidence": evidence if family and evidence != "nmap-service" else "nmap-service-name" if known else
                                       "no-recognized-fingerprint"}


def classify_all(services: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [classify(service) for service in services]
