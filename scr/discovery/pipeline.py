"""Sequential RustScan -> Nmap -> classifier discovery pipeline."""

from __future__ import annotations

from scr.core.context import TargetContext
from scr.core.output import collect
from scr.core.process import CommandRunner
from scr.core.terminal import TerminalManager
from scr.core.tasks import TaskState
from scr.core.evidence import write_json
from scr.core.hosts import HostsManager
from scr.discovery import classifier, nmap, rustscan
from config import load_settings
from scr.dependencies.manager import DependencyManager


def discover(context: TargetContext, *, port_spec: str | None = None,
             runner: CommandRunner | None = None,
             terminals: TerminalManager | None = None,
             hosts_manager: HostsManager | None = None) -> list[dict[str, object]]:
    runner = runner or CommandRunner()
    terminals = terminals or TerminalManager()
    dependencies = DependencyManager(install_missing=load_settings().install_missing_dependencies)
    available = dependencies.ensure(("rustscan",))
    if available.missing:
        raise RuntimeError("Missing required executable(s): " + ", ".join(available.missing))
    rust_task = rustscan.make_task(context, port_spec)
    state = terminals.execute(rust_task, runner)
    if state != TaskState.SUCCESS:
        raise RuntimeError(f"RustScan task ended in {state.value}")
    if rust_task.terminal_external:
        collect(rust_task.service, rust_task.argv, rust_task.output_path)
    ports = rustscan.extract_ports(rust_task.output_path.read_bytes())
    context.tcp_ports = ports["tcp"]
    context.udp_ports = ports["udp"]
    write_json(context.scan_dir / "metadata/ports.json", ports)
    if not context.tcp_ports and not context.udp_ports:
        context.services = []
        return []

    available = dependencies.ensure(("nmap",))
    if available.missing:
        raise RuntimeError("Missing required executable(s): " + ", ".join(available.missing))
    nmap_task = nmap.make_task(context)
    state = terminals.execute(nmap_task, runner)
    if state != TaskState.SUCCESS:
        raise RuntimeError(f"Nmap task ended in {state.value}")
    if nmap_task.terminal_external:
        collect(nmap_task.service, nmap_task.argv, nmap_task.output_path)
    services = nmap.parse_services(nmap_task.output_path.read_bytes())
    context.services = classifier.classify_all(services)
    identity = nmap.extract_host_identity(nmap_task.output_path.read_bytes(), context.target)
    if identity["hostname"]:
        context.add_hostname(str(identity["hostname"]))
        context.facts["hostname"] = identity["hostname"]
    if identity["fqdn"]:
        context.add_hostname(str(identity["fqdn"]))
        context.facts["fqdn"] = identity["fqdn"]
    if identity["domain"]:
        context.add_domain(str(identity["domain"]))
        context.facts["domain"] = identity["domain"]
    if identity["target_ip"]:
        context.facts["target_ip"] = identity["target_ip"]
    alias_set = {str(identity[name]) for name in ("hostname", "fqdn", "domain")
                 if identity[name]}
    hosts_result = (hosts_manager or HostsManager()).apply(
        str(identity["target_ip"]), alias_set
    ) if identity["target_ip"] and alias_set else {
        "status": "skipped", "reason": "Nmap did not identify a target IP and hostname/domain"
    }
    write_json(context.scan_dir / "metadata/hosts-update.json", hosts_result)
    write_json(context.scan_dir / "metadata/context.json", {
        "target": context.target, "tcp_ports": context.tcp_ports,
        "udp_ports": context.udp_ports, "services": context.services,
        "hostnames": sorted(context.hostnames), "domains": sorted(context.domains),
        "hostname": identity["hostname"], "fqdn": identity["fqdn"],
        "domain": identity["domain"], "target_ip": identity["target_ip"],
        "hosts_update": hosts_result,
    })
    return context.services
