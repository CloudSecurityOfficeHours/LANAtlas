# agent/scanner.py
def scan_subnet(cidr: str) -> list[RawObservation]:
    hosts = arp_sweep(cidr)
    results = []
    for host in hosts:
        hostname = resolve_mdns(host.ip)
        ports = scan_common_ports(host.ip)
        results.append(RawObservation(mac=host.mac, ip=host.ip, hostname=hostname, ports=ports))
    return results