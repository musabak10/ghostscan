"""Well-known service names and a curated list of common ports."""

SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 80: "http", 110: "pop3", 111: "rpcbind", 123: "ntp",
    135: "msrpc", 139: "netbios-ssn", 143: "imap", 161: "snmp", 389: "ldap",
    443: "https", 445: "smb", 465: "smtps", 514: "syslog", 587: "submission",
    631: "ipp", 636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s",
    1080: "socks", 1433: "mssql", 1521: "oracle", 1723: "pptp", 2049: "nfs",
    2375: "docker", 2376: "docker-tls", 3000: "dev-http", 3306: "mysql",
    3389: "rdp", 5000: "http-alt", 5432: "postgresql", 5601: "kibana",
    5672: "amqp", 5900: "vnc", 6379: "redis", 6443: "kubernetes-api",
    8000: "http-alt", 8080: "http-proxy", 8443: "https-alt", 8888: "http-alt",
    9000: "http-alt", 9092: "kafka", 9200: "elasticsearch", 11211: "memcached",
    27017: "mongodb",
}

HTTP_PORTS = {80, 3000, 5000, 5601, 8000, 8080, 8888, 9000, 9200}

TOP_PORTS = sorted(SERVICES)


def service_name(port: int) -> str:
    return SERVICES.get(port, "unknown")
