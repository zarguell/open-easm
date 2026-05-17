"""CPE 2.3 URI generation from detected technology names and versions.

Converts Wappalyzer ``technologies`` entries and nmap service strings
into CPE 2.3 formatted strings for NVD/KEV matching.
"""
from __future__ import annotations

import re
from typing import Any

# Map of common technology names to CPE vendor:product pairs.
# Extended during use — this is a bootstrap set.
TECH_TO_CPE: dict[str, tuple[str, str]] = {
    # Web servers
    "nginx": ("nginx", "nginx"),
    "apache http server": ("apache", "http_server"),
    "apache": ("apache", "http_server"),
    "iis": ("microsoft", "internet_information_services"),
    "microsoft iis": ("microsoft", "internet_information_services"),
    "caddy": ("caddyserver", "caddy"),
    "tomcat": ("apache", "tomcat"),
    "jetty": ("eclipse", "jetty"),
    # CMS
    "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"),
    "joomla": ("joomla", "joomla"),
    "ghost": ("ghost", "ghost"),
    # Languages / runtimes
    "php": ("php", "php"),
    "python": ("python", "python"),
    "ruby": ("ruby-lang", "ruby"),
    "node.js": ("nodejs", "node.js"),
    # Databases
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "redis": ("redis", "redis"),
    "mongodb": ("mongodb", "mongodb"),
    # JavaScript frameworks
    "react": ("facebook", "react"),
    "vue.js": ("vuejs", "vue.js"),
    "angular": ("angular", "angular"),
    "jquery": ("jquery", "jquery"),
    # Proxy / load balancer
    "haproxy": ("haproxy", "haproxy"),
    "varnish": ("varnish-cache", "varnish_cache"),
    "traefik": ("traefik", "traefik"),
    # Cloud / CDN
    "aws cloudfront": ("amazon", "cloudfront"),
    "cloudflare": ("cloudflare", "cloudflare"),
    # Misc
    "openssh": ("openbsd", "openssh"),
    "openssl": ("openssl", "openssl"),
    "exim": ("exim", "exim"),
    "postfix": ("postfix", "postfix"),
    "sendmail": ("sendmail", "sendmail"),
    "dovecot": ("dovecot", "dovecot"),
    "bind": ("isc", "bind"),
    "powerdns": ("powerdns", "powerdns"),
    "memcached": ("memcached", "memcached"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "kibana": ("elastic", "kibana"),
    "grafana": ("grafana", "grafana"),
    "prometheus": ("prometheus", "prometheus"),
    "jenkins": ("jenkins", "jenkins"),
    "gitlab": ("gitlab", "gitlab"),
}


def _normalize_version(version: str) -> str:
    """Strip leading non-digit characters (v, =, etc.) from version string."""
    if not version:
        return "*"
    cleaned = version.strip().lstrip("vV= ")
    if not cleaned or not re.match(r"^[\d.]+", cleaned):
        return "*"
    return cleaned


def tech_to_cpe(tech_name: str, tech_version: str | None = None) -> str | None:
    """Convert a technology name + version to a CPE 2.3 URI string.

    Returns a CPE 2.3 formatted string like
    ``cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*:*``
    or ``None`` if the technology is not in the mapping.
    """
    key = tech_name.lower().strip()
    if key not in TECH_TO_CPE:
        return None

    vendor, product = TECH_TO_CPE[key]
    version = _normalize_version(tech_version) if tech_version else "*"
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def nmap_service_to_cpe(service_name: str) -> str | None:
    """Convert an nmap service name to a CPE vendor:product lookup."""
    nmap_to_tech: dict[str, str] = {
        "http": "apache http server",
        "https": "apache http server",
        "http-proxy": "haproxy",
        "ssh": "openssh",
        "mysql": "mysql",
        "postgresql": "postgresql",
        "redis": "redis",
        "mongodb": "mongodb",
        "smtp": "postfix",
        "imap": "dovecot",
        "pop3": "dovecot",
        "dns": "bind",
        "ftp": "proftpd",
        "rdp": "microsoft",
        "vnc": "realvnc",
        "elasticsearch": "elasticsearch",
    }
    tech_name = nmap_to_tech.get(service_name, service_name)
    return tech_to_cpe(tech_name, None)


def compute_cpes_from_entity(entity_type: str, attributes: dict[str, Any]) -> list[str]:
    """Extract all CPEs from an entity's attributes.

    Handles Wappalyzer ``technologies``, Shodan ``cpes`` (pass-through),
    and portscan ``open_ports`` service names.
    """
    cpes: list[str] = []

    # 1. Shodan cpes (already CPE strings, pass-through)
    for cpe in attributes.get("cpes", []):
        if isinstance(cpe, str) and cpe.startswith("cpe:"):
            cpes.append(cpe)

    # 2. Wappalyzer technologies
    for tech in attributes.get("technologies", []):
        if isinstance(tech, dict):
            name = tech.get("name", "")
            version = tech.get("version") or None
            cpe = tech_to_cpe(name, version)
            if cpe:
                cpes.append(cpe)

    # 3. nmap port scan services
    for port_info in attributes.get("open_ports", []):
        if isinstance(port_info, dict):
            service = port_info.get("service", "")
            if service:
                cpe = nmap_service_to_cpe(service)
                if cpe:
                    cpes.append(cpe)

    # 4. Shodan full API service data
    for svc in attributes.get("services", []):
        if isinstance(svc, dict):
            product = svc.get("product", "")
            version = svc.get("version") or None
            if product:
                cpe = tech_to_cpe(product, version)
                if cpe:
                    cpes.append(cpe)

    return list(dict.fromkeys(cpes))  # deduplicate, preserve order
