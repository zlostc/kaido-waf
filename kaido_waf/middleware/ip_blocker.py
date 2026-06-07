"""
Kaido WAF — IP Blocker
Bloqueio de IPs por whitelist/blacklist e auto-bloqueio por detecção.
"""

import time
import ipaddress
import logging
from typing import Optional

logger = logging.getLogger("kaido-waf.ip_blocker")


class IPBlocked(Exception):
    """Exceção levantada quando o IP está bloqueado."""
    def __init__(self, client_ip: str, reason: str = ""):
        self.client_ip = client_ip
        self.reason = reason
        super().__init__(f"IP {client_ip} blocked: {reason}")


class IPBlocker:
    """Gerenciador de bloqueio de IPs."""

    def __init__(self, whitelist: list[str] = None,
                 blacklist: list[str] = None,
                 auto_block_threshold: int = 10,
                 auto_block_duration: int = 3600):
        self.whitelist = self._parse_networks(whitelist or [])
        self.blacklist = self._parse_networks(blacklist or [])
        self.auto_block_threshold = auto_block_threshold
        self.auto_block_duration = auto_block_duration
        self._offenses: dict[str, list[float]] = {}
        self._auto_blocked: dict[str, float] = {}

    def _parse_networks(self, nets: list[str]) -> list:
        """Converte lista de IPs/CIDR para objetos ip_network."""
        parsed = []
        for net in nets:
            try:
                if "/" in net:
                    parsed.append(ipaddress.ip_network(net, strict=False))
                else:
                    parsed.append(ipaddress.ip_address(net))
            except ValueError:
                logger.warning(f"Invalid IP/network: {net}")
        return parsed

    def _ip_in_list(self, ip_str: str, net_list: list) -> bool:
        """Verifica se um IP está em uma lista de redes."""
        try:
            ip = ipaddress.ip_address(ip_str)
            for net in net_list:
                if isinstance(net, ipaddress.IPv4Network | ipaddress.IPv6Network):
                    if ip in net:
                        return True
                elif ip == net:
                    return True
        except ValueError:
            pass
        return False

    def check(self, client_ip: str) -> Optional[str]:
        """Verifica se o IP está autorizado.
        Retorna None se permitido, ou a razão do bloqueio.
        """
        # Whitelist tem prioridade
        if self._ip_in_list(client_ip, self.whitelist):
            return None

        # Blacklist
        if self._ip_in_list(client_ip, self.blacklist):
            return "blacklisted"

        # Auto-bloqueio
        if client_ip in self._auto_blocked:
            until = self._auto_blocked[client_ip]
            if time.time() < until:
                return f"auto-blocked (until {time.ctime(until)})"
            else:
                del self._auto_blocked[client_ip]

        return None

    def report_offense(self, client_ip: str, severity: str = "medium"):
        """Registra uma ofensa contra um IP."""
        now = time.time()
        if client_ip not in self._offenses:
            self._offenses[client_ip] = []

        # Limpa ofensas com mais de 1 hora
        self._offenses[client_ip] = [
            t for t in self._offenses[client_ip] if t > now - 3600
        ]

        # Peso por severidade
        weight = {"low": 1, "medium": 2, "high": 3, "critical": 5}
        for _ in range(weight.get(severity, 1)):
            self._offenses[client_ip].append(now)

        # Verifica threshold
        if len(self._offenses[client_ip]) >= self.auto_block_threshold:
            self._auto_blocked[client_ip] = now + self.auto_block_duration
            logger.warning(
                f"Auto-blocked {client_ip} after "
                f"{len(self._offenses[client_ip])} offenses"
            )
            return True

        return False

    def is_whitelisted(self, client_ip: str) -> bool:
        """Verifica se IP está na whitelist."""
        return self._ip_in_list(client_ip, self.whitelist)

    def is_blacklisted(self, client_ip: str) -> bool:
        """Verifica se IP está na blacklist."""
        return self._ip_in_list(client_ip, self.blacklist)
