"""
Kaido WAF — Web Application Firewall do Kaido Red Team
Versão: 2.1.0
Licença: MIT
"""

__version__ = "2.1.0"
__author__ = "Gustavo (Kaido Team)"
__description__ = "Web Application Firewall com detecção de ataques, rate limiting e dashboard SSR"

from .config.settings import Config
from .engine.detector import DetectionEngine
from .proxy.reverse_proxy import ReverseProxy
