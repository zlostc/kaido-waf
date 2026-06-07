"""
Kaido WAF — Configurações centrais
"""

import os
import yaml
from pathlib import Path
from typing import Optional

DEFAULT_CONFIG_PATH = Path(__file__).parent.parent.parent / "config.yaml"


class Config:
    """Gerenciador de configuração do Kaido WAF."""

    def __init__(self, config_path: Optional[Path] = None):
        self.path = config_path or DEFAULT_CONFIG_PATH
        self._data = self._load()

    def _load(self) -> dict:
        if not self.path.exists():
            return self._defaults()
        with open(self.path) as f:
            return {**self._defaults(), **yaml.safe_load(f)}

    def _defaults(self) -> dict:
        return {
            "server": {
                "host": "0.0.0.0",
                "port": 8080,
                "workers": 4,
                "upstream": "http://127.0.0.1:3000",
                "timeout": 30,
                "buffer_size": 8192,
                "max_body_size": 10485760,
            },
            "waf": {
                "enabled": True,
                "mode": "block",        # block | detect | log
                "block_status_code": 403,
                "block_message": "Blocked by Kaido WAF",
            },
            "detection": {
                "sql_injection": True,
                "xss": True,
                "path_traversal": True,
                "command_injection": True,
                "ssrf": True,
                "lfi_rfi": True,
                "nosql_injection": True,
                "cookie_poisoning": True,
                "open_redirect": True,
                "scanner_detection": True,
            },
            "rate_limiting": {
                "enabled": True,
                "backend": "memory",    # memory | redis
                "redis_url": "redis://localhost:6379/0",
                "requests_per_minute": 60,
                "burst_size": 100,
                "block_duration": 300,
            },
            "ip_blocking": {
                "enabled": True,
                "whitelist": [],
                "blacklist": [],
                "auto_block_threshold": 10,
                "auto_block_duration": 3600,
            },
            "logging": {
                "level": "INFO",
                "format": "json",
                "file": "/var/log/kaido-waf/access.log",
                "discord_webhook": "",
            },
            "dashboard": {
                "enabled": True,
                "port": 9090,
                "auth_enabled": True,
                "username": "admin",
                "password": "kaido2026",
                "session_secret": "change-this-secret-in-production",
            },
        }

    @property
    def server_host(self) -> str:
        return self._data["server"]["host"]

    @property
    def server_port(self) -> int:
        return self._data["server"]["port"]

    @property
    def upstream(self) -> str:
        return self._data["server"]["upstream"]

    @property
    def waf_mode(self) -> str:
        return self._data["waf"]["mode"]

    @property
    def waf_block_message(self) -> str:
        return self._data["waf"]["block_message"]

    @property
    def waf_block_status(self) -> int:
        return self._data["waf"]["block_status_code"]

    @property
    def is_blocking(self) -> bool:
        return self._data["waf"]["mode"] == "block"

    @property
    def enabled_detectors(self) -> list:
        detection = self._data["detection"]
        return [k for k, v in detection.items() if v]

    @property
    def rate_limit_enabled(self) -> bool:
        return self._data["rate_limiting"]["enabled"]

    @property
    def rate_limit_rpm(self) -> int:
        return self._data["rate_limiting"]["requests_per_minute"]

    @property
    def rate_limit_burst(self) -> int:
        return self._data["rate_limiting"]["burst_size"]

    @property
    def rate_limit_backend(self) -> str:
        return self._data["rate_limiting"]["backend"]

    @property
    def redis_url(self) -> str:
        return self._data["rate_limiting"]["redis_url"]

    @property
    def ip_blocking_enabled(self) -> bool:
        return self._data["ip_blocking"]["enabled"]

    @property
    def whitelist(self) -> list:
        return self._data["ip_blocking"]["whitelist"]

    @property
    def blacklist(self) -> list:
        return self._data["ip_blocking"]["blacklist"]

    @property
    def auto_block_threshold(self) -> int:
        return self._data["ip_blocking"]["auto_block_threshold"]

    @property
    def dashboard_enabled(self) -> bool:
        return self._data["dashboard"]["enabled"]

    @property
    def dashboard_port(self) -> int:
        return self._data["dashboard"]["port"]

    def get(self, key: str, default=None):
        keys = key.split(".")
        data = self._data
        for k in keys:
            if isinstance(data, dict):
                data = data.get(k)
                if data is None:
                    return default
            else:
                return default
        return data

    def as_dict(self) -> dict:
        return self._data
