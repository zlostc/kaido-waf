"""
Kaido WAF — Logger
Sistema de logging estruturado com suporte a JSON e Discord webhook.
"""

import os
import json
import logging
import logging.handlers
from datetime import datetime
from typing import Optional

import aiohttp


class JSONFormatter(logging.Formatter):
    """Formatador JSON para logs estruturados."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "extra"):
            log_entry.update(record.extra)
        if record.exc_info and record.exc_info[0]:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)


class DiscordWebhookHandler(logging.Handler):
    """Handler que envia logs críticos para Discord webhook."""

    def __init__(self, webhook_url: str, level=logging.WARNING):
        super().__init__(level)
        self.webhook_url = webhook_url
        self._session: Optional[aiohttp.ClientSession] = None

    async def _ensure_session(self):
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()

    async def emit_async(self, record: logging.LogRecord):
        if not self.webhook_url:
            return
        await self._ensure_session()
        try:
            payload = {
                "content": None,
                "embeds": [{
                    "title": f"🚨 Kaido WAF — {record.levelname}",
                    "description": record.getMessage()[:2000],
                    "color": {"CRITICAL": 0xFF0000, "ERROR": 0xFF4444,
                              "WARNING": 0xFFAA00}.get(record.levelname, 0x888888),
                    "timestamp": datetime.utcfromtimestamp(
                        record.created).isoformat() + "Z",
                    "footer": {"text": "Kaido WAF Security Monitor"},
                }],
            }
            await self._session.post(self.webhook_url, json=payload)
        except Exception:
            pass

    def emit(self, record: logging.LogRecord):
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.ensure_future(self.emit_async(record))
            else:
                loop.run_until_complete(self.emit_async(record))
        except Exception:
            pass

    def close(self):
        if self._session and not self._session.closed:
            import asyncio
            try:
                asyncio.get_event_loop().run_until_complete(self._session.close())
            except Exception:
                pass
        super().close()


def setup_logger(level: str = "INFO", log_format: str = "json",
                 log_file: str = "", discord_webhook: str = ""):
    """Configura o sistema de logging."""
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Console handler
    console = logging.StreamHandler()
    if log_format == "json":
        console.setFormatter(JSONFormatter())
    else:
        console.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )
    root.addHandler(console)

    # File handler
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=50 * 1024 * 1024, backupCount=10
        )
        file_handler.setFormatter(JSONFormatter())
        root.addHandler(file_handler)

    # Discord webhook
    if discord_webhook:
        discord_handler = DiscordWebhookHandler(discord_webhook, logging.WARNING)
        root.addHandler(discord_handler)

    return root
