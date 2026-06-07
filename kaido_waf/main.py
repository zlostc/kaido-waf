"""
Kaido WAF — Servidor Principal
Ponto de entrada do Web Application Firewall.
"""

import os
import sys
import json
import signal
import asyncio
import logging
from pathlib import Path
from typing import Optional

import aiohttp
from aiohttp import web

from kaido_waf import __version__
from kaido_waf.config.settings import Config
from kaido_waf.engine.detector import DetectionEngine, Finding
from kaido_waf.proxy.reverse_proxy import ReverseProxy
from kaido_waf.middleware.rate_limiter import RateLimiter, RateLimitExceeded
from kaido_waf.middleware.ip_blocker import IPBlocker, IPBlocked
from kaido_waf.middleware.request_parser import get_client_ip, decode_body
from kaido_waf.utils.logger import setup_logger
from kaido_waf.dashboard.server import DashboardServer

logger = logging.getLogger("kaido-waf")


class KaidoWAF:
    """Servidor principal do Kaido WAF."""

    def __init__(self, config_path: Optional[Path] = None):
        self.config = Config(config_path)
        self._setup_logging()

        # Inicializa componentes
        self.detector = DetectionEngine(
            enabled_detectors=self.config.enabled_detectors
        )
        self.proxy = ReverseProxy(
            upstream=self.config.upstream,
            timeout=self.config.get("server.timeout", 30),
            buffer_size=self.config.get("server.buffer_size", 8192),
        )
        self.rate_limiter = RateLimiter(
            backend=self.config.rate_limit_backend,
            redis_url=self.config.redis_url,
            requests_per_minute=self.config.rate_limit_rpm,
            burst_size=self.config.rate_limit_burst,
        )
        self.ip_blocker = IPBlocker(
            whitelist=self.config.whitelist,
            blacklist=self.config.blacklist,
            auto_block_threshold=self.config.auto_block_threshold,
        )
        self.dashboard = DashboardServer(self.config) if self.config.dashboard_enabled else None

        self._app: Optional[web.Application] = None
        self._runner: Optional[web.AppRunner] = None

    def _setup_logging(self):
        setup_logger(
            level=self.config.get("logging.level", "INFO"),
            log_format=self.config.get("logging.format", "json"),
            log_file=self.config.get("logging.file", ""),
            discord_webhook=self.config.get("logging.discord_webhook", ""),
        )

    async def _handle_request(self, request: web.Request) -> web.Response:
        """Handler principal do proxy WAF."""
        client_ip = get_client_ip(dict(request.headers), request.remote)
        path = request.path
        query = request.query_string
        body = await request.read()
        headers = dict(request.headers)
        cookies = request.headers.get("Cookie", "")

        # ── 1. IP Blocker ──
        if self.config.ip_blocking_enabled:
            block_reason = self.ip_blocker.check(client_ip)
            if block_reason:
                logger.warning(f"Blocked {client_ip}: {block_reason}")
                return self._block_response(client_ip, reason=block_reason)

        # ── 2. Rate Limiter ──
        if self.config.rate_limit_enabled:
            allowed, status, retry_after = await self.rate_limiter.check(client_ip)
            if not allowed:
                logger.warning(f"Rate limit exceeded for {client_ip}")
                return web.Response(
                    status=status,
                    text=json.dumps({
                        "error": "rate_limit_exceeded",
                        "retry_after": retry_after,
                    }),
                    content_type="application/json",
                    headers={"Retry-After": str(retry_after)},
                )

        # ── 3. Detection Engine ──
        if self.config.get("waf.enabled", True):
            findings = self.detector.inspect_all(
                path=path,
                query=query,
                body=decode_body(body),
                headers=headers,
                cookies=cookies,
            )

            if findings:
                max_severity = max(
                    findings, key=lambda f: self.detector.get_severity_score(f.severity)
                )

                # Reporta ofensa ao IP blocker
                if self.config.ip_blocking_enabled:
                    self.ip_blocker.report_offense(client_ip, max_severity.severity)

                logger.warning(
                    f"Blocked attack from {client_ip} | "
                    f"type={max_severity.attack_type.value} | "
                    f"severity={max_severity.severity} | "
                    f"path={path}"
                )

                if self.config.is_blocking:
                    return self._block_response(
                        client_ip,
                        reason=f"Attack detected: {max_severity.attack_type.value}",
                        findings=findings,
                    )

        # ── 4. Forward to upstream ──
        try:
            upstream_response = await self.proxy.forward_request(
                method=request.method,
                path=path,
                query=query,
                headers=headers,
                body=body,
            )

            # Stream de resposta
            response_headers = self.proxy.build_response_headers(upstream_response)
            response = web.StreamResponse(
                status=upstream_response.status,
                headers=response_headers,
            )
            await response.prepare(request)

            async for chunk in upstream_response.content.iter_chunked(8192):
                await response.write(chunk)

            return response

        except aiohttp.ClientError as e:
            logger.error(f"Upstream error: {e}")
            return web.Response(
                status=502,
                text=json.dumps({"error": "bad_gateway", "message": str(e)}),
                content_type="application/json",
            )
        except asyncio.TimeoutError:
            logger.error(f"Upstream timeout: {self.config.upstream}{path}")
            return web.Response(
                status=504,
                text=json.dumps({"error": "gateway_timeout"}),
                content_type="application/json",
            )

    def _block_response(self, client_ip: str, reason: str = "",
                         findings: list[Finding] = None) -> web.Response:
        """Gera resposta de bloqueio."""
        block_data = {
            "error": "blocked_by_kaido_waf",
            "message": self.config.waf_block_message,
            "reason": reason,
            "client_ip": client_ip,
        }
        if findings:
            block_data["findings"] = [f.to_dict() for f in findings[:5]]

        return web.Response(
            status=self.config.waf_block_status,
            text=json.dumps(block_data, indent=2),
            content_type="application/json",
            headers={
                "X-Kaido-WAF": "blocked",
                "X-Kaido-Block-Reason": reason[:100],
            },
        )

    async def _health_check(self, request: web.Request) -> web.Response:
        """Endpoint de health check."""
        return web.json_response({
            "status": "ok",
            "version": __version__,
            "uptime": "TODO",
            "mode": self.config.waf_mode,
            "detectors": self.config.enabled_detectors,
        })

    async def _stats_handler(self, request: web.Request) -> web.Response:
        """Endpoint de estatísticas."""
        return web.json_response({
            "version": __version__,
            "waf_mode": self.config.waf_mode,
            "upstream": self.config.upstream,
            "detectors": self.config.enabled_detectors,
            "rate_limiting": {
                "enabled": self.config.rate_limit_enabled,
                "rpm": self.config.rate_limit_rpm,
            },
        })

    async def start(self):
        """Inicia o servidor WAF."""
        self._app = web.Application()

        # Rotas
        self._app.router.add_route("*", "/{tail:.*}", self._handle_request)
        self._app.router.add_get("/__health", self._health_check)
        self._app.router.add_get("/__stats", self._stats_handler)

        # Inicializa componentes
        await self.proxy.start()

        # Dashboard
        if self.dashboard:
            await self.dashboard.start()

        # Runner
        self._runner = web.AppRunner(self._app)
        await self._runner.setup()

        site = web.TCPSite(
            self._runner,
            self.config.server_host,
            self.config.server_port,
        )
        await site.start()

        logger.info(
            f"Kaido WAF v{__version__} started on "
            f"http://{self.config.server_host}:{self.config.server_port}"
        )
        logger.info(f"Upstream: {self.config.upstream}")
        logger.info(f"Mode: {self.config.waf_mode}")
        logger.info(f"Detectors: {', '.join(self.config.enabled_detectors)}")
        if self.dashboard:
            logger.info(
                f"Dashboard: http://{self.config.server_host}:{self.config.dashboard_port}"
            )

    async def stop(self):
        """Para o servidor WAF."""
        if self.dashboard:
            await self.dashboard.stop()
        await self.proxy.stop()
        await self.rate_limiter.close()
        if self._runner:
            await self._runner.cleanup()
        logger.info("Kaido WAF stopped")


async def main():
    """Entry point."""
    config_path = os.environ.get("KAIDO_WAF_CONFIG")
    if config_path:
        config_path = Path(config_path)

    waf = KaidoWAF(config_path)

    def shutdown(sig):
        logger.info(f"Received signal {sig}, shutting down...")
        asyncio.ensure_future(waf.stop())

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, lambda s=sig: shutdown(s))
        except NotImplementedError:
            pass  # Windows

    try:
        await waf.start()
        await asyncio.Event().wait()  # run forever
    except KeyboardInterrupt:
        await waf.stop()


if __name__ == "__main__":
    asyncio.run(main())
