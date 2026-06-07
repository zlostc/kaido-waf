"""
Kaido WAF — Dashboard SSR
Dashboard server-side renderizado com templates Jinja2.
"""

import os
import json
import logging
from pathlib import Path
import secrets

from aiohttp import web
import jinja2

logger = logging.getLogger("kaido-waf.dashboard")


class DashboardServer:
    """Servidor de dashboard do Kaido WAF."""

    def __init__(self, config):
        self.config = config
        self.port = config.dashboard_port
        self.auth_enabled = config.get("dashboard.auth_enabled", True)
        self.username = config.get("dashboard.username", "admin")
        self.password = config.get("dashboard.password", "kaido2026")
        self.session_secret = config.get("dashboard.session_secret", secrets.token_hex(16))

        # Jinja2 setup
        template_dir = Path(__file__).parent / "templates"
        self._env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(template_dir)),
            autoescape=True,
        )

        self._app: web.Application = None
        self._runner: web.AppRunner = None
        self._sessions: dict[str, dict] = {}

    def _check_auth(self, request: web.Request) -> bool:
        """Verifica autenticação via cookie de sessão."""
        if not self.auth_enabled:
            return True
        session_id = request.cookies.get("kaido_session")
        if session_id and session_id in self._sessions:
            return True
        return False

    def _render(self, template_name: str, **context) -> str:
        """Renderiza template Jinja2."""
        template = self._env.get_template(template_name)
        return template.render(**context)

    async def _login_page(self, request: web.Request) -> web.Response:
        if request.method == "POST":
            data = await request.post()
            if data.get("username") == self.username and data.get("password") == self.password:
                session_id = secrets.token_hex(16)
                self._sessions[session_id] = {"ip": request.remote}
                response = web.HTTPFound("/dashboard")
                response.set_cookie("kaido_session", session_id, max_age=86400, httponly=True)
                raise response
            return web.Response(
                text=self._render("login.html", error="Invalid credentials"),
                content_type="text/html",
            )
        return web.Response(
            text=self._render("login.html", error=""),
            content_type="text/html",
        )

    async def _dashboard_page(self, request: web.Request) -> web.Response:
        if not self._check_auth(request):
            raise web.HTTPFound("/login")

        from kaido_waf import __version__

        stats = {
            "version": __version__,
            "mode": self.config.waf_mode,
            "upstream": self.config.upstream,
            "detectors": self.config.enabled_detectors,
            "rate_limit_rpm": self.config.rate_limit_rpm,
            "status": "running",
        }

        return web.Response(
            text=self._render("dashboard.html", stats=stats),
            content_type="text/html",
        )

    async def _api_stats(self, request: web.Request) -> web.Response:
        return web.json_response({
            "version": __version__,
            "waf_mode": self.config.waf_mode,
            "upstream": self.config.upstream,
            "detectors": self.config.enabled_detectors,
            "rate_limiting": {
                "enabled": self.config.rate_limit_enabled,
                "rpm": self.config.rate_limit_rpm,
            },
            "ip_blocking": {
                "enabled": self.config.ip_blocking_enabled,
            },
        })

    async def start(self):
        """Inicia o servidor do dashboard."""
        self._app = web.Application()

        # Rotas
        self._app.router.add_get("/login", self._login_page)
        self._app.router.add_post("/login", self._login_page)
        self._app.router.add_get("/dashboard", self._dashboard_page)
        self._app.router.add_get("/api/dashboard/stats", self._api_stats)
        self._app.router.add_get("/", lambda r: web.HTTPFound("/dashboard"))

        self._runner = web.AppRunner(self._app)
        await self._runner.setup()

        site = web.TCPSite(self._runner, "0.0.0.0", self.port)
        await site.start()
        logger.info(f"Dashboard started on http://0.0.0.0:{self.port}")

    async def stop(self):
        """Para o servidor do dashboard."""
        if self._runner:
            await self._runner.cleanup()
