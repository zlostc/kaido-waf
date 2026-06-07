"""
Kaido WAF — Reverse Proxy Assíncrono
Proxy reverso HTTP/HTTPS com suporte a WebSocket e streaming.
"""

import asyncio
import aiohttp
import logging
from urllib.parse import urlparse, urlunparse

logger = logging.getLogger("kaido-waf.proxy")


class ReverseProxy:
    """Proxy reverso assíncrono para backend upstream."""

    def __init__(self, upstream: str, timeout: int = 30, buffer_size: int = 8192):
        self.upstream = upstream.rstrip("/")
        self.timeout = timeout
        self.buffer_size = buffer_size
        self._session: aiohttp.ClientSession = None

    async def start(self):
        """Inicializa a sessão HTTP."""
        timeout_config = aiohttp.ClientTimeout(total=self.timeout)
        self._session = aiohttp.ClientSession(timeout=timeout_config)

    async def stop(self):
        """Fecha a sessão HTTP."""
        if self._session and not self._session.closed:
            await self._session.close()

    def _build_upstream_url(self, path: str, query: str = "") -> str:
        """Constrói a URL de upstream mantendo path e query."""
        upstream_path = path
        if query:
            upstream_path += "?" + query
        return self.upstream + upstream_path

    async def forward_request(self, method: str, path: str, query: str,
                               headers: dict, body: bytes = None,
                               cookies: dict = None) -> aiohttp.ClientResponse:
        """Encaminha a requisição para o upstream."""
        if not self._session or self._session.closed:
            await self.start()

        url = self._build_upstream_url(path, query)

        # Remove headers hop-by-hop
        hop_by_hop = {
            "connection", "keep-alive", "proxy-authenticate",
            "proxy-authorization", "te", "trailers",
            "transfer-encoding", "upgrade",
        }
        clean_headers = {
            k: v for k, v in headers.items()
            if k.lower() not in hop_by_hop and not k.lower().startswith("proxy-")
        }

        try:
            response = await self._session.request(
                method=method,
                url=url,
                headers=clean_headers,
                data=body,
                cookies=cookies,
                allow_redirects=False,
                chunked=True,
            )
            return response
        except aiohttp.ClientError as e:
            logger.error(f"Proxy error forwarding to {url}: {e}")
            raise
        except asyncio.TimeoutError:
            logger.error(f"Timeout forwarding to {url}")
            raise

    async def stream_response(self, response: aiohttp.ClientResponse,
                               write_callback) -> None:
        """Faz streaming da resposta do upstream para o cliente."""
        async for chunk in response.content.iter_chunked(self.buffer_size):
            if chunk:
                await write_callback(chunk)

    @staticmethod
    def build_response_headers(response: aiohttp.ClientResponse) -> dict:
        """Constrói cabeçalhos de resposta sem hop-by-hop."""
        headers = dict(response.headers)
        for h in ["connection", "keep-alive", "transfer-encoding", "upgrade"]:
            headers.pop(h, None)
            headers.pop(h.title(), None)
        headers["X-Kaido-WAF"] = "protected"
        return headers
