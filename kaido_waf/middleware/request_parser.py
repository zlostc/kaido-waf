"""
Kaido WAF — Request Parser
Utilitários para parse de requisições HTTP.
"""

from urllib.parse import parse_qs, unquote


def parse_query_string(query: str) -> dict:
    """Parseia query string para dicionário."""
    return {k: v[0] if len(v) == 1 else v
            for k, v in parse_qs(query, keep_blank_values=True).items()}


def get_client_ip(headers: dict, remote: str = "") -> str:
    """Extrai o IP real do cliente considerando proxies."""
    for header in [
        "X-Real-IP",
        "X-Forwarded-For",
        "X-Client-IP",
        "CF-Connecting-IP",
        "True-Client-IP",
    ]:
        if header in headers:
            ip = headers[header].split(",")[0].strip()
            if ip and ip != "unknown":
                return ip
    return remote or "127.0.0.1"


def normalize_path(path: str) -> str:
    """Normaliza o caminho da URL."""
    from urllib.parse import unquote
    path = unquote(path)
    path = path.split("?")[0].split("#")[0]
    while "//" in path:
        path = path.replace("//", "/")
    return path.rstrip("/") or "/"


def decode_body(body: bytes) -> str:
    """Decodifica corpo da requisição."""
    try:
        return body.decode("utf-8", errors="replace")
    except Exception:
        return body.decode("latin-1", errors="replace")
