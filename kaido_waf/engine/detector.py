"""
Kaido WAF — Detection Engine
Motor de detecção de ataques com regras para SQLi, XSS, Path Traversal, etc.
"""

import re
import time
import logging
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("kaido-waf.detector")


class AttackType(Enum):
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    SSRF = "ssrf"
    LFI_RFI = "lfi_rfi"
    NOSQL_INJECTION = "nosql_injection"
    COOKIE_POISONING = "cookie_poisoning"
    OPEN_REDIRECT = "open_redirect"
    SCANNER_DETECTION = "scanner_detection"


@dataclass
class Finding:
    """Resultado de uma detecção."""
    attack_type: AttackType
    severity: str  # low | medium | high | critical
    matched: str
    location: str  # query | body | path | headers | cookies
    value: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "attack_type": self.attack_type.value,
            "severity": self.severity,
            "matched": self.matched,
            "location": self.location,
            "value": self.value[:200],
            "timestamp": self.timestamp,
        }


class DetectionEngine:
    """Motor de detecção de ataques com regras embutidas."""

    def __init__(self, enabled_detectors: list[str] = None):
        self.enabled = set(enabled_detectors or [])
        self._compile_rules()

    def _compile_rules(self):
        """Compila todas as regras de detecção."""
        # --- SQL Injection ---
        self.sql_patterns = [
            (r"(?i)(\bunion\b.*\bselect\b)", "high"),
            (r"(?i)(\bselect\b.*\bfrom\b)", "high"),
            (r"(?i)(\binsert\b.*\binto\b)", "high"),
            (r"(?i)(\bdelete\b.*\bfrom\b)", "high"),
            (r"(?i)(\bdrop\b.*\btable\b)", "critical"),
            (r"(?i)(\bexec\b.*\(|exec\b.*xp_)", "critical"),
            (r"(?i)(\bdeclare\b.*\@)", "medium"),
            (r"(?i)(\bwaitfor\b.*\bdelay\b)", "critical"),
            (r"(?i)(\bbenchmark\b\s*\()", "critical"),
            (r"'?\s*--\s*$", "high"),
            (r"\bOR\b\s+\d+\s*=\s*\d+", "high"),
            (r"\bAND\b\s+\d+\s*=\s*\d+", "high"),
            (r"'\s*\bOR\b\s+'1'\s*=\s*'1", "critical"),
            (r"'\s*\bOR\b\s+'1'\s*=\s*'1'?\s*--", "critical"),
            (r"\bpg_sleep\s*\(", "critical"),
            (r"\bsleep\s*\(", "medium"),
            (r"\b0x[0-9a-fA-F]{6,}\b", "medium"),
            (r"(?i)(\binto\b.*\boutfile\b)", "critical"),
            (r"(?i)(\bload_file\s*\()", "critical"),
            (r"(?i)(\binformation_schema\b)", "medium"),
            (r"(?i)(\@\@version)", "medium"),
        ]

        # --- XSS ---
        self.xss_patterns = [
            (r"<script[^>]*>.*?</script>", "critical"),
            (r"(?i)(javascript\s*:)", "high"),
            (r"(?i)(onload\s*=)", "high"),
            (r"(?i)(onerror\s*=)", "high"),
            (r"(?i)(onclick\s*=)", "high"),
            (r"(?i)(onmouseover\s*=)", "high"),
            (r"(?i)(onfocus\s*=)", "high"),
            (r"(?i)(onblur\s*=)", "medium"),
            (r"(?i)(onchange\s*=)", "medium"),
            (r"(?i)(onsubmit\s*=)", "medium"),
            (r"(?i)(onkeypress\s*=)", "medium"),
            (r"(?i)(onkeydown\s*=)", "medium"),
            (r"(?i)(onkeyup\s*=)", "medium"),
            (r"(?i)(ondblclick\s*=)", "medium"),
            (r"<img[^>]*\bonerror\s*=", "critical"),
            (r"<svg[^>]*\bonload\s*=", "critical"),
            (r"<body[^>]*\bonload\s*=", "critical"),
            (r"(?i)(alert\s*\()", "high"),
            (r"(?i)(confirm\s*\()", "high"),
            (r"(?i)(prompt\s*\()", "high"),
            (r"(?i)(document\.cookie)", "high"),
            (r"(?i)(document\.location)", "high"),
            (r"(?i)(window\.location)", "high"),
            (r"(?i)(fetch\s*\()", "medium"),
            (r"(?i)(XMLHttpRequest)", "medium"),
            (r"(?i)(eval\s*\()", "critical"),
            (r"(?i)(fromCharCode)", "high"),
            (r"(?i)(String\.fromCharCode)", "high"),
            (r"<[^>]*\s*on\w+\s*=", "high"),
            (r"(?i)(data\s*:\s*text\/html)", "critical"),
            (r"(?i)(data\s*:\s*text\/javascript)", "critical"),
            (r"<[^>]*\bdangerouslySetInnerHTML\b", "high"),
            (r"<[^>]*\bv-html\b", "medium"),
        ]

        # --- Path Traversal ---
        self.path_traversal_patterns = [
            (r"\.\./\.\./", "high"),
            (r"\.\.\\\.\.\\", "high"),
            (r"\.\.%2f", "high"),
            (r"\.\.%5c", "high"),
            (r"%2e%2e%2f", "high"),
            (r"%2e%2e%5c", "high"),
            (r"\.\./\.\./\.\./", "critical"),
            (r"\.\.\\\.\.\\\.\.\\", "critical"),
            (r"\.\.%252f", "medium"),
            (r"\.\.%255c", "medium"),
        ]

        # --- Command Injection ---
        self.cmdi_patterns = [
            (r"(?i)(;\s*(id|whoami|pwd|ls|cat|nc|bash|sh|cmd|dir|powershell))", "critical"),
            (r"(?i)(\|\s*(id|whoami|pwd|ls|cat|nc|bash|sh|cmd|dir|powershell))", "critical"),
            (r"(?i)(`\s*(id|whoami|pwd|ls|cat|nc|bash|sh|cmd|dir|powershell))", "critical"),
            (r"(?i)(\$\s*\(.*\))", "high"),
            (r"(?i)(&{2,}\s*(id|whoami|pwd))", "critical"),
            (r"(?i)(;|\||&)\s*(wget|curl|nc|ncat|bash|sh|python|perl|ruby)", "critical"),
            (r"(?i)(system\s*\()", "high"),
            (r"(?i)(shell_exec\s*\()", "high"),
            (r"(?i)(exec\s*\()", "high"),
            (r"(?i)(passthru\s*\()", "high"),
            (r"(?i)(popen\s*\()", "high"),
            (r"(?i)(proc_open\s*\()", "high"),
            (r"(?i)(eval\s*\()", "critical"),
            (r"(?i)(assert\s*\()", "high"),
            (r"(?i)(base64_decode\s*\()", "medium"),
            (r"(?i)(cmd\.exe)", "high"),
            (r"(?i)(powershell\s+(-Command|-EncodedCommand|-E) )", "critical"),
            (r"(?i)(Invoke-Expression|iex\s*\()", "critical"),
            (r"(?i)(Invoke-Command|icm\s*)", "critical"),
        ]

        # --- SSRF ---
        self.ssrf_patterns = [
            (r"(?i)(\b169\.254\.169\.254\b)", "critical"),
            (r"(?i)(\bmetadata\.google\.internal\b)", "critical"),
            (r"(?i)(\bmetadata\.google\.com\b)", "critical"),
            (r"(?i)(\b127\.0\.0\.1\b)", "medium"),
            (r"(?i)(\blocalhost\b)", "medium"),
            (r"(?i)(\b0\.0\.0\.0\b)", "medium"),
            (r"(?i)(\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)", "medium"),
            (r"(?i)(\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b)", "medium"),
            (r"(?i)(\b192\.168\.\d{1,3}\.\d{1,3}\b)", "medium"),
            (r"(?i)(\b100\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)", "low"),
            (r"(?i)(file://)", "high"),
            (r"(?i)(gopher://)", "high"),
            (r"(?i)(dict://)", "medium"),
            (r"(?i)(ftp://)", "low"),
        ]

        # --- LFI/RFI ---
        self.lfi_patterns = [
            (r"(?i)(\.\./.*\.(php|phtml|inc|conf|db|sql|txt|log|ini))", "high"),
            (r"(?i)(/etc/passwd)", "critical"),
            (r"(?i)(/etc/shadow)", "critical"),
            (r"(?i)(/etc/ssl/)", "high"),
            (r"(?i)(/proc/self/environ)", "critical"),
            (r"(?i)(/proc/self/fd/)", "high"),
            (r"(?i)(/var/log/)", "medium"),
            (r"(?i)(base64_decode.*\.\.\./)", "critical"),
            (r"(?i)(php://filter)", "critical"),
            (r"(?i)(php://input)", "high"),
            (r"(?i)(data://text/plain;base64)", "critical"),
            (r"(?i)(expect://)", "high"),
            (r"(?i)(\.{3,})", "medium"),
        ]

        # --- NoSQL Injection ---
        self.nosql_patterns = [
            (r"\$\s*\{?\s*(gt|gte|lt|lte|ne|eq|in|nin|exists|regex)", "critical"),
            (r"\$\s*regex\s*", "critical"),
            (r"\$\s*where\s*", "critical"),
            (r"'?\s*\|\|\s*'[^']*'\s*==\s*'", "high"),
            (r"\bne\b\s*null", "medium"),
            (r"\bgt\b\s*''", "medium"),
            (r"(?i)(\badmin'\s*\|\|\s*'.*')", "high"),
            (r'(?i)(\badmin"\s*\|\|\s*".*")', "high"),
        ]

        # --- Cookie Poisoning ---
        self.cookie_patterns = [
            (r"(?i)(\badmin\s*=\s*true\b)", "high"),
            (r"(?i)(\bis_admin\s*=\s*1\b)", "high"),
            (r"(?i)(\bdebug\s*=\s*true\b)", "medium"),
            (r"(?i)(\buser_type\s*=\s*admin\b)", "high"),
            (r"(?i)(\brole\s*=\s*admin\b)", "high"),
            (r"(?i)(\badmin_panel\s*=\s*1\b)", "medium"),
            (r"(?i)(\%7b\%7b|%7b%7b)", "medium"),
        ]

        # --- Open Redirect ---
        self.redirect_patterns = [
            (r"(?i)(next\s*=\s*https?://)", "medium"),
            (r"(?i)(redirect\s*=\s*https?://)", "medium"),
            (r"(?i)(url\s*=\s*https?://)", "medium"),
            (r"(?i)(return\s*=\s*https?://)", "medium"),
            (r"(?i)(\bhttp://[^\s]*evil\b)", "high"),
            (r"(?i)(\bhttps://[^\s]*\.(ru|cn|tk|ml|ga|cf)\b)", "medium"),
            (r"(?i)(//[^\s]*@)", "high"),
        ]

        # --- Scanner Detection ---
        self.scanner_patterns = [
            (r"(?i)(sqlmap)", "medium"),
            (r"(?i)(nmap)", "low"),
            (r"(?i)(nikto)", "low"),
            (r"(?i)(gobuster)", "low"),
            (r"(?i)(dirb)", "low"),
            (r"(?i)(wfuzz)", "low"),
            (r"(?i)(burpsuite)", "low"),
            (r"(?i)(acunetix)", "medium"),
            (r"(?i)(nessus)", "medium"),
            (r"(?i)(openvas)", "medium"),
            (r"(?i)(metasploit)", "medium"),
            (r"(?i)(masscan)", "low"),
            (r"(?i)(zap)", "low"),
            (r"(?i)(arachni)", "low"),
            (r"(?i)(netsparker)", "medium"),
            (r"(?i)(python-requests)", "low"),
            (r"(?i)(go-http-client)", "low"),
            (r"(?i)(curl)", "low"),
            (r"(?i)(wget)", "low"),
        ]

        # Compile all patterns
        self._compiled = {}
        for name, patterns in [
            ("sql_injection", self.sql_patterns),
            ("xss", self.xss_patterns),
            ("path_traversal", self.path_traversal_patterns),
            ("command_injection", self.cmdi_patterns),
            ("ssrf", self.ssrf_patterns),
            ("lfi_rfi", self.lfi_patterns),
            ("nosql_injection", self.nosql_patterns),
            ("cookie_poisoning", self.cookie_patterns),
            ("open_redirect", self.redirect_patterns),
            ("scanner_detection", self.scanner_patterns),
        ]:
            self._compiled[name] = [
                (re.compile(pattern), severity) for pattern, severity in patterns
            ]

        self._attack_type_map = {
            "sql_injection": AttackType.SQL_INJECTION,
            "xss": AttackType.XSS,
            "path_traversal": AttackType.PATH_TRAVERSAL,
            "command_injection": AttackType.COMMAND_INJECTION,
            "ssrf": AttackType.SSRF,
            "lfi_rfi": AttackType.LFI_RFI,
            "nosql_injection": AttackType.NOSQL_INJECTION,
            "cookie_poisoning": AttackType.COOKIE_POISONING,
            "open_redirect": AttackType.OPEN_REDIRECT,
            "scanner_detection": AttackType.SCANNER_DETECTION,
        }

    def inspect_query(self, query: str) -> list[Finding]:
        """Inspeciona query string."""
        findings = []
        for name in self.enabled:
            if name not in self._compiled:
                continue
            for pattern, severity in self._compiled[name]:
                match = pattern.search(query)
                if match:
                    findings.append(Finding(
                        attack_type=self._attack_type_map[name],
                        severity=severity,
                        matched=match.group(0)[:100],
                        location="query",
                        value=query[:200],
                    ))
        return findings

    def inspect_body(self, body: str) -> list[Finding]:
        """Inspeciona corpo da requisição."""
        findings = []
        for name in self.enabled:
            if name not in self._compiled:
                continue
            for pattern, severity in self._compiled[name]:
                match = pattern.search(body)
                if match:
                    findings.append(Finding(
                        attack_type=self._attack_type_map[name],
                        severity=severity,
                        matched=match.group(0)[:100],
                        location="body",
                        value=body[:200],
                    ))
        return findings

    def inspect_path(self, path: str) -> list[Finding]:
        """Inspeciona caminho da URL."""
        findings = []
        for name in self.enabled:
            if name not in self._compiled:
                continue
            for pattern, severity in self._compiled[name]:
                match = pattern.search(path)
                if match:
                    findings.append(Finding(
                        attack_type=self._attack_type_map[name],
                        severity=severity,
                        matched=match.group(0)[:100],
                        location="path",
                        value=path[:200],
                    ))
        return findings

    def inspect_headers(self, headers: dict) -> list[Finding]:
        """Inspeciona cabeçalhos HTTP."""
        findings = []
        raw = " ".join(f"{k}: {v}" for k, v in headers.items())
        for name in self.enabled:
            if name not in self._compiled:
                continue
            for pattern, severity in self._compiled[name]:
                match = pattern.search(raw)
                if match:
                    findings.append(Finding(
                        attack_type=self._attack_type_map[name],
                        severity=severity,
                        matched=match.group(0)[:100],
                        location="headers",
                        value=raw[:200],
                    ))
        return findings

    def inspect_cookies(self, cookies: str) -> list[Finding]:
        """Inspeciona cookies."""
        findings = []
        for name in self.enabled:
            if name not in self._compiled:
                continue
            for pattern, severity in self._compiled[name]:
                match = pattern.search(cookies)
                if match:
                    findings.append(Finding(
                        attack_type=self._attack_type_map[name],
                        severity=severity,
                        matched=match.group(0)[:100],
                        location="cookies",
                        value=cookies[:200],
                    ))
        return findings

    def inspect_all(self, path: str, query: str, body: str,
                    headers: dict, cookies: str) -> list[Finding]:
        """Inspeciona todos os vetores."""
        return (
            self.inspect_path(path) +
            self.inspect_query(query) +
            self.inspect_body(body) +
            self.inspect_headers(headers) +
            self.inspect_cookies(cookies)
        )

    def get_severity_score(self, severity: str) -> int:
        return {"low": 1, "medium": 4, "high": 7, "critical": 10}.get(severity, 0)
