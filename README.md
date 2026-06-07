<div align="center">
  <h1>⚔️ Kaido WAF</h1>
  <p><strong>Web Application Firewall do Kaido Red Team</strong></p>
  <p>
    <a href="#-sobre">Sobre</a> •
    <a href="#-features">Features</a> •
    <a href="#-instalação">Instalação</a> •
    <a href="#-configuração">Configuração</a> •
    <a href="#-modos-de-operação">Modos</a> •
    <a href="#-detectores">Detectores</a> •
    <a href="#-dashboard">Dashboard</a> •
    <a href="#-deploy">Deploy</a> •
    <a href="#-créditos">Créditos</a>
  </p>
  <p>
    <img src="https://img.shields.io/badge/version-2.1.0-ff4400" alt="Version">
    <img src="https://img.shields.io/badge/python-3.11%2B-ff8800" alt="Python">
    <img src="https://img.shields.io/badge/license-MIT-ff4400" alt="License">
    <img src="https://img.shields.io/badge/kaido-red_team-ff0000" alt="Kaido Red Team">
  </p>
</div>

---

## 🔥 Sobre

**Kaido WAF** é um Web Application Firewall desenvolvido pelo **Kaido Red Team**, projetado para proteger aplicações web contra ataques como SQL Injection, XSS, Path Traversal, Command Injection, SSRF, LFI/RFI, NoSQL Injection e muito mais.

Opera como um **proxy reverso** entre o cliente e o backend, inspecionando cada requisição em tempo real com um motor de detecção de alta performance. Pode operar em modo **block** (bloqueio automático), **detect** (apenas detectar) ou **log** (logar tudo).

> **👑 Criado por Gustavo — Membro do Kaido Red Team**

---

## 🚀 Features

| Feature | Descrição |
|---------|-----------|
| 🛡️ **Proxy Reverso** | Proxy assíncrono (aiohttp) com streaming e suporte a WebSocket |
| 🔍 **10 Detectores** | SQLi, XSS, Path Traversal, CMDi, SSRF, LFI/RFI, NoSQL, Cookie Poisoning, Open Redirect, Scanner Detection |
| ⚡ **Rate Limiting** | Sliding window com backend em memória ou Redis |
| 🚫 **IP Blocker** | Whitelist, blacklist e auto-bloqueio por ofensas |
| 📊 **Dashboard SSR** | Interface web server-side renderizada com Jinja2 (zero JS dependency) |
| 🔐 **Autenticação** | Dashboard com login protegido |
| 📝 **Logging Estruturado** | Saída em JSON, rotação de logs, webhook Discord |
| 🐳 **Docker** | Dockerfile e docker-compose prontos |
| 🔧 **Config YAML** | Configuração declarativa completa |

---

## 📦 Instalação

### Via pip

```bash
# Clone o repositório
git clone https://github.com/KaidoTeam/kaido-waf.git
cd kaido-waf

# Instale as dependências
pip install -r requirements.txt

# Execute
python3 -m kaido_waf.main
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
  kaido-waf
```

### Via Docker Compose

```bash
docker-compose -f examples/docker-compose.yml up -d
```

---

## ⚙️ Configuração

O Kaido WAF é configurado via arquivo YAML. Por padrão, ele busca `config.yaml` na raiz do projeto, ou você pode especificar via variável de ambiente `KAIDO_WAF_CONFIG`.

### Exemplo de configuração:

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  upstream: "http://127.0.0.1:3000"    # Backend a proteger

waf:
  mode: "block"                          # block | detect | log
  block_status_code: 403
  block_message: "Blocked by Kaido WAF"

detection:
  sql_injection: true
  xss: true
  path_traversal: true
  command_injection: true
  ssrf: true
  lfi_rfi: true
  nosql_injection: true
  cookie_poisoning: true
  open_redirect: true
  scanner_detection: true

rate_limiting:
  enabled: true
  backend: "memory"                      # memory | redis
  requests_per_minute: 60
  burst_size: 100
  block_duration: 300

ip_blocking:
  enabled: true
  whitelist:
    - "127.0.0.1"
  blacklist: []
  auto_block_threshold: 10

logging:
  level: "INFO"
  format: "json"
  file: "/var/log/kaido-waf/access.log"
  discord_webhook: ""                    # Webhook do Discord

dashboard:
  enabled: true
  port: 9090
  auth_enabled: true
  username: "admin"
  password: "kaido2026"
```

---

## 🎯 Modos de Operação

| Modo | Descrição |
|------|-----------|
| **block** | Bloqueia requisições maliciosas com HTTP 403 |
| **detect** | Apenas detecta e loga, não bloqueia |
| **log** | Loga tudo (incluindo requisições legítimas) para auditoria |

---

## 🧠 Detectores

O motor de detecção possui **10 categorias** com mais de **150 padrões** de ataque:

### SQL Injection (20+ padrões)
- `UNION SELECT`, `DROP TABLE`, `EXEC xp_`, `WAITFOR DELAY`, `BENCHMARK()`
- `OR 1=1`, `AND 1=1`, `pg_sleep()`, `information_schema`, `@@version`
- `LOAD_FILE()`, `INTO OUTFILE`, `0xHEX`

### XSS (30+ padrões)
- Tags `<script>`, `<img onerror>`, `<svg onload>`, `<body onload>`
- Handlers: `onload`, `onerror`, `onclick`, `onmouseover`, `onfocus`, `onchange`, `onsubmit`
- Funções: `alert()`, `confirm()`, `prompt()`, `eval()`, `fromCharCode()`
- Data URIs: `data:text/html`, `data:text/javascript`

### Path Traversal (10+ padrões)
- `../../../etc/passwd`, `..%2f`, `..%5c`, `%2e%2e%2f`

### Command Injection (18+ padrões)
- Shell commands: `;id`, `|whoami`, `` `ls` ``, `$(...)`
- Functions: `system()`, `shell_exec()`, `exec()`, `passthru()`, `eval()`, `assert()`
- PowerShell: `-Command`, `-EncodedCommand`, `Invoke-Expression`

### SSRF (14+ padrões)
- IPs internos: `169.254.169.254`, `127.0.0.1`, `10.x`, `172.16-31.x`, `192.168.x`
- Protocolos: `file://`, `gopher://`, `dict://`

### LFI/RFI (12+ padrões)
- Arquivos sensíveis: `/etc/passwd`, `/etc/shadow`, `/proc/self/environ`
- PHP wrappers: `php://filter`, `php://input`, `data://text/plain;base64`, `expect://`

### NoSQL Injection (8+ padrões)
- MongoDB operators: `$gt`, `$gte`, `$lt`, `$lte`, `$ne`, `$regex`, `$where`

### Cookie Poisoning (7+ padrões)
- `admin=true`, `is_admin=1`, `debug=true`, `role=admin`

### Open Redirect (7+ padrões)
- `next=http://`, `redirect=http://`, `url=http://`, `//evil.com@`

### Scanner Detection (18+ padrões)
- `sqlmap`, `nmap`, `nikto`, `gobuster`, `burpsuite`, `acunetix`, `nessus`, `metasploit`, `curl`, `wget`

---

## 📊 Dashboard

O Kaido WAF inclui um dashboard SSR (server-side rendered) que não depende de JavaScript para funcionar.

**Acesse:** `http://seu-servidor:9090/dashboard`

- Login protegido (usuário/senha configuráveis)
- Visão geral do status do WAF
- Lista de detectores ativos
- Configuração atual
- Totalmente server-side (zero JS dependency)

---

## 🐳 Deploy

### Produção com Redis

```yaml
# docker-compose.yml
version: "3.8"
services:
  kaido-waf:
    build: .
    ports:
      - "8080:8080"
      - "9090:9090"
    environment:
      - KAIDO_WAF_CONFIG=/etc/kaido-waf/config.yaml
    volumes:
      - ./config.yaml:/etc/kaido-waf/config.yaml
    depends_on:
      - redis

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
```

### Nginx como proxy reverso

```nginx
server {
    listen 443 ssl;
    server_name seu-dominio.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /dashboard {
        proxy_pass http://127.0.0.1:9090;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## 🔧 API Endpoints

| Endpoint | Descrição |
|----------|-----------|
| `GET /__health` | Health check do WAF |
| `GET /__stats` | Estatísticas do WAF |
| `GET /dashboard` | Dashboard web |
| `GET /api/dashboard/stats` | API de estatísticas |

---

## 📈 Roadmap

- [ ] Suporte a WebSocket nativo
- [ ] Regras customizáveis por domínio
- [ ] Machine Learning para detecção de anomalias
- [ ] API REST para gerenciamento remoto
- [ ] Integração com SIEM (Splunk, ELK)
- [ ] Modo cluster com Redis
- [ ] Cache de requisições legítimas
- [ ] Plugin system para detectores customizados

---

## 👑 Créditos

**Kaido WAF** foi criado e é mantido por:

### **Gustavo** — Kaido Red Team
> Mestre do Kaido Red Team, criador deste WAF e desenvolvedor de ferramentas de segurança ofensiva e defensiva.

### Kaido Red Team
Red team ofensivo brasileiro especializado em:
- 🔴 Pentest Blackbox & Whitebox
- 💀 Desenvolvimento de Malware
- 🛡️ Segurança Ofensiva e Defensiva
- 🔍 OSINT e Engenharia Reversa
- ⚡ Ferramentas C2 e RAT

### Mencões Especiais
- **b1/epy (Izy)** — Owner/CEO do Kaido Team, criador de todo o arsenal Kaido
- **tec** — Red team core, operador principal
- **Valeria** — Modelo de IA do time

---

## 📄 Licença

MIT License — veja o arquivo [LICENSE](LICENSE) para detalhes.

Copyright (c) 2026 **Gustavo — Kaido Red Team**

---

<div align="center">
  <p>
    <strong>⚔️ Kaido WAF — Protegendo aplicações, uma requisição por vez.</strong><br>
    <sub>Kaido Red Team &bull; Brasil &bull; 2026</sub>
  </p>
  <p>
    <a href="https://kaido.team">Kaido Team</a> •
    <a href="https://github.com/KaidoTeam">GitHub</a>
  </p>
</div>
