# AVISO
- Este projeto não é open-source, verifique a [licença](https://github.com/op3ny/hsdcm/blob/main/LICENSE.md) antes de executar ou replicar

---

---

# 📚 Manual Técnico – HSDCM

## 1 — Objetivo técnico

O HSDCM tem como meta permitir que usuários e aplicações **tradicionais** (exploradores de arquivos, navegadores, scripts) acessem conteúdo da rede HPS sem conhecer o protocolo P2P: o módulo age como ponte, provendo:

* API HTTP local (HSDCM-WI) com permissões interativas;
* Disco virtual que transforma arquivos no filesystem em ações na rede HPS;
* Proxy utilitário para integrar navegadores com domínios que representam hashes;
* Downloader GUI (DU) para usuários não técnicos;
* Mecanismo de verificação/assinatura e banco local para cache e auditoria.

---

## 2 — Principais componentes e responsabilidades

### 2.1 `HPSClient`

* **Funções principais:** conectar a servidores HPS via Socket.IO, autenticar (PoW + assinatura), pedir conteúdo, solicitar resolução DNS descentralizada, salvar e validar conteúdo localmente.
* **Storage:** usa `self.crypto_dir = ~/.hsdcm` por padrão; conteúdos ficam em `~/.hsdcm/content/<hash>.dat`. 
* **Cache DB:** usa `DatabaseManager` (SQLite) para configurações, cache de conteúdo, logs de segurança, DNS cache e estatísticas. 

### 2.2 `HSDCM_DI` (Desktop Integration)

* **Cria** `HPS_Virtual_Disk` (Desktop path no Windows/macOS, `~/HPS_Virtual_Disk` no Linux). 
* **Monitora** novos arquivos: se detectar `*.download` ou `*.dns.download` inicia fluxo de download.
* **Fluxo**: detecta → pede permissão (dialogos + se necessário login) → chama `HPSClient.request_content` ou `resolve_dns` → grava arquivo final → remove `.download`.

### 2.3 `HSDCM_WI` (Web Integration)

* **Servidor HTTP local** (classe `ThreadedHTTPServer` + `FastHTTPHandler`) escuta por requisições do navegador na porta (default) `18238`. 
* **Processador de permissões**: fila (`permission_queue`) e thread dedicada que serializa janelas de permissão para evitar múltiplos popups simultâneos. 
* **Endpoints**:

  * `/get-file?hash=<hash64>` — solicita download de arquivo pelo hash (verifica permissão e autenticação). 
  * `/resolve-dns?domain=<domain>` — resolve domínio HPS via rede. 
  * `/file-info?hash=<hash64>` — retorna metadados locais do arquivo (title, username, verified, reputation, size). 
  * `/health` — status do serviço (connected, authenticated, user, server, timestamp). 
  * `/search` — mecanismo de busca que envia `search_content` ao HPSClient e retorna resultados via callback (implementado no código). 

### 2.4 `HSDCM_DU` (Downloader Utility)

* UI para downloads manuais (hash ou domínio), seleção de pasta destino, e visual de progresso. Documentação na UI com exemplos. 

### 2.5 `Proxy Utility (PU)`

* **Objetivo:** permitir que navegadores acessem conteúdo HPS via URLs “normais” como `http://<hash64>.com` ou `http://<domain>.com`.
* **Heurística:** função `is_hash_domain` identifica hostnames cujo primeiro segmento tem 64 caracteres hexadecimais e trata como hash. 
* **Limitações:** NÃO suporta `CONNECT` (método CONNECT não suportado); funciona apenas para HTTP (não HTTPS). 

### 2.6 Segurança (SecurityDialog + validações)

* O sistema exige permissão do usuário para cada operação que envolva download/execução.
* Verificações feitas: integridade (SHA-256), assinatura (RSA 4096), comparação de `header_present` para conteúdos encapsulados, reputação, e logs de segurança no DB.  

---

## 3 — Fluxos detalhados (sequência temporal, timeouts e erros)

### 3.1 Login (FastLoginDialog + PoW)

1. App pede `request_pow_challenge` ao servidor (socketio).
2. `FastPowSolver.solve_challenge` minerará o nonce (multithread; 4 threads por padrão). Quando encontra nonce, retorna nonce e hashrate observada. 
3. Cliente envia assinatura do desafio com chave privada; servidor valida e retorna sucesso/falha.
4. Timeouts: várias esperas usam `wait` com timeouts (ex.: autenticação espera ~20–25s). Se timeout, processo de login falha e usuário é notificado. 

### 3.2 Download via API (`/get-file`)

1. Navegador chama `GET /get-file?hash=<hash>` → `FastHTTPHandler` → `wi_instance.handle_get_file_async`. 
2. `ask_permission` cria um `PermissionRequest` e aguarda resposta do thread de permissões (até 30s). 
3. Se o usuário permitir e autenticar (se necessário), `do_api_download` tenta servir do cache local (`get_content_file_path`). Se não existe, chama `HPSClient.request_content` (async) e espera callback/evento. 
4. Erros (timeout, conteúdo não disponível) são tratados e o WI retorna páginas de erro amigáveis (função `send_error_page`). 

### 3.3 Resolução de DNS (`/resolve-dns`)

* Fluxo similar: `resolve_dns(name)` é chamado, fio aguarda evento de callback (com timeout). Se sucesso, recebe `content_hash` e pode iniciar download. 

### 3.4 Busca (`/search`)

* Cria `search_id`, envia `search_content` ao HPSClient; registra callback em `response_callbacks` e espera o evento. Resultados retornam ao HTTP client se encontrados. 

---

## 4 — Endpoints completos e respostas (detalhes)

> **Nota:** os nomes exatos dos endpoints são os implementados em `FastHTTPHandler.do_GET` — use estes ao integrar frontends.

### `GET /get-file?hash=<hash64>`

* Valida `hash` (64 hex chars).
* Permissão do usuário (SecurityDialog).
* Se cache presente: serve arquivo com headers corretos.
* Se não: dispara `HPSClient.request_content` e espera evento (`content_download_events[hash]`).
* Possíveis respostas: `200` (arquivo), `400` (hash inválido), `403` (usuário negou / login falhou), `404` (arquivo não encontrado após tentativa), `500` (erro interno). 

### `GET /resolve-dns?domain=<domain>`

* Pergunta permissão, exige login se necessário, chama `client.resolve_dns(domain)` e aguarda callback. Retorna JSON com `content_hash` se encontrado. 

### `GET /file-info?hash=<hash64>`

* Retorna JSON com metadados (title, description, mime_type, username, verified, status, reputation, size). Se não encontrado, `404`. 

### `GET /health`

* Retorna algo como:

```json
{
  "status":"ok",
  "connected": true|false,
  "authenticated": true|false,
  "user": "username or anonymous",
  "server": "server address or none",
  "timestamp": 1234567890.0
}
```

Usado pelo UI para atualizar status. 

### `GET /search?q=<query>&type=<type>`

* Inicia `search_content` no HPSClient; espera resultados por callback. Retorna JSON com resultados ou erro. 

---

## 5 — Estrutura local de armazenamento e DB (importante para manutenção)

* **Conteúdos:** `~/.hsdcm/content/<hash>.dat` (conteúdo bruto, possivelmente com header). 
* **Chaves:** `~/.hsdcm/private_key.pem`, `~/.hsdcm/public_key.pem`. 
* **SQLite DB:** `~/.hsdcm/hsdcm.db` com tabelas (resumo das tabelas principais visto no `DatabaseManager`):

  * `hsdcm_settings` — configurações persistentes.
  * `hsdcm_content_cache` — metadados de arquivos (hash, path, mime, verified, reputation, integrity_ok, header_present, created_at, etc.).
  * `hsdcm_dns_cache` — cache de domínios → hash, ttl.
  * `hsdcm_security_logs` — logs de ações com timestamps.
  * `hsdcm_pending_requests`, `hsdcm_server_cache`, `hsdcm_node_stats`, `hsdcm_recent_files`.
    (Criação e schema confirmados no `DatabaseManager._init_schema`). 

---

## 6 — Como criar sites para a rede HPS (guia técnico)

Sites na HPS são **conteúdo publicado** (estático) identificado por hashes. O navegador não acessa CDNs externas — tudo precisa estar disponível na rede HPS ou embutido.

### Regras/Boas práticas (reais e reforçadas pelo código)

1. **Autonomia total:** evite dependências externas (CDNs, fonts remotas, APIs externas). O conteúdo deve funcionar offline a partir dos arquivos oferecidos na rede HPS. (Código força isso: WI serve recursos locais resolvendo cada requisição). 
2. **Arquivos múltiplos é OK:** você pode ter `index.html` já contendo JS, CSS, HTML (claro), etc. O arquivo vira um content hash individual. O WI irá resolver cada pedido. 
3. **Embed small assets:** para reduzir requisições, considere embutir CSS e JS minificados dentro do `index.html` via `<style>` e `<script>` quando fizer sentido.
4. **Assinatura:** todo conteúdo idealmente deve ser assinado (o sistema checa assinatura quando presente). Isso aumenta confiança e evita downloads adulterados. 
5. **Headers e meta:** inclua header metadata se desejar (o código detecta `"### :END START"` como separador de header em `save_content_to_storage` e `extract_content_from_header`). 

### Exemplo de publicação (alto nível)

1. Gere os arquivos estáticos localmente.
2. Publique-os na rede HPS usando o [Navegador HPS](https://github.com/op3ny/hps)
3. Registre um domínio `.hps` apontando para o `<hash>` (que representa o `index.html`) (registro na camada de DNS HPS).
4. Usuário acessa via proxy `http://dominio.extensao` (onde proxy converte dominio para hash). WI e PU fazem o resto. 

---

## 7 — Como integrar um site com HSDCM-WI (exemplo prático)

* No HTML do site, faça chamadas XHR/fetch para `http://localhost:18238` para recursos HPS (ex.: `/get-file?hash=...` ou `/file-info?hash=...`). O usuário verá popups pedindo permissão (por segurança). 

**Recomendação de implementação frontend (sem dependências externas):**

* Embuta CSS e JS quando possível.
* Se precisar carregar assets separados, coloque `<link rel="stylesheet" href="<HASH_DO_OUTRO_ARQUIVO>.com">` (o proxy vai receber a requisição, e fazer o resto, desde que o outro arquivo esteja na rede HPS).
* Nunca dependa de `https://` remoto.

---

## 8 — Logs, auditoria e privacidade

* Todas as ações relevantes (download, resolução DNS, busca, falhas) são registradas em `hsdcm_security_logs`. Isso permite auditoria por administrador. 
* O usuário sempre precisará aprovar operações sensíveis; não há execução silenciosa de código remoto. 

---

## 9 — Configurações e UI

* As configurações persistentes estão em `hsdcm_settings` (auto_start, start_with_system, default_server, api_port, proxy_port). A interface carrega e salva essas configurações via `load_settings()` / `save_settings()`. 

---

## 10 — Erros e tratamento

* Páginas de erro amigáveis construídas em HTML (função `send_error_page`) são usadas para explicar ao usuário o que ocorreu (403, 404, 500, timeout). O handler tenta sempre escrever resposta segura e registrar o incidente. 

---

## 11 — Performance / limites e recomendações operacionais

* PoW usa múltiplas threads (o código usa 4 threads). Em máquinas com poucos núcleos ajustar a estratégia pode melhorar UX. 
* Cache local evita downloads repetidos — mantenha o disco `~/.hsdcm` com espaço suficiente. `disk_quota` default no client sugere limites (ex.: 500 MB no código). 

---

## 12 — Apêndice técnico — código / hooks úteis

* **Callback registration:** o WI e DI usam `client.response_callbacks` para associar `search_id`, `content_hash` ou `domain` a callbacks que são acionados quando o HPSClient recebe resposta do supernó. Examine `with self.client.callback_lock` e manipulação nas funções `do_api_search`, `do_domain_resolution` etc. 
* **Eventos sincronizados via threading.Event:** o código frequentemente cria um `threading.Event()` e aguarda blocos de resultado com `.wait(timeout)`; revise timeouts para UX. 

---

## 13 — Nota final

Este manual técnico reflete os nomes exatos de endpoints, portas padrão, arquivos e fluxos implementados. Use-o como referência de integração para criar sites, ferramentas ou documentar a API local. Para partes do protocolo HPS (registro de domínios na rede, publicação de conteúdo) que dependem de supernó/infra do HPS, recomendo consultar a documentação do servidor HPS (não presente neste repositório).
Saiba mais em [Manual Técnico HPS (Hsyst Peer to Peer (P2P) Service)](https://github.com/op3ny/hps/blob/main/tecnico.md).

---

# Créditos
Feito com ❤️ pela [Thaís](https://github.com/op3ny)
