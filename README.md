# AVISO
- Este projeto não é open-source, verifique a [licença](https://github.com/op3ny/hsdcm/blob/main/LICENSE.md) antes de executar ou replicar

---

---

# 📘 Manual do Usuário – HSDCM

*HPS Surface and Desktop Compatibility Module*

Tem interesse em aprender mais a fundo? Criar sites, domínios e desenvolver para a rede HPS? [Clique Aqui!](https://github.com/op3ny/hsdcm/blob/main/MANUAL-TECNICO.md)

O que é o HSDCM?
**Resumo rápido:** o HSDCM integra a rede P2P HPS ao seu desktop. Ele fornece:

* Disco virtual (`HPS_Virtual_Disk`) para downloads por arquivo/hash ou por domínio HPS.
* API Web local para navegadores (HSDCM-WI).
* Downloader gráfico (HSDCM-DU) e Proxy (HSDCM-PU).
* Verificação de integridade e assinatura antes de qualquer download.

---

## 📥 Download

Baixe a versão mais recente em:
`https://github.com/Hsyst/hsdcm/releases`

Arquivos típicos nas releases:

* `hsdcm` — binário Linux.
* `hsdcm.py` — versão Python (multiplataforma).

---

## 🖥️ Requisitos

* Python 3.10+ (se for usar a versão `.py`).
* Dependências (para versão Python):

```
pip install tkinter aiohttp python-socketio cryptography pillow requests pystray
```

---

## ▶️ Como rodar

### Linux (binário)

```bash
chmod +x hsdcm
./hsdcm
```

### Qualquer sistema (Python)

```bash
python3 hsdcm.py
```

---

## 📁 Disco Virtual (HPS_Virtual_Disk)

Ao iniciar o HSDCM, ele cria uma pasta chamada `HPS_Virtual_Disk` no Desktop (ou `~/HPS_Virtual_Disk` no Linux). Dentro dela:

### Baixar por hash

Crie um arquivo com nome:

```
<hash64>.download
```

Ex.: `b1e3f0...a0fea933.download`
O HSDCM detecta, pede confirmação, faz login se necessário, verifica segurança e substitui o `.download` pelo arquivo real.

### Baixar por domínio HPS (DNS)

Crie:

```
example.hps.dns.download
```

Ele resolve o domínio na rede HPS, coleta o hash e baixa.

---

## 🌐 API Web local (para navegadores)

O HSDCM expõe uma API local que **por padrão** roda em:

```
http://localhost:18238/
```

(A porta padrão pode ser configurada nas settings UI). 

### Endpoints que você pode usar (resumido)

* `GET /get-file?hash=<hash64>` — baixa arquivo pelo hash. 
* `GET /resolve-dns?domain=<domain>` — resolve domínio HPS para hash. 
* `GET /file-info?hash=<hash64>` — retorna metadados do arquivo. 
* `GET /health` — status da API e conexão. 
* `GET /search?q=<query>&type=<type>` — busca (documentada no UI). 

**Observação de segurança:** toda requisição que acessa a rede HPS normalmente irá abrir um diálogo nativo para pedir permissão do usuário; downloads exigem confirmação e, se necessário, login. 

---

## 🔧 Proxy (HSDCM-PU)

Existe também uma utilidade de proxy para navegadores (instruções de proxy na GUI). Nas docs internas é sugerida a porta `8081` como padrão do proxy (configurável). O proxy mapeia domínios do tipo `<hash64>.com` para conteúdo HPS quando reconhece um hash no hostname.  

---

## 🔐 Segurança e verificações

Antes de baixar qualquer conteúdo o HSDCM:

* Mostra hash e metadados
* Mostra chave pública e assinatura (SecurityDialog)
* Verifica integridade (SHA-256) e assinatura (RSA)
* Registra ações no banco local

Os arquivos finais são salvos em `~/.hsdcm/content/` e os metadados ficam no banco SQLite local.  

---

## ✅ Dicas rápidas

* Não use CDNs ou links externos nos sites que pretende hospedar na HPS (o site deve ser autônomo).
* Use o Downloader Utility (DU) ou os arquivos `.download` para recuperar conteúdo. 
* Se o navegador não carrega direto, verifique `http://localhost:18238/health`.

---

# Créditos
Feito com ❤️ pela [Thaís](https://github.com/op3ny)
