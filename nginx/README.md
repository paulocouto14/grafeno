# Nginx + Cloudflare para Grafeno

Configuração para hospedar o Grafeno com **proxy reverso** e **Cloudflare** (HTTPS flexível: visitante → HTTPS no Cloudflare; Cloudflare → seu servidor em HTTP).

## Arquivos

| Arquivo | Uso |
|---------|-----|
| `grafeno.conf` | Bloco `server` do site (proxy, headers de segurança, rate limit). |
| `grafeno-http.conf` | Zonas de rate limit. Deve ser incluído no bloco `http { }` do `nginx.conf` principal. |
| `cloudflare-ips.conf` | IPs do Cloudflare para `real_ip` (IP real do visitante). |

## Passo a passo (Debian/Ubuntu)

### 1. Copiar arquivos para o servidor

```bash
sudo cp grafeno.conf /etc/nginx/sites-available/grafeno
sudo cp grafeno-http.conf /etc/nginx/
sudo cp cloudflare-ips.conf /etc/nginx/
```

### 2. Incluir zonas de rate limit no `nginx.conf`

Edite `/etc/nginx/nginx.conf` e, **dentro** do bloco `http { }`, adicione:

```nginx
include /etc/nginx/grafeno-http.conf;
```

### 3. Ajustar o `grafeno.conf`

Edite `/etc/nginx/sites-available/grafeno`:

- Troque **SEU_DOMINIO** pelo domínio que aponta no Cloudflare (ex.: `app.seudominio.com`).
- Se a aplicação Node rodar em outra porta, altere `proxy_pass http://127.0.0.1:3000` (ex.: `:4000`).
- Se quiser servir arquivos estáticos pelo Nginx, descomente o `location /public/` e coloque o caminho real da pasta `public` do projeto em `alias`.

### 4. Ativar o site e testar

```bash
sudo ln -s /etc/nginx/sites-available/grafeno /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 5. Atualizar IPs do Cloudflare (opcional)

Os IPs do Cloudflare mudam de vez em quando. Para atualizar:

- IPv4: <https://www.cloudflare.com/ips-v4>
- IPv6: <https://www.cloudflare.com/ips-v6>

Edite `/etc/nginx/cloudflare-ips.conf` com os blocos atuais ou use um script/cron que baixe e gere o arquivo.

## O que fica protegido

- **Real IP**: uso de `CF-Connecting-IP` para ver o IP real do visitante (e no app, `X-Forwarded-For` / `req.ip`).
- **Headers de segurança**: `X-Frame-Options`, `X-Content-Type-Options`, `X-XSS-Protection`, `Referrer-Policy`, `Permissions-Policy`.
- **Rate limit**: 10 req/s por IP com burst 20; até 20 conexões simultâneas por IP.
- **Body**: `client_max_body_size 256k` alinhado ao limit do Express.
- **Proxy**: repasse de `Host`, `X-Real-IP`, `X-Forwarded-For`, `X-Forwarded-Proto` para o Node.

## Cloudflare (HTTPS flexível)

- No Cloudflare: **SSL/TLS** → **Flexible** (tráfego visitante → Cloudflare em HTTPS; Cloudflare → origem em HTTP).
- O Nginx escuta na **porta 80**. Não é necessário certificado no servidor com Flexible.
- Se no futuro usar **Full** ou **Full (Strict)**:
  - Descomente o bloco `server { listen 443 ssl ... }` no `grafeno.conf`.
  - Configure certificado (ex.: Let's Encrypt) e caminhos em `ssl_certificate` e `ssl_certificate_key`.
  - HSTS já está no bloco comentado.

## Aplicação Node

Garanta que o Grafeno rode em modo produção e escute em `127.0.0.1:3000` (ou na porta configurada no Nginx), por exemplo com **pm2**:

```bash
cd /caminho/para/grafeno
NODE_ENV=production PORT=3000 pm2 start bin/www --name grafeno
pm2 save && pm2 startup
```

Defina `COOKIE_SECRET` (e outras variáveis) no `.env` em produção.
