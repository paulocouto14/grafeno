#!/bin/bash
# Atualiza /etc/nginx/cloudflare-ips.conf com os IPs atuais do Cloudflare.
# Uso: sudo ./update-cloudflare-ips.sh
# Sugestão: agendar no cron (ex.: semanal) para manter atualizado.

set -e
CONF="/etc/nginx/cloudflare-ips.conf"
TMP=$(mktemp)

echo "# Gerado em $(date -Iseconds) por update-cloudflare-ips.sh" > "$TMP"
echo "# Fonte: https://www.cloudflare.com/ips-v4 e /ips-v6" >> "$TMP"
echo "" >> "$TMP"

for ip in $(curl -sS https://www.cloudflare.com/ips-v4); do
  echo "set_real_ip_from $ip;" >> "$TMP"
done
echo "" >> "$TMP"
for ip in $(curl -sS https://www.cloudflare.com/ips-v6); do
  echo "set_real_ip_from $ip;" >> "$TMP"
done

mv "$TMP" "$CONF"
echo "Atualizado: $CONF"
nginx -t && systemctl reload nginx 2>/dev/null || true
