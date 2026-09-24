#!/usr/bin/env bash
# VulnVerdict appliance first-boot wizard (runs once on tty1). Fifteen-minute install, brief section 3 rule 4:
# hostname, network check, new password, then the stack starts and the console URL is printed.
set -euo pipefail
clear
cat <<'BANNER'

   VULNVERDICT appliance          Cut the noise. Know your risk.
   ---------------------------------------------------------------
BANNER
echo
IP="$(hostname -I | awk '{print $1}')"
echo "This VM has IP address ${IP:-none} (DHCP). Set a static address in your DHCP server or edit /etc/netplan afterwards."
echo
read -r -p "Hostname the console will answer on [vulnverdict.$(hostname -d 2>/dev/null || echo local)]: " HOST
HOST="${HOST:-vulnverdict.$(hostname -d 2>/dev/null || echo local)}"
sed -i "s|^VV_HOSTNAME=.*|VV_HOSTNAME=${HOST}|" /opt/vulnverdict/.env
hostnamectl set-hostname "${HOST%%.*}" || true
echo
echo "Set a new password for the local 'vulnverdict' account (SSH and console login)."
until passwd vulnverdict; do echo "Try again."; done
echo
echo "Starting VulnVerdict (Postgres, worker, console, TLS proxy)..."
cd /opt/vulnverdict && docker compose up -d
touch /opt/vulnverdict/.configured
systemctl enable vulnverdict.service >/dev/null 2>&1 || true
echo
echo "Done. Open https://${HOST}/ (or https://${IP}/) and create the administrator account."
echo "The certificate is from the appliance's internal CA; import it from /opt/vulnverdict/caddy-root.crt or replace it (see docs/install.md)."
docker compose exec -T proxy cat /data/caddy/pki/authorities/local/root.crt > /opt/vulnverdict/caddy-root.crt 2>/dev/null || true
echo "Feeds start loading now; the first full CVE list takes 10 to 20 minutes. Press Enter to continue."
read -r _
