#!/usr/bin/env bash
# VulnVerdict appliance first-boot wizard (runs once on tty1, vulnverdict-firstboot.service).
# Fifteen-minute install, brief section 3 rule 4: hostname, new password, then the stack starts and the
# console URL is printed. Everything unique to this appliance is created here, not at build time.
set -euo pipefail
ENV_FILE=/opt/vulnverdict/.env
# tty1 is also the system console: stop systemd's "[ OK ] Finished ..." lines and kernel messages
# printing over the questions while the wizard runs, and turn them back on when it is done.
kill -s SIGRTMIN+21 1 2>/dev/null || true
dmesg -n 1 2>/dev/null || true
trap 'kill -s SIGRTMIN+20 1 2>/dev/null || true' EXIT
clear || true
cat <<'BANNER'

   VULNVERDICT appliance          Cut the noise. Know your risk.
   ---------------------------------------------------------------
BANNER
echo

# Wait up to a minute for DHCP so the address shown is real.
IP=""
for _ in $(seq 1 30); do
  IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [ -n "$IP" ] && break
  sleep 2
done
echo "This appliance has IP address ${IP:-none yet} (DHCP)."
echo "Reserve it in your DHCP server, or set a static address in /etc/netplan afterwards."
echo

DOMAIN="$(hostname -d 2>/dev/null || true)"
DEFAULT_HOST="vulnverdict${DOMAIN:+.$DOMAIN}"
read -r -p "Hostname the console will answer on [${DEFAULT_HOST}]: " HOST
HOST="${HOST:-$DEFAULT_HOST}"
sed -i "s|^VV_HOSTNAME=.*|VV_HOSTNAME=${HOST}|" "$ENV_FILE"
hostnamectl set-hostname "${HOST%%.*}" || true

echo
echo "Choose a password for the local 'vulnverdict' account (console and SSH login)."
until passwd vulnverdict; do echo "Try again."; done

# This appliance's own database password.
if grep -q '^DB_PASSWORD=__SET_AT_FIRST_BOOT__$' "$ENV_FILE"; then
  sed -i "s|^DB_PASSWORD=.*|DB_PASSWORD=$(head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 40)|" "$ENV_FILE"
fi
chmod 600 "$ENV_FILE"

# The build's passwordless sudo goes; sudo now asks for the password just set.
rm -f /etc/sudoers.d/vulnverdict
# SSH was off until the default password was gone.
systemctl enable --now ssh.socket >/dev/null 2>&1 || systemctl enable --now ssh.service >/dev/null 2>&1 || true

echo
echo "Starting VulnVerdict (database, worker, console, TLS proxy)..."
cd /opt/vulnverdict
docker compose up -d
touch /opt/vulnverdict/.configured
systemctl enable vulnverdict.service >/dev/null 2>&1 || true
# Everything the stack just created (the database's first files above all) reaches the disk now, so a
# power cut or reset straight after setup leaves a working appliance.
sync

# Caddy creates its internal CA on first start; keep a copy of the root to import into browsers.
for _ in $(seq 1 15); do
  if docker compose exec -T proxy cat /data/caddy/pki/authorities/local/root.crt > /opt/vulnverdict/caddy-root.crt 2>/dev/null \
     && [ -s /opt/vulnverdict/caddy-root.crt ]; then break; fi
  sleep 2
done

echo
echo "Done. Open https://${HOST}/ (or https://${IP:-<this appliance>}/) and create the administrator account."
echo "The certificate is from the appliance's own internal CA. Import /opt/vulnverdict/caddy-root.crt into"
echo "your browsers, or replace it with your own certificate (docs/install.md)."
echo "Feeds start loading now; the first full CVE list takes 10 to 20 minutes."
echo
read -r -p "Press Enter for a login prompt. " _ || true
