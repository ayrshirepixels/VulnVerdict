#!/usr/bin/env bash
# Runs as root inside the build VM (build.pkr.hcl). Installs Docker and the VulnVerdict stack, then
# strips everything that must be unique per appliance so each imported copy gets its own identity.
# Env: VV_IMAGE (tag the stack runs), VV_VERSION.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
: "${VV_IMAGE:?}" "${VV_VERSION:?}"

# ── Docker ────────────────────────────────────────────────────────────────
apt-get update
apt-get install -y ca-certificates curl gnupg
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu noble stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
systemctl enable --now docker

# ── The stack ─────────────────────────────────────────────────────────────
install -d -m 0755 /opt/vulnverdict
install -m 0644 /tmp/vv/docker-compose.yml /tmp/vv/Caddyfile /opt/vulnverdict/
install -m 0755 /tmp/vv/update.sh /tmp/vv/rollback.sh /opt/vulnverdict/
# DB_PASSWORD is a placeholder: the first-boot wizard generates the real one, so no two appliances
# share it. The .env is root-only because it will hold that password.
printf 'DB_PASSWORD=__SET_AT_FIRST_BOOT__\nVV_HOSTNAME=vulnverdict\nVV_IMAGE=%s\nCVE_MIN_YEAR=0\n' "$VV_IMAGE" > /opt/vulnverdict/.env
chmod 600 /opt/vulnverdict/.env
echo "$VV_VERSION" > /opt/vulnverdict/VERSION

shopt -s nullglob
tars=(/tmp/vv/images/*.tar.gz /tmp/vv/images/*.tar)
if (( ${#tars[@]} )); then
  for t in "${tars[@]}"; do echo "loading $t"; docker load -i "$t"; done
else
  docker pull "$VV_IMAGE"
fi
docker image inspect "$VV_IMAGE" >/dev/null   # fail the build if the tag the stack needs is missing
docker pull postgres:16-alpine
docker pull caddy:2-alpine

install -m 0755 /tmp/vv/firstboot.sh /usr/local/sbin/vulnverdict-firstboot

# First-boot wizard on tty1. It holds tty1 while it runs, then hands the console back to a login prompt.
cat > /etc/systemd/system/vulnverdict-firstboot.service <<'UNIT'
[Unit]
Description=VulnVerdict first boot wizard
After=network-online.target docker.service systemd-user-sessions.service
Wants=network-online.target
Before=getty@tty1.service
Conflicts=getty@tty1.service
ConditionPathExists=!/opt/vulnverdict/.configured

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/vulnverdict-firstboot
ExecStartPost=-/bin/systemctl --no-block start getty@tty1.service
StandardInput=tty
StandardOutput=tty
StandardError=tty
TTYPath=/dev/tty1
TTYReset=yes
TTYVHangup=yes

[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/vulnverdict.service <<'UNIT'
[Unit]
Description=VulnVerdict stack
Requires=docker.service
After=docker.service network-online.target
ConditionPathExists=/opt/vulnverdict/.configured

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/vulnverdict
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down

[Install]
WantedBy=multi-user.target
UNIT

# Fresh SSH host keys on each appliance's first boot (the build's keys are deleted below).
cat > /etc/systemd/system/vulnverdict-hostkeys.service <<'UNIT'
[Unit]
Description=Generate this appliance's SSH host keys
Before=ssh.service ssh.socket
ConditionPathExists=!/etc/ssh/ssh_host_ed25519_key

[Service]
Type=oneshot
ExecStart=/usr/bin/ssh-keygen -A

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable vulnverdict-firstboot.service vulnverdict.service vulnverdict-hostkeys.service

# ── Portable networking ──────────────────────────────────────────────────
# The installer's netplan names this build VM's NIC (eth0 on Hyper-V); VMware calls it ens160/ens33.
# DHCP on any Ethernet interface instead, and turn cloud-init off so it neither rewrites this nor
# spends two minutes per boot looking for a cloud metadata service that isn't there.
rm -f /etc/netplan/*.yaml
cat > /etc/netplan/01-vulnverdict.yaml <<'NETPLAN'
network:
  version: 2
  ethernets:
    any-ethernet:
      match:
        name: "e*"
      dhcp4: true
      dhcp-identifier: mac
NETPLAN
chmod 600 /etc/netplan/01-vulnverdict.yaml
touch /etc/cloud/cloud-init.disabled

# ── Lock down until the wizard has run ───────────────────────────────────
# SSH stays off until the first-boot wizard has replaced the default password; the wizard turns it
# on. The build's passwordless sudo is removed by the wizard too.
systemctl disable ssh.socket ssh.service 2>/dev/null || true

# ── Per-appliance identity ───────────────────────────────────────────────
# (SSH host keys are deleted by the shutdown command in build.pkr.hcl, after Packer's last SSH use.)
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id && ln -s /etc/machine-id /var/lib/dbus/machine-id
rm -rf /tmp/vv

# ── Shrink ───────────────────────────────────────────────────────────────
apt-get clean
rm -rf /var/lib/apt/lists/*
journalctl --rotate && journalctl --vacuum-time=1s || true
fstrim -av || true
dd if=/dev/zero of=/EMPTY bs=1M status=none || true
rm -f /EMPTY
sync
echo "appliance setup complete: $VV_IMAGE"
