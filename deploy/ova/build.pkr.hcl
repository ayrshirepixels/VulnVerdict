# VulnVerdict appliance (OVA) build with HashiCorp Packer.
# Produces an Ubuntu 24.04 LTS VM with Docker and the VulnVerdict Compose stack pre-installed and a first-boot
# wizard for hostname and network. Run on a build host with Packer and VirtualBox or VMware installed:
#   packer init . && packer build -var "vv_image=ghcr.io/ayrshirepixels/vulnverdict:1.0.0" .
# The result is deploy/ova/output/vulnverdict-<version>.ova (2 vCPU, 4 GB RAM, 40 GB disk: brief section 10.1).

packer {
  required_plugins {
    virtualbox = { version = ">= 1.0.0", source = "github.com/hashicorp/virtualbox" }
  }
}

variable "vv_image"   { type = string, default = "ghcr.io/ayrshirepixels/vulnverdict:latest" }
variable "vv_version" { type = string, default = "dev" }
variable "iso_url"    { type = string, default = "https://releases.ubuntu.com/24.04/ubuntu-24.04.3-live-server-amd64.iso" }
variable "iso_checksum" { type = string, default = "file:https://releases.ubuntu.com/24.04/SHA256SUMS" }

source "virtualbox-iso" "vulnverdict" {
  guest_os_type    = "Ubuntu_64"
  iso_url          = var.iso_url
  iso_checksum     = var.iso_checksum
  cpus             = 2
  memory           = 4096
  disk_size        = 40960
  headless         = true
  http_directory   = "."
  boot_wait        = "5s"
  boot_command = [
    "c<wait>",
    "linux /casper/vmlinuz autoinstall ds=nocloud-net\\;s=http://{{ .HTTPIP }}:{{ .HTTPPort }}/ ---<enter><wait>",
    "initrd /casper/initrd<enter><wait>",
    "boot<enter>"
  ]
  ssh_username     = "vulnverdict"
  ssh_password     = "vulnverdict"       # first-boot forces a change
  ssh_timeout      = "30m"
  shutdown_command = "echo vulnverdict | sudo -S shutdown -P now"
  format           = "ova"
  output_directory = "output"
  vm_name          = "vulnverdict-${var.vv_version}"
  vboxmanage = [
    ["modifyvm", "{{.Name}}", "--nat-localhostreachable1", "on"],
    ["modifyvm", "{{.Name}}", "--description", "VulnVerdict appliance ${var.vv_version}. Cut the noise. Know your risk."]
  ]
}

build {
  sources = ["source.virtualbox-iso.vulnverdict"]

  provisioner "file" {
    source      = "../docker-compose.yml"
    destination = "/tmp/docker-compose.yml"
  }
  provisioner "file" {
    source      = "../Caddyfile"
    destination = "/tmp/Caddyfile"
  }
  provisioner "file" {
    source      = "../update.sh"
    destination = "/tmp/update.sh"
  }
  provisioner "file" {
    source      = "../rollback.sh"
    destination = "/tmp/rollback.sh"
  }
  provisioner "file" {
    source      = "firstboot.sh"
    destination = "/tmp/firstboot.sh"
  }
  provisioner "shell" {
    execute_command = "echo vulnverdict | sudo -S bash -c '{{ .Vars }} {{ .Path }}'"
    inline = [
      "set -e",
      "apt-get update && apt-get install -y ca-certificates curl gnupg",
      "install -m 0755 -d /etc/apt/keyrings",
      "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg",
      "echo \"deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu noble stable\" > /etc/apt/sources.list.d/docker.list",
      "apt-get update && apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin",
      "mkdir -p /opt/vulnverdict && mv /tmp/docker-compose.yml /tmp/Caddyfile /tmp/update.sh /tmp/rollback.sh /opt/vulnverdict/ && chmod +x /opt/vulnverdict/*.sh",
      "printf 'DB_PASSWORD=%s\\nVV_HOSTNAME=vulnverdict\\nVV_IMAGE=%s\\nCVE_MIN_YEAR=0\\n' \"$(head -c 32 /dev/urandom | base64 | tr -d '/+=')\" \"${VV_IMAGE}\" > /opt/vulnverdict/.env",
      "docker pull ${VV_IMAGE} && docker pull postgres:16-alpine && docker pull caddy:2-alpine",
      "install -m 0755 /tmp/firstboot.sh /usr/local/sbin/vulnverdict-firstboot",
      "printf '[Unit]\\nDescription=VulnVerdict first boot wizard\\nAfter=network-online.target docker.service\\nConditionPathExists=!/opt/vulnverdict/.configured\\n[Service]\\nType=oneshot\\nExecStart=/usr/local/sbin/vulnverdict-firstboot\\nStandardInput=tty\\nStandardOutput=tty\\nTTYPath=/dev/tty1\\n[Install]\\nWantedBy=multi-user.target\\n' > /etc/systemd/system/vulnverdict-firstboot.service",
      "printf '[Unit]\\nDescription=VulnVerdict stack\\nRequires=docker.service\\nAfter=docker.service\\nConditionPathExists=/opt/vulnverdict/.configured\\n[Service]\\nType=oneshot\\nRemainAfterExit=yes\\nWorkingDirectory=/opt/vulnverdict\\nExecStart=/usr/bin/docker compose up -d\\nExecStop=/usr/bin/docker compose down\\n[Install]\\nWantedBy=multi-user.target\\n' > /etc/systemd/system/vulnverdict.service",
      "systemctl enable vulnverdict-firstboot.service vulnverdict.service",
      "echo ${VV_VERSION} > /opt/vulnverdict/VERSION",
      "apt-get clean && rm -rf /var/lib/apt/lists/* && dd if=/dev/zero of=/EMPTY bs=1M || true && rm -f /EMPTY"
    ]
    environment_vars = ["VV_IMAGE=${var.vv_image}", "VV_VERSION=${var.vv_version}"]
  }
}
