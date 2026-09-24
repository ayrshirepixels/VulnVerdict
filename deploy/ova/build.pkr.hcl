# VulnVerdict appliance build with HashiCorp Packer.
#
# Produces an Ubuntu 24.04 LTS VM with Docker and the VulnVerdict Compose stack pre-installed and a
# first-boot wizard for hostname and password, packaged as an OVA for VMware and VirtualBox (and, via a
# one-line disk conversion, Hyper-V). 2 vCPU, 4 GB RAM, 40 GB disk: brief section 10.1.
#
# Two build hosts are supported; both end in the same OVA:
#   Hyper-V (Windows):  ./make-seed.sh && ./save-image.sh 1.0.0
#                       packer init . && packer build -only=hyperv-iso.vulnverdict -var vv_version=1.0.0 .
#                       ./make-ova.sh 1.0.0
#   VirtualBox:         packer init . && packer build -only=virtualbox-iso.vulnverdict -var vv_version=1.0.0 .
#                       (VirtualBox exports the OVA itself)
#
# The VM is BIOS-booted (Hyper-V generation 1) so the one disk boots unchanged in VMware, VirtualBox,
# Proxmox and Hyper-V, whose default firmware for an imported disk is BIOS.
#
# Image: if images/*.tar.gz exists (from save-image.sh) it is loaded into the VM; otherwise vv_image is
# pulled from its registry. Either way the tag must match vv_image.

packer {
  required_plugins {
    virtualbox = { version = ">= 1.0.0", source = "github.com/hashicorp/virtualbox" }
    hyperv     = { version = ">= 1.1.0", source = "github.com/hashicorp/hyperv" }
  }
}

variable "vv_version" {
  type    = string
  default = "dev"
}
variable "vv_image" {
  type        = string
  default     = ""
  description = "Image the appliance runs. Defaults to vulnverdict:<vv_version>, as tagged by save-image.sh."
}
variable "iso_url" {
  type    = string
  default = "https://releases.ubuntu.com/24.04/ubuntu-24.04.5-live-server-amd64.iso"
}
variable "iso_checksum" {
  type    = string
  default = "sha256:97f3d7ffb032c3eb3b23d2c8be9cc76e60c2c1f2c0146ba5ba9fe01cafae0fd8"
}
variable "hyperv_switch" {
  type    = string
  default = "Default Switch"
}

locals {
  image = var.vv_image != "" ? var.vv_image : "vulnverdict:${var.vv_version}"
  # Typed at the installer's GRUB prompt. The autoinstall answers come from the CIDATA seed (Hyper-V) or
  # Packer's HTTP server (VirtualBox).
  grub_hyperv = [
    "<wait3>c<wait2>",
    "linux /casper/vmlinuz autoinstall console=tty0 ---<enter><wait>",
    "initrd /casper/initrd<enter><wait>",
    "boot<enter>"
  ]
}

source "hyperv-iso" "vulnverdict" {
  iso_url              = var.iso_url
  iso_checksum         = var.iso_checksum
  generation           = 1
  cpus                 = 2
  memory               = 4096
  disk_size            = 40960
  switch_name          = var.hyperv_switch
  secondary_iso_images = ["seed/seed.iso"]
  enable_dynamic_memory = false
  headless             = true
  boot_wait            = "5s"
  boot_command         = local.grub_hyperv
  ssh_username         = "vulnverdict"
  ssh_password         = "vulnverdict" # replaced by the first-boot wizard
  ssh_timeout          = "45m"
  shutdown_command     = "echo vulnverdict | sudo -S sh -c 'rm -f /etc/ssh/ssh_host_*; shutdown -P now'"
  output_directory     = "output/hyperv-${var.vv_version}"
  vm_name              = "vulnverdict-${var.vv_version}"
}

source "virtualbox-iso" "vulnverdict" {
  guest_os_type    = "Ubuntu_64"
  iso_url          = var.iso_url
  iso_checksum     = var.iso_checksum
  cpus             = 2
  memory           = 4096
  disk_size        = 40960
  headless         = true
  http_directory   = "seed"
  boot_wait        = "5s"
  boot_command = [
    "c<wait>",
    "linux /casper/vmlinuz autoinstall ds=nocloud-net\\;s=http://{{ .HTTPIP }}:{{ .HTTPPort }}/ ---<enter><wait>",
    "initrd /casper/initrd<enter><wait>",
    "boot<enter>"
  ]
  ssh_username     = "vulnverdict"
  ssh_password     = "vulnverdict"
  ssh_timeout      = "45m"
  shutdown_command = "echo vulnverdict | sudo -S sh -c 'rm -f /etc/ssh/ssh_host_*; shutdown -P now'"
  format           = "ova"
  output_directory = "output/virtualbox-${var.vv_version}"
  vm_name          = "vulnverdict-${var.vv_version}"
  vboxmanage = [
    ["modifyvm", "{{.Name}}", "--nat-localhostreachable1", "on"],
    ["modifyvm", "{{.Name}}", "--description", "VulnVerdict appliance ${var.vv_version}. Cut the noise. Know your risk."]
  ]
}

build {
  sources = ["source.hyperv-iso.vulnverdict", "source.virtualbox-iso.vulnverdict"]

  provisioner "shell" {
    inline = ["mkdir -p /tmp/vv/images"]
  }
  provisioner "file" {
    sources = [
      "../docker-compose.yml", "../Caddyfile", "../update.sh", "../rollback.sh",
      "firstboot.sh", "appliance-setup.sh",
    ]
    destination = "/tmp/vv/"
  }
  provisioner "file" {
    source      = "images/"
    destination = "/tmp/vv/images"
  }
  provisioner "shell" {
    execute_command  = "echo vulnverdict | sudo -S env {{ .Vars }} bash '{{ .Path }}'"
    inline           = ["bash /tmp/vv/appliance-setup.sh"]
    environment_vars = ["VV_IMAGE=${local.image}", "VV_VERSION=${var.vv_version}"]
  }
}
