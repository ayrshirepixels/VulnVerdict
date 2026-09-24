# Boots a built appliance disk in Hyper-V and walks the first-boot wizard, then checks the result.
#   powershell -ExecutionPolicy Bypass -File test-hyperv.ps1 -Version 1.0.0
# Needs Windows PowerShell 5.1 with the Hyper-V module, run elevated or as a member of Hyper-V Administrators.
# Leaves nothing behind unless -Keep is given.
param(
  [Parameter(Mandatory)] [string] $Version,
  [string] $Switch = 'Default Switch',
  [string] $Password = 'Test-Appliance-2026!',
  [string] $HostName = 'vulnverdict.test',
  [switch] $Keep
)
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$disk = Join-Path $here "output\vulnverdict-$Version-hyperv.vhdx"
if (-not (Test-Path $disk)) { throw "missing $disk - run make-ova.sh $Version first" }
$name = "vulnverdict-test-$Version"
$work = Join-Path $here "output\test-$Version"
$shots = Join-Path $here "output\test-$Version-shots"
New-Item -ItemType Directory -Force $work, $shots | Out-Null
$results = [ordered]@{}
function Pass($k, $ok, $detail = '') { $results[$k] = @{ ok = [bool]$ok; detail = "$detail" }; "{0}  {1}  {2}" -f ($(if ($ok) { 'PASS' } else { 'FAIL' })), $k, $detail }

# Fresh copy of the shipped disk, so the test never alters the artefact.
Get-VM -Name $name -ErrorAction SilentlyContinue | Stop-VM -TurnOff -Force -ErrorAction SilentlyContinue
Get-VM -Name $name -ErrorAction SilentlyContinue | Remove-VM -Force
$vhd = Join-Path $work "$name.vhdx"
Copy-Item $disk $vhd -Force
New-VM -Name $name -Generation 1 -MemoryStartupBytes 4GB -VHDPath $vhd -SwitchName $Switch -Path $work | Out-Null
Set-VM -Name $name -ProcessorCount 2 -StaticMemory -AutomaticCheckpointsEnabled $false
Start-VM -Name $name

$vm = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_ComputerSystem -Filter "ElementName='$name'"
$kb = Get-CimAssociatedInstance -InputObject $vm -ResultClassName Msvm_Keyboard
function Type-Line([string] $text) {
  if ($text) { Invoke-CimMethod -InputObject $kb -MethodName TypeText -Arguments @{ asciiText = $text } | Out-Null }
  Invoke-CimMethod -InputObject $kb -MethodName TypeKey -Arguments @{ keyCode = 13 } | Out-Null
}
function Save-Shot([string] $label) {
  $svc = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_VirtualSystemManagementService
  $sd = Get-CimAssociatedInstance -InputObject $vm -ResultClassName Msvm_VirtualSystemSettingData | Where-Object { $_.VirtualSystemType -eq 'Microsoft:Hyper-V:System:Realized' }
  $w = 1024; $h = 768
  $r = Invoke-CimMethod -InputObject $svc -MethodName GetVirtualSystemThumbnailImage -Arguments @{ TargetSystem = $sd; WidthPixels = [uint16]$w; HeightPixels = [uint16]$h }
  Add-Type -AssemblyName System.Drawing
  $bmp = New-Object System.Drawing.Bitmap($w, $h, [System.Drawing.Imaging.PixelFormat]::Format16bppRgb565)
  $data = $bmp.LockBits((New-Object System.Drawing.Rectangle(0, 0, $w, $h)), 'WriteOnly', $bmp.PixelFormat)
  [System.Runtime.InteropServices.Marshal]::Copy([byte[]]$r.ImageData, 0, $data.Scan0, $r.ImageData.Length)
  $bmp.UnlockBits($data)
  $file = Join-Path $shots "$label.png"
  $bmp.Save($file, [System.Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose()
  "screenshot: $file"
}

# 1. Boots, gets an address by DHCP, and the wizard is waiting on the console.
$ip = $null; $deadline = (Get-Date).AddMinutes(6)
while (-not $ip -and (Get-Date) -lt $deadline) {
  Start-Sleep 5
  $ip = (Get-VMNetworkAdapter -VMName $name).IPAddresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -First 1
}
Pass 'boots and gets a DHCP address' $ip $ip
Start-Sleep 20
Save-Shot '1-wizard'

# 2. Answer the wizard: hostname, password twice, then Enter at the end.
Type-Line $HostName; Start-Sleep 3
Type-Line $Password; Start-Sleep 2
Type-Line $Password; Start-Sleep 5
Save-Shot '2-after-password'

# 3. The console answers over HTTPS once the stack is up.
$health = $null; $deadline = (Get-Date).AddMinutes(8)
[Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'
while (-not $health -and (Get-Date) -lt $deadline) {
  Start-Sleep 10
  try { $health = (Invoke-WebRequest -UseBasicParsing -TimeoutSec 10 "https://$ip/healthz").StatusCode } catch { }
}
Pass 'console /healthz over HTTPS' ($health -eq 200) "https://$ip/healthz -> $health"
try { $setup = Invoke-WebRequest -UseBasicParsing -TimeoutSec 15 "https://$ip/" ; Pass 'first page is the administrator setup' ($setup.Content -match 'administrator|Create') "$($setup.StatusCode)" } catch { Pass 'first page is the administrator setup' $false $_.Exception.Message }
Save-Shot '3-done'
Type-Line ''   # "Press Enter for a login prompt"

# 4. SSH is on now, with the new password; check what the wizard changed.
$askpass = Join-Path $work 'askpass.cmd'
Set-Content -Path $askpass -Value "@echo $Password" -Encoding ASCII
$env:SSH_ASKPASS = $askpass; $env:SSH_ASKPASS_REQUIRE = 'force'; $env:DISPLAY = 'x'
$remote = @'
echo "machine-id=$(cat /etc/machine-id)";
echo "hostkeys=$(ls /etc/ssh/ssh_host_*_key 2>/dev/null | wc -l)";
echo "configured=$(test -f /opt/vulnverdict/.configured && echo yes)";
echo "nopasswd-sudo=$(test -e /etc/sudoers.d/vulnverdict && echo present || echo removed)";
echo "$Password" | sudo -S -p '' sh -c 'grep -c "__SET_AT_FIRST_BOOT__" /opt/vulnverdict/.env; stat -c "env-mode=%a" /opt/vulnverdict/.env; docker compose -f /opt/vulnverdict/docker-compose.yml ps --format "{{.Service}}={{.State}}"'
'@ -replace '\$Password', $Password
$out = & ssh.exe -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -o ConnectTimeout=15 "vulnverdict@$ip" $remote 2>&1 | Out-String
$out
Pass 'SSH works with the new password' ($out -match 'machine-id=') ''
Pass 'machine ID generated on first boot' ($out -match 'machine-id=[0-9a-f]{32}') ''
Pass 'SSH host keys generated on first boot' ($out -match 'hostkeys=[1-9]') ''
Pass 'build sudo removed' ($out -match 'nopasswd-sudo=removed') ''
Pass 'database password generated (placeholder gone)' ($out -match '(?m)^0\s*$') ''
Pass '.env readable by root only' ($out -match 'env-mode=600') ''
Pass 'stack services running' (($out -match 'web=running') -and ($out -match 'worker=running') -and ($out -match 'db=running') -and ($out -match 'proxy=running')) ''

# 5. Survives a reboot: the stack comes back without the wizard.
Restart-VM -Name $name -Force
$health = $null; $deadline = (Get-Date).AddMinutes(6); Start-Sleep 30
while (-not $health -and (Get-Date) -lt $deadline) {
  Start-Sleep 10
  try { $health = (Invoke-WebRequest -UseBasicParsing -TimeoutSec 10 "https://$ip/healthz").StatusCode } catch { }
}
Pass 'console back after a reboot, no wizard' ($health -eq 200) "$health"
Save-Shot '4-after-reboot'

$results | ConvertTo-Json -Depth 3 | Set-Content (Join-Path $shots 'results.json')
if (-not $Keep) {
  Stop-VM -Name $name -TurnOff -Force; Remove-VM -Name $name -Force
  Remove-Item -Recurse -Force $work
}
$failed = @($results.Values | Where-Object { -not $_.ok }).Count
"`n$($results.Count - $failed) passed, $failed failed. Screenshots in $shots"
if ($failed) { exit 1 }
