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
# The keyboard's TypeText call is unreliable on this host (a whole hostname arrived as one letter, even
# typed a character at a time), so type PS/2 scancodes like Packer does. Set 1 make codes; a break is
# the make code with the high bit set. Letters, digits and this punctuation sit on the same keys in the
# GB layout the appliance uses and in US, so the guest layout does not matter for them.
$Scan = @{
  '1'=0x02;'2'=0x03;'3'=0x04;'4'=0x05;'5'=0x06;'6'=0x07;'7'=0x08;'8'=0x09;'9'=0x0A;'0'=0x0B;'-'=0x0C;'='=0x0D
  'q'=0x10;'w'=0x11;'e'=0x12;'r'=0x13;'t'=0x14;'y'=0x15;'u'=0x16;'i'=0x17;'o'=0x18;'p'=0x19;'['=0x1A;']'=0x1B
  'a'=0x1E;'s'=0x1F;'d'=0x20;'f'=0x21;'g'=0x22;'h'=0x23;'j'=0x24;'k'=0x25;'l'=0x26;';'=0x27;"'"=0x28
  'z'=0x2C;'x'=0x2D;'c'=0x2E;'v'=0x2F;'b'=0x30;'n'=0x31;'m'=0x32;','=0x33;'.'=0x34;'/'=0x35;' '=0x39
}
$Shifted = @{ '!'='1';'$'='4';'%'='5';'^'='6';'&'='7';'*'='8';'('='9';')'='0';'_'='-';'+'='=';':'=';';'<'=',';'>'='.';'?'='/' }
function Type-Line([string] $text) {
  $codes = New-Object System.Collections.Generic.List[byte]
  foreach ($ch in $text.ToCharArray()) {
    $s = [string]$ch; $shift = $false
    if ($Shifted.ContainsKey($s)) { $s = $Shifted[$s]; $shift = $true }
    elseif ([char]::IsUpper($ch)) { $s = $s.ToLower(); $shift = $true }
    if (-not $Scan.ContainsKey($s)) { throw "no scancode for '$ch'" }
    $k = [byte]$Scan[$s]
    if ($shift) { $codes.Add([byte]0x2A) }
    $codes.Add($k); $codes.Add([byte]($k -bor 0x80))
    if ($shift) { $codes.Add([byte]0xAA) }
  }
  $codes.Add([byte]0x1C); $codes.Add([byte]0x9C)   # Enter
  # Small batches, with a pause, so the console keeps up.
  for ($i = 0; $i -lt $codes.Count; $i += 8) {
    $chunk = $codes.GetRange($i, [Math]::Min(8, $codes.Count - $i)).ToArray()
    Invoke-CimMethod -InputObject $kb -MethodName TypeScanCodes -Arguments @{ ScanCodes = $chunk } | Out-Null
    Start-Sleep -Milliseconds 60
  }
}
function Save-Shot([string] $label) {
  $file = Join-Path $shots "$label.png"
  try { & (Join-Path $here 'vm-screenshot.ps1') -Name $name -Out $file | Out-Null; "screenshot: $file" }
  catch { "screenshot failed: $($_.Exception.Message)" }
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

# 3. The console answers over HTTPS once the stack is up. curl, not Invoke-WebRequest: the .NET/schannel
#    client intermittently fails a connection made by IP address with no server name, which curl
#    (pinned to TLS 1.2) and every browser handle.
function Http([string] $url) {
  $ErrorActionPreference = 'Continue'
  $r = & curl.exe -sk -m 10 --tls-max 1.2 -w '%{http_code}' $url 2>$null
  $ErrorActionPreference = 'Stop'
  $s = ($r -join ''); if ($s.Length -lt 3) { return @{ code = 0; body = '' } }
  @{ code = [int]$s.Substring($s.Length - 3); body = $s.Substring(0, $s.Length - 3) }
}
$health = $null; $deadline = (Get-Date).AddMinutes(8)
while (-not $health -and (Get-Date) -lt $deadline) {
  Start-Sleep 10
  $h = Http "https://$ip/healthz"; if ($h.code -eq 200) { $health = 200 }
}
Pass 'console /healthz over HTTPS by IP' ($health -eq 200) "https://$ip/healthz -> $health"
$byName = & curl.exe -sk -m 10 --resolve "${HostName}:443:$ip" -o NUL -w '%{http_code}' "https://$HostName/healthz" 2>$null
Pass 'console /healthz over HTTPS by hostname' ("$byName" -eq '200') "https://$HostName/healthz -> $byName"
$setup = Http "https://$ip/setup"
Pass 'first page is the administrator setup' ($setup.body -match 'Create the local administrator account') "$($setup.code)"
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
echo "$Password" | sudo -S -p '' sh -c 'grep -c "__SET_AT_FIRST_BOOT__" /opt/vulnverdict/.env; stat -c "env-mode=%a" /opt/vulnverdict/.env; cd /opt/vulnverdict && echo "running=$(docker compose ps --status running --services | sort | tr "\n" ,)"'
'@ -replace '\$Password', $Password
# A refused login writes to stderr, which would otherwise end the script under ErrorActionPreference Stop.
$ErrorActionPreference = 'Continue'
$out = (& ssh.exe -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -o ConnectTimeout=15 "vulnverdict@$ip" $remote 2>&1 | ForEach-Object { "$_" }) -join "`n"
$ErrorActionPreference = 'Stop'
$out
Pass 'SSH works with the new password' ($out -match 'machine-id=') ''
Pass 'machine ID generated on first boot' ($out -match 'machine-id=[0-9a-f]{32}') ''
Pass 'SSH host keys generated on first boot' ($out -match 'hostkeys=[1-9]') ''
Pass 'build sudo removed' ($out -match 'nopasswd-sudo=removed') ''
Pass 'database password generated (placeholder gone)' ($out -match '(?m)^0\s*$') ''
Pass '.env readable by root only' ($out -match 'env-mode=600') ''
$running = if ($out -match 'running=([^\s]*)') { $Matches[1] } else { '' }
Pass 'stack services running' (($running -match '\bweb\b') -and ($running -match '\bworker\b') -and ($running -match '\bdb\b') -and ($running -match '\bproxy\b')) $running

# 5. Survives a reboot: the stack comes back without the wizard.
Restart-VM -Name $name -Force
$health = $null; $deadline = (Get-Date).AddMinutes(6); Start-Sleep 30
while (-not $health -and (Get-Date) -lt $deadline) {
  Start-Sleep 10
  $h = Http "https://$ip/healthz"; if ($h.code -eq 200) { $health = 200 }
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
