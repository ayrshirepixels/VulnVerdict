# Types on a Hyper-V VM's console with PS/2 scancodes (the keyboard's TypeText call drops characters):
#   powershell -ExecutionPolicy Bypass -File vm-type.ps1 -Name vulnverdict-1.0.0 -Text 'systemctl list-jobs{ENTER}'
# Tokens: {ENTER} {TAB} {CTRL-ALT-F2} {CTRL-ALT-F1} {CTRL-C} {WAIT} (pauses a second). Letters, digits and
# this punctuation sit on the same keys in GB and US layouts: - = [ ] ; ' , . / and their shifted forms.
param([Parameter(Mandatory)] [string] $Name, [Parameter(Mandatory)] [string] $Text)
$ErrorActionPreference = 'Stop'
$cs = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_ComputerSystem -Filter "ElementName='$Name'"
if (-not $cs) { throw "no VM called $Name" }
$kb = Get-CimAssociatedInstance -InputObject $cs -ResultClassName Msvm_Keyboard
$Scan = @{
  '1'=0x02;'2'=0x03;'3'=0x04;'4'=0x05;'5'=0x06;'6'=0x07;'7'=0x08;'8'=0x09;'9'=0x0A;'0'=0x0B;'-'=0x0C;'='=0x0D
  'q'=0x10;'w'=0x11;'e'=0x12;'r'=0x13;'t'=0x14;'y'=0x15;'u'=0x16;'i'=0x17;'o'=0x18;'p'=0x19;'['=0x1A;']'=0x1B
  'a'=0x1E;'s'=0x1F;'d'=0x20;'f'=0x21;'g'=0x22;'h'=0x23;'j'=0x24;'k'=0x25;'l'=0x26;';'=0x27;"'"=0x28
  'z'=0x2C;'x'=0x2D;'c'=0x2E;'v'=0x2F;'b'=0x30;'n'=0x31;'m'=0x32;','=0x33;'.'=0x34;'/'=0x35;' '=0x39
}
$Shifted = @{ '!'='1';'$'='4';'%'='5';'^'='6';'&'='7';'*'='8';'('='9';')'='0';'_'='-';'+'='=';':'=';';'<'=',';'>'='.';'?'='/';'|'='\' }
$Ctrl = 0x1D; $Alt = 0x38; $Shift = 0x2A; $Enter = 0x1C; $Tab = 0x0F
$F = @{ 'F1'=0x3B; 'F2'=0x3C; 'F3'=0x3D }
function Send([byte[]] $codes) {
  for ($i = 0; $i -lt $codes.Count; $i += 8) {
    $chunk = $codes[$i..([Math]::Min($i + 7, $codes.Count - 1))]
    Invoke-CimMethod -InputObject $kb -MethodName TypeScanCodes -Arguments @{ ScanCodes = [byte[]]$chunk } | Out-Null
    Start-Sleep -Milliseconds 60
  }
}
function Key([int] $k) { [byte[]]@([byte]$k, [byte]($k -bor 0x80)) }
function Chord([int[]] $mods, [int] $k) {
  $c = New-Object System.Collections.Generic.List[byte]
  foreach ($m in $mods) { $c.Add([byte]$m) }
  $c.Add([byte]$k); $c.Add([byte]($k -bor 0x80))
  foreach ($m in $mods) { $c.Add([byte]($m -bor 0x80)) }
  $c.ToArray()
}
# Text between tokens is sent as one continuous stream of scancodes, chunked by eight: a call that begins
# with a Shift press on its own gets the shifted character dropped, so shifted keys must not start a call.
$buf = New-Object System.Collections.Generic.List[byte]
function Flush { if ($buf.Count) { Send $buf.ToArray(); $buf.Clear() } }
$i = 0
while ($i -lt $Text.Length) {
  if ($Text[$i] -eq '{') {
    Flush
    $end = $Text.IndexOf('}', $i); $tok = $Text.Substring($i + 1, $end - $i - 1).ToUpper(); $i = $end + 1
    switch -Regex ($tok) {
      '^ENTER$'         { Send (Key $Enter); Start-Sleep -Milliseconds 300 }
      '^TAB$'           { Send (Key $Tab) }
      '^WAIT$'          { Start-Sleep -Seconds 1 }
      '^CTRL-C$'        { Send (Chord @($Ctrl) 0x2E) }
      '^CTRL-ALT-(F\d)$' { Send (Chord @($Ctrl, $Alt) $F[$Matches[1]]); Start-Sleep -Seconds 2 }
      default           { throw "unknown token {$tok}" }
    }
    continue
  }
  $ch = $Text[$i]; $i++
  $s = [string]$ch; $shift = $false
  if ($Shifted.ContainsKey($s)) { $s = $Shifted[$s]; $shift = $true }
  elseif ([char]::IsUpper($ch)) { $s = $s.ToLower(); $shift = $true }
  if (-not $Scan.ContainsKey($s)) { throw "no scancode for '$ch'" }
  if ($shift) {
    # A Shift scancode inside a TypeScanCodes stream is dropped on this host; hold Shift through the
    # keyboard's own press/release (virtual-key 16) around the letter instead.
    Flush
    Invoke-CimMethod -InputObject $kb -MethodName PressKey -Arguments @{ keyCode = 16 } | Out-Null
    Send (Key $Scan[$s])
    Invoke-CimMethod -InputObject $kb -MethodName ReleaseKey -Arguments @{ keyCode = 16 } | Out-Null
    Start-Sleep -Milliseconds 60
    continue
  }
  $buf.Add([byte]$Scan[$s]); $buf.Add([byte]($Scan[$s] -bor 0x80))
}
Flush
"typed"
