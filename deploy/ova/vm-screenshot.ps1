# Saves what a Hyper-V VM is showing on its console as a PNG:
#   powershell -ExecutionPolicy Bypass -File vm-screenshot.ps1 -Name vulnverdict-1.0.0 -Out shot.png
# Uses the WMI thumbnail call, so it works headless and needs only Hyper-V Administrators rights.
param([Parameter(Mandatory)] [string] $Name, [Parameter(Mandatory)] [string] $Out, [int] $Width = 1024, [int] $Height = 768)
$ErrorActionPreference = 'Stop'
$cs = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_ComputerSystem -Filter "ElementName='$Name'"
if (-not $cs) { throw "no VM called $Name" }
$svc = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_VirtualSystemManagementService
$sd = Get-CimAssociatedInstance -InputObject $cs -ResultClassName Msvm_VirtualSystemSettingData | Where-Object { $_.VirtualSystemType -eq 'Microsoft:Hyper-V:System:Realized' } | Select-Object -First 1
$r = Invoke-CimMethod -InputObject $svc -MethodName GetVirtualSystemThumbnailImage -Arguments @{ TargetSystem = $sd; WidthPixels = [uint16]$Width; HeightPixels = [uint16]$Height }
if ($r.ReturnValue -ne 0 -or -not $r.ImageData) { throw "thumbnail call failed: return $($r.ReturnValue)" }
$bytes = [byte[]]$r.ImageData
Add-Type -AssemblyName System.Drawing
$bmp = New-Object System.Drawing.Bitmap($Width, $Height, [System.Drawing.Imaging.PixelFormat]::Format16bppRgb565)
$rect = New-Object System.Drawing.Rectangle(0, 0, $Width, $Height)
$data = $bmp.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::WriteOnly, $bmp.PixelFormat)
try {
  # RGB565 is two bytes a pixel; copy row by row to respect the bitmap's stride, and never past either buffer.
  $rowBytes = $Width * 2
  for ($y = 0; $y -lt $Height; $y++) {
    $src = $y * $rowBytes
    $n = [Math]::Min($rowBytes, $bytes.Length - $src)
    if ($n -le 0) { break }
    [System.Runtime.InteropServices.Marshal]::Copy($bytes, $src, [IntPtr]::Add($data.Scan0, $y * $data.Stride), $n)
  }
} finally { $bmp.UnlockBits($data) }
$bmp.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
"saved $Out ($($bytes.Length) bytes of image data)"
