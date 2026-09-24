using System.Text;

namespace VulnVerdict.Core.Adapters.Windows;

/// <summary>
/// Section 9.2 step 3 (and step 5 for Hyper-V): the one PowerShell collector that runs on the target and prints a
/// single JSON object to stdout. It must work on Windows PowerShell 5.1 and PowerShell 7, reads only (registry,
/// CIM, cmdlets), needs no module that might be missing (ServerManager, WebAdministration, Hyper-V and the SMB
/// cmdlets are each guarded) and never writes to the target. Sections that fail are reported in "warnings" and the
/// rest of the document is still produced.
/// </summary>
public static class WindowsCollectorScript
{
    /// <summary>Schema version written to the "collector" property.</summary>
    public const string Version = "vulnverdict-windows/1";

    /// <summary>The script as written (comments and indentation kept for readability).</summary>
    public const string Source = """
        # VulnVerdict Windows collector. Read-only. Prints one JSON object to stdout.
        $ErrorActionPreference = 'Continue'
        $ProgressPreference = 'SilentlyContinue'
        $WarningPreference = 'SilentlyContinue'
        try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }
        function Get-VvReg($p, $n) { try { (Get-ItemProperty -Path $p -Name $n -ErrorAction Stop).$n } catch { $null } }
        function ConvertTo-VvStr($v) { if ($null -eq $v) { $null } else { [string]$v } }
        $w = @()
        $o = [ordered]@{ collector = 'vulnverdict-windows/1'; psVersion = $PSVersionTable.PSVersion.ToString(); collectedAt = (Get-Date).ToUniversalTime().ToString('o') }

        # ---- host
        $nt = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $h = [ordered]@{}
        $h.name = $env:COMPUTERNAME
        $h.domain = ConvertTo-VvStr (Get-VvReg 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'Domain')
        $os = $null
        try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch { $w += "os: $($_.Exception.Message)" }
        $h.osCaption = if ($os -and $os.Caption) { ConvertTo-VvStr $os.Caption } else { ConvertTo-VvStr (Get-VvReg $nt 'ProductName') }
        $h.editionId = ConvertTo-VvStr (Get-VvReg $nt 'EditionID')
        $h.installationType = ConvertTo-VvStr (Get-VvReg $nt 'InstallationType')
        $maj = Get-VvReg $nt 'CurrentMajorVersionNumber'; $min = Get-VvReg $nt 'CurrentMinorVersionNumber'; $bld = Get-VvReg $nt 'CurrentBuildNumber'; $ubr = Get-VvReg $nt 'UBR'
        if ($null -eq $maj) { $ev = [Environment]::OSVersion.Version; $maj = $ev.Major; $min = $ev.Minor; if (-not $bld) { $bld = $ev.Build } }
        $h.displayVersion = ConvertTo-VvStr (Get-VvReg $nt 'DisplayVersion'); if (-not $h.displayVersion) { $h.displayVersion = ConvertTo-VvStr (Get-VvReg $nt 'ReleaseId') }
        $h.osVersion = "$maj.$min.$bld"
        $h.osBuild = "$maj.$min.$bld" + $(if ($null -ne $ubr) { ".$ubr" } else { '' })
        $h.lastBoot = $null
        if ($os -and $os.LastBootUpTime) { try { $h.lastBoot = ([datetime]$os.LastBootUpTime).ToUniversalTime().ToString('o') } catch { } }
        if (-not $h.lastBoot) { try { $h.lastBoot = (Get-Date).AddSeconds(-1 * [Diagnostics.Stopwatch]::GetTimestamp() / [Diagnostics.Stopwatch]::Frequency).ToUniversalTime().ToString('o') } catch { } }
        $h.macs = @(); $h.ips = @()
        try { $h.macs = @(Get-NetAdapter -Physical -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' -and $_.MacAddress } | ForEach-Object { $_.MacAddress }) } catch { }
        try { $h.ips = @(Get-NetIPAddress -ErrorAction Stop | Where-Object { $_.AddressState -ne 'Tentative' -and $_.SuffixOrigin -ne 'Random' -and $_.IPAddress -notmatch '^(127\.|169\.254\.|fe80:|::1$)' } | ForEach-Object { $_.IPAddress -replace '%.*$', '' } | Sort-Object -Unique) } catch { }
        if ($h.macs.Count -eq 0 -and $h.ips.Count -eq 0) {
          try { Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true' -ErrorAction Stop | ForEach-Object { if ($_.MACAddress) { $h.macs += $_.MACAddress }; if ($_.IPAddress) { $h.ips += @($_.IPAddress) } } } catch { }
        }
        $pt = Get-VvReg 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions' 'ProductType'
        $h.productType = ConvertTo-VvStr $pt
        $h.isDomainController = ($pt -eq 'LanmanNT')
        $h.isHyperVHost = $false
        try { $vmms = Get-Service vmms -ErrorAction Stop; $h.isHyperVHost = ($vmms.Status -eq 'Running') } catch { }
        $o.host = $h

        # ---- hotfixes (Get-HotFix needs local admin on some builds; the run continues without them)
        $o.hotfixes = @()
        try { $o.hotfixes = @(Get-HotFix -ErrorAction Stop | ForEach-Object { [ordered]@{ id = ConvertTo-VvStr $_.HotFixID; installedOn = $(if ($_.InstalledOn) { $_.InstalledOn.ToString('yyyy-MM-dd') } else { $null }); description = ConvertTo-VvStr $_.Description } }) } catch { $w += "hotfixes: $($_.Exception.Message)" }

        # ---- installed software (both Uninstall hives)
        $sw = @()
        $is64 = [Environment]::Is64BitOperatingSystem
        foreach ($k in @{ p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; a = $(if ($is64) { 'x64' } else { 'x86' }) }, @{ p = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; a = 'x86' }) {
          try {
            Get-ChildItem $k.p -ErrorAction Stop | ForEach-Object {
              try {
                $p = Get-ItemProperty $_.PSPath -ErrorAction Stop
                $dn = ([string]$p.DisplayName).Trim()
                if ($dn -and $p.SystemComponent -ne 1) { $sw += [ordered]@{ name = $dn; version = ConvertTo-VvStr $p.DisplayVersion; publisher = ConvertTo-VvStr $p.Publisher; installDate = ConvertTo-VvStr $p.InstallDate; arch = $k.a; key = $_.PSChildName } }
              } catch { }
            }
          } catch { }
        }
        $o.software = $sw

        # ---- roles and features
        $ft = @(); $fsrc = $null
        $want = @('Web-Server', 'Web-WebServer', 'Web-DAV-Publishing', 'FS-SMB1', 'FS-SMB1-Server', 'Print-Services', 'Print-Server', 'Remote-Desktop-Services', 'RDS-RD-Server', 'Hyper-V', 'AD-Domain-Services', 'IIS-WebServer', 'IIS-WebDAV', 'SMB1Protocol', 'SMB1Protocol-Server', 'Microsoft-Hyper-V', 'Printing-Foundation-Features')
        try { Import-Module ServerManager -ErrorAction Stop; $ft = @(Get-WindowsFeature -ErrorAction Stop | Where-Object { $_.Installed -or $_.Name -in $want } | ForEach-Object { [ordered]@{ name = ConvertTo-VvStr $_.Name; displayName = ConvertTo-VvStr $_.DisplayName; installed = [bool]$_.Installed } }); $fsrc = 'ServerManager' } catch { }
        if (-not $fsrc) { try { $ft = @(Get-WindowsOptionalFeature -Online -ErrorAction Stop | Where-Object { $_.State -eq 'Enabled' -or $_.FeatureName -in $want } | ForEach-Object { [ordered]@{ name = ConvertTo-VvStr $_.FeatureName; displayName = $null; installed = ($_.State -eq 'Enabled') } }); $fsrc = 'Dism' } catch { $w += "features: $($_.Exception.Message)" } }
        $o.features = $ft
        $o.featureSource = $fsrc

        # ---- services of interest
        $o.services = @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -in @('Spooler', 'TermService', 'LanmanServer', 'W3SVC', 'WAS', 'WinRM', 'sshd', 'vmms', 'WebClient', 'NTDS', 'DNS', 'MSDTC') -or $_.Name -like 'MSSQL*' -or $_.Name -like 'SQLAgent*' } | ForEach-Object { [ordered]@{ name = ConvertTo-VvStr $_.Name; displayName = ConvertTo-VvStr $_.DisplayName; status = ConvertTo-VvStr $_.Status; startType = ConvertTo-VvStr $_.StartType } })

        # ---- SMBv1 and RDP
        $o.smb1Enabled = $null
        try { $c = Get-SmbServerConfiguration -ErrorAction Stop; $o.smb1Enabled = [bool]$c.EnableSMB1Protocol } catch { $r = Get-VvReg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1'; if ($null -ne $r) { $o.smb1Enabled = ($r -ne 0) } }
        $d = Get-VvReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
        $o.rdpEnabled = $(if ($null -eq $d) { $null } else { ($d -eq 0) })
        $n = Get-VvReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
        $o.rdpNlaRequired = $(if ($null -eq $n) { $null } else { ($n -eq 1) })

        # ---- listeners with owning process and hosted services
        $o.listeners = @()
        $pm = @{}; $sm = @{}
        Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $pm[[int]$_.Id] = $_.ProcessName }
        try { Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object { $_.ProcessId -gt 0 } | ForEach-Object { $k = [int]$_.ProcessId; if ($sm[$k]) { $sm[$k] += ',' + $_.Name } else { $sm[$k] = $_.Name } } } catch { }
        try { $o.listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Sort-Object LocalAddress, LocalPort, OwningProcess -Unique | ForEach-Object { $op = [int]$_.OwningProcess; [ordered]@{ address = ConvertTo-VvStr $_.LocalAddress; port = [int]$_.LocalPort; pid = $op; process = ConvertTo-VvStr $pm[$op]; service = ConvertTo-VvStr $sm[$op] } }) } catch { $w += "listeners: $($_.Exception.Message)" }

        # ---- IIS
        $iis = [ordered]@{ version = $null; sites = @() }
        $im = Get-VvReg 'HKLM:\SOFTWARE\Microsoft\InetStp' 'MajorVersion'
        if ($null -ne $im) {
          $iis.version = "$im." + (Get-VvReg 'HKLM:\SOFTWARE\Microsoft\InetStp' 'MinorVersion')
          $iis.versionString = ConvertTo-VvStr (Get-VvReg 'HKLM:\SOFTWARE\Microsoft\InetStp' 'VersionString')
          try { Import-Module WebAdministration -ErrorAction Stop; $iis.sites = @(Get-Website -ErrorAction Stop | ForEach-Object { [ordered]@{ name = ConvertTo-VvStr $_.name; state = ConvertTo-VvStr $_.state; bindings = @($_.bindings.Collection | ForEach-Object { "$($_.protocol)/$($_.bindingInformation)" }) } }) }
          catch { try { [xml]$x = Get-Content "$env:windir\System32\inetsrv\config\applicationHost.config" -ErrorAction Stop; $iis.sites = @($x.configuration.'system.applicationHost'.sites.site | ForEach-Object { [ordered]@{ name = ConvertTo-VvStr $_.name; state = $null; bindings = @($_.bindings.binding | ForEach-Object { "$($_.protocol)/$($_.bindingInformation)" }) } }) } catch { $w += "iis sites: $($_.Exception.Message)" } }
        }
        $o.iis = $iis

        # ---- SQL Server instances
        $sql = @()
        foreach ($root in 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server') {
          try {
            $names = Get-ItemProperty "$root\Instance Names\SQL" -ErrorAction Stop
            $names.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
              $inst = $_.Name; $id = $_.Value; $s = $null
              try { $s = Get-ItemProperty "$root\$id\Setup" -ErrorAction Stop } catch { }
              $sql += [ordered]@{ instance = $inst; id = ConvertTo-VvStr $id; version = ConvertTo-VvStr $s.Version; patchLevel = ConvertTo-VvStr $s.PatchLevel; edition = ConvertTo-VvStr $s.Edition; arch = $(if ($root -like '*WOW6432Node*') { 'x86' } else { 'x64' }) }
            }
          } catch { }
        }
        $o.sql = $sql

        # ---- .NET runtimes, SDKs and Framework
        $dn = [ordered]@{ runtimes = @(); sdks = @(); frameworks = @() }
        $dx = $null
        try { $dx = (Get-Command dotnet.exe -ErrorAction Stop).Source } catch { if (Test-Path "$env:ProgramFiles\dotnet\dotnet.exe") { $dx = "$env:ProgramFiles\dotnet\dotnet.exe" } }
        if ($dx) {
          try { $dn.runtimes = @(& $dx --list-runtimes 2>$null | ForEach-Object { if ($_ -match '^(\S+)\s+(\S+)') { [ordered]@{ name = $matches[1]; version = $matches[2] } } }) } catch { }
          try { $dn.sdks = @(& $dx --list-sdks 2>$null | ForEach-Object { if ($_ -match '^(\S+)') { $matches[1] } }) } catch { }
        }
        $ndp = 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full'
        $rel = Get-VvReg $ndp 'Release'
        if ($null -ne $rel) { $dn.frameworks += [ordered]@{ release = [int]$rel; version = ConvertTo-VvStr (Get-VvReg $ndp 'Version') } }
        try { Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -ErrorAction Stop | Where-Object { $_.PSChildName -match '^v[23]' } | ForEach-Object { $v = Get-VvReg $_.PSPath 'Version'; $i = Get-VvReg $_.PSPath 'Install'; if ($i -eq 1 -and $v) { $dn.frameworks += [ordered]@{ release = $null; version = ConvertTo-VvStr $v } } } } catch { }
        $o.dotnet = $dn

        # ---- Hyper-V (the VM list is the coverage reconciliation set)
        $hv = [ordered]@{ vms = @() }
        if ($h.isHyperVHost) {
          try {
            Import-Module Hyper-V -ErrorAction Stop
            $hv.vms = @(Get-VM -ErrorAction Stop | ForEach-Object {
              $v = $_; $na = @()
              try { $na = @(Get-VMNetworkAdapter -VM $v -ErrorAction Stop) } catch { }
              [ordered]@{ name = ConvertTo-VvStr $v.Name; state = ConvertTo-VvStr $v.State; generation = $v.Generation; macs = @($na | ForEach-Object { $_.MacAddress } | Where-Object { $_ }); ips = @($na | ForEach-Object { @($_.IPAddresses) } | Where-Object { $_ -and $_ -notmatch '^(fe80|169\.254\.|127\.)' }) }
            })
          } catch { $w += "hyperv: $($_.Exception.Message)" }
        }
        $o.hyperv = $hv

        $o.warnings = $w
        [Console]::Out.Write((ConvertTo-Json -InputObject $o -Depth 6 -Compress))
        [Console]::Out.Write("`n")
        [Console]::Out.Flush()
        """;

    /// <summary>
    /// The script with comment lines, blank lines and indentation removed. This is what goes on the wire: WinRM
    /// runs the collector as an -EncodedCommand (UTF-16LE base64) on one command line, so size matters.
    /// </summary>
    public static string Compact { get; } = BuildCompact(Source);

    /// <summary>Base64 of the compact script in UTF-16LE, as powershell.exe -EncodedCommand expects.</summary>
    public static string EncodedCommand { get; } = Encode(Compact);

    public static string Encode(string script) => Convert.ToBase64String(Encoding.Unicode.GetBytes(script));

    private static string BuildCompact(string source)
    {
        var sb = new StringBuilder(source.Length);
        foreach (var raw in source.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;
            // built-in aliases that exist on every PowerShell version; none of these tokens occur inside a string literal
            line = line.Replace("| ForEach-Object {", "| % {").Replace("| Where-Object {", "| ? {")
                       .Replace("-ErrorAction Stop", "-EA Stop").Replace("-ErrorAction SilentlyContinue", "-EA 0");
            sb.Append(line).Append('\n');
        }
        return sb.ToString();
    }
}
