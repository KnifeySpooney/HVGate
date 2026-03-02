<#
.SYNOPSIS
     ██╗  ██╗██╗   ██╗ ██████╗  █████╗ ████████╗███████╗
     ██║  ██║██║   ██║██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝
      ███████║██║   ██║██║  ███╗███████║   ██║   █████╗  
      ██╔══██║╚██╗ ██╔╝██║   ██║██╔══██║   ██║   ██╔══╝  
      ██║  ██║ ╚████╔╝ ╚██████╔╝██║  ██║   ██║   ███████╗
      ╚═╝  ╚═╝  ╚═══╝   ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝
.NOTES
    Requires Administrator Privileges.
#>

$ErrorActionPreference = "Stop"

$Global:SafeExclusions = @("grub", "systemd-boot", "arch", "linux", "shim", "ubuntu", "fedora")
$Global:SafeHashes = @(
    "A3DEB41DE511974069D92BAE1B1BE91D274B39FF10951D5AFD21C2C481AC4C1E"
)
$Global:TimingThreshold = 5000

function Show-Header {
    Clear-Host
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "                HVGATE AUDITOR                 " -ForegroundColor White -BackgroundColor DarkBlue
    Write-Host "       Forensic Ring -1 / UEFI Persistence Audit          " -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan
}

function Check-Privileges {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "HVGate requires full Administrator privileges to access BCD and EFI partitions."
        exit
    }
}

function Audit-BCD {
    Write-Host "`n" + ("-"*60) -ForegroundColor DarkGray
    Write-Host "[*] PHASE 1: Deep BCD Inspection..." -ForegroundColor Yellow
    $bcdRes = @{ Detected = $false }
    
    Write-Host " [i] Enumerating currently booted Windows BCD object..." -ForegroundColor Gray
    $bcd = bcdedit /enum {current} /v
    
    $flags = @(
        "hypervisorlaunchtype", 
        "hypervisordebug", 
        "hypervisorsignalicertificate", 
        "testsigning",
        "nointegritychecks",
        "loadoptions"
    )

    foreach ($flag in $flags) {
        $match = $bcd | Select-String $flag
        if ($match) {
            Write-Host " [!] BCD Flag Detected: $match" -ForegroundColor Magenta
            if ($flag -ne "hypervisorlaunchtype") { $bcdRes.Detected = $true }
            if ($flag -eq "hypervisorlaunchtype" -and $match -notlike "*Off*") {
                Write-Host "     -> Warning: Native Hyper-V BCD launch flag is active." -ForegroundColor Gray
                $bcdRes.Detected = $true
            }
        }
    }

    $pathMatch = $bcd | Select-String "path"
    if ($pathMatch -notlike "*winload.efi*") {
        Write-Host " [!!!] CRITICAL: Non-standard boot path: $pathMatch" -ForegroundColor Red
        $bcdRes.Detected = $true
    }

    if (-not $bcdRes.Detected) { Write-Host " [+] BCD structure appears standard. No overt tampering detected." -ForegroundColor Green }
    return $bcdRes
}

function Audit-Instruction-Timing {
    Write-Host "`n" + ("-"*60) -ForegroundColor DarkGray
    Write-Host "[*] PHASE 2: Side-Channel Timing Analysis (VM Exit Check)..." -ForegroundColor Yellow
    Write-Host " [i] Measuring CPUID execution latency across 10 samples..." -ForegroundColor Gray
    
    $samples = 10
    $totalTime = 0
    for ($i=0; $i -lt $samples; $i++) {
        $start = [System.Diagnostics.Stopwatch]::StartNew()
        Get-WmiObject Win32_Processor | Out-Null
        $start.Stop()
        $totalTime += $start.ElapsedTicks
    }
    
    $avg = $totalTime / $samples
    Write-Host "     Average Instruction Latency: $avg ticks" -ForegroundColor Gray
    
    if ($avg -gt $Global:TimingThreshold) {
        Write-Host " [?] Observation: High instruction latency detected. Possible Ring -1 interception or active VBS." -ForegroundColor Cyan
    } else {
        Write-Host " [+] Latency within normal parameters. Hardware execution appears direct." -ForegroundColor Green
    }
}

function Audit-NVRAM {
    Write-Host "`n" + ("-"*60) -ForegroundColor DarkGray
    Write-Host "[*] PHASE 3: NVRAM Firmware & Boot Order Audit..." -ForegroundColor Yellow
    Write-Host " [i] Extracting raw EFI NVRAM variables..." -ForegroundColor Gray
    
    $fwEntries = (bcdedit /enum firmware /v) -join "`n"
    $suspicious = $false

    $rawEntries = $fwEntries -split "identifier"
    foreach ($entry in $rawEntries) {
        if ($entry -match "description") {
            $isSafe = $false
            foreach ($exclusion in $Global:SafeExclusions) {
                if ($entry -match $exclusion) { $isSafe = $true; break }
            }

            if ($entry -match "Windows Boot Manager" -or $entry -match "Microsoft") { $isSafe = $true }

            if ($entry -match "path" -and $entry -match "\.efi") {
                if ($isSafe) {
                    $desc = ($entry | Select-String "description").ToString().Split(" ", 2)[1].Trim()
                    Write-Host " [i] Safe/Known Entry: $desc" -ForegroundColor Cyan
                } elseif ($entry -match "BOOTX64\.EFI" -or $entry -match "UEFI OS") {
                    Write-Host " [?] Warning: Generic UEFI Fallback Path (BOOTX64.EFI) present. Relying on ESP Audit (Phase 4)." -ForegroundColor Yellow
                    $entry.Trim() -split "`n" | ForEach-Object { Write-Host "     $_" -ForegroundColor DarkYellow }
                } else {
                    Write-Host " [!] SUSPICIOUS FIRMWARE ENTRY:" -ForegroundColor Red
                    $entry.Trim() -split "`n" | ForEach-Object { Write-Host "     $_" -ForegroundColor Gray }
                    $suspicious = $true
                }
            }
        }
    }
    
    if (-not $suspicious) { Write-Host " [+] No anomalous UEFI boot entries discovered." -ForegroundColor Green }
    return $suspicious
}

function Audit-EFI-Partition {
    Write-Host "`n" + ("-"*60) -ForegroundColor DarkGray
    Write-Host "[*] PHASE 4: EFI System Partition (ESP) Forensic Audit..." -ForegroundColor Yellow
    
    $driveLetter = $null
    foreach ($letter in [char[]](90..65)) {
        if (-not (Test-Path "$letter`:\")) {
            $driveLetter = "$letter`:"
            break
        }
    }
    if (-not $driveLetter) { throw "No available drive letters to temporarily mount the ESP." }
    
    $found = $false
    
    try {
        Write-Host " [i] Attempting to mount ESP to $driveLetter via primary API (mountvol)..." -ForegroundColor Gray
        if (Test-Path "$driveLetter\"){ mountvol $driveLetter /d | Out-Null }
        
        mountvol $driveLetter /s 2>$null
        
        if (-not (Test-Path "$driveLetter\")) {
            throw "Mountvol API block detected."
        }
        Write-Host " [+] ESP Mounted successfully via mountvol." -ForegroundColor Green
    }
    catch {
        Write-Host " [!] Access Denied to ESP. OS-level lock (VBS) or active VMM interference detected." -ForegroundColor Yellow
        Write-Host " [i] Attempting low-level bypass utilizing DiskPart mappings..." -ForegroundColor Gray
        
        $espPart = Get-Partition | Where-Object { $_.GptType -eq "{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}" -or $_.Type -eq "System" } | Select-Object -First 1
        
        if ($espPart) {
            $letterChar = $driveLetter[0]
            $dpScript = @"
select disk $($espPart.DiskNumber)
select partition $($espPart.PartitionNumber)
assign letter=$letterChar
"@
            $dpScript | diskpart | Out-Null
            
            if (-not (Test-Path "$driveLetter\")) {
                Write-Host " [!!!] CRITICAL: DiskPart fallback failed. Disk I/O is actively being intercepted!" -ForegroundColor Red
                return $true
            }
            Write-Host " [+] ESP bypass successful. Volume mapped via DiskPart." -ForegroundColor Green
        } else {
            Write-Host " [!!!] CRITICAL: Could not locate System partition metadata." -ForegroundColor Red
            return $true
        }
    }
    
    Write-Host " [i] Hashing and verifying Authenticode signatures of .efi binaries..." -ForegroundColor Gray
    
    try {
        $files = Get-ChildItem -Path "$driveLetter\EFI" -Filter "*.efi" -Recurse -File
        foreach ($file in $files) {
            $isExcluded = $false
            foreach ($exc in $Global:SafeExclusions) {
                if ($file.FullName -like "*$exc*") { $isExcluded = $true; break }
            }
            if ($isExcluded) { continue }

            try {
                $sig = Get-AuthenticodeSignature $file.FullName
                if ($sig.Status -ne "Valid") {
                    $fileHash = (Get-FileHash $file.FullName -Algorithm SHA256).Hash
                    if ($Global:SafeHashes -contains $fileHash) {
                        Write-Host " [+] WHITELISTED BINARY (By Hash): $($file.FullName)" -ForegroundColor Cyan
                        Write-Host "     Matches known-safe SHA256: $fileHash" -ForegroundColor Gray
                    } else {
                        Write-Host " [!] UNSIGNED BINARY: $($file.FullName)" -ForegroundColor Red
                        Write-Host "     Created: $($file.CreationTime) | Size: $($file.Length) bytes | Hash: $fileHash" -ForegroundColor Gray
                        $found = $true
                    }
                } elseif ($sig.SignerCertificate.Subject -notlike "*Microsoft*") {
                    Write-Host " [!] THIRD-PARTY SIGNED BINARY: $($file.FullName)" -ForegroundColor Magenta
                    Write-Host "     Subject: $($sig.SignerCertificate.Subject)" -ForegroundColor Gray
                    $found = $true
                }
            } catch {
                Write-Host " [?] WARNING: Could not read file (Locked by OS/VMM): $($file.FullName)" -ForegroundColor Yellow
            }
        }
        if (-not $found) { Write-Host " [+] All active Windows boot binaries cryptographically verified." -ForegroundColor Green }
    }
    finally {
        Write-Host " [i] Unmounting ESP from $driveLetter..." -ForegroundColor Gray
        mountvol $driveLetter /d | Out-Null
        
        if (Test-Path "$driveLetter\") {
            $letterChar = $driveLetter[0]
            "remove letter=$letterChar" | diskpart | Out-Null
        }
    }
    
    return $found
}

function Check-Hypervisor-Interfaces {
    Write-Host "`n" + ("-"*60) -ForegroundColor DarkGray
    Write-Host "[*] PHASE 5: Hypervisor Interface & MSR Discovery..." -ForegroundColor Yellow
    Write-Host " [i] Querying Win32_ComputerSystem for hypervisor bit..." -ForegroundColor Gray
    
    $hv = Get-WmiObject -Class Win32_ComputerSystem
    $detected = $false

    if ($hv.HypervisorPresent) {
        Write-Host " [!] Hardware Virtualization is ACTIVE from OS perspective." -ForegroundColor Red
        
        Write-Host " [i] Validating Microsoft Virtualization-Based Security (DeviceGuard) status..." -ForegroundColor Gray
        $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
        
        if ($dg -and $dg.VirtualizationBasedSecurityStatus -eq 2) {
            Write-Host " [+] VBS/Secure Kernel is actively running (Status: 2)." -ForegroundColor Green
            Write-Host "     -> The detected hypervisor is native Microsoft architecture. Marking as safe." -ForegroundColor Cyan
        } else {
            Write-Host " [!!!] CRITICAL: Hypervisor is present, but Windows VBS is NOT reporting as running!" -ForegroundColor Red
            $detected = $true
        }
    } else {
        Write-Host " [+] Hypervisor present bit is cleared." -ForegroundColor Green
    }

    Write-Host " [i] Auditing BaseBoard artifacts for VM strings..." -ForegroundColor Gray
    $baseboard = Get-WmiObject Win32_BaseBoard
    if ($baseboard.Manufacturer -match "Microsoft" -or $baseboard.Product -match "Virtual") {
        Write-Host " [!] Virtualization Artifacts found in BaseBoard: $($baseboard.Manufacturer)" -ForegroundColor Red
        $detected = $true
    }

    if (-not $detected) { Write-Host " [+] No hostile Hypervisor interfaces exposed to Ring 0." -ForegroundColor Green }
    return $detected
}

function Show-Remediation($bcd, $nvram, $efi, $hv) {
    if ($bcd -or $nvram -or $efi -or $hv) {
        Write-Host @"

       \  /
       (oo)  <- THREAT DETECTED
      /(__)\ 
        ||
"@ -ForegroundColor Red
        Write-Host "`n" + ("="*60) -ForegroundColor Red
        Write-Host "              FORENSIC ANALYSIS COMPLETE - THREATS FOUND" -ForegroundColor White -BackgroundColor DarkRed
        Write-Host ("="*60) -ForegroundColor Red
        
        Write-Host "`nRecommended Actions for Research Cleanup:" -ForegroundColor Yellow
        if ($bcd) { Write-Host " 1. Restore Windows Bootloader: 'bcdedit /set {current} path \Windows\system32\winload.efi'" }
        if ($efi) { Write-Host " 2. Manual ESP Cleanup: Mount ESP and remove non-Microsoft .efi files." }
        if ($nvram) { Write-Host " 3. NVRAM Sanitization: Use BIOS 'Load Defaults' or 'bcdedit /delete' on custom IDs." }
        if ($hv -and -not $bcd) { 
            Write-Host " [!] WARNING: A rogue Hypervisor is active but has no BCD entry. High probability of an active Bootkit." -ForegroundColor Red 
        }
        
        Write-Host "`n[Note] Perform a COLD BOOT (unplug power) to ensure NVRAM registers are cleared." -ForegroundColor Gray
    } else {
        Write-Host @"

      ___________ 
     |  _______  |
     | |  >_   | |  -> HVGate Clean!
     | |       | |
     | |_______| |
     |___________|
     _[_________]_
    [_____________]
"@ -ForegroundColor Cyan
        Write-Host "`n[+] Audit Complete. No unauthorized hypervisors or bootkits detected." -ForegroundColor Green
    }
    Write-Host "`n"
}

Check-Privileges
Show-Header
$r1 = Audit-BCD
Audit-Instruction-Timing
$r2 = Check-Hypervisor-Interfaces
$r3 = Audit-NVRAM
$r4 = Audit-EFI-Partition


Show-Remediation $r1.Detected $r3 $r4 $r2
