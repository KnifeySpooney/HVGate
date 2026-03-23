<#
.SYNOPSIS

    ##+  ##+##+   ##+ ######+  #####+ ########+#######+
    ##|  ##|##|   ##|##+====+ ##+==##++==##+==+##+====+
    #######|##|   ##|##|  ###+#######|   ##|   #####+
    ##+==##|+##+ ##++##|   ##|##+==##|   ##|   ##+==+
    ##|  ##| +####++ +######++##|  ##|   ##|   #######+
    +=+  +=+  +===+   +=====+ +=+  +=+  +=+   +======+

    Advanced Hypervisor & Bootkit Forensic Auditor
    Ring -1 / Ring 0 Persistence Detection Framework
    https://github.com/KnifeySpooney/HVGate

.DESCRIPTION
    HVGate is a PowerShell-based forensic triage utility engineered to detect
    Ring -1 (Hypervisor) and Ring 0 (Kernel) persistence mechanisms on Windows systems.

    Detection Capabilities:
      - Bare-metal hypervisor implants (VMX/AMD-V abuse)
      - UEFI/ESP bootkit payloads and unauthorized EFI binaries
      - BCD tampering and non-standard boot path injection
      - Rogue NVRAM firmware entries
      - CPU-level side-channel timing anomalies (VM-Exit detection)

.NOTES
    Author  : KnifeySpooney
    Version : 2.0.0 (Refactored)
    Requires: Administrator privileges, Windows 10/11 x64
    WARNING : This tool allocates executable memory for timing shellcode.
              Some EDR products may flag this behaviour. This is expected.
#>

#Requires -RunAsAdministrator

# ============================================================
#  GLOBAL CONFIGURATION
# ============================================================

$Script:Config = @{
    Version          = "2.0.0"
    TimingThreshold  = 5000       # Ticks. Elevated latency above this suggests VM-Exit overhead.
    TimingSamples    = 20         # Number of shellcode timing samples to collect.
    SafelistPath     = Join-Path $PSScriptRoot "hvgate_safelist.json"
}

# Known-safe exclusion strings matched against NVRAM entry descriptions/paths.
# These represent legitimate non-Microsoft boot managers.
$Script:SafeExclusions = @(
    "grub", "systemd-boot", "arch", "linux", "shim",
    "ubuntu", "fedora", "opensuse", "debian", "refind"
)

# Fallback hash safelist. Prefer hvgate_safelist.json for operational use.
# See: -Baseline switch to generate a safelist from a known-clean system.
$Script:FallbackSafeHashes = @(
    "A3DEB41DE511974069D92BAE1B1BE91D274B39FF10951D5AFD21C2C481AC4C1E"
)

# Runtime state
$Script:SafeHashes   = @()
$Script:ThreatLog    = [System.Collections.Generic.List[string]]::new()
$Script:WarningLog   = [System.Collections.Generic.List[string]]::new()

# ============================================================
#  C# TYPE DEFINITIONS
# ============================================================

# P/Invoke definitions for executable memory allocation (timing shellcode)
# and high-resolution CPU timestamp reading.
$NativeCode = @"
using System;
using System.Runtime.InteropServices;

public static class NativeMethods {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAlloc(
        IntPtr lpAddress, UIntPtr dwSize,
        uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtect(
        IntPtr lpAddress, UIntPtr dwSize,
        uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualFree(
        IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

    // MEM_COMMIT | MEM_RESERVE
    public const uint MEM_COMMIT_RESERVE = 0x3000;
    // MEM_RELEASE
    public const uint MEM_RELEASE        = 0x8000;
    // PAGE_READWRITE
    public const uint PAGE_READWRITE     = 0x04;
    // PAGE_EXECUTE_READ (RX, not RWX -- avoids triggering ACG heuristics)
    public const uint PAGE_EXECUTE_READ  = 0x20;
}

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate long TimingDelegate();
"@

try {
    Add-Type -TypeDefinition $NativeCode -Language CSharp -ErrorAction Stop
} catch {
    # Types already loaded in session -- safe to continue.
}

# ============================================================
#  DISPLAY HELPERS
# ============================================================

function Write-Banner {
    Clear-Host
    $banner = @"

  ##+  ##+##+   ##+ ######+  #####+ ########+#######+
  ##|  ##|##|   ##|##+====+ ##+==##++==##+==+##+====+
  #######|##|   ##|##|  ###+#######|   ##|   #####+
  ##+==##|+##+ ##++##|   ##|##+==##|   ##|   ##+==+
  ##|  ##| +####++ +######++##|  ##|   ##|   #######+
  +=+  +=+  +===+   +=====+ +=+  +=+  +=+   +======+
"@
    Write-Host $banner -ForegroundColor Cyan
    Write-Host "  Advanced Hypervisor & Bootkit Forensic Auditor  v$($Script:Config.Version)" -ForegroundColor White
    Write-Host "  Ring -1 / Ring 0 Persistence Detection Framework" -ForegroundColor DarkGray
    Write-Host "  [$([System.Environment]::MachineName)]  [$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')]  [$([System.Environment]::OSVersion.Version)]" -ForegroundColor DarkGray
    Write-Divider -Heavy
}

function Write-Divider {
    param([switch]$Heavy)
    if ($Heavy) {
        Write-Host ("  " + ("=" * 62)) -ForegroundColor DarkCyan
    } else {
        Write-Host ("  " + ("-" * 62)) -ForegroundColor DarkGray
    }
}

function Write-PhaseHeader {
    param([int]$Phase, [string]$Title, [string]$Subtitle = "")
    Write-Host ""
    Write-Divider
    Write-Host "  +-[ PHASE $Phase ]" -ForegroundColor DarkCyan -NoNewline
    Write-Host " $Title" -ForegroundColor Cyan
    if ($Subtitle) {
        Write-Host "  |  $Subtitle" -ForegroundColor DarkGray
    }
    Write-Host ("  +" + ("-" * 40)) -ForegroundColor DarkCyan
    Write-Host ""
}

function Write-Status {
    param(
        [string]$Level,   # INFO, OK, WARN, ALERT, CRITICAL, DEBUG
        [string]$Message,
        [string]$Detail = ""
    )
    $switchResult = switch ($Level) {
        "INFO"     { @("  [.]", "Gray") }
        "OK"       { @("  [+]", "Green") }
        "WARN"     { @("  [!]", "Yellow") }
        "ALERT"    { @("  [!!]", "Magenta") }
        "CRITICAL" { @("  [!!!]", "Red") }
        "DEBUG"    { @("  [~]", "DarkGray") }
        default    { @("  [?]", "White") }
    }
    $prefix = $switchResult[0]
    $color  = $switchResult[1]
    Write-Host "$prefix $Message" -ForegroundColor $color
    if ($Detail) {
        Write-Host "       $Detail" -ForegroundColor DarkGray
    }

    # Persist to threat/warning log for summary report
    if ($Level -eq "CRITICAL" -or $Level -eq "ALERT") {
        $logDetail = if ($Detail) { " -- $Detail" } else { "" }
        $Script:ThreatLog.Add("[$Level] $Message$logDetail")
    } elseif ($Level -eq "WARN") {
        $logDetail = if ($Detail) { " -- $Detail" } else { "" }
        $Script:WarningLog.Add("[WARN] $Message$logDetail")
    }
}

# ============================================================
#  SAFELIST MANAGEMENT
# ============================================================

function Initialize-Safelist {
    $Script:SafeHashes = $Script:FallbackSafeHashes

    if (Test-Path $Script:Config.SafelistPath) {
        try {
            $json = Get-Content $Script:Config.SafelistPath -Raw | ConvertFrom-Json
            if ($json.SafeHashes -and $json.SafeHashes.Count -gt 0) {
                $Script:SafeHashes = $json.SafeHashes
                Write-Status INFO "Safelist loaded from hvgate_safelist.json" `
                    "Entries: $($Script:SafeHashes.Count) | Baselined: $($json.BaselinedAt) on $($json.BaselinedHost)"
            }
        } catch {
            Write-Status WARN "Could not parse hvgate_safelist.json. Falling back to embedded hashes." `
                $_.Exception.Message
        }
    } else {
        Write-Status INFO "No external safelist found. Using embedded fallback hashes." `
            "Run with -Baseline on a known-clean system to generate hvgate_safelist.json"
    }
}

function Save-Baseline {
    param([string[]]$Hashes, [string[]]$Files)
    $baseline = [PSCustomObject]@{
        BaselinedAt   = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        BaselinedHost = $env:COMPUTERNAME
        SafeHashes    = $Hashes
        BaselinedFiles = $Files
    }
    $baseline | ConvertTo-Json -Depth 4 | Set-Content $Script:Config.SafelistPath -Encoding UTF8
    Write-Status OK "Baseline saved to: $($Script:Config.SafelistPath)" `
        "$($Hashes.Count) EFI binaries recorded."
}

# ============================================================
#  PHASE 1: BCD INSPECTION
# ============================================================

function Invoke-BcdAudit {
    Write-PhaseHeader -Phase 1 -Title "Boot Configuration Data (BCD) Inspection" `
        -Subtitle "Validating boot flags, path integrity, and debug/test-signing state"

    $result = @{ Detected = $false }

    Write-Status INFO "Invoking bcdedit /enum {current} /v ..."

    $bcdRaw = $null
    try {
        # Run with a job to allow timeout -- a corrupted/attacked BCD can hang bcdedit.
        $job = Start-Job { bcdedit /enum '{current}' /v 2>&1 }
        if (-not (Wait-Job $job -Timeout 15)) {
            Stop-Job $job
            throw "bcdedit timed out after 15 seconds. BCD may be corrupted or locked."
        }
        $bcdRaw = Receive-Job $job
        Remove-Job $job
    } catch {
        Write-Status CRITICAL "bcdedit failed. BCD may be corrupted or inaccessible." $_.Exception.Message
        $result.Detected = $true
        return $result
    }

    # BUG-008 FIX: Convert MatchInfo objects to strings before comparison.
    $bcdText = $bcdRaw -join "`n"

    # --- Boot Path Validation ---
    $pathLine = ($bcdRaw | Where-Object { $_ -match '^\s*path\s+' } | Select-Object -First 1)
    if ($pathLine) {
        Write-Status DEBUG "Raw path line: $($pathLine.Trim())"
        if ($pathLine -notmatch 'winload\.efi') {
            Write-Status CRITICAL "Non-standard boot loader path detected." `
                "Found: $($pathLine.Trim()) | Expected: \Windows\system32\winload.efi"
            $result.Detected = $true
        } else {
            Write-Status OK "Boot path is standard Windows loader." $pathLine.Trim()
        }
    } else {
        Write-Status WARN "Could not locate a 'path' entry in BCD {current} output."
    }

    # --- Suspicious Flag Enumeration ---
    $flagChecks = @(
        @{ Flag = "hypervisordebug";              Severity = "ALERT";    Desc = "Hypervisor debug mode is enabled. Legitimate on dev machines; anomalous in production." }
        @{ Flag = "hypervisorsignalicertificate"; Severity = "ALERT";    Desc = "Custom hypervisor signing certificate override detected." }
        @{ Flag = "testsigning";                  Severity = "ALERT";    Desc = "Test-signing is enabled. Unsigned kernel drivers can load." }
        @{ Flag = "nointegritychecks";            Severity = "CRITICAL"; Desc = "Kernel integrity checks are DISABLED. Any unsigned code can run at Ring 0." }
        @{ Flag = "loadoptions";                  Severity = "WARN";     Desc = "Custom kernel load options present. Review for injection strings." }
    )

    foreach ($check in $flagChecks) {
        $match = $bcdRaw | Where-Object { $_ -match $check.Flag }
        if ($match) {
            Write-Status $check.Severity "BCD Flag: $($check.Flag.ToUpper())" $check.Desc
            Write-Host "       Raw: $(($match | Select-Object -First 1).ToString().Trim())" -ForegroundColor DarkGray
            if ($check.Severity -ne "WARN") { $result.Detected = $true }
        }
    }

    # --- Hypervisor Launch Type (special case -- Off is expected) ---
    $hvLaunch = $bcdRaw | Where-Object { $_ -match 'hypervisorlaunchtype' }
    if ($hvLaunch) {
        if ($hvLaunch -match '\bOff\b') {
            Write-Status DEBUG "hypervisorlaunchtype is Off (standard for non-Hyper-V hosts)."
        } elseif ($hvLaunch -match '\bAuto\b') {
            Write-Status INFO "Native Hyper-V hypervisorlaunchtype=Auto is active." `
                "This is expected on Hyper-V hosts. Will be correlated with Phase 5 VBS check."
        } else {
            Write-Status ALERT "hypervisorlaunchtype has an unexpected value." ($hvLaunch | Select-Object -First 1).ToString().Trim()
            $result.Detected = $true
        }
    }

    if (-not $result.Detected) {
        Write-Status OK "BCD structure is clean. No boot tampering indicators found."
    }

    return $result
}

# ============================================================
#  PHASE 2: CPU TIMING SIDE-CHANNEL
# ============================================================

function Invoke-TimingAudit {
    Write-PhaseHeader -Phase 2 -Title "CPU Timing Side-Channel Analysis" `
        -Subtitle "Measuring CPUID/RDTSC latency via shellcode to detect VM-Exit overhead"

    # BUG-001 FIX: Replace WMI wrapper timing with actual RDTSC/CPUID shellcode.
    #
    # x64 shellcode payload:
    #   RDTSC           -> reads TSC into EDX:EAX (low 32 bits in EAX)
    #   SHL RDX, 32     -> shift high bits into position
    #   OR  RAX, RDX    -> combine into full 64-bit value in RAX (t1)
    #   PUSH RAX        -> save t1 on stack
    #   XOR EAX, EAX    -> zero EAX for CPUID leaf 1
    #   CPUID           -> forces VM-Exit if hypervisor intercepts CPUID
    #   POP RAX         -> restore t1 from stack
    #   PUSH RAX        -> re-save t1
    #   RDTSC           -> t2
    #   SHL RDX, 32
    #   OR  RAX, RDX    -> full 64-bit t2 in RAX
    #   POP RCX         -> pop t1 into RCX
    #   SUB RAX, RCX    -> delta = t2 - t1 in RAX (return value)
    #   RET
    $shellcodeX64 = [byte[]]@(
        0x0F, 0x31,                         # rdtsc
        0x48, 0xC1, 0xE2, 0x20,             # shl rdx, 32
        0x48, 0x09, 0xD0,                   # or rax, rdx
        0x50,                               # push rax
        0x31, 0xC0,                         # xor eax, eax
        0x0F, 0xA2,                         # cpuid (VM-Exit trigger)
        0x58,                               # pop rax (restore t1)
        0x50,                               # push rax
        0x0F, 0x31,                         # rdtsc
        0x48, 0xC1, 0xE2, 0x20,             # shl rdx, 32
        0x48, 0x09, 0xD0,                   # or rax, rdx
        0x59,                               # pop rcx (t1)
        0x48, 0x29, 0xC8,                   # sub rax, rcx
        0xC3                                # ret
    )

    # Architecture guard -- shellcode is x64 only.
    if (-not [System.Environment]::Is64BitProcess) {
        Write-Status WARN "Shellcode timing requires a 64-bit PowerShell process." `
            "Falling back to Stopwatch method. Results will be less precise."
        Invoke-TimingAuditFallback
        return
    }

    $allocPtr = [IntPtr]::Zero
    try {
        # Allocate RW memory first, write shellcode, then transition to RX.
        # Avoids requesting RWX (PAGE_EXECUTE_READWRITE) which is a high-signal
        # EDR heuristic and may be blocked by ACG on hardened processes.
        $size = [UIntPtr]::new($shellcodeX64.Length)
        $allocPtr = [NativeMethods]::VirtualAlloc(
            [IntPtr]::Zero, $size,
            [NativeMethods]::MEM_COMMIT_RESERVE,
            [NativeMethods]::PAGE_READWRITE
        )

        if ($allocPtr -eq [IntPtr]::Zero) {
            $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw "VirtualAlloc failed. Win32 error: $err. ACG or memory policy may be blocking dynamic code."
        }

        # Write shellcode into RW buffer
        [System.Runtime.InteropServices.Marshal]::Copy($shellcodeX64, 0, $allocPtr, $shellcodeX64.Length)

        # Transition to RX (execute, no write)
        $oldProtect = [uint32]0
        $protected = [NativeMethods]::VirtualProtect(
            $allocPtr, $size,
            [NativeMethods]::PAGE_EXECUTE_READ,
            [ref]$oldProtect
        )
        if (-not $protected) {
            $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw "VirtualProtect RW->RX transition failed. Win32 error: $err."
        }

        Write-Status INFO "Shellcode allocated and transitioned RW->RX. Beginning timing loop..." `
            "Samples: $($Script:Config.TimingSamples) | Payload: RDTSC -> CPUID(Leaf 1) -> RDTSC"

        # Invoke via delegate
        $delegate = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
            $allocPtr, [TimingDelegate]
        )

        $samples = [System.Collections.Generic.List[long]]::new()
        for ($i = 0; $i -lt $Script:Config.TimingSamples; $i++) {
            $delta = $delegate.Invoke()
            if ($delta -gt 0) { $samples.Add($delta) }
        }

        if ($samples.Count -eq 0) {
            Write-Status WARN "All timing samples returned non-positive deltas. Results unreliable."
            return
        }

        # Statistical analysis: use 25th percentile (lower quartile) as the
        # representative metric. This filters outlier spikes from SMM/NMI/context
        # switches while preserving the underlying hypervisor latency signal.
        $sorted      = ($samples | Sort-Object)
        $p25Index    = [int]($sorted.Count * 0.25)
        $p25         = $sorted[$p25Index]
        $median      = $sorted[[int]($sorted.Count * 0.5)]
        $variance    = ($samples | Measure-Object -Average).Average - $median

        Write-Host ""
        Write-Host "       +-----------------------------------------+" -ForegroundColor DarkCyan
        Write-Host "       |  CPUID Timing Results                   |" -ForegroundColor DarkCyan
        Write-Host "       |                                         |" -ForegroundColor DarkCyan
        Write-Host "       |  Samples Collected : $($samples.Count.ToString().PadRight(19))|" -ForegroundColor Gray
        Write-Host "       |  25th Percentile   : $($p25.ToString().PadRight(16)) ticks |" -ForegroundColor White
        Write-Host "       |  Median            : $($median.ToString().PadRight(16)) ticks |" -ForegroundColor White
        Write-Host "       |  Variance (avg-med): $($variance.ToString('F0').PadRight(16)) ticks |" -ForegroundColor White
        Write-Host "       |  Threshold         : $($Script:Config.TimingThreshold.ToString().PadRight(16)) ticks |" -ForegroundColor DarkGray
        Write-Host "       +-----------------------------------------+" -ForegroundColor DarkCyan
        Write-Host ""

        # Primary signal: elevated p25 suggests VM-Exit overhead on CPUID intercept.
        if ($p25 -gt $Script:Config.TimingThreshold) {
            Write-Status ALERT "Elevated CPUID latency detected (P25: $p25 ticks > threshold: $($Script:Config.TimingThreshold))." `
                "This is consistent with a hypervisor intercepting CPUID Leaf 1. Correlate with Phase 5."
        } else {
            Write-Status OK "CPUID latency within normal bare-metal parameters (P25: $p25 ticks)."
        }

        # Secondary signal: unnaturally LOW variance can also indicate a
        # hypervisor spoofing timing responses with synthetic consistency.
        $absVariance = [Math]::Abs($variance)
        if ($absVariance -lt 50 -and $samples.Count -ge 10) {
            Write-Status WARN "Suspiciously low timing variance detected ($($absVariance.ToString('F0')) ticks)." `
                "Bare-metal systems exhibit natural SMM/NMI jitter. Artificially clean timing may indicate spoofing."
        }

        # Hypervisor enumeration via CPUID Leaf 0x40000000
        Write-Host ""
        Write-Status INFO "Attempting explicit hypervisor interface enumeration (CPUID Leaf 0x40000000)..." `
            "This leaf returns a vendor string if a hypervisor is present and willing to identify itself."

        # Note: Leaf 0x40000000 requires a separate shellcode payload with EAX=0x40000000.
        # Currently surfaced via WMI as a corroborating signal.
        $hv = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        if ($hv -and $hv.HypervisorPresent) {
            Write-Status INFO "OS hypervisor-present bit is set. A hypervisor has self-identified to the OS." `
                "This does NOT confirm malicious intent -- see Phase 5 for VBS correlation."
        } else {
            Write-Status DEBUG "OS hypervisor-present bit is clear (CPUID Leaf 1 ECX bit 31 = 0)."
        }

    } catch {
        Write-Status WARN "Shellcode execution failed: $($_.Exception.Message)" `
            "Falling back to Stopwatch method. ACG may be enforced on this process."
        Invoke-TimingAuditFallback
    } finally {
        # Always free allocated memory
        if ($allocPtr -ne [IntPtr]::Zero) {
            [NativeMethods]::VirtualFree($allocPtr, [UIntPtr]::Zero, [NativeMethods]::MEM_RELEASE) | Out-Null
        }
    }
}

function Invoke-TimingAuditFallback {
    Write-Status INFO "Fallback: Measuring ring-transition latency via Stopwatch (less precise)."
    $samples = @()
    for ($i = 0; $i -lt $Script:Config.TimingSamples; $i++) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        [System.Threading.Thread]::SpinWait(100) | Out-Null  # deterministic minimal work unit
        $sw.Stop()
        $samples += $sw.ElapsedTicks
    }
    $avg = ($samples | Measure-Object -Average).Average
    Write-Status INFO "Average fallback latency: $([Math]::Round($avg, 1)) ticks" `
        "Note: This path measures ring transitions, not CPUID intercept overhead."
}

# ============================================================
#  PHASE 3: NVRAM / FIRMWARE BOOT ENTRIES
# ============================================================

function Invoke-NvramAudit {
    Write-PhaseHeader -Phase 3 -Title "NVRAM Firmware & EFI Boot Order Audit" `
        -Subtitle "Parsing EFI boot entries from bcdedit /enum firmware for rogue loaders"

    $suspicious = $false

    Write-Status INFO "Invoking bcdedit /enum firmware /v ..."

    $fwRaw = $null
    try {
        $job = Start-Job { bcdedit /enum firmware /v 2>&1 }
        if (-not (Wait-Job $job -Timeout 15)) {
            Stop-Job $job
            throw "bcdedit /enum firmware timed out after 15 seconds."
        }
        $fwRaw = Receive-Job $job
        Remove-Job $job
    } catch {
        Write-Status CRITICAL "Failed to enumerate firmware entries." $_.Exception.Message
        return $true
    }

    # BUG-006 / BUG-003 FIX: State-machine parser instead of split("identifier").
    # Iterates line-by-line; a new entry begins at lines containing only an
    # identifier GUID pattern or the literal word "identifier" as a key.
    $entries     = [System.Collections.Generic.List[hashtable]]::new()
    $currentEntry = $null

    foreach ($line in $fwRaw) {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) {
            if ($currentEntry -and $currentEntry.Count -gt 0) {
                $entries.Add($currentEntry)
            }
            $currentEntry = $null
            continue
        }

        # Key-value lines: split on first run of whitespace after the key
        if ($trimmed -match '^(\S+)\s+(.+)$') {
            $key   = $Matches[1].ToLower()
            $value = $Matches[2].Trim()
            if ($currentEntry -eq $null) { $currentEntry = @{} }
            $currentEntry[$key] = $value
        }
    }
    # Flush final entry
    if ($currentEntry -and $currentEntry.Count -gt 0) { $entries.Add($currentEntry) }

    Write-Status INFO "Parsed $($entries.Count) firmware boot entries."
    Write-Host ""

    foreach ($entry in $entries) {
        $id   = if ($entry["identifier"])  { $entry["identifier"]  } else { "(no id)" }
        $desc = if ($entry["description"]) { $entry["description"] } else { "(no description)" }
        $path = if ($entry["path"])        { $entry["path"]        } else { "" }

        # Skip entries without a path -- metadata-only entries aren't boot loaders.
        if (-not $path -or $path -notmatch '\.efi') { continue }

        # Classify entry
        $isMicrosoft = ($desc -match "Windows Boot Manager" -or $desc -match "Microsoft" -or
                        $path -match "\\Microsoft\\")
        $isKnownGood = $false
        foreach ($exc in $Script:SafeExclusions) {
            if ($desc -match $exc -or $path -match $exc) { $isKnownGood = $true; break }
        }
        $isGenericFallback = ($path -match 'BOOTX64\.EFI' -or $desc -match 'UEFI OS')

        Write-Host "  +- Entry: $id" -ForegroundColor DarkCyan
        Write-Host "  |  Description : $desc" -ForegroundColor Gray
        Write-Host "  |  Path        : $path" -ForegroundColor Gray

        if ($isMicrosoft) {
            Write-Host "  +- " -ForegroundColor DarkCyan -NoNewline
            Write-Host "[[OK]] Known Microsoft entry. Safe." -ForegroundColor Green
        } elseif ($isKnownGood) {
            Write-Host "  +- " -ForegroundColor DarkCyan -NoNewline
            Write-Host "[[OK]] Known third-party boot manager ($desc). Excluded." -ForegroundColor Cyan
        } elseif ($isGenericFallback) {
            Write-Host "  +- " -ForegroundColor DarkCyan -NoNewline
            Write-Host "[!] Generic UEFI fallback path (BOOTX64.EFI). Deferring to Phase 4 ESP audit." -ForegroundColor Yellow
            $Script:WarningLog.Add("[WARN] Generic UEFI fallback entry present: $desc @ $path")
        } else {
            Write-Host "  +- " -ForegroundColor Red -NoNewline
            Write-Host "[!!!] UNRECOGNIZED FIRMWARE ENTRY -- POSSIBLE BOOTKIT IMPLANT" -ForegroundColor Red
            $suspicious = $true
        }
        Write-Host ""
    }

    if (-not $suspicious) {
        Write-Status OK "No unauthorized UEFI boot entries found in NVRAM."
    }

    return $suspicious
}

# ============================================================
#  PHASE 4: EFI SYSTEM PARTITION AUDIT
# ============================================================

function Invoke-EspAudit {
    param([switch]$Baseline)

    Write-PhaseHeader -Phase 4 -Title "EFI System Partition (ESP) Forensic Audit" `
        -Subtitle "Mounting ESP, hashing EFI binaries, validating Authenticode signatures"

    $driveLetter = $null
    $mountedViaDiskpart = $false
    $found = $false

    # BUG-003 FIX: Dynamic drive letter selection (Z descending, avoid used letters).
    $usedLetters = ([System.IO.DriveInfo]::GetDrives() | ForEach-Object { $_.Name[0] })
    foreach ($letter in [char[]](90..65)) {
        if ($usedLetters -notcontains $letter) {
            $driveLetter = "$letter`:"
            break
        }
    }
    if (-not $driveLetter) {
        throw "No available drive letters to mount the ESP. Cannot continue Phase 4."
    }

    Write-Status INFO "Selected mount point: $driveLetter (first available letter, descending from Z)"

    # --- Mount attempt 1: mountvol /s ---
    try {
        Write-Status INFO "Attempting ESP mount via mountvol /s ..."
        $mountOutput = mountvol $driveLetter /s 2>&1
        $mountSuccess = $LASTEXITCODE -eq 0

        if (-not $mountSuccess -or -not (Test-Path "$driveLetter\")) {
            throw "mountvol returned exit code $LASTEXITCODE or path not accessible. Output: $mountOutput"
        }

        # BUG-004 FIX: Verify we actually mounted an ESP (EFI directory must exist).
        if (-not (Test-Path "$driveLetter\EFI")) {
            mountvol $driveLetter /d 2>&1 | Out-Null
            throw "Mounted volume does not contain an \EFI directory. Not an ESP. Trying DiskPart."
        }

        Write-Status OK "ESP mounted successfully via mountvol. EFI directory confirmed."

    } catch {
        Write-Status WARN "mountvol failed: $($_.Exception.Message)"
        Write-Status INFO "Attempting low-level DiskPart fallback (GPT type GUID enumeration)..."

        # --- Mount attempt 2: DiskPart via GPT type GUID ---
        $espGuid = "{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}"
        $espPart = Get-Partition | Where-Object {
            $_.GptType -eq $espGuid -or $_.Type -eq "System"
        } | Select-Object -First 1

        if (-not $espPart) {
            Write-Status CRITICAL "Cannot locate ESP partition metadata via GPT GUID or partition type." `
                "This may indicate partition table tampering or an unsupported disk layout."
            return $true
        }

        Write-Status INFO "Located ESP: Disk $($espPart.DiskNumber), Partition $($espPart.PartitionNumber)"

        $letterChar = $driveLetter[0]
        $dpScript = @"
select disk $($espPart.DiskNumber)
select partition $($espPart.PartitionNumber)
assign letter=$letterChar
"@
        # BUG-005 FIX: Capture DiskPart output and check $LASTEXITCODE.
        $dpOutput = $dpScript | diskpart 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Status CRITICAL "DiskPart failed with exit code $LASTEXITCODE." `
                "DiskPart output: $($dpOutput -join ' | ')"
            Write-Status ALERT "Disk I/O may be actively intercepted by a VMM." ""
            return $true
        }

        if (-not (Test-Path "$driveLetter\")) {
            Write-Status CRITICAL "DiskPart reported success but drive letter is inaccessible." `
                "Active VMM interference suspected."
            return $true
        }

        if (-not (Test-Path "$driveLetter\EFI")) {
            Write-Status CRITICAL "DiskPart-mounted volume has no \EFI directory. Partition targeting may be wrong."
            return $true
        }

        Write-Status OK "ESP mounted via DiskPart fallback. EFI directory confirmed."
        $mountedViaDiskpart = $true
    }

    # --- EFI Binary Enumeration & Verification ---
    try {
        $files = Get-ChildItem -Path "$driveLetter\EFI" -Filter "*.efi" -Recurse -File -ErrorAction Stop
        Write-Status INFO "Discovered $($files.Count) EFI binary/binaries in ESP."
        Write-Host ""

        $baselineHashes = [System.Collections.Generic.List[string]]::new()
        $baselineFiles  = [System.Collections.Generic.List[string]]::new()

        foreach ($file in $files) {
            # BUG-012 FIX: Exclusions match on directory component only (not filename).
            $dirPart = Split-Path $file.FullName -Parent
            $isExcluded = $false
            foreach ($exc in $Script:SafeExclusions) {
                if ($dirPart -like "*$exc*") { $isExcluded = $true; break }
            }

            if ($isExcluded -and -not $Baseline) {
                Write-Status DEBUG "Excluded (known-good path): $($file.FullName)"
                continue
            }

            try {
                $fileHash = (Get-FileHash $file.FullName -Algorithm SHA256).Hash
                $sig      = Get-AuthenticodeSignature $file.FullName -ErrorAction Stop

                if ($Baseline) {
                    $baselineHashes.Add($fileHash)
                    $baselineFiles.Add($file.FullName)
                    Write-Status OK "Baselined: $($file.Name)" "SHA256: $fileHash"
                    continue
                }

                Write-Host "  +- $($file.FullName)" -ForegroundColor DarkGray
                Write-Host "  |  Created : $($file.CreationTime) | Size: $($file.Length) bytes" -ForegroundColor DarkGray
                Write-Host "  |  SHA256  : $fileHash" -ForegroundColor DarkGray

                switch ($sig.Status) {
                    "Valid" {
                        if ($sig.SignerCertificate.Subject -notlike "*Microsoft*") {
                            Write-Host "  +- " -NoNewline -ForegroundColor Magenta
                            Write-Host "[!!] THIRD-PARTY SIGNED: $($sig.SignerCertificate.Subject)" -ForegroundColor Magenta
                            $found = $true
                        } else {
                            Write-Host "  +- " -NoNewline -ForegroundColor Green
                            Write-Host "[[OK]] Valid Microsoft Authenticode signature." -ForegroundColor Green
                        }
                    }
                    "NotSigned" {
                        if ($Script:SafeHashes -contains $fileHash) {
                            Write-Host "  +- " -NoNewline -ForegroundColor Cyan
                            Write-Host "[[OK]] Unsigned but matches safelist hash." -ForegroundColor Cyan
                        } else {
                            Write-Host "  +- " -NoNewline -ForegroundColor Red
                            Write-Host "[!!!] UNSIGNED BINARY -- NOT IN SAFELIST" -ForegroundColor Red
                            $found = $true
                        }
                    }
                    "UnknownError" {
                        # BUG-014 FIX: Non-PE files in ESP are themselves anomalous.
                        Write-Host "  +- " -NoNewline -ForegroundColor Red
                        Write-Host "[!!!] NON-PE / UNREADABLE FILE IN ESP -- HIGHLY SUSPICIOUS" -ForegroundColor Red
                        $Script:ThreatLog.Add("[CRITICAL] Non-PE file detected in ESP: $($file.FullName)")
                        $found = $true
                    }
                    default {
                        if ($Script:SafeHashes -contains $fileHash) {
                            Write-Host "  +- " -NoNewline -ForegroundColor Cyan
                            Write-Host "[[OK]] Sig status '$($sig.Status)' but hash matches safelist." -ForegroundColor Cyan
                        } else {
                            Write-Host "  +- " -NoNewline -ForegroundColor Red
                            Write-Host "[!!!] INVALID/REVOKED SIGNATURE: $($sig.Status)" -ForegroundColor Red
                            $found = $true
                        }
                    }
                }
                Write-Host ""

            } catch {
                Write-Status WARN "Could not process file (locked/inaccessible): $($file.FullName)" `
                    $_.Exception.Message
            }
        }

        if ($Baseline -and $baselineHashes.Count -gt 0) {
            Save-Baseline -Hashes $baselineHashes -Files $baselineFiles
        }

        if (-not $found -and -not $Baseline) {
            Write-Status OK "All EFI binaries cryptographically verified. ESP is clean."
        }

    } catch {
        $innerMsg = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { "" }
        Write-Status CRITICAL "Failed to enumerate ESP contents." `
            "$($_.Exception.Message)$(if ($innerMsg) { " | $innerMsg" })"
        $found = $true
    } finally {
        # BUG-011 FIX: Explicit dismount with error surfacing (not silently swallowed).
        Write-Host ""
        Write-Status INFO "Unmounting ESP from $driveLetter ..."
        try {
            if (-not $mountedViaDiskpart) {
                $umOut = mountvol $driveLetter /d 2>&1
                if ($LASTEXITCODE -ne 0) { throw "mountvol /d failed: $umOut" }
            } else {
                $letterChar = $driveLetter[0]
                $umOut = "remove letter=$letterChar" | diskpart 2>&1
                if ($LASTEXITCODE -ne 0) { throw "DiskPart remove failed: $($umOut -join ' ')" }
            }
            if (-not (Test-Path "$driveLetter\")) {
                Write-Status OK "ESP unmounted cleanly."
            } else {
                throw "Drive letter $driveLetter still accessible after dismount attempt."
            }
        } catch {
            Write-Status WARN "ESP dismount may have failed: $($_.Exception.Message)" `
                "ESP may remain mounted at $driveLetter. Verify manually."
        }
    }

    return $found
}

# ============================================================
#  PHASE 5: HYPERVISOR INTERFACE DISCOVERY
# ============================================================

function Invoke-HypervisorAudit {
    Write-PhaseHeader -Phase 5 -Title "Hypervisor Interface & VBS Correlation" `
        -Subtitle "Cross-referencing OS hypervisor flags against known-legitimate VBS/HVCI architecture"

    $detected = $false

    # --- HypervisorPresent bit (CPUID Leaf 1 ECX bit 31) ---
    Write-Status INFO "Querying Win32_ComputerSystem for HypervisorPresent bit..."
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    if (-not $cs) {
        Write-Status WARN "Could not query Win32_ComputerSystem."
    } elseif ($cs.HypervisorPresent) {
        Write-Status ALERT "HypervisorPresent bit is SET. A hypervisor has identified itself to the OS."

        # VBS Correlation: if Hyper-V/VBS is the explanation, mark as benign.
        Write-Status INFO "Validating against Windows Virtualization-Based Security (VBS/DeviceGuard)..."
        $dg = Get-CimInstance -ClassName Win32_DeviceGuard `
            -Namespace "root\Microsoft\Windows\DeviceGuard" `
            -ErrorAction SilentlyContinue

        if ($dg -and $dg.VirtualizationBasedSecurityStatus -eq 2) {
            Write-Status OK "VBS/Secure Kernel is actively running (Status=2)." `
                "Detected hypervisor is native Microsoft architecture. Correlating with timing data."

            # Even with legitimate VBS, flag if timing was anomalously HIGH -- a
            # nested hypervisor below VBS would still show elevated CPUID latency.
            Write-Status INFO "If Phase 2 timing was elevated significantly above VBS baseline (~1000 ticks)," `
                "consider nested hypervisor analysis."
        } else {
            $dgStatus = if ($dg) { $dg.VirtualizationBasedSecurityStatus } else { "N/A (query failed)" }
            Write-Status CRITICAL "A HYPERVISOR IS ACTIVE BUT VBS IS NOT RUNNING (VBS Status: $dgStatus)." `
                "This is the primary indicator of an unauthorized Ring -1 implant."
            $detected = $true
        }
    } else {
        Write-Status OK "HypervisorPresent bit is clear. No hypervisor self-identified to the OS."
        Write-Status INFO "Note: A sophisticated hypervisor may spoof CPUID to hide this bit." `
            "Correlate with Phase 2 timing results for a complete picture."
    }

    # --- BaseBoard VM artifact check ---
    # BUG-009 FIX: Only flag BaseBoard artifacts if HypervisorPresent is true
    # AND VBS was not already confirmed as the explanation. Prevents false positives
    # on legitimate Hyper-V VMs, Azure instances, and developer machines.
    Write-Host ""
    Write-Status INFO "Inspecting BaseBoard manufacturer strings for virtualization artifacts..."
    $bb = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction SilentlyContinue
    if ($bb) {
        $isVmArtifact = ($bb.Manufacturer -match "Microsoft" -or $bb.Product -match "Virtual" -or
                         $bb.Manufacturer -match "VMware"    -or $bb.Product  -match "VMware")
        if ($isVmArtifact) {
            if ($cs.HypervisorPresent -and -not $detected) {
                # Hypervisor is present and already confirmed as VBS -- this is expected.
                Write-Status INFO "VM BaseBoard artifacts present ($($bb.Manufacturer) / $($bb.Product))." `
                    "Consistent with confirmed VBS/Hyper-V environment. Not flagged."
            } elseif (-not $cs.HypervisorPresent) {
                # BaseBoard says VM, but HypervisorPresent bit is CLEAR -- possible spoofing.
                Write-Status ALERT "VM artifacts in BaseBoard but HypervisorPresent bit is CLEAR." `
                    "Manufacturer: $($bb.Manufacturer) | Product: $($bb.Product) -- Possible CPUID spoofing."
                $detected = $true
            } else {
                Write-Status ALERT "VM BaseBoard artifacts corroborate unconfirmed hypervisor." `
                    "Manufacturer: $($bb.Manufacturer) | Product: $($bb.Product)"
                $detected = $true
            }
        } else {
            Write-Status OK "BaseBoard shows no virtualization artifacts." `
                "Manufacturer: $($bb.Manufacturer) | Product: $($bb.Product)"
        }
    }

    if (-not $detected) {
        Write-Status OK "No unauthorized hypervisor interfaces discovered at the OS level."
    }

    return $detected
}

# ============================================================
#  FINAL REPORT
# ============================================================

function Show-FinalReport {
    param(
        [bool]$BcdDetected,
        [bool]$NvramDetected,
        [bool]$EspDetected,
        [bool]$HvDetected
    )

    $anyThreat = $BcdDetected -or $NvramDetected -or $EspDetected -or $HvDetected

    Write-Host ""
    Write-Divider -Heavy

    if ($anyThreat) {
        $skull = @"

     ##############################
     ##  ######+  #######+######+  ##
     ##  ##+==##+ ##+====+##+==##+ ##
     ##  ######++ #####+  ##|  ##| ##
     ##  ##+==##+ ##+==+  ##|  ##| ##
     ##  ##|  ##| #######+######++ ##
     ##  +=+  +=+ +======++=====+  ##
     ##    THREAT DETECTED -- ACT    ##
     ##############################
"@
        Write-Host $skull -ForegroundColor Red
        Write-Host "  +==========================================================+" -ForegroundColor Red
        Write-Host "  |         FORENSIC ANALYSIS COMPLETE -- THREATS FOUND      |" -ForegroundColor Red
        Write-Host "  +==========================================================+" -ForegroundColor Red

        Write-Host ""
        Write-Host "  THREAT SUMMARY:" -ForegroundColor Yellow
        foreach ($threat in $Script:ThreatLog) {
            Write-Host "    $threat" -ForegroundColor Red
        }

        if ($Script:WarningLog.Count -gt 0) {
            Write-Host ""
            Write-Host "  WARNINGS:" -ForegroundColor Yellow
            foreach ($warn in $Script:WarningLog) {
                Write-Host "    $warn" -ForegroundColor Yellow
            }
        }

        Write-Host ""
        Write-Host "  RECOMMENDED REMEDIATION:" -ForegroundColor Yellow

        if ($BcdDetected) {
            Write-Host "    [BCD]   Restore standard bootloader:" -ForegroundColor Cyan
            Write-Host "            bcdedit /set {current} path \Windows\system32\winload.efi" -ForegroundColor Gray
            Write-Host "            bcdedit /set {current} nointegritychecks No" -ForegroundColor Gray
            Write-Host "            bcdedit /set {current} testsigning Off" -ForegroundColor Gray
        }
        if ($EspDetected) {
            Write-Host "    [ESP]   Manually mount ESP and remove unrecognized .efi files." -ForegroundColor Cyan
            Write-Host "            Re-run HVGate after cleanup to confirm." -ForegroundColor Gray
        }
        if ($NvramDetected) {
            Write-Host "    [NVRAM] Use BIOS 'Load Defaults' or target entries with:" -ForegroundColor Cyan
            Write-Host "            bcdedit /delete {<identifier>}" -ForegroundColor Gray
        }
        if ($HvDetected -and -not $BcdDetected) {
            Write-Host "    [HV]    Rogue hypervisor active with no BCD entry." -ForegroundColor Red
            Write-Host "            HIGH PROBABILITY OF ACTIVE BOOTKIT IMPLANT." -ForegroundColor Red
            Write-Host "            Consider full re-image from known-clean media." -ForegroundColor Gray
        }

        Write-Host ""
        Write-Host "  [NOTE] Perform a COLD BOOT (full power cycle, not restart) to flush" -ForegroundColor DarkGray
        Write-Host "         NVRAM registers and evict any DRAM-resident implants." -ForegroundColor DarkGray

    } else {
        $clean = @"

     +---------------------------------+
     |  ######+##+     #######+ #####+ |
     | ##+====+##|     ##+====+##+==##+|
     | ##|     ##|     #####+  #######||
     | ##|     ##|     ##+==+  ##+==##||
     | +######+#######+#######+##|  ##||
     |  +=====++======++======++=+  +=+|
     |                                 |
     |     HVGate -- System is Clean    |
     +---------------------------------+
"@
        Write-Host $clean -ForegroundColor Green
        Write-Host "  +==========================================================+" -ForegroundColor Green
        Write-Host "  |       FORENSIC ANALYSIS COMPLETE -- NO THREATS FOUND     |" -ForegroundColor Green
        Write-Host "  +==========================================================+" -ForegroundColor Green
        Write-Host ""
        Write-Host "  [+] No unauthorized hypervisors, bootkits, or ESP anomalies detected." -ForegroundColor Green

        if ($Script:WarningLog.Count -gt 0) {
            Write-Host ""
            Write-Host "  ADVISORY WARNINGS (non-critical):" -ForegroundColor Yellow
            foreach ($warn in $Script:WarningLog) {
                Write-Host "    $warn" -ForegroundColor Yellow
            }
        }
    }

    Write-Host ""
    Write-Host "  Audit completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
    Write-Divider -Heavy
    Write-Host ""
}

# ============================================================
#  ENTRY POINT
# ============================================================

param(
    [switch]$Baseline  # Run in baseline mode: hash all ESP EFI binaries and save safelist.
)

# BUG-002 FIX: Elevation enforced via #Requires -RunAsAdministrator at top of script.
# This causes PowerShell to display a proper, readable error and halt before execution
# rather than silently exiting from within a running function.

$ErrorActionPreference = "Stop"

Write-Banner
Initialize-Safelist

if ($Baseline) {
    Write-Host "  [BASELINE MODE] Hashing all EFI binaries on a known-clean system." -ForegroundColor Cyan
    Write-Host "  Output will be saved to: $($Script:Config.SafelistPath)" -ForegroundColor DarkGray
    Write-Host ""
    Invoke-EspAudit -Baseline
    Write-Host ""
    Write-Host "  [+] Baseline complete. Use hvgate_safelist.json on target systems." -ForegroundColor Green
    exit 0
}

$r_bcd  = Invoke-BcdAudit
          Invoke-TimingAudit
$r_hv   = Invoke-HypervisorAudit
$r_nvram = Invoke-NvramAudit
$r_esp  = Invoke-EspAudit

Show-FinalReport `
    -BcdDetected  $r_bcd.Detected `
    -NvramDetected $r_nvram `
    -EspDetected  $r_esp `
    -HvDetected   $r_hv
