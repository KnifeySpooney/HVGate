# HVGate
### Advanced Hypervisor & Bootkit Forensic Auditor
### Ring -1 / Ring 0 Persistence Detection Framework

```
  ██╗  ██╗██╗   ██╗ ██████╗  █████╗ ████████╗███████╗
  ██║  ██║██║   ██║██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝
  ███████║██║   ██║██║  ███╗███████║   ██║   █████╗
  ██╔══██║╚██╗ ██╔╝██║   ██║██╔══██║   ██║   ██╔══╝
  ██║  ██║ ╚████╔╝ ╚██████╔╝██║  ██║   ██║   ███████╗
  ╚═╝  ╚═╝  ╚═══╝   ╚═════╝ ╚═╝  ╚═╝  ╚═╝   ╚══════╝
  v2.0.0 // Ring -1 Detection // UEFI Forensics // Open Source
```

HVGate is a PowerShell-based forensic triage utility engineered to detect Ring -1 (Hypervisor) and Ring 0 (Kernel) persistence mechanisms on Windows systems. By cross-referencing CPU instruction timing, Boot Configuration Data (BCD) integrity, NVRAM firmware variables, and cryptographic signatures inside the EFI System Partition (ESP), HVGate surfaces deeply hidden anomalies indicative of an unacknowledged hypervisor or bootkit payload.

Threat families in scope include BlackLotus, CosmicStrand, MosaicRegressor, EfiGuard, and BluePill variants.

---

## Table of Contents

- [Core Capabilities](#core-capabilities)
- [Architecture Overview](#architecture-overview)
- [Installation & Prerequisites](#installation--prerequisites)
- [Execution Guide](#execution-guide)
- [Baseline Workflow](#baseline-workflow)
- [Configuration & Tuning](#configuration--tuning)
- [Architectural Edge Cases & Troubleshooting](#architectural-edge-cases--troubleshooting)
- [Disclaimer](#disclaimer)

---

## Core Capabilities

| Phase | Target | Method |
|---|---|---|
| 1 — BCD Inspection | Boot flag tampering, path hijacking | bcdedit /enum {current} with state-machine parsing |
| 2 — Timing Analysis | Hidden hypervisor VM-Exit overhead | x64 RDTSC/CPUID shellcode, 20-sample P25 statistics |
| 3 — NVRAM Audit | Rogue pre-boot EFI applications | bcdedit /enum firmware state-machine parser |
| 4 — ESP Audit | Unsigned/malicious EFI binaries | Authenticode validation + SHA-256 safelist matching |
| 5 — HV Interface | Unauthorized Ring -1 presence | HypervisorPresent bit cross-referenced against VBS/DeviceGuard |

---

## Architecture Overview

### Phase 1: BCD Inspection

Enumerates the active BCD object and validates boot integrity. Flags any of the following as anomalous:

- `nointegritychecks` — kernel integrity checks disabled; any unsigned code can run at Ring 0
- `testsigning` — unsigned kernel drivers permitted to load
- `hypervisordebug` — hypervisor debug mode active
- `hypervisorsignalicertificate` — custom hypervisor signing certificate override
- `loadoptions` — custom kernel load options; reviewed for injection strings
- Non-standard `path` value deviating from `\Windows\System32\winload.efi`

`hypervisorlaunchtype=Auto` is correlated with Phase 5 VBS results before flagging.

bcdedit is invoked with a 15-second job timeout. A hung bcdedit call is itself treated as an anomaly.

### Phase 2: CPU Timing Side-Channel

Detects hypervisor presence via CPUID intercept latency — without relying on the OS to self-report.

**How it works:** When a hypervisor intercepts a CPUID instruction, the CPU must exit guest mode, transfer execution to the VMM, and return. This VM-Exit introduces measurable latency. HVGate allocates executable memory, writes a raw x64 shellcode payload, and measures the RDTSC delta across CPUID execution:

```
RDTSC  ->  save t1  ->  CPUID (Leaf 1, forces VM-Exit)  ->  RDTSC  ->  delta = t2 - t1
```

Memory is allocated RW then transitioned to RX via VirtualProtect, avoiding PAGE_EXECUTE_READWRITE which triggers EDR heuristics. 20 samples are collected; the 25th percentile is used as the representative metric to filter SMM/NMI jitter.

**Secondary signal:** Unnaturally low timing variance is also flagged. Bare-metal systems exhibit natural jitter from hardware interrupts. Artificially consistent timing is a hypervisor spoofing fingerprint.

If ACG (Arbitrary Code Guard) blocks dynamic code allocation, Phase 2 gracefully degrades to a Stopwatch fallback and reports reduced precision.

### Phase 3: NVRAM Firmware Audit

Enumerates all EFI applications registered in motherboard NVRAM via `bcdedit /enum firmware`. These entries execute before the Windows Boot Manager and are a primary persistence vector for UEFI bootkits.

Output is parsed with a line-by-line state-machine parser — not string splitting — to produce structured objects safe for exact matching and classification. Entries are classified as Microsoft, known third-party (GRUB, systemd-boot, shim, etc.), generic UEFI fallback (BOOTX64.EFI), or unrecognized/suspicious.

### Phase 4: ESP Forensic Audit

Dynamically mounts the hidden EFI System Partition and iterates all `.efi` binaries under `\EFI\`.

Mount strategy:
1. `mountvol /s` — primary method
2. If blocked (VBS/Memory Integrity locks the ESP even under SYSTEM), falls back to DiskPart assignment via GPT type GUID `{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}`
3. Post-mount validation confirms `\EFI\` directory presence before proceeding — misdirected mounts are rejected

Each binary is evaluated:

- **Valid Microsoft signature** — clean
- **Valid third-party signature** — flagged for review
- **Unsigned, hash in safelist** — clean (see Baseline Workflow)
- **Unsigned, not in safelist** — flagged as suspicious
- **Non-PE / UnknownError** — flagged as highly suspicious; non-executable files in the ESP are anomalous

Exclusions are applied to the *directory path* only, not the filename, to prevent a bootkit named `grub_payload.efi` from escaping detection.

The ESP is always unmounted in a `finally` block with explicit success validation.

### Phase 5: Hypervisor Interface Discovery

Queries the OS hypervisor-present bit (CPUID Leaf 1 ECX bit 31) via `Win32_ComputerSystem.HypervisorPresent`.

Critically, a detected hypervisor is **cross-referenced against Windows VBS** (`Win32_DeviceGuard.VirtualizationBasedSecurityStatus`) before raising an alert:

- `VBS Status = 2` (running) → hypervisor attributed to Microsoft Secure Kernel; not flagged
- `VBS Status != 2` with hypervisor present → **CRITICAL** — unauthorized Ring -1 presence

BaseBoard manufacturer strings are checked for VM artifacts, but only raised as an additional signal when the hypervisor cannot be explained by VBS — preventing false positives on Hyper-V hosts, Azure VMs, and developer machines.

---

## Installation & Prerequisites

**Operating System:** Windows 10 / 11 (64-bit)

**PowerShell:** 5.1 or later. The script is fully compatible with Windows PowerShell 5.1 — no PowerShell 7 dependency.

**Permissions:** Full Administrator privileges required. HVGate accesses low-level volume managers, NVRAM, the BCD registry hive, and the EFI System Partition.

```powershell
git clone https://github.com/KnifeySpooney/HVGate.git
cd HVGate
```

No additional dependencies. No modules to install.

---

## Execution Guide

Windows restricts unsigned PowerShell script execution by default. To run HVGate without permanently modifying system policy:

**1. Open PowerShell as Administrator**

**2. Navigate to the repository directory**

**3. Temporarily bypass execution policy for the current session only:**
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
```
This applies only to the current process and reverts automatically when the window closes.

**4. Run HVGate:**
```powershell
.\HVGate.ps1
```

**5. Optional — Baseline mode (see below):**
```powershell
.\HVGate.ps1 -Baseline
```

---

## Baseline Workflow

HVGate supports a two-phase operational model for environments where unsigned but legitimate EFI binaries are present (GRUB, shim, third-party firmware tools, etc.).

### Step 1 — Baseline a known-clean system

On a system you trust, run:

```powershell
.\HVGate.ps1 -Baseline
```

HVGate will mount the ESP, SHA-256 hash every EFI binary, and write the results to `hvgate_safelist.json` in the script directory. The file includes a timestamp and the hostname of the baseline machine for provenance.

```json
{
  "BaselinedAt": "2026-03-07 21:00:00",
  "BaselinedHost": "WORKSTATION-01",
  "SafeHashes": [ "a3deb41d...", "..." ],
  "BaselinedFiles": [ "Z:\\EFI\\Microsoft\\Boot\\bootmgfw.efi", "..." ]
}
```

### Step 2 — Audit suspect machines

Copy `hvgate_safelist.json` alongside `HVGate.ps1` on the target machine and run normally. HVGate automatically loads the safelist and uses it during Phase 4 hash validation.

If no `hvgate_safelist.json` is present, HVGate falls back to the embedded minimal hash array and logs an advisory notice.

> **Security note:** Keep `hvgate_safelist.json` on separate read-only media. An attacker with write access to the script directory could poison the safelist. A detached hash stored separately provides tamper detection.

---

## Configuration & Tuning

All tuning variables are defined in `$Script:Config` at the top of the script.

### `$Script:Config.TimingThreshold`

CPU tick threshold for Phase 2 hypervisor timing detection.

**Default:** `5000`

Modern Intel CPUs with Efficiency cores (E-cores) or aggressive power management may naturally exceed this threshold on clean systems. If Phase 2 produces false positives on known-clean hardware, increase this value. To establish the correct baseline for your microarchitecture, run HVGate on a trusted system and observe the reported P25 value.

```powershell
$Script:Config.TimingThreshold = 8000  # Example for E-core systems
```

### `$Script:Config.TimingSamples`

Number of RDTSC/CPUID timing samples collected in Phase 2.

**Default:** `20`

More samples improve statistical reliability at the cost of a slightly longer Phase 2 runtime.

### `$Script:SafeExclusions`

Array of strings matched against EFI entry directory paths and NVRAM descriptions to exclude known-legitimate third-party boot managers from alerting.

**Default:** `@("grub", "systemd-boot", "arch", "linux", "shim", "ubuntu", "fedora", "opensuse", "debian", "refind")`

Note: Exclusions are matched against the **directory path component only**, not filenames. A binary named `grub_implant.efi` in a Microsoft directory will not be excluded.

### `$Script:FallbackSafeHashes`

Minimal embedded SHA-256 hash safelist used when no `hvgate_safelist.json` is present. For operational deployments, generate a proper safelist using `-Baseline` mode rather than maintaining this array manually.

---

## Architectural Edge Cases & Troubleshooting

### 1. Phase 2 false positive on clean hardware (high P25 timing)

**Symptom:** Phase 2 flags elevated CPUID latency on a system with no hypervisor.

**Explanation:** Timing is microarchitecture-dependent. Intel E-cores, power-saving states (C-states), and SMM interrupt frequency all affect baseline RDTSC measurements. VBS/Memory Integrity also adds legitimate hypervisor overhead of approximately 500–1500 ticks.

**Resolution:** Run on a known-clean system and note the reported P25 value. Set `$Script:Config.TimingThreshold` above that value with a reasonable margin. A threshold of 8000–12000 is appropriate for many modern systems with VBS enabled.

### 2. Phase 2 ACG fallback

**Symptom:** Phase 2 reports `Shellcode execution failed` and falls back to Stopwatch timing.

**Explanation:** Arbitrary Code Guard (ACG) is enforced process-wide on some hardened configurations, blocking VirtualAlloc/VirtualProtect for executable memory even from Administrator context.

**Resolution:** No action required. The Stopwatch fallback runs automatically. Results will be less forensically precise — rely on Phase 5 HypervisorPresent correlation for definitive Ring -1 assessment on ACG-enforced systems.

### 3. ESP mount "Access Denied" / VBS lock

**Symptom:** Phase 4 logs a mountvol failure and falls back to DiskPart.

**Explanation:** When VBS or Memory Integrity is active, the Secure Kernel places a lock on the ESP that rejects `mountvol /s` even under SYSTEM authority. This is a Windows security feature, not an error.

**Resolution:** No action required. HVGate automatically attempts DiskPart assignment via GPT type GUID as a fallback. If both methods fail, repeated failure to access the ESP is itself flagged as a potential VMM interference signal.

### 4. BOOTX64.EFI flagged in Phase 4

**Symptom:** Phase 4 reports `\EFI\BOOT\BOOTX64.EFI` as unsigned or third-party signed.

**Explanation:** Per the UEFI specification, `BOOTX64.EFI` is the universal fallback boot path. Linux distributions frequently place unsigned GRUB2 or shim here. It is also the primary drop location for UEFI threats like BlackLotus.

**Resolution:** Do not blindly whitelist by filename. Verify by hash:
```powershell
Get-FileHash "Z:\EFI\BOOT\BOOTX64.EFI" -Algorithm SHA256
```
If the hash is expected, add it to `hvgate_safelist.json` via `-Baseline` mode or append manually.

### 5. BCD file read lock in Phase 4

**Symptom:** Phase 4 logs `Could not read file (Locked by OS/VMM): Z:\EFI\Microsoft\Boot\BCD`

**Explanation:** The BCD store is a binary registry hive. The Windows Configuration Manager (ntoskrnl.exe) holds a mandatory kernel-level lock at runtime. This is normal system behaviour.

**Resolution:** No action required. HVGate logs the condition and continues.

### 6. Phase 1 clean, Phase 5 detects hypervisor

**Symptom:** No suspicious BCD flags in Phase 1, but Phase 5 reports HypervisorPresent.

**Explanation:** Modern Windows enables VBS and Hyper-V via UEFI Secure Launch without writing legacy BCD flags. This is expected behaviour on Windows 11 systems with Core Isolation enabled. Phase 5 will query `Win32_DeviceGuard` and confirm or deny the Microsoft attribution automatically.

**Resolution:** If Phase 5 confirms VBS Status = 2, the result is benign. If Phase 5 cannot attribute the hypervisor to VBS, it is flagged as CRITICAL — proceed with a full system review.

---

## Disclaimer

HVGate is provided strictly for educational use, security research, and forensic triage on systems you own or have explicit written authorization to audit.

Performing remediation actions based on HVGate output — including modifying UEFI NVRAM variables, altering BCD entries, or removing files from the EFI System Partition — can render a system unbootable. Ensure you have verified backups, Windows recovery media, and adequate architectural understanding before taking any remediation steps.

The authors accept no liability for data loss, system damage, or any other consequence arising from use of this tool.

---

*HVGate is open source. Contributions, bug reports, and threat intelligence welcome.*
*https://github.com/KnifeySpooney/HVGate*
