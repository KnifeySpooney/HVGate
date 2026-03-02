# HVGate  
**Advanced Hypervisor & Bootkit Forensic Auditor**

HVGate is a PowerShell-based forensic triage utility engineered to detect **Ring -1 (Hypervisor)** and **Ring 0 (Kernel)** persistence mechanisms on Windows systems.

It targets:

- Bare-metal virtualization threats  
- Hardware-assisted DRM / Anti-Cheat bypasses (VMX / AMD-V abuse)  
- Sophisticated UEFI bootkits  

By cross-referencing OS-level virtualization metrics, CPU instruction timing, Boot Configuration Data (BCD) integrity, and cryptographic signatures inside the EFI System Partition (ESP), HVGate surfaces deeply hidden anomalies indicative of an unacknowledged hypervisor or bootkit payload.

---

## 📑 Table of Contents

- [Core Capabilities & Architecture](#-core-capabilities--architecture)  
- [Installation & Prerequisites](#-installation--prerequisites)  
- [Execution Guide](#-execution-guide)  
- [Configuration & Tuning](#-configuration--tuning)  
- [Architectural Edge Cases & Troubleshooting](#-architectural-edge-cases--troubleshooting)  
- [Disclaimer](#-disclaimer)

---

# 🔍 Core Capabilities & Architecture

HVGate executes a structured **five-phase forensic audit**, each targeting a known persistence vector used by modern bootkits such as BlackLotus, EfiGuard, and BluePill variants.

---

## Phase 1: Deep BCD Inspection

Analyzes the actively booted Windows Boot Configuration Data (BCD) object.

HVGate hunts for suspicious flags that disable kernel protections or allow unsigned code execution:

- `hypervisorlaunchtype`
- `testsigning`
- `nointegritychecks`
- `hypervisordebug`

It also verifies the bootloader path has not been hijacked from:

```
\Windows\System32\winload.efi
```

---

## Phase 2: Side-Channel Timing Analysis

Performs a timing-based hypervisor detection technique.

By measuring `CPUID` execution latency via WMI calls, HVGate detects anomalous VM Exit overhead.  

If a hidden Virtual Machine Monitor (VMM) is present, the CPU must:

1. Exit guest mode  
2. Transfer control to the hypervisor  
3. Return to the guest  

This context switching introduces measurable execution latency.

---

## Phase 3: NVRAM Firmware Audit

Parses raw UEFI firmware boot variables:

```
bcdedit /enum firmware
```

Detects rogue EFI applications registered in motherboard firmware that execute **before** Windows Boot Manager — a primary persistence mechanism for UEFI bootkits.

---

## Phase 4: ESP Forensic Audit

Dynamically mounts the hidden **EFI System Partition (ESP)**.

HVGate:

- Iterates through EFI boot paths  
- Performs WinTrust / Authenticode signature validation on `.efi` binaries  
- Flags:
  - Unsigned payloads
  - Non-Microsoft signatures
  - Suspicious boot chain alterations

This phase uncovers hidden stage-2 bootloaders.

---

## Phase 5: Hypervisor Interface Discovery

Queries Ring 0 hypervisor-present bits and maps hardware topology.

Crucially, HVGate cross-references these results with Windows Virtualization-Based Security (VBS) WMI namespaces (`Win32_DeviceGuard`) to differentiate:

- A malicious rogue hypervisor  
- Microsoft’s legitimate Secure Kernel / Core Isolation subsystem  

---

# ⚙️ Installation & Prerequisites

## Operating System
- Windows 10 (64-bit)
- Windows 11 (64-bit)

## Permissions
Full **Administrator privileges** are required.

HVGate interacts with:
- Low-level volume managers  
- WMI namespaces  
- Windows Registry BCD hive  
- EFI partitions  

These are protected by the NT Kernel.

## Clone the Repository

```bash
git clone https://github.com/yourusername/HVGate.git
cd HVGate
```

---

# 🚀 Execution Guide

Windows restricts unsigned PowerShell script execution by default.

To run HVGate without permanently weakening system security:

1. Open **PowerShell as Administrator**
2. Navigate to the repository directory
3. Temporarily bypass execution policy for the current session:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
```

This does **not** modify global system policy.

4. Execute HVGate:

```powershell
.\hvgate.ps1
```

Once the PowerShell window closes, execution policy automatically reverts.

---

# 🛠️ Configuration & Tuning

HVGate exposes tuning variables at the top of the script:

## `$Global:SafeExclusions`
Whitelist legitimate third-party bootloaders.

Example:
```powershell
@("grub", "systemd-boot", "arch", "linux", "shim")
```

---

## `$Global:SafeHashes`
Array of SHA-256 hashes used to cryptographically whitelist known-good unsigned bootloaders.

This prevents false positives without disabling detection logic.

---

## `$Global:TimingThreshold`
CPU tick latency threshold used in Phase 2.

Default:
```
5000
```

Adjust based on host microarchitecture.

---

# ⚠️ Architectural Edge Cases & Troubleshooting

---

## 1. UEFI Fallback Path (BOOTX64.EFI) False Positive

**Symptom**  
Phase 4 flags:
```
\EFI\BOOT\BOOTX64.EFI
```
as unsigned.

**Explanation**  
Per the UEFI specification, this is the fallback boot path. Linux distributions frequently place unsigned GRUB here.

However, it is also the primary drop location for UEFI threats like BlackLotus.

**Resolution**  
Do not blindly whitelist by filename.

Instead:

```powershell
Get-FileHash <path-to-bootx64.efi> -Algorithm SHA256
```

Add the resulting hash to `$Global:SafeHashes`.

---

## 2. High CPU Latency (Phase 2 Variations)

**Symptom**  
Phase 2 flags high instruction latency on a clean system.

**Explanation**  
Instruction timing is hardware-dependent.  

Modern Intel CPUs may schedule on low-power Efficiency cores (E-cores), naturally exceeding 5000 ticks.

**Resolution**  
Increase `$Global:TimingThreshold` to establish a correct baseline for your architecture.

---

## 3. ESP Mount "Access Denied"

**Symptom**  
Phase 4 reports Access Denied but later succeeds.

**Explanation**  
When VBS or Memory Integrity is active, the Secure Kernel locks the ESP. Standard `mountvol` calls fail even under SYSTEM authority.

HVGate automatically falls back to DiskPart volume assignment.

No action required.

---

## 4. BCD File Read Lock Warning

**Symptom**
```
Could not read file (Locked by OS/VMM):
Z:\EFI\Microsoft\Boot\BCD
```

**Explanation**  
BCD is a binary Registry Hive. The Windows Configuration Manager (`ntoskrnl.exe`) places a mandatory kernel-level lock during runtime.

HVGate logs the condition and continues safely.

No action required.

---

## 5. Invisible Hypervisor / VBS Detection

**Symptom**  
Phase 1 shows no hypervisor BCD flags, but Phase 5 detects a hypervisor.

**Explanation**  
Modern Windows enables VBS via UEFI Secure Launch, bypassing legacy BCD flags.

HVGate queries `Win32_DeviceGuard`.

If:
```
Status = 2
```
It correctly identifies Microsoft Secure Kernel and dismisses the alert.

---

# ⚖️ Disclaimer

HVGate is provided strictly for:

- Educational use  
- Security research  
- Forensic triage  

Modifying:

- UEFI NVRAM variables  
- BCD entries  
- EFI System Partition contents  

can render a system unbootable.

Ensure you have:

- Verified backups  
- Recovery media  
- Adequate architectural understanding  

before performing remediation.
