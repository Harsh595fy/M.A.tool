# 🛡️ HSR Advanced Malware Analysis Sandbox

> **Multi-Platform Dynamic & Static Malware Analysis Tool**  
> Supports: Windows PE | Android APK | Linux ELF

---

> ⚠️ **WARNING:** This tool is strictly for **educational and research purposes only**.  
> Always use in an **isolated, controlled environment**. Never analyze malware on production systems.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Modules](#modules)
- [Output & Reports](#output--reports)
- [Project Structure](#project-structure)

---

## Overview

The **HSR Advanced Malware Analysis Sandbox** is a comprehensive GUI-based tool built in Python that enables security researchers to perform both **static** and **dynamic** analysis of malicious files across multiple platforms. It integrates real-time process monitoring, network traffic analysis, behavioral tracking, YARA rule scanning, and Android APK inspection — all from a single Tkinter interface.

---

## Features

### 🔍 Static Analysis
- File hash computation (MD5, SHA1, SHA256)
- PE header parsing for Windows executables
- YARA rule matching
- String extraction and suspicious keyword detection

### 📱 Android APK Analysis
- Package metadata extraction (version, SDK, main activity)
- Permission auditing against a suspicious permission list
- Component inspection (activities, services, receivers, providers)
- DEX file analysis and string extraction
- Certificate verification
- Automated risk scoring (0–100)

### 🌐 Network Monitoring
- Real-time packet capture via Scapy
- TCP/UDP connection logging
- DNS query tracking
- HTTP request detection
- Suspicious IP alerting

### 🔄 Process Monitoring
- Tracks newly spawned processes
- Detects suspicious process names and command-line patterns (e.g., `powershell`, `wscript`, `rundll32`)
- Behavioral timeline recording

### 🧠 Behavioral Analysis
- Aggregates all behavioral events (process, network, file system)
- Flags persistence attempts via known Windows registry locations
- Generates unified behavioral reports

### 🖥️ GUI Interface
- Built with Tkinter + ttk
- Tabbed configuration window
- Scrollable live log viewer
- One-click report saving

---

## Architecture

```
MalwareSandboxGUI
├── SandboxConfig          # JSON-based configuration management
├── SandboxLogger          # File + GUI-linked logging system
├── APKAnalyzer            # Android APK static analysis (Androguard)
├── StaticAnalyzer         # PE / ELF static analysis (pefile)
├── NetworkAnalyzer        # Live packet capture (Scapy)
├── ProcessMonitor         # Process tracking (psutil)
├── BehavioralAnalyzer     # Behavioral event aggregation
└── FileSystemWatcher      # File change monitoring (Watchdog)
```

---

## Requirements

### Python Version
- Python 3.8+

### Core Dependencies

| Package | Purpose |
|---|---|
| `psutil` | Process monitoring |
| `watchdog` | File system event tracking |
| `scapy` | Network packet capture |
| `pefile` | Windows PE file parsing |
| `yara-python` | YARA rule scanning |
| `androguard` | Android APK analysis *(optional)* |
| `tkinter` | GUI (usually bundled with Python) |

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Harsh595fy/M.A.tool.git
cd M.A.tool
```

### 2. Install Core Dependencies

```bash
pip install psutil watchdog scapy pefile yara-python
```

### 3. Install Android Support *(Optional)*

```bash
pip install androguard
```

> If Androguard is not installed, APK analysis falls back to basic ZIP-based inspection of `AndroidManifest.xml`.

### 4. YARA Rules *(Optional)*

Place your `.yar` YARA rule files in the `rules/` directory (or update the path in config).

---

## Configuration

On first run, a `sandbox_config.json` file is auto-generated with default values. You can edit it manually or via the GUI's **Configuration** window.

### Key Configuration Options

| Key | Default | Description |
|---|---|---|
| `monitor_dir` | `~/sandbox` | Directory to watch for file changes |
| `network_monitoring` | `true` | Enable/disable network capture |
| `process_monitoring` | `true` | Enable/disable process tracking |
| `yara_rules_path` | `rules/` | Path to YARA rule files |
| `virustotal_api_key` | `""` | VirusTotal API key for hash lookups |
| `timeout_seconds` | `300` | Max execution time for sample runs |
| `suspicious_ips` | *(list)* | Known malicious IPs to alert on |
| `suspicious_processes` | *(list)* | Process names to flag |
| `android_suspicious_permissions` | *(list)* | Dangerous Android permissions |
| `android_suspicious_components` | *(list)* | Dangerous Android component names |

### Default Suspicious Processes
`powershell`, `cmd`, `wscript`, `cscript`, `regsvr32`, `rundll32`, `mshta`, `wmic`

### Default Monitored Persistence Locations
- `Software\Microsoft\Windows\CurrentVersion\Run`
- `Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `Software\Microsoft\Windows\CurrentVersion\Policies`
- `Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved`

---

## Usage

### Launch the GUI

```bash
python malwer_anylizer_tool.py
```

### Analyzing a Sample

1. Open the application.
2. Use the **File** menu or browse button to load a sample (`.exe`, `.apk`, `.elf`, etc.).
3. Click **Start Monitors** to begin dynamic monitoring.
4. Optionally click **Execute Sample** to run the file inside the sandbox.
5. View live logs in the scrollable log panel.
6. Click **Save Reports** to export all analysis results.

### Analyzing an APK

1. Navigate to the **APK Analysis** tab.
2. Browse and select an `.apk` file.
3. Click **Analyze APK** — results appear in the output panel.
4. Save the APK report (both `.txt` and `.json` formats are generated).

---

## Modules

### `SandboxConfig`
Loads and persists configuration from `sandbox_config.json`. Provides `get()` and `set()` methods for runtime updates.

### `SandboxLogger`
Dual-output logger: writes to `sandbox.log` and optionally streams to the GUI log panel via a registered callback.

### `APKAnalyzer`
Performs deep static analysis of Android APK files using Androguard. Falls back to ZIP-based inspection when Androguard is unavailable. Outputs a risk score from 0–100 based on suspicious permissions, components, and string patterns.

### `NetworkAnalyzer`
Captures live network traffic using Scapy. Logs TCP/UDP connections, DNS queries, HTTP request headers, and flags connections to known suspicious IPs.

### `ProcessMonitor`
Uses `psutil` to baseline the running process list at startup and continuously detect newly spawned processes. Flags processes matching known suspicious name patterns.

### `BehavioralAnalyzer`
Aggregates behavioral events from all monitors into a unified timeline. Generates a structured report of all observed behaviors during the analysis session.

---

## Output & Reports

All reports are saved to an `analysis_results/` subdirectory alongside the analyzed sample.

| Report File | Contents |
|---|---|
| `static_analysis.txt` | PE/ELF static analysis results |
| `network_activity.txt` | Connections, DNS queries, HTTP requests |
| `process_activity.txt` | Spawned processes and command lines |
| `behavioral_analysis.txt` | Aggregated behavioral event timeline |
| `apk_analysis_report.txt` | Full APK analysis (human-readable) |
| `apk_analysis_report.json` | Full APK analysis (machine-readable) |
| `sandbox.log` | Complete debug/info/warning log |

---

## Project Structure

```
hsr-malware-sandbox/
├── malwer_anylizer_tool.py    # Main application file
├── sandbox_config.json        # Auto-generated configuration
├── sandbox.log                # Runtime log output
├── rules/                     # YARA rule files (.yar)
└── <sample_dir>/
    └── analysis_results/      # Per-sample output reports
```

---

## License

This project is intended for **research and educational use only**. Use responsibly and only on systems and files you have explicit permission to analyze.
