import os
import sys
import time
import json
import logging
import threading
import subprocess
import hashlib
import shutil
import zipfile
import xml.etree.ElementTree as ET
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple

# Third-party imports
try:
    import psutil
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    from scapy.all import sniff, IP, TCP, UDP, Raw, DNS, DNSQR
    import pefile
    import yara
except ImportError as e:
    print(f"[!] Missing required module: {e}")
    print("[!] Please install required packages: pip install psutil watchdog scapy pefile yara-python")
    sys.exit(1)

# Android-specific imports
try:
    from androguard.core.bytecodes.apk import APK
    from androguard.core.bytecodes.dvm import DalvikVMFormat
    from androguard.core.analysis.analysis import Analysis
    ANDROGUARD_AVAILABLE = True
except ImportError:
    ANDROGUARD_AVAILABLE = False
    print("[!] Androguard not installed. APK analysis will be limited.")
    print("[!] Install with: pip install androguard")

# ============================================================================
# Configuration Management
# ============================================================================

class SandboxConfig:
    """Configuration management for the sandbox."""
    
    def __init__(self, config_file: str = "sandbox_config.json"):
        self.config_file = config_file
        self.config = self.load_config()
    
    def load_config(self) -> Dict:
        """Load configuration from file."""
        default_config = {
            "monitor_dir": os.path.join(os.path.expanduser("~"), "sandbox"),
            "network_monitoring": True,
            "process_monitoring": True,
            "registry_monitoring": True,
            "api_hooking": False,
            "yara_rules_path": "rules/",
            "virustotal_api_key": "",
            "timeout_seconds": 300,
            "log_level": "INFO",
            "suspicious_ips": [
                "185.130.5.253", "94.102.61.78", "45.155.205.233"
            ],
            "suspicious_processes": [
                "powershell", "cmd", "wscript", "cscript", 
                "regsvr32", "rundll32", "mshta", "wmic"
            ],
            "persistence_locations": [
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                r"Software\Microsoft\Windows\CurrentVersion\Policies",
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"
            ],
            "android_suspicious_permissions": [
                "android.permission.READ_SMS",
                "android.permission.SEND_SMS",
                "android.permission.RECORD_AUDIO",
                "android.permission.CAMERA",
                "android.permission.READ_CONTACTS",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.INSTALL_PACKAGES",
                "android.permission.REQUEST_INSTALL_PACKAGES",
                "android.permission.SYSTEM_ALERT_WINDOW"
            ],
            "android_suspicious_components": [
                "SmsReceiver", "BootReceiver", "SmsService",
                "NotificationListener", "AccessibilityService"
            ]
        }
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                    default_config.update(loaded_config)
                    return default_config
            except Exception as e:
                print(f"[!] Error loading config: {e}")
                return default_config
        else:
            try:
                with open(self.config_file, 'w') as f:
                    json.dump(default_config, f, indent=4)
                print(f"[+] Created default configuration file: {self.config_file}")
            except Exception as e:
                print(f"[!] Error saving config: {e}")
            return default_config
    
    def get(self, key: str, default: any = None) -> any:
        return self.config.get(key, default)
    
    def set(self, key: str, value: any) -> None:
        self.config[key] = value
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
            print(f"[+] Configuration updated: {key} = {value}")
        except Exception as e:
            print(f"[!] Error saving config: {e}")

# ============================================================================
# Logging System
# ============================================================================

class SandboxLogger:
    """Advanced logging system for sandbox operations."""
    
    def __init__(self, log_file: str = "sandbox.log"):
        self.logger = logging.getLogger("MalwareSandbox")
        self.logger.setLevel(logging.DEBUG)
        
        # Clear any existing handlers
        self.logger.handlers.clear()
        
        # File handler
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.DEBUG)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        fh.setFormatter(formatter)
        
        self.logger.addHandler(fh)
        self.log_file = log_file
        self.gui_callback = None
    
    def set_gui_callback(self, callback):
        """Set callback for GUI log display."""
        self.gui_callback = callback
    
    def _log(self, level, message):
        """Internal logging method."""
        if self.gui_callback:
            self.gui_callback(f"[{level}] {message}")
        
        if level == "INFO":
            self.logger.info(message)
        elif level == "WARNING":
            self.logger.warning(message)
        elif level == "ERROR":
            self.logger.error(message)
        elif level == "DEBUG":
            self.logger.debug(message)
    
    def info(self, message: str) -> None:
        self._log("INFO", message)
    
    def warning(self, message: str) -> None:
        self._log("WARNING", message)
    
    def error(self, message: str) -> None:
        self._log("ERROR", message)
    
    def debug(self, message: str) -> None:
        self._log("DEBUG", message)
    
    def critical(self, message: str) -> None:
        self._log("CRITICAL", message)

# ============================================================================
# APK Analyzer
# ============================================================================

class APKAnalyzer:
    """Android APK analysis module."""
    
    def __init__(self, logger: SandboxLogger, config: SandboxConfig):
        self.logger = logger
        self.config = config
        self.suspicious_permissions = config.get("android_suspicious_permissions", [])
        self.suspicious_components = config.get("android_suspicious_components", [])
    
    def analyze(self, apk_path: str) -> Dict:
        """Perform comprehensive APK analysis."""
        results = {
            "file_path": apk_path,
            "hashes": {},
            "package_info": {},
            "permissions": [],
            "components": {},
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
            "strings": [],
            "certificates": [],
            "dex_info": {},
            "suspicious_indicators": [],
            "risk_score": 0,
            "signature_verification": False
        }
        
        # Calculate hashes
        try:
            with open(apk_path, "rb") as f:
                content = f.read()
                results["hashes"]["md5"] = hashlib.md5(content).hexdigest()
                results["hashes"]["sha1"] = hashlib.sha1(content).hexdigest()
                results["hashes"]["sha256"] = hashlib.sha256(content).hexdigest()
        except Exception as e:
            self.logger.error(f"Hash calculation failed: {e}")
        
        if ANDROGUARD_AVAILABLE:
            try:
                # Load APK
                apk = APK(apk_path)
                
                # Package information
                results["package_info"] = {
                    "package_name": apk.get_package(),
                    "version_name": apk.get_android_version_name(),
                    "version_code": apk.get_android_version_code(),
                    "min_sdk": apk.get_min_sdk_version(),
                    "target_sdk": apk.get_target_sdk_version(),
                    "main_activity": apk.get_main_activity()
                }
                
                # Permissions
                results["permissions"] = apk.get_permissions()
                
                # Components
                results["activities"] = apk.get_activities()
                results["services"] = apk.get_services()
                results["receivers"] = apk.get_receivers()
                results["providers"] = apk.get_providers()
                
                # Get certificates
                certs = apk.get_certificates_der_v2()
                if certs:
                    results["certificates"] = [
                        {"hash": hashlib.sha256(cert).hexdigest()[:16]}
                        for cert in certs[:3]  # Limit to first 3 certificates
                    ]
                
                # Check for suspicious components
                for component in results["receivers"]:
                    for susp in self.suspicious_components:
                        if susp.lower() in component.lower():
                            results["suspicious_indicators"].append(f"Suspicious receiver: {component}")
                
                # Check for suspicious services
                for service in results["services"]:
                    if "accessibility" in service.lower() or "notification" in service.lower():
                        results["suspicious_indicators"].append(f"Sensitive service: {service}")
                
                # Analyze DEX files
                dex_files = apk.get_dex()
                if dex_files:
                    results["dex_info"]["num_dex_files"] = len(dex_files)
                    results["dex_info"]["total_dex_size"] = sum(len(dex) for dex in dex_files)
                    
                    # Extract strings from first DEX file
                    try:
                        dvm = DalvikVMFormat(dex_files[0])
                        analysis = Analysis()
                        dvm.set_vm(analysis, None)
                        
                        # Get strings
                        strings = dvm.get_strings()
                        results["strings"] = list(set(strings))[:100]  # First 100 unique strings
                        
                        # Check for suspicious strings
                        suspicious_strings = [
                            "sms", "send", "steal", "bank", "crypto", "coin",
                            "phish", "spy", "root", "exploit", "payload"
                        ]
                        for s in strings[:500]:
                            s_lower = s.lower()
                            for susp in suspicious_strings:
                                if susp in s_lower:
                                    results["suspicious_indicators"].append(f"Suspicious string: {s[:50]}")
                                    break
                        
                        # Check for native code
                        if dvm.get_methods():
                            results["dex_info"]["num_methods"] = len(dvm.get_methods())
                        
                    except Exception as e:
                        self.logger.debug(f"DEX analysis error: {e}")
                
                # Check suspicious permissions
                for perm in results["permissions"]:
                    if perm in self.suspicious_permissions:
                        results["suspicious_indicators"].append(f"Suspicious permission: {perm}")
                
                # Calculate risk score
                risk_score = 0
                risk_score += len([p for p in results["permissions"] if p in self.suspicious_permissions]) * 10
                risk_score += len(results["suspicious_indicators"]) * 5
                risk_score += 5 if results["receivers"] else 0
                risk_score += 5 if results["services"] else 0
                
                results["risk_score"] = min(risk_score, 100)
                
                # Signature verification (basic)
                if certs:
                    results["signature_verification"] = True
                
            except Exception as e:
                self.logger.error(f"APK analysis error: {e}")
                results["error"] = str(e)
        else:
            # Fallback to basic APK analysis using zipfile
            try:
                with zipfile.ZipFile(apk_path, 'r') as zf:
                    # Extract AndroidManifest.xml
                    if "AndroidManifest.xml" in zf.namelist():
                        self.logger.info("Found AndroidManifest.xml, performing basic analysis...")
                        
                        # Try to parse AndroidManifest.xml (simplified)
                        manifest_data = zf.read("AndroidManifest.xml")
                        results["basic_info"] = {
                            "has_manifest": True,
                            "manifest_size": len(manifest_data)
                        }
                        
                        # Check for suspicious file names
                        suspicious_files = []
                        for name in zf.namelist():
                            name_lower = name.lower()
                            if any(x in name_lower for x in [".so", "lib", "payload", "exploit", "smali"]):
                                suspicious_files.append(name)
                        
                        if suspicious_files:
                            results["suspicious_indicators"].append(f"Suspicious files: {', '.join(suspicious_files[:5])}")
                        
            except Exception as e:
                self.logger.error(f"Basic APK analysis error: {e}")
        
        return results
    
    def generate_report(self, analysis: Dict) -> str:
        """Generate APK analysis report."""
        report = "\n" + "="*50 + "\n"
        report += "ANDROID APK ANALYSIS REPORT\n"
        report += "="*50 + "\n"
        report += f"File: {analysis['file_path']}\n\n"
        
        # Hashes
        report += "File Hashes:\n"
        for hash_type, hash_value in analysis['hashes'].items():
            report += f"  {hash_type.upper()}: {hash_value}\n"
        
        # Package information
        if analysis.get('package_info'):
            report += "\nPackage Information:\n"
            for key, value in analysis['package_info'].items():
                report += f"  {key}: {value}\n"
        
        # Risk score
        if analysis.get('risk_score', 0) > 0:
            report += f"\nRisk Score: {analysis['risk_score']}/100\n"
            if analysis['risk_score'] >= 70:
                report += "Severity: CRITICAL - Highly suspicious APK\n"
            elif analysis['risk_score'] >= 40:
                report += "Severity: HIGH - Potentially malicious\n"
            elif analysis['risk_score'] >= 20:
                report += "Severity: MEDIUM - Some suspicious indicators\n"
            else:
                report += "Severity: LOW - Minimal suspicious indicators\n"
        
        # Permissions
        if analysis.get('permissions'):
            report += "\nPermissions:\n"
            for perm in analysis['permissions']:
                marker = "[!] " if perm in self.suspicious_permissions else "    "
                report += f"  {marker}{perm}\n"
        
        # Components
        if analysis.get('activities'):
            report += f"\nActivities ({len(analysis['activities'])}):\n"
            for act in analysis['activities'][:10]:
                report += f"  - {act}\n"
        
        if analysis.get('services'):
            report += f"\nServices ({len(analysis['services'])}):\n"
            for svc in analysis['services'][:10]:
                report += f"  - {svc}\n"
        
        if analysis.get('receivers'):
            report += f"\nReceivers ({len(analysis['receivers'])}):\n"
            for rcvr in analysis['receivers'][:10]:
                report += f"  - {rcvr}\n"
        
        # Suspicious indicators
        if analysis.get('suspicious_indicators'):
            report += "\nSuspicious Indicators Found:\n"
            for indicator in analysis['suspicious_indicators'][:20]:
                report += f"  [!] {indicator}\n"
        
        # DEX information
        if analysis.get('dex_info'):
            report += "\nDEX Information:\n"
            for key, value in analysis['dex_info'].items():
                report += f"  {key}: {value}\n"
        
        # Strings sample
        if analysis.get('strings'):
            report += "\nSample Strings (first 20):\n"
            for s in analysis['strings'][:20]:
                report += f"  - {s}\n"
        
        # Certificates
        if analysis.get('certificates'):
            report += "\nCertificate Information:\n"
            for cert in analysis['certificates']:
                report += f"  - Hash: {cert['hash']}\n"
        
        return report

# ============================================================================
# File System Monitoring
# ============================================================================

class FileSystemHandler(FileSystemEventHandler):
    """Handles file system events."""
    
    def __init__(self, logger: SandboxLogger, behavioral_analyzer=None):
        self.logger = logger
        self.behavioral_analyzer = behavioral_analyzer
    
    def on_modified(self, event):
        if not event.is_directory:
            self.logger.info(f"[File Modified] {event.src_path}")
            if self.behavioral_analyzer:
                self.behavioral_analyzer.add_behavior("file", {
                    "action": "modified",
                    "path": event.src_path,
                    "timestamp": datetime.now().isoformat()
                })
    
    def on_created(self, event):
        if not event.is_directory:
            self.logger.info(f"[File Created] {event.src_path}")
            if self.behavioral_analyzer:
                self.behavioral_analyzer.add_behavior("file", {
                    "action": "created",
                    "path": event.src_path,
                    "timestamp": datetime.now().isoformat()
                })
    
    def on_deleted(self, event):
        if not event.is_directory:
            self.logger.info(f"[File Deleted] {event.src_path}")
            if self.behavioral_analyzer:
                self.behavioral_analyzer.add_behavior("file", {
                    "action": "deleted",
                    "path": event.src_path,
                    "timestamp": datetime.now().isoformat()
                })

# ============================================================================
# Network Traffic Analysis
# ============================================================================

class NetworkAnalyzer:
    """Deep analysis of network traffic."""
    
    def __init__(self, logger: SandboxLogger, config: SandboxConfig, behavioral_analyzer=None):
        self.logger = logger
        self.config = config
        self.behavioral_analyzer = behavioral_analyzer
        self.connections = []
        self.dns_queries = []
        self.http_requests = []
        self.suspicious_ips = config.get("suspicious_ips", [])
        self.monitoring = False
        self.sniff_thread = None
    
    def packet_callback(self, packet):
        """Callback for processing captured packets."""
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                connection = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": "IP",
                    "timestamp": datetime.now().isoformat()
                }
                
                if TCP in packet:
                    connection["protocol"] = "TCP"
                    connection["src_port"] = packet[TCP].sport
                    connection["dst_port"] = packet[TCP].dport
                    
                    if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                        if Raw in packet:
                            try:
                                data = packet[Raw].load.decode('utf-8', errors='ignore')
                                if "GET" in data or "POST" in data:
                                    http_req = data.split('\n')[0]
                                    self.http_requests.append(http_req)
                                    connection["http"] = http_req
                                    self.logger.info(f"[HTTP] {http_req}")
                            except:
                                pass
                
                elif UDP in packet:
                    connection["protocol"] = "UDP"
                    connection["src_port"] = packet[UDP].sport
                    connection["dst_port"] = packet[UDP].dport
                
                self.connections.append(connection)
                
                if packet.haslayer(DNSQR):
                    query = packet[DNSQR].qname.decode('utf-8', errors='ignore')
                    self.dns_queries.append(query)
                    self.logger.info(f"[DNS] Query: {query}")
                    if self.behavioral_analyzer:
                        self.behavioral_analyzer.add_behavior("network", {
                            "type": "dns",
                            "query": query,
                            "timestamp": datetime.now().isoformat()
                        })
                
                if dst_ip in self.suspicious_ips:
                    self.logger.warning(f"[!] Connection to suspicious IP: {dst_ip}")
                    if self.behavioral_analyzer:
                        self.behavioral_analyzer.add_behavior("suspicious", {
                            "type": "suspicious_ip",
                            "ip": dst_ip,
                            "timestamp": datetime.now().isoformat()
                        })
                
        except Exception as e:
            self.logger.debug(f"Packet processing error: {e}")
    
    def start(self):
        """Start network monitoring."""
        self.monitoring = True
        self.logger.info("Starting network monitoring...")
        
        def sniff_packets():
            try:
                sniff(prn=self.packet_callback, store=False, timeout=1)
            except PermissionError:
                self.logger.error("Network monitoring requires root/administrator privileges")
            except Exception as e:
                self.logger.error(f"Network monitoring error: {e}")
        
        self.sniff_thread = threading.Thread(target=sniff_packets, daemon=True)
        self.sniff_thread.start()
    
    def stop(self):
        """Stop network monitoring."""
        self.monitoring = False
        self.logger.info("Stopped network monitoring")
    
    def get_report(self) -> str:
        """Generate network activity report."""
        report = "\n" + "="*50 + "\n"
        report += "NETWORK ACTIVITY REPORT\n"
        report += "="*50 + "\n"
        report += f"Total Connections: {len(self.connections)}\n"
        report += f"DNS Queries: {len(self.dns_queries)}\n"
        report += f"HTTP Requests: {len(self.http_requests)}\n\n"
        
        if self.dns_queries:
            report += "DNS Queries:\n"
            for query in set(self.dns_queries):
                report += f"  - {query}\n"
        
        if self.http_requests:
            report += "\nHTTP Requests:\n"
            for req in set(self.http_requests):
                report += f"  - {req}\n"
        
        return report

# ============================================================================
# Process Monitoring
# ============================================================================

class ProcessMonitor:
    """Monitors processes created by the malware sample."""
    
    def __init__(self, logger: SandboxLogger, config: SandboxConfig, behavioral_analyzer=None):
        self.logger = logger
        self.config = config
        self.behavioral_analyzer = behavioral_analyzer
        self.running_processes = set()
        self.process_history = []
        self.suspicious_patterns = config.get("suspicious_processes", [])
        self.monitoring = False
    
    def get_process_list(self) -> Dict:
        """Get current running processes."""
        processes = {}
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
            try:
                processes[proc.pid] = {
                    'pid': proc.pid,
                    'name': proc.info['name'],
                    'cmdline': ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else '',
                    'create_time': proc.info['create_time']
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return processes
    
    def check_suspicious_activity(self, process: Dict):
        """Check for suspicious process behaviors."""
        try:
            name = process['name'].lower() if process['name'] else ''
            cmdline = process['cmdline'].lower()
            
            for pattern in self.suspicious_patterns:
                if pattern in name or pattern in cmdline:
                    self.logger.warning(f"[!] Suspicious process: {process['name']} - {process['cmdline']}")
                    if self.behavioral_analyzer:
                        self.behavioral_analyzer.add_behavior("process", {
                            "type": "suspicious_process",
                            "name": process['name'],
                            "cmdline": process['cmdline'],
                            "pattern": pattern,
                            "timestamp": datetime.now().isoformat()
                        })
        except Exception as e:
            self.logger.debug(f"Suspicious activity check error: {e}")
    
    def start(self):
        """Start process monitoring."""
        self.monitoring = True
        self.running_processes = set(self.get_process_list().keys())
        self.logger.info("Started process monitoring")
    
    def stop(self):
        """Stop process monitoring."""
        self.monitoring = False
        self.logger.info("Stopped process monitoring")
    
    def update(self):
        """Update process list and detect new processes."""
        if not self.monitoring:
            return
        
        current_processes = self.get_process_list()
        current_pids = set(current_processes.keys())
        
        new_processes = current_pids - self.running_processes
        
        for pid in new_processes:
            process = current_processes[pid]
            self.logger.info(f"[New Process] PID: {pid}, Name: {process['name']}, Cmdline: {process['cmdline']}")
            self.process_history.append(process)
            self.check_suspicious_activity(process)
            if self.behavioral_analyzer:
                self.behavioral_analyzer.add_behavior("process", {
                    "action": "created",
                    "pid": pid,
                    "name": process['name'],
                    "cmdline": process['cmdline'],
                    "timestamp": datetime.now().isoformat()
                })
        
        self.running_processes = current_pids
    
    def get_report(self) -> str:
        """Generate process activity report."""
        report = "\n" + "="*50 + "\n"
        report += "PROCESS ACTIVITY REPORT\n"
        report += "="*50 + "\n"
        report += f"Total Processes Created: {len(self.process_history)}\n\n"
        
        if self.process_history:
            report += "Processes Created:\n"
            for proc in self.process_history:
                report += f"  - {proc['name']} (PID: {proc['pid']})\n"
                if proc['cmdline']:
                    report += f"    Command: {proc['cmdline']}\n"
        
        return report

# ============================================================================
# YARA Scanner
# ============================================================================

class YaraScanner:
    """Scan files and memory using YARA rules."""
    
    def __init__(self, logger: SandboxLogger, config: SandboxConfig):
        self.logger = logger
        self.config = config
        self.rules = None
        self.load_rules()
    
    def load_rules(self):
        """Load YARA rules from directory."""
        rule_path = self.config.get("yara_rules_path")
        
        if not os.path.exists(rule_path):
            self.logger.warning(f"YARA rules directory not found: {rule_path}")
            return
        
        try:
            rule_files = {}
            for rule_file in os.listdir(rule_path):
                if rule_file.endswith(('.yar', '.yara')):
                    with open(os.path.join(rule_path, rule_file), 'r', encoding='utf-8', errors='ignore') as f:
                        rule_files[rule_file] = f.read()
            
            if rule_files:
                self.rules = yara.compile(sources=rule_files)
                self.logger.info(f"[+] Loaded {len(rule_files)} YARA rule files")
            else:
                self.logger.warning("No YARA rule files found")
        except Exception as e:
            self.logger.error(f"Failed to load YARA rules: {e}")
    
    def scan_file(self, file_path: str) -> List[str]:
        """Scan file with YARA rules."""
        if not self.rules or not os.path.exists(file_path):
            return []
        
        try:
            matches = self.rules.match(file_path)
            if matches:
                self.logger.warning(f"[!] YARA matches found for {file_path}")
                for match in matches:
                    self.logger.warning(f"    - {match.rule}")
                return [match.rule for match in matches]
        except Exception as e:
            self.logger.error(f"YARA scan error: {e}")
        
        return []

# ============================================================================
# Static Analysis (PE/ELF)
# ============================================================================

class StaticAnalyzer:
    """Performs static analysis on executable files."""
    
    def __init__(self, logger: SandboxLogger):
        self.logger = logger
    
    def analyze(self, file_path: str) -> Dict:
        """Analyze file and return findings."""
        results = {
            "file_path": file_path,
            "hashes": {},
            "pe_info": None,
            "strings": [],
            "suspicious_indicators": []
        }
        
        # Calculate hashes
        try:
            with open(file_path, "rb") as f:
                content = f.read()
                results["hashes"]["md5"] = hashlib.md5(content).hexdigest()
                results["hashes"]["sha1"] = hashlib.sha1(content).hexdigest()
                results["hashes"]["sha256"] = hashlib.sha256(content).hexdigest()
        except Exception as e:
            self.logger.error(f"Hash calculation failed: {e}")
        
        # PE analysis
        if file_path.endswith((".exe", ".dll", ".scr")):
            try:
                pe = pefile.PE(file_path)
                results["pe_info"] = {
                    "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                    "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
                    "sections": [],
                    "imports": [],
                    "exports": []
                }
                
                # Sections
                for section in pe.sections:
                    results["pe_info"]["sections"].append({
                        "name": section.Name.decode().strip(),
                        "virtual_address": hex(section.VirtualAddress),
                        "virtual_size": hex(section.Misc_VirtualSize),
                        "raw_size": hex(section.SizeOfRawData)
                    })
                
                # Imports
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        dll_name = entry.dll.decode()
                        for imp in entry.imports:
                            if imp.name:
                                results["pe_info"]["imports"].append({
                                    "dll": dll_name,
                                    "function": imp.name.decode()
                                })
                
                # Check for suspicious imports
                suspicious_apis = ["CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", 
                                  "SetWindowsHookEx", "RegSetValueEx", "URLDownloadToFile"]
                for imp in results["pe_info"]["imports"]:
                    if imp["function"] in suspicious_apis:
                        results["suspicious_indicators"].append(f"Suspicious API: {imp['function']}")
                
            except pefile.PEFormatError:
                self.logger.warning("File is not a valid PE file")
            except Exception as e:
                self.logger.error(f"PE analysis failed: {e}")
        
        return results
    
    def generate_report(self, analysis: Dict) -> str:
        """Generate static analysis report."""
        report = "\n" + "="*50 + "\n"
        report += "STATIC ANALYSIS REPORT\n"
        report += "="*50 + "\n"
        report += f"File: {analysis['file_path']}\n\n"
        
        # Hashes
        report += "File Hashes:\n"
        for hash_type, hash_value in analysis['hashes'].items():
            report += f"  {hash_type.upper()}: {hash_value}\n"
        
        # PE Info
        if analysis['pe_info']:
            report += "\nPE Information:\n"
            report += f"  Entry Point: {analysis['pe_info']['entry_point']}\n"
            report += f"  Image Base: {analysis['pe_info']['image_base']}\n"
            
            report += "\nSections:\n"
            for section in analysis['pe_info']['sections']:
                report += f"  {section['name']}: VA={section['virtual_address']}\n"
            
            if analysis['pe_info']['imports']:
                report += "\nImported Functions:\n"
                for imp in analysis['pe_info']['imports'][:20]:
                    report += f"  {imp['dll']} -> {imp['function']}\n"
        
        # Suspicious indicators
        if analysis['suspicious_indicators']:
            report += "\nSuspicious Indicators Found:\n"
            for indicator in analysis['suspicious_indicators']:
                report += f"  [!] {indicator}\n"
        
        return report

# ============================================================================
# Behavioral Analysis
# ============================================================================

class BehavioralAnalyzer:
    """Aggregate and analyze all behaviors."""
    
    def __init__(self, logger: SandboxLogger):
        self.logger = logger
        self.file_operations = []
        self.network_connections = []
        self.registry_changes = []
        self.process_creations = []
        self.suspicious_activities = []
        self.score = 0
    
    def add_behavior(self, behavior_type: str, details: Dict):
        """Add a detected behavior."""
        if behavior_type == "file":
            self.file_operations.append(details)
            self.score += 10
        elif behavior_type == "network":
            self.network_connections.append(details)
            self.score += 20
        elif behavior_type == "registry":
            self.registry_changes.append(details)
            self.score += 15
        elif behavior_type == "process":
            self.process_creations.append(details)
            self.score += 25
        elif behavior_type == "suspicious":
            self.suspicious_activities.append(details)
            self.score += 30
    
    def generate_report(self) -> str:
        """Generate comprehensive behavior report."""
        report = "\n" + "="*50 + "\n"
        report += "BEHAVIORAL ANALYSIS SUMMARY\n"
        report += "="*50 + "\n"
        
        # Risk scoring
        report += f"Risk Score: {min(self.score, 100)}/100\n"
        
        if self.score >= 75:
            report += "Severity: CRITICAL - Highly malicious behavior detected\n"
        elif self.score >= 50:
            report += "Severity: HIGH - Significant malicious activity\n"
        elif self.score >= 25:
            report += "Severity: MEDIUM - Suspicious behavior detected\n"
        else:
            report += "Severity: LOW - Minimal suspicious activity\n"
        
        # Statistics
        report += f"\nDetected Behaviors:\n"
        report += f"- File Operations: {len(self.file_operations)}\n"
        report += f"- Network Connections: {len(self.network_connections)}\n"
        report += f"- Registry Changes: {len(self.registry_changes)}\n"
        report += f"- Process Creations: {len(self.process_creations)}\n"
        report += f"- Suspicious Activities: {len(self.suspicious_activities)}\n"
        
        # Detailed findings
        if self.suspicious_activities:
            report += "\nSuspicious Activities:\n"
            for activity in self.suspicious_activities:
                report += f"  - {activity.get('type', 'unknown')}: {activity}\n"
        
        return report

# ============================================================================
# GUI Application
# ============================================================================

class MalwareSandboxGUI:
    """Main GUI application for malware analysis sandbox."""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Advanced Malware Analysis Sandbox - Multi-Platform Edition")
        self.root.geometry("1300x850")
        
        # Initialize components
        self.config = SandboxConfig()
        self.logger = SandboxLogger()
        self.logger.set_gui_callback(self.update_log)
        
        self.behavioral_analyzer = BehavioralAnalyzer(self.logger)
        self.network_analyzer = NetworkAnalyzer(self.logger, self.config, self.behavioral_analyzer)
        self.process_monitor = ProcessMonitor(self.logger, self.config, self.behavioral_analyzer)
        self.yara_scanner = YaraScanner(self.logger, self.config)
        self.static_analyzer = StaticAnalyzer(self.logger)
        self.apk_analyzer = APKAnalyzer(self.logger, self.config)
        
        self.monitoring_threads = []
        self.current_sample = None
        self.current_sample_type = None
        self.monitoring_active = False
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the user interface."""
        # Create main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="Advanced Malware Analysis Sandbox - Multi-Platform Edition", 
                                font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, pady=10)
        
        # Platform indicator
        platform_frame = ttk.Frame(main_frame)
        platform_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(platform_frame, text="Supported Platforms:").pack(side=tk.LEFT)
        ttk.Label(platform_frame, text="Windows (PE)", foreground="blue").pack(side=tk.LEFT, padx=5)
        ttk.Label(platform_frame, text="Android (APK)", foreground="green").pack(side=tk.LEFT, padx=5)
        ttk.Label(platform_frame, text="Linux (ELF)", foreground="orange").pack(side=tk.LEFT, padx=5)
        
        # Button Frame
        button_frame = ttk.LabelFrame(main_frame, text="Analysis Options", padding="10")
        button_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=5)
        button_frame.columnconfigure(0, weight=1)
        
        # Create buttons in a grid
        buttons = [
            ("🔍 Full Analysis (Recommended)", self.full_analysis, "Complete static and dynamic analysis"),
            ("📱 APK Analysis", self.apk_analysis, "Analyze Android APK file"),
            ("📄 Static Analysis Only", self.static_analysis, "Analyze file without execution"),
            ("⚡ Dynamic Analysis", self.dynamic_analysis, "Execute and monitor behavior"),
            ("📁 File Monitor", self.start_file_monitor, "Monitor file system changes"),
            ("🌐 Network Monitor", self.start_network_monitor, "Capture network traffic"),
            ("🔄 Process Monitor", self.start_process_monitor, "Monitor process creation"),
            ("🎯 YARA Scan", self.yara_scan, "Scan with YARA rules"),
            ("📊 Generate Report", self.generate_report, "Create comprehensive report"),
            ("⚙️ Configuration", self.show_config, "View/Edit settings"),
            ("🗑️ Clear Log", self.clear_log, "Clear log display"),
            ("❌ Exit", self.exit_app, "Exit application")
        ]
        
        row, col = 0, 0
        for text, command, tooltip in buttons:
            btn = ttk.Button(button_frame, text=text, command=command, width=25)
            btn.grid(row=row, column=col, padx=5, pady=5, sticky=tk.W)
            
            # Add tooltip
            tooltip_label = ttk.Label(button_frame, text=tooltip, font=('Arial', 8), foreground='gray')
            tooltip_label.grid(row=row+1, column=col, padx=5, sticky=tk.W)
            
            col += 1
            if col > 2:
                col = 0
                row += 2
        
        # Log Frame
        log_frame = ttk.LabelFrame(main_frame, text="Log Output", padding="10")
        log_frame.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        # Log text area with scrollbar
        self.log_text = scrolledtext.ScrolledText(log_frame, height=20, width=100)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=4, column=0, sticky=(tk.W, tk.E))
    
    def update_log(self, message: str):
        """Update log display with message."""
        def _update():
            self.log_text.insert(tk.END, message + "\n")
            self.log_text.see(tk.END)
            self.root.update_idletasks()
        
        self.root.after(0, _update)
    
    def update_status(self, message: str):
        """Update status bar."""
        def _update():
            self.status_var.set(message)
        
        self.root.after(0, _update)
    
    def clear_log(self):
        """Clear the log display."""
        self.log_text.delete(1.0, tk.END)
        self.logger.info("Log cleared")
    
    def select_file(self) -> Optional[str]:
        """Open file dialog to select a file."""
        file_path = filedialog.askopenfilename(
            title="Select File",
            filetypes=[
                ("Executable files", "*.exe *.dll *.scr"),
                ("Android APK", "*.apk"),
                ("All files", "*.*")
            ]
        )
        return file_path if file_path else None
    
    def detect_file_type(self, file_path: str) -> str:
        """Detect file type based on extension."""
        ext = os.path.splitext(file_path)[1].lower()
        if ext == '.apk':
            return 'apk'
        elif ext in ['.exe', '.dll', '.scr']:
            return 'pe'
        elif ext in ['.elf', '.so']:
            return 'elf'
        else:
            return 'unknown'
    
    def full_analysis(self):
        """Perform complete analysis of a sample."""
        file_path = self.select_file()
        if not file_path:
            return
        
        self.current_sample = file_path
        self.current_sample_type = self.detect_file_type(file_path)
        
        self.update_status(f"Analyzing: {os.path.basename(file_path)}")
        self.logger.info("="*60)
        self.logger.info(f"Starting FULL ANALYSIS of: {file_path}")
        self.logger.info(f"File Type: {self.current_sample_type.upper()}")
        self.logger.info("="*60)
        
        # Run analysis in a separate thread
        def analyze():
            try:
                # Static analysis based on file type
                self.logger.info("\n[1/4] Performing Static Analysis...")
                
                if self.current_sample_type == 'apk':
                    static_results = self.apk_analyzer.analyze(file_path)
                    self.logger.info(self.apk_analyzer.generate_report(static_results))
                else:
                    static_results = self.static_analyzer.analyze(file_path)
                    self.logger.info(self.static_analyzer.generate_report(static_results))
                
                # YARA scan
                self.logger.info("\n[2/4] Performing YARA Scan...")
                yara_matches = self.yara_scanner.scan_file(file_path)
                if yara_matches:
                    self.logger.warning(f"YARA Matches: {', '.join(yara_matches)}")
                else:
                    self.logger.info("No YARA matches found")
                
                # Dynamic analysis for executable files
                if self.current_sample_type != 'apk':
                    self.logger.warning("\n[3/4] Dynamic Analysis Phase")
                    self.logger.warning("⚠️  WARNING: Next phase will execute the sample!")
                    self.logger.warning("Ensure you are in a controlled, isolated environment.")
                    
                    response = messagebox.askyesno(
                        "Execute Sample",
                        f"WARNING: This will execute {os.path.basename(file_path)}!\n\n"
                        "Are you in a controlled, isolated environment?\n\n"
                        "Only click YES if you understand the risks!"
                    )
                    
                    if response:
                        self.logger.info("Starting dynamic analysis...")
                        self.start_all_monitors()
                        self.execute_sample(file_path)
                        
                        # Wait for activities
                        self.logger.info("Waiting 30 seconds for activities to be captured...")
                        time.sleep(30)
                        
                        self.stop_all_monitors()
                        
                        # Generate reports
                        self.logger.info("\n[4/4] Generating Reports...")
                        self.logger.info(self.network_analyzer.get_report())
                        self.logger.info(self.process_monitor.get_report())
                        self.logger.info(self.behavioral_analyzer.generate_report())
                        
                        # Save reports
                        self.save_reports(file_path, static_results, yara_matches)
                    else:
                        self.logger.info("Dynamic analysis skipped by user")
                else:
                    self.logger.info("\n[3/4] APK Analysis Complete")
                    self.logger.info("[4/4] Generating Final Report...")
                    self.save_apk_report(file_path, static_results)
                
                self.update_status("Analysis completed")
                self.logger.info("="*60)
                self.logger.info("Analysis completed successfully!")
                
            except Exception as e:
                self.logger.error(f"Analysis error: {e}")
                self.update_status("Analysis failed")
        
        threading.Thread(target=analyze, daemon=True).start()
    
    def apk_analysis(self):
        """Perform APK analysis."""
        file_path = self.select_file()
        if not file_path:
            return
        
        if not file_path.endswith('.apk'):
            messagebox.showwarning("Invalid File", "Please select an APK file (.apk)")
            return
        
        self.current_sample = file_path
        self.current_sample_type = 'apk'
        
        self.update_status(f"Analyzing APK: {os.path.basename(file_path)}")
        self.logger.info("Starting APK Analysis...")
        
        def analyze():
            results = self.apk_analyzer.analyze(file_path)
            self.logger.info(self.apk_analyzer.generate_report(results))
            
            # Save report
            self.save_apk_report(file_path, results)
            
            self.update_status("APK analysis completed")
        
        threading.Thread(target=analyze, daemon=True).start()
    
    def static_analysis(self):
        """Perform static analysis only."""
        file_path = self.select_file()
        if not file_path:
            return
        
        self.update_status(f"Analyzing: {os.path.basename(file_path)}")
        self.logger.info("Starting Static Analysis...")
        
        file_type = self.detect_file_type(file_path)
        
        def analyze():
            if file_type == 'apk':
                results = self.apk_analyzer.analyze(file_path)
                self.logger.info(self.apk_analyzer.generate_report(results))
            else:
                results = self.static_analyzer.analyze(file_path)
                self.logger.info(self.static_analyzer.generate_report(results))
            
            # Also do YARA scan
            self.logger.info("\nPerforming YARA scan...")
            matches = self.yara_scanner.scan_file(file_path)
            if matches:
                self.logger.warning(f"YARA matches: {', '.join(matches)}")
            
            self.update_status("Static analysis completed")
        
        threading.Thread(target=analyze, daemon=True).start()
    
    def dynamic_analysis(self):
        """Perform dynamic analysis with execution."""
        file_path = self.select_file()
        if not file_path:
            return
        
        file_type = self.detect_file_type(file_path)
        
        if file_type == 'apk':
            messagebox.showinfo("APK Analysis", "APK files cannot be executed directly.\nUse 'APK Analysis' for static analysis.")
            return
        
        response = messagebox.askyesno(
            "Dynamic Analysis",
            f"This will execute {os.path.basename(file_path)} and monitor its behavior.\n\n"
            "Are you sure you want to proceed?"
        )
        
        if not response:
            return
        
        self.update_status(f"Dynamic analysis of: {os.path.basename(file_path)}")
        self.logger.info("Starting Dynamic Analysis...")
        
        def analyze():
            try:
                self.start_all_monitors()
                self.execute_sample(file_path)
                
                self.logger.info("Monitoring for 30 seconds...")
                time.sleep(30)
                
                self.stop_all_monitors()
                
                self.logger.info(self.network_analyzer.get_report())
                self.logger.info(self.process_monitor.get_report())
                self.logger.info(self.behavioral_analyzer.generate_report())
                
                self.update_status("Dynamic analysis completed")
            except Exception as e:
                self.logger.error(f"Dynamic analysis error: {e}")
        
        threading.Thread(target=analyze, daemon=True).start()
    
    def start_file_monitor(self):
        """Start file system monitoring."""
        directory = filedialog.askdirectory(title="Select directory to monitor")
        if not directory:
            return
        
        self.update_status(f"Monitoring: {directory}")
        self.logger.info(f"Starting file monitor on: {directory}")
        
        # This would need file monitor implementation
        self.logger.info("File monitoring feature - would monitor file changes")
    
    def start_network_monitor(self):
        """Start network monitoring."""
        self.update_status("Network monitoring active")
        self.logger.info("Starting network monitoring...")
        
        def monitor():
            try:
                self.network_analyzer.start()
                self.logger.info("Network monitoring running. Press Stop to end.")
            except Exception as e:
                self.logger.error(f"Network monitoring error: {e}")
        
        threading.Thread(target=monitor, daemon=True).start()
        
        # Show stop button in a new window
        stop_window = tk.Toplevel(self.root)
        stop_window.title("Network Monitor")
        stop_window.geometry("300x100")
        
        ttk.Label(stop_window, text="Network monitoring is active").pack(pady=10)
        ttk.Button(stop_window, text="Stop Monitoring", 
                  command=lambda: self.stop_network_monitor(stop_window)).pack(pady=10)
    
    def stop_network_monitor(self, window):
        """Stop network monitoring."""
        self.network_analyzer.stop()
        self.logger.info("Network monitoring stopped")
        window.destroy()
    
    def start_process_monitor(self):
        """Start process monitoring."""
        self.update_status("Process monitoring active")
        self.logger.info("Starting process monitoring...")
        
        def monitor():
            self.process_monitor.start()
            while True:
                self.process_monitor.update()
                time.sleep(2)
        
        threading.Thread(target=monitor, daemon=True).start()
        
        # Show stop button
        stop_window = tk.Toplevel(self.root)
        stop_window.title("Process Monitor")
        stop_window.geometry("300x100")
        
        ttk.Label(stop_window, text="Process monitoring is active").pack(pady=10)
        ttk.Button(stop_window, text="Stop Monitoring", 
                  command=lambda: self.stop_process_monitor(stop_window)).pack(pady=10)
    
    def stop_process_monitor(self, window):
        """Stop process monitoring."""
        self.process_monitor.stop()
        self.logger.info("Process monitoring stopped")
        window.destroy()
    
    def yara_scan(self):
        """Perform YARA scan on a file."""
        file_path = self.select_file()
        if not file_path:
            return
        
        self.update_status(f"YARA scanning: {os.path.basename(file_path)}")
        self.logger.info(f"Starting YARA scan on: {file_path}")
        
        def scan():
            matches = self.yara_scanner.scan_file(file_path)
            if matches:
                self.logger.warning(f"YARA matches found: {', '.join(matches)}")
            else:
                self.logger.info("No YARA matches found")
            self.update_status("YARA scan completed")
        
        threading.Thread(target=scan, daemon=True).start()
    
    def generate_report(self):
        """Generate comprehensive report."""
        if not self.current_sample:
            file_path = self.select_file()
            if not file_path:
                return
            self.current_sample = file_path
            self.current_sample_type = self.detect_file_type(file_path)
        
        self.update_status("Generating report...")
        self.logger.info("Generating comprehensive report...")
        
        def generate():
            if self.current_sample_type == 'apk':
                results = self.apk_analyzer.analyze(self.current_sample)
                report = self.apk_analyzer.generate_report(results)
            else:
                results = self.static_analyzer.analyze(self.current_sample)
                report = self.static_analyzer.generate_report(results)
            
            # Save to file
            report_path = f"report_{self.current_sample_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(report_path, 'w') as f:
                f.write(report)
            
            self.logger.info(f"Report saved to: {report_path}")
            self.logger.info(report)
            self.update_status(f"Report saved: {report_path}")
        
        threading.Thread(target=generate, daemon=True).start()
    
    def save_apk_report(self, apk_path: str, results: Dict):
        """Save APK analysis report."""
        analysis_dir = os.path.join(os.path.dirname(apk_path), "apk_analysis_results")
        os.makedirs(analysis_dir, exist_ok=True)
        
        # Save analysis report
        report_path = os.path.join(analysis_dir, "apk_analysis_report.txt")
        with open(report_path, 'w') as f:
            f.write(self.apk_analyzer.generate_report(results))
        
        # Save JSON report
        json_path = os.path.join(analysis_dir, "apk_analysis_report.json")
        with open(json_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        self.logger.info(f"APK reports saved to: {analysis_dir}")
    
    def show_config(self):
        """Show configuration window."""
        config_window = tk.Toplevel(self.root)
        config_window.title("Configuration")
        config_window.geometry("600x500")
        
        # Create notebook for tabs
        notebook = ttk.Notebook(config_window)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # General tab
        general_frame = ttk.Frame(notebook)
        notebook.add(general_frame, text="General")
        
        ttk.Label(general_frame, text="Monitor Directory:").grid(row=0, column=0, sticky=tk.W, pady=5)
        monitor_dir_var = tk.StringVar(value=self.config.get("monitor_dir"))
        ttk.Entry(general_frame, textvariable=monitor_dir_var, width=40).grid(row=0, column=1, pady=5)
        
        ttk.Label(general_frame, text="Timeout (seconds):").grid(row=1, column=0, sticky=tk.W, pady=5)
        timeout_var = tk.StringVar(value=str(self.config.get("timeout_seconds")))
        ttk.Entry(general_frame, textvariable=timeout_var, width=10).grid(row=1, column=1, sticky=tk.W, pady=5)
        
        # Android tab
        android_frame = ttk.Frame(notebook)
        notebook.add(android_frame, text="Android")
        
        ttk.Label(android_frame, text="Suspicious Permissions:").grid(row=0, column=0, sticky=tk.NW, pady=5)
        perm_text = tk.Text(android_frame, height=8, width=40)
        perm_text.grid(row=0, column=1, pady=5)
        perm_text.insert('1.0', '\n'.join(self.config.get("android_suspicious_permissions", [])))
        
        ttk.Label(android_frame, text="Suspicious Components:").grid(row=1, column=0, sticky=tk.NW, pady=5)
        comp_text = tk.Text(android_frame, height=5, width=40)
        comp_text.grid(row=1, column=1, pady=5)
        comp_text.insert('1.0', '\n'.join(self.config.get("android_suspicious_components", [])))
        
        # YARA tab
        yara_frame = ttk.Frame(notebook)
        notebook.add(yara_frame, text="YARA")
        
        ttk.Label(yara_frame, text="YARA Rules Path:").grid(row=0, column=0, sticky=tk.W, pady=5)
        yara_path_var = tk.StringVar(value=self.config.get("yara_rules_path"))
        ttk.Entry(yara_frame, textvariable=yara_path_var, width=40).grid(row=0, column=1, pady=5)
        
        # VirusTotal tab
        vt_frame = ttk.Frame(notebook)
        notebook.add(vt_frame, text="VirusTotal")
        
        ttk.Label(vt_frame, text="API Key:").grid(row=0, column=0, sticky=tk.W, pady=5)
        api_key_var = tk.StringVar(value=self.config.get("virustotal_api_key"))
        ttk.Entry(vt_frame, textvariable=api_key_var, width=40, show="*").grid(row=0, column=1, pady=5)
        
        def save_config():
            self.config.set("monitor_dir", monitor_dir_var.get())
            self.config.set("timeout_seconds", int(timeout_var.get()))
            self.config.set("yara_rules_path", yara_path_var.get())
            self.config.set("virustotal_api_key", api_key_var.get())
            
            # Save Android permissions
            perms = [p.strip() for p in perm_text.get('1.0', tk.END).split('\n') if p.strip()]
            self.config.set("android_suspicious_permissions", perms)
            
            # Save Android components
            comps = [c.strip() for c in comp_text.get('1.0', tk.END).split('\n') if c.strip()]
            self.config.set("android_suspicious_components", comps)
            
            messagebox.showinfo("Success", "Configuration saved!")
            config_window.destroy()
        
        ttk.Button(config_window, text="Save", command=save_config).pack(pady=10)
    
    def start_all_monitors(self):
        """Start all monitoring components."""
        self.monitoring_active = True
        self.process_monitor.start()
        self.network_analyzer.start()
        self.logger.info("All monitors started")
    
    def stop_all_monitors(self):
        """Stop all monitoring components."""
        self.monitoring_active = False
        self.process_monitor.stop()
        self.network_analyzer.stop()
        self.logger.info("All monitors stopped")
    
    def execute_sample(self, sample_path: str):
        """Execute the malware sample."""
        self.logger.info(f"Executing sample: {sample_path}")
        
        if not os.path.exists(sample_path):
            self.logger.error(f"File not found: {sample_path}")
            return
        
        def run():
            try:
                if sample_path.endswith(".exe") and sys.platform != "win32":
                    subprocess.run(["wine", sample_path], timeout=self.config.get("timeout_seconds"))
                elif os.access(sample_path, os.X_OK):
                    subprocess.run(sample_path, timeout=self.config.get("timeout_seconds"))
                else:
                    self.logger.error(f"Unsupported file type: {sample_path}")
            except subprocess.TimeoutExpired:
                self.logger.warning(f"Sample execution timed out")
            except Exception as e:
                self.logger.error(f"Execution error: {e}")
        
        threading.Thread(target=run, daemon=True).start()
    
    def save_reports(self, sample_path: str, static_results: Dict, yara_matches: List):
        """Save analysis reports."""
        analysis_dir = os.path.join(os.path.dirname(sample_path), "analysis_results")
        os.makedirs(analysis_dir, exist_ok=True)
        
        # Save static analysis
        with open(os.path.join(analysis_dir, "static_analysis.txt"), 'w') as f:
            f.write(self.static_analyzer.generate_report(static_results))
        
        # Save network report
        with open(os.path.join(analysis_dir, "network_activity.txt"), 'w') as f:
            f.write(self.network_analyzer.get_report())
        
        # Save process report
        with open(os.path.join(analysis_dir, "process_activity.txt"), 'w') as f:
            f.write(self.process_monitor.get_report())
        
        # Save behavioral report
        with open(os.path.join(analysis_dir, "behavioral_analysis.txt"), 'w') as f:
            f.write(self.behavioral_analyzer.generate_report())
        
        self.logger.info(f"Reports saved to: {analysis_dir}")
    
    def exit_app(self):
        """Exit the application."""
        if messagebox.askyesno("Exit", "Are you sure you want to exit?"):
            if self.monitoring_active:
                self.stop_all_monitors()
            self.root.quit()
            self.root.destroy()
    
    def run(self):
        """Run the GUI application."""
        self.root.protocol("WM_DELETE_WINDOW", self.exit_app)
        self.root.mainloop()

# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    """Main entry point."""
    print("""
    ╔══════════════════════════════════════════════════════════════════╗
    ║  HSR ADVANCED MALWARE ANALYSIS SANDBOX - MULTI-PLATFORM EDITION  ║
    ║     Comprehensive Dynamic & Static Analysis Tool                 ║
    ║     Windows PE | Android APK | Linux ELF                         ║
    ╚══════════════════════════════════════════════════════════════════╝
    
    [!] WARNING: This tool is for educational and research purposes only.
    [!] Always use in isolated, controlled environments.
    [!] Never analyze malware on production systems.
    """)
    
    # Check for Android support
    if not ANDROGUARD_AVAILABLE:
        print("[!] Androguard not installed. APK analysis will be limited.")
        print("[!] Install with: pip install androguard")
        print()
    
    try:
        app = MalwareSandboxGUI()
        app.run()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
