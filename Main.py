#!/usr/bin/env python3
"""
Forensic Automation Suite
==========================

This tool provides multiple forensic analysis capabilities:
  1. Forensic Image Analysis (Memory dumps, Disk images)
  2. Static Malware Analysis (File hashing, YARA scanning, string extraction, metadata analysis,
     VirusTotal check, and packed detection)
  3. Interactive DeepSeek AI Chat (Send queries, upload files)
  
Optional/Advanced Modules (Stubs available for future integration):
  - Real-Time Monitoring
  - Behavioral Analysis of Processes
  - Enhanced Reporting (PDF/CSV/HTML)
  - Interactive CLI for dynamic analysis control
  - Automated Incident Response Playbooks
  - Network Traffic Analysis (e.g., Wireshark/Zeek integration)
  - Automated Malware Classification (ML-based)
  - Support for Additional Disk Image Formats (VHD, VMDK, etc.)
  - Timeline Correlation with External Logs
  - Machine Learning Anomaly Detection

SIEM integrations available (Wazuh, ELK, Splunk, HELK) are activated by entering their network locations.

Dependencies:
  - Python 3.x
  - paramiko, pywinrm, requests (install via pip)
  - pefile, yara-python (install via pip)
  - Volatility, SleuthKit, Bulk Extractor, etc. for forensic image analysis (install separately)
  - For VirusTotal checks, obtain an API key from https://www.virustotal.com
  - On Windows: optionally use WSL with Ubuntu to run YARA (if USE_WSL_FOR_YARA is True)

Setup:
  1. Install required Python packages:
       pip install paramiko pywinrm requests pefile yara-python
  2. Install external tools:
       - Volatility (for memory analysis)
       - SleuthKit (for disk image analysis)
       - YARA (if not using the native Windows version, install in WSL via "sudo apt install yara")
  3. Configure your VirusTotal API key below.
  4. Adjust paths for DeepSeek AI (DEEPSEEK_PATH) and YARA rules (YARA_RULE_PATH) as needed.
  5. Configure SIEM endpoints when prompted at runtime.

Usage:
  Run the script and follow the menu prompts:
      python forensic_suite.py

The menu will allow you to choose:
  1. Forensic Image Analysis
  2. Static Malware Analysis
  3. Interactive DeepSeek AI Chat
  4. (Optional) Launch advanced modules (stubs)
  5. Exit

"""

import os
import json
import time
import threading
import subprocess
import hashlib
import requests
import paramiko
import winrm
import pefile
import platform
import psutil
from scapy.all import sniff
from fpdf import FPDF
import csv

# ---------------------------
# CONFIGURATION VARIABLES
# ---------------------------
OLLAMA_API = "http://localhost:11434/api/generate"  # Ollama API endpoint
REPORT_DIR = "forensics_reports"

yara = None
try:
    import yara
except ImportError:
    print("[INFO] YARA is not installed. YARA scanning will be skipped unless running in WSL.")

# SIEM configuration dictionary; user will be prompted to fill these in.
SIEM_TOOLS = {
    "wazuh": None,
    "elk": None,
    "splunk": None,
    "helk": None
}

# YARA configuration
YARA_RULE_PATH = "rules/malware_rules.yar"  # Ensure this file exists
USE_WSL_FOR_YARA = True  # Set to True if using WSL on Windows

# VirusTotal API Key
VIRUSTOTAL_API_KEY = "f6a0141a94b1afa96c4d0fbb501d759cf89f86d9f201974c930d32dc7e4fec5f"  # Replace with your key

# ---------------------------
# UTILITY FUNCTIONS
# ---------------------------

def ask_for_siem_network_locations():
    """Prompt user for SIEM network locations."""
    print("[INFO] Enter the network locations for the following SIEM tools (leave blank to skip):")
    for siem in SIEM_TOOLS.keys():
        value = input(f"  {siem.capitalize()} SIEM (IP/hostname): ").strip()
        SIEM_TOOLS[siem] = value if value else None

def run_command(command):
    """Run a system command and return its output."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout.strip() + "\n" + result.stderr.strip()
    except Exception as e:
        return f"[ERROR] Command execution failed: {e}"

def send_to_ollama(prompt):
    """Send a prompt to Ollama and return its response."""
    try:
        data = {
            "model": "llama2",  # Replace with your preferred model
            "prompt": prompt,
            "stream": False
        }
        response = requests.post(OLLAMA_API, json=data)
        if response.status_code == 200:
            return response.json().get("response", "No response")
        else:
            return f"[ERROR] Ollama API request failed: {response.text}"
    except Exception as e:
        return f"[ERROR] Ollama communication failed: {e}"

def send_file_to_ollama(filepath):
    """Upload a file to Ollama for analysis."""
    try:
        with open(filepath, "r") as f:
            file_content = f.read()
        prompt = f"Analyze the following file content:\n{file_content}"
        return send_to_ollama(prompt)
    except Exception as e:
        return f"[ERROR] File upload failed: {e}"

def send_to_siem(siem, data):
    """Send data to a SIEM tool based on network location configuration."""
    if SIEM_TOOLS.get(siem):
        print(f"[INFO] Sending data to {siem.upper()} SIEM at {SIEM_TOOLS[siem]}...")
        # Example: Uncomment and configure the below line for actual integration.
        # response = requests.post(f"http://{SIEM_TOOLS[siem]}/ingest", json={"data": data})
    else:
        print(f"[INFO] No network location configured for {siem.upper()} SIEM.")

# ---------------------------
# FORENSIC IMAGE ANALYSIS
# ---------------------------
def analyze_memory_dump(file_path):
    """Analyze a memory dump using Volatility."""
    print(f"[INFO] Running Volatility on {file_path}...")
    results = {}
    commands = [
        f"volatility -f {file_path} imageinfo",
        f"volatility -f {file_path} pslist",
        f"volatility -f {file_path} netscan",
        f"volatility -f {file_path} filescan",
    ]
    for cmd in commands:
        output = run_command(cmd)
        results[cmd] = output
        print(output)
    report_file = f"{REPORT_DIR}/{os.path.basename(file_path)}_memory_analysis.json"
    with open(report_file, "w") as f:
        json.dump(results, f, indent=4)
    print(f"[INFO] Memory analysis saved to {report_file}")
    return report_file

def analyze_disk_image(file_path):
    """Analyze a disk image using SleuthKit and Autopsy (as available)."""
    print(f"[INFO] Running SleuthKit on {file_path}...")
    results = {}
    commands = [
        f"fls -r {file_path}",
        f"icat {file_path} 512",  # Example: extract file content
        f"tsk_recover {file_path} {REPORT_DIR}/recovered_files/",
    ]
    for cmd in commands:
        output = run_command(cmd)
        results[cmd] = output
        print(output)
    report_file = f"{REPORT_DIR}/{os.path.basename(file_path)}_disk_analysis.json"
    with open(report_file, "w") as f:
        json.dump(results, f, indent=4)
    print(f"[INFO] Disk analysis saved to {report_file}")
    return report_file

def forensic_image_analysis():
    """Prompt user for forensic image file paths and analyze them."""
    print("\n[INFO] Enter paths for forensic image files (memory dumps, disk images). Type 'done' when finished.")
    file_paths = []
    while True:
        path = input("  File path: ").strip()
        if path.lower() == "done":
            break
        if os.path.exists(path):
            file_paths.append(path)
        else:
            print("[ERROR] File not found.")

    threads = []
    for path in file_paths:
        def analyze_file(file_path):
            if file_path.endswith((".mem", ".raw")):
                report = analyze_memory_dump(file_path)
            elif file_path.endswith((".dd", ".E01")):
                report = analyze_disk_image(file_path)
            else:
                print(f"[ERROR] Unsupported file type: {file_path}")
                return
            print(f"[INFO] Sending analysis report for {file_path} to Ollama...")
            ollama_response = send_file_to_ollama(report)
            print(f"Ollama Response: {ollama_response}")
            # Export to SIEMs
            for siem in SIEM_TOOLS.keys():
                send_to_siem(siem, ollama_response)
        t = threading.Thread(target=analyze_file, args=(path,))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

# ---------------------------
# STATIC MALWARE ANALYSIS
# ---------------------------
def calculate_file_hash(file_path):
    """Calculate the SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(block)
    return sha256_hash.hexdigest()

def yara_scan(file_path):
    """Scan a file using YARA rules. If on Windows and USE_WSL_FOR_YARA is True,
       run YARA via WSL.
    """
    try:
        if os.name == 'nt' and USE_WSL_FOR_YARA:
            # Using WSL to run YARA
            command = f"wsl yara -r {YARA_RULE_PATH} {file_path}"
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            output = result.stdout.strip()
            matches = output.splitlines() if output else []
            return matches
        else:
            rules = yara.compile(YARA_RULE_PATH)
            matches = rules.match(file_path)
            return matches
    except Exception as e:
        return f"[ERROR] YARA scan failed: {e}"

def extract_strings(file_path):
    """Extract human-readable strings from a file."""
    try:
        strings_command = f"strings {file_path}"
        result = subprocess.run(strings_command, shell=True, capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        return f"[ERROR] String extraction failed: {e}"

def analyze_file_metadata(file_path):
    """Analyze file metadata (PE headers) for Windows executables."""
    try:
        pe = pefile.PE(file_path)
        metadata = {
            "timestamp": pe.FILE_HEADER.TimeDateStamp,
            "imports": [entry.dll.decode(errors="ignore") for entry in pe.DIRECTORY_ENTRY_IMPORT] if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else [],
            "sections": [section.Name.decode(errors="ignore").strip() for section in pe.sections]
        }
        return metadata
    except Exception as e:
        return f"[ERROR] Metadata analysis failed: {e}"

def virus_total_check(file_hash):
    """Check file hash against VirusTotal."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return f"[ERROR] VirusTotal check failed: {response.text}"

def detect_packed_exe(file_path):
    """Detect if a PE file is packed."""
    try:
        pe = pefile.PE(file_path)
        packed = any(b".packer" in section.Name for section in pe.sections)
        return packed
    except Exception as e:
        return f"[ERROR] Packed detection failed: {e}"

def static_malware_analysis(file_path):
    """Perform static malware analysis on a given file."""
    results = {}
    print(f"[INFO] Performing static analysis on {file_path}...")
    
    # Calculate file hash
    file_hash = calculate_file_hash(file_path)
    print(f"[INFO] SHA256: {file_hash}")
    results["hash"] = file_hash

    # YARA scan
    yara_matches = yara_scan(file_path)
    print(f"[INFO] YARA Matches: {yara_matches}")
    results["yara_matches"] = yara_matches

    # Extract strings
    strings_extracted = extract_strings(file_path)
    print(f"[INFO] Extracted Strings: {strings_extracted[:200]}...")  # show first 200 chars
    results["strings"] = strings_extracted

    # File metadata analysis
    metadata = analyze_file_metadata(file_path)
    print(f"[INFO] Metadata: {metadata}")
    results["metadata"] = metadata

    # VirusTotal check
    vt_result = virus_total_check(file_hash)
    print(f"[INFO] VirusTotal Result: {vt_result}")
    results["virustotal"] = vt_result

    # Detect if packed
    packed = detect_packed_exe(file_path)
    print(f"[INFO] Is Packed: {packed}")
    results["packed"] = packed

    # Save the static analysis report
    report_file = f"{REPORT_DIR}/static_analysis_{os.path.basename(file_path)}.json"
    with open(report_file, "w") as f:
        json.dump(results, f, indent=4)
    print(f"[INFO] Static analysis report saved to {report_file}")
    return report_file

def prompt_static_analysis():
    """Prompt user for a file to perform static malware analysis."""
    file_path = input("\nEnter the path to the file for static malware analysis: ").strip()
    if os.path.exists(file_path):
        static_malware_analysis(file_path)
    else:
        print("[ERROR] File not found.")

# ---------------------------
# INTERACTIVE OLLAMA AI CHAT
# ---------------------------
def interactive_chat():
    """Interactive prompt for chatting with Ollama and uploading files."""
    print("\n[INFO] Entering Ollama Interactive Console. Type 'exit' to quit.")
    while True:
        user_input = input("You: ").strip()
        if user_input.lower() == "exit":
            break
        elif user_input.lower().startswith("upload "):
            filepath = user_input.split(" ", 1)[1]
            if os.path.exists(filepath):
                print("[INFO] Uploading file to Ollama...")
                response = send_file_to_ollama(filepath)
                print(f"Ollama: {response}")
            else:
                print("[ERROR] File not found.")
        else:
            response = send_to_ollama(user_input)
            print(f"Ollama: {response}")

# ---------------------------
# ADVANCED MODULES (IMPLEMENTED)
# ---------------------------

def real_time_monitoring():
    """Monitor a directory for new files and analyze them."""
    print("[INFO] Starting real-time monitoring...")
    monitor_dir = input("Enter the directory to monitor: ").strip()
    if not os.path.exists(monitor_dir):
        print("[ERROR] Directory not found.")
        return

    print(f"[INFO] Monitoring {monitor_dir} for new files...")
    known_files = set(os.listdir(monitor_dir))

    try:
        while True:
            time.sleep(5)  # Check every 5 seconds
            current_files = set(os.listdir(monitor_dir))
            new_files = current_files - known_files
            if new_files:
                for file in new_files:
                    file_path = os.path.join(monitor_dir, file)
                    print(f"[INFO] New file detected: {file_path}")
                    static_malware_analysis(file_path)  # Analyze the new file
                known_files = current_files
    except KeyboardInterrupt:
        print("[INFO] Stopping real-time monitoring.")

def behavioral_analysis():
    """Monitor running processes for suspicious behavior."""
    print("[INFO] Starting behavioral analysis...")
    try:
        while True:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
                print(f"Process: {proc.info['name']} (PID: {proc.info['pid']})")
                print(f"  CPU Usage: {proc.info['cpu_percent']}%")
                print(f"  Memory Usage: {proc.info['memory_info'].rss / 1024 / 1024:.2f} MB")
            time.sleep(10)  # Check every 10 seconds
    except KeyboardInterrupt:
        print("[INFO] Stopping behavioral analysis.")

def enhanced_reporting():
    """Generate reports in PDF, CSV, and HTML formats."""
    print("[INFO] Generating enhanced reports...")
    report_data = {
        "example_key": "example_value",
        "analysis_results": "example_results"
    }

    # Generate PDF report
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Forensic Analysis Report", ln=True, align="C")
    pdf.cell(200, 10, txt=json.dumps(report_data, indent=4), ln=True)
    pdf.output(f"{REPORT_DIR}/report.pdf")
    print(f"[INFO] PDF report saved to {REPORT_DIR}/report.pdf")

    # Generate CSV report
    with open(f"{REPORT_DIR}/report.csv", "w") as csv_file:
        writer = csv.writer(csv_file)
        for key, value in report_data.items():
            writer.writerow([key, value])
    print(f"[INFO] CSV report saved to {REPORT_DIR}/report.csv")

    # Generate HTML report
    with open(f"{REPORT_DIR}/report.html", "w") as html_file:
        html_file.write("<html><body><h1>Forensic Analysis Report</h1>")
        html_file.write(f"<pre>{json.dumps(report_data, indent=4)}</pre>")
        html_file.write("</body></html>")
    print(f"[INFO] HTML report saved to {REPORT_DIR}/report.html")

def incident_response_playbooks():
    """Run predefined incident response playbooks."""
    print("[INFO] Running incident response playbooks...")
    playbooks = {
        "isolate_host": "netsh advfirewall set allprofiles state on",
        "collect_logs": "wevtutil qe System /f:text",
        "kill_malicious_process": "taskkill /im malware.exe /f"
    }

    for name, command in playbooks.items():
        print(f"[INFO] Running playbook: {name}")
        result = run_command(command)
        print(result)

def network_traffic_analysis():
    """Capture and analyze network traffic using Scapy."""
    print("[INFO] Starting network traffic analysis...")
    def packet_callback(packet):
        print(f"Packet: {packet.summary()}")

    try:
        sniff(prn=packet_callback, count=10)  # Capture 10 packets
    except Exception as e:
        print(f"[ERROR] Network traffic analysis failed: {e}")

def automated_malware_classification():
    """Classify files as malicious or benign using heuristics."""
    print("[INFO] Starting automated malware classification...")
    file_path = input("Enter the path to the file for classification: ").strip()
    if not os.path.exists(file_path):
        print("[ERROR] File not found.")
        return

    # Simple heuristic: Check if the file contains suspicious strings
    suspicious_strings = ["malware", "virus", "exploit"]
    with open(file_path, "r", errors="ignore") as f:
        content = f.read()
        for s in suspicious_strings:
            if s in content:
                print(f"[WARNING] File classified as malicious: {file_path}")
                return
    print(f"[INFO] File classified as benign: {file_path}")

def timeline_correlation():
    """Correlate events from a log file with a timeline."""
    print("[INFO] Starting timeline correlation...")
    log_file = input("Enter the path to the log file: ").strip()
    if not os.path.exists(log_file):
        print("[ERROR] Log file not found.")
        return

    with open(log_file, "r") as f:
        logs = f.readlines()
        for log in logs:
            print(f"Log Entry: {log.strip()}")

def anomaly_detection():
    """Detect anomalies in a dataset using simple statistics."""
    print("[INFO] Starting anomaly detection...")
    dataset = [10, 12, 11, 15, 10, 100, 11, 12]  # Example dataset
    mean = sum(dataset) / len(dataset)
    std_dev = (sum((x - mean) ** 2 for x in dataset) / len(dataset)) ** 0.5

    print(f"Mean: {mean}, Standard Deviation: {std_dev}")
    for value in dataset:
        if abs(value - mean) > 2 * std_dev:
            print(f"[WARNING] Anomaly detected: {value}")

def advanced_modules_menu():
    print("\n--- Advanced Modules ---")
    print("1. Real-Time Monitoring")
    print("2. Behavioral Analysis of Processes")
    print("3. Enhanced Reporting Options")
    print("4. Automated Incident Response Playbooks")
    print("5. Network Traffic Analysis")
    print("6. Automated Malware Classification")
    print("7. Timeline Correlation with External Logs")
    print("8. Machine Learning Anomaly Detection")
    print("9. Return to Main Menu")
    choice = input("Select an option: ").strip()
    if choice == "1":
        real_time_monitoring()
    elif choice == "2":
        behavioral_analysis()
    elif choice == "3":
        enhanced_reporting()
    elif choice == "4":
        incident_response_playbooks()
    elif choice == "5":
        network_traffic_analysis()
    elif choice == "6":
        automated_malware_classification()
    elif choice == "7":
        timeline_correlation()
    elif choice == "8":
        anomaly_detection()
    elif choice == "9":
        return
    else:
        print("[ERROR] Invalid choice.")

# ---------------------------
# MAIN MENU
# ---------------------------
def main_menu():
    if not os.path.exists(REPORT_DIR):
        os.makedirs(REPORT_DIR)

    ask_for_siem_network_locations()

    while True:
        print("\n=== Forensic Automation Suite ===")
        print("1. Forensic Image Analysis")
        print("2. Static Malware Analysis")
        print("3. Interactive DeepSeek AI Chat")
        print("4. Advanced Modules")
        print("5. Exit")
        choice = input("Select an option: ").strip()

        if choice == "1":
            forensic_image_analysis()
        elif choice == "2":
            prompt_static_analysis()
        elif choice == "3":
            interactive_chat()
        elif choice == "4":
            advanced_modules_menu()
        elif choice == "5":
            print("Exiting...")
            break
        else:
            print("[ERROR] Invalid choice, please try again.")

if __name__ == "__main__":
    main_menu()
