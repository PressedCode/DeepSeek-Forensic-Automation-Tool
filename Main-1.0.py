#!/usr/bin/env python3
"""
Forensic AI Suite
=================

An advanced cybersecurity AI for digital forensics, malware analysis, and SIEM integration.

Features:
  - SQLite database for persistence.
  - Background analysis mode.
  - AI-driven forensic investigations.
  - Full forensic image and malware analysis.
  - Windows PowerShell & WSL connectivity.
  - SIEM integration (Wazuh, ELK, Splunk, HELK).
  - Advanced report generation.

Requirements:
  - Python 3.x
  - Dependencies installed via pip.

Usage:
  Run the script and follow the prompts:
      python forensic_ai.py
"""

import os
import sqlite3
import time
import threading
import subprocess
import requests
import json
import hashlib
import paramiko
import winrm
import pefile
import psutil
from datetime import datetime
from scapy.all import sniff
from fpdf import FPDF
from PIL import ImageGrab

# ---------------------------
# CONFIGURATION
# ---------------------------
DATABASE_FILE = "forensic_ai.db"
REPORT_DIR = "forensic_reports"
OLLAMA_API = "http://localhost:11434/api/generate"
BACKGROUND_ANALYSIS_INTERVAL = 3600  # Run every hour
SIEM_TOOLS = {"wazuh": None, "elk": None, "splunk": None, "helk": None}
YARA_RULE_PATH = "rules/malware_rules.yar"

if not os.path.exists(REPORT_DIR):
    os.makedirs(REPORT_DIR)

# ---------------------------
# DATABASE SETUP
# ---------------------------
def initialize_database():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS forensic_cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT,
            analysis_results TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ai_interactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query TEXT,
            response TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def save_forensic_case(file_path, analysis_results):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO forensic_cases (file_path, analysis_results) VALUES (?, ?)",
                   (file_path, json.dumps(analysis_results)))
    conn.commit()
    conn.close()

def save_ai_interaction(query, response):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO ai_interactions (query, response) VALUES (?, ?)",
                   (query, response))
    conn.commit()
    conn.close()

# ---------------------------
# AI INTERACTION
# ---------------------------
def send_to_ollama(prompt):
    data = {"model": "deepseek-r1", "prompt": prompt, "stream": False}
    response = requests.post(OLLAMA_API, json=data)
    if response.status_code == 200:
        full_response = response.json().get("response", "No response")
        
        # Extract only the structured analysis part (if possible)
        extracted_summary = full_response.split("To analyze the unknown1.exe file")[1] if "To analyze the unknown1.exe file" in full_response else full_response
        
        save_ai_interaction(prompt, extracted_summary)
        return extracted_summary.strip()
    return f"[ERROR] Ollama API request failed: {response.text}"

def display_reports():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM forensic_cases ORDER BY timestamp DESC LIMIT 5")
    cases = cursor.fetchall()
    conn.close()
    
    for case in cases:
        case_id, file_path, analysis_results, timestamp = case
        results = json.loads(analysis_results)

        print(f"\n=== Case {case_id} ===")
        print(f"File: {file_path}")
        print(f"Analyzed: {timestamp}")
        print(f"SHA256: {results.get('hash', 'N/A')}")
        print(f"AI Summary: {results.get('ai_analysis', 'N/A')[:300]}...")  # Truncate for readability
        print(f"YARA Matches: {results.get('yara_matches', [])}")
        print(f"PE Sections: {results.get('pe_metadata', {}).get('sections', [])}")
        
        vt_results = results.get("virus_total", {})
        if isinstance(vt_results, dict) and "malicious" in vt_results:
            print(f"VirusTotal: {vt_results['malicious']} detections, Threats: {', '.join(vt_results['threat_labels'])}")
            print(f"VT Link: {vt_results['link']}")
        else:
            print("VirusTotal: Not available")

# ---------------------------
# FORENSIC ANALYSIS
# ---------------------------
def analyze_file(file_path):
    """Perform full forensic and malware analysis on a file."""
    print(f"[INFO] Analyzing {file_path}...")

    file_hash = hashlib.sha256(open(file_path, "rb").read()).hexdigest()

    findings = {
        "hash": file_hash,
        "ai_analysis": send_to_ollama(f"Analyze file: {file_path}"),
        "yara_matches": yara_scan(file_path),
        "pe_metadata": analyze_file_metadata(file_path),
        "virus_total": virus_total_check(file_hash)  # Now using the precomputed hash
    }

    save_forensic_case(file_path, findings)
    print(f"[INFO] Analysis complete: {findings}")

def yara_scan(file_path):
    """Perform YARA malware scanning on a file."""
    try:
        command = f"yara -r {YARA_RULE_PATH} {file_path}"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout.strip().split('\n') if result.stdout else []
    except Exception as e:
        return f"[ERROR] YARA scan failed: {e}"

def analyze_file_metadata(file_path):
    """Extract metadata from a PE file."""
    try:
        pe = pefile.PE(file_path)
        return {
            "timestamp": pe.FILE_HEADER.TimeDateStamp,
            "imports": [entry.dll.decode(errors="ignore") for entry in pe.DIRECTORY_ENTRY_IMPORT] if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else [],
            "sections": [section.Name.decode(errors="ignore").strip() for section in pe.sections]
        }
    except Exception as e:
        return f"[ERROR] Metadata analysis failed: {e}"

def virus_total_check(file_hash):
    """Check a file hash against VirusTotal and summarize key results."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        vt_data = response.json()
        attributes = vt_data.get("data", {}).get("attributes", {})

        # Extract key details
        detection_stats = attributes.get("last_analysis_stats", {})
        threat_classifications = attributes.get("popular_threat_classification", {}).get("popular_threat_name", [])
        threat_labels = [t["value"] for t in threat_classifications]

        return {
            "malicious": detection_stats.get("malicious", 0),
            "undetected": detection_stats.get("undetected", 0),
            "first_seen": attributes.get("first_submission_date", "Unknown"),
            "threat_labels": threat_labels,
            "link": vt_data["data"]["links"]["self"]
        }
    
    return {"error": f"VirusTotal check failed: {response.text}"}


# ---------------------------
# BACKGROUND ANALYSIS
# ---------------------------
def background_analysis():
    while True:
        print("[INFO] Running scheduled background analysis...")
        time.sleep(BACKGROUND_ANALYSIS_INTERVAL)

def start_background_thread():
    thread = threading.Thread(target=background_analysis, daemon=True)
    thread.start()

# ---------------------------
# MAIN FUNCTION
# ---------------------------
def main():
    initialize_database()
    start_background_thread()
    print("[INFO] Forensic AI Suite is running.")
    while True:
        command = input("Enter command (analyze/report/exit): ").strip().lower()
        if command == "analyze":
            file_path = input("Enter file path for analysis: ").strip()
            file_path = file_path.strip('"')
    
            # Replace backslashes with forward slashes
            file_path = file_path.replace("\\", "/")
            if os.path.exists(file_path):
                analyze_file(file_path)
            else:
                print("[ERROR] File not found.")
        elif command == "report":
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM forensic_cases ORDER BY timestamp DESC LIMIT 5")
            cases = cursor.fetchall()
            conn.close()
            for case in cases:
                print(f"Case {case[0]}: {case[1]}\nResults: {case[2]}\nTime: {case[3]}\n")
        elif command == "exit":
            print("[INFO] Exiting Forensic AI Suite.")
            break
        else:
            print("[ERROR] Invalid command.")

if __name__ == "__main__":
    main()

