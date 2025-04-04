import os
import pdfkit
from langchain_community.tools import ShellTool
import subprocess
import time
import json
import questionary
from typing import Dict, Any, Optional
import re
import requests
from ollama import Client
import pefile

os.environ['WKHTMLTOPDF_PATH'] = r'"C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe"'
YARA_RULE_PATH = "rules/malware_rules.yar"
USE_WSL_FOR_YARA = True  # Set to True if using WSL on Windows
yara = None
try:
    import yara
except ImportError:
    print("[INFO] YARA is not installed. YARA scanning will be skipped unless running in WSL.")

class CyberSecurityAI:
    def __init__(self):
        try:
            print("Initializing Ollama client...")
            self.client = Client(host='http://localhost:11434')
    
            # Check available models
            models = self.client.list()
        
            # Check if any model contains 'deepseek' in its name
            if not hasattr(models, 'models') or not any(
                'deepseek' in model.model.lower() 
                for model in models.models
            ):
                print("\nERROR: DeepSeek model not found in Ollama")
                print("Available models:", [model.model for model in getattr(models, 'models', [])])
                print("Please install it with: ollama pull deepseek-r1")
                raise RuntimeError("DeepSeek model not available")
        
            # Test with actual model name
            test_response = self.client.generate(
                model='deepseek-r1',  # Use the exact model name from the list
                prompt='test'
            )
            if not test_response:
                raise ConnectionError("Could not connect to Ollama service")
        
            print("DeepSeek model connected successfully!")
        
            # Set up shell tools with safety checks
            self.powershell_tool = ShellTool()
            self.wsl_tool = ShellTool(shell="wsl")
        
            # Restricted command list (for safety)
            self.allowed_commands = {
                'powershell': ['Get-Process', 'Get-Service', 'Get-NetTCPConnection', 
                              'Get-ChildItem', 'Get-Content', 'Measure-Object',
                              'Select-Object', 'Where-Object', 'Export-Csv'],
                'wsl': ['file', 'strings', 'objdump', 'md5sum', 'sha256sum', 'volatility',
                       'grep', 'awk', 'sed', 'cat', 'less', 'head', 'tail']
            }
            self._check_dependencies()
            self._check_pdf_dependencies()
        
        except Exception as e:
            print(f"Failed to initialize Ollama client: {e}")
            raise RuntimeError("Could not connect to Ollama service with DeepSeek model")

    def convert_windows_path_to_wsl(self, windows_path):
        """Convert a Windows file path to a WSL-compatible path."""
        windows_path = windows_path.strip('"')
        windows_path = windows_path.replace("\\", "/")
    
        if ":/" in windows_path:
            drive_letter = windows_path[0].lower()
            wsl_path = windows_path.replace(f"{drive_letter.upper()}:/", f"/mnt/{drive_letter}/")
            return wsl_path
        else:
            return windows_path
        
    def _find_wkhtmltopdf(self) -> Optional[str]:
        """Search for wkhtmltopdf in common locations"""
        possible_paths = [
            os.environ.get('WKHTMLTOPDF_PATH', ''),
            r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe',
            r'C:\Program Files (x86)\wkhtmltopdf\bin\wkhtmltopdf.exe',
            '/usr/local/bin/wkhtmltopdf',
            '/usr/bin/wkhtmltopdf',
            'wkhtmltopdf'  # Try system PATH
        ]
    
        for path in possible_paths:
            if path and os.path.isfile(path):
                return os.path.abspath(path)
        return None

    def _check_pdf_dependencies(self) -> bool:
        """Check if PDF generation is possible"""
        if self._find_wkhtmltopdf():
            return True
        
        print("\nPDF Generation Requirements:")
        print("1. Install wkhtmltopdf from https://wkhtmltopdf.org/")
        print("2. Add it to your system PATH or")
        print("3. Set WKHTMLTOPDF_PATH environment variable to its location")
        return False

    def _check_dependencies(self):
        """Verify required dependencies are available"""
        try:
            import pdfkit
            try:
                pdfkit.from_string('<html></html>', 'test_delete_me.pdf')
                os.remove('test_delete_me.pdf')
            except (OSError, IOError):
                print("\nWARNING: wkhtmltopdf not found. PDF reports will not work.")
                print("Install from: https://wkhtmltopdf.org/")
        except ImportError:
            print("\nWARNING: pdfkit not installed. Install with: pip install pdfkit")

    def get_analysis_target(self) -> Optional[str]:
        """Safely get and validate analysis target from user"""
        while True:
            target = questionary.text(
                "Enter the file path to analyze (or 'quit' to cancel):"
            ).ask()
        
            if target.lower() in ('quit', 'exit', 'cancel'):
                return None
            
            try:
                return self._sanitize_file_path(target)
            except ValueError as e:
                print(f"Invalid path: {e}")
                if not questionary.confirm("Try again?").ask():
                    return None

    def _secure_command_execution(self, command: str, file_path: str, shell_type: str) -> Dict[str, Any]:
        """Execute commands with proper path escaping"""
        verified_path = self._sanitize_file_path(file_path)
    
        # Convert path for WSL commands
        if shell_type == "wsl":
            verified_path = self.convert_windows_path_to_wsl(verified_path)
            # Escape single quotes and wrap the entire path in quotes
            verified_path = verified_path.replace("'", "'\\''")
            verified_path = f"'{verified_path}'"
    
        # Update command with properly escaped path
        command = command.replace(file_path, verified_path)
    
        return self.execute_command(command, shell_type)

    def _sanitize_file_path(self, path: str) -> str:
        """Sanitize and validate file paths with strict checks for Windows/Linux"""
        try:
            # Step 1: Normalize path (convert to raw string, handle slashes)
            path = path.strip(' "\'\t\n\r')  # Remove surrounding quotes/whitespace
            path = os.path.normpath(path)     # Convert to OS-specific path

            # Step 2: Handle network paths (Windows UNC)
            if os.name == 'nt' and path.startswith('\\\\'):
                # Ensure UNC format (\\server\share\path)
                if not path.startswith('\\\\?\\UNC\\'):
                    path = '\\\\?\\UNC\\' + path[2:]
            elif os.name == 'nt' and len(path) > 260:  # Handle long paths
                if not path.startswith('\\\\?\\'):
                    path = '\\\\?\\' + os.path.abspath(path)

            # Step 3: Verify existence
            if not os.path.exists(path):
                raise FileNotFoundError(f"Path not found: {path}")
            if not os.path.isfile(path):
                raise ValueError(f"Not a file: {path}")

            return path

        except Exception as e:
            raise ValueError(f"Path sanitization failed: {str(e)}")

    def execute_command(self, command: str, shell_type: str = "powershell") -> Dict[str, Any]:
        """Execute a command with safety checks"""
        result = {
            "success": False,
            "output": "",
            "error": "",
            "command_executed": command
        }
        
        try:
            if shell_type not in ["powershell", "wsl"]:
                raise ValueError(f"Invalid shell type: {shell_type}")
                
            if not self._is_command_allowed(command, shell_type):
                raise PermissionError(f"Command not allowed: {command}")
                
            if shell_type == "powershell":
                process = subprocess.Popen(
                    ["powershell", "-Command", command],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
            else:
                process = subprocess.Popen(
                    ["wsl"] + command.split(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
            stdout, stderr = process.communicate()
            
            if process.returncode == 0:
                result["success"] = True
                result["output"] = stdout
            else:
                result["error"] = stderr
                
        except Exception as e:
            result["error"] = str(e)
            
        return result
        
    def _is_command_allowed(self, command: str, shell_type: str) -> bool:
        """Check if command is allowed"""
        for allowed in self.allowed_commands[shell_type]:
            if command.strip().startswith(allowed):
                return True
                
        if shell_type == "powershell" and "|" in command:
            parts = [p.strip() for p in command.split("|")]
            return all(self._is_command_allowed(part, shell_type) for part in parts)
            
        return False
        
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Analyze a file using DeepSeek via Ollama with secure path handling"""
        try:
            safe_path = self._sanitize_file_path(file_path)
            analysis = {
                "file_info": {},
                "hashes": {},
                "strings": "",
                "pe_info": "",
                "ai_analysis": "",
                "original_path": file_path,
                "safe_path": safe_path
            }

            # Note: No quotes around {safe_path} here - they'll be added in _secure_command_execution
            file_type = self._secure_command_execution(
                f"file --mime-type -b {safe_path}", 
                safe_path, 
                "wsl"
            )
            if file_type["success"]:
                analysis["file_info"]["type"] = file_type["output"].strip()
            
            md5_result = self._secure_command_execution(
                f"md5sum {safe_path}",
                safe_path,
                "wsl"
            )
            if md5_result["success"]:
                analysis["hashes"]["md5"] = md5_result["output"].split()[0]
            
            sha256_result = self._secure_command_execution(
                f"sha256sum {safe_path}",
                safe_path,
                "wsl"
            )
            if sha256_result["success"]:
                analysis["hashes"]["sha256"] = sha256_result["output"].split()[0]
        
            strings_result = self._secure_command_execution(
                f"strings {safe_path} | head -n 500",
                safe_path,
                "wsl"
            )
            if strings_result["success"]:
                analysis["strings"] = strings_result["output"]
        
            if "executable" in analysis["file_info"].get("type", "").lower():
                pe_result = self._secure_command_execution(
                    f"objdump -x {safe_path} | head -n 200",
                    safe_path,
                    "wsl"
                )
                if pe_result["success"]:
                    analysis["pe_info"] = pe_result["output"]
                    ##############################################################
                """Analyze file metadata (PE headers) for Windows executables."""
                try:
                    pe = pefile.PE(file_path)
                    metadata = f"\nTimestamp: {pe.FILE_HEADER.TimeDateStamp}\n"

                    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                        imports = ", ".join(entry.dll.decode(errors="ignore") for entry in pe.DIRECTORY_ENTRY_IMPORT)
                        metadata += f"Imports: {imports}\n"
                    else:
                        metadata += "Imports: None\n"

                    sections = ", ".join(section.Name.rstrip(b'\x00').decode(errors="ignore") for section in pe.sections)
                    metadata += f"Sections: {sections}\n"

                    analysis["pe_info"] += metadata  # Append metadata to the string
                except Exception as e:
                    error_msg = f"[ERROR] PE header analysis failed: {e}\n"
                    print(error_msg)
                    analysis["pe_info"] += error_msg

                """Check file hash against VirusTotal."""
                try:
                    url = f"https://www.virustotal.com/api/v3/files/{sha256_result}"
                    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
                    response = requests.get(url, headers=headers)

                    if response.status_code == 200:
                        vt_data = response.json()
                        attributes = vt_data.get("data", {}).get("attributes", {})
        
                        detection_stats = attributes.get("last_analysis_stats", {})
                        threat_classifications = attributes.get("popular_threat_classification", {}).get("popular_threat_name", [])
                        threat_labels = ", ".join(t["value"] for t in threat_classifications)

                        vt_info = (
                            f"\nVirusTotal Analysis:\n"
                            f"Malicious: {detection_stats.get('malicious', 0)}\n"
                            f"Undetected: {detection_stats.get('undetected', 0)}\n"
                            f"First Seen: {attributes.get('first_submission_date', 'Unknown')}\n"
                            f"Threat Labels: {threat_labels}\n"
                            f"Report Link: {vt_data['data']['links']['self']}\n"
                        )
                        analysis["pe_info"] += vt_info  # Append VirusTotal analysis
                    else:
                        error_msg = f"[ERROR] VirusTotal check failed: {response.text}\n"
                        print(error_msg)
                        analysis["pe_info"] += error_msg
                except Exception as e:
                    error_msg = f"[ERROR] VirusTotal API check failed: {e}\n"
                    print(error_msg)
                    analysis["pe_info"] += error_msg

                """Detect if a PE file is packed."""
                try:
                    pe = pefile.PE(file_path)
                    packed = any(b"UPX" in section.Name for section in pe.sections)  # UPX is a common packer
                    pack_status = "Yes" if packed else "No"
                    analysis["pe_info"] += f"\nPacked File: {pack_status}\n"
                except Exception as e:
                    error_msg = f"[ERROR] Packing analysis failed: {e}\n"
                    print(error_msg)
                    analysis["pe_info"] += error_msg

    #########################################################################################################3
            
            analysis["ai_analysis"] = self._get_ai_analysis(analysis)
        
        except ValueError as e:
            return {"error": str(e), "input_path": file_path}
        except Exception as e:
            return {"error": f"Analysis failed: {str(e)}", "input_path": file_path}
        
        return analysis

    def _get_ai_analysis(self, analysis_data: Dict[str, Any]) -> str:
        """Generate cybersecurity reports with more flexible validation"""
        print("\n[ANALYSIS] Starting AI report generation...")
        start = time.time()

        # Configuration
        MAX_RETRIES = 3
        md5_hash = analysis_data.get('hashes', {}).get('md5', 'N/A')
        sha256_hash = analysis_data.get('hashes', {}).get('sha256', 'N/A')
        pe_info = analysis_data.get('pe_info', 'No PE header information available')[:2000]
        strings_analysis = analysis_data.get('strings', 'No strings extracted')[:2000]

        def generate_report() -> str:
            """Generate the report with clear instructions"""

            prompts = [
                "/Generative_Prompts/Overview_Prompt.txt",
                "/Generative_Prompts/Technical_Analysis_Prompt.txt",
                "/Generative_Prompts/Behavioural_Indicators_Prompt.txt",
                "/Generative_Prompts/Threat_Assessment_Prompt.txt",
                "/Generative_Prompts/Recommendation_Prompt.txt",
                ]

            responses = ""
        
            try:
                for prompt in prompts:
                    prompt = open(f"{os.getcwd()}{prompt}", "r").read()
                    response = self.client.generate(
                        model='deepseek-r1',
                        prompt=prompt,
                        options={
                            'temperature': 0.5,
                            'num_predict': 700000,
                            'top_k': 60
                        }
                    )

                    responses += response.response
                return responses
            except Exception as e:
                print(f"[ERROR] Generation failed: {str(e)}")
                return ""

        # Try to get the best possible report
        best_report = ""
        for attempt in range(MAX_RETRIES):
            print(f"[ATTEMPT] Generation attempt {attempt + 1}")
            report = generate_report()
        
            # Basic quality checks
            if not report:
                continue
            
            # Ensure we have some minimal content
            if ("<h2>Overview</h2>" in report or 
                "<h2>Technical Findings</h2>" in report or
                "MITRE" in report or "ATT&CK" in report):
                best_report = report
                break
            
            if len(report.split()) > 2000:  # Minimum word count
                best_report = report
                break

        # If we got something reasonable, use it
        if best_report and len(best_report.split()) > 1000:
            print("[SUCCESS] Using generated report")
            end = time.time()
            Generation_Timer = end - start
            print(f"[SUCCESS] Generation time took: {Generation_Timer}s")
            return best_report

        # Fallback minimal analysis
        print("[WARNING] Using fallback analysis")
        end = time.time()
        Generation_Timer = end - start
        print(f"[SUCCESS] Generation time took: {Generation_Timer}s")
        return f"""
        <h1>Basic Malware Analysis</h1>
    
        <h2>File Information</h2>
        <table>
            <tr><th>Type</th><td>Windows PE Executable</td></tr>
            <tr><th>MD5</th><td>{md5_hash}</td></tr>
            <tr><th>SHA256</th><td>{sha256_hash}</td></tr>
        </table>
    
        <h2>Key Findings</h2>
        <ul>
            <li>Contains suspicious API calls: {', '.join(set(re.findall(r'[A-Za-z0-9]+\.dll|CreateProcess|ShellExecute|VirtualAlloc', strings_analysis)))[:10]}</li>
            <li>PE headers indicate a GUI Windows executable</li>
            <li>Entry point at 0x{pe_info.split('AddressOfEntryPoint')[1][:10].split()[0] if 'AddressOfEntryPoint' in pe_info else 'N/A'}</li>
        </ul>
    
        <h2>Recommended Actions</h2>
        <ol>
            <li>Isolate and monitor in sandbox environment</li>
            <li>Check for network connections</li>
            <li>Scan for similar hashes in threat intelligence feeds</li>
        </ol>
    
        <h3>PE Header Excerpt</h3>
        <pre>{pe_info[:1000] if pe_info else 'No PE info available'}</pre>
        """

    def generate_report(self, analysis_results: Dict[str, Any], output_path: str) -> bool:
        """Generate PDF report with improved formatting and filtered strings"""
        try:
            output_path = (os.path.abspath(output_path))
            if not output_path.endswith('.pdf'):
                output_path += '.pdf'
    
            # Process AI analysis to split into sections
            ai_analysis = analysis_results.get("ai_analysis", "")
        
            # Split analysis into sections if they exist
            sections = {
                "Potential Malicious Indicators": "",
                "Behavioral Analysis": "",
                "MITRE ATT&CK Techniques": "",
                "Recommended Detection Rules": "",
                "Suggested Mitigation Strategies": "",
                "Artifacts Found": "",
                "Next Steps": ""
            }
        
            current_section = None
            for line in ai_analysis.split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                # Check for section headers
                for section in sections:
                    if line.startswith(section):
                        current_section = section
                        continue
                    
                if current_section:
                    sections[current_section] += line + '\n'
        
            # Filter suspicious strings
            all_strings = analysis_results.get("strings", "")
            suspicious_strings = []
            suspicious_patterns = [
                r'\.dll', r'\.exe', r'http://', r'https://', 
                r'\\', r'powershell', r'cmd\.exe', r'regsvr32',
                r'CreateProcess', r'WinExec', r'ShellExecute',
                r'GetProcAddress', r'LoadLibrary', r'VirtualAlloc',
                r'WriteProcessMemory', r'ReadProcessMemory'
            ]
        
            for line in all_strings.split('\n'):
                line = line.strip()
                if any(re.search(pattern, line, re.IGNORECASE) for pattern in suspicious_patterns):
                    suspicious_strings.append(line)
        
            # Create HTML content with improved structure
            html_template = f"""
            <html>
            <head>
                <title>DeepSeek Cybersecurity Analysis Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 2em; }}
                    h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; }}
                    h2 {{ color: #34495e; border-bottom: 1px solid #eee; padding-top: 0.5em; }}
                    .section {{ margin-bottom: 2em; }}
                    .metadata {{ background: #f8f9fa; padding: 1em; border-radius: 5px; }}
                    pre {{ background: #f5f5f5; padding: 1em; border-radius: 5px; overflow-x: auto; }}
                    table {{ border-collapse: collapse; width: 100%; margin: 1em 0; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #f2f2f2; }}
                    .error {{ color: #d9534f; background: #fdf7f7; padding: 1em; border-radius: 5px; }}
                    .suspicious {{ color: #d9534f; font-weight: bold; }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>DeepSeek Cybersecurity Analysis Report</h1>
                </div>
        
                <div class="section metadata">
                    <h2>File Metadata</h2>
                    {"<div class='error'>File not found at original path: " + analysis_results.get('original_path', '') + "</div>" 
                     if 'error' in analysis_results else ''}
                    <table>
                        <tr><th>File Type</th><td>{analysis_results.get('file_info', {}).get('type', 'Unknown')}</td></tr>
                        <tr><th>MD5</th><td>{analysis_results.get('hashes', {}).get('md5', '')}</td></tr>
                        <tr><th>SHA256</th><td>{analysis_results.get('hashes', {}).get('sha256', '')}</td></tr>
                        <tr><th>Original Path</th><td>{analysis_results.get('original_path', '')}</td></tr>
                        <tr><th>Safe Path</th><td>{analysis_results.get('safe_path', '')}</td></tr>
                    </table>
                </div>
        
                <div class="section">
                    <h2>Technical Analysis</h2>
                    {re.sub(r'<think>.*?</think>', '', ai_analysis, flags=re.DOTALL)}
                </div>
        
                <div class="section">
                    <h2>Artifacts</h2>
                    <h3>Suspicious Strings</h3>
                    <pre>{'\n'.join(suspicious_strings[:500]) if suspicious_strings else 'No suspicious strings found'}</pre>
            
                    {f'<h3>PE Information (partial)</h3><pre>{analysis_results.get("pe_info", "")[:2000]}</pre>' 
                     if analysis_results.get('pe_info') else ''}
                </div>
            </body>
            </html>
            """

            # Rest of the PDF generation code remains the same...
            wkhtml_path = self._find_wkhtmltopdf()
            if wkhtml_path:
                try:
                    import pdfkit
                    config = pdfkit.configuration(wkhtmltopdf=wkhtml_path)
                    pdfkit.from_string(html_template, output_path, configuration=config)
                    return True
                except Exception as e:
                    print(f"wkhtmltopdf failed, trying alternatives: {e}")

            # Fallback to weasyprint if available
            try:
                from weasyprint import HTML
                HTML(string=html_template).write_pdf(output_path)
                print("Report generated using weasyprint")
                return True
            except ImportError:
                pass
            except Exception as e:
                print(f"weasyprint failed: {e}")

            # Final fallback: Save as HTML
            html_path = os.path.splitext(output_path)[0] + ".html"
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_template)
            print(f"Could not generate PDF. Saved HTML report instead: {html_path}")
            return False

        except Exception as e:
            print(f"Error generating report: {e}")
            return False

def main():
    print("DeepSeek Cybersecurity Research Assistant")
    
    try:
        ai = CyberSecurityAI()
        
        # First prompt: Select research type
        research_type = questionary.select(
            "What type of research are you conducting?",
            choices=[
                "Malware Analysis",
                "Disk Image Analysis",
                "Network Traffic Analysis",
                "Memory Forensics",
                "Other"
            ]
        ).ask()
        
        if research_type == "Other":
            research_type = questionary.text("Please specify your research type:").ask()

        # Get target file with retry logic
        while True:
            target = ai.get_analysis_target()
            if not target:
                print("Analysis cancelled.")
                return
                
            try:
                print(f"\nStarting analysis on: {target}")
                analysis = ai.analyze_file(target)  # Original analyze_file call with 1 argument
                break
            except Exception as e:
                print(f"Analysis failed: {e}")
                if not questionary.confirm("Try different file?").ask():
                    return

        # Generate report
        output_pdf = questionary.text(
            "Enter PDF report path:",
            default=f"{os.getcwd()}/forensics_reports/"+f"{os.path.splitext(os.path.basename(target))[0]}_report.pdf"
        ).ask()
        
        if ai.generate_report(analysis, output_pdf):
            print(f"\nSuccess! Report saved to: {os.path.abspath(output_pdf)}")
            if questionary.confirm("Open report now?").ask():
                os.startfile(os.path.abspath(output_pdf))
        
        # Additional questions based on research type
        additional_info = {}
        if research_type == "Malware Analysis":
            additional_info["sandbox"] = questionary.confirm("Run in sandboxed environment?").ask()
            additional_info["behavioral"] = questionary.confirm("Perform behavioral analysis?").ask()
            
        elif research_type == "Disk Image Analysis":
            additional_info["artifacts"] = questionary.checkbox(
                "Select artifacts to analyze:",
                choices=[
                    "Registry Hives",
                    "Event Logs",
                    "Prefetch Files",
                    "Browser History",
                    "File System Metadata"
                ]
            ).ask()
            
        # Confirm before proceeding with full analysis
        if not questionary.confirm(f"Begin {research_type} analysis on {target}?").ask():
            print("Analysis cancelled.")
            return
            
        # Perform full analysis with research type context
        print(f"\nStarting {research_type} analysis with DeepSeek...")
        analysis = ai.analyze_file(target)  # Keeping original function call
        
        # Generate final report
        if "error" not in analysis:
            print("Generating PDF report...")
            if ai.generate_report(analysis, output_pdf):
                print(f"Success! Report saved to {os.path.abspath(output_pdf)}")
                if questionary.confirm("Would you like to open the report now?").ask():
                    os.startfile(os.path.abspath(output_pdf))
            else:
                print("Failed to generate report.")
        else:
            print(f"Analysis failed: {analysis['error']}")
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
    except Exception as e:
        print(f"\nFatal error: {e}")
        print("Troubleshooting tips:")
        print("- Ensure Ollama is running (ollama serve)")
        print("- Install DeepSeek model (ollama pull deepseek)")
        print("- Check file exists and path is correct")

if __name__ == "__main__":
    try:
        import ollama
    except ImportError:
        print("Installing required Ollama package...")
        os.system("pip install ollama")
    
    main()