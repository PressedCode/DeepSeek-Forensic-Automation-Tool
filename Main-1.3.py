import os
import pdfkit
from langchain_community.tools import ShellTool
import subprocess
import json
import questionary
from typing import Dict, Any
from ollama import Client

class CyberSecurityAI:
    def __init__(self):
        try:
            print("Initializing Ollama client with DeepSeek model...")
            self.client = Client(host='http://localhost:11434')
            
            # Test the connection
            test_response = self.client.generate(model='deepseek-r1', prompt='test')
            if not test_response:
                raise ConnectionError("Could not connect to Ollama service")
                
            print("DeepSeek model connected via Ollama successfully!")
            
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
            
        except Exception as e:
            print(f"Failed to initialize Ollama client: {e}")
            raise RuntimeError("Could not connect to Ollama service with DeepSeek model")

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
        """Analyze a file using DeepSeek via Ollama"""
        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}
            
        analysis = {
            "file_info": {},
            "hashes": {},
            "strings": "",
            "pe_info": "",
            "ai_analysis": ""
        }
        
        try:
            # File type detection
            file_type = self.execute_command(f"file --mime-type -b '{file_path}'", "wsl")
            if file_type["success"]:
                analysis["file_info"]["type"] = file_type["output"].strip()
                
            # Hash calculation
            analysis["hashes"]["md5"] = self.execute_command(f"md5sum '{file_path}'", "wsl")["output"].split()[0]
            analysis["hashes"]["sha256"] = self.execute_command(f"sha256sum '{file_path}'", "wsl")["output"].split()[0]
            
            # Strings extraction
            strings_result = self.execute_command(f"strings '{file_path}' | head -n 500", "wsl")
            analysis["strings"] = strings_result["output"] if strings_result["success"] else ""
            
            # PE analysis if executable
            if "executable" in analysis["file_info"].get("type", "").lower():
                pe_result = self.execute_command(f"objdump -x '{file_path}' | head -n 200", "wsl")
                analysis["pe_info"] = pe_result["output"] if pe_result["success"] else ""
                
            # Get AI analysis
            analysis["ai_analysis"] = self._get_ai_analysis(analysis)
            
        except Exception as e:
            analysis["error"] = str(e)
            
        return analysis
        
    def _get_ai_analysis(self, analysis_data: Dict[str, Any]) -> str:
        """Generate analysis using DeepSeek via Ollama"""
        prompt = f"""
        Perform a professional cybersecurity analysis on this file:

        File Information:
        - Type: {analysis_data.get('file_info', {}).get('type', 'unknown')}
        - MD5: {analysis_data.get('hashes', {}).get('md5', '')}
        - SHA256: {analysis_data.get('hashes', {}).get('sha256', '')}

        Strings Analysis (first 500 lines):
        {analysis_data.get('strings', '')}

        PE Information (if executable):
        {analysis_data.get('pe_info', 'N/A')}

        Provide a detailed report covering:
        1. Potential malicious indicators
        2. Behavioral analysis
        3. MITRE ATT&CK techniques likely used
        4. Recommended detection rules (YARA, Sigma)
        5. Suggested mitigation strategies
        6. Any interesting artifacts found
        7. Recommended next steps for investigation

        Respond with only the analysis content, no additional commentary or formatting.
        """
        
        try:
            response = self.client.generate(
                model='deepseek',
                prompt=prompt,
                options={
                    'temperature': 0.7,
                    'num_predict': 2000
                }
            )
            return response['response']
        except Exception as e:
            return f"Error generating analysis: {str(e)}"
        
    def generate_report(self, analysis_results: Dict[str, Any], output_path: str) -> bool:
        """Generate PDF report"""
        try:
            formatted_analysis = analysis_results.get("ai_analysis", "").replace("\n", "<br>")
            
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
                </style>
            </head>
            <body>
                <h1>DeepSeek Cybersecurity Analysis Report</h1>
                
                <div class="section metadata">
                    <h2>File Metadata</h2>
                    <table>
                        <tr><th>File Type</th><td>{analysis_results.get('file_info', {}).get('type', 'Unknown')}</td></tr>
                        <tr><th>MD5</th><td>{analysis_results.get('hashes', {}).get('md5', '')}</td></tr>
                        <tr><th>SHA256</th><td>{analysis_results.get('hashes', {}).get('sha256', '')}</td></tr>
                    </table>
                </div>
                
                <div class="section">
                    <h2>Technical Analysis</h2>
                    {formatted_analysis}
                </div>
                
                <div class="section">
                    <h2>Artifacts</h2>
                    <h3>Strings Output (partial)</h3>
                    <pre>{analysis_results.get('strings', '')[:2000]}</pre>
                    
                    {f'<h3>PE Information (partial)</h3><pre>{analysis_results.get("pe_info", "")[:2000]}</pre>' 
                     if analysis_results.get('pe_info') else ''}
                </div>
            </body>
            </html>
            """
            
            pdfkit.from_string(html_template, output_path)
            return True
            
        except Exception as e:
            print(f"Error generating report: {e}")
            return False

def main():
    print("DeepSeek Cybersecurity Research Assistant (Ollama)")
    
    try:
        print("Initializing DeepSeek AI via Ollama...")
        ai = CyberSecurityAI()
        
        # Get research details
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
        
        target = questionary.text("Enter the file path or object to analyze:").ask()
        output_pdf = questionary.text("Enter the desired PDF report path:", default="analysis_report.pdf").ask()
        
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
            
        # Confirm before proceeding
        if not questionary.confirm(f"Begin {research_type} analysis on {target}?").ask():
            print("Analysis cancelled.")
            return
            
        # Perform analysis
        print(f"\nStarting {research_type} analysis with DeepSeek...")
        
        if os.path.exists(target):
            print("Analyzing file...")
            analysis = ai.analyze_file(target)
        else:
            print(f"Target {target} not found as file. Treating as special analysis...")
            analysis = {"error": "Non-file analysis not yet implemented"}
        
        # Generate report
        if "error" not in analysis:
            print("Generating PDF report...")
            if ai.generate_report(analysis, output_pdf):
                print(f"Success! Report saved to {output_pdf}")
            else:
                print("Failed to generate report.")
        else:
            print(f"Analysis failed: {analysis['error']}")
            
        # Offer to open the report
        if os.path.exists(output_pdf) and questionary.confirm("Would you like to open the report now?").ask():
            os.startfile(output_pdf)
            
    except Exception as e:
        print(f"Fatal error: {e}")
        print("Please ensure you have:")
        print("- Ollama running locally (ollama serve)")
        print("- DeepSeek model installed (ollama pull deepseek)")
        print("- All required Python dependencies installed")

if __name__ == "__main__":
    # First install required packages if not already installed
    try:
        import ollama
    except ImportError:
        print("Installing required Ollama package...")
        os.system("pip install ollama")
    
    main()