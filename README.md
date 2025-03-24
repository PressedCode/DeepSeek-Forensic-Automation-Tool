# Forensic AI Suite

## Overview
Forensic AI Suite is an advanced cybersecurity assistant that performs digital forensics, malware analysis, and SIEM integration. It leverages AI-driven analysis and persistent case management to assist both experts and non-experts in cybersecurity investigations.

## Features
- **AI-Powered Digital Forensics**: Perform memory and disk forensics dynamically.
- **Malware Analysis**: File hashing, YARA scanning, and VirusTotal checks.
- **Persistent Case Management**: Uses SQLite for forensic data storage.
- **Background Analysis Mode**: Periodically runs forensic checks and logs findings.
- **SIEM Integration**: Connects with Wazuh, ELK, Splunk, and HELK.
- **Windows PowerShell & WSL Support**: Executes forensic commands dynamically.
- **Automated Report Generation**: Generates structured forensic reports.

## Installation
### **Requirements**
- Python 3.x
- [Ollama](https://ollama.ai) running DeepSeek AI

### **Install Dependencies**
```sh
pip install requests sqlite3
```

### **Setup DeepSeek AI on Ollama**
Start Ollama:
```sh
ollama serve
```

### **Run the Forensic AI Suite**
```sh
python forensic_ai.py
```

## Usage
- **Analyze a file**:
  ```sh
  analyze
  ```
  Enter the file path, and the AI will generate a forensic report.

- **View past reports**:
  ```sh
  report
  ```
  Displays previous forensic findings stored in the SQLite database.

- **Exit the program**:
  ```sh
  exit
  ```

## License
This project is licensed under the MIT License. See `LICENSE` for details.

## Contributing
Contributions are welcome! Feel free to submit pull requests or report issues.

## Contact
For questions or suggestions, please create an issue on GitHub.

