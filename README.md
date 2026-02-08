# drop-analyzer

⚡ **Instant Incident Dropzone Triage Tool**

A one-command security analysis tool that automatically extracts archives, scans for threats using entropy and YARA rules, and ranks suspicious files—helping SOC analysts and DFIR teams speed up initial incident response.

## 🚀 Features

- **Automatic Archive Extraction**: Supports ZIP, 7z, RAR, TAR, GZ
- **Multi-Layer Analysis**: 
  - File entropy calculation
  - YARA rule matching
  - Packer detection (UPX, ASPack)
  - Malicious LNK & Office macro detection
- **Threat Scoring**: Ranks files by suspicion level
- **Clean Output**: Rich terminal tables with clear findings

## 📦 Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/kakashi-kx/drop-analyzer.git
   cd drop-analyzer
2. **Install system dependencies (Debian/Ubuntu):
```bash
sudo apt update
sudo apt install p7zip-full -y
```
3. **Set up Python environment:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 🛠️ Usage

```bash
# Analyze a single file or archive
python3 dropreport.py suspicious.zip

# Analyze a directory
python3 dropreport.py ./malware_drop/
```

<details>
<summary><b>📊 Click to view example output</b></summary>

```
╔══════════════════════════════════════════════════╗
║ drop-analyzer v0.1 — Threat Triage Results       ║
╚══════════════════════════════════════════════════╝
Top 3 hottest artifacts:
╭───────┬──────────────────┬────────────────────────╮
│ Score │ File             │ Why suspicious         │
├───────┼──────────────────┼────────────────────────┤
│ 92/100 │ evil.lnk        │ YARA: Malicious_LNK    │
│ 78/100 │ payload.exe     │ High entropy (7.9/8.0) │
│ 45/100 │ invoice.doc     │ Suspicious macro       │
╰───────┴──────────────────┴────────────────────────╯
```
</details>

## 📁 Project Structure

drop-analyzer/
├── dropreport.py          # Main analysis script
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── .gitignore            # Python-specific ignores
└── LICENSE               # MIT License

## 🔧 Requirements

-Python 3.8+

-p7zip system package

-Python packages: rich, python-magic, yara-python

## 🤝 Contributing
Found a bug or have a feature request? Please open an issue or submit a pull request!

## 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
