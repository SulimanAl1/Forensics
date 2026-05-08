# SEC435: Chromium Browser Forensic Analyzer

### **Project Overview**
This tool is a Python-based forensic suite designed for automated artifact extraction from Google Chrome and Microsoft Edge. It was developed as part of the SEC435 Digital Forensics course to demonstrate the "Double Agent Simulation"—a scenario where suspects attempt to hide evidence through history deletion.

### **Core Features**
* **Forensic Soundness:** Uses a read-only approach to protect source evidence.
* **Integrity Verification:** Automated SHA-256 hashing for every extracted database.
* **Artifact Recovery:** Extracts history, search terms, and downloads.
* **Deleted Data Recovery:** Performs slack space carving to find erased URLs.
* **Live Triage:** Captures active browser process IDs (PIDs) and RAM usage.

### **Dependencies**
To run this tool, you need Python 3.x and the following libraries:
* `pandas` (for Excel reporting)
* `psutil` (for RAM/Process analysis)
* `hashlib` (for SHA-256 verification)
* `sqlite3` (for database interaction)

### **Usage**
1. Clone the repository.
2. Run `python main.py`.
3. Review the generated `.xlsx` forensic report.
