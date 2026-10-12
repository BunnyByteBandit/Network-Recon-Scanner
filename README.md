# Network-Recon-Scanner

# Network Reconnaissance & Port Scanner 🛡️🔍

A multi-threaded Python network scanning tool built for security auditing and network reconnaissance. It performs TCP connect scans, identifies running services, grabs banner responses, and exports JSON audit reports.

## ✨ Features
- ⚡ **Multi-threaded Execution:** Fast scanning using Python's `ThreadPoolExecutor`.
- 🔍 **Banner Grabbing:** Service identification for common services (SSH, HTTP, FTP, etc.).
- 📊 **JSON Export:** Automatically formats output for vulnerability analysis pipelines.

## 🚀 Quickstart

```bash
# Clone repository
git clone [https://github.com/BunnyByteBandit/Network-Recon-Scanner.git](https://github.com/BunnyByteBandit/Network-Recon-Scanner.git)

# Navigate into directory
cd Network-Recon-Scanner

# Run scanner
python3 scanner.py
