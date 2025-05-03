# System Call Monitoring Tool

[![Python Version](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Linux-based CLI tool for real-time system call monitoring with security alerts, inspired by APT/malware detection patterns.

## Features

- Real-time system call monitoring with process context
- Malicious pattern detection (customizable rules)
- Visual and audible alerts for suspicious activity
- Process tree visualization (PID/PPID tracking)
- Whitelisting for trusted processes
- Export capabilities (JSON/CSV)
- Metasploit-like CLI interface with rich visualization

## Requirements

- Linux Kernel 4.4+ (recommended: 5.10+)
- Python 3.8+
- auditd framework
- Root privileges

## Installation

### 1. Clone Repository
```bash
git clone https://github.com/yourusername/sysmon.git
cd sysmon
```
### 2. Install Dependencies
```bash
# Python packages
pip install -r requirements.txt

# System packages (Kali/Debian)
sudo apt update
sudo apt install auditd psutil python3-tk
sudo apt install linux-headers-$(uname -r)
```
### 3. Configure auditd
```bash
# Start auditd service
sudo systemctl start auditd
sudo systemctl enable auditd

# Add monitoring rules
sudo auditctl -a always,exit -S execve -k process_monitor
sudo auditctl -a always,exit -S ptrace -k process_monitor
```
## Configuration
Edit configuration files in `config/` directory:

`malicious_patterns.yaml`
```yaml
syscalls:
  - execve
  - ptrace
  - openat
  - keyctl

dangerous_args:
  - "O_WRONLY"
  - "PROT_EXEC"
  - "/dev/shm"
```

`whitelist.yaml`
```yaml
pids:
  - 1        # systemd
  - 1234     # your trusted process

processes:
  - "sshd"
  - "bash"

commands:
  - "sudo apt update"
```
### Usage
Basic Monitoring
```
sudo python3 sysmon.py
```
With Sound Alerts
```
sudo python3 sysmon.py --sound
```
### Interface Navigation
```
Main Menu:
1. Live Monitoring      - Real-time system call display
2. View Security Alerts - Show triggered alerts
3. Export Logs          - Save logs to JSON/CSV
4. Exit                 - Quit program
```
### Keybindings

`Ctrl+C` - Exit program and auto-save logs

`↑/↓` - Navigate menus

`Enter` - Select option

## License
MIT License - See [LICENSE](./LICENSE) for details

## Disclaimer
This tool is for educational and authorized security testing purposes only. Misuse of this software is strictly prohibited.
