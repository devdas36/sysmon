import re
import subprocess
import psutil
from datetime import datetime
import os

class AuditParser:
    def __init__(self, alert_engine):
        self.alert_engine = alert_engine
        self.log_file = "/var/log/audit/audit.log"
        self.syscall_table = self._build_syscall_table()
        self.patterns = {
            'syscall': re.compile(r'syscall=(\d+)'),
            'pid': re.compile(r'pid=(\d+)'),
            'args': re.compile(r'a\d+="(.*?)"'),
            'exe': re.compile(r'exe="(.*?)"')
        }
        self._validate_log_file()

    def _build_syscall_table(self):
        """Parse syscall numbers from system headers"""
        syscall_table = {}
        header_paths = [
            '/usr/include/x86_64-linux-gnu/asm/unistd_64.h',  # Kali/Debian
            '/usr/include/asm/unistd_64.h',                   # Generic
            '/usr/include/asm-generic/unistd.h'               # Fallback
        ]
        
        for path in header_paths:
            if os.path.exists(path):
                try:
                    with open(path, 'r') as f:
                        for line in f:
                            if line.startswith('#define __NR_'):
                                parts = line.strip().split()
                                name = parts[1][5:]  # Remove "__NR_"
                                num = int(parts[2])
                                syscall_table[num] = name
                    break  # Use first valid header
                except Exception:
                    continue
        return syscall_table

    def _validate_log_file(self):
        if not os.path.exists(self.log_file):
            raise FileNotFoundError(f"Audit log {self.log_file} not found! Run: sudo systemctl start auditd")
        if not os.access(self.log_file, os.R_OK):
            raise PermissionError(f"Need sudo to read {self.log_file}!")

    def get_process_info(self, pid):
        try:
            process = psutil.Process(pid)
            return {
                'name': process.name(),
                'cmdline': ' '.join(process.cmdline()),
                'parent': process.ppid()
            }
        except psutil.NoSuchProcess:
            return {'name': 'Zombie Process', 'cmdline': 'N/A'}

    def parse_line(self, line):
        parsed = {'timestamp': datetime.now().isoformat()}
        for key, pattern in self.patterns.items():
            match = pattern.search(line)
            if match:
                if key == 'syscall':
                    num = int(match.group(1))
                    parsed[key] = self.syscall_table.get(num, f"unknown({num})")
                else:
                    parsed[key] = match.group(1)
        
        if 'pid' in parsed:
            pid = int(parsed['pid'])
            parsed.update(self.get_process_info(pid))
            parsed['args'] = self.parse_args(parsed.get('args', ''))
        
        return parsed if 'syscall' in parsed else None

    def parse_args(self, args):
        return [arg for arg in args.split(',') if arg.strip()]

    def tail_logs(self):
        proc = subprocess.Popen(['tail', '-F', self.log_file], stdout=subprocess.PIPE)
        while True:
            line = proc.stdout.readline()
            if line:
                parsed = self.parse_line(line.decode())
                if parsed:
                    self.alert_engine.process_event(parsed)
