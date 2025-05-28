# core/file_integrity_monitor.py
import hashlib
import time
import os

class FileIntegrityMonitor:
    def __init__(self, watch_files):
        self.watch_files = watch_files
        self.baseline = self._generate_hashes()

    def _generate_hashes(self):
        hashes = {}
        for file in self.watch_files:
            if os.path.exists(file):
                with open(file, 'rb') as f:
                    hashes[file] = hashlib.sha256(f.read()).hexdigest()
        return hashes

    def monitor_changes(self):
        print("[*] FileIntegrityMonitor: Watching for unauthorized file changes...")
        while True:
            for file in self.watch_files:
                if not os.path.exists(file):
                    continue
                with open(file, 'rb') as f:
                    current_hash = hashlib.sha256(f.read()).hexdigest()
                    if self.baseline.get(file) and self.baseline[file] != current_hash:
                        print(f"[!] ALERT: File modified => {file}")
                        self.baseline[file] = current_hash
            time.sleep(10)
