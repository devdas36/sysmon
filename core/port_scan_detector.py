# core/port_scan_detector.py
import psutil
import time
from collections import defaultdict

class PortScanDetector:
    def __init__(self, threshold=10, interval=5):
        self.threshold = threshold
        self.interval = interval
        self.connection_log = defaultdict(list)

    def monitor_ports(self):
        print("[*] PortScanDetector: Monitoring for potential scans...")
        while True:
            conns = psutil.net_connections(kind='inet')
            timestamp = time.time()
            for conn in conns:
                if conn.raddr:
                    ip = conn.raddr.ip
                    port = conn.raddr.port
                    self.connection_log[ip].append((port, timestamp))

            self.detect_scans(timestamp)
            time.sleep(self.interval)

    def detect_scans(self, current_time):
        for ip, entries in list(self.connection_log.items()):
            recent_ports = [p for p, t in entries if current_time - t <= self.interval]
            if len(set(recent_ports)) >= self.threshold:
                print(f"[!] Possible Port Scan Detected from {ip} on ports {set(recent_ports)}")
                self.connection_log[ip] = []  # reset after detection
