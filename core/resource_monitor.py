# core/resource_monitor.py
import psutil
import time

class ResourceMonitor:
    def __init__(self, cpu_threshold=80, mem_threshold=70):
        self.cpu_threshold = cpu_threshold
        self.mem_threshold = mem_threshold

    def monitor_usage(self):
        print("[*] ResourceMonitor: Monitoring process resource usage...")
        while True:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    if proc.info['cpu_percent'] > self.cpu_threshold or proc.info['memory_percent'] > self.mem_threshold:
                        print(f"[!] High Resource Usage Detected: {proc.info}")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            time.sleep(5)
