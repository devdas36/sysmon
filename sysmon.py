#!/usr/bin/env python3
import argparse
import threading
import time
import psutil
import json
from cli.interface import MainInterface
from core.audit_parser import AuditParser
from core.alert_engine import AlertEngine
from core.log_exporter import export_logs
from core.port_scan_detector import PortScanDetector
from core.resource_monitor import ResourceMonitor
from core.file_integrity_monitor import FileIntegrityMonitor
import os

activity_log_file = "system_activity.json"

process_snapshot = set()
network_snapshot = set()

def monitor_processes(interval=5):
    global process_snapshot
    while True:
        current_procs = {p.pid for p in psutil.process_iter(['pid', 'name'])}
        new_procs = current_procs - process_snapshot
        ended_procs = process_snapshot - current_procs

        if new_procs or ended_procs:
            log_entry = {
                "timestamp": time.ctime(),
                "new_processes": list(new_procs),
                "ended_processes": list(ended_procs)
            }
            with open(activity_log_file, "a") as f:
                f.write(json.dumps(log_entry) + "\n")

        process_snapshot = current_procs
        time.sleep(interval)

def monitor_network(interval=5):
    global network_snapshot
    while True:
        current_conns = {(conn.laddr, conn.raddr, conn.status) for conn in psutil.net_connections() if conn.raddr}
        new_conns = current_conns - network_snapshot

        if new_conns:
            log_entry = {
                "timestamp": time.ctime(),
                "new_connections": [
                    {
                        "local": str(laddr),
                        "remote": str(raddr),
                        "status": status
                    }
                    for (laddr, raddr, status) in new_conns
                ]
            }
            with open(activity_log_file, "a") as f:
                f.write(json.dumps(log_entry) + "\n")

        network_snapshot = current_conns
        time.sleep(interval)

def main():
    parser = argparse.ArgumentParser(description="Advanced System Call Monitoring Tool")
    parser.add_argument("-c", "--config", default="config/malicious_patterns.yaml", help="Path to config file")
    parser.add_argument("--sound", action="store_true", help="Enable alert sounds")
    args = parser.parse_args()

    alert_engine = AlertEngine(args.config, sound_alerts=args.sound)
    audit_parser = AuditParser(alert_engine)
    port_scan = PortScanDetector()
    resource_monitor = ResourceMonitor()
    fim = FileIntegrityMonitor(watch_files=["/etc/passwd", "/etc/hosts"])

    # Start real-time monitoring thread
    monitor_thread = threading.Thread(target=audit_parser.tail_logs, daemon=True)
    monitor_thread.start()

    # Start background threads for additional monitoring
    threading.Thread(target=monitor_processes, daemon=True).start()
    threading.Thread(target=monitor_network, daemon=True).start()
    threading.Thread(target=port_scan.monitor_ports, daemon=True).start()
    threading.Thread(target=resource_monitor.monitor_usage, daemon=True).start()
    threading.Thread(target=fim.monitor_changes, daemon=True).start()

    try:
        MainInterface(audit_parser, alert_engine, port_scan, resource_monitor, fim).run()
    except KeyboardInterrupt:
        export_logs(alert_engine.alerts, "monitor_logs.json")  # Auto-export on exit
        print("\n[!] Exiting...")

if __name__ == "__main__":
    main()