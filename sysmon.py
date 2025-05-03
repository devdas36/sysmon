#!/usr/bin/env python3
import argparse
import threading
from cli.interface import MainInterface
from core.audit_parser import AuditParser
from core.alert_engine import AlertEngine
from core.log_exporter import export_logs

def main():
    parser = argparse.ArgumentParser(description="Advanced System Call Monitoring Tool")
    parser.add_argument("-c", "--config", default="config/malicious_patterns.yaml", help="Path to config file")
    parser.add_argument("--sound", action="store_true", help="Enable alert sounds")
    args = parser.parse_args()

    alert_engine = AlertEngine(args.config, sound_alerts=args.sound)
    audit_parser = AuditParser(alert_engine)
    
    # Start real-time monitoring thread
    monitor_thread = threading.Thread(target=audit_parser.tail_logs, daemon=True)
    monitor_thread.start()

    try:
        MainInterface(audit_parser, alert_engine).run()
    except KeyboardInterrupt:
        export_logs(alert_engine.alerts, "monitor_logs.json")  # Auto-export on exit
        print("\n[!] Exiting...")

if __name__ == "__main__":
    main()
