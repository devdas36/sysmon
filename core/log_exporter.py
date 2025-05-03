import json
import csv
from datetime import datetime

def export_logs(logs, filename="sysmon_logs.json"):
    """Export logs to JSON/CSV based on file extension"""
    try:
        if filename.endswith('.json'):
            with open(filename, 'w') as f:
                json.dump(logs, f, indent=2)
        elif filename.endswith('.csv'):
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "PID", "Process", "Syscall", "Arguments"])
                for log in logs:
                    writer.writerow([
                        log.get('timestamp', ''),
                        log.get('pid', ''),
                        log.get('name', ''),
                        log.get('syscall', ''),
                        ','.join(log.get('args', []))
                    ])
        return True
    except Exception as e:
        return False
