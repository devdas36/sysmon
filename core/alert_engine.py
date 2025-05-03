import yaml
import json
import csv
from datetime import datetime
import platform
import os

class AlertEngine:
    def __init__(self, config_path, sound_alerts=False):
        self.config = self._load_config(config_path)
        self.whitelist = self._load_config("config/whitelist.yaml")
        self.alerts = []
        self.all_events = []
        self.sound_alerts = sound_alerts

    def _load_config(self, path):
        with open(path) as f:
            return yaml.safe_load(f) or {}

    def _play_alert_sound(self):
        if self.sound_alerts:
            if platform.system() == 'Windows':
                import winsound
                winsound.Beep(2000, 500)
            else:
                os.system('echo -e "\a"')

    def process_event(self, event):
        self.all_events.append(event)
        
        if self._is_whitelisted(event):
            return

        if self._is_malicious(event):
            self.alerts.append(event)
            self._play_alert_sound()

    def _is_whitelisted(self, event):
        return any([
            event['pid'] in self.whitelist.get('pids', []),
            event['name'] in self.whitelist.get('processes', []),
            event['cmdline'] in self.whitelist.get('commands', [])
        ])

    def _is_malicious(self, event):
        syscall_check = event['syscall'] in self.config.get('syscalls', [])
        args_check = any(arg in event.get('args', []) 
                       for arg in self.config.get('dangerous_args', []))
        return syscall_check or args_check

    def export_logs(self, filename, format='json'):
        if format == 'json':
            with open(filename, 'w') as f:
                json.dump(self.all_events, f)
        elif format == 'csv':
            with open(filename, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=self.all_events[0].keys())
                writer.writeheader()
                writer.writerows(self.all_events)
