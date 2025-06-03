from rich.console import Console
from rich.table import Table
from rich.live import Live
from prompt_toolkit import prompt
from prompt_toolkit.styles import Style
import threading
import pyfiglet
import time
import psutil
import os

class MainInterface:
    def __init__(self, audit_parser, alert_engine, port_scan_detector, resource_monitor, file_integrity_monitor):
        self.console = Console()
        self.audit_parser = audit_parser
        self.alert_engine = alert_engine
        self.port_scan_detector = port_scan_detector
        self.resource_monitor = resource_monitor
        self.file_integrity_monitor = file_integrity_monitor
        self.running = True
        self.style = Style.from_dict({
            'option': 'cyan bold',
            'alert': 'red reverse',
            'prompt': 'yellow bold'
        })

    def generate_table(self):
        """Generate the live monitoring table with proper markup"""
        table = Table(
            title="[bold]Live System Calls[/bold]",
            expand=True,
            show_header=True,
            header_style="bold magenta"
        )
        table.add_column("Time", style="cyan", no_wrap=True)
        table.add_column("PID", style="magenta")
        table.add_column("Process", min_width=12)
        table.add_column("Syscall", style="bold")
        table.add_column("Arguments", min_width=20)

        last_events = self.alert_engine.all_events[-10:]
        
        if not last_events:
            table.add_row(
                "--:--:--", "-", "No events detected", 
                "Run commands in another terminal", "-"
            )
        else:
            for event in last_events:
                is_alert = event in self.alert_engine.alerts
                syscall_text = (
                    f"[red]{event['syscall']}[/]" 
                    if is_alert 
                    else event['syscall']
                )
                
                args_text = ', '.join(event.get('args', []))[:25] + (
                    '...' if len(event.get('args', [])) > 25 else ''
                )
                
                table.add_row(
                    event['timestamp'][11:19],
                    str(event['pid']),
                    event.get('name', 'unknown')[:12],
                    syscall_text,
                    args_text
                )
        return table

    def show_resources(self):
        """Display system resource usage"""
        self.console.clear()
        table = Table(
            title="[bold]System Resource Usage[/bold]",
            show_header=True,
            header_style="bold blue"
        )
        table.add_column("CPU %", style="red")
        table.add_column("Memory %", style="green")
        table.add_column("Process Count")
        table.add_column("Network Connections")
        
        cpu_percent = psutil.cpu_percent()
        mem_percent = psutil.virtual_memory().percent
        process_count = len(psutil.pids())
        net_connections = len(psutil.net_connections())
        
        table.add_row(
            f"{cpu_percent:.1f}%",
            f"{mem_percent:.1f}%",
            str(process_count),
            str(net_connections)
        )
        
        self.console.print(table)
        
        # Show top processes
        top_table = Table(
            title="[bold]Top Processes[/bold]",
            show_header=True,
            header_style="bold magenta"
        )
        top_table.add_column("PID")
        top_table.add_column("Name")
        top_table.add_column("CPU %")
        top_table.add_column("Memory %")
        
        for proc in sorted(psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']), 
                          key=lambda p: p.info['cpu_percent'], reverse=True)[:5]:
            info = proc.info
            top_table.add_row(
                str(info['pid']),
                info['name'][:20],
                f"{info['cpu_percent']:.1f}%",
                f"{info['memory_percent']:.1f}%"
            )
            
        self.console.print(top_table)
        prompt("[Press Enter to return]", style=self.style)

    def show_network(self):
        """Display network connections"""
        self.console.clear()
        table = Table(
            title="[bold]Active Network Connections[/bold]",
            show_header=True,
            header_style="bold green"
        )
        table.add_column("Protocol")
        table.add_column("Local Address")
        table.add_column("Remote Address")
        table.add_column("Status")
        table.add_column("PID")
        
        for conn in psutil.net_connections():
            if conn.raddr:
                table.add_row(
                    conn.type.name,
                    f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "-",
                    f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-",
                    conn.status,
                    str(conn.pid))
        
        self.console.print(table)
        prompt("[Press Enter to return]", style=self.style)

    def show_file_monitor(self):
        """Display file integrity monitoring status"""
        self.console.clear()
        table = Table(
            title="[bold]File Integrity Monitoring[/bold]",
            show_header=True,
            header_style="bold yellow"
        )
        table.add_column("File Path")
        table.add_column("Status")
        table.add_column("Last Check")
        
        for file, current_hash in self.file_integrity_monitor.baseline.items():
            status = "[green]OK[/green]" if os.path.exists(file) else "[red]Missing[/red]"
            table.add_row(
                file,
                status,
                time.ctime(os.path.getmtime(file)) if os.path.exists(file) else "N/A"
            )
        
        self.console.print(table)
        prompt("[Press Enter to return]", style=self.style)

    def live_monitoring(self):
        """Real-time monitoring view with proper refresh"""
        try:
            with Live(console=self.console, refresh_per_second=1) as live:
                while self.running:
                    live.update(self.generate_table())
                    time.sleep(1)
        except KeyboardInterrupt:
            self.running = False

    def show_alerts(self):
        """Display security alerts table"""
        self.console.clear()
        table = Table(
            title="[bold red]Security Alerts[/bold red]",
            show_lines=True
        )
        table.add_column("Time", style="cyan")
        table.add_column("PID", style="magenta")
        table.add_column("Process")
        table.add_column("Syscall", style="bold red")
        table.add_column("Arguments")
        
        for alert in self.alert_engine.alerts[-10:]:
            table.add_row(
                alert['timestamp'][11:19],
                str(alert['pid']),
                alert.get('name', 'unknown')[:15],
                alert['syscall'],
                ', '.join(alert.get('args', []))[:35]
            )
            
        self.console.print(table)
        prompt("[Press Enter to return]", style=self.style)

    def export_menu(self):
        """Handle log exports"""
        filename = prompt("Enter filename: ", style=self.style)
        fmt = prompt("Format (json/csv): ", style=self.style).lower()
        
        if fmt not in ['json', 'csv']:
            self.console.print("[red]Invalid format! Use json/csv[/red]")
            time.sleep(1)
            return
            
        try:
            self.alert_engine.export_logs(filename, fmt)
            self.console.print(f"[green]Logs exported to {filename}![/green]")
        except Exception as e:
            self.console.print(f"[red]Error: {str(e)}[/red]")
        time.sleep(1)

    def run(self):
        """Main run loop"""
        self.running = True
        while self.running:
            self.console.clear()
            choice = self.show_main_menu()
            
            if choice == '1':
                self.live_monitoring()
            elif choice == '2':
                self.show_alerts()
            elif choice == '3':
                self.show_resources()
            elif choice == '4':
                self.show_network()
            elif choice == '5':
                self.show_file_monitor()
            elif choice == '6':
                self.export_menu()
            elif choice == '7':
                self.running = False
            else:
                self.console.print("[red]Invalid option![/red]")
                time.sleep(1)

    def show_main_menu(self):
        print(pyfiglet.figlet_format("SYSMON", font="slant"))
        """Display main menu"""
        menu = Table.grid(padding=(1,2), pad_edge=True)
        menu.add_column(style="bold cyan")
        menu.add_row("1", "Live System Call Monitoring")
        menu.add_row("2", "View Security Alerts")
        menu.add_row("3", "System Resources")
        menu.add_row("4", "Network Connections")
        menu.add_row("5", "File Integrity Monitor")
        menu.add_row("6", "Export Logs")
        menu.add_row("7", "Exit")
        
        self.console.print(menu)
        return prompt("Select an option: ", style=self.style)