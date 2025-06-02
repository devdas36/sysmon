from rich.console import Console
from rich.table import Table
from rich.live import Live
from prompt_toolkit import prompt
from prompt_toolkit.styles import Style
import threading
import pyfiglet
import time


class MainInterface:
    def __init__(self, audit_parser, alert_engine):
        self.console = Console()
        self.audit_parser = audit_parser
        self.alert_engine = alert_engine
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
                self.export_menu()
            elif choice == '4':
                self.running = False
            else:
                self.console.print("[red]Invalid option![/red]")
                time.sleep(1)

    def show_main_menu(self):
        print(pyfiglet.figlet_format("SYSMON", font="slant"))
        """Display main menu"""
        menu = Table.grid(padding=(1,2), pad_edge=True)
        menu.add_column(style="bold cyan")
        menu.add_row("1", "Live Monitoring (Last 10 events)")
        menu.add_row("2", "View Security Alerts")
        menu.add_row("3", "Export Logs")
        menu.add_row("4", "Exit")
        
        self.console.print(menu)
        return prompt("Select an option: ", style=self.style)
