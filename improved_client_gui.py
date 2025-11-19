#!/usr/bin/env python3
"""
Improved Client GUI - Named Data Networks Framework
Fully functional client with proper integration
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
from datetime import datetime

from common import create_interest_packet, DataPacket
from communication_module import CommunicationModule

class ImprovedClientGUI:
    def __init__(self, root, client_id="Client"):
        self.root = root
        self.root.title(f"NDN Client - {client_id}")
        self.root.geometry("1400x850")
        
        # Client configuration
        self.client_id = client_id
        self.node_name = f"Client-{client_id}"
        
        # Network configuration
        self.router_host = "127.0.0.1"
        self.router_port = 8001
        
        # Initialize communication module
        self.comm_module = CommunicationModule(self.node_name, port=0)
        
        # Statistics
        self.stats = {
            'sent': 0,
            'received': 0,
            'errors': 0,
            'cache_hits': 0,
            'timeouts': 0
        }
        
        # Track if we're currently sending (prevent double-send)
        self.sending = False
        
        self.setup_ui()
        
    def setup_ui(self):
        """Create the user interface"""
        
        # Configure root
        self.root.configure(bg='#ECF0F1')
        
        # Header
        self._create_header()
        
        # Main content area
        main_container = tk.Frame(self.root, bg='#ECF0F1')
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Left panel - Request builder
        left_panel = tk.Frame(main_container, bg='#ECF0F1', width=450)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=False, padx=(0, 5))
        left_panel.pack_propagate(False)
        
        self._create_request_panel(left_panel)
        self._create_quick_actions(left_panel)
        self._create_statistics_panel(left_panel)
        
        # Right panel - Response log
        right_panel = tk.Frame(main_container, bg='#ECF0F1')
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        self._create_response_log(right_panel)
        
        # Command input at bottom
        self._create_command_panel()
        
        # Status bar
        self._create_status_bar()
        
        # Initial log message
        self.log("="*100, 'separator')
        self.log(f"NDN Client '{self.client_id}' initialized", 'success')
        self.log(f"Router: {self.router_host}:{self.router_port}", 'info')
        self.log(f"Type commands in the box below or use Quick Action buttons", 'info')
        self.log("="*100 + "\n", 'separator')
    
    def _create_header(self):
        """Create header with title and connection info"""
        header = tk.Frame(self.root, bg='#2C3E50', height=70)
        header.pack(fill=tk.X, side=tk.TOP)
        header.pack_propagate(False)
        
        # Title
        title_frame = tk.Frame(header, bg='#2C3E50')
        title_frame.pack(side=tk.LEFT, padx=20, pady=15)
        
        tk.Label(
            title_frame,
            text=f"Named Data Networks Client",
            font=('Arial', 18, 'bold'),
            bg='#2C3E50',
            fg='white'
        ).pack(anchor='w')
        
        tk.Label(
            title_frame,
            text=f"Client ID: {self.client_id}",
            font=('Arial', 11),
            bg='#2C3E50',
            fg='#BDC3C7'
        ).pack(anchor='w')
        
        # Connection status
        status_frame = tk.Frame(header, bg='#2C3E50')
        status_frame.pack(side=tk.RIGHT, padx=20, pady=15)
        
        self.connection_label = tk.Label(
            status_frame,
            text=f"● Connected",
            font=('Arial', 12, 'bold'),
            bg='#2C3E50',
            fg='#27AE60'
        )
        self.connection_label.pack(anchor='e')
        
        tk.Label(
            status_frame,
            text=f"{self.router_host}:{self.router_port} (UDP)",
            font=('Arial', 10),
            bg='#2C3E50',
            fg='#BDC3C7'
        ).pack(anchor='e')
    
    def _create_request_panel(self, parent):
        """Create request builder panel"""
        frame = tk.LabelFrame(
            parent,
            text=" Build Request ",
            font=('Arial', 11, 'bold'),
            fg='#2C3E50',
            bg='#ECF0F1'
        )
        frame.pack(fill=tk.X, pady=(0, 10))
        
        inner = tk.Frame(frame, bg='white')
        inner.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Operation
        op_frame = tk.Frame(inner, bg='white')
        op_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(
            op_frame,
            text="Operation:",
            font=('Arial', 10, 'bold'),
            bg='white',
            fg='#34495E',
            width=12,
            anchor='w'
        ).pack(side=tk.LEFT)
        
        self.operation_var = tk.StringVar(value="READ")
        
        for op in ["READ", "WRITE", "PERMISSION"]:
            color = '#27AE60' if op == "READ" else ('#3498DB' if op == "WRITE" else '#9B59B6')
            tk.Radiobutton(
                op_frame,
                text=op,
                variable=self.operation_var,
                value=op,
                font=('Arial', 10),
                bg='white',
                fg=color,
                selectcolor='white',
                activebackground='white'
            ).pack(side=tk.LEFT, padx=10)
        
        # Content Name
        name_frame = tk.Frame(inner, bg='white')
        name_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(
            name_frame,
            text="Content Name:",
            font=('Arial', 10, 'bold'),
            bg='white',
            fg='#34495E',
            width=12,
            anchor='w'
        ).pack(side=tk.LEFT)
        
        self.content_name_entry = tk.Entry(
            name_frame,
            font=('Consolas', 11),
            bg='#F8F9FA',
            relief=tk.FLAT,
            highlightthickness=1,
            highlightbackground='#BDC3C7',
            highlightcolor='#3498DB'
        )
        self.content_name_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 0))
        self.content_name_entry.insert(0, "/dlsu/hello")
        self.content_name_entry.bind('<Return>', lambda e: self.send_request())
        
        # Send button
        btn_frame = tk.Frame(inner, bg='white')
        btn_frame.pack(fill=tk.X, pady=(15, 5))
        
        self.send_btn = tk.Button(
            btn_frame,
            text="Send Request",
            command=self.send_request,
            bg='#3498DB',
            fg='white',
            font=('Arial', 11, 'bold'),
            relief=tk.FLAT,
            padx=30,
            pady=10,
            cursor='hand2'
        )
        self.send_btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 5))
        
        tk.Button(
            btn_frame,
            text="Clear Logs",
            command=self.clear_logs,
            bg='#E74C3C',
            fg='white',
            font=('Arial', 11, 'bold'),
            relief=tk.FLAT,
            padx=30,
            pady=10,
            cursor='hand2'
        ).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(5, 0))
    
    def _create_quick_actions(self, parent):
        """Create quick action buttons"""
        frame = tk.LabelFrame(
            parent,
            text=" Quick Actions ",
            font=('Arial', 11, 'bold'),
            fg='#2C3E50',
            bg='#ECF0F1'
        )
        frame.pack(fill=tk.X, pady=(0, 10))
        
        inner = tk.Frame(frame, bg='white')
        inner.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        actions = [
            ("/dlsu/hello", "READ", "Hello DLSU", '#27AE60'),
            ("/dlsu/storage/test", "READ", "Storage Test", '#16A085'),
            ("/storage/test", "READ", "Alt Storage", '#2980B9'),
            ("/dlsu/write/file", "WRITE", "Write File", '#8E44AD')
        ]
        
        for path, op, label, color in actions:
            btn = tk.Button(
                inner,
                text=label,
                command=lambda p=path, o=op: self.quick_request(o, p),
                bg=color,
                fg='white',
                font=('Arial', 10, 'bold'),
                relief=tk.FLAT,
                pady=8,
                cursor='hand2'
            )
            btn.pack(fill=tk.X, pady=3)
    
    def _create_statistics_panel(self, parent):
        """Create statistics panel"""
        frame = tk.LabelFrame(
            parent,
            text=" Statistics ",
            font=('Arial', 11, 'bold'),
            fg='#2C3E50',
            bg='#ECF0F1'
        )
        frame.pack(fill=tk.BOTH, expand=True)
        
        inner = tk.Frame(frame, bg='white')
        inner.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.stat_labels = {}
        
        stats = [
            ('Sent', 'sent', '#3498DB'),
            ('Received', 'received', '#27AE60'),
            ('Errors', 'errors', '#E74C3C'),
            ('Cache Hits', 'cache_hits', '#F39C12'),
            ('Timeouts', 'timeouts', '#95A5A6')
        ]
        
        for label, key, color in stats:
            row = tk.Frame(inner, bg='white')
            row.pack(fill=tk.X, pady=5)
            
            tk.Label(
                row,
                text=f"{label}:",
                font=('Arial', 10),
                bg='white',
                fg='#7F8C8D',
                anchor='w',
                width=12
            ).pack(side=tk.LEFT)
            
            value = tk.Label(
                row,
                text="0",
                font=('Arial', 12, 'bold'),
                bg='white',
                fg=color,
                anchor='e'
            )
            value.pack(side=tk.RIGHT)
            
            self.stat_labels[key] = value
        
        # Success rate
        rate_row = tk.Frame(inner, bg='white')
        rate_row.pack(fill=tk.X, pady=(10, 5))
        
        tk.Label(
            rate_row,
            text="Success Rate:",
            font=('Arial', 10, 'bold'),
            bg='white',
            fg='#2C3E50',
            anchor='w',
            width=12
        ).pack(side=tk.LEFT)
        
        self.success_rate_label = tk.Label(
            rate_row,
            text="0.0%",
            font=('Arial', 13, 'bold'),
            bg='white',
            fg='#16A085',
            anchor='e'
        )
        self.success_rate_label.pack(side=tk.RIGHT)
    
    def _create_response_log(self, parent):
        """Create response log panel"""
        frame = tk.LabelFrame(
            parent,
            text=" Response Log ",
            font=('Arial', 11, 'bold'),
            fg='#2C3E50',
            bg='#ECF0F1'
        )
        frame.pack(fill=tk.BOTH, expand=True)
        
        self.log_text = scrolledtext.ScrolledText(
            frame,
            font=('Consolas', 10),
            bg='#FAFAFA',
            relief=tk.FLAT,
            padx=10,
            pady=10,
            wrap=tk.WORD
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure tags
        self.log_text.tag_config('success', foreground='#27AE60', font=('Consolas', 10, 'bold'))
        self.log_text.tag_config('error', foreground='#E74C3C', font=('Consolas', 10, 'bold'))
        self.log_text.tag_config('info', foreground='#3498DB', font=('Consolas', 10))
        self.log_text.tag_config('warning', foreground='#F39C12', font=('Consolas', 10))
        self.log_text.tag_config('header', foreground='#8E44AD', font=('Consolas', 11, 'bold'))
        self.log_text.tag_config('separator', foreground='#BDC3C7', font=('Consolas', 9))
        self.log_text.tag_config('timestamp', foreground='#95A5A6', font=('Consolas', 9))
        self.log_text.tag_config('content', foreground='#34495E', font=('Consolas', 10))
    
    def _create_command_panel(self):
        """Create command input panel"""
        cmd_frame = tk.Frame(self.root, bg='#34495E', height=70)
        cmd_frame.pack(fill=tk.X, side=tk.BOTTOM, padx=10, pady=(5, 10))
        cmd_frame.pack_propagate(False)
        
        tk.Label(
            cmd_frame,
            text="Command:",
            font=('Arial', 10, 'bold'),
            bg='#34495E',
            fg='white'
        ).pack(side=tk.LEFT, padx=(15, 10), pady=20)
        
        self.command_entry = tk.Entry(
            cmd_frame,
            font=('Consolas', 11),
            bg='white',
            relief=tk.FLAT
        )
        self.command_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=20)
        self.command_entry.bind('<Return>', lambda e: self.handle_command())
        
        tk.Button(
            cmd_frame,
            text="Execute",
            command=self.handle_command,
            bg='#27AE60',
            fg='white',
            font=('Arial', 10, 'bold'),
            relief=tk.FLAT,
            padx=20,
            cursor='hand2'
        ).pack(side=tk.LEFT, padx=(5, 15), pady=20)
    
    def _create_status_bar(self):
        """Create status bar"""
        status_frame = tk.Frame(self.root, relief=tk.SUNKEN, bd=1, bg='#2C3E50')
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.status_label = tk.Label(
            status_frame,
            text=f"Ready | Client: {self.client_id} | Router: {self.router_host}:{self.router_port}",
            anchor=tk.W,
            font=('Arial', 9),
            bg='#2C3E50',
            fg='#ECF0F1',
            padx=10,
            pady=3
        )
        self.status_label.pack(fill=tk.X)
    
    def handle_command(self):
        """Handle command input"""
        command = self.command_entry.get().strip()
        
        if not command:
            return
        
        self.command_entry.delete(0, tk.END)
        
        self.log(f"\n> {command}", 'info')
        
        parts = command.lower().split(maxsplit=1)
        cmd = parts[0]
        
        if cmd == "help":
            self.show_help()
        elif cmd == "stats":
            self.show_stats()
        elif cmd == "clear":
            self.clear_logs()
        elif cmd == "read" and len(parts) > 1:
            path = parts[1].strip()
            self.quick_request("READ", path)
        elif cmd == "write" and len(parts) > 1:
            path = parts[1].strip()
            self.quick_request("WRITE", path)
        elif cmd == "permission" and len(parts) > 1:
            path = parts[1].strip()
            self.quick_request("PERMISSION", path)
        else:
            self.log(f"Unknown command: {command}\nType 'help' for available commands.", 'warning')
    
    def show_help(self):
        """Show help information"""
        help_text = """
Available Commands:
  read <path>       - Send READ request (e.g., read /dlsu/hello)
  write <path>      - Send WRITE request (e.g., write /storage/file)
  permission <path> - Send PERMISSION request
  stats             - Display statistics
  clear             - Clear logs
  help              - Show this help message

Quick Actions:
  - Use Quick Action buttons for common requests
  - Or type content name and click Send Request
  - Press Enter in content name field to send
"""
        self.log(help_text, 'info')
    
    def show_stats(self):
        """Show detailed statistics"""
        success_rate = 0
        if self.stats['sent'] > 0:
            success_rate = (self.stats['received'] / self.stats['sent']) * 100
        
        cache_rate = 0
        if self.stats['received'] > 0:
            cache_rate = (self.stats['cache_hits'] / self.stats['received']) * 100
        
        stats_text = f"""
Statistics Summary:
  Requests Sent:      {self.stats['sent']}
  Responses Received: {self.stats['received']}
  Errors:             {self.stats['errors']}
  Timeouts:           {self.stats['timeouts']}
  Cache Hits:         {self.stats['cache_hits']}
  Success Rate:       {success_rate:.1f}%
  Cache Hit Rate:     {cache_rate:.1f}%
"""
        self.log(stats_text, 'success')
    
    def quick_request(self, operation, content_name):
        """Quick request action"""
        self.operation_var.set(operation)
        self.content_name_entry.delete(0, tk.END)
        self.content_name_entry.insert(0, content_name)
        self.send_request()
    
    def send_request(self):
        """Send Interest packet"""
        if self.sending:
            return  # Prevent double-send
        
        operation = self.operation_var.get()
        content_name = self.content_name_entry.get().strip()
        
        if not content_name:
            messagebox.showerror("Error", "Content name cannot be empty!")
            return
        
        if not content_name.startswith('/'):
            content_name = '/' + content_name
        
        # Disable send button
        self.sending = True
        self.send_btn.config(state='disabled', text='Sending...')
        
        # Send in background thread
        threading.Thread(
            target=self._send_and_receive,
            args=(content_name, operation),
            daemon=True
        ).start()
    
    def _send_and_receive(self, content_name, operation):
        """Send packet and wait for response"""
        try:
            interest = create_interest_packet(content_name, self.client_id, operation)
            
            self.root.after(0, self.log, "\n" + "="*100, 'separator')
            self.root.after(0, self.log, f"SENDING {operation} REQUEST", 'header')
            self.root.after(0, self.log, "="*100, 'separator')
            
            timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
            self.root.after(0, self.log, f"[{timestamp}] Content: {content_name}", 'info')
            self.root.after(0, self.log, f"[{timestamp}] User: {self.client_id}", 'info')
            # Nonce was removed from packet structure; log checksum if nonce absent
            if hasattr(interest, 'nonce'):
                self.root.after(0, self.log, f"[{timestamp}] Nonce: {interest.nonce}", 'info')
            else:
                self.root.after(0, self.log, f"[{timestamp}] Checksum: {interest.checksum}", 'info')
            
            self.stats['sent'] += 1
            self.root.after(0, self.update_stats)
            
            start_time = time.time()
            
            response = self.comm_module.send_packet_sync(
                self.router_host,
                self.router_port,
                interest.to_json()
            )
            
            response_time = (time.time() - start_time) * 1000
            
            if response:
                try:
                    data_packet = DataPacket.from_json(response)
                    self.root.after(0, self._handle_response, data_packet, response_time)
                except Exception as e:
                    self.root.after(0, self.log, f"Error parsing response: {str(e)}", 'error')
                    self.stats['errors'] += 1
                    self.root.after(0, self.update_stats)
            else:
                self.root.after(0, self.log, f"\nTIMEOUT: No response within 5 seconds", 'error')
                self.root.after(0, self.log, f"Content: {content_name}\n", 'error')
                self.stats['timeouts'] += 1
                self.stats['errors'] += 1
                self.root.after(0, self.update_stats)
        
        except Exception as e:
            self.root.after(0, self.log, f"\nERROR: {str(e)}\n", 'error')
            self.stats['errors'] += 1
            self.root.after(0, self.update_stats)
        
        finally:
            # Re-enable send button
            self.root.after(0, self._reset_send_button)
    
    def _reset_send_button(self):
        """Reset send button state"""
        self.sending = False
        self.send_btn.config(state='normal', text='Send Request')
    
    def _handle_response(self, data_packet, response_time):
        """Handle received response"""
        if "/error" in data_packet.name:
            error_msg = data_packet.data_payload.decode('utf-8', errors='ignore')
            self.log(f"\nERROR RESPONSE: {error_msg}\n", 'error')
            self.stats['errors'] += 1
            self.update_stats()
            return
        
        self.log(f"\nRECEIVED DATA PACKET ({response_time:.2f} ms)", 'success')
        self.log("="*100, 'separator')
        
        if response_time < 20:
            self.log(f"Source: CACHE HIT (fast response)", 'success')
            self.stats['cache_hits'] += 1
        else:
            self.log(f"Source: Storage Node", 'info')
        
        self.log(f"Name: {data_packet.name}", 'info')
        self.log(f"Length: {data_packet.data_length} bytes", 'info')
        
        try:
            content_str = data_packet.data_payload.decode('utf-8', errors='ignore')
            self.log(f"\nCONTENT:", 'header')
            self.log("-"*100, 'separator')
            
            if len(content_str) > 500:
                self.log(content_str[:500] + f"\n... ({len(content_str) - 500} more characters)", 'content')
            else:
                self.log(content_str, 'content')
            
            self.log("-"*100, 'separator')
        except:
            self.log(f"\nContent: [Binary data - {data_packet.data_length} bytes]", 'info')
        
        self.log(f"\nResponse Time: {response_time:.3f} ms", 'success')
        self.log("="*100 + "\n", 'separator')
        
        self.stats['received'] += 1
        self.update_stats()
    
    def log(self, message, tag='info'):
        """Add message to log"""
        self.log_text.insert(tk.END, message + '\n', tag)
        self.log_text.see(tk.END)
    
    def clear_logs(self):
        """Clear logs"""
        self.log_text.delete('1.0', tk.END)
        self.log("="*100, 'separator')
        self.log("Logs cleared.", 'info')
        self.log("="*100 + "\n", 'separator')
    
    def update_stats(self):
        """Update statistics display"""
        for key, label in self.stat_labels.items():
            label.config(text=str(self.stats[key]))
        
        if self.stats['sent'] > 0:
            success_rate = (self.stats['received'] / self.stats['sent']) * 100
            self.success_rate_label.config(text=f"{success_rate:.1f}%")
        
        # Update status bar
        self.status_label.config(
            text=f"Requests: {self.stats['sent']} | Received: {self.stats['received']} | Client: {self.client_id}"
        )


def main():
    import sys
    client_id = sys.argv[1] if len(sys.argv) > 1 else "Alice"
    
    print("="*70)
    print(f"Starting NDN Client for: {client_id}")
    print("="*70)
    
    root = tk.Tk()
    app = ImprovedClientGUI(root, client_id)
    
    def on_closing():
        if messagebox.askokcancel("Quit", f"Close {client_id}'s client?"):
            root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    
    print(f"✓ GUI initialized for client: {client_id}")
    print(f"  Router: 127.0.0.1:8001")
    print(f"  Ready to send requests!\n")
    
    root.mainloop()


if __name__ == "__main__":
    main()