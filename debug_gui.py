#!/usr/bin/env python3
"""
Debugging GUI - Named Networks Framework
Dual-pane interface for Control Messages and Debugging Messages
"""

import tkinter as tk
from tkinter import scrolledtext, ttk
import threading
import queue
from datetime import datetime

class DebugGUI:
    """
    Debugging GUI with dual-pane display
    Left: Control Messages (FIB, PIT, Content Store queries)
    Right: Packet Debugging (Interest/Data with timestamps)
    """
    
    def __init__(self, node_name="Node"):
        self.node_name = node_name
        self.root = None
        self.control_text = None
        self.debug_text = None
        
        # Message queues for thread-safe updates
        self.control_queue = queue.Queue()
        self.debug_queue = queue.Queue()
        
        # Filter checkboxes state (initialize later after root window created)
        self.show_interest = None
        self.show_data = None
        self.show_permission = None
        self.show_errors = None
        
        # Export log storage
        self.export_log = []
    
    def initialize(self):
        """Initialize the GUI (must be called from main thread)"""
        self.root = tk.Tk()
        self.root.title(f"Named Networks Debugger - {self.node_name}")
        self.root.geometry("1400x700")
        
        # Initialize BooleanVars after root window is created
        self.show_interest = tk.BooleanVar(value=True)
        self.show_data = tk.BooleanVar(value=True)
        self.show_permission = tk.BooleanVar(value=True)
        self.show_errors = tk.BooleanVar(value=True)
        
        # Create main container
        main_container = tk.Frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left Panel - Control Messages
        self._create_control_panel(main_container)
        
        # Right Panel - Debugging Messages
        self._create_debug_panel(main_container)
        
        # Bottom status bar
        self._create_status_bar()
        
        # Start queue processing (200ms interval to reduce GUI strain)
        self.root.after(200, self._process_queues)
        
        return self.root
    
    def _create_control_panel(self, parent):
        """Create left panel for control messages"""
        left_frame = tk.Frame(parent, width=700)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        # Header
        header = tk.Label(
            left_frame, 
            text="Control Messages", 
            font=('Arial', 14, 'bold'),
            bg='#E3F2FD',
            pady=5
        )
        header.pack(fill=tk.X)
        
        # Control buttons
        btn_frame = tk.Frame(left_frame)
        btn_frame.pack(fill=tk.X, pady=5)
        
        tk.Button(
            btn_frame, 
            text="Clear", 
            command=self._clear_control
        ).pack(side=tk.LEFT, padx=2)
        
        tk.Button(
            btn_frame,
            text="Export Log",
            command=self._export_logs
        ).pack(side=tk.LEFT, padx=2)
        
        # Scrolled text area
        self.control_text = scrolledtext.ScrolledText(
            left_frame,
            wrap=tk.WORD,
            width=85,
            height=35,
            font=('Consolas', 9),
            bg='#FAFAFA'
        )
        self.control_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Configure tags for formatting
        self.control_text.tag_config("header", foreground="#1976D2", font=('Consolas', 9, 'bold'))
        self.control_text.tag_config("value", foreground="#388E3C")
        self.control_text.tag_config("separator", foreground="#BDBDBD")
    
    def _create_debug_panel(self, parent):
        """Create right panel for debugging messages"""
        right_frame = tk.Frame(parent, width=700)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)
        
        # Header
        header = tk.Label(
            right_frame,
            text="Packet Debugging",
            font=('Arial', 14, 'bold'),
            bg='#FFF3E0',
            pady=5
        )
        header.pack(fill=tk.X)
        
        # Filter checkboxes
        filter_frame = tk.Frame(right_frame)
        filter_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(filter_frame, text="Show:", font=('Arial', 9, 'bold')).pack(side=tk.LEFT, padx=5)
        
        tk.Checkbutton(
            filter_frame,
            text="Interest",
            variable=self.show_interest,
            fg='red'
        ).pack(side=tk.LEFT, padx=2)
        
        tk.Checkbutton(
            filter_frame,
            text="Data",
            variable=self.show_data,
            fg='blue'
        ).pack(side=tk.LEFT, padx=2)
        
        tk.Checkbutton(
            filter_frame,
            text="Permission",
            variable=self.show_permission,
            fg='purple'
        ).pack(side=tk.LEFT, padx=2)
        
        tk.Checkbutton(
            filter_frame,
            text="Errors",
            variable=self.show_errors,
            fg='orange'
        ).pack(side=tk.LEFT, padx=2)
        
        # Clear button
        tk.Button(
            filter_frame,
            text="Clear",
            command=self._clear_debug
        ).pack(side=tk.RIGHT, padx=5)
        
        # Scrolled text area
        self.debug_text = scrolledtext.ScrolledText(
            right_frame,
            wrap=tk.WORD,
            width=85,
            height=35,
            font=('Consolas', 9),
            bg='#FAFAFA'
        )
        self.debug_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Configure color tags
        self.debug_text.tag_config("timestamp", foreground="#757575", font=('Consolas', 8))
        self.debug_text.tag_config("interest", foreground="#D32F2F", font=('Consolas', 9, 'bold'))
        self.debug_text.tag_config("data", foreground="#1976D2", font=('Consolas', 9, 'bold'))
        self.debug_text.tag_config("permission", foreground="#7B1FA2", font=('Consolas', 9, 'bold'))
        self.debug_text.tag_config("error", foreground="#F57C00", font=('Consolas', 9, 'bold'))
        self.debug_text.tag_config("content", foreground="#424242")
        self.debug_text.tag_config("payload", foreground="#006064", font=('Consolas', 8))
    
    def _create_status_bar(self):
        """Create bottom status bar"""
        status_frame = tk.Frame(self.root, relief=tk.SUNKEN, bd=1)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.status_label = tk.Label(
            status_frame,
            text=f"Node: {self.node_name} | Status: Active | Messages: 0",
            anchor=tk.W,
            font=('Arial', 9)
        )
        self.status_label.pack(fill=tk.X, padx=5, pady=2)
    
    def log_control(self, message, tag="normal"):
        """Thread-safe control message logging"""
        self.control_queue.put((message, tag))
    
    def _sanitize(self, text: str) -> str:
        """Replace non-ASCII or decorative characters with plain ASCII equivalents"""
        replacements = {
            "✓": "[OK]",
            "✗": "[FAIL]",
            "→": "->",
            "←": "<-",
            "📦": "[PKT]",
            "⚠️": "[WARN]",
            "❌": "[ERROR]",
            "✉️": "[MSG]",
            "═": "=",
            "─": "-",
            "│": "|",
            "┌": "+",
            "┐": "+",
            "└": "+",
            "┘": "+",
            "├": "+",
            "┤": "+",
            "┬": "+",
            "┴": "+",
            "┼": "+",
            "📋": "[CTRL]",
            "🔍": "[DBG]"
        }
        out = text
        for k, v in replacements.items():
            out = out.replace(k, v)
        # Remove any remaining non-ascii characters
        out = ''.join(ch for ch in out if ord(ch) < 128)
        return out

    def log_debug(self, message, msg_type="normal"):
        """Thread-safe debug message logging"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        sanitized = self._sanitize(message)
        self.debug_queue.put((timestamp, sanitized, msg_type))
        
        # Store in export log (sanitized)
        self.export_log.append(f"[{timestamp}] [{msg_type.upper()}] {sanitized}")
    
    def _process_queues(self):
        """Process message queues and update GUI"""
        # Process control messages
        try:
            while True:
                message, tag = self.control_queue.get_nowait()
                self.control_text.insert(tk.END, message + "\n", tag)
                self.control_text.see(tk.END)
        except queue.Empty:
            pass
        
        # Process debug messages
        try:
            while True:
                timestamp, message, msg_type = self.debug_queue.get_nowait()
                
                # Apply filters (only if BooleanVars are initialized)
                if (self.show_interest and msg_type == "interest" and 
                    not self.show_interest.get()):
                    continue
                if (self.show_data and msg_type == "data" and 
                    not self.show_data.get()):
                    continue
                if (self.show_permission and msg_type == "permission" and 
                    not self.show_permission.get()):
                    continue
                if (self.show_errors and msg_type == "error" and 
                    not self.show_errors.get()):
                    continue
                
                # Insert timestamp
                self.debug_text.insert(tk.END, f"[{timestamp}] ", "timestamp")
                
                # Insert message with appropriate tag
                self.debug_text.insert(tk.END, message + "\n", msg_type)
                self.debug_text.see(tk.END)
        except queue.Empty:
            pass
        
        # Schedule next update (200ms to reduce CPU usage)
        if self.root:
            self.root.after(200, self._process_queues)
    
    def _clear_control(self):
        """Clear control messages panel"""
        self.control_text.delete(1.0, tk.END)
    
    def _clear_debug(self):
        """Clear debug messages panel"""
        self.debug_text.delete(1.0, tk.END)
    
    def _export_logs(self):
        """Export debug logs to file"""
        from tkinter import filedialog
        filename = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt")]
        )
        
        if filename:
            with open(filename, 'w') as f:
                f.write(f"Named Networks Debug Log - {self.node_name}\n")
                f.write(f"Generated: {datetime.now()}\n")
                f.write("=" * 80 + "\n\n")
                for log_entry in self.export_log:
                    f.write(log_entry + "\n")
            
            self.log_control(f"✓ Exported {len(self.export_log)} log entries to {filename}", "header")
    
    def update_status(self, status_text):
        """Update status bar"""
        if self.status_label:
            self.status_label.config(text=status_text)
    
    def run(self):
        """Start GUI main loop"""
        if self.root:
            self.root.mainloop()


# Usage example
if __name__ == "__main__":
    gui = DebugGUI("Test-Router")
    gui.initialize()
    
    # Simulate some messages
    gui.log_control("=== FIB Table ===", "header")
    gui.log_control("/dlsu -> Router-1 (port 8001)", "value")
    gui.log_control("/storage -> Storage-1 (port 9001)", "value")
    gui.log_control("=" * 50, "separator")
    
    gui.log_debug("Interest sent: /dlsu/hello.txt", "interest")
    gui.log_debug("  Name: /dlsu/hello.txt", "content")
    gui.log_debug("  Operation: READ", "content")
    gui.log_debug("  Nonce: 12345", "content")
    
    gui.log_debug("Data received: /dlsu/hello.txt [245 bytes]", "data")
    gui.log_debug("  Payload: Hello from DLSU Named Networks!", "payload")
    gui.log_debug("  Checksum: abc123def456", "content")
    
    gui.log_debug("Permission check: User Alice on /dlsu/private/file.txt", "permission")
    
    gui.log_debug("Error: Timeout waiting for response", "error")
    
    gui.run()