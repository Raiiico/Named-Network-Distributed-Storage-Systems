
#!/usr/bin/env python3
"""
Improved Debug GUI - Named Networks Framework
Fixed GUI with command input, organized logs, and better layout
"""

import tkinter as tk
from tkinter import scrolledtext, ttk
import threading
import queue
from datetime import datetime

class ImprovedDebugGUI:
    """
    Improved Debugging GUI with:
    - Command input panel
    - Organized log categories
    - Better filtering
    - Clean layout
    """

    def log_debug(self, message, tag='info'):
        """Log debug message (for compatibility with Router/Client code)"""
        # For now, treat as a system message with 'debug' tag
        self.log_system(message, tag)
    
    def __init__(self, node_name="Node", node_type="Router"):
        self.node_name = node_name
        self.node_type = node_type
        self.root = None
        
        # Separate queues for different log types
        self.control_queue = queue.Queue()
        self.packet_queue = queue.Queue()
        self.system_queue = queue.Queue()
        
        # Command callback
        self.command_callback = None
        
        # Filter states
        self.show_interest = None
        self.show_data = None
        self.show_errors = None
        self.show_system = None
        
        # Export log storage
        self.export_log = []
        
        # Statistics
        self.stats = {
            'packets_total': 0,
            'interests': 0,
            'data': 0,
            'errors': 0
        }
    
    def initialize(self):
        """Initialize the GUI (must be called from main thread)"""
        self.root = tk.Tk()
        self.root.title(f"NDN Debug - {self.node_name} ({self.node_type})")
        self.root.geometry("1600x900")
        
        # Initialize filter variables
        self.show_interest = tk.BooleanVar(value=True)
        self.show_data = tk.BooleanVar(value=True)
        self.show_errors = tk.BooleanVar(value=True)
        self.show_system = tk.BooleanVar(value=True)
        
        # Create main layout
        self._create_header()
        self._create_main_content()
        self._create_command_panel()
        self._create_status_bar()
        
        # Start queue processing
        self.root.after(100, self._process_queues)
        
        return self.root
    
    def _create_header(self):
        """Create header with node info and filters"""
        header_frame = tk.Frame(self.root, bg='#2C3E50', height=60)
        header_frame.pack(fill=tk.X, side=tk.TOP)
        header_frame.pack_propagate(False)
        
        # Node info
        info_frame = tk.Frame(header_frame, bg='#2C3E50')
        info_frame.pack(side=tk.LEFT, padx=20, pady=10)
        
        tk.Label(
            info_frame,
            text=f"{self.node_name}",
            font=('Arial', 16, 'bold'),
            bg='#2C3E50',
            fg='white'
        ).pack(side=tk.LEFT)
        
        tk.Label(
            info_frame,
            text=f"  |  {self.node_type}",
            font=('Arial', 12),
            bg='#2C3E50',
            fg='#BDC3C7'
        ).pack(side=tk.LEFT)
        
        # Filter controls
        filter_frame = tk.Frame(header_frame, bg='#2C3E50')
        filter_frame.pack(side=tk.RIGHT, padx=20, pady=10)
        
        tk.Label(
            filter_frame,
            text="Show:",
            font=('Arial', 10, 'bold'),
            bg='#2C3E50',
            fg='white'
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        filters = [
            ("Interest", self.show_interest, '#E74C3C'),
            ("Data", self.show_data, '#3498DB'),
            ("Errors", self.show_errors, '#E67E22'),
            ("System", self.show_system, '#95A5A6')
        ]
        
        for text, var, color in filters:
            cb = tk.Checkbutton(
                filter_frame,
                text=text,
                variable=var,
                bg='#2C3E50',
                fg=color,
                selectcolor='#34495E',
                font=('Arial', 9, 'bold'),
                activebackground='#2C3E50',
                activeforeground=color
            )
            cb.pack(side=tk.LEFT, padx=5)
        
        # Clear button
        tk.Button(
            filter_frame,
            text="Clear Logs",
            command=self._clear_all_logs,
            bg='#E74C3C',
            fg='white',
            font=('Arial', 9, 'bold'),
            relief=tk.FLAT,
            padx=15,
            pady=5,
            cursor='hand2'
        ).pack(side=tk.LEFT, padx=(20, 0))
    
    def _create_main_content(self):
        """Create main content area with three columns"""
        content_frame = tk.Frame(self.root)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Left column - System & Control
        left_frame = tk.Frame(content_frame, width=400)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=False, padx=(0, 5))
        left_frame.pack_propagate(False)
        
        self._create_system_log_panel(left_frame)
        self._create_control_panel(left_frame)
        
        # Middle column - Packet Log
        middle_frame = tk.Frame(content_frame)
        middle_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        self._create_packet_log_panel(middle_frame)
        
        # Right column - Statistics & Info
        right_frame = tk.Frame(content_frame, width=300)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=False, padx=(5, 0))
        right_frame.pack_propagate(False)
        
        self._create_statistics_panel(right_frame)
        self._create_info_panel(right_frame)
    
    def _create_system_log_panel(self, parent):
        """Create system log panel"""
        frame = tk.LabelFrame(
            parent,
            text=" System Log ",
            font=('Arial', 10, 'bold'),
            fg='#2C3E50'
        )
        frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        self.system_text = scrolledtext.ScrolledText(
            frame,
            wrap=tk.WORD,
            height=10,
            font=('Consolas', 9),
            bg='#FAFAFA',
            relief=tk.FLAT,
            padx=2,
            pady=2
        )
        self.system_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure tags
        self.system_text.tag_config('info', foreground='#2980B9')
        self.system_text.tag_config('success', foreground='#27AE60', font=('Consolas', 9, 'bold'))
        self.system_text.tag_config('error', foreground='#C0392B', font=('Consolas', 9, 'bold'))
        self.system_text.tag_config('warning', foreground='#F39C12')
        self.system_text.tag_config('timestamp', foreground='#7F8C8D', font=('Consolas', 8))
    
    def _create_control_panel(self, parent):
        """Create control messages panel"""
        frame = tk.LabelFrame(
            parent,
            text=" Control Messages (FIB/PIT/Cache) ",
            font=('Arial', 10, 'bold'),
            fg='#2C3E50'
        )
        frame.pack(fill=tk.BOTH, expand=True)
        
        self.control_text = scrolledtext.ScrolledText(
            frame,
            wrap=tk.WORD,
            height=15,
            font=('Consolas', 9),
            bg='#F8F9FA',
            relief=tk.FLAT,
            padx=5,
            pady=5
        )
        self.control_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure tags
        self.control_text.tag_config('header', foreground='#16A085', font=('Consolas', 9, 'bold'))
        self.control_text.tag_config('entry', foreground='#34495E')
        self.control_text.tag_config('value', foreground='#8E44AD')
        self.control_text.tag_config('separator', foreground='#BDC3C7')
    
    def _create_packet_log_panel(self, parent):
        """Create packet log panel"""
        frame = tk.LabelFrame(
            parent,
            text=" Packet Log (Interest/Data) ",
            font=('Arial', 10, 'bold'),
            fg='#2C3E50'
        )
        frame.pack(fill=tk.BOTH, expand=True)
        
        self.packet_text = scrolledtext.ScrolledText(
            frame,
            wrap=tk.WORD,
            font=('Consolas', 9),
            bg='#FFFFFF',
            relief=tk.FLAT,
            padx=5,
            pady=5
        )
        self.packet_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure tags for packet types
        self.packet_text.tag_config('timestamp', foreground='#95A5A6', font=('Consolas', 8))
        self.packet_text.tag_config('interest', foreground='#E74C3C', font=('Consolas', 10, 'bold'))
        self.packet_text.tag_config('data', foreground='#3498DB', font=('Consolas', 10, 'bold'))
        self.packet_text.tag_config('error', foreground='#E67E22', font=('Consolas', 10, 'bold'))
        self.packet_text.tag_config('field', foreground='#7F8C8D')
        self.packet_text.tag_config('value', foreground='#2C3E50')
        self.packet_text.tag_config('separator', foreground='#ECF0F1')
    
    def _create_statistics_panel(self, parent):
        """Create statistics panel"""
        frame = tk.LabelFrame(
            parent,
            text=" Statistics ",
            font=('Arial', 10, 'bold'),
            fg='#2C3E50'
        )
        frame.pack(fill=tk.X, pady=(0, 5))
        
        stats_inner = tk.Frame(frame, bg='white')
        stats_inner.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Statistics labels
        self.stat_labels = {}
        
        stats = [
            ('Total Packets', 'packets_total', '#34495E'),
            ('Interest', 'interests', '#E74C3C'),
            ('Data', 'data', '#3498DB'),
            ('Errors', 'errors', '#E67E22')
        ]
        
        for label, key, color in stats:
            row = tk.Frame(stats_inner, bg='white')
            row.pack(fill=tk.X, pady=3)
            
            tk.Label(
                row,
                text=f"{label}:",
                font=('Arial', 9),
                bg='white',
                fg='#7F8C8D',
                anchor='w'
            ).pack(side=tk.LEFT)
            
            value_label = tk.Label(
                row,
                text="0",
                font=('Arial', 10, 'bold'),
                bg='white',
                fg=color,
                anchor='e'
            )
            value_label.pack(side=tk.RIGHT)
            
            self.stat_labels[key] = value_label
    
    def _create_info_panel(self, parent):
        """Create info/help panel"""
        frame = tk.LabelFrame(
            parent,
            text=" Quick Reference ",
            font=('Arial', 10, 'bold'),
            fg='#2C3E50'
        )
        frame.pack(fill=tk.BOTH, expand=True)
        
        info_text = scrolledtext.ScrolledText(
            frame,
            wrap=tk.WORD,
            height=20,
            font=('Consolas', 9),
            bg='#F8F9FA',
            relief=tk.FLAT,
            padx=5,
            pady=5
        )
        info_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add help text based on node type
        if self.node_type == "Router":
            help_text = """ROUTER COMMANDS:
            
show fib
  Display FIB routing table
  
show pit
  Display Pending Interest Table
  
show cache
  Display Content Store entries
  
show stats
  Display router statistics
  
route <prefix> <nexthop>
  Add FIB route
  Example: route /dlsu 127.0.0.1:9001
  
clear cache
  Clear Content Store
  
help
  Show this help message
  
quit
  Stop the router"""
        else:
            help_text = """CLIENT COMMANDS:

read <name>
  Send READ Interest
  Example: read /dlsu/hello
  
write <name>
  Send WRITE Interest
  Example: write /storage/file
  
stats
  Show client statistics
  
help
  Show this help message
  
quit
  Exit client"""
        
        info_text.insert('1.0', help_text)
        info_text.config(state='disabled')
    
    def _create_command_panel(self):
        """Create command input panel at bottom"""
        cmd_frame = tk.Frame(self.root, bg='#ECF0F1', height=80)
        cmd_frame.pack(fill=tk.X, side=tk.BOTTOM, padx=10, pady=(5, 10))
        cmd_frame.pack_propagate(False)
        
        # Command label
        tk.Label(
            cmd_frame,
            text="Command:",
            font=('Arial', 10, 'bold'),
            bg='#ECF0F1',
            fg='#2C3E50'
        ).pack(side=tk.LEFT, padx=(10, 5), pady=20)
        
        # Command entry
        self.command_entry = tk.Entry(
            cmd_frame,
            font=('Consolas', 11),
            bg='white',
            relief=tk.FLAT,
            highlightthickness=1,
            highlightbackground='#BDC3C7',
            highlightcolor='#3498DB'
        )
        self.command_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=20)
        self.command_entry.bind('<Return>', self._handle_command)
        self.command_entry.focus_set()
        
        # Send button
        send_btn = tk.Button(
            cmd_frame,
            text="Send",
            command=self._handle_command,
            bg='#3498DB',
            fg='white',
            font=('Arial', 10, 'bold'),
            relief=tk.FLAT,
            padx=20,
            pady=10,
            cursor='hand2'
        )
        send_btn.pack(side=tk.LEFT, padx=(5, 10), pady=20)
    
    def _create_status_bar(self):
        """Create status bar"""
        status_frame = tk.Frame(self.root, relief=tk.SUNKEN, bd=1, bg='#34495E')
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.status_label = tk.Label(
            status_frame,
            text=f"Ready | Node: {self.node_name} | Type: {self.node_type} | Status: Active",
            anchor=tk.W,
            font=('Arial', 9),
            bg='#34495E',
            fg='#ECF0F1',
            padx=10,
            pady=3
        )
        self.status_label.pack(fill=tk.X)
    
    def _handle_command(self, event=None):
        """Handle command input"""
        command = self.command_entry.get().strip()
        
        if not command:
            return
        
        # Clear entry
        self.command_entry.delete(0, tk.END)
        
        # Log command
        self.log_system(f"> {command}", 'info')
        
        # Execute command callback if set
        if self.command_callback:
            try:
                result = self.command_callback(command)
                if result:
                    self.log_system(result, 'success')
            except Exception as e:
                self.log_system(f"Command error: {str(e)}", 'error')
        else:
            self.log_system("No command handler registered", 'warning')
    
    def set_command_callback(self, callback):
        """Set callback function for commands"""
        self.command_callback = callback
    
    def log_system(self, message, tag='info'):
        """Log system message"""
        self.system_queue.put((message, tag))
        self.export_log.append(f"[SYSTEM] {message}")
    
    def log_control(self, message, tag='entry'):
        """Log control message"""
        self.control_queue.put((message, tag))
        self.export_log.append(f"[CONTROL] {message}")
    
    def log_packet(self, message, packet_type='interest'):
        """Log packet message"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        self.packet_queue.put((timestamp, message, packet_type))
        self.export_log.append(f"[{timestamp}] [{packet_type.upper()}] {message}")
        
        # Update statistics
        self.stats['packets_total'] += 1
        if packet_type == 'interest':
            self.stats['interests'] += 1
        elif packet_type == 'data':
            self.stats['data'] += 1
        elif packet_type == 'error':
            self.stats['errors'] += 1
    
    def _process_queues(self):
        """Process message queues and update GUI"""
        # Process system messages
        try:
            while True:
                message, tag = self.system_queue.get_nowait()
                timestamp = datetime.now().strftime("%H:%M:%S")
                self.system_text.insert(tk.END, f"[{timestamp}] ", 'timestamp')
                self.system_text.insert(tk.END, message + "\n", tag)
                self.system_text.see(tk.END)
        except queue.Empty:
            pass
        
        # Process control messages
        try:
            while True:
                message, tag = self.control_queue.get_nowait()
                self.control_text.insert(tk.END, message + "\n", tag)
                self.control_text.see(tk.END)
        except queue.Empty:
            pass
        
        # Process packet messages
        try:
            while True:
                timestamp, message, packet_type = self.packet_queue.get_nowait()
                
                # Apply filters
                if packet_type == 'interest' and not self.show_interest.get():
                    continue
                if packet_type == 'data' and not self.show_data.get():
                    continue
                if packet_type == 'error' and not self.show_errors.get():
                    continue
                
                # Insert with formatting
                self.packet_text.insert(tk.END, f"[{timestamp}] ", 'timestamp')
                self.packet_text.insert(tk.END, f"{packet_type.upper()}", packet_type)
                self.packet_text.insert(tk.END, f": {message}\n", 'value')
                self.packet_text.see(tk.END)
        except queue.Empty:
            pass
        
        # Update statistics
        self._update_statistics()
        
        # Schedule next update
        if self.root:
            self.root.after(100, self._process_queues)
    
    def _update_statistics(self):
        """Update statistics display"""
        for key, label in self.stat_labels.items():
            label.config(text=str(self.stats[key]))
    
    def _clear_all_logs(self):
        """Clear all log areas"""
        self.system_text.delete('1.0', tk.END)
        self.control_text.delete('1.0', tk.END)
        self.packet_text.delete('1.0', tk.END)
        self.log_system("Logs cleared", 'info')
    
    def update_status(self, status_text):
        """Update status bar"""
        if self.status_label:
            self.status_label.config(
                text=f"{status_text} | Node: {self.node_name} | Packets: {self.stats['packets_total']}"
            )
    
    def run(self):
        """Start GUI main loop"""
        if self.root:
            self.root.mainloop()


# Test the GUI
if __name__ == "__main__":
    gui = ImprovedDebugGUI("Router-R1", "Router")
    gui.initialize()
    
    # Set up test command handler
    def test_command_handler(command):
        if command == "show fib":
            gui.log_control("=== FIB Table ===", 'header')
            gui.log_control("/dlsu -> 127.0.0.1:9001", 'entry')
            gui.log_control("/storage -> 127.0.0.1:9002", 'entry')
            return "FIB table displayed"
        elif command == "show stats":
            gui.log_system("Statistics displayed", 'success')
            return "Stats shown"
        elif command == "help":
            return "Commands available: show fib, show pit, show cache, show stats"
        else:
            return f"Unknown command: {command}"
    
    gui.set_command_callback(test_command_handler)
    
    # Simulate some activity
    gui.log_system("Router initialized successfully", 'success')
    gui.log_system("Listening on 127.0.0.1:8001", 'info')
    
    gui.log_control("=== Initial FIB ===", 'header')
    gui.log_control("/dlsu -> 127.0.0.1:9001", 'entry')
    
    gui.log_packet("INTEREST received: /dlsu/hello from Client-Alice", 'interest')
    gui.log_packet("DATA sent: /dlsu/hello [245 bytes]", 'data')
    
    gui.run()