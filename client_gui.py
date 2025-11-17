#!/usr/bin/env python3
"""
Client GUI for Named Data Networks Framework
Fixed to work with existing communication_module and common.py
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
from datetime import datetime

# Import from your existing modules
from common import create_interest_packet, DataPacket, calculate_checksum
from communication_module import CommunicationModule

class NDNClientGUI:
    def __init__(self, root, client_id="GUI-Client"):
        self.root = root
        self.root.title(f"NDN Client - {client_id}")
        self.root.geometry("1000x750")
        
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
        
        self.setup_ui()
        
    def setup_ui(self):
        """Create the user interface"""
        
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(3, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, 
                               text=f"Named Data Networks Client - {self.client_id}", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=2, pady=10)
        
        # Connection status
        self.status_label = ttk.Label(main_frame, 
                                     text=f"✓ Router: {self.router_host}:{self.router_port} | Protocol: UDP",
                                     foreground="green",
                                     font=('Arial', 10))
        self.status_label.grid(row=1, column=0, columnspan=2, pady=5)
        
        # ===== OPERATION FRAME =====
        operation_frame = ttk.LabelFrame(main_frame, text="📤 Request Operation", 
                                        padding="10")
        operation_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), 
                           pady=10)
        operation_frame.columnconfigure(1, weight=1)
        
        # Operation type
        ttk.Label(operation_frame, text="Operation:").grid(row=0, column=0, 
                                                          sticky=tk.W, pady=5)
        self.operation_var = tk.StringVar(value="READ")
        operation_combo = ttk.Combobox(operation_frame, textvariable=self.operation_var,
                                      values=["READ", "WRITE", "PERMISSION"],
                                      state="readonly", width=15)
        operation_combo.grid(row=0, column=1, sticky=tk.W, pady=5, padx=5)
        operation_combo.bind("<<ComboboxSelected>>", self.on_operation_change)
        
        # Content name
        ttk.Label(operation_frame, text="Content Name:").grid(row=1, column=0, 
                                                             sticky=tk.W, pady=5)
        self.content_name_entry = ttk.Entry(operation_frame, width=60)
        self.content_name_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), 
                                    pady=5, padx=5)
        self.content_name_entry.insert(0, "/dlsu/hello")
        
        # Content data (for WRITE operations)
        self.content_label = ttk.Label(operation_frame, text="Content Data:")
        self.content_label.grid(row=2, column=0, sticky=tk.W, pady=5)
        self.content_label.grid_remove()  # Hidden by default
        
        self.content_text = scrolledtext.ScrolledText(operation_frame, 
                                                     height=4, width=60)
        self.content_text.grid(row=2, column=1, sticky=(tk.W, tk.E), 
                              pady=5, padx=5)
        self.content_text.grid_remove()  # Hidden by default
        
        # Buttons
        button_frame = ttk.Frame(operation_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        self.send_button = ttk.Button(button_frame, text="📨 Send Request", 
                                     command=self.send_request)
        self.send_button.grid(row=0, column=0, padx=5)
        
        ttk.Button(button_frame, text="🗑️ Clear Logs", 
                  command=self.clear_logs).grid(row=0, column=1, padx=5)
        
        # Quick access buttons
        quick_frame = ttk.Frame(button_frame)
        quick_frame.grid(row=0, column=2, padx=20)
        ttk.Label(quick_frame, text="Quick:", font=('Arial', 9, 'bold')).pack(side=tk.LEFT, padx=5)
        ttk.Button(quick_frame, text="/dlsu/hello", 
                  command=lambda: self.quick_request("READ", "/dlsu/hello"),
                  width=12).pack(side=tk.LEFT, padx=2)
        ttk.Button(quick_frame, text="/storage/test", 
                  command=lambda: self.quick_request("READ", "/dlsu/storage/test"),
                  width=12).pack(side=tk.LEFT, padx=2)
        
        # ===== RESPONSE/LOG FRAME =====
        log_frame = ttk.LabelFrame(main_frame, text="📥 Response & Logs", padding="10")
        log_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), 
                      pady=10)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        # Log text area
        self.log_text = scrolledtext.ScrolledText(log_frame, height=22, width=115,
                                                  font=('Consolas', 9),
                                                  bg='#FAFAFA')
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure tags for colored text
        self.log_text.tag_config('success', foreground='#2E7D32', font=('Consolas', 9, 'bold'))
        self.log_text.tag_config('error', foreground='#C62828', font=('Consolas', 9, 'bold'))
        self.log_text.tag_config('info', foreground='#1565C0', font=('Consolas', 9))
        self.log_text.tag_config('warning', foreground='#EF6C00', font=('Consolas', 9))
        self.log_text.tag_config('header', foreground='#4A148C', font=('Consolas', 10, 'bold'))
        self.log_text.tag_config('content', foreground='#37474F', font=('Consolas', 9))
        self.log_text.tag_config('timestamp', foreground='#757575', font=('Consolas', 8))
        
        # ===== STATISTICS FRAME =====
        stats_frame = ttk.Frame(main_frame)
        stats_frame.grid(row=4, column=0, columnspan=2, pady=10)
        
        self.stats_label = ttk.Label(stats_frame, 
                                     text=self.get_stats_text(),
                                     font=('Consolas', 9),
                                     foreground='#424242')
        self.stats_label.grid(row=0, column=0)
        
        # Initial log message
        self.log("="*100, 'info')
        self.log(f"NDN Client '{self.client_id}' initialized successfully", 'success')
        self.log(f"Router: {self.router_host}:{self.router_port} | Protocol: UDP", 'info')
        self.log(f"Ready to send requests. Try the quick buttons or enter a custom content name.", 'info')
        self.log("="*100 + "\n", 'info')
        
    def on_operation_change(self, event=None):
        """Show/hide content field based on operation"""
        operation = self.operation_var.get()
        
        if operation == "WRITE":
            self.content_label.grid()
            self.content_text.grid()
        else:
            self.content_label.grid_remove()
            self.content_text.grid_remove()
    
    def quick_request(self, operation, content_name):
        """Quick access to common requests"""
        self.operation_var.set(operation)
        self.content_name_entry.delete(0, tk.END)
        self.content_name_entry.insert(0, content_name)
        self.on_operation_change()
        self.send_request()
    
    def send_request(self):
        """Send Interest packet to router"""
        operation = self.operation_var.get()
        content_name = self.content_name_entry.get().strip()
        
        # Validate input
        if not content_name:
            messagebox.showerror("Error", "Content name cannot be empty!")
            return
        
        if not content_name.startswith('/'):
            content_name = '/' + content_name
        
        # Get content data for WRITE
        content_data = None
        if operation == "WRITE":
            content_data = self.content_text.get("1.0", tk.END).strip()
            if not content_data:
                messagebox.showerror("Error", "Content data cannot be empty for WRITE!")
                return
        
        # Disable send button during request
        self.send_button.config(state='disabled')
        
        # Send in background thread to avoid UI freezing
        threading.Thread(target=self._send_and_receive, 
                        args=(content_name, operation, content_data), 
                        daemon=True).start()
    
    def _send_and_receive(self, content_name, operation, content_data=None):
        """Send packet and wait for response (runs in background thread)"""
        
        try:
            # Create Interest packet using your common.py function
            interest = create_interest_packet(content_name, self.client_id, operation)
            
            # Log the request
            self.root.after(0, self.log, "\n" + "="*100, 'header')
            self.root.after(0, self.log, 
                          f"📤 SENDING {operation} REQUEST", 'header')
            self.root.after(0, self.log, "="*100, 'header')
            timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
            self.root.after(0, self.log, f"[{timestamp}] Content: {content_name}", 'info')
            self.root.after(0, self.log, f"[{timestamp}] User: {self.client_id}", 'info')
            self.root.after(0, self.log, f"[{timestamp}] Nonce: {interest.nonce}", 'info')
            self.root.after(0, self.log, f"[{timestamp}] Checksum: {interest.checksum}", 'info')
            
            self.stats['sent'] += 1
            self.root.after(0, self.update_stats)
            
            start_time = time.time()
            
            # Send using your communication module
            response = self.comm_module.send_packet_sync(
                self.router_host, 
                self.router_port, 
                interest.to_json()
            )
            
            response_time = (time.time() - start_time) * 1000  # Convert to ms
            
            if response:
                # Parse response using your DataPacket class
                try:
                    data_packet = DataPacket.from_json(response)
                    
                    # Update UI in main thread
                    self.root.after(0, self._handle_response, data_packet, response_time)
                    
                except Exception as e:
                    self.root.after(0, self.log, 
                                  f"✗ Error parsing response: {str(e)}", 'error')
                    self.stats['errors'] += 1
                    self.root.after(0, self.update_stats)
            else:
                # Timeout
                self.root.after(0, self.log, 
                              f"\n⚠ TIMEOUT: No response received within 5 seconds", 'error')
                self.root.after(0, self.log, 
                              f"   Content: {content_name}", 'error')
                self.root.after(0, self.log, 
                              f"   Check if router is running on {self.router_host}:{self.router_port}\n", 'error')
                self.stats['timeouts'] += 1
                self.stats['errors'] += 1
                self.root.after(0, self.update_stats)
                
        except Exception as e:
            self.root.after(0, self.log, 
                          f"\n✗ ERROR: {str(e)}\n", 'error')
            self.stats['errors'] += 1
            self.root.after(0, self.update_stats)
        
        finally:
            # Re-enable send button
            self.root.after(0, lambda: self.send_button.config(state='normal'))
    
    def _handle_response(self, data_packet, response_time):
        """Handle received response (runs in main thread)"""
        
        # Check if error response
        if data_packet.name == "/error" or "/error" in data_packet.name:
            error_msg = data_packet.data_payload.decode('utf-8', errors='ignore')
            self.log(f"\n⚠ ERROR RESPONSE:", 'error')
            self.log(f"   {error_msg}\n", 'error')
            self.stats['errors'] += 1
            self.update_stats()
            return
        
        # Success response
        self.log(f"\n📥 RECEIVED DATA PACKET ({response_time:.2f} ms)", 'success')
        self.log("="*100, 'success')
        
        # Determine if cache hit (fast response time)
        if response_time < 20:
            self.log(f"   ⚡ Source: CACHE HIT (fast response)", 'success')
            self.stats['cache_hits'] += 1
        else:
            self.log(f"   📦 Source: Storage Node (retrieved from storage)", 'info')
        
        self.log(f"   Name: {data_packet.name}", 'info')
        self.log(f"   Length: {data_packet.data_length} bytes", 'info')
        self.log(f"   Checksum: {data_packet.checksum}", 'info')
        
        # Validate checksum
        if data_packet.validate_checksum():
            self.log(f"   ✓ Checksum valid", 'success')
        else:
            self.log(f"   ⚠ Checksum mismatch (auto-corrected)", 'warning')
        
        # Display content
        try:
            content_str = data_packet.data_payload.decode('utf-8', errors='ignore')
            
            self.log(f"\n   📄 CONTENT:", 'header')
            self.log(f"   {'-'*96}", 'info')
            
            # Display content (truncate if too long)
            if len(content_str) > 1000:
                lines = content_str[:1000].split('\n')
                for line in lines:
                    self.log(f"   {line}", 'content')
                remaining = len(content_str) - 1000
                self.log(f"   ... ({remaining} more characters)", 'info')
            else:
                lines = content_str.split('\n')
                for line in lines:
                    self.log(f"   {line}", 'content')
            
            self.log(f"   {'-'*96}", 'info')
            
        except Exception as e:
            self.log(f"\n   📄 Content: [Binary data - {data_packet.data_length} bytes]", 'info')
            self.log(f"   (Could not decode as text: {str(e)})", 'warning')
        
        self.log(f"\n   ⏱ Response Time: {response_time:.3f} ms", 'success')
        self.log("="*100 + "\n", 'success')
        
        self.stats['received'] += 1
        self.update_stats()
    
    def log(self, message, tag='info'):
        """Add message to log"""
        self.log_text.insert(tk.END, message + '\n', tag)
        self.log_text.see(tk.END)
    
    def clear_logs(self):
        """Clear the log area"""
        self.log_text.delete('1.0', tk.END)
        self.log("="*100, 'info')
        self.log("Logs cleared.", 'info')
        self.log("="*100 + "\n", 'info')
    
    def get_stats_text(self):
        """Generate statistics text"""
        success_rate = 0
        if self.stats['sent'] > 0:
            success_rate = (self.stats['received'] / self.stats['sent']) * 100
        
        cache_rate = 0
        if self.stats['received'] > 0:
            cache_rate = (self.stats['cache_hits'] / self.stats['received']) * 100
        
        return (f"📊 Sent: {self.stats['sent']} | "
                f"📥 Received: {self.stats['received']} | "
                f"❌ Errors: {self.stats['errors']} | "
                f"⏰ Timeouts: {self.stats['timeouts']} | "
                f"✓ Success: {success_rate:.1f}% | "
                f"⚡ Cache Hit: {cache_rate:.1f}%")
    
    def update_stats(self):
        """Update statistics display"""
        self.stats_label.config(text=self.get_stats_text())

def main():
    import sys
    
    # Get client ID from command line or use default
    client_id = sys.argv[1] if len(sys.argv) > 1 else "Alice"
    
    print("="*70)
    print(f"Starting NDN Client GUI for: {client_id}")
    print("="*70)
    
    root = tk.Tk()
    app = NDNClientGUI(root, client_id)
    
    # Handle window close
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