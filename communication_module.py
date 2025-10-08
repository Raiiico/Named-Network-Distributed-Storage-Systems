#!/usr/bin/env python3
"""
Communication Module - Named Networks Framework
UDP-based communication with fixed port allocation
Fixes the TCP/UDP inconsistency and port confusion issues
"""

import socket
import threading
import queue
import time
from typing import Callable, Optional

class CommunicationModule:
    """
    Communication Module implementing UDP producer-consumer architecture
    Fixed for Named Data Network principles
    """
    
    def __init__(self, node_name: str, host: str = "127.0.0.1", port: int = 0):
        self.node_name = node_name
        self.host = host
        self.port = port
        self.running = False
        
        # Network components - UDP ONLY
        self.server_socket: Optional[socket.socket] = None
        
        # Producer-Consumer Buffers
        self.receive_buffer = queue.Queue(maxsize=100)
        self.send_buffer = queue.Queue(maxsize=100)
        
        # Threading
        self.receive_thread: Optional[threading.Thread] = None
        self.process_thread: Optional[threading.Thread] = None
        self.send_thread: Optional[threading.Thread] = None
        
        # Callback for processing received packets
        self.packet_handler: Optional[Callable] = None
        
        # Statistics
        self.stats = {
            "packets_received": 0,
            "packets_sent": 0,
            "errors": 0,
            "buffer_overflows": 0
        }
        
        print(f"[{self.node_name}][COMM] Communication Module initialized (UDP)")
    
    def set_packet_handler(self, handler: Callable):
        """Set callback function to handle received packets"""
        self.packet_handler = handler
        print(f"[{self.node_name}][COMM] Packet handler registered")
    
    def start(self):
        """Start the communication module"""
        if self.running:
            return
        
        # Initialize UDP socket (NOT TCP)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        
        # Get actual port if auto-assigned
        if self.port == 0:
            self.port = self.server_socket.getsockname()[1]
        
        self.running = True
        
        # Start buffer management threads
        self.receive_thread = threading.Thread(target=self._receive_loop, daemon=True)
        self.process_thread = threading.Thread(target=self._process_buffer, daemon=True)
        self.send_thread = threading.Thread(target=self._send_buffer_processor, daemon=True)
        
        self.receive_thread.start()
        self.process_thread.start()
        self.send_thread.start()
        
        print(f"[{self.node_name}][COMM] Started on {self.host}:{self.port} (UDP)")
    
    def stop(self):
        """Stop the communication module"""
        print(f"[{self.node_name}][COMM] Stopping Communication Module...")
        self.running = False
        
        if self.server_socket:
            self.server_socket.close()
        
        # Wait for threads
        for thread in [self.receive_thread, self.process_thread, self.send_thread]:
            if thread:
                thread.join(timeout=1.0)
        
        print(f"[{self.node_name}][COMM] Stopped")
    
    def _receive_loop(self):
        """Producer: Receive UDP packets and add to buffer"""
        print(f"[{self.node_name}][COMM] Receive thread started (UDP)")
        
        while self.running:
            try:
                # Set timeout to allow periodic checking of running flag
                self.server_socket.settimeout(1.0)
                
                # Receive UDP packet
                data, addr = self.server_socket.recvfrom(65536)
                
                if data:
                    # Try to add to receive buffer
                    try:
                        self.receive_buffer.put_nowait((data, addr))
                        self.stats["packets_received"] += 1
                        
                        print(f"[{self.node_name}][COMM] Received packet from {addr} ({len(data)} bytes)")
                        
                    except queue.Full:
                        self.stats["buffer_overflows"] += 1
                        print(f"[{self.node_name}][COMM] Receive buffer overflow! Packet dropped from {addr}")
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    self.stats["errors"] += 1
                    print(f"[{self.node_name}][COMM] Receive error: {e}")
        
        print(f"[{self.node_name}][COMM] Receive thread stopped")
    
    def _process_buffer(self):
        """Consumer: Process packets from receive buffer"""
        print(f"[{self.node_name}][COMM] Process thread started")
        
        while self.running:
            try:
                # Get packet from buffer with timeout
                packet_data, source_addr = self.receive_buffer.get(timeout=1.0)
                
                # Decode packet
                packet_str = packet_data.decode('utf-8', errors='ignore')
                source_str = f"{source_addr[0]}:{source_addr[1]}"
                
                # Call packet handler if registered
                if self.packet_handler:
                    try:
                        response = self.packet_handler(packet_str, source_str)
                        
                        if response:
                            # Queue response for sending back to source
                            self.send(response, source_addr[0], source_addr[1])
                    
                    except Exception as e:
                        self.stats["errors"] += 1
                        print(f"[{self.node_name}][COMM] Handler error: {e}")
                
            except queue.Empty:
                continue
            except Exception as e:
                if self.running:
                    self.stats["errors"] += 1
                    print(f"[{self.node_name}][COMM] Processing error: {e}")
        
        print(f"[{self.node_name}][COMM] Process thread stopped")
    
    def _send_buffer_processor(self):
        """Consumer: Process send buffer and transmit packets"""
        print(f"[{self.node_name}][COMM] Send thread started")
        
        while self.running:
            try:
                # Get packet from send buffer
                packet, host, port = self.send_buffer.get(timeout=1.0)
                
                # Send via UDP (creates temporary socket for each send)
                try:
                    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    client_socket.sendto(packet.encode('utf-8'), (host, port))
                    client_socket.close()
                    
                    self.stats["packets_sent"] += 1
                    print(f"[{self.node_name}][COMM] Sent packet to {host}:{port}")
                    
                except Exception as e:
                    self.stats["errors"] += 1
                    print(f"[{self.node_name}][COMM] Send error to {host}:{port}: {e}")
                
            except queue.Empty:
                continue
            except Exception as e:
                if self.running:
                    self.stats["errors"] += 1
                    print(f"[{self.node_name}][COMM] Send buffer error: {e}")
        
        print(f"[{self.node_name}][COMM] Send thread stopped")
    
    def send(self, packet: str, host: str, port: int):
        """Queue packet for sending (non-blocking)"""
        try:
            self.send_buffer.put_nowait((packet, host, port))
        except queue.Full:
            self.stats["buffer_overflows"] += 1
            print(f"[{self.node_name}][COMM] Send buffer overflow! Packet to {host}:{port} dropped")
    
    def send_packet_sync(self, host: str, port: int, packet_data: str) -> Optional[str]:
        """
        Send packet synchronously and wait for response (for client use)
        Uses UDP with consistent port behavior
        """
        try:
            # Create UDP socket for request-response
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket.settimeout(5.0)
            
            # Send packet
            client_socket.sendto(packet_data.encode('utf-8'), (host, port))
            self.stats["packets_sent"] += 1
            
            print(f"[{self.node_name}][COMM] Sent packet to {host}:{port}")
            
            # Wait for response
            response_data, _ = client_socket.recvfrom(65536)
            self.stats["packets_received"] += 1
            
            client_socket.close()
            
            response_str = response_data.decode('utf-8', errors='ignore')
            return response_str
            
        except socket.timeout:
            print(f"[{self.node_name}][COMM] Timeout waiting for response from {host}:{port}")
            return None
        except Exception as e:
            self.stats["errors"] += 1
            print(f"[{self.node_name}][COMM] Send-receive error: {e}")
            return None
    
    def get_port(self) -> int:
        """Get the actual port being used"""
        return self.port
    
    def get_stats(self) -> dict:
        """Get communication statistics"""
        return self.stats.copy()
    
    def get_buffer_status(self):
        """Get current buffer status"""
        return {
            'receive_buffer_size': self.receive_buffer.qsize(),
            'send_buffer_size': self.send_buffer.qsize(),
            'max_buffer_size': 100
        }


# Test the UDP module
if __name__ == "__main__":
    print("Testing UDP Communication Module")
    
    # Create test module
    comm = CommunicationModule("TestNode", port=8888)
    
    # Simple handler
    def test_handler(packet, source):
        print(f"Received from {source}: {packet[:50]}...")
        return "ACK: UDP packet received"
    
    comm.set_packet_handler(test_handler)
    comm.start()
    
    print(f"UDP server listening on port {comm.get_port()}")
    print("Press Ctrl+C to stop")
    
    try:
        while True:
            time.sleep(1)
            stats = comm.get_stats()
            if stats['packets_received'] > 0 or stats['packets_sent'] > 0:
                print(f"Stats: RX={stats['packets_received']}, TX={stats['packets_sent']}, Errors={stats['errors']}")
    except KeyboardInterrupt:
        print("\nStopping...")
        comm.stop()