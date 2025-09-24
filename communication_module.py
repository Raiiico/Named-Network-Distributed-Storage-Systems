#!/usr/bin/env python3
"""
Communication Module - Named Networks Framework
Handles network communication with producer-consumer buffer management
"""

import socket
import threading
import queue
import time
from typing import Callable, Optional

class CommunicationModule:
    """
    Communication Module implementing producer-consumer architecture
    with separate receive and send buffer management
    """
    
    def __init__(self, node_name: str, host: str = "127.0.0.1", port: int = 0):
        self.node_name = node_name
        self.host = host
        self.port = port
        self.running = False
        
        # Network components
        self.server_socket: Optional[socket.socket] = None
        
        # Producer-Consumer Buffers
        self.receive_buffer = queue.Queue(maxsize=100)  # Incoming packets queue
        self.send_buffer = queue.Queue(maxsize=100)     # Outgoing packets queue
        
        # Threading
        self.receive_thread: Optional[threading.Thread] = None
        self.send_thread: Optional[threading.Thread] = None
        self.connection_threads = []
        
        # Callback for processing received packets
        self.packet_handler: Optional[Callable] = None
        
        print(f"[{self.node_name}][COMM] Communication Module initialized")
    
    def set_packet_handler(self, handler: Callable):
        """Set callback function to handle received packets"""
        self.packet_handler = handler
        print(f"[{self.node_name}][COMM] Packet handler registered")
    
    def start(self):
        """Start the communication module"""
        if self.running:
            return
        
        # Initialize server socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        
        # Get actual port if auto-assigned
        if self.port == 0:
            self.port = self.server_socket.getsockname()[1]
        
        self.server_socket.listen(10)  # Allow multiple connections
        self.running = True
        
        # Start buffer management threads
        self.receive_thread = threading.Thread(target=self._connection_acceptor, daemon=True)
        self.send_thread = threading.Thread(target=self._send_buffer_processor, daemon=True)
        
        self.receive_thread.start()
        self.send_thread.start()
        
        print(f"[{self.node_name}][COMM] Started on {self.host}:{self.port}")
    
    def stop(self):
        """Stop the communication module"""
        if not self.running:
            return
        
        self.running = False
        
        # Close server socket
        if self.server_socket:
            self.server_socket.close()
        
        # Clear buffers
        while not self.receive_buffer.empty():
            try:
                self.receive_buffer.get_nowait()
            except queue.Empty:
                break
        
        while not self.send_buffer.empty():
            try:
                self.send_buffer.get_nowait()
            except queue.Empty:
                break
        
        print(f"[{self.node_name}][COMM] Stopped")
    
    def _connection_acceptor(self):
        """Accept incoming connections (Producer for receive buffer)"""
        while self.running:
            try:
                client_socket, client_addr = self.server_socket.accept()
                
                # Handle each connection in separate thread
                connection_thread = threading.Thread(
                    target=self._handle_connection,
                    args=(client_socket, client_addr),
                    daemon=True
                )
                connection_thread.start()
                self.connection_threads.append(connection_thread)
                
            except OSError:
                # Socket closed
                break
            except Exception as e:
                if self.running:
                    print(f"[{self.node_name}][COMM] Error accepting connection: {e}")
    
    def _handle_connection(self, client_socket: socket.socket, client_addr):
        """Handle individual connection and add to receive buffer"""
        try:
            # Receive data with timeout
            client_socket.settimeout(5.0)
            data = client_socket.recv(4096)
            
            if data:
                packet_info = {
                    'data': data.decode('utf-8'),
                    'source': f"{client_addr[0]}:{client_addr[1]}",
                    'timestamp': time.time(),
                    'response_socket': client_socket  # Keep socket for response
                }
                
                # Add to receive buffer (Producer)
                try:
                    self.receive_buffer.put(packet_info, timeout=1.0)
                    print(f"[{self.node_name}][COMM] Received packet from {client_addr}")
                except queue.Full:
                    print(f"[{self.node_name}][COMM] Receive buffer full, dropping packet")
                    client_socket.close()
                    return
                
                # Process the packet if handler is available
                if self.packet_handler:
                    threading.Thread(
                        target=self._process_received_packet,
                        args=(packet_info,),
                        daemon=True
                    ).start()
            else:
                client_socket.close()
                
        except socket.timeout:
            print(f"[{self.node_name}][COMM] Connection timeout from {client_addr}")
            client_socket.close()
        except Exception as e:
            print(f"[{self.node_name}][COMM] Error handling connection: {e}")
            client_socket.close()
    
    def _process_received_packet(self, packet_info):
        """Process received packet using registered handler"""
        if self.packet_handler:
            try:
                # Call the parsing module through the handler
                response = self.packet_handler(packet_info['data'], packet_info['source'])
                
                if response and packet_info['response_socket']:
                    # Send response back through the same socket
                    try:
                        packet_info['response_socket'].send(response.encode('utf-8'))
                    except Exception as e:
                        print(f"[{self.node_name}][COMM] Error sending response: {e}")
                    finally:
                        packet_info['response_socket'].close()
                else:
                    packet_info['response_socket'].close()
                    
            except Exception as e:
                print(f"[{self.node_name}][COMM] Error processing packet: {e}")
                packet_info['response_socket'].close()
    
    def _send_buffer_processor(self):
        """Process send buffer (Consumer for outgoing packets)"""
        while self.running:
            try:
                # Get packet from send buffer
                send_info = self.send_buffer.get(timeout=1.0)
                
                # Send packet to destination
                success = self._send_packet_to_destination(
                    send_info['host'],
                    send_info['port'],
                    send_info['data']
                )
                
                # Handle send callback if provided
                if 'callback' in send_info and send_info['callback']:
                    send_info['callback'](success)
                
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[{self.node_name}][COMM] Error in send buffer processor: {e}")
    
    def send_packet(self, host: str, port: int, packet_data: str, callback=None) -> bool:
        """Queue packet for sending"""
        send_info = {
            'host': host,
            'port': port,
            'data': packet_data,
            'callback': callback,
            'timestamp': time.time()
        }
        
        try:
            self.send_buffer.put(send_info, timeout=1.0)
            print(f"[{self.node_name}][COMM] Queued packet for {host}:{port}")
            return True
        except queue.Full:
            print(f"[{self.node_name}][COMM] Send buffer full, dropping packet")
            return False
    
    def send_packet_sync(self, host: str, port: int, packet_data: str) -> Optional[str]:
        """Send packet synchronously and wait for response"""
        return self._send_packet_to_destination(host, port, packet_data)
    
    def _send_packet_to_destination(self, host: str, port: int, packet_data: str) -> Optional[str]:
        """Internal method to send packet to specific destination"""
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(5.0)
            client_socket.connect((host, port))
            
            # Send packet
            client_socket.send(packet_data.encode('utf-8'))
            
            # Wait for response
            response = client_socket.recv(4096).decode('utf-8')
            client_socket.close()
            
            print(f"[{self.node_name}][COMM] Sent packet to {host}:{port}")
            return response
            
        except Exception as e:
            print(f"[{self.node_name}][COMM] Error sending to {host}:{port}: {e}")
            return None
    
    def get_buffer_status(self):
        """Get current buffer status"""
        return {
            'receive_buffer_size': self.receive_buffer.qsize(),
            'send_buffer_size': self.send_buffer.qsize(),
            'max_buffer_size': 100
        }
    
    def get_port(self):
        """Get the actual port being used"""
        return self.port