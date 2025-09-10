#!/usr/bin/env python3
"""
Named Networks Server
Stores and serves content based on hierarchical names
"""

import socket
import json
import threading
from common import InterestPacket, DataPacket

class NamedNetworksServer:
    """Named Networks Server implementation"""
    def __init__(self, host: str = "127.0.0.1", port: int = 8002):
        self.node_name = "Server"
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        
        # Content repository with hierarchical names
        self.content_repository = {
            "/dlsu/hello": "Hello from DLSU Server!",
            "/dlsu/goks/welcome": "Welcome to GOKS project!",
            "/dlsu/thesis/info": "This is a Named Networks implementation for distributed storage",
            "/dlsu/storage/node1": "Storage Node 1 is active",
            "/dlsu/storage/node2": "Storage Node 2 is active",
            "/server/status": "Server is running normally",
            "/server/time": "Server time: Current timestamp"
        }
    
    def start(self):
        """Start the server"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        self.running = True
        
        print(f"[{self.node_name}] Started on {self.host}:{self.port}")
        print(f"[{self.node_name}] Available content:")
        for name in self.content_repository.keys():
            print(f"  - {name}")
        print()
        
        while self.running:
            try:
                client_socket, addr = self.socket.accept()
                threading.Thread(
                    target=self.handle_connection,
                    args=(client_socket, addr),
                    daemon=True
                ).start()
            except OSError:
                break
    
    def stop(self):
        """Stop the server"""
        self.running = False
        if self.socket:
            self.socket.close()
        print(f"[{self.node_name}] Stopped")
    
    def handle_connection(self, client_socket, addr):
        """Handle incoming connection"""
        try:
            data = client_socket.recv(4096).decode()
            packet_data = json.loads(data)
            
            if packet_data["type"] == "INTEREST":
                interest = InterestPacket.from_json(data)
                response = self.handle_interest(interest)
                client_socket.send(response.encode())
            else:
                print(f"[{self.node_name}] Unknown packet type: {packet_data['type']}")
                
        except Exception as e:
            print(f"[{self.node_name}] Error handling connection from {addr}: {e}")
        finally:
            client_socket.close()
    
    def handle_interest(self, interest: InterestPacket) -> str:
        """Handle Interest packet and return Data packet"""
        print(f"[{self.node_name}] Processing Interest for: {interest.name} (from user: {interest.user_id})")
        
        # Look up content in repository
        content = self.content_repository.get(interest.name)
        
        if content:
            # Create Data packet with content
            data_packet = DataPacket(
                name=interest.name,
                payload=content,
                checksum="server_generated"
            )
            print(f"[{self.node_name}] Sending Data for: {interest.name}")
            return data_packet.to_json()
        else:
            # Create error Data packet
            error_data = DataPacket(
                name=interest.name,
                payload=f"Content '{interest.name}' not found on server",
                checksum="error"
            )
            print(f"[{self.node_name}] Content not found: {interest.name}")
            return error_data.to_json()
    
    def add_content(self, name: str, content: str):
        """Add content to the repository"""
        self.content_repository[name] = content
        print(f"[{self.node_name}] Added content: {name}")

def main():
    """Run the server"""
    server = NamedNetworksServer()
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.stop()

if __name__ == "__main__":
    main()