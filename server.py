#!/usr/bin/env python3
"""
Server - Named Networks Framework
Central server for permission checking and access control
"""

import time
from communication_module import CommunicationModule
from common import InterestPacket, DataPacket

class Server:
    """Central server handling authentication and permissions"""
    
    def __init__(self, server_id: str, host: str = "127.0.0.1", port: int = 7001):
        self.server_id = server_id
        self.node_name = f"Server-{server_id}"
        
        # Simple permission table (user -> allowed paths)
        self.permissions = {
            "Alice": ["/dlsu/alice", "/dlsu/storage/node1"],
            "Bob": ["/dlsu/bob", "/dlsu/storage/node2"],
            "admin": ["/dlsu"],  # Admin has access to everything under /dlsu
        }
        
        # Initialize communication
        self.comm_module = CommunicationModule(self.node_name, host, port)
        self.comm_module.set_packet_handler(self.handle_packet)
        
        print(f"[{self.node_name}] Server initialized on {host}:{port}")
    
    def handle_packet(self, raw_packet: str, source: str):
        """Handle incoming packets"""
        try:
            # Parse Interest packet
            interest = InterestPacket.from_json(raw_packet)
            
            print(f"[{self.node_name}] Permission check: {interest.user_id} -> {interest.name}")
            
            # Check permission
            if self.check_permission(interest.user_id, interest.name):
                # Authorized - return storage location
                response_data = f"AUTHORIZED:{self.get_storage_location(interest.name)}"
                print(f"[{self.node_name}] ✅ AUTHORIZED")
            else:
                # Denied
                response_data = "DENIED:Permission denied"
                print(f"[{self.node_name}] ❌ DENIED")
            
            # Send response
            response = DataPacket(
                name=interest.name,
                data_payload=response_data.encode('utf-8')
            )
            
            return response.to_json()
            
        except Exception as e:
            print(f"[{self.node_name}] Error: {e}")
            return None
    
    def check_permission(self, user_id: str, content_name: str) -> bool:
        """Check if user has permission for content"""
        user_paths = self.permissions.get(user_id, [])
        
        # Check if content_name starts with any allowed path
        for allowed_path in user_paths:
            if content_name.startswith(allowed_path):
                return True
        
        return False
    
    def get_storage_location(self, content_name: str) -> str:
        """Determine which storage node has the content"""
        # Simple routing: alice -> node1, bob -> node2
        if "/alice" in content_name:
            return "127.0.0.1:9001"
        elif "/bob" in content_name:
            return "127.0.0.1:9002"
        else:
            return "127.0.0.1:9001"  # Default to node1
    
    def start(self):
        """Start the server"""
        self.comm_module.start()
        print(f"[{self.node_name}] Server running...")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n[{self.node_name}] Shutting down...")
            self.comm_module.stop()


if __name__ == "__main__":
    import sys
    server_id = sys.argv[1] if len(sys.argv) > 1 else "S1"
    
    server = Server(server_id)
    server.start()