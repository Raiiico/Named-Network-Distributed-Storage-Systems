#!/usr/bin/env python3
"""
Named Networks Client
Sends Interest packets and receives Data packets
"""

import socket
import json
import time
from common import InterestPacket, DataPacket, generate_nonce

class NamedNetworksClient:
    """Named Networks Client implementation"""
    def __init__(self, client_id: str):
        self.node_name = f"Client-{client_id}"
        self.client_id = client_id
        print(f"[{self.node_name}] Initialized")
    
    def send_packet(self, host: str, port: int, packet_data: str):
        """Send packet to router/server"""
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((host, port))
            client_socket.send(packet_data.encode())
            response = client_socket.recv(4096).decode()
            client_socket.close()
            return response
        except Exception as e:
            print(f"[{self.node_name}] Error sending packet to {host}:{port} - {e}")
            return None
    
    def send_interest(self, content_name: str, router_host: str = "127.0.0.1", router_port: int = 8001):
        """Send Interest packet for content"""
        interest = InterestPacket(
            name=content_name,
            user_id=self.client_id,
            nonce=generate_nonce()
        )
        
        print(f"[{self.node_name}] Sending Interest for: {content_name}")
        
        response = self.send_packet(router_host, router_port, interest.to_json())
        
        if response:
            try:
                data_packet = DataPacket.from_json(response)
                print(f"[{self.node_name}] Received Data for: {data_packet.name}")
                
                if data_packet.checksum == "error":
                    print(f"[{self.node_name}] Error: {data_packet.payload}")
                else:
                    print(f"[{self.node_name}] Content: {data_packet.payload}")
                    if data_packet.checksum == "cached":
                        print(f"[{self.node_name}] (Retrieved from cache)")
                
                return data_packet
            except Exception as e:
                print(f"[{self.node_name}] Error parsing response: {e}")
                print(f"[{self.node_name}] Raw response: {response}")
        else:
            print(f"[{self.node_name}] No response received")
        
        return None
    
    def interactive_mode(self):
        """Interactive mode for testing"""
        print(f"\n=== {self.node_name} Interactive Mode ===")
        print("Enter content names to request (or 'quit' to exit):")
        print("Examples: /dlsu/hello, /dlsu/goks/welcome, /server/status")
        print()
        
        while True:
            try:
                content_name = input(f"{self.client_id}> ").strip()
                
                if content_name.lower() in ['quit', 'exit', 'q']:
                    break
                
                if not content_name:
                    continue
                
                if not content_name.startswith('/'):
                    print("Content name should start with '/'")
                    continue
                
                print()
                self.send_interest(content_name)
                print("-" * 50)
                
            except KeyboardInterrupt:
                break
        
        print(f"\n[{self.node_name}] Goodbye!")

def main():
    """Run the client"""
    import sys
    
    # Get client ID from command line or use default
    client_id = sys.argv[1] if len(sys.argv) > 1 else "Alice"
    
    client = NamedNetworksClient(client_id)
    
    # Demo mode - send some test requests
    print("=== Demo Mode ===")
    test_requests = [
        "/dlsu/hello",
        "/dlsu/goks/welcome",
        "/dlsu/thesis/info",
        "/dlsu/hello",  # Should be cached at router
        "/server/status",
        "/nonexistent/content"  # Should return error
    ]
    
    for content_name in test_requests:
        print(f"\n--- Requesting: {content_name} ---")
        client.send_interest(content_name)
        time.sleep(1)
    
    print("\n" + "="*60)
    
    # Interactive mode
    try:
        client.interactive_mode()
    except KeyboardInterrupt:
        print(f"\n[{client.node_name}] Shutting down...")

if __name__ == "__main__":
    main()