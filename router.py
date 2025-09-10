#!/usr/bin/env python3
"""
Named Networks Router
Forwards Interest/Data packets and manages Content Store, PIT, and FIB
"""

import socket
import json
import threading
from common import InterestPacket, DataPacket, ContentStore, PendingInterestTable, ForwardingInformationBase

class NamedNetworksRouter:
    """Named Networks Router implementation"""
    def __init__(self, router_id: str, host: str = "127.0.0.1", port: int = 8001):
        self.node_name = f"Router-{router_id}"
        self.router_id = router_id
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        
        # Named Networks core data structures
        self.content_store = ContentStore()
        self.pit = PendingInterestTable()
        self.fib = ForwardingInformationBase()
        
        # Configure default static routes
        self.setup_static_routes()
    
    def setup_static_routes(self):
        """Configure static routing table"""
        # Route DLSU content to server
        self.fib.add_route("/dlsu", "127.0.0.1:8002")
        self.fib.add_route("/server", "127.0.0.1:8002")
        # Add more routes as needed
        print(f"[{self.node_name}] Static routes configured")
    
    def start(self):
        """Start the router"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        self.running = True
        
        print(f"[{self.node_name}] Started on {self.host}:{self.port}")
        
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
        """Stop the router"""
        self.running = False
        if self.socket:
            self.socket.close()
        print(f"[{self.node_name}] Stopped")
    
    def send_packet(self, host: str, port: int, packet_data: str):
        """Send packet to another node"""
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
    
    def handle_connection(self, client_socket, addr):
        """Handle incoming connection"""
        try:
            data = client_socket.recv(4096).decode()
            packet_data = json.loads(data)
            
            if packet_data["type"] == "INTEREST":
                interest = InterestPacket.from_json(data)
                response = self.handle_interest(interest, f"{addr[0]}:{addr[1]}")
                client_socket.send(response.encode())
            elif packet_data["type"] == "DATA":
                data_packet = DataPacket.from_json(data)
                self.handle_data(data_packet)
                client_socket.send(b"ACK")
            else:
                print(f"[{self.node_name}] Unknown packet type: {packet_data['type']}")
                
        except Exception as e:
            print(f"[{self.node_name}] Error handling connection from {addr}: {e}")
        finally:
            client_socket.close()
    
    def handle_interest(self, interest: InterestPacket, incoming_face: str) -> str:
        """Handle Interest packet following Named Networks principles"""
        print(f"[{self.node_name}] Processing Interest for: {interest.name} (from {interest.user_id})")
        
        # Step 1: Check Content Store
        cached_content = self.content_store.get(interest.name)
        if cached_content:
            print(f"[{self.node_name}] Content Store HIT for: {interest.name}")
            data_packet = DataPacket(
                name=interest.name,
                payload=cached_content,
                checksum="cached"
            )
            return data_packet.to_json()
        
        print(f"[{self.node_name}] Content Store MISS for: {interest.name}")
        
        # Step 2: Add to PIT
        self.pit.add_entry(interest.name, incoming_face)
        
        # Step 3: Forward Interest using FIB
        next_hop = self.fib.lookup(interest.name)
        if next_hop:
            host, port = next_hop.split(":")
            print(f"[{self.node_name}] Forwarding Interest to: {next_hop}")
            
            response = self.send_packet(host, int(port), interest.to_json())
            if response:
                try:
                    # Cache the response
                    data_packet = DataPacket.from_json(response)
                    self.content_store.put(interest.name, data_packet.payload)
                    self.pit.remove_entry(interest.name)
                    return response
                except Exception as e:
                    print(f"[{self.node_name}] Error processing response: {e}")
        
        # Step 4: Return error if no route found
        error_data = DataPacket(
            name=interest.name,
            payload=f"No route found for: {interest.name}",
            checksum="error"
        )
        self.pit.remove_entry(interest.name)
        return error_data.to_json()
    
    def handle_data(self, data_packet: DataPacket):
        """Handle incoming Data packet"""
        print(f"[{self.node_name}] Received Data for: {data_packet.name}")
        
        # Forward to interested faces from PIT
        faces = self.pit.get_faces(data_packet.name)
        for face in faces:
            print(f"[{self.node_name}] Forwarding Data to: {face}")
            # In a real implementation, would forward to the actual face
        
        # Cache content and remove PIT entry
        self.content_store.put(data_packet.name, data_packet.payload)
        self.pit.remove_entry(data_packet.name)
    
    def add_route(self, prefix: str, next_hop: str):
        """Add a route to the FIB"""
        self.fib.add_route(prefix, next_hop)
    
    def show_status(self):
        """Show router status"""
        print(f"\n=== {self.node_name} Status ===")
        print(f"Content Store entries: {len(self.content_store.store)}")
        print(f"PIT entries: {len(self.pit.table)}")
        print(f"FIB routes: {len(self.fib.fib)}")
        
        if self.content_store.store:
            print("Cached content:")
            for name in self.content_store.store.keys():
                print(f"  - {name}")

def main():
    """Run the router"""
    router = NamedNetworksRouter("R1")
    
    try:
        router.start()
    except KeyboardInterrupt:
        print("\nShutting down router...")
        router.show_status()
        router.stop()

if __name__ == "__main__":
    main()