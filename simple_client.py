#!/usr/bin/env python3
"""
Simple Named Networks Client
Sends Interest packets to Router (Communication + Parsing test)
"""

import time
from common import InterestPacket, DataPacket, generate_nonce, calculate_checksum
from communication_module import CommunicationModule

class SimpleClient:
    """Simple client for testing Communication and Parsing modules"""
    
    def __init__(self, client_id: str):
        self.client_id = client_id
        self.node_name = f"Client-{client_id}"
        
        # Initialize communication module (client doesn't need to listen)
        self.comm_module = CommunicationModule(self.node_name, port=0)
        
        print(f"[{self.node_name}] Client initialized")
    
    def send_interest(self, content_name: str, operation: str = "READ", 
                     router_host: str = "127.0.0.1", router_port: int = 8001):
        """Send Interest packet to router"""
        
        # Create Interest packet following thesis specification
        interest = InterestPacket(
            name=content_name,
            user_id=self.client_id,
            operation=operation,
            nonce=generate_nonce(),
            checksum=calculate_checksum(content_name + self.client_id + operation)
        )
        
        print(f"[{self.node_name}] Sending {operation} Interest for: {content_name}")
        print(f"[{self.node_name}] Nonce: {interest.nonce}")
        
        # Send using communication module
        response = self.comm_module.send_packet_sync(router_host, router_port, interest.to_json())
        
        if response:
            try:
                # Parse response as Data packet
                data_packet = DataPacket.from_json(response)
                print(f"[{self.node_name}] Received Data for: {data_packet.name}")
                
                # Check if error response
                if data_packet.checksum == "error":
                    print(f"[{self.node_name}] Error: {data_packet.data_payload.decode('utf-8')}")
                else:
                    print(f"[{self.node_name}] Content: {data_packet.data_payload.decode('utf-8')}")
                    print(f"[{self.node_name}] Data length: {data_packet.data_length} bytes")
                
                return data_packet
                
            except Exception as e:
                print(f"[{self.node_name}] Error parsing response: {e}")
                print(f"[{self.node_name}] Raw response: {response}")
        else:
            print(f"[{self.node_name}] No response received from router")
        
        return None
    
    def run_test_scenarios(self, router_host: str = "127.0.0.1", router_port: int = 8001):
        """Run various test scenarios"""
        print(f"\n=== {self.node_name} Test Scenarios ===\n")
        
        test_cases = [
            # Valid requests
            {"name": "/dlsu/hello", "operation": "READ", "description": "Basic read request"},
            {"name": "/dlsu/goks/welcome", "operation": "READ", "description": "Hierarchical path"},
            {"name": "/dlsu/storage/node1", "operation": "WRITE", "description": "Write operation"},
            
            # Fragment requests
            {"name": "/dlsu/files/large.pdf:[1/4]", "operation": "READ", "description": "Fragment request"},
            
            # Permission requests
            {"name": "/dlsu/private/data", "operation": "PERMISSION", "description": "Permission operation"},
            
            # Invalid requests (for error handling testing)
            {"name": "invalid-name", "operation": "READ", "description": "Invalid name format"},
            {"name": "/dlsu/test", "operation": "INVALID", "description": "Invalid operation"},
        ]
        
        for i, test in enumerate(test_cases, 1):
            print(f"Test {i}: {test['description']}")
            print(f"Requesting: {test['name']} ({test['operation']})")
            
            self.send_interest(test["name"], test["operation"], router_host, router_port)
            
            print("-" * 60)
            time.sleep(1)
    
    def interactive_mode(self, router_host: str = "127.0.0.1", router_port: int = 8001):
        """Interactive mode for manual testing"""
        print(f"\n=== {self.node_name} Interactive Mode ===")
        print("Enter content names to request (or 'quit' to exit)")
        print("Format: <content_name> [operation]")
        print("Operations: READ (default), WRITE, PERMISSION")
        print("Examples:")
        print("  /dlsu/hello")
        print("  /dlsu/storage/node1 WRITE")
        print("  /dlsu/files/doc:[1/3] READ")
        print()
        
        while True:
            try:
                user_input = input(f"{self.client_id}> ").strip()
                
                if user_input.lower() in ['quit', 'exit', 'q']:
                    break
                
                if not user_input:
                    continue
                
                # Parse input
                parts = user_input.split()
                content_name = parts[0]
                operation = parts[1] if len(parts) > 1 else "READ"
                
                # Validate content name format
                if not content_name.startswith('/'):
                    print("Content name should start with '/'")
                    continue
                
                # Validate operation
                if operation.upper() not in ["READ", "WRITE", "PERMISSION"]:
                    print("Valid operations: READ, WRITE, PERMISSION")
                    continue
                
                print()
                self.send_interest(content_name, operation.upper(), router_host, router_port)
                print("-" * 50)
                
            except KeyboardInterrupt:
                break
        
        print(f"\n[{self.node_name}] Goodbye!")

def main():
    """Run the client"""
    import sys
    
    # Get client ID from command line or use default
    client_id = sys.argv[1] if len(sys.argv) > 1 else "Alice"
    
    client = SimpleClient(client_id)
    
    # Check if router is available first
    router_host = "127.0.0.1"
    router_port = 8001
    
    print(f"Testing connection to router at {router_host}:{router_port}")
    
    # Run demo scenarios first
    client.run_test_scenarios(router_host, router_port)
    
    # Then interactive mode
    try:
        client.interactive_mode(router_host, router_port)
    except KeyboardInterrupt:
        print(f"\n[{client.node_name}] Shutting down...")

if __name__ == "__main__":
    main()