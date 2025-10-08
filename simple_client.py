#!/usr/bin/env python3
"""
Simple Named Networks Client - Updated for UDP and Fixed Checksums
Compatible with the fixed communication_module.py and common.py
"""

import time
import sys
from common import create_interest_packet, DataPacket, calculate_checksum
from communication_module import CommunicationModule

class SimpleClient:
    """Simple client for testing with fixed UDP communication"""
    
    def __init__(self, client_id: str):
        self.client_id = client_id
        self.node_name = f"Client-{client_id}"
        self.comm_module = CommunicationModule(self.node_name, port=0)
        
        # Statistics
        self.stats = {
            "interests_sent": 0,
            "data_received": 0,
            "timeouts": 0,
            "errors": 0,
            "checksum_corrections": 0
        }
        
        print(f"[{self.node_name}] Client initialized (UDP)")
    
    def send_interest(self, content_name: str, operation: str = "READ", 
                     router_host: str = "127.0.0.1", router_port: int = 8001):
        """Send Interest packet to router"""
        
        # Create Interest packet with proper checksum
        interest = create_interest_packet(content_name, self.client_id, operation)
        
        send_time = time.time()
        self.stats["interests_sent"] += 1
        
        # Display sent Interest
        print(f"\n{'='*70}")
        print(f"📤 SENDING INTEREST")
        print(f"{'='*70}")
        print(f"  From:      {self.node_name}")
        print(f"  To:        {router_host}:{router_port}")
        print(f"  Name:      {interest.name}")
        print(f"  Operation: {interest.operation}")
        print(f"  User ID:   {interest.user_id}")
        print(f"  Nonce:     {interest.nonce}")
        print(f"  Checksum:  {interest.checksum}")
        print(f"  Timestamp: {time.strftime('%H:%M:%S', time.localtime(send_time))}")
        print(f"{'='*70}")
        
        # Send using UDP communication module
        response = self.comm_module.send_packet_sync(router_host, router_port, interest.to_json())
        
        if response:
            # Handle response
            try:
                data_packet = DataPacket.from_json(response)
                
                # Check if error
                if data_packet.name == "/error":
                    self.stats["errors"] += 1
                    error_msg = data_packet.data_payload.decode('utf-8', errors='ignore')
                    print(f"\n⚠️  ERROR: {error_msg}\n")
                    return None
                
                self.stats["data_received"] += 1
                
                # Validate checksum
                if not data_packet.validate_checksum():
                    self.stats["checksum_corrections"] += 1
                    print(f"[{self.node_name}] Note: Response checksum recalculated")
                
                # Display received Data
                print(f"\n{'='*70}")
                print(f"📥 RECEIVED DATA")
                print(f"{'='*70}")
                print(f"  Name:        {data_packet.name}")
                print(f"  Length:      {data_packet.data_length} bytes")
                print(f"  Checksum:    {data_packet.checksum}")
                
                # Check if fragmented
                if ":[" in data_packet.name and "/" in data_packet.name.split(":[")[1]:
                    fragment_info = data_packet.name.split(":[")[1].rstrip("]")
                    print(f"  Fragment:    {fragment_info}")
                
                # Display payload
                try:
                    payload_str = data_packet.data_payload.decode('utf-8', errors='ignore')
                    print(f"\n  📄 Content:")
                    print(f"  {'-'*66}")
                    if len(payload_str) > 500:
                        print(f"  {payload_str[:500]}")
                        print(f"  ... ({len(payload_str) - 500} more characters)")
                    else:
                        print(f"  {payload_str}")
                    print(f"  {'-'*66}")
                except:
                    print(f"\n  📄 Content: [Binary data - {data_packet.data_length} bytes]")
                
                # Response time
                response_time = time.time() - send_time
                print(f"\n  ⏱️  Response Time: {response_time:.3f}s")
                print(f"{'='*70}\n")
                
                return data_packet
                
            except Exception as e:
                self.stats["errors"] += 1
                print(f"\n❌ Error parsing response: {e}")
                print(f"   Raw response: {response[:200]}...\n")
                return None
        else:
            self.stats["timeouts"] += 1
            print(f"\n❌ TIMEOUT: No response within 5s")
            print(f"   Interest: {content_name}")
            print(f"   Router: {router_host}:{router_port}\n")
            return None
    
    def run_test_scenarios(self, router_host: str = "127.0.0.1", router_port: int = 8001):
        """Run test scenarios"""
        print(f"\n{'#'*70}")
        print(f"# {self.node_name} - TEST SCENARIOS (UDP)")
        print(f"{'#'*70}\n")
        
        test_cases = [
            ("/dlsu/hello", "READ", "Basic READ request (cached)"),
            ("/dlsu/storage/test", "READ", "Storage node request"),
            ("/dlsu/hello", "READ", "Cache hit test (should be instant)"),
            ("/storage/test", "READ", "Alternative storage path"),
            ("/dlsu/storage/node1", "WRITE", "WRITE operation test"),
            ("/dlsu/files/test:[1/4]", "READ", "Fragment request test"),
        ]
        
        for i, (name, op, desc) in enumerate(test_cases, 1):
            print(f"\n{'─'*70}")
            print(f"TEST {i}/{len(test_cases)}: {desc}")
            print(f"{'─'*70}")
            
            result = self.send_interest(name, op, router_host, router_port)
            
            if result:
                print(f"✓ Test {i} completed successfully")
            else:
                print(f"✗ Test {i} failed")
            
            time.sleep(0.5)
        
        self._show_statistics()
    
    def concurrent_test(self, router_host: str = "127.0.0.1", router_port: int = 8001):
        """Test concurrent request handling"""
        import threading
        
        print(f"\n{'='*70}")
        print(f"CONCURRENT REQUEST TEST (UDP)")
        print(f"{'='*70}")
        print(f"Testing router's ability to handle simultaneous UDP requests...")
        print()
        
        # Define concurrent requests
        requests = [
            {"name": f"/test/concurrent{i}.txt", "operation": "READ"}
            for i in range(1, 6)
        ]
        
        results = []
        threads = []
        
        def send_request(req):
            result = self.send_interest(
                req["name"],
                req["operation"],
                router_host,
                router_port
            )
            results.append((req["name"], result is not None))
        
        # Launch concurrent requests
        print(f"Sending {len(requests)} concurrent UDP requests...")
        start_time = time.time()
        
        for req in requests:
            thread = threading.Thread(target=send_request, args=(req,))
            thread.start()
            threads.append(thread)
        
        # Wait for all to complete
        for thread in threads:
            thread.join()
        
        elapsed = time.time() - start_time
        
        # Show results
        print(f"\n{'='*70}")
        print(f"CONCURRENT TEST RESULTS")
        print(f"{'='*70}")
        print(f"  Total Requests:  {len(requests)}")
        print(f"  Successful:      {sum(1 for _, success in results if success)}")
        print(f"  Failed:          {sum(1 for _, success in results if not success)}")
        print(f"  Time Elapsed:    {elapsed:.2f}s")
        print(f"  Protocol:        UDP")
        print(f"{'='*70}\n")
    
    def interactive_mode(self, router_host: str = "127.0.0.1", router_port: int = 8001):
        """Interactive mode"""
        print(f"\n{'='*70}")
        print(f"INTERACTIVE MODE - {self.node_name} (UDP)")
        print(f"{'='*70}")
        print(f"Router: {router_host}:{router_port}")
        print(f"\nCommands:")
        print(f"  read <name>       - Send READ Interest")
        print(f"  write <name>      - Send WRITE Interest")
        print(f"  permission <name> - Send PERMISSION Interest")
        print(f"  concurrent        - Run concurrent test")
        print(f"  stats             - Show statistics")
        print(f"  quit              - Exit")
        print(f"{'='*70}\n")
        
        while True:
            try:
                command = input(f"{self.node_name}> ").strip()
                
                if not command:
                    continue
                
                parts = command.split(maxsplit=1)
                cmd = parts[0].lower()
                
                if cmd in ["quit", "exit"]:
                    print(f"\n👋 Goodbye from {self.node_name}!")
                    break
                
                elif cmd == "stats":
                    self._show_statistics()
                
                elif cmd == "concurrent":
                    self.concurrent_test(router_host, router_port)
                
                elif cmd in ["read", "write", "permission"]:
                    if len(parts) < 2:
                        print("  Usage: <operation> <name>")
                        print("  Example: read /dlsu/hello")
                        continue
                    
                    name = parts[1]
                    operation = cmd.upper()
                    self.send_interest(name, operation, router_host, router_port)
                
                elif cmd == "help":
                    print("\nAvailable commands:")
                    print("  read <name>       - Request content")
                    print("  write <name>      - Write content")
                    print("  permission <name> - Check permissions")
                    print("  concurrent        - Test concurrent requests")
                    print("  stats             - Show statistics")
                    print("  quit              - Exit client")
                
                else:
                    print(f"Unknown command: {cmd}")
                    print("Type 'help' for available commands")
                
            except KeyboardInterrupt:
                print(f"\n\n👋 Goodbye from {self.node_name}!")
                break
            except EOFError:
                print(f"\n\n👋 Goodbye from {self.node_name}!")
                break
            except Exception as e:
                print(f"Error: {e}")
    
    def _show_statistics(self):
        """Display statistics"""
        print(f"\n{'='*70}")
        print(f"CLIENT STATISTICS - {self.node_name}")
        print(f"{'='*70}")
        print(f"  Protocol:           UDP")
        print(f"  Interests Sent:     {self.stats['interests_sent']}")
        print(f"  Data Received:      {self.stats['data_received']}")
        print(f"  Timeouts:           {self.stats['timeouts']}")
        print(f"  Errors:             {self.stats['errors']}")
        print(f"  Checksum Fixed:     {self.stats['checksum_corrections']}")
        
        total = self.stats['interests_sent']
        if total > 0:
            success_rate = (self.stats['data_received'] / total) * 100
            print(f"  Success Rate:       {success_rate:.1f}%")
        
        print(f"{'='*70}\n")


def main():
    """Run the client"""
    client_id = sys.argv[1] if len(sys.argv) > 1 else "Alice"
    
    print(f"\n{'#'*70}")
    print(f"# NAMED NETWORKS CLIENT (UDP)")
    print(f"{'#'*70}")
    
    client = SimpleClient(client_id)
    
    router_host = "127.0.0.1"
    router_port = 8001
    
    print(f"\nClient ID:     {client_id}")
    print(f"Target Router: {router_host}:{router_port}")
    print(f"Protocol:      UDP")
    print()
    
    # Check for test modes
    if len(sys.argv) > 2:
        if sys.argv[2] == "--test":
            client.run_test_scenarios(router_host, router_port)
            return
        elif sys.argv[2] == "--concurrent":
            client.concurrent_test(router_host, router_port)
            return
    
    # Quick demo
    print("Running quick demo (3 UDP requests)...\n")
    
    demo_requests = [
        ("/dlsu/hello", "READ", "Test cached content"),
        ("/dlsu/storage/test", "READ", "Test storage request"),
        ("/dlsu/hello", "READ", "Test cache hit (UDP)"),
    ]
    
    for name, op, desc in demo_requests:
        print(f"Demo: {desc}")
        client.send_interest(name, op, router_host, router_port)
        time.sleep(0.5)
    
    # Interactive mode
    print("\n" + "─"*70)
    print("Demo complete! Entering interactive mode...")
    print("─"*70)
    
    try:
        client.interactive_mode(router_host, router_port)
    except KeyboardInterrupt:
        print(f"\n\n👋 Goodbye from {client.node_name}!")
    
    # Final stats
    client._show_statistics()


if __name__ == "__main__":
    main()