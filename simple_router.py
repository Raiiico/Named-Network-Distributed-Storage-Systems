#!/usr/bin/env python3
"""
Simple Named Networks Router
Implements Communication Module and Parsing Module integration
"""

import time
import threading
from communication_module import CommunicationModule
from parsing_module import ParsingModule
from common import InterestPacket, DataPacket, ContentStore, PendingInterestTable

class SimpleRouter:
    """
    Simple Router implementing Communication and Parsing modules
    Testing the interface between these core components
    """
    
    def __init__(self, router_id: str, host: str = "127.0.0.1", port: int = 8001):
        self.router_id = router_id
        self.node_name = f"Router-{router_id}"
        self.host = host
        self.port = port
        
        # Initialize core modules
        self.comm_module = CommunicationModule(self.node_name, host, port)
        self.parsing_module = ParsingModule(self.node_name)
        
        # Named Networks data structures (basic implementation)
        self.content_store = ContentStore()
        self.pit = PendingInterestTable()
        
        # Statistics
        self.stats = {
            "total_interests": 0,
            "total_data_packets": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "parsing_errors": 0
        }
        
        # Set up module connections
        self._setup_module_interfaces()
        
        print(f"[{self.node_name}] Router initialized")
    
    def _setup_module_interfaces(self):
        """Setup interfaces between modules"""
        # Communication Module -> Parsing Module
        self.comm_module.set_packet_handler(self.parsing_module.handle_packet)
        
        # Parsing Module -> Processing logic (simplified for now)
        self.parsing_module.set_processing_handler(self.handle_parsed_packet)
        
        print(f"[{self.node_name}] Module interfaces configured")
    
    def start(self):
        """Start the router"""
        print(f"[{self.node_name}] Starting router...")
        
        # Start communication module
        self.comm_module.start()
        
        print(f"[{self.node_name}] Router started on {self.host}:{self.port}")
        print(f"[{self.node_name}] Ready to handle Named Networks traffic")
    
    def stop(self):
        """Stop the router"""
        print(f"[{self.node_name}] Stopping router...")
        
        # Stop communication module
        self.comm_module.stop()
        
        # Show final statistics
        self.show_stats()
        
        print(f"[{self.node_name}] Router stopped")
    
    def handle_parsed_packet(self, packet, source: str, packet_type: str):
        """
        Handle packet from Parsing Module
        This simulates the Processing Module functionality
        """
        try:
            if packet_type == "interest":
                return self._handle_interest(packet, source)
            elif packet_type == "data":
                return self._handle_data(packet, source)
            else:
                print(f"[{self.node_name}] Unknown packet type: {packet_type}")
                return None
                
        except Exception as e:
            print(f"[{self.node_name}] Error handling parsed packet: {e}")
            self.stats["parsing_errors"] += 1
            return self._create_error_response("Processing error")
    
    def _handle_interest(self, interest: InterestPacket, source: str):
        """Handle parsed Interest packet (simplified processing)"""
        self.stats["total_interests"] += 1
        
        print(f"[{self.node_name}] Processing Interest: {interest.name}")
        print(f"[{self.node_name}] Operation: {interest.operation}, User: {interest.user_id}")
        
        # Check Content Store first
        cached_content = self.content_store.get(interest.name)
        if cached_content:
            self.stats["cache_hits"] += 1
            print(f"[{self.node_name}] Content Store HIT for: {interest.name}")
            
            # Return cached content
            data_packet = DataPacket(
                name=interest.name,
                data_payload=cached_content,
                data_length=len(cached_content),
                checksum="cached"
            )
            return data_packet.to_json()
        
        # Content Store miss
        self.stats["cache_misses"] += 1
        print(f"[{self.node_name}] Content Store MISS for: {interest.name}")
        
        # Add to PIT
        self.pit.add_entry(interest.name, source)
        
        # For now, generate simple response based on operation
        response_content = self._generate_simple_content(interest)
        
        # Cache the content
        content_bytes = response_content.encode('utf-8')
        self.content_store.put(interest.name, content_bytes)
        
        # Create Data packet response
        data_packet = DataPacket(
            name=interest.name,
            data_payload=content_bytes,
            data_length=len(content_bytes),
            checksum="router_generated"
        )
        
        # Remove from PIT
        self.pit.remove_entry(interest.name)
        
        return data_packet.to_json()
    
    def _handle_data(self, data_packet: DataPacket, source: str):
        """Handle parsed Data packet"""
        self.stats["total_data_packets"] += 1
        
        print(f"[{self.node_name}] Received Data packet: {data_packet.name}")
        print(f"[{self.node_name}] Data length: {data_packet.data_length} bytes")
        
        # Cache the data
        self.content_store.put(data_packet.name, data_packet.data_payload)
        
        # Forward to interested faces (simplified)
        faces = self.pit.get_faces(data_packet.name)
        for face in faces:
            print(f"[{self.node_name}] Would forward Data to: {face}")
        
        self.pit.remove_entry(data_packet.name)
        
        return "ACK"
    
    def _generate_simple_content(self, interest: InterestPacket) -> str:
        """Generate simple content based on Interest (for testing)"""
        content_templates = {
            "READ": f"Content for {interest.name} requested by {interest.user_id}",
            "WRITE": f"Write operation acknowledged for {interest.name} by {interest.user_id}",
            "PERMISSION": f"Permission check for {interest.name} by {interest.user_id}: GRANTED"
        }
        
        # Special content for specific paths
        if interest.name.startswith("/dlsu/hello"):
            return "Hello from DLSU Named Networks Router!"
        elif interest.name.startswith("/dlsu/goks"):
            return "Welcome to GOKS Named Networks project!"
        elif interest.name.startswith("/dlsu/storage"):
            return f"Storage node {interest.name} is active and ready"
        elif "large.pdf" in interest.name:
            return "This is fragment content from a large PDF file"
        else:
            return content_templates.get(interest.operation, "Generic content response")
    
    def _create_error_response(self, error_msg: str) -> str:
        """Create error response"""
        error_packet = DataPacket(
            name="/error",
            data_payload=error_msg.encode('utf-8'),
            data_length=len(error_msg),
            checksum="error"
        )
        return error_packet.to_json()
    
    def show_stats(self):
        """Display router statistics"""
        print(f"\n=== {self.node_name} Statistics ===")
        print(f"Total Interest packets: {self.stats['total_interests']}")
        print(f"Total Data packets: {self.stats['total_data_packets']}")
        print(f"Cache hits: {self.stats['cache_hits']}")
        print(f"Cache misses: {self.stats['cache_misses']}")
        print(f"Parsing errors: {self.stats['parsing_errors']}")
        
        # Buffer status
        buffer_status = self.comm_module.get_buffer_status()
        print(f"Receive buffer: {buffer_status['receive_buffer_size']}/{buffer_status['max_buffer_size']}")
        print(f"Send buffer: {buffer_status['send_buffer_size']}/{buffer_status['max_buffer_size']}")
        
        # Content Store status
        print(f"Content Store entries: {len(self.content_store.store)}")
        if self.content_store.store:
            print("Cached content:")
            for name in list(self.content_store.store.keys())[:5]:  # Show first 5
                print(f"  - {name}")
            if len(self.content_store.store) > 5:
                print(f"  ... and {len(self.content_store.store) - 5} more")
        
        print("=" * 40)
    
    def add_test_content(self):
        """Add some test content to Content Store"""
        test_content = {
            "/dlsu/test/cached": b"This content was pre-cached",
            "/dlsu/demo/content": b"Demo content for testing",
            "/dlsu/storage/info": b"Storage system information"
        }
        
        for name, content in test_content.items():
            self.content_store.put(name, content)
        
        print(f"[{self.node_name}] Added {len(test_content)} test content items")

def main():
    """Run the router"""
    import sys
    
    # Get router ID from command line
    router_id = sys.argv[1] if len(sys.argv) > 1 else "R1"
    
    router = SimpleRouter(router_id)
    
    # Add some test content
    router.add_test_content()
    
    try:
        router.start()
        
        print("\n" + "="*60)
        print("Router is running. Test with:")
        print("  python simple_client.py Alice")
        print("  python simple_client.py Bob")
        print("Press Ctrl+C to stop and show statistics")
        print("="*60 + "\n")
        
        # Keep running
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nShutting down router...")
        router.stop()

if __name__ == "__main__":
    main()