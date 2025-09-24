#!/usr/bin/env python3
"""
Router - Named Networks Framework
Uses Communication, Parsing, Processing, and Routing modules
Routes packets between Clients and Storage Nodes
"""

import time
import threading
from communication_module import CommunicationModule
from parsing_module import ParsingModule
from processing_module import ProcessingModule
from routing_module import RoutingModule
from common import ContentStore, PendingInterestTable

class Router:
    """
    Router implementing core Named Networks functionality
    Routes between Clients and Storage Nodes
    """
    
    def __init__(self, router_id: str, host: str = "127.0.0.1", port: int = 8001):
        self.router_id = router_id
        self.node_name = f"Router-{router_id}"
        self.host = host
        self.port = port
        
        print(f"[{self.node_name}] Initializing Router...")
        
        # Initialize core modules (no Security module yet)
        self.comm_module = CommunicationModule(self.node_name, host, port)
        self.parsing_module = ParsingModule(self.node_name)
        self.processing_module = ProcessingModule(self.node_name)
        self.routing_module = RoutingModule(self.node_name)
        
        # Router-level statistics
        self.stats = {
            "packets_routed": 0,
            "clients_served": 0,
            "storage_requests": 0,
            "uptime_start": time.time()
        }
        
        # Set up module interfaces
        self._setup_module_interfaces()
        
        print(f"[{self.node_name}] Router initialized successfully")
    
    def _setup_module_interfaces(self):
        """Setup interfaces between modules"""
        print(f"[{self.node_name}] Setting up module interfaces...")
        
        # Communication -> Parsing
        self.comm_module.set_packet_handler(self.parsing_module.handle_packet)
        
        # Parsing -> Processing
        self.parsing_module.set_processing_handler(self._handle_processed_packet)
        
        # Processing doesn't connect to Security/Storage modules yet
        # Instead, we'll handle routing directly in this router
        
        print(f"[{self.node_name}] Module interfaces configured")
    
    def _handle_processed_packet(self, packet, source: str, packet_type: str):
        """
        Handle packets from Processing Module
        Route to appropriate destination
        """
        try:
            if packet_type == "interest":
                return self._route_interest_packet(packet, source)
            elif packet_type == "data":
                return self._route_data_packet(packet, source)
            else:
                print(f"[{self.node_name}] Unknown packet type: {packet_type}")
                return self._create_error_response("Unknown packet type")
                
        except Exception as e:
            print(f"[{self.node_name}] Error handling processed packet: {e}")
            return self._create_error_response("Routing error")
    
    def _route_interest_packet(self, interest, source: str):
        """Route Interest packet based on content name"""
        self.stats["packets_routed"] += 1
        
        print(f"[{self.node_name}] Routing Interest: {interest.name}")
        
        # Check local Content Store first
        cached_content = self.processing_module.content_store.get(interest.name)
        if cached_content:
            print(f"[{self.node_name}] Content Store HIT: {interest.name}")
            return self._create_data_response(interest.name, cached_content)
        
        print(f"[{self.node_name}] Content Store MISS: {interest.name}")
        
        # Use routing module to find next hop
        routing_info = self.routing_module.get_routing_info(interest.name)
        
        if routing_info:
            next_hop, interface = routing_info
            print(f"[{self.node_name}] Forwarding to {next_hop} via {interface}")
            
            # For now, simulate forwarding by generating response
            # In real implementation, would forward to actual storage node
            response_content = self._simulate_storage_response(interest)
            
            # Cache the response
            content_bytes = response_content.encode('utf-8')
            self.processing_module.content_store.put(interest.name, content_bytes)
            
            self.stats["storage_requests"] += 1
            return self._create_data_response(interest.name, content_bytes)
        else:
            print(f"[{self.node_name}] No route found for {interest.name}")
            return self._create_error_response("No route to destination")
    
    def _route_data_packet(self, data_packet, source: str):
        """Route Data packet back to requester"""
        print(f"[{self.node_name}] Routing Data packet: {data_packet.name}")
        
        # Cache the data packet
        self.processing_module.content_store.put(data_packet.name, data_packet.data_payload)
        
        # In real implementation, would forward to requesting client
        return "ACK"
    
    def _simulate_storage_response(self, interest):
        """
        Simulate storage node response
        In real implementation, this would forward to actual storage nodes
        """
        content_templates = {
            "READ": f"Content for {interest.name} requested by {interest.user_id}",
            "WRITE": f"Write operation acknowledged for {interest.name}",
            "PERMISSION": f"Permission operation for {interest.name}"
        }
        
        # Special responses for known paths
        if "/dlsu/hello" in interest.name:
            return "Hello from DLSU Named Networks Router!"
        elif "/dlsu/public" in interest.name:
            return "Public content accessible to all users"
        elif "/dlsu/storage" in interest.name:
            return f"Storage content from {interest.name}"
        else:
            return content_templates.get(interest.operation, f"Response for {interest.name}")
    
    def _create_data_response(self, name: str, content: bytes) -> str:
        """Create Data packet response"""
        from common import DataPacket, calculate_checksum
        
        if isinstance(content, str):
            content = content.encode('utf-8')
            
        data_packet = DataPacket(
            name=name,
            data_payload=content,
            data_length=len(content),
            checksum=calculate_checksum(content.decode('utf-8', errors='ignore'))
        )
        return data_packet.to_json()
    
    def _create_error_response(self, error_message: str) -> str:
        """Create error Data packet response"""
        from common import DataPacket
        
        data_packet = DataPacket(
            name="/error",
            data_payload=error_message.encode('utf-8'),
            data_length=len(error_message),
            checksum="error"
        )
        return data_packet.to_json()
    
    def start(self):
        """Start the router"""
        print(f"[{self.node_name}] Starting router...")
        
        # Start communication module
        self.comm_module.start()
        
        # Add some test content
        self._add_test_content()
        
        print(f"[{self.node_name}] Router started on {self.host}:{self.port}")
        print(f"[{self.node_name}] Ready to route Named Networks traffic")
        
        # Show routing table
        self.routing_module.show_fib()
    
    def stop(self):
        """Stop the router"""
        print(f"[{self.node_name}] Stopping router...")
        
        # Stop communication module
        self.comm_module.stop()
        
        # Show final statistics
        self.show_comprehensive_stats()
        
        print(f"[{self.node_name}] Router stopped")
    
    def _add_test_content(self):
        """Add test content for caching demonstration"""
        test_content = {
            "/dlsu/hello": b"Hello from DLSU Named Networks!",
            "/dlsu/public/info": b"Public information for all users",
            "/dlsu/test/cached": b"This content was pre-cached for testing"
        }
        
        for name, content in test_content.items():
            self.processing_module.content_store.put(name, content)
        
        print(f"[{self.node_name}] Added {len(test_content)} test content items")
    
    def add_route(self, prefix: str, next_hop: str, interface: str = "eth0"):
        """Add a new route to the routing table"""
        self.routing_module.add_route(prefix, next_hop, interface)
    
    def show_comprehensive_stats(self):
        """Display statistics from all modules"""
        print(f"\n=== {self.node_name} Comprehensive Statistics ===")
        
        # Router-level stats
        uptime = time.time() - self.stats['uptime_start']
        print(f"Router Uptime: {uptime:.1f} seconds")
        print(f"Packets Routed: {self.stats['packets_routed']}")
        print(f"Clients Served: {self.stats['clients_served']}")
        print(f"Storage Requests: {self.stats['storage_requests']}")
        
        print("\n" + "="*60)
        
        # Module statistics
        print("COMMUNICATION MODULE:")
        buffer_status = self.comm_module.get_buffer_status()
        print(f"  Receive Buffer: {buffer_status['receive_buffer_size']}/100")
        print(f"  Send Buffer: {buffer_status['send_buffer_size']}/100")
        
        print("\nPROCESSING MODULE:")
        processing_stats = self.processing_module.get_processing_stats()
        print(f"  Interests Processed: {processing_stats['total_interests_processed']}")
        print(f"  Cache Hits: {processing_stats['cache_hits']}")
        print(f"  Cache Misses: {processing_stats['cache_misses']}")
        print(f"  Cache Hit Ratio: {processing_stats['cache_hit_ratio']:.1%}")
        
        print("\nROUTING MODULE:")
        self.routing_module.show_stats()
        
        print("\n" + "="*60)
    
    def interactive_commands(self):
        """Interactive command interface for router management"""
        print("\nAvailable commands:")
        print("  'stats' - Show comprehensive statistics")
        print("  'fib' - Show Forwarding Information Base")
        print("  'cache' - Show Content Store contents")
        print("  'route <prefix> <next_hop>' - Add new route")
        print("  'quit' - Stop router")
        
        while True:
            try:
                command = input(f"{self.router_id}> ").strip()
                
                if command.lower() in ['quit', 'exit', 'q']:
                    break
                elif command.lower() == 'stats':
                    self.show_comprehensive_stats()
                elif command.lower() == 'fib':
                    self.routing_module.show_fib()
                elif command.lower() == 'cache':
                    self._show_cache_contents()
                elif command.lower().startswith('route'):
                    self._handle_route_command(command)
                elif command.lower() == 'help':
                    print("Available commands: stats, fib, cache, route, quit")
                elif command == '':
                    continue
                else:
                    print(f"Unknown command: {command}")
                    
            except KeyboardInterrupt:
                break
    
    def _show_cache_contents(self):
        """Show Content Store contents"""
        print(f"\n=== {self.node_name} Content Store ===")
        store = self.processing_module.content_store.store
        if not store:
            print("Content Store is empty")
        else:
            for name, content in store.items():
                content_preview = content[:50] if len(content) > 50 else content
                print(f"{name}: {content_preview}...")
        print("=" * 50)
    
    def _handle_route_command(self, command):
        """Handle route addition command"""
        parts = command.split()
        if len(parts) >= 3:
            prefix = parts[1]
            next_hop = parts[2]
            self.add_route(prefix, next_hop)
            print(f"Added route: {prefix} -> {next_hop}")
        else:
            print("Usage: route <prefix> <next_hop>")
    
    def get_port(self):
        """Get the actual port being used"""
        return self.comm_module.get_port()

def main():
    """Run the router"""
    import sys
    
    # Get router ID from command line
    router_id = sys.argv[1] if len(sys.argv) > 1 else "R1"
    
    # Create router
    router = Router(router_id)
    
    try:
        router.start()
        
        print("\n" + "="*70)
        print("NAMED NETWORKS ROUTER")
        print("="*70)
        print("Router is running with Communication, Parsing, Processing, and Routing modules.")
        print("Test with:")
        print("  python simple_client.py Alice")
        print("  python simple_client.py Bob")
        print("\nRouter management interface available.")
        print("="*70 + "\n")
        
        # Start interactive command interface
        router.interactive_commands()
        
    except KeyboardInterrupt:
        print("\nShutting down router...")
    finally:
        router.stop()

if __name__ == "__main__":
    main()