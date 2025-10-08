#!/usr/bin/env python3
"""
Router - Named Networks Framework
Hub-and-spoke topology with GUI debugging support
Enhanced packet visualization and logging
"""

import time
import threading
import sys
from communication_module import CommunicationModule
from parsing_module import ParsingModule
from processing_module import ProcessingModule
from routing_module import RoutingModule
from common import ContentStore, PendingInterestTable

# Import GUI if available
try:
    from debug_gui import DebugGUI
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False
    print("Warning: debug_gui.py not found. Running without GUI.")


class Router:
    """
    Router implementing hub-and-spoke topology
    Central hub connecting Client, Server, and Storage nodes
    """
    
    def __init__(self, router_id: str, host: str = "127.0.0.1", port: int = 8001, use_gui: bool = True):
        self.router_id = router_id
        self.node_name = f"Router-{router_id}"
        self.host = host
        self.port = port
        
        # Initialize GUI if requested and available
        self.gui = None
        if use_gui and GUI_AVAILABLE:
            self.gui = DebugGUI(self.node_name)
            gui_thread = threading.Thread(target=self._init_gui, daemon=True)
            gui_thread.start()
            time.sleep(0.5)  # Give GUI time to initialize
        
        self._log(f"Initializing Router...")
        
        # Initialize core modules (WITHOUT gui parameter for compatibility)
        self.comm_module = CommunicationModule(self.node_name, host, port)
        self.parsing_module = ParsingModule(self.node_name)
        self.processing_module = ProcessingModule(self.node_name)
        self.routing_module = RoutingModule(self.node_name)
        
        # Router-level statistics
        self.stats = {
            "packets_routed": 0,
            "clients_served": 0,
            "storage_requests": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "uptime_start": time.time()
        }
        
        # Set up module interfaces
        self._setup_module_interfaces()
        
        # Add default routes for hub-and-spoke topology
        self._setup_hub_spoke_routes()
        
        self._log(f"Router initialized successfully", "data")
    
    def _init_gui(self):
        """Initialize GUI in separate thread"""
        if self.gui:
            self.gui.initialize()
            self.gui.run()
    
    def _setup_module_interfaces(self):
        """Setup interfaces between modules"""
        self._log(f"Setting up module interfaces...")
        
        # Communication -> Parsing
        self.comm_module.set_packet_handler(self.parsing_module.handle_packet)
        
        # Parsing -> Processing (Router handles this directly)
        self.parsing_module.set_processing_handler(self._handle_parsed_packet)
        
        # Router handles routing directly, no need to connect Processing to Routing
        
        self._log(f"Module interfaces configured")
    
    def _setup_hub_spoke_routes(self):
        """Setup routes for hub-and-spoke topology"""
        self._log("Setting up hub-and-spoke routing table...")
        
        # Default routes (will be updated when nodes connect)
        # add_route(prefix, next_hop, interface, hop_count)
        self.routing_module.add_route("/server", "127.0.0.1:7001", "eth0", 1)
        self.routing_module.add_route("/storage", "127.0.0.1:9001", "eth0", 1)
        self.routing_module.add_route("/admin", "127.0.0.1:7001", "eth0", 1)
        
        self._log_control("=== Initial FIB Table ===")
        self.routing_module.show_fib()
    
    def _handle_parsed_packet(self, packet_obj, source: str, packet_type: str):
        """
        Handle parsed packet from Parsing Module
        Routes to appropriate destination
        """
        from common import InterestPacket, DataPacket
        
        if packet_type == "interest":
            return self._route_interest_packet(packet_obj, source)
        elif packet_type == "data":
            return self._route_data_packet(packet_obj, source)
        else:
            self._log_debug(f"❌ Unknown packet type: {packet_type}", "error")
            return None
    
    def _route_interest_packet(self, interest: 'InterestPacket', source: str):
        """Route Interest packet through the network"""
        self._log_debug(
            f"📨 INTEREST packet: {interest.name}",
            "interest"
        )
        self._log_debug(f"  Operation: {interest.operation}", "content")
        self._log_debug(f"  User: {interest.user_id}", "content")
        self._log_debug(f"  Nonce: {interest.nonce}", "content")
        self._log_debug(f"  From: {source}", "content")
        
        self.stats["packets_routed"] += 1
        
        # Step 1: Check Content Store (cache)
        cached_data = self.processing_module.content_store.get(interest.name)
        if cached_data:
            self.stats["cache_hits"] += 1
            self._log_debug(f"✓ Cache HIT: {interest.name}", "data")
            self._log_control(f"[CACHE HIT] {interest.name} ({len(cached_data)} bytes)")
            
            return self._create_data_response(interest.name, cached_data)
        
        self.stats["cache_misses"] += 1
        self._log_debug(f"✗ Cache MISS: {interest.name}", "content")
        
        # Step 2: Add to PIT
        self.processing_module.pit.add_entry(interest.name, source)
        self._log_control(f"[PIT] Added entry: {interest.name} from {source}")
        
        # Step 3: Lookup route in FIB
        routing_info = self.routing_module.get_routing_info(interest.name)
        
        if routing_info:
            next_hop, interface = routing_info
            self._log_debug(f"→ Forwarding to {next_hop} via {interface}", "content")
            self._log_control(f"[FIB LOOKUP] {interest.name} → {next_hop}")
            
            # For hub-and-spoke: forward to actual storage node
            self._log_debug(f"→ Forwarding to {next_hop} via {interface}", "content")
            self._log_control(f"[FIB LOOKUP] {interest.name} → {next_hop}")
            
            # Forward to actual storage node
            response_content = self._forward_to_storage(interest, next_hop)
            
            if response_content:
                # Cache the response
                content_bytes = response_content.encode('utf-8') if isinstance(response_content, str) else response_content
                self.processing_module.content_store.put(interest.name, content_bytes)
                self._log_control(f"[CACHE] Stored: {interest.name} ({len(content_bytes)} bytes)")
                
                self.stats["storage_requests"] += 1
                return response_content
            else:
                return self._create_error_response("Storage node not responding")
        else:
            self._log_debug(f"❌ No route found for {interest.name}", "error")
            return self._create_error_response("No route to destination")
    
    def _forward_to_storage(self, interest, next_hop):
        """Forward Interest to actual storage node"""
        try:
            # Parse host:port
            host, port = next_hop.split(':')
            port = int(port)
            
            self._log_debug(f"📤 Forwarding Interest to {host}:{port}", "interest")
            
            # Send Interest to storage node
            response = self.comm_module.send_packet_sync(host, port, interest.to_json())
            
            if response:
                self._log_debug(f"📥 Received response from storage node", "data")
                return response
            else:
                self._log_debug(f"⏱️ Storage node timeout", "error")
                return None
                
        except Exception as e:
            self._log_debug(f"❌ Forward error: {e}", "error")
            return None
        else:
            self._log_debug(f"❌ No route found for {interest.name}", "error")
            return self._create_error_response("No route to destination")
    
    def _route_data_packet(self, data_packet, source: str):
        """Route Data packet back to requester"""
        self._log_debug(f"📦 DATA packet: {data_packet.name}", "data")
        self._log_debug(f"  Length: {data_packet.data_length} bytes", "content")
        self._log_debug(f"  Checksum: {data_packet.checksum}", "content")
        
        # Show payload preview
        try:
            payload_preview = data_packet.data_payload.decode('utf-8', errors='ignore')[:100]
            self._log_debug(f"  Payload: {payload_preview}...", "payload")
        except:
            self._log_debug(f"  Payload: [Binary data]", "payload")
        
        # Cache the data packet
        self.processing_module.content_store.put(data_packet.name, data_packet.data_payload)
        self._log_control(f"[CACHE] Stored: {data_packet.name}")
        
        return "ACK"
    
    def _simulate_storage_response(self, interest):
        """Simulate storage node response (temporary for hub-spoke testing)"""
        content_templates = {
            "READ": f"Content for {interest.name} requested by {interest.user_id}",
            "WRITE": f"Write operation acknowledged for {interest.name}",
            "PERMISSION": f"Permission granted for {interest.user_id} on {interest.name}"
        }
        
        # Special test responses
        if "/dlsu/hello" in interest.name:
            return "Hello from DLSU Named Networks Router! Your hub-and-spoke topology is working!"
        elif "/dlsu/goks" in interest.name:
            return "Welcome to DLSU Goks community network!"
        elif "/storage" in interest.name:
            return f"Storage content from {interest.name} (RAID 0 configuration)"
        elif "/server" in interest.name:
            return f"Server response for {interest.name}"
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
        
        self._log_debug(f"✉️  Created DATA response for {name}", "data")
        
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
        
        self._log_debug(f"⚠️  Created ERROR response: {error_message}", "error")
        
        return data_packet.to_json()
    
    def add_route(self, prefix: str, next_hop: str):
        """Add route to FIB"""
        self.routing_module.add_route(prefix, next_hop, "eth0", 1)
        self._log_control(f"[FIB] Added route: {prefix} → {next_hop}")
    
    def start(self):
        """Start the router"""
        self._log(f"Starting router...", "interest")
        
        # Start communication module
        self.comm_module.start()
        
        # Add test content
        self._add_test_content()
        
        self._log(f"Router started on {self.host}:{self.port} (UDP)", "data")
        self._log(f"Ready to route Named Networks traffic", "data")
        
        # Show initial configuration
        self.show_configuration()
    
    def stop(self):
        """Stop the router"""
        self._log(f"Stopping router...")
        
        # Stop communication module
        self.comm_module.stop()
        
        # Show final statistics
        self.show_comprehensive_stats()
        
        self._log(f"Router stopped")
    
    def _add_test_content(self):
        """Add test content for demonstration"""
        test_content = {
            "/dlsu/hello": b"Hello from DLSU Named Networks!",
            "/dlsu/public/info": b"Public information accessible to all users",
            "/test/sample": b"Sample test data for validation"
        }
        
        for name, content in test_content.items():
            self.processing_module.content_store.put(name, content)
        
        self._log_control(f"[CACHE] Pre-loaded {len(test_content)} test entries")
    
    def show_configuration(self):
        """Display router configuration"""
        self._log_control("=" * 50)
        self._log_control(f"ROUTER CONFIGURATION: {self.node_name}")
        self._log_control("=" * 50)
        self._log_control(f"Network: {self.host}:{self.port} (UDP)")
        self._log_control(f"Topology: Hub-and-Spoke")
        self._log_control(f"Modules: Communication, Parsing, Processing, Routing")
        self._log_control("=" * 50)
        
        # Show FIB
        self.routing_module.show_fib()
        
        # Show initial cache
        self._show_cache_contents()
    
    def show_comprehensive_stats(self):
        """Display comprehensive statistics"""
        uptime = time.time() - self.stats['uptime_start']
        
        self._log_control("=" * 50)
        self._log_control(f"ROUTER STATISTICS: {self.node_name}")
        self._log_control("=" * 50)
        self._log_control(f"Uptime: {uptime:.2f} seconds")
        self._log_control(f"Packets Routed: {self.stats['packets_routed']}")
        self._log_control(f"Cache Hits: {self.stats['cache_hits']}")
        self._log_control(f"Cache Misses: {self.stats['cache_misses']}")
        
        if self.stats['cache_hits'] + self.stats['cache_misses'] > 0:
            hit_rate = (self.stats['cache_hits'] / 
                       (self.stats['cache_hits'] + self.stats['cache_misses'])) * 100
            self._log_control(f"Cache Hit Rate: {hit_rate:.1f}%")
        
        print(f"Storage Requests: {self.stats['storage_requests']}")
        
        # Communication stats (create stub since method doesn't exist)
        try:
            comm_stats = self.comm_module.get_stats()
        except AttributeError:
            comm_stats = {"packets_received": "N/A", "packets_sent": "N/A", "errors": "N/A"}
        
        self._log_control(f"Packets RX: {comm_stats['packets_received']}")
        self._log_control(f"Packets TX: {comm_stats['packets_sent']}")
        self._log_control(f"Errors: {comm_stats['errors']}")
        self._log_control("=" * 50)
    
    def _show_cache_contents(self):
        """Show Content Store contents"""
        self._log_control("=== Content Store ===")
        store = self.processing_module.content_store.store
        if not store:
            self._log_control("  (empty)")
        else:
            for name, content in store.items():
                size = len(content)
                self._log_control(f"  {name} ({size} bytes)")
        self._log_control("=" * 20)
    
    def _log(self, message: str, log_type: str = "normal"):
        """Internal logging"""
        print(f"[{self.node_name}] {message}")
    
    def _log_control(self, message: str):
        """Log to control panel"""
        if self.gui:
            self.gui.log_control(message)
        else:
            print(f"[{self.node_name}][CONTROL] {message}")
    
    def _log_debug(self, message: str, msg_type: str = "normal"):
        """Log to debug panel"""
        if self.gui:
            self.gui.log_debug(message, msg_type)
        else:
            print(f"[{self.node_name}][DEBUG] {message}")
    
    def interactive_commands(self):
        """Interactive command interface"""
        print("\nRouter Management Commands:")
        print("  show cache  - Display Content Store contents")
        print("  show fib    - Display FIB routing table")
        print("  show pit    - Display PIT table")
        print("  show stats  - Display statistics")
        print("  route <prefix> <nexthop> - Add route")
        print("  quit        - Stop router")
        print()
        
        while True:
            try:
                command = input(f"{self.node_name}> ").strip().lower()
                
                if command == "quit" or command == "exit":
                    break
                elif command == "show cache":
                    self._show_cache_contents()
                elif command == "show fib":
                    self.routing_module.show_fib()
                elif command == "show pit":
                    # Simple PIT display since show() method doesn't exist
                    pit_table = self.processing_module.pit.table
                    if not pit_table:
                        print("PIT is empty")
                    else:
                        print("=== PIT Table ===")
                        for name, faces in pit_table.items():
                            print(f"{name}: {faces}")
                        print("=" * 20)
                elif command == "show stats":
                    self.show_comprehensive_stats()
                elif command.startswith("route"):
                    self._handle_route_command(command)
                elif command:
                    print(f"Unknown command: {command}")
                    
            except (KeyboardInterrupt, EOFError):
                break
    
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
    router_id = sys.argv[1] if len(sys.argv) > 1 else "R1"
    
    print("="*70)
    print("NAMED NETWORKS ROUTER - HUB-AND-SPOKE TOPOLOGY")
    print("="*70)
    
    # Create router with GUI
    router = Router(router_id, use_gui=True)
    
    try:
        router.start()
        
        print("\n✓ Router is running with debugging GUI")
        print("  - Check GUI window for real-time packet visualization")
        print("  - Interest packets shown in RED")
        print("  - Data packets shown in BLUE")
        print("\nTest with:")
        print("  python simple_client.py Alice")
        print("  python simple_client.py Bob")
        print("\n" + "="*70 + "\n")
        
        # Interactive command interface
        router.interactive_commands()
        
    except KeyboardInterrupt:
        print("\n\nShutting down router...")
    finally:
        router.stop()
        print("Router stopped. Goodbye!")


if __name__ == "__main__":
    main()