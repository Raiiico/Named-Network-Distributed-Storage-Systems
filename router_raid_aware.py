#!/usr/bin/env python3
"""
RAID-Aware Router - Named Networks Framework
Implements RAID 0 (striping) and RAID 1 (mirroring) across storage nodes
Demonstrates data distribution and fragment management
"""

import time
import threading
import sys
import json
from communication_module import CommunicationModule
from parsing_module import ParsingModule
from processing_module import ProcessingModule
from routing_module import RoutingModule
from common import ContentStore, PendingInterestTable, DataPacket, calculate_checksum

try:
    from debug_gui import DebugGUI
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False


class RAIDAwareRouter:
    """
    Router implementing RAID-aware data distribution
    - RAID 0: Striping across ST1 and ST2
    - RAID 1: Mirroring to both ST1 and ST2
    """
    
    def __init__(self, router_id: str, host: str = "127.0.0.1", port: int = 8001, use_gui: bool = True):
        self.router_id = router_id
        self.node_name = f"Router-{router_id}"
        self.host = host
        self.port = port
        
        # Storage node configuration
        self.storage_nodes = {
            "ST1": {"host": "127.0.0.1", "port": 9001, "raid": 0, "status": "unknown"},
            "ST2": {"host": "127.0.0.1", "port": 9002, "raid": 1, "status": "unknown"}
        }
        
        # RAID configuration
        self.raid_mode = "RAID1"  # Default: RAID1 (mirroring)
        self.fragment_size = 512  # bytes for RAID 0 striping
        
        # Initialize GUI
        self.gui = None
        if use_gui and GUI_AVAILABLE:
            self.gui = DebugGUI(self.node_name)
            gui_thread = threading.Thread(target=self._init_gui, daemon=True)
            gui_thread.start()
            time.sleep(0.5)
        
        self._log("Initializing RAID-Aware Router...")
        
        # Initialize modules
        self.comm_module = CommunicationModule(self.node_name, host, port)
        self.parsing_module = ParsingModule(self.node_name)
        self.processing_module = ProcessingModule(self.node_name)
        self.routing_module = RoutingModule(self.node_name)
        
        # Statistics
        self.stats = {
            "packets_routed": 0,
            "raid0_operations": 0,
            "raid1_operations": 0,
            "fragments_created": 0,
            "mirrors_created": 0,
            "storage_failures": 0,
            "uptime_start": time.time()
        }
        
        self._setup_module_interfaces()
        self._setup_storage_routes()
        
        self._log("RAID-Aware Router initialized", "data")
    
    def _init_gui(self):
        if self.gui:
            self.gui.initialize()
            self.gui.run()
    
    def _setup_module_interfaces(self):
        self.comm_module.set_packet_handler(self.parsing_module.handle_packet)
        self.parsing_module.set_processing_handler(self._handle_parsed_packet)
    
    def _setup_storage_routes(self):
        """Setup routes to storage nodes"""
        self._log_control("=== Storage Node Configuration ===")
        for node_id, config in self.storage_nodes.items():
            route = f"{config['host']}:{config['port']}"
            self.routing_module.add_route(f"/storage/{node_id}", route, "eth0", 1)
            self._log_control(f"{node_id} (RAID {config['raid']}): {route}")
        self._log_control("=" * 50)
    
    def set_raid_mode(self, mode: str):
        """Set RAID mode: RAID0 or RAID1"""
        if mode.upper() in ["RAID0", "RAID1"]:
            self.raid_mode = mode.upper()
            self._log_control(f"RAID mode set to: {self.raid_mode}")
        else:
            self._log_control(f"Invalid RAID mode: {mode}")
    
    def _handle_parsed_packet(self, packet_obj, source: str, packet_type: str):
        """Handle parsed packets with RAID awareness"""
        from common import InterestPacket
        
        if packet_type == "interest":
            return self._route_interest_with_raid(packet_obj, source)
        elif packet_type == "data":
            return self._handle_data_packet(packet_obj, source)
        else:
            return None
    
    def _route_interest_with_raid(self, interest: 'InterestPacket', source: str):
        """Route Interest with RAID-aware distribution"""
        self._log_debug(f"📨 INTEREST: {interest.name}", "interest")
        self._log_debug(f"  Operation: {interest.operation}", "content")
        self._log_debug(f"  User: {interest.user_id}", "content")
        self._log_debug(f"  RAID Mode: {self.raid_mode}", "content")
        
        self.stats["packets_routed"] += 1
        
        # Check cache first
        cached_data = self.processing_module.content_store.get(interest.name)
        if cached_data:
            self._log_debug(f"✅ Cache HIT: {interest.name}", "data")
            self._log_control(f"[CACHE HIT] {interest.name}")
            return self._create_data_response(interest.name, cached_data)
        
        self._log_debug(f"❌ Cache MISS: {interest.name}", "content")
        self.processing_module.pit.add_entry(interest.name, source)
        
        # Route based on operation and RAID mode
        if interest.operation == "READ":
            return self._handle_raid_read(interest)
        elif interest.operation == "WRITE":
            return self._handle_raid_write(interest)
        else:
            return self._forward_to_primary_storage(interest)
    
    def _handle_raid_read(self, interest):
        """
        Handle READ with RAID awareness:
        - RAID 0: Try to reassemble from fragments
        - RAID 1: Read from primary, fallback to mirror
        """
        self._log_control(f"[READ] {interest.name} using {self.raid_mode}")
        
        if self.raid_mode == "RAID0":
            # RAID 0: Try to read fragments from both nodes
            return self._read_raid0_striped(interest)
        else:  # RAID1
            # RAID 1: Read from primary, fallback to mirror
            return self._read_raid1_mirrored(interest)
    
    def _read_raid0_striped(self, interest):
        """
        RAID 0 Read: Retrieve fragments from both storage nodes
        Fragment notation: /path/file:[0/2], /path/file:[1/2]
        """
        self._log_control(f"[RAID0 READ] Attempting to read fragments")
        self.stats["raid0_operations"] += 1
        
        # Check if this is already a fragment request
        if ":[" in interest.name:
            # Direct fragment request - forward to appropriate node
            return self._forward_fragment_request(interest)
        
        # Try to get fragments from both nodes
        fragments = {}
        total_fragments = 2  # We stripe across 2 nodes
        
        for fragment_idx in range(total_fragments):
            fragment_name = f"{interest.name}:[{fragment_idx}/{total_fragments}]"
            
            # Determine which node has this fragment (even=ST1, odd=ST2)
            storage_node = "ST1" if fragment_idx % 2 == 0 else "ST2"
            
            self._log_debug(f"  Requesting fragment {fragment_idx} from {storage_node}", "content")
            
            # Create fragment interest
            from common import InterestPacket
            fragment_interest = InterestPacket(
                name=fragment_name,
                user_id=interest.user_id,
                operation="READ",
                nonce=interest.nonce + fragment_idx
            )
            
            # Forward to storage node
            node_config = self.storage_nodes[storage_node]
            response = self.comm_module.send_packet_sync(
                node_config["host"],
                node_config["port"],
                fragment_interest.to_json()
            )
            
            if response:
                try:
                    data_packet = DataPacket.from_json(response)
                    if "/error" not in data_packet.name:
                        fragments[fragment_idx] = data_packet.data_payload
                        self._log_debug(f"  ✅ Fragment {fragment_idx} retrieved", "data")
                except:
                    self._log_debug(f"  ❌ Fragment {fragment_idx} failed", "error")
        
        # Reassemble fragments
        if len(fragments) == total_fragments:
            reassembled = b"".join([fragments[i] for i in sorted(fragments.keys())])
            
            self._log_control(f"[RAID0] ✅ Reassembled {len(reassembled)} bytes from {len(fragments)} fragments")
            self.stats["fragments_created"] += len(fragments)
            
            # Cache reassembled content
            self.processing_module.content_store.put(interest.name, reassembled)
            
            self.processing_module.pit.remove_entry(interest.name)
            return self._create_data_response(interest.name, reassembled)
        else:
            self._log_control(f"[RAID0] ❌ Failed to retrieve all fragments ({len(fragments)}/{total_fragments})")
            self.stats["storage_failures"] += 1
            return self._create_error_response("RAID 0 fragment retrieval failed")
    
    def _read_raid1_mirrored(self, interest):
        """
        RAID 1 Read: Try primary node first, fallback to mirror
        """
        self._log_control(f"[RAID1 READ] Attempting primary then mirror")
        self.stats["raid1_operations"] += 1
        
        # Try ST1 first (primary)
        st1_response = self._forward_to_storage_node(interest, "ST1")
        
        if st1_response and "/error" not in st1_response:
            self._log_control(f"[RAID1] ✅ Read from ST1 (primary)")
            
            # Cache the response
            try:
                data_packet = DataPacket.from_json(st1_response)
                self.processing_module.content_store.put(interest.name, data_packet.data_payload)
            except:
                pass
            
            self.processing_module.pit.remove_entry(interest.name)
            return st1_response
        
        # Fallback to ST2 (mirror)
        self._log_control(f"[RAID1] Primary failed, trying ST2 (mirror)")
        st2_response = self._forward_to_storage_node(interest, "ST2")
        
        if st2_response and "/error" not in st2_response:
            self._log_control(f"[RAID1] ✅ Read from ST2 (mirror/fallback)")
            
            # Cache the response
            try:
                data_packet = DataPacket.from_json(st2_response)
                self.processing_module.content_store.put(interest.name, data_packet.data_payload)
            except:
                pass
            
            self.processing_module.pit.remove_entry(interest.name)
            return st2_response
        
        # Both failed
        self._log_control(f"[RAID1] ❌ Both storage nodes failed")
        self.stats["storage_failures"] += 1
        self.processing_module.pit.remove_entry(interest.name)
        return self._create_error_response("RAID 1 read failed on both nodes")
    
    def _handle_raid_write(self, interest):
        """
        Handle WRITE with RAID awareness:
        - RAID 0: Stripe data across ST1 and ST2
        - RAID 1: Mirror data to both ST1 and ST2
        """
        self._log_control(f"[WRITE] {interest.name} using {self.raid_mode}")
        
        if self.raid_mode == "RAID0":
            return self._write_raid0_striped(interest)
        else:  # RAID1
            return self._write_raid1_mirrored(interest)
    
    def _write_raid0_striped(self, interest):
        """
        RAID 0 Write: Stripe data across storage nodes
        Fragment content and distribute
        """
        self._log_control(f"[RAID0 WRITE] Striping across ST1 and ST2")
        self.stats["raid0_operations"] += 1
        
        # For demo: create mock content (in real system, comes from Interest payload)
        content = f"User {interest.user_id} wrote to {interest.name}"
        content_bytes = content.encode('utf-8')
        
        # Fragment content
        fragments = self._create_fragments(content_bytes, 2)
        self._log_control(f"[RAID0] Created {len(fragments)} fragments")
        self.stats["fragments_created"] += len(fragments)
        
        # Send fragments to storage nodes
        success_count = 0
        for fragment_idx, fragment_data in fragments.items():
            storage_node = "ST1" if fragment_idx % 2 == 0 else "ST2"
            fragment_name = f"{interest.name}:[{fragment_idx}/{len(fragments)}]"
            
            # Create fragment write interest
            from common import InterestPacket
            fragment_interest = InterestPacket(
                name=fragment_name,
                user_id=interest.user_id,
                operation="WRITE",
                nonce=interest.nonce + fragment_idx
            )
            
            response = self._forward_to_storage_node(fragment_interest, storage_node)
            
            if response and "/error" not in response:
                self._log_control(f"[RAID0] ✅ Fragment {fragment_idx} → {storage_node}")
                success_count += 1
            else:
                self._log_control(f"[RAID0] ❌ Fragment {fragment_idx} → {storage_node} FAILED")
        
        self.processing_module.pit.remove_entry(interest.name)
        
        if success_count == len(fragments):
            response_content = f"""RAID 0 Write Complete:
File: {interest.name}
Fragments: {len(fragments)}
Distribution: ST1 (even), ST2 (odd)
Status: SUCCESS"""
            return self._create_data_response(interest.name, response_content.encode('utf-8'))
        else:
            self.stats["storage_failures"] += 1
            return self._create_error_response(f"RAID 0 write partial failure ({success_count}/{len(fragments)})")
    
    def _write_raid1_mirrored(self, interest):
        """
        RAID 1 Write: Mirror data to both storage nodes
        """
        self._log_control(f"[RAID1 WRITE] Mirroring to ST1 and ST2")
        self.stats["raid1_operations"] += 1
        
        # Send to both storage nodes
        st1_response = self._forward_to_storage_node(interest, "ST1")
        st2_response = self._forward_to_storage_node(interest, "ST2")
        
        st1_success = st1_response and "/error" not in st1_response
        st2_success = st2_response and "/error" not in st2_response
        
        self.processing_module.pit.remove_entry(interest.name)
        
        if st1_success and st2_success:
            self._log_control(f"[RAID1] ✅ Mirrored to both ST1 and ST2")
            self.stats["mirrors_created"] += 1
            
            response_content = f"""RAID 1 Write Complete:
File: {interest.name}
Mirrored to: ST1, ST2
Redundancy: 2 copies
Status: SUCCESS"""
            return self._create_data_response(interest.name, response_content.encode('utf-8'))
        elif st1_success or st2_success:
            self._log_control(f"[RAID1] ⚠️  Partial success (ST1: {st1_success}, ST2: {st2_success})")
            
            response_content = f"""RAID 1 Write Partial:
File: {interest.name}
ST1: {'SUCCESS' if st1_success else 'FAILED'}
ST2: {'SUCCESS' if st2_success else 'FAILED'}
Status: DEGRADED"""
            return self._create_data_response(interest.name, response_content.encode('utf-8'))
        else:
            self._log_control(f"[RAID1] ❌ Both storage nodes failed")
            self.stats["storage_failures"] += 1
            return self._create_error_response("RAID 1 write failed on both nodes")
    
    def _create_fragments(self, content: bytes, num_fragments: int):
        """Fragment content into equal pieces"""
        fragment_size = len(content) // num_fragments
        if len(content) % num_fragments != 0:
            fragment_size += 1
        
        fragments = {}
        for i in range(num_fragments):
            start = i * fragment_size
            end = min(start + fragment_size, len(content))
            fragments[i] = content[start:end]
        
        return fragments
    
    def _forward_to_storage_node(self, interest, node_id: str):
        """Forward Interest to specific storage node"""
        node_config = self.storage_nodes.get(node_id)
        
        if not node_config:
            return None
        
        response = self.comm_module.send_packet_sync(
            node_config["host"],
            node_config["port"],
            interest.to_json()
        )
        
        return response
    
    def _forward_to_primary_storage(self, interest):
        """Forward to ST1 (primary) for non-RAID operations"""
        return self._forward_to_storage_node(interest, "ST1")
    
    def _forward_fragment_request(self, interest):
        """Forward fragment request to appropriate node"""
        # Parse fragment index
        try:
            fragment_part = interest.name.split(":[")[1].rstrip("]")
            fragment_idx = int(fragment_part.split("/")[0])
            
            # Route to appropriate node
            storage_node = "ST1" if fragment_idx % 2 == 0 else "ST2"
            
            return self._forward_to_storage_node(interest, storage_node)
        except:
            return self._forward_to_primary_storage(interest)
    
    def _handle_data_packet(self, data_packet, source: str):
        """Handle incoming Data packet"""
        self._log_debug(f"📦 DATA: {data_packet.name}", "data")
        self.processing_module.content_store.put(data_packet.name, data_packet.data_payload)
        return "ACK"
    
    def _create_data_response(self, name: str, content: bytes):
        """Create Data packet response"""
        if isinstance(content, str):
            content = content.encode('utf-8')
        
        data_packet = DataPacket(
            name=name,
            data_payload=content,
            data_length=len(content),
            checksum=calculate_checksum(content.decode('utf-8', errors='ignore'))
        )
        
        return data_packet.to_json()
    
    def _create_error_response(self, error_message: str):
        """Create error response"""
        data_packet = DataPacket(
            name="/error",
            data_payload=error_message.encode('utf-8'),
            data_length=len(error_message),
            checksum="error"
        )
        
        return data_packet.to_json()
    
    def start(self):
        """Start the RAID-aware router"""
        self._log(f"Starting RAID-aware router...", "interest")
        
        self.comm_module.start()
        
        self._log(f"Router started on {self.host}:{self.port}", "data")
        self._log(f"RAID Mode: {self.raid_mode}", "data")
        self._log(f"Storage Nodes: ST1 (RAID 0), ST2 (RAID 1)", "data")
        
        self.show_configuration()
    
    def stop(self):
        """Stop the router"""
        self._log("Stopping RAID-aware router...")
        self.comm_module.stop()
        self.show_stats()
        self._log("Router stopped")
    
    def show_configuration(self):
        """Display configuration"""
        self._log_control("=" * 60)
        self._log_control(f"RAID-AWARE ROUTER: {self.node_name}")
        self._log_control("=" * 60)
        self._log_control(f"Network: {self.host}:{self.port}")
        self._log_control(f"RAID Mode: {self.raid_mode}")
        self._log_control(f"Fragment Size: {self.fragment_size} bytes")
        self._log_control("")
        self._log_control("Storage Nodes:")
        for node_id, config in self.storage_nodes.items():
            self._log_control(f"  {node_id}: {config['host']}:{config['port']} (RAID {config['raid']})")
        self._log_control("=" * 60)
    
    def show_stats(self):
        """Display statistics"""
        uptime = time.time() - self.stats['uptime_start']
        
        self._log_control("=" * 60)
        self._log_control(f"RAID-AWARE ROUTER STATISTICS")
        self._log_control("=" * 60)
        self._log_control(f"Uptime: {uptime:.2f}s")
        self._log_control(f"Packets Routed: {self.stats['packets_routed']}")
        self._log_control(f"RAID 0 Operations: {self.stats['raid0_operations']}")
        self._log_control(f"RAID 1 Operations: {self.stats['raid1_operations']}")
        self._log_control(f"Fragments Created: {self.stats['fragments_created']}")
        self._log_control(f"Mirrors Created: {self.stats['mirrors_created']}")
        self._log_control(f"Storage Failures: {self.stats['storage_failures']}")
        self._log_control("=" * 60)
    
    def interactive_commands(self):
        """Interactive command interface"""
        print("\nRAID-Aware Router Commands:")
        print("  raid0       - Switch to RAID 0 (striping)")
        print("  raid1       - Switch to RAID 1 (mirroring)")
        print("  show stats  - Display statistics")
        print("  show config - Display configuration")
        print("  quit        - Stop router")
        print()
        
        while True:
            try:
                command = input(f"{self.node_name}> ").strip().lower()
                
                if command in ["quit", "exit"]:
                    break
                elif command == "raid0":
                    self.set_raid_mode("RAID0")
                elif command == "raid1":
                    self.set_raid_mode("RAID1")
                elif command == "show stats":
                    self.show_stats()
                elif command == "show config":
                    self.show_configuration()
                elif command:
                    print(f"Unknown command: {command}")
            
            except (KeyboardInterrupt, EOFError):
                break
    
    def _log(self, message, log_type="normal"):
        print(f"[{self.node_name}] {message}")
    
    def _log_control(self, message):
        if self.gui:
            self.gui.log_control(message)
        else:
            print(f"[{self.node_name}][CONTROL] {message}")
    
    def _log_debug(self, message, msg_type="normal"):
        if self.gui:
            self.gui.log_debug(message, msg_type)
        else:
            print(f"[{self.node_name}][DEBUG] {message}")


def main():
    router_id = sys.argv[1] if len(sys.argv) > 1 else "R1"
    
    print("="*70)
    print("RAID-AWARE ROUTER - RAID 0 & RAID 1 IMPLEMENTATION")
    print("="*70)
    
    router = RAIDAwareRouter(router_id, use_gui=True)
    
    try:
        router.start()
        
        print("\n✅ RAID-Aware Router is running")
        print("  - RAID 0: Striping across ST1 and ST2")
        print("  - RAID 1: Mirroring to both ST1 and ST2")
        print("  - Type 'raid0' or 'raid1' to switch modes")
        print("\n" + "="*70 + "\n")
        
        router.interactive_commands()
        
    except KeyboardInterrupt:
        print("\n\nShutting down router...")
    finally:
        router.stop()


if __name__ == "__main__":
    main()