#!/usr/bin/env python3
"""
Storage Node - Named Networks Framework
Individual storage node that uses the Storage Module
Each node specializes in a single RAID configuration
"""

import time
import threading
from communication_module import CommunicationModule
from parsing_module import ParsingModule
from storage_module import StorageModule
from common import InterestPacket, DataPacket

class StorageNode:
    """
    Storage Node that uses Communication, Parsing, and Storage modules
    Each node supports one specific RAID level
    """
    
    def __init__(self, node_id: str, raid_level: int, host: str = "127.0.0.1", 
                 port: int = 9001, storage_path: str = None):
        self.node_id = node_id
        self.raid_level = raid_level
        self.node_name = f"StorageNode-{node_id}"
        self.host = host
        self.port = port
        
        # Storage configuration
        if storage_path is None:
            storage_path = f"./storage_{node_id}_raid{raid_level}"
        
        print(f"[{self.node_name}] Initializing Storage Node...")
        
        # Initialize modules
        self.comm_module = CommunicationModule(self.node_name, host, port)
        self.parsing_module = ParsingModule(self.node_name)
        self.storage_module = StorageModule(self.node_name, raid_level, storage_path)
        
        # Node statistics
        self.stats = {
            "requests_handled": 0,
            "successful_operations": 0,
            "failed_operations": 0,
            "uptime_start": time.time()
        }
        
        # Set up module interfaces
        self._setup_module_interfaces()
        
        print(f"[{self.node_name}] Storage Node initialized (RAID {raid_level})")
    
    def _setup_module_interfaces(self):
        """Setup interfaces between modules"""
        print(f"[{self.node_name}] Setting up module interfaces...")
        
        # Communication -> Parsing
        self.comm_module.set_packet_handler(self.parsing_module.handle_packet)
        
        # Parsing -> Storage operations (through this node)
        self.parsing_module.set_processing_handler(self._handle_parsed_packet)
        
        print(f"[{self.node_name}] Module interfaces configured")
    
    def _handle_parsed_packet(self, packet, source: str, packet_type: str):
        """Handle packets from Parsing Module"""
        self.stats["requests_handled"] += 1
        
        try:
            if packet_type == "interest":
                return self._handle_interest_packet(packet, source)
            elif packet_type == "data":
                return self._handle_data_packet(packet, source)
            else:
                self.stats["failed_operations"] += 1
                return self._create_error_response("Unknown packet type")
                
        except Exception as e:
            print(f"[{self.node_name}] Error handling packet: {e}")
            self.stats["failed_operations"] += 1
            return self._create_error_response("Processing error")
    
    def _handle_interest_packet(self, interest: InterestPacket, source: str):
        """Handle Interest packet for storage operations"""
        print(f"[{self.node_name}] Received {interest.operation} request for: {interest.name}")
        
        if interest.operation == "READ":
            return self._handle_read_request(interest)
        elif interest.operation == "WRITE":
            return self._handle_write_request(interest)
        else:
            self.stats["failed_operations"] += 1
            return self._create_error_response(f"Unsupported operation: {interest.operation}")
    
    def _handle_read_request(self, interest: InterestPacket):
        """Handle file read request using Storage Module"""
        file_name = interest.name
        
        # Use Storage Module to retrieve file
        storage_response = self.storage_module.retrieve_file(file_name)
        
        if storage_response.success:
            self.stats["successful_operations"] += 1
            print(f"[{self.node_name}] Successfully retrieved {file_name}")
            return self._create_data_response(file_name, storage_response.content)
        else:
            self.stats["failed_operations"] += 1
            print(f"[{self.node_name}] Failed to retrieve {file_name}: {storage_response.error}")
            return self._create_error_response(storage_response.error)
    
    def _handle_write_request(self, interest: InterestPacket):
        """Handle write request - signal readiness for file storage"""
        file_name = interest.name
        
        print(f"[{self.node_name}] Preparing for file storage: {file_name}")
        
        # Check if we can store this file
        if self._can_accept_file(file_name):
            # Signal readiness to receive file data
            response_content = f"STORAGE_READY:RAID{self.raid_level}:{self.node_id}"
            self.stats["successful_operations"] += 1
            return self._create_data_response(file_name, response_content.encode('utf-8'))
        else:
            self.stats["failed_operations"] += 1
            return self._create_error_response("Cannot accept file for storage")
    
    def _handle_data_packet(self, data_packet: DataPacket, source: str):
        """Handle incoming Data packet containing file content"""
        file_name = data_packet.name
        content = data_packet.data_payload
        
        print(f"[{self.node_name}] Storing file content: {file_name} ({len(content)} bytes)")
        
        # Use Storage Module to store file
        storage_response = self.storage_module.store_file(file_name, content)
        
        if storage_response.success:
            self.stats["successful_operations"] += 1
            print(f"[{self.node_name}] Successfully stored {file_name}")
            
            # Return success acknowledgment with storage info
            ack_message = f"STORED_SUCCESS:RAID{self.raid_level}"
            return self._create_data_response(file_name, ack_message.encode('utf-8'))
        else:
            self.stats["failed_operations"] += 1
            print(f"[{self.node_name}] Failed to store {file_name}: {storage_response.error}")
            return self._create_error_response(storage_response.error)
    
    def _can_accept_file(self, file_name: str) -> bool:
        """Check if this node can accept the file for storage"""
        # Simple capacity and capability check
        # In real implementation, might check available space, file type restrictions, etc.
        return True
    
    def _create_data_response(self, name: str, content: bytes) -> str:
        """Create Data packet response"""
        from common import calculate_checksum
        
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
        """Create error response"""
        data_packet = DataPacket(
            name="/error",
            data_payload=error_message.encode('utf-8'),
            data_length=len(error_message),
            checksum="error"
        )
        return data_packet.to_json()
    
    def start(self):
        """Start the storage node"""
        print(f"[{self.node_name}] Starting storage node...")
        
        # Start communication module
        self.comm_module.start()
        
        print(f"[{self.node_name}] Storage node started on {self.host}:{self.port}")
        print(f"[{self.node_name}] Supporting RAID {self.raid_level} operations")
        
        # Show initial storage info
        self._show_node_info()
    
    def stop(self):
        """Stop the storage node"""
        print(f"[{self.node_name}] Stopping storage node...")
        
        # Stop communication module
        self.comm_module.stop()
        
        # Show final statistics
        self.show_comprehensive_stats()
        
        print(f"[{self.node_name}] Storage node stopped")
    
    def _show_node_info(self):
        """Display node information"""
        storage_info = self.storage_module.get_storage_info()
        
        print(f"\n=== {self.node_name} Information ===")
        print(f"Node ID: {self.node_id}")
        print(f"RAID Level: {storage_info['raid_level']} ({storage_info['raid_description']})")
        print(f"Address: {self.host}:{self.port}")
        print(f"Storage Path: {storage_info['storage_path']}")
        print(f"Fragment Size: {storage_info['fragment_size']} bytes")
        print("=" * 50)
    
    def show_comprehensive_stats(self):
        """Display statistics from all modules"""
        uptime = time.time() - self.stats['uptime_start']
        
        print(f"\n=== {self.node_name} Comprehensive Statistics ===")
        
        # Node-level stats
        print(f"Node Uptime: {uptime:.1f} seconds")
        print(f"Requests Handled: {self.stats['requests_handled']}")
        print(f"Successful Operations: {self.stats['successful_operations']}")
        print(f"Failed Operations: {self.stats['failed_operations']}")
        
        if self.stats['requests_handled'] > 0:
            success_rate = (self.stats['successful_operations'] / self.stats['requests_handled']) * 100
            print(f"Success Rate: {success_rate:.1f}%")
        
        print("\n" + "="*60)
        
        # Communication Module stats
        print("COMMUNICATION MODULE:")
        buffer_status = self.comm_module.get_buffer_status()
        print(f"  Receive Buffer: {buffer_status['receive_buffer_size']}/100")
        print(f"  Send Buffer: {buffer_status['send_buffer_size']}/100")
        
        print("\nSTORAGE MODULE:")
        self.storage_module.show_stats()
        
        print("\n" + "="*60)
    
    def list_stored_files(self):
        """List all files stored in this node"""
        files = self.storage_module.list_files()
        
        print(f"\n=== {self.node_name} Stored Files ===")
        if not files:
            print("No files stored")
        else:
            for file_metadata in files:
                stored_time = time.ctime(file_metadata.stored_at)
                print(f"File: {file_metadata.file_name}")
                print(f"  Original Size: {file_metadata.original_size} bytes")
                print(f"  Stored Size: {file_metadata.stored_size} bytes")
                print(f"  RAID Level: {file_metadata.raid_level}")
                print(f"  Stored At: {stored_time}")
                print(f"  Checksum: {file_metadata.checksum[:16]}...")
                print("-" * 40)
        print("=" * 50)
    
    def interactive_commands(self):
        """Interactive command interface"""
        print("\nAvailable commands:")
        print("  'stats' - Show comprehensive statistics")
        print("  'files' - List stored files")
        print("  'storage' - Show storage module stats")
        print("  'info' - Show node information")
        print("  'quit' - Stop storage node")
        
        while True:
            try:
                command = input(f"{self.node_id}> ").strip().lower()
                
                if command in ['quit', 'exit', 'q']:
                    break
                elif command == 'stats':
                    self.show_comprehensive_stats()
                elif command == 'files':
                    self.list_stored_files()
                elif command == 'storage':
                    self.storage_module.show_stats()
                elif command == 'info':
                    self._show_node_info()
                elif command == 'help':
                    print("Available commands: stats, files, storage, info, quit")
                elif command == '':
                    continue
                else:
                    print(f"Unknown command: {command}")
                    
            except KeyboardInterrupt:
                break
    
    def get_port(self):
        """Get the actual port being used"""
        return self.comm_module.get_port()

def main():
    """Run a storage node"""
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python storage_node.py <node_id> <raid_level> [port]")
        print("Example: python storage_node.py node1 0 9001")
        print("RAID levels: 0=Striping, 1=Mirroring, 5=Single Parity, 6=Double Parity")
        return
    
    node_id = sys.argv[1]
    raid_level = int(sys.argv[2])
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 9001
    
    # Validate RAID level
    if raid_level not in [0, 1, 5, 6]:
        print("Error: RAID level must be 0, 1, 5, or 6")
        return
    
    # Create storage node
    storage_node = StorageNode(node_id, raid_level, port=port)
    
    try:
        storage_node.start()
        
        print("\n" + "="*70)
        print(f"STORAGE NODE - {node_id} (RAID {raid_level})")
        print("="*70)
        print("Storage node is running with Communication, Parsing, and Storage modules.")
        print(f"Specialized for RAID {raid_level} operations.")
        print("Node management interface available.")
        print("="*70 + "\n")
        
        # Start interactive command interface
        storage_node.interactive_commands()
        
    except KeyboardInterrupt:
        print("\nShutting down storage node...")
    finally:
        storage_node.stop()

if __name__ == "__main__":
    main()