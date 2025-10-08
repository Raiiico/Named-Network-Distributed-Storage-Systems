#!/usr/bin/env python3
"""
Storage Node - Named Networks Framework
Working storage node that responds to router requests
Compatible with existing communication_module.py
"""

import sys
import time
import os
import hashlib
from communication_module import CommunicationModule
from parsing_module import ParsingModule
from common import InterestPacket, DataPacket, calculate_checksum

class SimpleStorageNode:
    """
    Simple Storage Node for demonstrating hub-and-spoke topology
    Stores files and responds to Interest packets
    """
    
    def __init__(self, node_id: str, raid_level: int, host: str = "127.0.0.1", port: int = 9001):
        self.node_id = node_id
        self.raid_level = raid_level
        self.node_name = f"Storage-{node_id}"
        self.host = host
        self.port = port
        
        # Create storage directory
        self.storage_path = f"./storage_{node_id}_raid{raid_level}"
        os.makedirs(self.storage_path, exist_ok=True)
        
        # Initialize modules
        self.comm_module = CommunicationModule(self.node_name, host, port)
        self.parsing_module = ParsingModule(self.node_name)
        
        # Storage data
        self.stored_files = {}
        
        # Statistics
        self.stats = {
            "requests_handled": 0,
            "files_stored": 0,
            "files_retrieved": 0,
            "bytes_stored": 0,
            "uptime_start": time.time()
        }
        
        # Set up module interfaces
        self._setup_interfaces()
        
        # Pre-populate with some test files
        self._create_test_files()
        
        print(f"[{self.node_name}] Storage Node initialized")
        print(f"[{self.node_name}] RAID Level: {raid_level}")
        print(f"[{self.node_name}] Storage Path: {self.storage_path}")
    
    def _setup_interfaces(self):
        """Setup module interfaces"""
        # Communication -> Parsing
        self.comm_module.set_packet_handler(self.parsing_module.handle_packet)
        
        # Parsing -> Storage (this node)
        self.parsing_module.set_processing_handler(self._handle_storage_request)
        
        print(f"[{self.node_name}] Module interfaces configured")
    
    def _handle_storage_request(self, packet_obj, source: str, packet_type: str):
        """Handle storage requests from router"""
        if packet_type == "interest":
            return self._handle_interest(packet_obj, source)
        else:
            return self._create_error_response("Unsupported packet type")
    
    def _handle_interest(self, interest: InterestPacket, source: str):
        """Handle Interest packets for storage operations"""
        self.stats["requests_handled"] += 1
        
        print(f"\n[{self.node_name}] === STORAGE REQUEST ===")
        print(f"[{self.node_name}] From: {source}")
        print(f"[{self.node_name}] File: {interest.name}")
        print(f"[{self.node_name}] Operation: {interest.operation}")
        print(f"[{self.node_name}] User: {interest.user_id}")
        print(f"[{self.node_name}] =====================================")
        
        try:
            if interest.operation == "READ":
                return self._handle_read_request(interest)
            elif interest.operation == "WRITE":
                return self._handle_write_request(interest)
            elif interest.operation == "PERMISSION":
                return self._handle_permission_request(interest)
            else:
                return self._create_error_response(f"Unknown operation: {interest.operation}")
        
        except Exception as e:
            print(f"[{self.node_name}] Error handling request: {e}")
            return self._create_error_response(f"Storage error: {str(e)}")
    
    def _handle_read_request(self, interest: InterestPacket):
        """Handle READ requests"""
        file_name = interest.name
        
        # Check if file exists in storage
        if file_name in self.stored_files:
            file_data = self.stored_files[file_name]
            self.stats["files_retrieved"] += 1
            
            print(f"[{self.node_name}] ✓ File found: {file_name}")
            print(f"[{self.node_name}] Size: {len(file_data['content'])} bytes")
            print(f"[{self.node_name}] RAID: {self.raid_level}")
            
            # Create response with file content
            response_content = f"""RAID {self.raid_level} Storage Response:
File: {file_name}
Content: {file_data['content'].decode('utf-8', errors='ignore')}
Stored: {file_data['stored_at']}
Checksum: {file_data['checksum']}
Storage Node: {self.node_name}"""
            
            return self._create_data_response(file_name, response_content)
        
        else:
            # File not found, but provide meaningful response
            print(f"[{self.node_name}] ✗ File not found: {file_name}")
            
            response_content = f"""RAID {self.raid_level} Storage Response:
File: {file_name}
Status: Available for storage
Storage Node: {self.node_name}
RAID Level: {self.raid_level}
Available Space: 1.2TB
Files Stored: {len(self.stored_files)}"""
            
            return self._create_data_response(file_name, response_content)
    
    def _handle_write_request(self, interest: InterestPacket):
        """Handle WRITE requests with actual file content"""
        file_name = interest.name
        
        # For demo: simulate content (in real system, content would come in Interest payload)
        content = f"User {interest.user_id} wrote to {file_name} at {time.strftime('%Y-%m-%d %H:%M:%S')}"
        content_bytes = content.encode('utf-8')
        
        # Write to actual file
        safe_filename = file_name.replace('/', '_')
        file_path = os.path.join(self.storage_path, f"{safe_filename}.txt")
        
        with open(file_path, 'w') as f:
            f.write(content)
        
        # Store in memory
        self.stored_files[file_name] = {
            "content": content_bytes,
            "file_path": file_path,  # Add file path
            "stored_at": time.strftime('%Y-%m-%d %H:%M:%S'),
            "checksum": hashlib.md5(content_bytes).hexdigest(),
            "size": len(content_bytes),
            "user": interest.user_id
        }
        
        self.stats["files_stored"] += 1
        self.stats["bytes_stored"] += len(content_bytes)
        
        print(f"[{self.node_name}] ✓ File stored: {file_name}")
        print(f"[{self.node_name}] User: {interest.user_id}")
        print(f"[{self.node_name}] RAID: {self.raid_level}")
        
        response_content = f"""RAID {self.raid_level} Write Confirmation:
File: {file_name}
Status: Successfully stored
Size: {len(content_bytes)} bytes
RAID Level: {self.raid_level}
Storage Node: {self.node_name}
User: {interest.user_id}"""
        
        return self._create_data_response(file_name, response_content)
    
    def _handle_permission_request(self, interest: InterestPacket):
        """Handle PERMISSION requests"""
        response_content = f"""RAID {self.raid_level} Permission Response:
File: {interest.name}
User: {interest.user_id}
Permission: GRANTED
Storage Node: {self.node_name}
RAID Level: {self.raid_level}"""
        
        return self._create_data_response(interest.name, response_content)
    
    def _create_test_files(self):
        """Create some test files for demonstration"""
        test_files = {
            "/dlsu/hello": "Hello from DLSU Named Networks Storage!",
            "/dlsu/storage/test": f"Test file stored on RAID {self.raid_level} storage",
            "/dlsu/storage/node1": f"Storage Node {self.node_id} - RAID {self.raid_level}",
            "/storage/test": f"Storage test file from {self.node_name}",
            "/dlsu/public": "Public content available to all users",
            f"/dlsu/storage/node{self.node_id}": f"Node-specific content from {self.node_name}"
        }
        
        for file_name, content in test_files.items():
            content_bytes = content.encode('utf-8')
            self.stored_files[file_name] = {
                "content": content_bytes,
                "stored_at": time.strftime('%Y-%m-%d %H:%M:%S'),
                "checksum": hashlib.md5(content_bytes).hexdigest(),
                "size": len(content_bytes),
                "user": "system"
            }
        
        self.stats["files_stored"] = len(test_files)
        print(f"[{self.node_name}] Pre-loaded {len(test_files)} test files")
    
    def _create_data_response(self, name: str, content: str):
        """Create Data packet response"""
        content_bytes = content.encode('utf-8')
        
        data_packet = DataPacket(
            name=name,
            data_payload=content_bytes,
            data_length=len(content_bytes),
            checksum=calculate_checksum(content)
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
        """Start the storage node"""
        print(f"\n{'='*70}")
        print(f"NAMED NETWORKS STORAGE NODE")
        print(f"{'='*70}")
        print(f"Node ID:      {self.node_id}")
        print(f"RAID Level:   {self.raid_level}")
        print(f"Address:      {self.host}:{self.port}")
        print(f"Storage Path: {self.storage_path}")
        print(f"Files Ready:  {len(self.stored_files)}")
        print(f"{'='*70}\n")
        
        # Start communication module
        self.comm_module.start()
        
        print(f"[{self.node_name}] Storage node started and ready")
        print(f"[{self.node_name}] Waiting for requests from router...")
    
    def stop(self):
        """Stop the storage node"""
        print(f"\n[{self.node_name}] Stopping storage node...")
        
        # Stop communication module
        self.comm_module.stop()
        
        # Show final statistics
        self._show_stats()
        
        print(f"[{self.node_name}] Storage node stopped")
    
    def _show_stats(self):
        """Display storage statistics"""
        uptime = time.time() - self.stats['uptime_start']
        
        print(f"\n{'='*70}")
        print(f"STORAGE NODE STATISTICS - {self.node_name}")
        print(f"{'='*70}")
        print(f"Uptime:           {uptime:.1f} seconds")
        print(f"Requests Handled: {self.stats['requests_handled']}")
        print(f"Files Stored:     {self.stats['files_stored']}")
        print(f"Files Retrieved:  {self.stats['files_retrieved']}")
        print(f"Bytes Stored:     {self.stats['bytes_stored']}")
        print(f"RAID Level:       {self.raid_level}")
        print(f"Storage Path:     {self.storage_path}")
        print(f"{'='*70}")
    
    def interactive_commands(self):
        """Interactive command interface"""
        print("\nStorage Node Commands:")
        print("  show files   - List stored files")
        print("  show stats   - Display statistics")
        print("  store <name> - Store a test file")
        print("  quit         - Stop storage node")
        print()
        
        while True:
            try:
                command = input(f"{self.node_name}> ").strip().lower()
                
                if command in ["quit", "exit"]:
                    break
                elif command == "show files":
                    self._show_files()
                elif command == "show stats":
                    self._show_stats()
                elif command.startswith("store"):
                    parts = command.split(maxsplit=1)
                    if len(parts) > 1:
                        self._store_test_file(parts[1])
                    else:
                        print("Usage: store <filename>")
                elif command == "help":
                    print("Available commands: show files, show stats, store <name>, quit")
                elif command:
                    print(f"Unknown command: {command}")
                    
            except (KeyboardInterrupt, EOFError):
                break
    
    def _show_files(self):
        """Show stored files"""
        print(f"\n=== {self.node_name} Stored Files ===")
        if not self.stored_files:
            print("No files stored")
        else:
            for name, data in self.stored_files.items():
                print(f"  {name}")
                print(f"    Size: {data['size']} bytes")
                print(f"    Stored: {data['stored_at']}")
                print(f"    User: {data['user']}")
        print("=" * 50)
    
    def _store_test_file(self, filename):
        """Store a test file"""
        content = f"Test file {filename} stored on {self.node_name} at {time.strftime('%Y-%m-%d %H:%M:%S')}"
        content_bytes = content.encode('utf-8')
        
        self.stored_files[filename] = {
            "content": content_bytes,
            "stored_at": time.strftime('%Y-%m-%d %H:%M:%S'),
            "checksum": hashlib.md5(content_bytes).hexdigest(),
            "size": len(content_bytes),
            "user": "admin"
        }
        
        print(f"✓ Stored: {filename} ({len(content_bytes)} bytes)")


def main():
    """Run the storage node"""
    # Parse command line arguments
    if len(sys.argv) < 3:
        print("Usage: python storage_node.py <node_id> <raid_level> [port]")
        print("Example: python storage_node.py ST1 0 9001")
        sys.exit(1)
    
    node_id = sys.argv[1]
    raid_level = int(sys.argv[2])
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 9001
    
    # Create storage node
    storage_node = SimpleStorageNode(node_id, raid_level, port=port)
    
    try:
        storage_node.start()
        
        print(f"\n{'='*70}")
        print("STORAGE NODE READY")
        print("="*70)
        print("The storage node is now running and can receive requests from the router.")
        print("Test by sending storage requests from the client:")
        print("  read /dlsu/storage/test")
        print("  read /storage/test")
        print(f"  write /files/{node_id}/newfile")
        print("="*70 + "\n")
        
        # Interactive command interface
        storage_node.interactive_commands()
        
    except KeyboardInterrupt:
        print("\n\nShutting down storage node...")
    finally:
        storage_node.stop()
        print("Storage node stopped. Goodbye!")


if __name__ == "__main__":
    main()