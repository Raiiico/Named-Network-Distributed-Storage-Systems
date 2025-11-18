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
import threading
import json
from communication_module import CommunicationModule
from parsing_module import ParsingModule
from common import InterestPacket, DataPacket, calculate_checksum

from storage_module import StorageModule

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
        # Initialize Storage Module with RAID
        self.storage_module = StorageModule(self.node_name, raid_level, self.storage_path)
    
        # Storage data
        self.stored_files = {}
        # Fragment accumulator: base_name -> { index: bytes }
        self.fragment_accumulator = {}
        self._fragment_lock = threading.Lock()
        
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
        elif packet_type == "data":
            return self._handle_data_packet(packet_obj, source)
        else:
            return self._create_error_response("Unsupported packet type")

    def _handle_data_packet(self, data_packet: DataPacket, source: str):
        """Handle incoming DataPacket uploads (persist file bytes)."""
        try:
            file_name = data_packet.name
            content_bytes = data_packet.data_payload
            uploader = None

            # Try to detect JSON-wrapped uploader + base64 payload
            try:
                decoded = content_bytes.decode('utf-8')
                import json, base64
                parsed = json.loads(decoded)
                if isinstance(parsed, dict) and 'uploader' in parsed and 'data_b64' in parsed:
                    uploader = parsed.get('uploader')
                    content_bytes = base64.b64decode(parsed.get('data_b64'))
            except Exception:
                # Not a wrapped payload, treat as raw bytes
                pass

            # Detect fragment notation (e.g., /path/file:[1/3])
            try:
                from common import parse_fragment_notation, validate_content_name
                frag_info = parse_fragment_notation(file_name)
            except Exception:
                frag_info = None

            # If fragment, accumulate in memory until all parts received
            if frag_info and frag_info.get("is_fragment"):
                base_name = frag_info["base_name"]
                index = int(frag_info["index"])  # 1-based index expected from client
                total = int(frag_info["total"])

                with self._fragment_lock:
                    if base_name not in self.fragment_accumulator:
                        self.fragment_accumulator[base_name] = {}

                    self.fragment_accumulator[base_name][index] = content_bytes

                    # Check if we have all fragments
                    parts = self.fragment_accumulator[base_name]
                    if len(parts) >= total:
                        # We have all fragments; store them as fragment files instead
                        # so that the storage preserves fragmentation on disk.
                        storage_resp = self.storage_module.store_fragments(base_name, parts)

                        # Clean up accumulator
                        del self.fragment_accumulator[base_name]

                        if storage_resp.success:
                            self.stored_files[base_name] = {
                                "content": assembled,
                                "stored_at": time.strftime('%Y-%m-%d %H:%M:%S'),
                                "checksum": storage_resp.metadata.checksum if storage_resp.metadata else "",
                                "size": len(assembled),
                                "user": uploader if uploader else "uploader",
                                "raid_processed": True
                            }
                            self.stats["files_stored"] += 1
                            self.stats["bytes_stored"] += len(assembled)

                            # Write metadata JSON so stored files are discoverable on disk
                            try:
                                stored_path = storage_resp.metadata.file_path if storage_resp.metadata and hasattr(storage_resp.metadata, 'file_path') else ''
                                safe_name = os.path.basename(stored_path) if stored_path else base_name.replace('/', '_')
                                meta_dir = os.path.join(self.storage_path, 'metadata')
                                os.makedirs(meta_dir, exist_ok=True)
                                meta_path = os.path.join(meta_dir, f"{safe_name}.json")
                                meta = {
                                    "original_name": base_name,
                                    "stored_path": stored_path,
                                    "checksum": storage_resp.metadata.checksum if storage_resp.metadata else "",
                                    "size": len(assembled),
                                    "stored_at": time.strftime('%Y-%m-%d %H:%M:%S')
                                }
                                with open(meta_path, 'w', encoding='utf-8') as mf:
                                    json.dump(meta, mf, indent=2)
                            except Exception as e:
                                print(f"[{self.node_name}] Warning: could not write metadata file: {e}")

                            resp_msg = f"STORED:{base_name}"
                            return self._create_data_response(base_name, resp_msg)
                        else:
                            return self._create_error_response(storage_resp.error or "Store failed")

                    # Not all fragments yet
                    return self._create_data_response(file_name, f"FRAGMENT_RECEIVED:{index}/{total}")

            # Non-fragment: validate name (best-effort)
            try:
                from common import validate_content_name
                if not validate_content_name(file_name):
                    return self._create_error_response(f"Invalid content name: {file_name}")
            except Exception:
                pass

            # Persist using StorageModule
            storage_resp = self.storage_module.store_file(file_name, content_bytes)

            if storage_resp.success:
                # Keep lightweight in-memory index
                self.stored_files[file_name] = {
                    "content": content_bytes,
                    "stored_at": time.strftime('%Y-%m-%d %H:%M:%S'),
                    "checksum": storage_resp.metadata.checksum if storage_resp.metadata else "",
                    "size": len(content_bytes),
                    "user": uploader if uploader else "uploader"
                }

                self.stats["files_stored"] += 1
                self.stats["bytes_stored"] += len(content_bytes)

                # Write metadata JSON so stored files are discoverable on disk
                try:
                    stored_path = storage_resp.metadata.file_path if storage_resp.metadata and hasattr(storage_resp.metadata, 'file_path') else ''
                    safe_name = os.path.basename(stored_path) if stored_path else file_name.replace('/', '_')
                    meta_dir = os.path.join(self.storage_path, 'metadata')
                    os.makedirs(meta_dir, exist_ok=True)
                    meta_path = os.path.join(meta_dir, f"{safe_name}.json")
                    meta = {
                        "original_name": file_name,
                        "stored_path": stored_path,
                        "checksum": storage_resp.metadata.checksum if storage_resp.metadata else "",
                        "size": len(content_bytes),
                        "stored_at": time.strftime('%Y-%m-%d %H:%M:%S')
                    }
                    with open(meta_path, 'w', encoding='utf-8') as mf:
                        json.dump(meta, mf, indent=2)
                except Exception as e:
                    print(f"[{self.node_name}] Warning: could not write metadata file: {e}")

                resp_msg = f"STORED:{file_name}"
                return self._create_data_response(file_name, resp_msg)
            else:
                return self._create_error_response(storage_resp.error or "Store failed")

        except Exception as e:
            print(f"[{self.node_name}] Error storing uploaded data: {e}")
            return self._create_error_response(f"Upload error: {e}")
    
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
                return self._handle_read_request(interest, source)
            elif interest.operation == "WRITE":
                return self._handle_write_request(interest)
            elif interest.operation == "PERMISSION":
                return self._handle_permission_request(interest)
            else:
                return self._create_error_response(f"Unknown operation: {interest.operation}")
        
        except Exception as e:
            print(f"[{self.node_name}] Error handling request: {e}")
            return self._create_error_response(f"Storage error: {str(e)}")
    
    def _handle_read_request(self, interest: InterestPacket, source: str):
        """Handle READ requests using Storage Module. If the content is larger
        than the configured fragment size, split into fragments and send them
        back to the requester. The first fragment is returned synchronously; the
        remaining fragments are sent asynchronously via `comm_module.send`.
        """
        file_name = interest.name

        print(f"\n[{self.node_name}] === READ REQUEST ===")
        print(f"[{self.node_name}] File: {file_name}")

        # If the Interest explicitly requests a fragment (e.g. /file:[i/total]),
        # serve that specific fragment synchronously. This enables pull-based
        # fragment retrieval by clients and avoids relying on async fragment
        # delivery which can be lost in some network setups.
        from common import parse_fragment_notation
        frag_req = parse_fragment_notation(interest.name)
        if frag_req and frag_req.get('is_fragment'):
            base_name = frag_req['base_name']
            try:
                idx = int(frag_req['index'])
            except Exception:
                idx = 1

            # Retrieve full content and return only the requested fragment
            storage_response = self.storage_module.retrieve_file(base_name)
            if storage_response.success:
                content_bytes = storage_response.content
                frag_size = getattr(self.storage_module, 'fragment_size', 1024)
                fragments = [content_bytes[i:i + frag_size] for i in range(0, len(content_bytes), frag_size)]
                total = len(fragments)
                if 1 <= idx <= total:
                    chunk = fragments[idx-1]
                    frag_name = f"{base_name}:[{idx}/{total}]"
                    pkt = DataPacket(name=frag_name, data_payload=chunk, data_length=len(chunk))
                    return pkt.to_json()
                else:
                    return self._create_error_response(f"Fragment index out of range: {idx}")

            # If retrieval failed, fall through to error handling below

        # Try Storage Module first (RAID-processed files)
        storage_response = self.storage_module.retrieve_file(file_name)

        if storage_response.success:
            self.stats["files_retrieved"] += 1

            content_bytes = storage_response.content
            total_size = len(content_bytes)

            print(f"[{self.node_name}] ✓ Retrieved from RAID {self.raid_level} storage")
            print(f"[{self.node_name}] Size: {total_size} bytes")

            # Decide whether to fragment the response
            frag_size = getattr(self.storage_module, 'fragment_size', 4096)
            if total_size > frag_size:
                # Create fragments
                fragments = [content_bytes[i:i + frag_size] for i in range(0, total_size, frag_size)]
                total = len(fragments)

                print(f"[{self.node_name}] Sending {total} fragments (frag_size={frag_size}) to {source}")

                # Parse source address (expected format 'host:port')
                try:
                    host, port_s = source.split(":")
                    dest_port = int(port_s)
                except Exception:
                    # Fallback: if parsing fails, don't attempt async sends
                    host = None
                    dest_port = None

                # Prepare DataPackets for each fragment
                first_pkt_json = None
                for idx, chunk in enumerate(fragments, start=1):
                    frag_name = f"{file_name}:[{idx}/{total}]"
                    pkt = DataPacket(name=frag_name, data_payload=chunk, data_length=len(chunk))
                    pkt_json = pkt.to_json()

                    if idx == 1:
                        # Return first fragment synchronously
                        first_pkt_json = pkt_json
                    else:
                        # Send remaining fragments asynchronously if we have a valid host/port
                        if host and dest_port:
                            try:
                                self._send_fragment_with_backpressure(pkt_json, host, dest_port)
                            except Exception as e:
                                print(f"[{self.node_name}][COMM] Failed to send fragment {idx}/{total} to {host}:{dest_port}: {e}")

                # Return first fragment (guaranteed to exist)
                return first_pkt_json

            else:
                # Not large: return in a single packet
                return self._create_data_response(file_name, content_bytes)

        # Fallback to in-memory (for pre-loaded test files)
        elif file_name in self.stored_files:
            file_data = self.stored_files[file_name]
            self.stats["files_retrieved"] += 1

            print(f"[{self.node_name}] ✓ Retrieved from memory (test file)")

            content_bytes = file_data['content']
            total_size = len(content_bytes)
            frag_size = getattr(self.storage_module, 'fragment_size', 4096)

            if total_size > frag_size:
                # Fragment and send similarly to RAID branch
                fragments = [content_bytes[i:i + frag_size] for i in range(0, total_size, frag_size)]
                total = len(fragments)
                print(f"[{self.node_name}] Sending {total} fragments (memory file) to {source}")

                try:
                    host, port_s = source.split(":")
                    dest_port = int(port_s)
                except Exception:
                    host = None
                    dest_port = None

                first_pkt_json = None
                for idx, chunk in enumerate(fragments, start=1):
                    frag_name = f"{file_name}:[{idx}/{total}]"
                    pkt = DataPacket(name=frag_name, data_payload=chunk, data_length=len(chunk))
                    pkt_json = pkt.to_json()

                    if idx == 1:
                        first_pkt_json = pkt_json
                    else:
                        if host and dest_port:
                            try:
                                self._send_fragment_with_backpressure(pkt_json, host, dest_port)
                            except Exception as e:
                                print(f"[{self.node_name}][COMM] Failed to send fragment {idx}/{total} to {host}:{dest_port}: {e}")

                return first_pkt_json

            else:
                return self._create_data_response(file_name, content_bytes)

        else:
            print(f"[{self.node_name}] ✗ File not found")
            return self._create_error_response(f"File not found: {file_name}")
        
        
    def _handle_write_request(self, interest: InterestPacket):
        """Handle WRITE requests using Storage Module"""
        file_name = interest.name
        
        # Generate content (in real system, comes from Interest payload)
        content = f"User {interest.user_id} wrote to {file_name} at {time.strftime('%Y-%m-%d %H:%M:%S')}"
        content_bytes = content.encode('utf-8')
        
        print(f"\n[{self.node_name}] === WRITE REQUEST ===")
        print(f"[{self.node_name}] File: {file_name}")
        print(f"[{self.node_name}] User: {interest.user_id}")
        print(f"[{self.node_name}] Size: {len(content_bytes)} bytes")
        
        # USE Storage Module for RAID processing
        storage_response = self.storage_module.store_file(file_name, content_bytes)
        
        if storage_response.success:
            # Also keep in memory for quick access
            self.stored_files[file_name] = {
                "content": content_bytes,
                "stored_at": time.strftime('%Y-%m-%d %H:%M:%S'),
                "checksum": storage_response.metadata.checksum,
                "size": len(content_bytes),
                "user": interest.user_id,
                "raid_processed": True
            }
            
            self.stats["files_stored"] += 1
            self.stats["bytes_stored"] += len(content_bytes)
            
            print(f"[{self.node_name}] ✓ RAID {self.raid_level} processing complete")
            print(f"[{self.node_name}] Original: {storage_response.metadata.original_size} bytes")
            print(f"[{self.node_name}] Stored: {storage_response.metadata.stored_size} bytes")
            
            response_content = f"""RAID {self.raid_level} Write Confirmation:
File: {file_name}
Status: Successfully stored with RAID {self.raid_level}
Original Size: {storage_response.metadata.original_size} bytes
Stored Size: {storage_response.metadata.stored_size} bytes
Storage Node: {self.node_name}
User: {interest.user_id}"""
            
            return self._create_data_response(file_name, response_content)
        else:
            print(f"[{self.node_name}] ✗ Storage error: {storage_response.error}")
            return self._create_error_response(storage_response.error)
    
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

    def _send_fragment_with_backpressure(self, pkt_json: str, host: str, port: int, timeout: float = 5.0):
        """Send fragment while respecting comm_module send buffer capacity.

        This waits briefly if the send buffer is full to avoid "Send buffer overflow"
        messages and dropped fragments. It will wait up to `timeout` seconds
        before raising an exception.
        """
        start = time.time()
        # Poll for available buffer space
        while True:
            try:
                status = self.comm_module.get_buffer_status()
                send_q = status.get('send_buffer_size', 0)
                max_q = status.get('max_buffer_size', 100)
                # If there's reasonable headroom, enqueue
                if send_q < max_q - 5:
                    self.comm_module.send(pkt_json, host, port)
                    return
                else:
                    # Sleep a short while to let sender drain
                    time.sleep(0.01)
            except Exception:
                # If we cannot query buffer status, just send with a tiny pause
                try:
                    self.comm_module.send(pkt_json, host, port)
                    return
                except Exception:
                    time.sleep(0.01)

            if time.time() - start > timeout:
                raise TimeoutError(f"Timeout sending fragment to {host}:{port}")
    
    def _create_data_response(self, name: str, content):
        """Create Data packet response. `content` may be `str` or `bytes`."""
        # Accept bytes or string content without forcing a UTF-8 decode that
        # would corrupt binary data. DataPacket.to_json() will base64-encode
        # the payload for safe JSON transport.
        if isinstance(content, bytes):
            content_bytes = content
            # calculate checksum using existing helper which expects str/bytes
            checksum_src = content_bytes.decode('utf-8', errors='ignore')
        else:
            content_bytes = str(content).encode('utf-8')
            checksum_src = str(content)

        data_packet = DataPacket(
            name=name,
            data_payload=content_bytes,
            data_length=len(content_bytes),
            checksum=calculate_checksum(checksum_src)
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
        print("  show raid    - Display RAID information")  # ADD 
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
                elif command == "show raid":  # ADD 
                    self._show_raid_info()
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
    
    def _show_raid_info(self):
        """Show RAID storage information"""
        info = self.storage_module.get_storage_info()
        
        print(f"\n=== {self.node_name} RAID Information ===")
        print(f"RAID Level: {info['raid_level']} ({info['raid_description']})")
        print(f"Storage Path: {info['storage_path']}")
        print(f"Files Stored: {info['files_stored']}")
        print(f"Files Retrieved: {info['files_retrieved']}")
        print(f"Total Files: {info['total_files']}")
        print(f"Total Size: {info['total_size_bytes']} bytes")
        print(f"RAID Operations: {info['raid_operations']}")
        print(f"Parity Calculations: {info['parity_calculations']}")
        print("=" * 50)
    
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