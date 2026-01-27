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
from typing import Optional
from communication_module import CommunicationModule
from parsing_module import ParsingModule
from common import InterestPacket, DataPacket, calculate_checksum

from storage_module import StorageModule
import fib_config  # topology config (default gateway ports)

class SimpleStorageNode:
    """
    Simple Storage Node for demonstrating hub-and-spoke topology
    Stores files and responds to Interest packets
    """
    
    def __init__(self, node_id: str, raid_level: int, host: str = "127.0.0.1", port: int = 9001, gateway_host: Optional[str] = None, gateway_port: Optional[int] = None):
        self.node_id = node_id
        self.raid_level = raid_level
        self.node_name = f"Storage-{node_id}"
        self.host = host
        self.port = port

        # Determine default gateway (router) for storage nodes: default to R2 port from fib_config
        self.gateway_host = gateway_host or '127.0.0.1'
        self.gateway_port = gateway_port or fib_config.get_port_for_router('R2')
        
        # RAID 1 Mirror configuration: ST2 (port 9002) mirrors to ST1 (port 9001)
        # This allows true mirroring - data written to RAID1 node also goes to mirror
        self.mirror_config = {
            9002: ('127.0.0.1', 9001),  # ST2 mirrors to ST1
        }
        self.mirror_target = self.mirror_config.get(port, None)
        self.is_mirror_copy = False  # Flag to prevent infinite mirror loops
        
        # Create storage directory
        self.storage_path = f"./storage_{node_id}_raid{raid_level}"
        os.makedirs(self.storage_path, exist_ok=True)
        
        # Initialize modules
        self.comm_module = CommunicationModule(self.node_name, host, port)
        self.parsing_module = ParsingModule(self.node_name)      
        # Attach PacketLogger to communication module
        try:
            from common import PacketLogger
            self.logger = PacketLogger(self.node_name)
            try:
                self.comm_module.set_logger(self.logger)
            except Exception:
                pass
        except Exception:
            self.logger = None
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
            is_mirror_copy = False  # Flag to detect RAID 1 mirror copies

            # Try to detect JSON-wrapped uploader + base64 payload
            try:
                decoded = content_bytes.decode('utf-8')
                import json, base64
                parsed = json.loads(decoded)
                if isinstance(parsed, dict) and 'uploader' in parsed and 'data_b64' in parsed:
                    uploader = parsed.get('uploader')
                    content_bytes = base64.b64decode(parsed.get('data_b64'))
                    is_mirror_copy = parsed.get('is_mirror', False)  # Check if this is a mirror copy
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
                        # Calculate total size
                        total_size = sum(len(chunk) for chunk in parts.values())
                        
                        # We have all fragments; store them as fragment files instead
                        # so that the storage preserves fragmentation on disk.
                        storage_resp = self.storage_module.store_fragments(base_name, parts)

                        # Clean up accumulator
                        del self.fragment_accumulator[base_name]

                        if storage_resp.success:
                            self.stored_files[base_name] = {
                                "content": b'',  # Don't store full content in memory
                                "stored_at": time.strftime('%Y-%m-%d %H:%M:%S'),
                                "checksum": storage_resp.metadata.checksum if storage_resp.metadata else "",
                                "size": total_size,
                                "user": uploader if uploader else "uploader",
                                "raid_processed": True
                            }
                            self.stats["files_stored"] += 1
                            self.stats["bytes_stored"] += total_size

                            # Notify auth server to create ACL
                            if uploader:
                                self._notify_auth_server_ownership(base_name, uploader, server_host='127.0.0.1', server_port=7001)

                            # Register file location with server (send directly to server)
                            try:
                                stored_path = storage_resp.metadata.file_path if storage_resp.metadata and hasattr(storage_resp.metadata, 'file_path') else None
                                self._register_location(base_name, stored_path, server_host='127.0.0.1', server_port=7001, owner=uploader)
                            except Exception as e:
                                print(f"[{self.node_name}] Warning: could not register location for {base_name}: {e}")

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
                                    "size": total_size,
                                    "stored_at": time.strftime('%Y-%m-%d %H:%M:%S'),
                                    "user": uploader if uploader else "system"
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
                    # Persist a metadata entry in DB (if available)
                    try:
                        from db import get_db
                        db = get_db()
                        # Use uploader if present, otherwise mark as 'uploader'
                        owner = uploader if uploader else 'uploader'
                        db.add_file(file_name, owner, size=len(content_bytes), storage_path=storage_resp.metadata.file_path if storage_resp.metadata and hasattr(storage_resp.metadata, 'file_path') else None)
                        # merge checksum/other metadata if available
                        try:
                            meta = {'checksum': storage_resp.metadata.checksum if storage_resp.metadata else '', 'size': len(content_bytes)}
                            db.set_file_metadata(file_name, meta)
                        except Exception:
                            pass
                    except Exception:
                        # If DB not available, fallback to in-memory index and auth server notify
                        self.stored_files[file_name] = {
                            "content": content_bytes,
                            "stored_at": time.strftime('%Y-%m-%d %H:%M:%S'),
                            "checksum": storage_resp.metadata.checksum if storage_resp.metadata else "",
                            "size": len(content_bytes),
                            "user": uploader if uploader else "uploader"
                        }

                    self.stats["files_stored"] += 1
                    self.stats["bytes_stored"] += len(content_bytes)

                    # Notify auth server to create ACL if DB not used for registration
                    if uploader:
                        try:
                            from db import get_db
                            db = get_db()
                            # ensure entry exists
                            try:
                                db.add_file(file_name, uploader)
                            except Exception:
                                pass
                        except Exception:
                            self._notify_auth_server_ownership(file_name, uploader)

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
                            "stored_at": time.strftime('%Y-%m-%d %H:%M:%S'),
                            "user": uploader if uploader else 'system'
                        }
                        with open(meta_path, 'w', encoding='utf-8') as mf:
                            json.dump(meta, mf, indent=2)
                    except Exception as e:
                        print(f"[{self.node_name}] Warning: could not write metadata file: {e}")

                    # Register file ownership with auth server (send directly to server)
                    if uploader:
                        try:
                            self._notify_auth_server_ownership(file_name, uploader, server_host='127.0.0.1', server_port=7001)
                        except Exception as e:
                            print(f"[{self.node_name}] Warning: could not notify ownership: {e}")

                    # Register file location with server (send directly to server, not via gateway)
                    try:
                        stored_path = storage_resp.metadata.file_path if storage_resp.metadata and hasattr(storage_resp.metadata, 'file_path') else None
                        self._register_location(file_name, stored_path, server_host='127.0.0.1', server_port=7001, owner=uploader)
                    except Exception as e:
                        print(f"[{self.node_name}] Warning: could not register location: {e}")

                    # RAID 1: Replicate to mirror node (only if not already a mirror copy)
                    if self.raid_level == 1 and not is_mirror_copy and self.mirror_target:
                        self._replicate_to_mirror(file_name, content_bytes, uploader)

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
            elif interest.operation == "DELETE":
                return self._handle_delete_request(interest)
            elif interest.operation == "PERMISSION":
                return self._handle_permission_request(interest)
            elif interest.operation == "STATS":
                return self._handle_stats_request(interest)
            elif interest.operation == "CLEAR":
                return self._handle_clear_request(interest)
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
            if content_bytes is None:
                return self._create_error_response(f"File content is empty or corrupted: {file_name}")
            total_size = len(content_bytes)

            print(f"[{self.node_name}] ✓ Retrieved from RAID {self.raid_level} storage")
            print(f"[{self.node_name}] Size: {total_size} bytes")
            print(f"[{self.node_name}] 📦 Storage Node: {self.node_name} (RAID {self.raid_level})")

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

            # Write metadata JSON to storage path for persistence and later re-sync
            try:
                stored_path = storage_response.metadata.file_path if storage_response.metadata and hasattr(storage_response.metadata, 'file_path') else ''
                safe_name = os.path.basename(stored_path) if stored_path else file_name.replace('/', '_')
                meta_dir = os.path.join(self.storage_path, 'metadata')
                os.makedirs(meta_dir, exist_ok=True)
                meta_path = os.path.join(meta_dir, f"{safe_name}.json")
                meta = {
                    "original_name": file_name,
                    "stored_path": stored_path,
                    "checksum": storage_response.metadata.checksum if storage_response.metadata else hashlib.md5(content_bytes).hexdigest(),
                    "size": len(content_bytes),
                    "stored_at": time.strftime('%Y-%m-%d %H:%M:%S')
                }
                with open(meta_path, 'w', encoding='utf-8') as mf:
                    json.dump(meta, mf, indent=2)
            except Exception as e:
                print(f"[{self.node_name}] Warning: could not write metadata file: {e}")

            # Register ownership and location with Authentication Server / DB
            try:
                # Try to register ownership first (backwards-compatible)
                self._notify_auth_server_ownership(file_name, interest.user_id)
            except Exception:
                pass

            try:
                # Register precise location so server DB knows which node holds this file
                stored_path = storage_response.metadata.file_path if storage_response.metadata and hasattr(storage_response.metadata, 'file_path') else None
                self._register_location(file_name, stored_path)
            except Exception as e:
                print(f"[{self.node_name}] Warning: could not register location with server: {e}")
            
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
    
    def _handle_delete_request(self, interest: InterestPacket):
        """Handle DELETE requests - remove file from storage including fragments"""
        file_name = interest.name
        
        print(f"\n[{self.node_name}] === DELETE REQUEST ===")
        print(f"[{self.node_name}] File: {file_name}")
        print(f"[{self.node_name}] User: {interest.user_id}")
        
        try:
            # Remove from storage module (main file)
            storage_response = self.storage_module.delete_file(file_name)
            
            # Even if storage_module didn't find the file, try to clean up fragments
            # This handles cases where fragmented files might not be in the in-memory index
            
            # Remove from in-memory index
            if file_name in self.stored_files:
                del self.stored_files[file_name]
            
            # Create safe name pattern for fragment/parity matching
            safe_name = file_name.replace('/', '_')
            fragments_deleted = 0
            parity_deleted = 0
            
            # Remove matching fragments
            fragments_dir = os.path.join(self.storage_path, 'fragments')
            if os.path.exists(fragments_dir):
                for f in os.listdir(fragments_dir):
                    # Fragments are named like: _dlsu_filename_frag0, _dlsu_filename_frag1, etc.
                    if f.startswith(safe_name) or safe_name in f:
                        try:
                            fpath = os.path.join(fragments_dir, f)
                            if os.path.isfile(fpath):
                                os.remove(fpath)
                                fragments_deleted += 1
                        except Exception:
                            pass
            
            # Remove matching parity files
            parity_dir = os.path.join(self.storage_path, 'parity')
            if os.path.exists(parity_dir):
                for f in os.listdir(parity_dir):
                    # Parity files are named like: _dlsu_filename_parity, etc.
                    if f.startswith(safe_name) or safe_name in f:
                        try:
                            fpath = os.path.join(parity_dir, f)
                            if os.path.isfile(fpath):
                                os.remove(fpath)
                                parity_deleted += 1
                        except Exception:
                            pass
            
            # Remove matching files in files directory
            files_dir = os.path.join(self.storage_path, 'files')
            if os.path.exists(files_dir):
                for f in os.listdir(files_dir):
                    if f.startswith(safe_name) or safe_name in f or f == safe_name:
                        try:
                            fpath = os.path.join(files_dir, f)
                            if os.path.isfile(fpath):
                                os.remove(fpath)
                        except Exception:
                            pass
            
            # Remove metadata file if exists
            try:
                meta_path = os.path.join(self.storage_path, 'metadata', f"{safe_name}.json")
                if os.path.exists(meta_path):
                    os.remove(meta_path)
            except Exception:
                pass
            
            print(f"[{self.node_name}] ✓ File deleted: {file_name}")
            if fragments_deleted > 0:
                print(f"[{self.node_name}]   - Fragments removed: {fragments_deleted}")
            if parity_deleted > 0:
                print(f"[{self.node_name}]   - Parity files removed: {parity_deleted}")
            
            response_content = f"DELETED:{file_name}"
            return self._create_data_response(file_name, response_content)
                
        except Exception as e:
            print(f"[{self.node_name}] ✗ Delete error: {e}")
            return self._create_error_response(f"Delete error: {e}")
    
    def _handle_permission_request(self, interest: InterestPacket):
        """Handle PERMISSION requests"""
        response_content = f"""RAID {self.raid_level} Permission Response:
File: {interest.name}
User: {interest.user_id}
Permission: GRANTED
Storage Node: {self.node_name}
RAID Level: {self.raid_level}"""
        
        return self._create_data_response(interest.name, response_content)
    
    def _handle_stats_request(self, interest: InterestPacket):
        """Handle STATS requests - return RAID and storage statistics"""
        import json
        
        print(f"\n[{self.node_name}] === STATS REQUEST ===")
        
        # Count files in storage
        files_dir = os.path.join(self.storage_path, 'files')
        fragments_dir = os.path.join(self.storage_path, 'fragments')
        parity_dir = os.path.join(self.storage_path, 'parity')
        metadata_dir = os.path.join(self.storage_path, 'metadata')
        
        file_count = 0
        fragment_count = 0
        parity_count = 0
        total_size = 0
        
        try:
            if os.path.exists(files_dir):
                for f in os.listdir(files_dir):
                    fpath = os.path.join(files_dir, f)
                    if os.path.isfile(fpath):
                        file_count += 1
                        total_size += os.path.getsize(fpath)
        except Exception:
            pass
        
        try:
            if os.path.exists(fragments_dir):
                for f in os.listdir(fragments_dir):
                    fpath = os.path.join(fragments_dir, f)
                    if os.path.isfile(fpath):
                        fragment_count += 1
                        total_size += os.path.getsize(fpath)
        except Exception:
            pass
        
        try:
            if os.path.exists(parity_dir):
                for f in os.listdir(parity_dir):
                    fpath = os.path.join(parity_dir, f)
                    if os.path.isfile(fpath):
                        parity_count += 1
                        total_size += os.path.getsize(fpath)
        except Exception:
            pass
        
        # Calculate RAID overhead
        raid_overhead = 0.0
        raid_description = ""
        if self.raid_level == 0:
            raid_description = "Striping (no redundancy)"
            raid_overhead = 0.0
        elif self.raid_level == 1:
            raid_description = "Mirroring (100% redundancy)"
            raid_overhead = 100.0
        elif self.raid_level == 5:
            raid_description = "Single parity (N-1 data, 1 parity)"
            raid_overhead = 33.3  # Approximate for 3 drives
        elif self.raid_level == 6:
            raid_description = "Double parity (N-2 data, 2 parity)"
            raid_overhead = 50.0  # Approximate for 4 drives
        
        stats = {
            'node_name': self.node_name,
            'node_id': self.node_id,
            'raid_level': self.raid_level,
            'raid_description': raid_description,
            'raid_overhead_percent': raid_overhead,
            'storage_path': self.storage_path,
            'port': self.port,
            'file_count': file_count,
            'fragment_count': fragment_count,
            'parity_count': parity_count,
            'total_size_bytes': total_size,
            'total_size_kb': round(total_size / 1024, 2),
            'requests_handled': self.stats.get('requests_handled', 0),
            'files_stored': self.stats.get('files_stored', 0),
            'files_retrieved': self.stats.get('files_retrieved', 0),
            'is_mirror_target': hasattr(self, 'mirror_target') and self.mirror_target is not None
        }
        
        print(f"[{self.node_name}] Returning stats: {file_count} files, {fragment_count} fragments, {parity_count} parity blocks")
        
        response_content = json.dumps(stats)
        return self._create_data_response(interest.name, response_content)
    
    def _handle_clear_request(self, interest: InterestPacket):
        """Handle CLEAR requests - delete all stored files (admin only)"""
        import json
        import shutil
        
        print(f"\n[{self.node_name}] === CLEAR REQUEST ===")
        print(f"[{self.node_name}] User: {interest.user_id}")
        
        # Collect file names before clearing (to notify server)
        cleared_files = []
        files_cleared = 0
        fragments_cleared = 0
        parity_cleared = 0
        errors = []
        
        # Read metadata to get original file names
        metadata_dir = os.path.join(self.storage_path, 'metadata')
        if os.path.exists(metadata_dir):
            for f in os.listdir(metadata_dir):
                if f.endswith('.json'):
                    try:
                        with open(os.path.join(metadata_dir, f), 'r') as mf:
                            meta = json.load(mf)
                            if meta.get('original_name'):
                                cleared_files.append(meta['original_name'])
                    except Exception:
                        pass
        
        # Clear files directory
        files_dir = os.path.join(self.storage_path, 'files')
        try:
            if os.path.exists(files_dir):
                for f in os.listdir(files_dir):
                    fpath = os.path.join(files_dir, f)
                    if os.path.isfile(fpath):
                        os.remove(fpath)
                        files_cleared += 1
        except Exception as e:
            errors.append(f"files: {e}")
        
        # Clear fragments directory
        fragments_dir = os.path.join(self.storage_path, 'fragments')
        try:
            if os.path.exists(fragments_dir):
                for f in os.listdir(fragments_dir):
                    fpath = os.path.join(fragments_dir, f)
                    if os.path.isfile(fpath):
                        os.remove(fpath)
                        fragments_cleared += 1
        except Exception as e:
            errors.append(f"fragments: {e}")
        
        # Clear parity directory
        parity_dir = os.path.join(self.storage_path, 'parity')
        try:
            if os.path.exists(parity_dir):
                for f in os.listdir(parity_dir):
                    fpath = os.path.join(parity_dir, f)
                    if os.path.isfile(fpath):
                        os.remove(fpath)
                        parity_cleared += 1
        except Exception as e:
            errors.append(f"parity: {e}")
        
        # Clear metadata directory
        try:
            if os.path.exists(metadata_dir):
                for f in os.listdir(metadata_dir):
                    fpath = os.path.join(metadata_dir, f)
                    if os.path.isfile(fpath):
                        os.remove(fpath)
        except Exception as e:
            errors.append(f"metadata: {e}")
        
        # Clear in-memory state
        self.stored_files.clear()
        self.stats["files_stored"] = 0
        self.stats["files_retrieved"] = 0
        
        # Notify server to remove file records from DB
        try:
            clear_payload = {
                'action': 'clear_node_files',
                'node_name': self.node_name,
                'cleared_files': cleared_files
            }
            resp = self.comm_module.send_packet_sync('127.0.0.1', 7001, json.dumps(clear_payload))
            if resp:
                print(f"[{self.node_name}] Notified server to clear {len(cleared_files)} file records")
        except Exception as e:
            print(f"[{self.node_name}] Warning: could not notify server about cleared files: {e}")
        
        result = {
            'success': len(errors) == 0,
            'node_name': self.node_name,
            'raid_level': self.raid_level,
            'files_cleared': files_cleared,
            'fragments_cleared': fragments_cleared,
            'parity_cleared': parity_cleared,
            'db_records_cleared': len(cleared_files),
            'errors': errors if errors else None
        }
        
        print(f"[{self.node_name}] ✓ Cleared: {files_cleared} files, {fragments_cleared} fragments, {parity_cleared} parity blocks")
        
        response_content = json.dumps(result)
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
            # Persist using StorageModule so files are on disk and retrievable via RAID module
            try:
                resp = self.storage_module.store_file(file_name, content_bytes)
                if resp.success:
                    self.stats["files_stored"] += 1
                    # Write metadata JSON
                    try:
                        stored_path = resp.metadata.file_path if resp.metadata and hasattr(resp.metadata, 'file_path') else ''
                        safe_name = os.path.basename(stored_path) if stored_path else file_name.replace('/', '_')
                        meta_dir = os.path.join(self.storage_path, 'metadata')
                        os.makedirs(meta_dir, exist_ok=True)
                        meta_path = os.path.join(meta_dir, f"{safe_name}.json")
                        meta = {
                            "original_name": file_name,
                            "stored_path": stored_path,
                            "checksum": resp.metadata.checksum if resp.metadata else hashlib.md5(content_bytes).hexdigest(),
                            "size": len(content_bytes),
                            "stored_at": time.strftime('%Y-%m-%d %H:%M:%S'),
                            "user": "system"
                        }
                        with open(meta_path, 'w', encoding='utf-8') as mf:
                            json.dump(meta, mf, indent=2)
                    except Exception as e:
                        print(f"[{self.node_name}] Warning: could not write metadata file: {e}")

                    # Try to register in DB directly; if unavailable, notify auth server
                    try:
                        from db import get_db
                        db = get_db()
                        db.add_file(file_name, 'system')
                    except Exception:
                        self._notify_auth_server_ownership(file_name, 'system')
            except Exception as e:
                print(f"[{self.node_name}] Warning: could not create test file {file_name}: {e}")

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

    def _replicate_to_mirror(self, file_name: str, content_bytes: bytes, uploader: str = None):
        """RAID 1: Replicate data to mirror node.
        
        This sends a DataPacket directly to the mirror storage node.
        The mirror will store it but NOT re-replicate (is_mirror_copy flag prevents loops).
        """
        if not self.mirror_target:
            return  # No mirror configured
        
        if self.raid_level != 1:
            return  # Only RAID 1 does mirroring
        
        mirror_host, mirror_port = self.mirror_target
        print(f"[{self.node_name}] RAID 1: Replicating to mirror at {mirror_host}:{mirror_port}")
        
        try:
            import socket
            import json
            import base64
            
            # Create a DataPacket with mirror flag
            payload = {
                'uploader': uploader or 'mirror',
                'data_b64': base64.b64encode(content_bytes).decode('utf-8'),
                'is_mirror': True  # Flag so mirror doesn't re-replicate
            }
            
            dp = DataPacket(
                name=file_name,
                data_payload=json.dumps(payload).encode('utf-8')
            )
            
            # Send directly to mirror node
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5.0)
            try:
                sock.sendto(dp.to_json().encode('utf-8'), (mirror_host, mirror_port))
                print(f"[{self.node_name}] RAID 1: ✓ Sent mirror copy to {mirror_host}:{mirror_port}")
                self.storage_module.stats["raid_operations"] += 1
            finally:
                sock.close()
                
        except Exception as e:
            print(f"[{self.node_name}] RAID 1: ✗ Mirror replication failed: {e}")
    
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
        print(f"Gateway:       {self.gateway_host}:{self.gateway_port}")
        print(f"Storage Path: {self.storage_path}")
        print(f"Files Ready:  {len(self.stored_files)}")
        print(f"{'='*70}\n")
        
        # Start communication module
        self.comm_module.start()
        
        # Re-sync any locally present files and register with server
        try:
            self._sync_local_files_on_startup()
        except Exception as e:
            print(f"[{self.node_name}] Warning: error during startup sync: {e}")
        
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
    
    def _notify_auth_server_ownership(self, file_name: str, owner: str, server_host: Optional[str] = None, server_port: Optional[int] = None):
        """Notify authentication server that a file was uploaded to create ACL.
        By default this sends to the configured gateway (router) so it follows the topology instead of contacting server directly."""
        import json
        
        # Strip fragment notation to register only the base filename
        base_name = file_name.split(':[')[0] if ':[' in file_name else file_name
        
        payload = {
            "action": "register_file",
            "resource": base_name,
            "owner": owner
        }
        req = json.dumps(payload)
        # Send registration to local gateway (router) so the message follows topology
        target_host = server_host or self.gateway_host
        target_port = server_port or self.gateway_port
        try:
            resp = self.comm_module.send_packet_sync(target_host, target_port, req)
            if resp:
                print(f"[{self.node_name}] ACL created for {base_name} (owner: {owner}) via {target_host}:{target_port}")
        except Exception as e:
            print(f"[{self.node_name}] Warning: Could not register file ownership via {target_host}:{target_port}: {e}")

    def _register_location(self, file_name: str, stored_path: Optional[str] = None, server_host: Optional[str] = None, server_port: Optional[int] = None, owner: Optional[str] = None):
        """Notify server to persist mapping of file -> this storage node (location).
        By default this sends to the configured gateway (router) so it follows the topology."""
        import json
        base_name = file_name.split(':[')[0] if ':[' in file_name else file_name
        payload = {
            "action": "register_location",
            "resource": base_name,
            "node_name": self.node_name,
            "host": self.host,
            "port": self.port,
            "stored_path": stored_path
        }
        if owner:
            payload["owner"] = owner
        # Send registration to the local gateway (router) so the message follows topology
        target_host = server_host or self.gateway_host
        target_port = server_port or self.gateway_port
        print(f"[{self.node_name}] >>> Sending register_location to {target_host}:{target_port}: {payload}")
        try:
            req = json.dumps(payload)
            resp = self.comm_module.send_packet_sync(target_host, target_port, req)
            if resp:
                print(f"[{self.node_name}] Registered location for {base_name} via {target_host}:{target_port}")
                print(f"[{self.node_name}] <<< Server response: {resp}")
        except Exception as e:
            print(f"[{self.node_name}] Warning: Could not register file location via {target_host}:{target_port}: {e}")

    def _sync_local_files_on_startup(self, server_host: str = '127.0.0.1', server_port: int = 7001):
        """Scan on-disk metadata files and re-register each local file with the auth server/DB.
        Also rehydrate in-memory self.stored_files so interactive commands work after restart.
        """
        meta_dir = os.path.join(self.storage_path, 'metadata')
        if not os.path.isdir(meta_dir):
            return
        for fn in os.listdir(meta_dir):
            if not fn.endswith('.json'):
                continue
            full = os.path.join(meta_dir, fn)
            try:
                with open(full, 'r', encoding='utf-8') as mf:
                    meta = json.load(mf)
                    name = meta.get('original_name')
                    stored_path = meta.get('stored_path')
                    checksum = meta.get('checksum')
                    size = meta.get('size', 0)
                    stored_at = meta.get('stored_at')

                    if name:
                        # rehydrate in-memory index
                        self.stored_files[name] = {
                            'content': None,
                            'stored_at': stored_at,
                            'checksum': checksum,
                            'size': size,
                            'user': meta.get('user','system')
                        }
                        # attempt to register in DB/server
                        try:
                            self._notify_auth_server_ownership(name, self.stored_files[name]['user'])
                        except Exception:
                            pass
                        try:
                            self._register_location(name, stored_path)
                        except Exception:
                            pass
            except Exception as e:
                print(f"[{self.node_name}] Warning: could not process metadata file {fn}: {e}")
    
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
        """Show stored files. If in-memory index is empty, attempt to read on-disk metadata for persisted entries."""
        print(f"\n=== {self.node_name} Stored Files ===")
        if not self.stored_files:
            # Attempt to rehydrate from metadata directory
            meta_dir = os.path.join(self.storage_path, 'metadata')
            if os.path.isdir(meta_dir):
                files_shown = False
                for fn in os.listdir(meta_dir):
                    if fn.endswith('.json'):
                        try:
                            with open(os.path.join(meta_dir, fn), 'r', encoding='utf-8') as mf:
                                meta = json.load(mf)
                                name = meta.get('original_name') or fn.replace('.json','')
                                print(f"  {name}")
                                print(f"    Size: {meta.get('size','?')} bytes")
                                print(f"    Stored: {meta.get('stored_at','?')}")
                                print(f"    Checksum: {meta.get('checksum','?')}")
                                files_shown = True
                        except Exception:
                            pass
                if not files_shown:
                    print("No files stored")
            else:
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
        
        # Ensure the file is registered with the AuthenticationServer/DB so it
        # appears in the server's file listings (try DB first, fallback to UDP notify)
        try:
            from db import get_db
            db = get_db()
            try:
                db.add_file(filename, 'admin')
                print(f"✓ Registered {filename} in DB (owner: admin)")
            except Exception:
                print(f"i: {filename} already present in DB or registration failed")
        except Exception:
            # DB not available -> notify auth server via UDP
            try:
                self._notify_auth_server_ownership(filename, 'admin')
            except Exception:
                pass

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