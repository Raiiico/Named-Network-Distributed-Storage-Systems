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

# Import network configuration
try:
    from network_config import get_server_address, get_router_address, DEFAULT_HOST
    _USE_NETWORK_CONFIG = True
except ImportError:
    _USE_NETWORK_CONFIG = False
    DEFAULT_HOST = '127.0.0.1'

class SimpleStorageNode:
    """
    Simple Storage Node for demonstrating hub-and-spoke topology
    Stores files and responds to Interest packets
    """
    
    def __init__(self, node_id: str, raid_level: int, host: str = None, port: int = 9001, gateway_host: Optional[str] = None, gateway_port: Optional[int] = None):
        self.node_id = node_id
        self.raid_level = raid_level
        self.node_name = f"Storage-{node_id}"
        self.host = host if host is not None else DEFAULT_HOST
        self.port = port

        # Determine default gateway (router) for storage nodes: default to R2 port from fib_config
        if gateway_host is None:
            if _USE_NETWORK_CONFIG:
                router_host, _ = get_router_address('R2')
                self.gateway_host = router_host
            else:
                self.gateway_host = DEFAULT_HOST
        else:
            self.gateway_host = gateway_host
        self.gateway_port = gateway_port or fib_config.get_port_for_router('R2')
        
        # RAID peer configuration from fib_config
        # Each RAID group has peer nodes for replication/parity
        self.raid_peers = self._get_raid_peers(node_id, port)
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
        # Encryption key tracker: base_name -> key_hex (generated on first fragment)
        self.encryption_keys = {}
        self._encryption_lock = threading.Lock()
        
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
        
        # NOTE: Test file pre-population removed - storage starts clean
        
        print(f"[{self.node_name}] Storage Node initialized")
        print(f"[{self.node_name}] RAID Level: {raid_level}")
        print(f"[{self.node_name}] Storage Path: {self.storage_path}")
        if self.raid_peers:
            print(f"[{self.node_name}] RAID Peers: {[p['name'] for p in self.raid_peers]}")
    
    def _get_raid_peers(self, node_id: str, port: int) -> list:
        """Get peer nodes in the same RAID group from fib_config.
        
        Returns list of peer nodes (excluding self) for RAID operations:
        - RAID 1: peer nodes for mirroring
        - RAID 5: peer nodes for parity distribution
        - RAID 6: peer nodes for dual parity
        """
        try:
            from fib_config import RAID_GROUPS
            
            # Find which group this node belongs to
            for group_name, config in RAID_GROUPS.items():
                for node in config['nodes']:
                    if node['name'] == node_id or node['port'] == port:
                        # Found our group - return all OTHER nodes
                        peers = [
                            {'name': n['name'], 'host': n['host'], 'port': n['port']}
                            for n in config['nodes']
                            if n['name'] != node_id and n['port'] != port
                        ]
                        return peers
            return []
        except ImportError:
            return []
    
    def _setup_interfaces(self):
        """Setup module interfaces"""
        # Communication -> Custom handler that checks for RAID messages first
        self.comm_module.set_packet_handler(self._handle_raw_packet)
        
        # Parsing -> Storage (this node)
        self.parsing_module.set_processing_handler(self._handle_storage_request)
        
        print(f"[{self.node_name}] Module interfaces configured")
    
    def _handle_raw_packet(self, packet_str: str, source: str):
        """Pre-process raw packets to handle RAID replication messages directly.
        
        RAID_REPLICATE messages bypass the normal Interest/Data parsing since
        they are internal storage node communication.
        """
        import json
        import base64
        
        try:
            parsed = json.loads(packet_str)
            
            # Handle RAID replication messages directly
            if isinstance(parsed, dict) and parsed.get('type') == 'RAID_REPLICATE':
                return self._handle_raid_replicate(parsed, source)
        except json.JSONDecodeError:
            pass  # Not JSON, let parsing module handle it
        except Exception as e:
            print(f"[{self.node_name}] Error checking RAID message: {e}")
        
        # Normal packet - pass to parsing module
        return self.parsing_module.handle_packet(packet_str, source)
    
    def _handle_raid_replicate(self, msg: dict, source: str) -> str:
        """Handle RAID replication message from a peer storage node.
        
        This stores the replicated data locally without re-replicating.
        """
        import json
        import base64
        
        file_name = msg.get('file_name')
        uploader = msg.get('uploader', 'mirror')
        data_b64 = msg.get('data_b64')
        source_node = msg.get('source_node', 'unknown')
        
        print(f"[{self.node_name}] RAID 1: Receiving replication from {source_node}")
        print(f"[{self.node_name}] RAID 1: File: {file_name}")
        
        if not file_name or not data_b64:
            error_resp = {'success': False, 'error': 'Missing file_name or data'}
            return json.dumps(error_resp)
        
        try:
            content_bytes = base64.b64decode(data_b64)
            
            # Store the file locally using storage module
            storage_resp = self.storage_module.store_file(file_name, content_bytes)
            
            if storage_resp.success:
                self.stats["files_stored"] += 1
                self.stats["bytes_stored"] += len(content_bytes)
                
                print(f"[{self.node_name}] RAID 1: ✓ Stored replica of {file_name} ({len(content_bytes)} bytes)")
                
                resp = {'success': True, 'message': f'STORED:{file_name}', 'node': self.node_name}
                return json.dumps(resp)
            else:
                print(f"[{self.node_name}] RAID 1: ✗ Failed to store replica: {storage_resp.error}")
                resp = {'success': False, 'error': storage_resp.error}
                return json.dumps(resp)
                
        except Exception as e:
            print(f"[{self.node_name}] RAID 1: ✗ Replication error: {e}")
            resp = {'success': False, 'error': str(e)}
            return json.dumps(resp)
    
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
        print(f"[{self.node_name}] _handle_data_packet called: {data_packet.name}")
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

            # Check for RAID 0 stripe write (e.g., /path/file:stripe[0/2])
            # These are stored directly without fragment accumulation
            if ':stripe[' in file_name:
                print(f"[{self.node_name}] RAID 0: Storing stripe: {file_name}")
                storage_resp = self.storage_module.store_file(file_name, content_bytes)
                
                if storage_resp.success:
                    self.stats["files_stored"] += 1
                    self.stats["bytes_stored"] += len(content_bytes)
                    print(f"[{self.node_name}] ✓ RAID 0: Stripe stored ({len(content_bytes)} bytes)")
                    
                    resp_msg = f"STORED:{file_name}"
                    return self._create_data_response(file_name, resp_msg)
                else:
                    print(f"[{self.node_name}] ✗ RAID 0: Stripe store failed: {storage_resp.error}")
                    return self._create_error_response(storage_resp.error or "Stripe store failed")

            # Check for RAID 5/6 parity write
            # RAID 5: :parity[N] or :parity[N]:sizes[...]
            # RAID 6: :parity_p[N] or :parity_q[N] with optional sizes
            if ':parity' in file_name:
                import re
                # Match parity_p, parity_q, or just parity
                parity_match = re.search(r':parity(_[pq])?\[(\d+)\](?::sizes\[([^\]]*)\])?', file_name)
                if parity_match:
                    parity_type = parity_match.group(1) or ''  # '_p', '_q', or ''
                    parity_idx = int(parity_match.group(2))
                    sizes_str = parity_match.group(3)  # May be None
                    base_name = file_name[:file_name.index(':parity')]
                    
                    parity_label = f"P" if parity_type == '_p' else ('Q' if parity_type == '_q' else 'XOR')
                    print(f"[{self.node_name}] RAID 5/6: Storing {parity_label} parity block {parity_idx} for {base_name}")
                    
                    # Store parity in parity/ directory
                    safe_name = base_name.replace('/', '_')
                    parity_dir = os.path.join(self.storage_path, 'parity')
                    os.makedirs(parity_dir, exist_ok=True)
                    parity_path = os.path.join(parity_dir, f"{safe_name}_parity{parity_type}_{parity_idx}.bin")
                    
                    with open(parity_path, 'wb') as f:
                        f.write(content_bytes)
                    
                    # Store fragment sizes metadata if provided
                    if sizes_str:
                        sizes_path = os.path.join(parity_dir, f"{safe_name}_parity{parity_type}_{parity_idx}_sizes.txt")
                        with open(sizes_path, 'w') as f:
                            f.write(sizes_str)
                        print(f"[{self.node_name}] RAID 5/6: Stored sizes metadata: {sizes_str}")
                    
                    self.stats["files_stored"] += 1
                    self.stats["bytes_stored"] += len(content_bytes)
                    print(f"[{self.node_name}] ✓ RAID 5/6: {parity_label} parity stored ({len(content_bytes)} bytes)")
                    
                    resp_msg = f"STORED:{file_name}"
                    return self._create_data_response(file_name, resp_msg)

            # If fragment, handle based on RAID level
            if frag_info and frag_info.get("is_fragment"):
                base_name = frag_info["base_name"]
                index = int(frag_info["index"])  # 1-based index expected from client
                total = int(frag_info["total"])
                
                # RAID 0: Store each fragment immediately (no accumulation)
                # Each node only receives a subset of fragments (round-robin distribution)
                if self.raid_level == 0 or '/raid0/' in base_name:
                    print(f"[{self.node_name}] RAID 0: Storing fragment {index}/{total} immediately")
                    
                    # Get or generate encryption key for this file
                    with self._encryption_lock:
                        enc_key = self.encryption_keys.get(base_name)
                        # If no key yet, storage_module will generate one
                    
                    # Use dedicated RAID 0 single-fragment storage method with encryption
                    storage_resp = self.storage_module.store_raid0_fragment(base_name, index, total, content_bytes, encryption_key=enc_key)
                    
                    if storage_resp.success:
                        # Store the encryption key for subsequent fragments
                        if storage_resp.storage_info and storage_resp.storage_info.get('encryption_key'):
                            with self._encryption_lock:
                                self.encryption_keys[base_name] = storage_resp.storage_info['encryption_key']
                            # Send key to server on first fragment
                            if index == 1:
                                try:
                                    self._send_encryption_key(base_name, storage_resp.storage_info['encryption_key'], interest.user_id or 'system')
                                except Exception as e:
                                    print(f"[{self.node_name}] Warning: Could not send encryption key: {e}")
                        
                        self.stats["files_stored"] += 1
                        self.stats["bytes_stored"] += len(content_bytes)
                        print(f"[{self.node_name}] ✓ RAID 0: Fragment {index}/{total} encrypted and stored ({len(content_bytes)} bytes)")
                        
                        resp_msg = f"STORED:{file_name}"
                        return self._create_data_response(file_name, resp_msg)
                    else:
                        print(f"[{self.node_name}] ✗ RAID 0: Fragment store failed: {storage_resp.error}")
                        return self._create_error_response(storage_resp.error or "Fragment store failed")

                # RAID 5: Store each data fragment immediately (like RAID 0)
                # Each data node only receives specific fragments based on stripe distribution
                if self.raid_level == 5 or '/raid5/' in base_name:
                    print(f"[{self.node_name}] RAID 5: Storing data fragment {index}/{total} immediately")
                    
                    # Get or generate encryption key for this file
                    with self._encryption_lock:
                        enc_key = self.encryption_keys.get(base_name)
                    
                    # Use the same single-fragment storage method as RAID 0 with encryption
                    storage_resp = self.storage_module.store_raid0_fragment(base_name, index, total, content_bytes, encryption_key=enc_key)
                    
                    if storage_resp.success:
                        # Store the encryption key for subsequent fragments
                        if storage_resp.storage_info and storage_resp.storage_info.get('encryption_key'):
                            with self._encryption_lock:
                                self.encryption_keys[base_name] = storage_resp.storage_info['encryption_key']
                            # Send key to server on first fragment
                            if index == 1:
                                try:
                                    self._send_encryption_key(base_name, storage_resp.storage_info['encryption_key'], interest.user_id or 'system')
                                except Exception as e:
                                    print(f"[{self.node_name}] Warning: Could not send encryption key: {e}")
                        
                        self.stats["files_stored"] += 1
                        self.stats["bytes_stored"] += len(content_bytes)
                        print(f"[{self.node_name}] ✓ RAID 5: Fragment {index}/{total} encrypted and stored ({len(content_bytes)} bytes)")
                        
                        # Include encryption key in response so router can encrypt parity
                        resp_enc_key = storage_resp.storage_info.get('encryption_key', '')
                        resp_msg = f"STORED:{file_name}:enc_key={resp_enc_key}"
                        return self._create_data_response(file_name, resp_msg)
                    else:
                        print(f"[{self.node_name}] ✗ RAID 5: Fragment store failed: {storage_resp.error}")
                        return self._create_error_response(storage_resp.error or "Fragment store failed")

                # RAID 6: Store each data fragment immediately (like RAID 0/5)
                # Each data node only receives specific fragments based on stripe distribution
                if self.raid_level == 6 or '/raid6/' in base_name:
                    print(f"[{self.node_name}] RAID 6: Storing data fragment {index}/{total} immediately")
                    
                    # Get or generate encryption key for this file
                    with self._encryption_lock:
                        enc_key = self.encryption_keys.get(base_name)
                    
                    # Use the same single-fragment storage method as RAID 0/5 with encryption
                    storage_resp = self.storage_module.store_raid0_fragment(base_name, index, total, content_bytes, encryption_key=enc_key)
                    
                    if storage_resp.success:
                        # Store the encryption key for subsequent fragments
                        if storage_resp.storage_info and storage_resp.storage_info.get('encryption_key'):
                            with self._encryption_lock:
                                self.encryption_keys[base_name] = storage_resp.storage_info['encryption_key']
                            # Send key to server on first fragment
                            if index == 1:
                                try:
                                    self._send_encryption_key(base_name, storage_resp.storage_info['encryption_key'], interest.user_id or 'system')
                                except Exception as e:
                                    print(f"[{self.node_name}] Warning: Could not send encryption key: {e}")
                        
                        self.stats["files_stored"] += 1
                        self.stats["bytes_stored"] += len(content_bytes)
                        print(f"[{self.node_name}] ✓ RAID 6: Fragment {index}/{total} encrypted and stored ({len(content_bytes)} bytes)")
                        
                        # Include encryption key in response so router can encrypt parity
                        resp_enc_key = storage_resp.storage_info.get('encryption_key', '')
                        resp_msg = f"STORED:{file_name}:enc_key={resp_enc_key}"
                        return self._create_data_response(file_name, resp_msg)
                    else:
                        print(f"[{self.node_name}] ✗ RAID 6: Fragment store failed: {storage_resp.error}")
                        return self._create_error_response(storage_resp.error or "Fragment store failed")

                # RAID 1: Accumulate all fragments before storing (each node gets ALL fragments)
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
                            # Get encryption key from storage response
                            encryption_key = None
                            if storage_resp.storage_info and storage_resp.storage_info.get('encryption_key'):
                                encryption_key = storage_resp.storage_info['encryption_key']
                            
                            self.stored_files[base_name] = {
                                "content": b'',  # Don't store full content in memory
                                "stored_at": time.strftime('%Y-%m-%d %H:%M:%S'),
                                "checksum": storage_resp.metadata.checksum if storage_resp.metadata else "",
                                "size": total_size,
                                "user": uploader if uploader else "uploader",
                                "raid_processed": True,
                                "encryption_key": encryption_key
                            }
                            self.stats["files_stored"] += 1
                            self.stats["bytes_stored"] += total_size

                            # Write metadata JSON so stored files are discoverable on disk
                            try:
                                stored_path = storage_resp.metadata.file_path if storage_resp.metadata and hasattr(storage_resp.metadata, 'file_path') else ''
                                safe_name = os.path.basename(stored_path) if stored_path else base_name.replace('/', '_')
                                meta_dir = os.path.join(self.storage_path, 'metadata')
                                os.makedirs(meta_dir, exist_ok=True)
                                meta_path = os.path.join(meta_dir, f"{safe_name}.json")
                                
                                # Include fragments map for fragment-based storage (critical for recovery after restart)
                                fragments_map = {}
                                if storage_resp.metadata and hasattr(storage_resp.metadata, 'fragments') and storage_resp.metadata.fragments:
                                    # Convert int keys to string for JSON serialization
                                    fragments_map = {str(k): v for k, v in storage_resp.metadata.fragments.items()}
                                
                                meta = {
                                    "original_name": base_name,
                                    "stored_path": stored_path,
                                    "checksum": storage_resp.metadata.checksum if storage_resp.metadata else "",
                                    "size": total_size,
                                    "stored_at": time.strftime('%Y-%m-%d %H:%M:%S'),
                                    "user": uploader if uploader else "system",
                                    "fragments": fragments_map,  # Fragment paths for reassembly on restart
                                    "encryption_key": encryption_key,
                                    "is_encrypted": True if encryption_key else False
                                }
                                with open(meta_path, 'w', encoding='utf-8') as mf:
                                    json.dump(meta, mf, indent=2)
                            except Exception as e:
                                print(f"[{self.node_name}] Warning: could not write metadata file: {e}")

                            # Prepare response FIRST before registration (to avoid blocking)
                            resp_msg = f"STORED:{base_name}"
                            data_response = self._create_data_response(base_name, resp_msg)
                            
                            # Run registration in background thread to avoid blocking the response
                            import threading
                            def _do_registration():
                                # Notify auth server to create ACL (via gateway/router)
                                if uploader:
                                    try:
                                        self._notify_auth_server_ownership(base_name, uploader)
                                    except Exception as e:
                                        print(f"[{self.node_name}] Warning: could not notify ownership: {e}")
                                # Register file location with server (via gateway/router)
                                try:
                                    sp = storage_resp.metadata.file_path if storage_resp.metadata and hasattr(storage_resp.metadata, 'file_path') else None
                                    self._register_location(base_name, sp, owner=uploader)
                                except Exception as e:
                                    print(f"[{self.node_name}] Warning: could not register location for {base_name}: {e}")
                                # Send encryption key to server
                                if encryption_key:
                                    try:
                                        self._send_encryption_key(base_name, encryption_key, uploader or 'system')
                                        print(f"[{self.node_name}] ✓ Encryption key sent to server for {base_name}")
                                    except Exception as e:
                                        print(f"[{self.node_name}] Warning: could not send encryption key: {e}")
                            
                            reg_thread = threading.Thread(target=_do_registration, daemon=True)
                            reg_thread.start()
                            
                            return data_response
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

                    # Prepare response FIRST before registration (to avoid blocking)
                    resp_msg = f"STORED:{file_name}"
                    data_response = self._create_data_response(file_name, resp_msg)

                    # Run registration in background thread to avoid blocking the response
                    import threading
                    stored_path_for_reg = storage_resp.metadata.file_path if storage_resp.metadata and hasattr(storage_resp.metadata, 'file_path') else None
                    # Get encryption key from storage_info (if file was encrypted)
                    encryption_key = storage_resp.storage_info.get('encryption_key') if storage_resp.storage_info else None
                    
                    def _do_registration():
                        # Notify auth server to create ACL (via gateway/router)
                        if uploader:
                            try:
                                self._notify_auth_server_ownership(file_name, uploader)
                            except Exception as e:
                                print(f"[{self.node_name}] Warning: could not notify ownership: {e}")
                        # Register file location with server (via gateway/router)
                        try:
                            self._register_location(file_name, stored_path_for_reg, owner=uploader)
                        except Exception as e:
                            print(f"[{self.node_name}] Warning: could not register location: {e}")
                        # Send encryption key to server for secure storage
                        if encryption_key:
                            try:
                                self._send_encryption_key(file_name, encryption_key, uploader or 'system')
                            except Exception as e:
                                print(f"[{self.node_name}] Warning: could not send encryption key: {e}")

                    reg_thread = threading.Thread(target=_do_registration, daemon=True)
                    reg_thread.start()

                    # RAID 1: Replicate to ALL peer nodes (only if not already a mirror copy)
                    print(f"[{self.node_name}] RAID check: level={self.raid_level}, is_mirror={is_mirror_copy}, peers={len(self.raid_peers) if self.raid_peers else 0}")
                    if self.raid_level == 1 and not is_mirror_copy and self.raid_peers:
                        print(f"[{self.node_name}] RAID 1: Starting replication for {file_name}")
                        self._replicate_to_peers(file_name, content_bytes, uploader)
                    elif self.raid_level == 1 and is_mirror_copy:
                        print(f"[{self.node_name}] RAID 1: Skipping replication (this is a mirror copy)")
                    elif self.raid_level == 1 and not self.raid_peers:
                        print(f"[{self.node_name}] RAID 1: No peers found for replication!")

                    return data_response
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

        # Check for RAID 5/6 parity request
        # RAID 5: :parity[N]
        # RAID 6: :parity_p[N] or :parity_q[N]
        if ':parity' in file_name:
            import re
            parity_match = re.search(r':parity(_[pq])?\[(\d+)\]$', file_name)
            if parity_match:
                parity_type = parity_match.group(1) or ''  # '_p', '_q', or ''
                parity_idx = int(parity_match.group(2))
                base_name = file_name[:file_name.index(':parity')]
                
                parity_label = f"P" if parity_type == '_p' else ('Q' if parity_type == '_q' else 'XOR')
                print(f"[{self.node_name}] RAID 5/6: {parity_label} parity request idx={parity_idx} for {base_name}")
                
                # Try to read parity from parity/ directory
                safe_name = base_name.replace('/', '_')
                parity_path = os.path.join(self.storage_path, 'parity', f"{safe_name}_parity{parity_type}_{parity_idx}.bin")
                sizes_path = os.path.join(self.storage_path, 'parity', f"{safe_name}_parity{parity_type}_{parity_idx}_sizes.txt")
                
                if os.path.exists(parity_path):
                    with open(parity_path, 'rb') as f:
                        parity_data = f.read()
                    
                    # Check for sizes metadata
                    sizes_str = ""
                    if os.path.exists(sizes_path):
                        with open(sizes_path, 'r') as f:
                            sizes_str = f.read().strip()
                        print(f"[{self.node_name}] RAID 5/6: Found sizes metadata: {sizes_str}")
                    
                    print(f"[{self.node_name}] ✓ RAID 5/6: Found {parity_label} parity {parity_idx} ({len(parity_data)} bytes)")
                    
                    # Include sizes in response name so router can parse it
                    resp_name = file_name
                    if sizes_str:
                        resp_name = f"{base_name}:parity{parity_type}[{parity_idx}]:sizes[{sizes_str}]"
                    
                    pkt = DataPacket(name=resp_name, data_payload=parity_data, data_length=len(parity_data))
                    return pkt.to_json()
                else:
                    print(f"[{self.node_name}] ✗ RAID 5/6: {parity_label} parity {parity_idx} not found at {parity_path}")
                    return self._create_error_response(f"Parity not found: {file_name}")

        # Check for RAID 0 stripe request (e.g., /file:stripe[0/2])
        stripe_match = None
        if ':stripe[' in file_name:
            import re
            stripe_match = re.search(r':stripe\[(\d+)/(\d+)\]$', file_name)
            if stripe_match:
                stripe_idx = int(stripe_match.group(1))
                total_stripes = int(stripe_match.group(2))
                base_name = file_name[:file_name.index(':stripe[')]
                
                print(f"[{self.node_name}] RAID 0: Stripe request idx={stripe_idx}, total={total_stripes}")
                print(f"[{self.node_name}] RAID 0: Base name: {base_name}")
                
                # Try to retrieve the stripe file
                stripe_response = self.storage_module.retrieve_file(file_name)
                
                if stripe_response and stripe_response.success:
                    stripe_data = stripe_response.content
                    print(f"[{self.node_name}] ✓ RAID 0: Found stripe {stripe_idx} ({len(stripe_data)} bytes)")
                    
                    pkt = DataPacket(name=file_name, data_payload=stripe_data, data_length=len(stripe_data))
                    return pkt.to_json()
                else:
                    print(f"[{self.node_name}] ✗ RAID 0: Stripe {stripe_idx} not found")
                    return self._create_error_response(f"Stripe not found: {file_name}")

        # If the Interest explicitly requests a fragment (e.g. /file:[i/total]),
        # serve that specific fragment synchronously. This enables pull-based
        # fragment retrieval by clients and avoids relying on async fragment
        # delivery which can be lost in some network setups.
        from common import parse_fragment_notation, MAX_UDP_FRAGMENT_SIZE
        frag_req = parse_fragment_notation(interest.name)
        if frag_req and frag_req.get('is_fragment'):
            base_name = frag_req['base_name']
            try:
                idx = int(frag_req['index'])
            except Exception:
                idx = 1
            
            # For RAID 0, preserve the total from the original request
            # Each node only stores a subset, but the client knows the real total
            try:
                request_total = int(frag_req['total'])
            except Exception:
                request_total = None

            # Use efficient retrieve_fragment() instead of loading entire file
            # This is MUCH faster for large files with many fragments
            frag_response = self.storage_module.retrieve_fragment(base_name, idx)
            if not frag_response or not frag_response.success:
                # Fragment not found - return error immediately
                error_msg = frag_response.error if frag_response else "Retrieve failed"
                print(f"[{self.node_name}] Fragment request failed: {error_msg}")
                return self._create_error_response(f"File not found: {base_name}")
            
            chunk = frag_response.content
            if chunk is None:
                print(f"[{self.node_name}] Fragment request: content is None for {base_name}:[{idx}]")
                return self._create_error_response(f"Fragment content is empty or corrupted: {base_name}")
            
            # Use total from request if available (critical for RAID 0 where each node has subset)
            # Fall back to storage info only if request didn't specify total
            if request_total:
                total = request_total
            else:
                total = frag_response.storage_info.get('total_fragments', 1) if frag_response.storage_info else 1
            
            frag_name = f"{base_name}:[{idx}/{total}]"
            pkt = DataPacket(name=frag_name, data_payload=chunk, data_length=len(chunk))
            return pkt.to_json()

        # Try Storage Module first (RAID-processed files)
        # First, check if file has stored fragment info - use that for consistent fragment counts
        frag_info = self.storage_module.get_fragment_info(file_name)
        
        if frag_info:
            # File was stored as fragments - use stored fragment info for consistency
            # This ensures first response and subsequent fragment requests use same total
            total = frag_info['total_fragments']
            print(f"[{self.node_name}] ✓ File has {total} stored fragments")
            
            # Use efficient fragment retrieval for first fragment
            frag_response = self.storage_module.retrieve_fragment(file_name, 1)
            if frag_response and frag_response.success:
                self.stats["files_retrieved"] += 1
                chunk = frag_response.content
                
                print(f"[{self.node_name}] ✓ Retrieved from RAID {self.raid_level} storage")
                print(f"[{self.node_name}] Total size: {frag_info.get('total_size', 'unknown')} bytes")
                print(f"[{self.node_name}] 📦 Storage Node: {self.node_name} (RAID {self.raid_level})")
                print(f"[{self.node_name}] Large file: {total} fragments")
                print(f"[{self.node_name}] Returning first fragment, client will pull remaining")
                
                frag_name = f"{file_name}:[1/{total}]"
                pkt = DataPacket(name=frag_name, data_payload=chunk, data_length=len(chunk))
                return pkt.to_json()
        
        # No stored fragments - retrieve full file and fragment on-the-fly if needed
        storage_response = self.storage_module.retrieve_file(file_name)

        if storage_response and storage_response.success:
            self.stats["files_retrieved"] += 1

            content_bytes = storage_response.content
            if content_bytes is None:
                print(f"[{self.node_name}] Content is None for {file_name} despite success=True")
                return self._create_error_response(f"File content is empty or corrupted: {file_name}")
            total_size = len(content_bytes)

            print(f"[{self.node_name}] ✓ Retrieved from RAID {self.raid_level} storage")
            print(f"[{self.node_name}] Size: {total_size} bytes")
            print(f"[{self.node_name}] 📦 Storage Node: {self.node_name} (RAID {self.raid_level})")

            # Decide whether to fragment the response
            # Use consistent fragment size from common.py (UDP-safe 8KB max)
            from common import MAX_UDP_FRAGMENT_SIZE
            frag_size = MAX_UDP_FRAGMENT_SIZE
            if total_size > frag_size:
                # Large file: return ONLY the first fragment with fragment info
                # Client will use PULL-based approach to request remaining fragments
                # This avoids the "fire hose" problem where push overwhelms buffers
                fragments = [content_bytes[i:i + frag_size] for i in range(0, total_size, frag_size)]
                total = len(fragments)

                print(f"[{self.node_name}] Large file: {total} fragments ({frag_size//1024}KB each)")
                print(f"[{self.node_name}] Returning first fragment, client will pull remaining")

                # Return only the first fragment - client will request others by name
                frag_name = f"{file_name}:[1/{total}]"
                pkt = DataPacket(name=frag_name, data_payload=fragments[0], data_length=len(fragments[0]))
                return pkt.to_json()

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
            # Use consistent fragment size from common.py (UDP-safe 8KB max)
            from common import MAX_UDP_FRAGMENT_SIZE
            frag_size = MAX_UDP_FRAGMENT_SIZE

            if total_size > frag_size:
                # Large file: return ONLY the first fragment with fragment info
                # Client will use PULL-based approach to request remaining fragments
                fragments = [content_bytes[i:i + frag_size] for i in range(0, total_size, frag_size)]
                total = len(fragments)
                print(f"[{self.node_name}] Large file (memory): {total} fragments ({frag_size//1024}KB each)")
                print(f"[{self.node_name}] Returning first fragment, client will pull remaining")

                # Return only the first fragment - client will request others by name
                frag_name = f"{file_name}:[1/{total}]"
                pkt = DataPacket(name=frag_name, data_payload=fragments[0], data_length=len(fragments[0]))
                return pkt.to_json()

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

            # Prepare response content FIRST
            response_content = f"""RAID {self.raid_level} Write Confirmation:
File: {file_name}
Status: Successfully stored with RAID {self.raid_level}
Original Size: {storage_response.metadata.original_size} bytes
Stored Size: {storage_response.metadata.stored_size} bytes
Storage Node: {self.node_name}
User: {interest.user_id}"""
            
            data_response = self._create_data_response(file_name, response_content)

            # Run registration in background thread to avoid blocking the response
            import threading
            stored_path_for_reg = storage_response.metadata.file_path if storage_response.metadata and hasattr(storage_response.metadata, 'file_path') else None
            user_id = interest.user_id
            def _do_registration():
                try:
                    self._notify_auth_server_ownership(file_name, user_id)
                except Exception:
                    pass
                try:
                    self._register_location(file_name, stored_path_for_reg)
                except Exception as e:
                    print(f"[{self.node_name}] Warning: could not register location with server: {e}")
            
            reg_thread = threading.Thread(target=_do_registration, daemon=True)
            reg_thread.start()
            
            return data_response
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
            
            # Create safe name patterns for fragment/parity matching
            # Fragments use basename: GPUZ6.exe_[1_100]
            # Parity uses full path: _dlsu_storage_raid6_GPUZ6.exe_parity_0.bin
            base_name = os.path.basename(file_name) if '/' in file_name else file_name
            safe_base = base_name.replace('/', '_').replace('\\', '_').replace(':', '_')
            safe_full = file_name.replace('/', '_').replace('\\', '_').replace(':', '_')
            
            fragments_deleted = 0
            parity_deleted = 0
            metadata_deleted = 0
            files_deleted = 0
            
            # Remove matching fragments (use basename pattern)
            fragments_dir = os.path.join(self.storage_path, 'fragments')
            if os.path.exists(fragments_dir):
                for f in os.listdir(fragments_dir):
                    # Fragments are named like: GPUZ6.exe_[1_100]
                    if f.startswith(safe_base) or safe_base in f:
                        try:
                            fpath = os.path.join(fragments_dir, f)
                            if os.path.isfile(fpath):
                                os.remove(fpath)
                                fragments_deleted += 1
                        except Exception as e:
                            print(f"[{self.node_name}]   Warning: Could not delete fragment {f}: {e}")
            
            # Remove matching parity files (use full path pattern for RAID 5/6)
            parity_dir = os.path.join(self.storage_path, 'parity')
            if os.path.exists(parity_dir):
                for f in os.listdir(parity_dir):
                    # Parity files named like: _dlsu_storage_raid6_GPUZ6.exe_parity_0.bin
                    # or _dlsu_storage_raid6_GPUZ6.exe_parity_p_0.bin for RAID 6
                    if safe_full in f or safe_base in f:
                        try:
                            fpath = os.path.join(parity_dir, f)
                            if os.path.isfile(fpath):
                                os.remove(fpath)
                                parity_deleted += 1
                        except Exception as e:
                            print(f"[{self.node_name}]   Warning: Could not delete parity {f}: {e}")
            
            # Remove matching files in files directory
            files_dir = os.path.join(self.storage_path, 'files')
            if os.path.exists(files_dir):
                for f in os.listdir(files_dir):
                    if f.startswith(safe_base) or safe_base in f or f == safe_full:
                        try:
                            fpath = os.path.join(files_dir, f)
                            if os.path.isfile(fpath):
                                os.remove(fpath)
                                files_deleted += 1
                        except Exception as e:
                            print(f"[{self.node_name}]   Warning: Could not delete file {f}: {e}")
            
            # Remove metadata files (check both basename and full path patterns)
            metadata_dir = os.path.join(self.storage_path, 'metadata')
            if os.path.exists(metadata_dir):
                for pattern in [safe_base, safe_full]:
                    for f in os.listdir(metadata_dir):
                        if f.startswith(pattern) or pattern in f:
                            try:
                                fpath = os.path.join(metadata_dir, f)
                                if os.path.isfile(fpath):
                                    os.remove(fpath)
                                    metadata_deleted += 1
                            except Exception:
                                pass
            
            print(f"[{self.node_name}] ✓ File deleted: {file_name}")
            if files_deleted > 0:
                print(f"[{self.node_name}]   - Main files removed: {files_deleted}")
            if fragments_deleted > 0:
                print(f"[{self.node_name}]   - Fragments removed: {fragments_deleted}")
            if parity_deleted > 0:
                print(f"[{self.node_name}]   - Parity files removed: {parity_deleted}")
            if metadata_deleted > 0:
                print(f"[{self.node_name}]   - Metadata files removed: {metadata_deleted}")
            
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
            'raid_peers': [p['name'] for p in self.raid_peers] if self.raid_peers else [],
            'raid_operations': self.storage_module.stats.get('raid_operations', 0)
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
            if _USE_NETWORK_CONFIG:
                srv_host, srv_port = get_server_address()
            else:
                srv_host, srv_port = DEFAULT_HOST, 7001
            resp = self.comm_module.send_packet_sync(srv_host, srv_port, json.dumps(clear_payload))
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

    def _replicate_to_peers(self, file_name: str, content_bytes: bytes, uploader: str = None):
        """RAID 1: Replicate data to ALL peer nodes in the RAID group.
        
        This directly calls the peer's storage module via a simple replication protocol.
        Peers store the data but do NOT re-replicate (is_mirror flag prevents loops).
        """
        print(f"[{self.node_name}] _replicate_to_peers called: file={file_name}, bytes={len(content_bytes)}")
        
        if not self.raid_peers:
            print(f"[{self.node_name}] No RAID peers, skipping replication")
            return  # No peers configured
        
        if self.raid_level != 1:
            print(f"[{self.node_name}] RAID level is {self.raid_level}, not 1 - skipping")
            return  # Only RAID 1 does full mirroring (RAID 5/6 use parity instead)
        
        print(f"[{self.node_name}] RAID 1: Replicating to {len(self.raid_peers)} peer(s): {[p['name'] for p in self.raid_peers]}")
        
        import threading
        
        def _replicate_to_peer(peer):
            """Replicate to a single peer in background thread"""
            try:
                import socket
                import json
                import base64
                
                peer_host = peer['host']
                peer_port = peer['port']
                peer_name = peer['name']
                
                # Create a simple replication message (not Interest/Data)
                replication_msg = {
                    'type': 'RAID_REPLICATE',
                    'file_name': file_name,
                    'uploader': uploader or 'mirror',
                    'data_b64': base64.b64encode(content_bytes).decode('utf-8'),
                    'source_node': self.node_name,
                    'is_mirror': True  # Flag so peer doesn't re-replicate
                }
                
                # Send directly to peer node via UDP
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(10.0)
                try:
                    msg_bytes = json.dumps(replication_msg).encode('utf-8')
                    sock.sendto(msg_bytes, (peer_host, peer_port))
                    
                    # Wait for acknowledgment
                    try:
                        resp, _ = sock.recvfrom(65536)
                        resp_str = resp.decode('utf-8', errors='ignore')
                        if 'success' in resp_str.lower() or 'stored' in resp_str.lower():
                            print(f"[{self.node_name}] RAID 1: ✓ Replicated to {peer_name}")
                            self.storage_module.stats["raid_operations"] += 1
                        else:
                            print(f"[{self.node_name}] RAID 1: ⚠ {peer_name} response: {resp_str[:100]}")
                    except socket.timeout:
                        print(f"[{self.node_name}] RAID 1: ⚠ {peer_name} timeout")
                        
                finally:
                    sock.close()
                    
            except Exception as e:
                print(f"[{self.node_name}] RAID 1: ✗ Replication to {peer.get('name', 'unknown')} failed: {e}")
        
        # Replicate to all peers in parallel
        threads = []
        for peer in self.raid_peers:
            t = threading.Thread(target=_replicate_to_peer, args=(peer,), daemon=True)
            t.start()
            threads.append(t)
        
        # Wait for all replications to complete (with timeout)
        for t in threads:
            t.join(timeout=15.0)
    
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
        
        # Register this storage node with the server
        try:
            self._register_node_with_server()
        except Exception as e:
            print(f"[{self.node_name}] Warning: could not register with server: {e}")
        
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
    
    def _register_node_with_server(self):
        """Register this storage node with the server so it can be assigned files.
        Sends directly to server (bypassing routers) since this is node registration."""
        import json
        import socket
        
        # Send registration directly to server (not via router, as this is infrastructure setup)
        payload = {
            "action": "register_node",
            "node_name": self.node_name,
            "host": self.host,
            "port": self.port,
            "raid_level": self.raid_level
        }
        
        if _USE_NETWORK_CONFIG:
            server_host, server_port = get_server_address()
        else:
            server_host, server_port = DEFAULT_HOST, 7001
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5.0)
            sock.sendto(json.dumps(payload).encode('utf-8'), (server_host, server_port))
            resp, _ = sock.recvfrom(65536)
            sock.close()
            print(f"[{self.node_name}] Registered with server: {resp.decode('utf-8', errors='ignore')}")
        except Exception as e:
            print(f"[{self.node_name}] Warning: Could not register with server: {e}")
    
    def _notify_auth_server_ownership(self, file_name: str, owner: str, server_host: Optional[str] = None, server_port: Optional[int] = None):
        """Notify authentication server that a file was uploaded to create ACL.
        Sends as proper Interest packet via gateway (router) following FIB topology."""
        import json
        from common import InterestPacket
        
        # Strip fragment notation to register only the base filename
        base_name = file_name.split(':[')[0] if ':[' in file_name else file_name
        
        # Create an Interest packet for the server with REGISTER_FILE operation
        # The resource to register and owner are embedded in the packet
        interest = InterestPacket(
            name='/dlsu/server/register_file',
            operation='REGISTER_FILE',
            user_id=owner
        )
        # Add custom fields for the registration
        interest.resource = base_name
        interest.owner = owner
        
        # Send via gateway (router) so the message follows topology
        target_host = server_host or self.gateway_host
        target_port = server_port or self.gateway_port
        try:
            resp = self.comm_module.send_packet_sync(target_host, target_port, interest.to_json())
            if resp:
                print(f"[{self.node_name}] ACL created for {base_name} (owner: {owner}) via {target_host}:{target_port}")
        except Exception as e:
            print(f"[{self.node_name}] Warning: Could not register file ownership via {target_host}:{target_port}: {e}")

    def _send_encryption_key(self, file_name: str, encryption_key: str, owner: str, server_host: Optional[str] = None, server_port: Optional[int] = None):
        """Send XOR encryption key to auth server for secure storage.
        The key is stored in the server's DB linked to the file, not kept locally.
        This ensures separation of data (on storage) from keys (on server)."""
        from common import InterestPacket
        
        base_name = file_name.split(':[')[0] if ':[' in file_name else file_name
        
        # Create an Interest packet for the server with STORE_KEY operation
        interest = InterestPacket(
            name='/dlsu/server/store_key',
            operation='STORE_KEY',
            user_id=owner
        )
        # Add custom fields for the key storage
        interest.resource = base_name
        interest.encryption_key = encryption_key
        
        # Send via gateway (router) so the message follows topology
        target_host = server_host or self.gateway_host
        target_port = server_port or self.gateway_port
        try:
            resp = self.comm_module.send_packet_sync(target_host, target_port, interest.to_json(), timeout=5.0)
            if resp:
                print(f"[{self.node_name}] Encryption key sent to server for {base_name}")
        except Exception as e:
            print(f"[{self.node_name}] Warning: Could not send encryption key to server: {e}")

    def _register_location(self, file_name: str, stored_path: Optional[str] = None, server_host: Optional[str] = None, server_port: Optional[int] = None, owner: Optional[str] = None):
        """Notify server to persist mapping of file -> this storage node (location).
        Sends as proper Interest packet via gateway (router) following FIB topology."""
        import json
        from common import InterestPacket
        
        base_name = file_name.split(':[')[0] if ':[' in file_name else file_name
        
        # Create an Interest packet for the server with REGISTER_LOCATION operation
        interest = InterestPacket(
            name='/dlsu/server/register_location',
            operation='REGISTER_LOCATION',
            user_id=owner or 'system'
        )
        # Add custom fields for the location registration
        interest.resource = base_name
        interest.node_name = self.node_name
        interest.storage_host = self.host
        interest.storage_port = self.port
        interest.stored_path = stored_path
        if owner:
            interest.owner = owner
        
        # Send via gateway (router) so the message follows topology
        target_host = server_host or self.gateway_host
        target_port = server_port or self.gateway_port
        print(f"[{self.node_name}] >>> Sending REGISTER_LOCATION Interest to {target_host}:{target_port} for {base_name}")
        try:
            resp = self.comm_module.send_packet_sync(target_host, target_port, interest.to_json())
            if resp:
                print(f"[{self.node_name}] Registered location for {base_name} via {target_host}:{target_port}")
                print(f"[{self.node_name}] <<< Server response: {resp[:200] if len(resp) > 200 else resp}")
        except Exception as e:
            print(f"[{self.node_name}] Warning: Could not register file location via {target_host}:{target_port}: {e}")

    def _sync_local_files_on_startup(self, server_host: str = None, server_port: int = None):
        """Scan on-disk metadata files and re-register each local file with the auth server/DB.
        Also rehydrate in-memory self.stored_files so interactive commands work after restart.
        """
        # Use network config defaults if not specified
        if server_host is None or server_port is None:
            if _USE_NETWORK_CONFIG:
                default_srv_host, default_srv_port = get_server_address()
            else:
                default_srv_host, default_srv_port = DEFAULT_HOST, 7001
            server_host = server_host or default_srv_host
            server_port = server_port or default_srv_port
        
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