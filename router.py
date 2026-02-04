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
from common import ContentStore, InterestPacket, PendingInterestTable
from fib_config import get_fib_config, get_port_for_router, get_host_for_router

# Import network configuration
try:
    from network_config import (
        get_default_router_address, get_server_address, get_all_storage_addresses,
        STORAGE_CONFIG, DEFAULT_HOST
    )
    _USE_NETWORK_CONFIG = True
except ImportError:
    _USE_NETWORK_CONFIG = False
    DEFAULT_HOST = '127.0.0.1'

# Import GUI if available
try:
    from debug_gui import DebugGUI
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False
    print("Warning: debug_gui.py not found. Running without GUI.")


class Router:
    def __init__(self, router_id: str, host: str = None, port: int = None, use_gui: bool = True):
        self.router_id = router_id
        self.node_name = f"Router-{router_id}"
        
        # Auto-determine host and port based on router ID if not specified
        if host is None:
            host = get_host_for_router(router_id)
        if port is None:
            port = get_port_for_router(router_id)
        
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
        # Attach PacketLogger if available
        try:
            from common import PacketLogger
            self.logger = PacketLogger(self.node_name)
            try:
                self.comm_module.set_logger(self.logger)
            except Exception:
                pass
        except Exception:
            self.logger = None

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
        # PIT entries: name -> { 'faces': set(host:port), 'timestamp': float, 'forwarded': bool }
        self.pit = {}
        
        # Round-robin storage node selection (for R2)
        if _USE_NETWORK_CONFIG:
            self._storage_nodes = get_all_storage_addresses()
        else:
            self._storage_nodes = [
                ('127.0.0.1', 9001, 0),  # ST1 - RAID 0
                ('127.0.0.1', 9002, 1),  # ST2 - RAID 1
                ('127.0.0.1', 9003, 5),  # ST3 - RAID 5
                ('127.0.0.1', 9004, 6),  # ST4 - RAID 6
            ]
        self._storage_index = 0
        self._storage_lock = threading.Lock()
        
        # RAID 5 stripe buffer for parity calculation
        # Format: {base_name: {stripe_set: {frag_index: raw_bytes}}}
        self._raid5_stripe_buffer = {}
        self._raid5_buffer_lock = threading.Lock()
        
        # Encryption key cache for RAID 5/6 parity encryption
        # Format: {base_name: encryption_key_hex}
        self._raid_encryption_keys = {}
        self._raid_encryption_lock = threading.Lock()
        
        # Read token cache for R2 (multi-use tokens for fragment access)
        # Format: {token: {user_id, resource, expires_at, access_count}}
        self._read_token_cache = {}
        self._read_token_lock = threading.Lock()
        
        # Set up module interfaces
        self._setup_module_interfaces()
        
        # Add default routes for hub-and-spoke topology
        self._setup_hub_spoke_routes()
        
        self._log(f"Router initialized successfully", "data")
        self._setup_router_fib()

    def _setup_router_fib(self):
        """Setup FIB based on router identity"""
        self._log("Loading router-specific FIB configuration...")
        
        # Get FIB config for this router
        fib_routes = get_fib_config(self.router_id)
        
        if not fib_routes:
            self._log(f"⚠️ No FIB config found for {self.router_id}", "error")
            return
        
        # Load routes into routing module
        self.routing_module.load_fib_from_config(fib_routes)
        
        # Display FIB
        self._log_control(f"=== {self.router_id} FIB Table ===")
        self.routing_module.show_fib()
    
    def _init_gui(self):
        """Initialize GUI in separate thread"""
        if self.gui:
            self.gui.initialize()
            self.gui.run()
    
    def _select_storage_node(self, raid_preference: int = None) -> str:
        """Select a storage node for WRITE operations.
        
        Args:
            raid_preference: Optional RAID level (0, 1, 5, 6). If None, uses round-robin.
            
        Returns:
            'host:port' string for the selected storage node.
        """
        if raid_preference is not None:
            # Find node with matching RAID level
            for host, port, raid in self._storage_nodes:
                if raid == raid_preference:
                    self._log_debug(f"Selected storage node {host}:{port} (RAID {raid}) by preference", "routing")
                    return f"{host}:{port}"
            # Fall back to round-robin if RAID not found
            self._log_debug(f"RAID {raid_preference} not found, using round-robin", "routing")
        
        # Round-robin selection
        with self._storage_lock:
            node = self._storage_nodes[self._storage_index]
            self._storage_index = (self._storage_index + 1) % len(self._storage_nodes)
        
        host, port, raid = node
        self._log_debug(f"Selected storage node {host}:{port} (RAID {raid}) via round-robin", "routing")
        return f"{host}:{port}"

    def _parse_raid_preference(self, interest) -> int:
        """Extract RAID preference from Interest packet if present.
        
        Checks for raid_level attribute or parses from name like /dlsu/storage/raid5/file.txt
        """
        # Check for explicit raid_level attribute
        if hasattr(interest, 'raid_level') and interest.raid_level is not None:
            return int(interest.raid_level)
        
        # Parse from name: /dlsu/storage/raid<N>/...
        name = interest.name or ''
        if '/raid0' in name.lower():
            return 0
        elif '/raid1' in name.lower():
            return 1
        elif '/raid5' in name.lower():
            return 5
        elif '/raid6' in name.lower():
            return 6
        
        return None  # No preference
    
    def _validate_read_token(self, token: str, resource_name: str) -> dict:
        """Validate a read token locally (R2 only).
        
        Returns dict with 'valid': bool, 'user_id': str if valid.
        Read tokens are multi-use and not consumed on validation.
        """
        if not token:
            return {'valid': False, 'reason': 'No token provided'}
        
        # Strip fragment notation for resource comparison
        base_resource = resource_name.split(':[')[0] if ':[' in resource_name else resource_name
        
        with self._read_token_lock:
            token_info = self._read_token_cache.get(token)
            
            if not token_info:
                return {'valid': False, 'reason': 'Token not in cache'}
            
            # Check expiry
            import time
            if time.time() > token_info['expires_at']:
                # Clean up expired token
                del self._read_token_cache[token]
                return {'valid': False, 'reason': 'Token expired'}
            
            # Check resource matches
            if token_info['resource'] != base_resource:
                return {'valid': False, 'reason': f'Token not valid for {base_resource}'}
            
            # Token is valid - increment access count
            token_info['access_count'] += 1
            
            return {'valid': True, 'user_id': token_info['user_id']}
    
    def _cache_read_token(self, token: str, user_id: str, resource_name: str, ttl: int = 3600):
        """Cache a read token for local validation (R2 only)."""
        base_resource = resource_name.split(':[')[0] if ':[' in resource_name else resource_name
        
        import time
        with self._read_token_lock:
            self._read_token_cache[token] = {
                'user_id': user_id,
                'resource': base_resource,
                'expires_at': time.time() + ttl,
                'access_count': 0
            }
        self._log_debug(f"[R2 TOKEN] Cached read token for {user_id} -> {base_resource}", "permission")
    
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
        if _USE_NETWORK_CONFIG:
            server_host, server_port = get_server_address()
            storage_nodes = get_all_storage_addresses()
            default_storage = storage_nodes[0] if storage_nodes else (DEFAULT_HOST, 9001, 0)
            self.routing_module.add_route("/server", f"{server_host}:{server_port}", "eth0", 1)
            self.routing_module.add_route("/storage", f"{default_storage[0]}:{default_storage[1]}", "eth0", 1)
            self.routing_module.add_route("/admin", f"{server_host}:{server_port}", "eth0", 1)
        else:
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
        
        self._log_debug(f"[PROCESS] Received {packet_type} packet from {source} (object: {getattr(packet_obj, 'name', str(packet_obj))})", "process")
        if packet_type == "interest":
            result = self._route_interest_packet(packet_obj, source)
            self._log_debug(f"[PROCESS] _route_interest_packet returned: {repr(result)[:200]}", "process")
            return result
        elif packet_type == "data":
            result = self._route_data_packet(packet_obj, source)
            self._log_debug(f"[PROCESS] _route_data_packet returned: {repr(result)[:200]}", "process")
            return result
        else:
            self._log_debug(f"❌ Unknown packet type: {packet_type}", "error")
            return None
    
    def _route_interest_packet(self, interest: 'InterestPacket', source: str):
        """Route Interest packet through the network"""
        # Auth Interests should NOT be cached (each is for a different resource/operation)
        is_auth_interest = interest.name.startswith('/dlsu/server/auth') or interest.operation.upper() == 'PERMISSION'
        is_storage_interest = interest.name.startswith('/dlsu/storage') or interest.name.startswith('/dlsu/test')
        
        # ==========================================================================
        # R1 (Edge Router): Explicit handling for all storage operations
        # R1 forwards to R2, which handles auth and storage access
        # Caching: R1 caches READ responses AFTER auth is confirmed by R2
        # NOTE: For caching, use FULL name (with fragment notation) to cache each fragment separately
        #       For invalidation (WRITE/DELETE), use STRIPPED name to invalidate all fragments of a file
        # ==========================================================================
        if self.router_id == "R1" and is_storage_interest and not is_auth_interest:
            operation = (interest.operation or 'READ').upper()
            # For cache invalidation (WRITE/DELETE), strip fragment notation to invalidate all fragments
            invalidation_key = self._strip_fragment_notation(interest.name)
            # For cache lookup/storage (READ), use full name to cache each fragment separately
            cache_key = interest.name
            
            if operation == 'WRITE_DATA':
                # WRITE_DATA: Forward file data to R2 -> Storage
                self._log_control(f"[R1] WRITE_DATA received: {interest.name}")
                
                # Invalidate cache for ALL fragments of this file (use stripped name)
                if self.processing_module.content_store.remove(invalidation_key):
                    self._log_control(f"[R1 CACHE] Invalidated (WRITE_DATA): {invalidation_key}")
                # Also try to remove by prefix for fragment entries
                self._invalidate_cache_by_prefix(invalidation_key)
                
                # Forward to R2 via FIB lookup
                r2_route = self.routing_module.lookup_route(interest.name)
                if r2_route:
                    next_hop = r2_route.next_hop if hasattr(r2_route, 'next_hop') else str(r2_route)
                    self._log_control(f"[R1] Forwarding WRITE_DATA to R2 at {next_hop}")
                    
                    response = self._forward_to_next_hop(interest, r2_route, timeout=30.0)
                    if response:
                        self._log_control(f"[R1] WRITE_DATA response received from R2")
                        return response
                    else:
                        self._log_control(f"[R1] WRITE_DATA timeout from R2")
                        return self._create_error_response("R1: Timeout forwarding WRITE_DATA to R2")
                else:
                    self._log_control(f"[R1] No FIB route found for {interest.name}")
                    return self._create_error_response("R1: No route to R2 for WRITE_DATA")
            
            elif operation == 'DELETE':
                # DELETE: Forward to R2 -> Server/Storage
                self._log_control(f"[R1] DELETE received: {interest.name}")
                
                # Invalidate cache for ALL fragments of this file
                if self.processing_module.content_store.remove(invalidation_key):
                    self._log_control(f"[R1 CACHE] Invalidated (DELETE): {invalidation_key}")
                # Also try to remove by prefix for fragment entries
                self._invalidate_cache_by_prefix(invalidation_key)
                
                r2_route = self.routing_module.lookup_route(interest.name)
                if r2_route:
                    next_hop = r2_route.next_hop if hasattr(r2_route, 'next_hop') else str(r2_route)
                    self._log_control(f"[R1] Forwarding DELETE to R2 at {next_hop}")
                    response = self._forward_to_next_hop(interest, r2_route, timeout=15.0)
                    if response:
                        return response
                    else:
                        return self._create_error_response("R1: Timeout forwarding DELETE to R2")
                else:
                    return self._create_error_response("R1: No route to R2 for DELETE")
            
            elif operation == 'READ':
                # READ: First check cache, but STILL need auth from R2
                # If cached, send auth-only request to R2, then serve from cache
                # If not cached, forward full READ to R2
                self._log_control(f"━━━ [R1] READ REQUEST ━━━")
                self._log_control(f"    File: {interest.name}")
                self._log_control(f"    User: {interest.user_id}")
                
                cached_data = self.processing_module.content_store.get(cache_key)
                
                r2_route = self.routing_module.lookup_route(interest.name)
                if not r2_route:
                    return self._create_error_response("R1: No route to R2 for READ")
                
                next_hop = r2_route.next_hop if hasattr(r2_route, 'next_hop') else str(r2_route)
                
                if cached_data:
                    # Have cache - but still need auth check
                    self._log_control(f"    📦 CACHE EXISTS - Checking auth before serving...")
                    
                    # Create auth-check Interest to forward to R2
                    from common import InterestPacket as IP
                    auth_interest = IP(
                        name='/dlsu/server/auth',
                        user_id=interest.user_id,
                        operation='READ',
                        auth_key=interest.auth_key,
                        target=interest.name
                    )
                    
                    auth_response = self._forward_to_next_hop(auth_interest, r2_route, timeout=10.0)
                    if auth_response:
                        try:
                            import json as _json
                            from common import DataPacket
                            auth_dp = DataPacket.from_json(auth_response)
                            payload = auth_dp.data_payload.decode('utf-8', errors='ignore')
                            parsed = _json.loads(payload)
                            
                            if parsed.get('authorized'):
                                self._log_control(f"    ✓ Auth confirmed by Server")
                                self._log_control(f"━━━ [R1] RESPONSE: FROM CACHE ━━━")
                                self._log_control(f"    📦 Serving cached data for: {cache_key}")
                                self.stats["cache_hits"] += 1
                                return self._create_data_response(interest.name, cached_data)
                            else:
                                self._log_control(f"    ✗ Auth DENIED for cached content")
                                return self._create_error_response("Permission denied")
                        except Exception as e:
                            self._log_debug(f"[R1] Auth response parse error: {e}", "error")
                            # Fall through to full READ
                    
                    # Auth failed or error - try full READ
                    self._log_control(f"    ⚠ Auth check failed, fetching from R2...")
                
                # No cache or auth check failed - forward full READ to R2
                self._log_control(f"    📭 CACHE MISS - Forwarding to R2 at {next_hop}")
                self.stats["cache_misses"] += 1
                
                response = self._forward_to_next_hop(interest, r2_route, timeout=30.0)
                if response:
                    # Cache the response for future requests
                    try:
                        import json as _json
                        import base64
                        if isinstance(response, bytes):
                            response_str = response.decode('utf-8', errors='ignore')
                        else:
                            response_str = response
                        resp_data = _json.loads(response_str)
                        if resp_data.get('type') == 'DATA' and resp_data.get('data_payload'):
                            payload_bytes = base64.b64decode(resp_data['data_payload'])
                            if not payload_bytes.startswith(b'ERROR'):
                                # Use RESPONSE name for caching, not request name
                                # This ensures fragments are cached under their fragment name
                                # e.g., /file:[1/61] not /file (which would corrupt cache)
                                response_name = resp_data.get('name', cache_key)
                                self.processing_module.content_store.put(response_name, payload_bytes)
                                self._log_control(f"━━━ [R1] RESPONSE: FROM R2/STORAGE ━━━")
                                self._log_control(f"    💾 Received data, now caching: {response_name}")
                    except Exception as cache_err:
                        self._log_debug(f"[R1 CACHE] Could not cache: {cache_err}", "error")
                    
                    return response
                else:
                    return self._create_error_response("R1: Timeout forwarding READ to R2")
            
            elif operation == 'WRITE':
                # WRITE (auth request): Forward to R2 for auth check
                self._log_control(f"[R1] WRITE auth received: {interest.name}")
                
                r2_route = self.routing_module.lookup_route(interest.name)
                if r2_route:
                    next_hop = r2_route.next_hop if hasattr(r2_route, 'next_hop') else str(r2_route)
                    self._log_control(f"[R1] Forwarding WRITE auth to R2 at {next_hop}")
                    response = self._forward_to_next_hop(interest, r2_route, timeout=15.0)
                    if response:
                        return response
                    else:
                        return self._create_error_response("R1: Timeout forwarding WRITE auth to R2")
                else:
                    return self._create_error_response("R1: No route to R2 for WRITE auth")

        # For auth Interests, use a unique PIT key that includes target and operation
        # This prevents different auth checks from being treated as duplicates
        if is_auth_interest:
            target = getattr(interest, 'target', None) or ''
            pit_key = f"{interest.name}|{interest.user_id}|{interest.operation}|{target}"
        else:
            pit_key = interest.name
        
        # Clean up stale PIT entries (older than 30 seconds)
        try:
            now = time.time()
            stale_keys = [k for k, v in self.pit.items() if now - v.get('timestamp', 0) > 30]
            for k in stale_keys:
                del self.pit[k]
                self._log_debug(f"[PIT] Cleaned stale entry: {k}", "pit")
        except Exception:
            pass

        # PIT duplicate detection disabled for reliability - each request is processed
        # (Original NDN uses this for aggregation but it causes issues with repeated commands)
        # Just track the source face for response routing
        try:
            if pit_key in self.pit:
                entry = self.pit[pit_key]
                entry['faces'].add(source)
                entry['timestamp'] = time.time()
                # Don't skip - process each request
        except Exception as e:
            self._log_debug(f"[PIT] Error handling PIT entry: {e}", "error")

        # New PIT entry: first arrival -> record and forward according to FIB
        # Also store the operation for cache decisions (only cache READ responses)
        try:
            operation = (interest.operation or '').upper()
            self.pit[pit_key] = {'faces': set([source]), 'timestamp': time.time(), 'forwarded': False, 'operation': operation}
            self._log_debug(f"[PIT] Created entry for {pit_key} from {source} (op={operation})", "pit")
        except Exception as e:
            self._log_debug(f"[PIT] Error creating PIT entry: {e}", "error")
            return self._create_error_response(f"PIT create error: {e}")
        except Exception as e:
            self._log_debug(f"[PIT] Error creating PIT entry: {e}", "error")
            return self._create_error_response(f"PIT create error: {e}")

        # Router-specific behavior
        # For R2: handle permission operations (PERMISSION) and auth checks before forwarding to storage
        if self.router_id == "R2":
            # Check if this is a direct auth check from client (name=/dlsu/server/auth with READ/WRITE operation)
            # These should be forwarded directly to the server, not re-wrapped
            op = interest.operation.upper() if interest.operation else 'NONE'
            self._log_debug(f"R2: checking interest name={interest.name}, operation={op}", "permission")
            if interest.name.startswith('/dlsu/server/auth') and op in ('READ', 'WRITE', 'EXECUTE'):
                server_route = self.routing_module.lookup_route('/dlsu/server')
                if server_route:
                    self._log_debug(f"📤 Forwarding client auth Interest ({op}) to server", "permission")
                    response = self._forward_to_next_hop(interest, server_route)
                    self._log_debug(f"📥 Auth response received: {response is not None}", "permission")
                    
                    # Handle storage assignment for authorized operations
                    if response:
                        try:
                            import json as _json
                            from common import DataPacket
                            auth_dp = DataPacket.from_json(response)
                            payload = auth_dp.data_payload.decode('utf-8', errors='ignore')
                            parsed = _json.loads(payload)
                            
                            if parsed.get('authorized'):
                                # Check if server returned storage location (existing file)
                                if parsed.get('storage_location'):
                                    # Use server-provided location (file exists)
                                    parsed['assigned_storage'] = parsed['storage_location']
                                    self._log_debug(f"Using server-provided storage: {parsed['storage_location']}", "permission")
                                elif op == 'WRITE' and parsed.get('is_new_file', True):
                                    # New file - use round-robin selection OR RAID preference
                                    raid_pref = self._parse_raid_preference(interest)
                                    assigned_hostport = self._select_storage_node(raid_pref)
                                    parsed['assigned_storage'] = assigned_hostport
                                    self._log_debug(f"New file - assigned storage via round-robin: {assigned_hostport}", "permission")
                                
                                augmented_dp = DataPacket(name=auth_dp.name, data_payload=_json.dumps(parsed).encode('utf-8'))
                                return augmented_dp.to_json()
                        except Exception as e:
                            self._log_debug(f"Could not augment auth response: {e}", "error")
                    
                    return response
            
            # Permission/LIST operation handling - includes GRANT, REVOKE, MYFILES, LOCATIONS
            if interest.operation.upper() in ('PERMISSION', 'LIST', 'GRANT', 'REVOKE'):
                # Permission patterns: /dlsu/server/permission/grant:<perm_level>:<resource>:<target>
                name = interest.name
                if name.startswith('/dlsu/server/permission/grant'):
                    # parse grant request - format: grant:<perm_level>:<resource>:<target>
                    try:
                        _, rest = name.split('/dlsu/server/permission/grant', 1)
                        rest = rest.lstrip(':')
                        parts = rest.split(':') if rest else []
                        # parts[0] = perm_level (READ or WRITE)
                        # parts[1] = resource
                        # parts[2] = target_user
                        perm_level = parts[0].upper() if len(parts) > 0 else 'READ'
                        resource = parts[1] if len(parts) > 1 else None
                        target_user = parts[2] if len(parts) > 2 else None
                        payload = {
                            'action': 'grant',
                            'perm_level': perm_level,  # 'READ' or 'WRITE'
                            'resource': resource,
                            'owner': interest.user_id,
                            'target_user': target_user,
                            'password': interest.auth_key
                        }
                        import json as _json
                        server_route = self.routing_module.lookup_route('/dlsu/server')
                        if server_route:
                            # send JSON to server and get response
                            host, port = (server_route.next_hop if hasattr(server_route, 'next_hop') else server_route).split(':')
                            port = int(port)
                            resp = self.comm_module.send_and_wait(_json.dumps(payload), host, port)
                            # build DataPacket response to requester
                            from common import DataPacket
                            resp_content = resp.encode('utf-8') if isinstance(resp, str) and resp else b'OK'
                            dp = DataPacket(name=interest.name, data_payload=resp_content, data_length=len(resp_content))
                            return dp.to_json()
                    except Exception as e:
                        return self._create_error_response(f"Grant failed: {e}")

                elif name.startswith('/dlsu/server/permission/revoke'):
                    # parse revoke request - format: revoke:<mode>:<resource>:<target>
                    # mode = 'ALL' (revoke everything) or 'WRITE' (revoke only write, keep read)
                    try:
                        _, rest = name.split('/dlsu/server/permission/revoke', 1)
                        rest = rest.lstrip(':')
                        parts = rest.split(':') if rest else []
                        # parts[0] = mode (ALL or WRITE)
                        # parts[1] = resource
                        # parts[2] = target_user
                        revoke_mode = parts[0].upper() if len(parts) > 0 else 'ALL'
                        resource = parts[1] if len(parts) > 1 else None
                        target_user = parts[2] if len(parts) > 2 else None
                        payload = {
                            'action': 'revoke',
                            'revoke_mode': revoke_mode,  # 'ALL' or 'WRITE'
                            'resource': resource,
                            'owner': interest.user_id,
                            'target_user': target_user,
                            'password': interest.auth_key
                        }
                        import json as _json
                        server_route = self.routing_module.lookup_route('/dlsu/server')
                        if server_route:
                            host, port = (server_route.next_hop if hasattr(server_route, 'next_hop') else server_route).split(':')
                            port = int(port)
                            resp = self.comm_module.send_and_wait(_json.dumps(payload), host, port)
                            from common import DataPacket
                            resp_content = resp.encode('utf-8') if isinstance(resp, str) and resp else b'OK'
                            dp = DataPacket(name=interest.name, data_payload=resp_content, data_length=len(resp_content))
                            return dp.to_json()
                    except Exception as e:
                        return self._create_error_response(f"Revoke failed: {e}")

                elif name.startswith('/dlsu/server/locations'):
                    # request storage locations for a file: /dlsu/server/locations:<resource>
                    try:
                        _, rest = name.split('/dlsu/server/locations', 1)
                        rest = rest.lstrip(':')
                        resource = rest if rest else None
                        payload = {'action': 'get_file_locations', 'resource': resource, 'user_id': interest.user_id, 'password': interest.auth_key}
                        import json as _json
                        server_route = self.routing_module.lookup_route('/dlsu/server')
                        if server_route:
                            host, port = (server_route.next_hop if hasattr(server_route, 'next_hop') else server_route).split(':')
                            port = int(port)
                            resp = self.comm_module.send_and_wait(_json.dumps(payload), host, port)
                            from common import DataPacket
                            resp_content = resp.encode('utf-8') if isinstance(resp, str) and resp else b''
                            dp = DataPacket(name=interest.name, data_payload=resp_content, data_length=len(resp_content))
                            return dp.to_json()
                    except Exception as e:
                        return self._create_error_response(f"Location lookup failed: {e}")

                elif name.startswith('/dlsu/server/myfiles'):
                    # request list of files owned by user - forward Interest to server
                    server_route = self.routing_module.lookup_route('/dlsu/server')
                    if server_route:
                        self._log_debug(f"📤 Forwarding MYFILES Interest to server", "interest")
                        return self._forward_to_next_hop(interest, server_route)

                elif name.startswith('/dlsu/server/register_location'):
                    # Storage node registering file location - forward Interest to server
                    server_route = self.routing_module.lookup_route('/dlsu/server')
                    if server_route:
                        self._log_debug(f"📤 Forwarding REGISTER_LOCATION Interest to server", "interest")
                        return self._forward_to_next_hop(interest, server_route)

                elif name.startswith('/dlsu/server/register_file'):
                    # Storage node registering file ownership - forward Interest to server
                    server_route = self.routing_module.lookup_route('/dlsu/server')
                    if server_route:
                        self._log_debug(f"📤 Forwarding REGISTER_FILE Interest to server", "interest")
                        return self._forward_to_next_hop(interest, server_route)

                elif name.startswith('/dlsu/server/store_key'):
                    # Storage node sending encryption key for secure storage - forward Interest to server
                    server_route = self.routing_module.lookup_route('/dlsu/server')
                    if server_route:
                        self._log_debug(f"📤 Forwarding STORE_KEY Interest to server", "interest")
                        return self._forward_to_next_hop(interest, server_route)

                elif name.startswith('/dlsu/server/auth'):
                    # Direct auth check request from client - forward Interest as-is to server
                    server_route = self.routing_module.lookup_route('/dlsu/server')
                    if server_route:
                        return self._forward_to_next_hop(interest, server_route)

            # Handle WRITE_DATA operation - client sending actual file data through router
            # This happens AFTER the client already got WRITE authorization
            print(f"[{self.router_id}] Checking for WRITE_DATA: operation={interest.operation}")
            if interest.operation and interest.operation.upper() == 'WRITE_DATA':
                print(f"[{self.router_id}] ★★★ WRITE_DATA DETECTED: {interest.name} ★★★")
                self._log_debug(f"📤 WRITE_DATA: {interest.name} from {interest.user_id}", "data")
                
                import json as _json
                resource_to_check = self._strip_fragment_notation(interest.name)
                
                # PRE-DELETE: Delete old file from ALL RAID nodes before overwriting
                # This ensures clean overwrite even when new file has different fragment count
                raid_level = None
                for level in ['raid0', 'raid1', 'raid5', 'raid6']:
                    if f'/{level}/' in interest.name:
                        raid_level = level
                        break
                
                # Default to raid1 if no RAID in path
                if not raid_level:
                    raid_level = 'raid1'
                
                # Only send pre-delete for first fragment (avoid repeating for each fragment)
                from common import parse_fragment_notation, InterestPacket
                frag_info = parse_fragment_notation(interest.name)
                is_first_fragment = (not frag_info or not frag_info.get('is_fragment') or frag_info.get('index') == 1)
                
                if is_first_fragment:
                    print(f"[{self.router_id}] 🗑️ PRE-DELETE: Cleaning old data from {raid_level.upper()} nodes before write")
                    try:
                        from fib_config import RAID_GROUPS
                        raid_nodes = RAID_GROUPS.get(raid_level, {}).get('nodes', [])
                        
                        # Send DELETE to all RAID nodes (don't wait, fire-and-forget)
                        delete_interest = InterestPacket(
                            name=resource_to_check,
                            user_id=interest.user_id,
                            operation='DELETE',
                            auth_key=getattr(interest, 'auth_key', None)
                        )
                        
                        for node in raid_nodes:
                            try:
                                # Use short timeout - we don't need to wait for response
                                self.comm_module.send_and_wait(
                                    delete_interest.to_json(), 
                                    node['host'], 
                                    node['port'], 
                                    timeout=2
                                )
                                print(f"[{self.router_id}] 🗑️ Pre-delete sent to {node['name']}")
                            except Exception:
                                pass  # Ignore errors - file may not exist yet
                    except ImportError:
                        pass
                
                # Get storage location from Interest (client passes assigned_storage from WRITE auth)
                target_storage = getattr(interest, 'target_storage', None)
                if target_storage:
                    try:
                        storage_host, storage_port = target_storage.split(':')
                        storage_port = int(storage_port)
                        self._log_debug(f"📦 WRITE_DATA using client-provided storage: {storage_host}:{storage_port}", "data")
                    except Exception as e:
                        self._log_debug(f"Invalid target_storage format: {target_storage}, using default", "error")
                        default_storage = self._storage_nodes[0] if self._storage_nodes else (DEFAULT_HOST, 9001, 0)
                        storage_host, storage_port = default_storage[0], default_storage[1]
                else:
                    # Fallback: Query server for file location (for updates to existing files)
                    default_storage = self._storage_nodes[0] if self._storage_nodes else (DEFAULT_HOST, 9001, 0)
                    storage_host, storage_port = default_storage[0], default_storage[1]  # Default fallback
                    server_route = self.routing_module.lookup_route('/dlsu/server')
                    if server_route:
                        location_payload = {
                            'action': 'get_file_locations',
                            'resource': resource_to_check,
                            'user_id': interest.user_id,
                            'password': interest.auth_key
                        }
                        server_host, server_port = (server_route.next_hop if hasattr(server_route, 'next_hop') else server_route).split(':')
                        loc_resp = self.comm_module.send_and_wait(_json.dumps(location_payload), server_host, int(server_port), timeout=5)
                        
                        if loc_resp:
                            try:
                                loc_data = _json.loads(loc_resp.decode('utf-8', errors='ignore') if isinstance(loc_resp, bytes) else loc_resp)
                                # Server returns array directly, not {'locations': [...]}
                                locations = loc_data if isinstance(loc_data, list) else loc_data.get('locations', [])
                                if locations:
                                    storage_host = locations[0].get('host', DEFAULT_HOST)
                                    storage_port = locations[0].get('port', 9001)
                                    self._log_debug(f"📦 WRITE_DATA to storage via server lookup: {storage_host}:{storage_port}", "data")
                            except Exception as e:
                                self._log_debug(f"Could not parse location response: {e}", "error")
                
                # Forward WRITE_DATA Interest to storage
                # Convert to a DataPacket-like format that storage expects for writes
                from common import DataPacket
                write_payload = getattr(interest, 'write_payload', None)
                if write_payload:
                    # Create a DataPacket to send to storage (storage expects DataPacket for writes)
                    data_pkt = DataPacket(
                        name=interest.name,
                        data_payload=write_payload.encode('utf-8') if isinstance(write_payload, str) else write_payload
                    )
                    
                    # RAID CONTROLLER: Detect RAID level and apply appropriate strategy
                    raid_level = None
                    raid_nodes = []
                    
                    # Detect RAID level from path (e.g., /dlsu/storage/raid1/file.txt)
                    print(f"[{self.router_id}] RAID detection for path: {interest.name}")
                    for level in ['raid0', 'raid1', 'raid5', 'raid6']:
                        if f'/{level}/' in interest.name:
                            raid_level = level
                            print(f"[{self.router_id}] ★ Detected RAID level: {raid_level}")
                            break
                    
                    # MANDATORY RAID: If no RAID level in path, default to RAID 1
                    if not raid_level:
                        raid_level = 'raid1'
                        print(f"[{self.router_id}] No RAID level in path - DEFAULTING to RAID 1 (mirroring)")
                    
                    # Get RAID nodes based on level
                    try:
                        from fib_config import RAID_GROUPS
                        if raid_level in RAID_GROUPS:
                            raid_nodes = RAID_GROUPS[raid_level]['nodes']
                            print(f"[{self.router_id}] ★ RAID {raid_level.upper()}: {len(raid_nodes)} nodes: {[n['name'] for n in raid_nodes]}")
                    except ImportError:
                        print(f"[{self.router_id}] ERROR: Could not import RAID_GROUPS from fib_config")
                    
                    if raid_level == 'raid1' and len(raid_nodes) > 1:
                        # RAID 1: Send to ALL nodes in parallel
                        import threading
                        responses = {}
                        
                        def send_to_node(node):
                            try:
                                node_host = node['host']
                                node_port = node['port']
                                node_name = node['name']
                                self._log_debug(f"📤 RAID 1: Sending to {node_name} ({node_host}:{node_port})", "data")
                                resp = self.comm_module.send_and_wait(data_pkt.to_json(), node_host, node_port, timeout=10)
                                responses[node_name] = resp
                                if resp:
                                    self._log_debug(f"✓ RAID 1: {node_name} stored successfully", "data")
                                else:
                                    self._log_debug(f"⚠ RAID 1: {node_name} timeout", "error")
                            except Exception as e:
                                self._log_debug(f"✗ RAID 1: {node_name} error: {e}", "error")
                                responses[node_name] = None
                        
                        threads = []
                        for node in raid_nodes:
                            t = threading.Thread(target=send_to_node, args=(node,), daemon=True)
                            t.start()
                            threads.append(t)
                        
                        # Wait for all nodes to respond
                        for t in threads:
                            t.join(timeout=12)
                        
                        # Check if at least one succeeded
                        success_count = sum(1 for r in responses.values() if r)
                        self._log_debug(f"📊 RAID 1: {success_count}/{len(raid_nodes)} nodes stored", "data")
                        
                        if success_count > 0:
                            # Invalidate cache
                            base_key = self._strip_fragment_notation(interest.name)
                            self._invalidate_cache_by_prefix(base_key)
                            
                            # Return first successful response
                            for resp in responses.values():
                                if resp:
                                    return resp if isinstance(resp, str) else resp.decode('utf-8', errors='ignore')
                        else:
                            return self._create_error_response("RAID 1: All storage nodes failed")
                    
                    elif raid_level == 'raid0':
                        # RAID 0: STRIPING - distribute fragments round-robin across nodes
                        # Fragment 1 → Node A, Fragment 2 → Node B, Fragment 3 → Node A, etc.
                        try:
                            from fib_config import RAID_GROUPS
                            if 'raid0' in RAID_GROUPS:
                                raid_nodes = RAID_GROUPS['raid0']['nodes']
                        except ImportError:
                            raid_nodes = []
                        
                        if len(raid_nodes) >= 2:
                            # Determine which node to use based on fragment index
                            # Parse fragment notation from interest name if present
                            from common import parse_fragment_notation
                            frag_info = parse_fragment_notation(interest.name)
                            
                            if frag_info and frag_info.get('is_fragment'):
                                frag_idx = frag_info['index']
                                node_idx = (frag_idx - 1) % len(raid_nodes)  # 1-based to 0-based
                            else:
                                # Non-fragmented file - use first node
                                node_idx = 0
                            
                            target_node = raid_nodes[node_idx]
                            print(f"[{self.router_id}] ★ RAID 0: Routing to {target_node['name']} (node {node_idx})")
                            
                            # Send to the selected node
                            storage_resp = self.comm_module.send_and_wait(
                                data_pkt.to_json(), 
                                target_node['host'], 
                                target_node['port'], 
                                timeout=10
                            )
                            
                            if storage_resp:
                                base_key = self._strip_fragment_notation(interest.name)
                                self._invalidate_cache_by_prefix(base_key)
                                print(f"[{self.router_id}] ✓ RAID 0: Stored on {target_node['name']}")
                                return storage_resp if isinstance(storage_resp, str) else storage_resp.decode('utf-8', errors='ignore')
                            else:
                                return self._create_error_response(f"RAID 0: {target_node['name']} timeout")
                        else:
                            # Fall back to first available node
                            print(f"[{self.router_id}] RAID 0: Not enough nodes")
                            storage_resp = self.comm_module.send_and_wait(data_pkt.to_json(), storage_host, storage_port, timeout=10)
                            if storage_resp:
                                return storage_resp if isinstance(storage_resp, str) else storage_resp.decode('utf-8', errors='ignore')
                            else:
                                return self._create_error_response("Storage write timeout")
                    
                    elif raid_level == 'raid5':
                        # RAID 5: Striping with distributed parity (single parity)
                        # With 3 nodes: 2 data fragments + 1 parity per stripe set
                        # Parity rotates: Stripe 0→C has parity, Stripe 1→B, Stripe 2→A, ...
                        
                        num_nodes = len(raid_nodes)  # Should be 3
                        data_nodes = num_nodes - 1   # 2 data nodes per stripe
                        
                        frag_info = parse_fragment_notation(interest.name)
                        
                        if frag_info and frag_info.get('is_fragment'):
                            frag_idx = frag_info['index']  # 1-based
                            total_frags = frag_info['total']
                            base_name = frag_info['base_name']
                            
                            # Calculate which stripe set this fragment belongs to
                            # Stripe sets: frags 1-2 = set 0, frags 3-4 = set 1, etc.
                            stripe_set = (frag_idx - 1) // data_nodes
                            position_in_stripe = (frag_idx - 1) % data_nodes  # 0 or 1
                            
                            # Parity node rotates: set 0 → node 2, set 1 → node 1, set 2 → node 0, ...
                            parity_node_idx = (num_nodes - 1 - (stripe_set % num_nodes))
                            
                            # Data nodes are the others, in order
                            data_node_indices = [i for i in range(num_nodes) if i != parity_node_idx]
                            target_node_idx = data_node_indices[position_in_stripe]
                            
                            target_node = raid_nodes[target_node_idx]
                            print(f"[{self.router_id}] ★ RAID 5: Fragment {frag_idx}/{total_frags} → {target_node['name']} (stripe set {stripe_set}, parity on node {parity_node_idx})")
                            
                            # Store fragment in stripe buffer for consistent parity calculation
                            # IMPORTANT: Unwrap the JSON payload to get raw bytes that match what storage stores
                            frag_bytes = write_payload.encode('utf-8') if isinstance(write_payload, str) else write_payload
                            try:
                                import base64 as _b64
                                payload_str = frag_bytes.decode('utf-8') if isinstance(frag_bytes, bytes) else frag_bytes
                                payload_dict = _json.loads(payload_str)
                                if isinstance(payload_dict, dict) and 'data_b64' in payload_dict:
                                    # Extract raw bytes from base64-encoded payload
                                    frag_bytes = _b64.b64decode(payload_dict['data_b64'])
                            except Exception:
                                pass  # Keep original bytes if unwrapping fails
                            with self._raid5_buffer_lock:
                                if base_name not in self._raid5_stripe_buffer:
                                    self._raid5_stripe_buffer[base_name] = {}
                                if stripe_set not in self._raid5_stripe_buffer[base_name]:
                                    self._raid5_stripe_buffer[base_name][stripe_set] = {}
                                self._raid5_stripe_buffer[base_name][stripe_set][frag_idx] = frag_bytes
                            
                            # Send data fragment to target node
                            storage_resp = self.comm_module.send_and_wait(data_pkt.to_json(), target_node['host'], target_node['port'], timeout=10)
                            
                            # Parse encryption key from storage response (format: STORED:filename:enc_key=KEY)
                            if storage_resp:
                                resp_str = storage_resp if isinstance(storage_resp, str) else storage_resp.decode('utf-8', errors='ignore')
                                if ':enc_key=' in resp_str:
                                    try:
                                        import re as _re
                                        enc_match = _re.search(r':enc_key=([a-fA-F0-9]+)', resp_str)
                                        if enc_match:
                                            enc_key = enc_match.group(1)
                                            with self._raid_encryption_lock:
                                                self._raid_encryption_keys[base_name] = enc_key
                                            print(f"[{self.router_id}] RAID 5: Captured encryption key for {base_name}")
                                    except Exception as e:
                                        print(f"[{self.router_id}] RAID 5: Could not parse encryption key: {e}")
                            
                            # Check if this is the last fragment in the stripe set - compute and store parity
                            is_last_in_stripe = (position_in_stripe == data_nodes - 1)
                            is_last_overall = (frag_idx == total_frags)
                            
                            if is_last_in_stripe or is_last_overall:
                                # Compute parity for this stripe set
                                # IMPORTANT: Encrypt fragments before computing parity so parity matches stored encrypted data
                                stripe_start = stripe_set * data_nodes + 1
                                stripe_frags = []
                                frag_sizes = {}  # Track individual fragment sizes for recovery
                                
                                # Get encryption key for this file
                                with self._raid_encryption_lock:
                                    enc_key = self._raid_encryption_keys.get(base_name)
                                
                                with self._raid5_buffer_lock:
                                    stripe_buffer = self._raid5_stripe_buffer.get(base_name, {}).get(stripe_set, {})
                                    for i in range(data_nodes):
                                        frag_num = stripe_start + i
                                        if frag_num <= total_frags:
                                            if frag_num in stripe_buffer:
                                                frag_data = stripe_buffer[frag_num]
                                                # Encrypt fragment before adding to parity calculation
                                                if enc_key:
                                                    frag_data = self._xor_cipher(frag_data, enc_key)
                                                stripe_frags.append(frag_data)
                                                frag_sizes[frag_num] = len(frag_data)
                                            else:
                                                print(f"[{self.router_id}] RAID 5: Warning - missing frag {frag_num} in buffer for parity calc")
                                
                                # Compute XOR parity if we have fragments for this stripe
                                # Parity is computed on ENCRYPTED fragments so it can be used for recovery
                                if len(stripe_frags) >= 1:
                                    parity_data = self._compute_xor_parity(stripe_frags)
                                    parity_node = raid_nodes[parity_node_idx]
                                    
                                    # Create parity fragment packet with fragment size metadata
                                    # Include frag_sizes in the name so storage node can save it
                                    # Format: base:parity[stripe_set]:sizes[f1=s1,f2=s2]
                                    sizes_str = ",".join(f"{k}={v}" for k, v in sorted(frag_sizes.items()))
                                    parity_name = f"{base_name}:parity[{stripe_set}]:sizes[{sizes_str}]"
                                    parity_pkt = DataPacket(
                                        name=parity_name,
                                        data_payload=parity_data
                                    )
                                    
                                    print(f"[{self.router_id}] ★ RAID 5: Storing encrypted parity for stripe set {stripe_set} on {parity_node['name']} ({len(parity_data)} bytes, sizes: {frag_sizes})")
                                    
                                    # Send parity to parity node
                                    parity_resp = self.comm_module.send_and_wait(parity_pkt.to_json(), parity_node['host'], parity_node['port'], timeout=10)
                                    if parity_resp:
                                        print(f"[{self.router_id}] ✓ RAID 5: Parity stored on {parity_node['name']}")
                                
                                # Clear buffer for this stripe set after parity is stored
                                with self._raid5_buffer_lock:
                                    if base_name in self._raid5_stripe_buffer:
                                        if stripe_set in self._raid5_stripe_buffer[base_name]:
                                            del self._raid5_stripe_buffer[base_name][stripe_set]
                                        # Clean up empty base_name entries
                                        if not self._raid5_stripe_buffer[base_name]:
                                            del self._raid5_stripe_buffer[base_name]
                            
                            if storage_resp:
                                base_key = self._strip_fragment_notation(interest.name)
                                self._invalidate_cache_by_prefix(base_key)
                                return storage_resp if isinstance(storage_resp, str) else storage_resp.decode('utf-8', errors='ignore')
                            else:
                                return self._create_error_response(f"RAID 5: {target_node['name']} timeout")
                        else:
                            # Non-fragmented file - store on first data node, compute parity with padding
                            target_node = raid_nodes[0]
                            parity_node = raid_nodes[-1]
                            
                            storage_resp = self.comm_module.send_and_wait(data_pkt.to_json(), target_node['host'], target_node['port'], timeout=10)
                            
                            # For small files, parity = data itself (XOR with zeros)
                            payload_bytes = write_payload.encode('utf-8') if isinstance(write_payload, str) else write_payload
                            parity_name = f"{interest.name}:parity[0]"
                            parity_pkt = DataPacket(name=parity_name, data_payload=payload_bytes)
                            self.comm_module.send_and_wait(parity_pkt.to_json(), parity_node['host'], parity_node['port'], timeout=10)
                            
                            if storage_resp:
                                return storage_resp if isinstance(storage_resp, str) else storage_resp.decode('utf-8', errors='ignore')
                            else:
                                return self._create_error_response("RAID 5: Storage timeout")
                    
                    elif raid_level == 'raid6':
                        # RAID 6: Striping with dual parity (P + Q)
                        # With 4 nodes: 2 data fragments + 2 parity blocks per stripe set
                        # P = XOR of data blocks (same as RAID 5)
                        # Q = Weighted XOR (simplified Reed-Solomon)
                        # Parity rotates across nodes like RAID 5 but with 2 parity nodes
                        
                        num_nodes = len(raid_nodes)  # Should be 4
                        data_nodes_per_stripe = num_nodes - 2  # 2 data nodes per stripe
                        
                        frag_info = parse_fragment_notation(interest.name)
                        
                        if frag_info and frag_info.get('is_fragment'):
                            frag_idx = frag_info['index']  # 1-based
                            total_frags = frag_info['total']
                            base_name = frag_info['base_name']
                            
                            # Calculate which stripe set this fragment belongs to
                            # Stripe sets: frags 1-2 = set 0, frags 3-4 = set 1, etc.
                            stripe_set = (frag_idx - 1) // data_nodes_per_stripe
                            position_in_stripe = (frag_idx - 1) % data_nodes_per_stripe
                            
                            # Parity nodes rotate: P and Q move together
                            # Set 0: P→node3, Q→node2, data→nodes 0,1
                            # Set 1: P→node2, Q→node1, data→nodes 0,3
                            # Set 2: P→node1, Q→node0, data→nodes 2,3
                            # Set 3: P→node0, Q→node3, data→nodes 1,2
                            p_node_idx = (num_nodes - 1 - (stripe_set % num_nodes)) % num_nodes
                            q_node_idx = (num_nodes - 2 - (stripe_set % num_nodes)) % num_nodes
                            
                            # Data nodes are the remaining nodes in order
                            data_node_indices = [i for i in range(num_nodes) if i != p_node_idx and i != q_node_idx]
                            target_node_idx = data_node_indices[position_in_stripe]
                            
                            target_node = raid_nodes[target_node_idx]
                            print(f"[{self.router_id}] ★ RAID 6: Fragment {frag_idx}/{total_frags} → {target_node['name']} (stripe {stripe_set}, P→node{p_node_idx}, Q→node{q_node_idx})")
                            
                            # Store fragment in stripe buffer for parity calculation
                            # IMPORTANT: Unwrap the JSON payload to get raw bytes that match what storage stores
                            frag_bytes = write_payload.encode('utf-8') if isinstance(write_payload, str) else write_payload
                            try:
                                import base64 as _b64
                                payload_str = frag_bytes.decode('utf-8') if isinstance(frag_bytes, bytes) else frag_bytes
                                payload_dict = _json.loads(payload_str)
                                if isinstance(payload_dict, dict) and 'data_b64' in payload_dict:
                                    # Extract raw bytes from base64-encoded payload
                                    frag_bytes = _b64.b64decode(payload_dict['data_b64'])
                            except Exception:
                                pass  # Keep original bytes if unwrapping fails
                            with self._raid5_buffer_lock:  # Reuse RAID 5 buffer
                                buffer_key = f"raid6_{base_name}"
                                if buffer_key not in self._raid5_stripe_buffer:
                                    self._raid5_stripe_buffer[buffer_key] = {}
                                if stripe_set not in self._raid5_stripe_buffer[buffer_key]:
                                    self._raid5_stripe_buffer[buffer_key][stripe_set] = {}
                                self._raid5_stripe_buffer[buffer_key][stripe_set][frag_idx] = frag_bytes
                            
                            # Send data fragment to target node
                            storage_resp = self.comm_module.send_and_wait(data_pkt.to_json(), target_node['host'], target_node['port'], timeout=10)
                            
                            # Parse encryption key from storage response (format: STORED:filename:enc_key=KEY)
                            if storage_resp:
                                resp_str = storage_resp if isinstance(storage_resp, str) else storage_resp.decode('utf-8', errors='ignore')
                                if ':enc_key=' in resp_str:
                                    try:
                                        import re as _re
                                        enc_match = _re.search(r':enc_key=([a-fA-F0-9]+)', resp_str)
                                        if enc_match:
                                            enc_key = enc_match.group(1)
                                            with self._raid_encryption_lock:
                                                self._raid_encryption_keys[base_name] = enc_key
                                            print(f"[{self.router_id}] RAID 6: Captured encryption key for {base_name}")
                                    except Exception as e:
                                        print(f"[{self.router_id}] RAID 6: Could not parse encryption key: {e}")
                            
                            # Check if this is the last fragment in the stripe set - compute and store both parities
                            is_last_in_stripe = (position_in_stripe == data_nodes_per_stripe - 1)
                            is_last_overall = (frag_idx == total_frags)
                            
                            if is_last_in_stripe or is_last_overall:
                                # Compute P and Q parity for this stripe set
                                # IMPORTANT: Encrypt fragments before computing parity so parity matches stored encrypted data
                                stripe_start = stripe_set * data_nodes_per_stripe + 1
                                stripe_frags = []
                                frag_sizes = {}
                                
                                # Get encryption key for this file
                                with self._raid_encryption_lock:
                                    enc_key = self._raid_encryption_keys.get(base_name)
                                
                                with self._raid5_buffer_lock:
                                    buffer_key = f"raid6_{base_name}"
                                    stripe_buffer = self._raid5_stripe_buffer.get(buffer_key, {}).get(stripe_set, {})
                                    for i in range(data_nodes_per_stripe):
                                        frag_num = stripe_start + i
                                        if frag_num <= total_frags:
                                            if frag_num in stripe_buffer:
                                                frag_data = stripe_buffer[frag_num]
                                                # Encrypt fragment before adding to parity calculation
                                                if enc_key:
                                                    frag_data = self._xor_cipher(frag_data, enc_key)
                                                stripe_frags.append(frag_data)
                                                frag_sizes[frag_num] = len(frag_data)
                                
                                if len(stripe_frags) >= 1:
                                    # Compute P parity (XOR) on ENCRYPTED fragments
                                    p_parity = self._compute_xor_parity(stripe_frags)
                                    
                                    # Compute Q parity (weighted XOR for Reed-Solomon-like behavior)
                                    q_parity = self._compute_q_parity(stripe_frags)
                                    
                                    p_node = raid_nodes[p_node_idx]
                                    q_node = raid_nodes[q_node_idx]
                                    
                                    # Store P parity
                                    sizes_str = ",".join(f"{k}={v}" for k, v in sorted(frag_sizes.items()))
                                    p_name = f"{base_name}:parity_p[{stripe_set}]:sizes[{sizes_str}]"
                                    p_pkt = DataPacket(name=p_name, data_payload=p_parity)
                                    
                                    print(f"[{self.router_id}] ★ RAID 6: Storing encrypted P parity for stripe {stripe_set} on {p_node['name']} ({len(p_parity)} bytes)")
                                    self.comm_module.send_and_wait(p_pkt.to_json(), p_node['host'], p_node['port'], timeout=10)
                                    
                                    # Store Q parity
                                    q_name = f"{base_name}:parity_q[{stripe_set}]:sizes[{sizes_str}]"
                                    q_pkt = DataPacket(name=q_name, data_payload=q_parity)
                                    
                                    print(f"[{self.router_id}] ★ RAID 6: Storing encrypted Q parity for stripe {stripe_set} on {q_node['name']} ({len(q_parity)} bytes)")
                                    self.comm_module.send_and_wait(q_pkt.to_json(), q_node['host'], q_node['port'], timeout=10)
                                    
                                    print(f"[{self.router_id}] ✓ RAID 6: Both parities stored for stripe {stripe_set}")
                                
                                # Clear buffer for this stripe set
                                with self._raid5_buffer_lock:
                                    buffer_key = f"raid6_{base_name}"
                                    if buffer_key in self._raid5_stripe_buffer:
                                        if stripe_set in self._raid5_stripe_buffer[buffer_key]:
                                            del self._raid5_stripe_buffer[buffer_key][stripe_set]
                                        if not self._raid5_stripe_buffer[buffer_key]:
                                            del self._raid5_stripe_buffer[buffer_key]
                            
                            if storage_resp:
                                base_key = self._strip_fragment_notation(interest.name)
                                self._invalidate_cache_by_prefix(base_key)
                                return storage_resp if isinstance(storage_resp, str) else storage_resp.decode('utf-8', errors='ignore')
                            else:
                                return self._create_error_response(f"RAID 6: {target_node['name']} timeout")
                        else:
                            # Non-fragmented file - store on first data node with both parities
                            p_node_idx = num_nodes - 1  # Last node has P for stripe 0
                            q_node_idx = num_nodes - 2  # Second to last has Q
                            data_node_indices = [i for i in range(num_nodes) if i != p_node_idx and i != q_node_idx]
                            target_node = raid_nodes[data_node_indices[0]]
                            
                            storage_resp = self.comm_module.send_and_wait(data_pkt.to_json(), target_node['host'], target_node['port'], timeout=10)
                            
                            # Store P and Q (for small files, P=Q=data XOR zeros = data)
                            payload_bytes = write_payload.encode('utf-8') if isinstance(write_payload, str) else write_payload
                            p_name = f"{interest.name}:parity_p[0]"
                            p_pkt = DataPacket(name=p_name, data_payload=payload_bytes)
                            self.comm_module.send_and_wait(p_pkt.to_json(), raid_nodes[p_node_idx]['host'], raid_nodes[p_node_idx]['port'], timeout=10)
                            
                            q_parity = self._compute_q_parity([payload_bytes])
                            q_name = f"{interest.name}:parity_q[0]"
                            q_pkt = DataPacket(name=q_name, data_payload=q_parity)
                            self.comm_module.send_and_wait(q_pkt.to_json(), raid_nodes[q_node_idx]['host'], raid_nodes[q_node_idx]['port'], timeout=10)
                            
                            if storage_resp:
                                return storage_resp if isinstance(storage_resp, str) else storage_resp.decode('utf-8', errors='ignore')
                            else:
                                return self._create_error_response("RAID 6: Storage timeout")
                    
                    else:
                        # Fallback (shouldn't reach here with mandatory RAID)
                        storage_resp = self.comm_module.send_and_wait(data_pkt.to_json(), storage_host, storage_port, timeout=10)
                        
                        if storage_resp:
                            base_key = self._strip_fragment_notation(interest.name)
                            self._invalidate_cache_by_prefix(base_key)
                            return storage_resp if isinstance(storage_resp, str) else storage_resp.decode('utf-8', errors='ignore')
                        else:
                            return self._create_error_response("Storage write timeout")
                else:
                    return self._create_error_response("WRITE_DATA missing payload")

            # For other operations (READ/WRITE/DELETE), perform auth check with server
            # OPTIMIZATION: For READ operations with read_token, validate locally to skip server
            server_route = self.routing_module.lookup_route('/dlsu/server')
            
            # Check if this is a READ with a read_token (fragment access optimization)
            read_token = getattr(interest, 'read_token', None)
            operation_upper = (interest.operation or 'READ').upper()
            
            if operation_upper == 'READ' and read_token:
                # Validate read token locally (R2 token cache)
                incoming_name = self._strip_fragment_notation(interest.name)
                token_result = self._validate_read_token(read_token, incoming_name)
                
                if token_result.get('valid'):
                    # Token is valid - skip server auth, go directly to cache/storage
                    self._log_debug(f"🔑 Read token valid for {interest.user_id} -> {incoming_name}", "permission")
                    
                    # Check if this is a RAID file (need special routing)
                    raid_level = None
                    for level in ['raid0', 'raid1', 'raid5', 'raid6']:
                        if f'/{level}/' in interest.name:
                            raid_level = level
                            break
                    
                    if raid_level == 'raid0':
                        # RAID 0 READ: Route to correct node based on fragment index
                        self._log_debug(f"📦 RAID 0 token-auth routing for {interest.name}", "routing")
                        return self._read_raid0_stripes(interest)
                    
                    if raid_level == 'raid5':
                        # RAID 5 READ: Route to correct data node, with parity recovery if needed
                        self._log_debug(f"📦 RAID 5 token-auth routing for {interest.name}", "routing")
                        return self._read_raid5_fragment(interest)
                    
                    if raid_level == 'raid6':
                        # RAID 6 READ: Route to correct data node, with dual parity recovery if needed
                        self._log_debug(f"📦 RAID 6 token-auth routing for {interest.name}", "routing")
                        return self._read_raid6_fragment(interest)
                    
                    # Look for storage location from FIB (use base name for FIB lookup, not fragment name)
                    base_name_for_fib = self._strip_fragment_notation(interest.name)
                    storage_route = self.routing_module.lookup_route(base_name_for_fib)
                    storage_location = storage_route.next_hop if hasattr(storage_route, 'next_hop') else str(storage_route) if storage_route else None
                    self._log_debug(f"🔍 FIB lookup for {base_name_for_fib} -> {storage_location}", "routing")
                    
                    # Check cache first (using full name with fragment notation)
                    cache_key = interest.name
                    cached_data = self.processing_module.content_store.get(cache_key)
                    
                    if cached_data:
                        # Cache HIT - serve directly
                        self.stats["cache_hits"] += 1
                        self._log_control(f"━━━ [R2] TOKEN AUTH: FROM CACHE ━━━")
                        self._log_control(f"    📦 Serving cached data for: {cache_key}")
                        return self._create_data_response(interest.name, cached_data)
                    
                    # Cache MISS - go to storage
                    self.stats["cache_misses"] += 1
                    self._log_control(f"━━━ [R2] TOKEN AUTH: FROM STORAGE ━━━")
                    self._log_control(f"    📦 Storage location: {storage_location}")
                    
                    if storage_location:
                        storage_response = self._forward_to_next_hop(interest, storage_location)
                    else:
                        self._log_debug(f"❌ No storage route for {base_name_for_fib}", "error")
                        return self._create_error_response(f"No storage route found for: {base_name_for_fib}")
                    
                    # Cache the response
                    if storage_response:
                        try:
                            import json as _json
                            import base64
                            from common import DataPacket
                            if isinstance(storage_response, bytes):
                                storage_response = storage_response.decode('utf-8', errors='ignore')
                            resp_data = _json.loads(storage_response)
                            if resp_data.get('type') == 'DATA' and resp_data.get('data_payload'):
                                payload_bytes = base64.b64decode(resp_data['data_payload'])
                                if not payload_bytes.startswith(b'ERROR'):
                                    # Use response name for caching (handles fragments correctly)
                                    response_name = resp_data.get('name', cache_key)
                                    self.processing_module.content_store.put(response_name, payload_bytes)
                        except Exception as cache_err:
                            self._log_debug(f"[CACHE] Could not cache token-auth response: {cache_err}", "error")
                    
                    return storage_response
                else:
                    # Token invalid - log and fall through to server auth
                    self._log_debug(f"⚠️ Read token invalid: {token_result.get('reason', 'unknown')}", "permission")
            
            # Standard server-based permission check
            if server_route:
                self._log_debug(f"🔐 Checking permission with Server", "permission")
                try:
                    from common import InterestPacket, DataPacket
                    incoming_name = self._strip_fragment_notation(interest.name)

                    # If the incoming Interest already has a target field set (e.g., from client auth check),
                    # use that target directly instead of extracting from the name
                    incoming_target = getattr(interest, 'target', None)
                    if incoming_target:
                        resource_to_check = self._strip_fragment_notation(incoming_target)
                    elif incoming_name.startswith('/dlsu/server/auth'):
                        # Avoid double-prefix: if incoming already embeds an auth prefix, extract its target
                        candidate = incoming_name[len('/dlsu/server/auth'):]
                        if candidate.startswith('/'):
                            candidate = candidate[1:]
                        resource_to_check = '/' + candidate if candidate else '/'
                    else:
                        resource_to_check = incoming_name

                    # Build a dedicated auth Interest and include the original resource in `target`
                    auth_name = '/dlsu/server/auth'
                    # Preserve the original operation (READ/WRITE) so the AuthServer can check the proper permission
                    auth_interest = InterestPacket(name=auth_name, user_id=interest.user_id, operation=interest.operation)
                    auth_interest.target = resource_to_check
                    try:
                        auth_interest.auth_key = interest.auth_key
                    except Exception:
                        pass

                    auth_response_raw = self._forward_to_next_hop(auth_interest, server_route)

                    if not auth_response_raw:
                        return self._create_error_response("Permission denied (auth timeout)")

                    # Try parse JSON or Data
                    try:
                        auth_dp = DataPacket.from_json(auth_response_raw)
                    except Exception:
                        # Plain text response from server
                        auth_allowed = ("AUTHORIZED" in str(auth_response_raw) or "SUCCESS" in str(auth_response_raw))
                        auth_dp = None
                    else:
                        self._log_debug(f"🔐 Received auth Data from server: {auth_dp.name}", "permission")
                        # Do NOT cache or route auth Data - it's specific to this request
                        try:
                            import json as _json
                            payload = auth_dp.data_payload.decode('utf-8', errors='ignore')
                            parsed = _json.loads(payload)
                            auth_allowed = bool(parsed.get('authorized'))
                            # Get storage_location (host:port) for existing files
                            storage_location = parsed.get('storage_location')
                            storage_node = parsed.get('storage_node')
                            is_new_file = parsed.get('is_new_file', True)
                            
                            # Cache read_token for future fragment requests (R2 optimization)
                            server_read_token = parsed.get('read_token')
                            if server_read_token and auth_allowed and interest.operation.upper() == 'READ':
                                self._cache_read_token(server_read_token, interest.user_id, resource_to_check)
                                self._log_debug(f"🔑 Cached read_token for {interest.user_id} -> {resource_to_check}", "permission")
                        except Exception:
                            auth_allowed = ("AUTHORIZED" in payload or "SUCCESS" in payload)
                            storage_location = None
                            storage_node = None
                            is_new_file = True

                    if auth_allowed:
                        # If WRITE: return authorization + assignment, do not forward
                        if interest.operation.upper() == 'WRITE':
                            if storage_location:
                                # Use server-provided storage location (server assigns for new files too)
                                if is_new_file:
                                    self._log_debug(f"📦 New file - server assigned storage: {storage_location} ({storage_node})", "permission")
                                else:
                                    self._log_debug(f"📦 File exists at {storage_location} ({storage_node}) - using existing location", "permission")
                                assigned_hostport = storage_location
                            else:
                                # Fallback: server didn't provide location, use router round-robin
                                raid_pref = self._parse_raid_preference(interest)
                                assigned_hostport = self._select_storage_node(raid_pref)
                                self._log_debug(f"📦 No server storage assignment - router fallback to round-robin: {assigned_hostport}", "permission")
                            
                            # Invalidate cache for ALL fragments of this file (in case of overwrite)
                            base_key = self._strip_fragment_notation(resource_to_check)
                            self._invalidate_cache_by_prefix(base_key)
                            
                            msg = {'authorized': True, 'assigned_storage': assigned_hostport, 'storage_node': storage_node, 'is_new_file': is_new_file}
                            from common import DataPacket
                            import json as _json
                            dp = DataPacket(name=interest.name, data_payload=_json.dumps(msg).encode('utf-8'))
                            return dp.to_json()
                        elif interest.operation.upper() == 'DELETE':
                            # DELETE: First ask server to validate ownership and get storage locations
                            # Server will delete DB entry and return storage locations for physical deletion
                            import json as _json
                            delete_payload = {
                                'action': 'delete_file',
                                'resource': resource_to_check,
                                'user_id': interest.user_id,
                                'password': getattr(interest, 'auth_key', None)
                            }
                            server_host, server_port = (server_route.next_hop if hasattr(server_route, 'next_hop') else server_route).split(':')
                            delete_resp = self.comm_module.send_and_wait(_json.dumps(delete_payload), server_host, int(server_port), timeout=10)
                            
                            if delete_resp:
                                try:
                                    delete_result = _json.loads(delete_resp.decode('utf-8', errors='ignore') if isinstance(delete_resp, bytes) else delete_resp)
                                    if delete_result.get('success'):
                                        # DB record deleted, now forward to storage to delete physical file
                                        # For RAID files, delete from ALL nodes in the RAID group
                                        storage_locs = delete_result.get('storage_locations', [])
                                        
                                        # Detect RAID level from path and get ALL RAID group nodes
                                        raid_level = None
                                        for level in ['raid0', 'raid1', 'raid5', 'raid6']:
                                            if f'/{level}/' in resource_to_check:
                                                raid_level = level
                                                break
                                        
                                        if raid_level:
                                            # Get all nodes in this RAID group
                                            try:
                                                from fib_config import RAID_GROUPS
                                                raid_nodes = RAID_GROUPS.get(raid_level, {}).get('nodes', [])
                                                print(f"[{self.router_id}] ★ RAID {raid_level.upper()} DELETE: Sending to {len(raid_nodes)} nodes")
                                                
                                                delete_count = 0
                                                for node in raid_nodes:
                                                    try:
                                                        storage_resp = self._forward_to_next_hop(interest, f"{node['host']}:{node['port']}")
                                                        if storage_resp:
                                                            delete_count += 1
                                                            self._log_debug(f"Storage {node['name']} DELETE response received", "data")
                                                    except Exception as e:
                                                        self._log_debug(f"Storage {node['name']} DELETE failed: {e}", "error")
                                                
                                                print(f"[{self.router_id}] ✓ RAID {raid_level.upper()} DELETE: {delete_count}/{len(raid_nodes)} nodes deleted")
                                            except ImportError:
                                                print(f"[{self.router_id}] ERROR: Could not import RAID_GROUPS for DELETE")
                                        elif storage_locs:
                                            # Non-RAID file: use storage locations from DB
                                            for loc in storage_locs:
                                                loc_host = loc.get('host', DEFAULT_HOST)
                                                loc_port = loc.get('port', 9001)
                                                try:
                                                    storage_resp = self._forward_to_next_hop(interest, f"{loc_host}:{loc_port}")
                                                    if storage_resp:
                                                        self._log_debug(f"Storage {loc_host}:{loc_port} DELETE response received", "data")
                                                except Exception as e:
                                                    self._log_debug(f"Storage {loc_host}:{loc_port} DELETE failed: {e}", "error")
                                        
                                        # Invalidate cache for ALL fragments of this file
                                        base_key = self._strip_fragment_notation(resource_to_check)
                                        self._invalidate_cache_by_prefix(base_key)
                                        
                                        msg = {'success': True, 'deleted': resource_to_check, 'message': 'File deleted from DB and storage'}
                                        dp = DataPacket(name=interest.name, data_payload=_json.dumps(msg).encode('utf-8'))
                                        return dp.to_json()
                                    else:
                                        # Delete denied (not owner or not found)
                                        error_msg = delete_result.get('message', 'Delete denied')
                                        return self._create_error_response(error_msg)
                                except Exception as e:
                                    return self._create_error_response(f"Delete error: {e}")
                            else:
                                return self._create_error_response("Delete failed: no response from server")
                        else:
                            # READ: First check cache (after auth), then go to storage if not cached
                            self._log_control(f"━━━ [R2] READ REQUEST (after auth) ━━━")
                            self._log_control(f"    File: {interest.name}")
                            self._log_control(f"    User: {interest.user_id}")
                            
                            # Check if this is a RAID file (need special routing)
                            raid_level = None
                            for level in ['raid0', 'raid1', 'raid5', 'raid6']:
                                if f'/{level}/' in interest.name:
                                    raid_level = level
                                    break
                            
                            if raid_level == 'raid0':
                                # RAID 0 READ: Route to correct node based on fragment index
                                return self._read_raid0_stripes(interest)
                            
                            if raid_level == 'raid5':
                                # RAID 5 READ: Route to correct data node, with parity recovery if needed
                                return self._read_raid5_fragment(interest)
                            
                            if raid_level == 'raid6':
                                # RAID 6 READ: Route to correct data node, with dual parity recovery if needed
                                return self._read_raid6_fragment(interest)
                            
                            # Use FULL name (with fragment notation) as cache key
                            # Each fragment is cached separately: /file.txt:[1/100], /file.txt:[2/100], etc.
                            cache_key = interest.name
                            cached_data = self.processing_module.content_store.get(cache_key)
                            
                            if cached_data:
                                # Cache HIT - serve directly without going to storage
                                self.stats["cache_hits"] += 1
                                self._log_control(f"━━━ [R2] RESPONSE: FROM CACHE ━━━")
                                self._log_control(f"    📦 Serving cached data for: {cache_key}")
                                return self._create_data_response(interest.name, cached_data)
                            
                            # Cache MISS - go to storage
                            self.stats["cache_misses"] += 1
                            self._log_control(f"    📭 CACHE MISS - Fetching from Storage...")
                            
                            if storage_location:
                                self._log_control(f"    📤 Forwarding to Storage at {storage_location}")
                                storage_response = self._forward_to_next_hop(interest, storage_location)
                            else:
                                # Use base name (without fragment notation) for FIB lookup
                                base_name_for_fib = self._strip_fragment_notation(interest.name)
                                storage_route = self.routing_module.lookup_route(base_name_for_fib)
                                if storage_route:
                                    next_hop = storage_route.next_hop if hasattr(storage_route, 'next_hop') else str(storage_route)
                                    self._log_control(f"    📤 Forwarding to Storage via FIB: {base_name_for_fib} -> {next_hop}")
                                    storage_response = self._forward_to_next_hop(interest, storage_route)
                                else:
                                    self._log_debug(f"❌ No storage route for {base_name_for_fib}", "error")
                                    return self._create_error_response(f"No storage route found for: {base_name_for_fib}")
                            
                            # Cache the storage response for future READs
                            if storage_response:
                                try:
                                    # Parse the response to get the data payload
                                    import json as _json
                                    from common import DataPacket
                                    if isinstance(storage_response, bytes):
                                        storage_response = storage_response.decode('utf-8', errors='ignore')
                                    resp_data = _json.loads(storage_response)
                                    if resp_data.get('type') == 'DATA' and resp_data.get('data_payload'):
                                        # Decode base64 payload and cache it
                                        import base64
                                        payload_bytes = base64.b64decode(resp_data['data_payload'])
                                        # Don't cache error responses
                                        if not payload_bytes.startswith(b'ERROR'):
                                            # Use response name for caching (handles fragments correctly)
                                            response_name = resp_data.get('name', cache_key)
                                            self.processing_module.content_store.put(response_name, payload_bytes)
                                            self._log_control(f"━━━ [R2] RESPONSE: FROM STORAGE ━━━")
                                            self._log_control(f"    💾 Data received from storage, cached as: {response_name}")
                                except Exception as cache_err:
                                    self._log_debug(f"[CACHE] Could not cache response: {cache_err}", "error")
                            
                            return storage_response
                    else:
                        return self._create_error_response("Permission denied")

                except Exception as e:
                    return self._create_error_response(f"Permission denied (auth error: {e})")

        # Generic forwarding for routers (use FIB lookup)
        # This is the main path for R1 forwarding to R2
        route = self.routing_module.lookup_route(interest.name)
        if route:
            self._log_debug(f"📤 Forwarding Interest via FIB to {route.next_hop if hasattr(route, 'next_hop') else route}", "interest")
            response = self._forward_to_next_hop(interest, route)
            
            # R1: Cache READ responses from R2 for future requests
            if self.router_id == "R1" and response:
                operation = (interest.operation or 'READ').upper()
                is_storage_request = interest.name.startswith('/dlsu/storage') or interest.name.startswith('/dlsu/test')
                
                if operation == 'READ' and is_storage_request:
                    try:
                        import json as _json
                        import base64
                        if isinstance(response, bytes):
                            response_str = response.decode('utf-8', errors='ignore')
                        else:
                            response_str = response
                        resp_data = _json.loads(response_str)
                        if resp_data.get('type') == 'DATA' and resp_data.get('data_payload'):
                            payload_bytes = base64.b64decode(resp_data['data_payload'])
                            # Don't cache error responses
                            if not payload_bytes.startswith(b'ERROR'):
                                # Use response name for caching (handles fragments correctly)
                                response_name = resp_data.get('name', interest.name)
                                self.processing_module.content_store.put(response_name, payload_bytes)
                                self._log_control(f"[R1 CACHE] Stored READ response: {response_name}")
                    except Exception as cache_err:
                        self._log_debug(f"[R1 CACHE] Could not cache: {cache_err}", "error")
                elif operation in ('WRITE', 'WRITE_DATA', 'DELETE') and is_storage_request:
                    # Invalidate cache for ALL fragments on WRITE/WRITE_DATA/DELETE
                    base_key = self._strip_fragment_notation(interest.name)
                    self._invalidate_cache_by_prefix(base_key)
            
            return response

        return None
    
    def _read_raid0_stripes(self, interest):
        """RAID 0 READ: Route request to the correct node based on fragment index.
        
        RAID 0 distributes fragments round-robin:
        - Fragment 1, 3, 5... → Node A
        - Fragment 2, 4, 6... → Node B
        
        For non-fragmented requests, this fetches the first fragment from Node A.
        """
        from common import DataPacket, InterestPacket, parse_fragment_notation
        
        try:
            from fib_config import RAID_GROUPS
            raid_nodes = RAID_GROUPS.get('raid0', {}).get('nodes', [])
        except ImportError:
            print(f"[{self.router_id}] ERROR: Could not import RAID_GROUPS for RAID 0 read")
            return self._create_error_response("RAID 0 configuration not available")
        
        if len(raid_nodes) < 2:
            print(f"[{self.router_id}] RAID 0: Not enough nodes configured")
            return self._create_error_response("RAID 0: Not enough nodes configured")
        
        num_nodes = len(raid_nodes)
        
        # Determine which node has this fragment
        frag_info = parse_fragment_notation(interest.name)
        
        if frag_info and frag_info.get('is_fragment'):
            frag_idx = frag_info['index']
            node_idx = (frag_idx - 1) % num_nodes  # 1-based to 0-based
        else:
            # Non-fragmented request - use first node
            node_idx = 0
        
        target_node = raid_nodes[node_idx]
        print(f"[{self.router_id}] ★ RAID 0 READ: Fragment -> {target_node['name']} (node {node_idx})")
        
        # Forward the READ to the correct node
        read_interest = InterestPacket(
            name=interest.name,
            user_id=interest.user_id,
            operation='READ',
            auth_key=interest.auth_key
        )
        
        resp = self.comm_module.send_and_wait(
            read_interest.to_json(), 
            target_node['host'], 
            target_node['port'], 
            timeout=10
        )
        
        if resp:
            print(f"[{self.router_id}] ✓ RAID 0 READ: Got response from {target_node['name']}")
            return resp if isinstance(resp, str) else resp.decode('utf-8', errors='ignore')
        else:
            print(f"[{self.router_id}] ✗ RAID 0 READ: Timeout from {target_node['name']}")
            return self._create_error_response(f"RAID 0: Timeout from {target_node['name']}")
    
    def _read_raid5_fragment(self, interest):
        """RAID 5 READ: Route to correct data node, with parity-based recovery if node fails.
        
        RAID 5 distributes data with rotating parity (3 nodes: ST5-A, ST5-B, ST5-C):
        - Stripe set 0: Frag 1 → A, Frag 2 → B, Parity → C
        - Stripe set 1: Frag 3 → A, Parity → B, Frag 4 → C
        - Stripe set 2: Parity → A, Frag 5 → B, Frag 6 → C
        
        If the target node fails, we can recover using XOR of other data + parity.
        """
        from common import DataPacket, InterestPacket, parse_fragment_notation
        import json as _json
        import base64
        
        try:
            from fib_config import RAID_GROUPS
            raid_nodes = RAID_GROUPS.get('raid5', {}).get('nodes', [])
        except ImportError:
            print(f"[{self.router_id}] ERROR: Could not import RAID_GROUPS for RAID 5 read")
            return self._create_error_response("RAID 5 configuration not available")
        
        num_nodes = len(raid_nodes)  # Should be 3
        data_nodes = num_nodes - 1   # 2 data nodes per stripe
        
        if num_nodes < 3:
            print(f"[{self.router_id}] RAID 5: Not enough nodes configured")
            return self._create_error_response("RAID 5: Need at least 3 nodes")
        
        frag_info = parse_fragment_notation(interest.name)
        
        if frag_info and frag_info.get('is_fragment'):
            frag_idx = frag_info['index']  # 1-based
            total_frags = frag_info['total']
            base_name = frag_info['base_name']
            
            # Calculate which stripe set this fragment belongs to
            stripe_set = (frag_idx - 1) // data_nodes
            position_in_stripe = (frag_idx - 1) % data_nodes
            
            # Parity node rotates
            parity_node_idx = (num_nodes - 1 - (stripe_set % num_nodes))
            
            # Data nodes are the others
            data_node_indices = [i for i in range(num_nodes) if i != parity_node_idx]
            target_node_idx = data_node_indices[position_in_stripe]
            target_node = raid_nodes[target_node_idx]
            
            print(f"[{self.router_id}] ★ RAID 5 READ: Fragment {frag_idx} → {target_node['name']} (stripe {stripe_set})")
            
            # Try to read from the target node
            read_interest = InterestPacket(
                name=interest.name,
                user_id=interest.user_id,
                operation='READ',
                auth_key=interest.auth_key
            )
            
            resp = self.comm_module.send_and_wait(
                read_interest.to_json(),
                target_node['host'],
                target_node['port'],
                timeout=5
            )
            
            if resp:
                print(f"[{self.router_id}] ✓ RAID 5 READ: Got fragment from {target_node['name']}")
                return resp if isinstance(resp, str) else resp.decode('utf-8', errors='ignore')
            else:
                # Node failed - try parity recovery
                print(f"[{self.router_id}] ⚠ RAID 5 READ: {target_node['name']} failed, attempting parity recovery...")
                
                # Determine which node failed - is it a data node or parity node?
                # We need: other data fragment(s) + parity
                # If parity node is down, we can't recover (need dual parity/RAID 6)
                
                # Check if we can reach the parity node
                parity_node = raid_nodes[parity_node_idx]
                
                # We need to fetch the other data fragment(s) and parity, then XOR to recover
                recovery_data = []
                other_frag_sizes = []  # Track sizes to handle last fragment properly
                
                # Fetch other data fragment(s) in this stripe
                stripe_start = stripe_set * data_nodes + 1
                for i in range(data_nodes):
                    other_frag_num = stripe_start + i
                    if other_frag_num != frag_idx and other_frag_num <= total_frags:
                        other_position = i
                        other_node_idx = data_node_indices[other_position]
                        other_node = raid_nodes[other_node_idx]
                        
                        fetch_interest = InterestPacket(
                            name=f"{base_name}:[{other_frag_num}/{total_frags}]",
                            user_id=interest.user_id,
                            operation='READ'
                        )
                        
                        other_resp = self.comm_module.send_and_wait(
                            fetch_interest.to_json(),
                            other_node['host'],
                            other_node['port'],
                            timeout=5
                        )
                        
                        if other_resp:
                            try:
                                resp_data = _json.loads(other_resp.decode('utf-8', errors='ignore') if isinstance(other_resp, bytes) else other_resp)
                                if resp_data.get('data_payload'):
                                    frag_data = base64.b64decode(resp_data['data_payload'])
                                    recovery_data.append(frag_data)
                                    other_frag_sizes.append((other_frag_num, len(frag_data)))
                                    print(f"[{self.router_id}]   ✓ Got fragment {other_frag_num} from {other_node['name']} ({len(frag_data)} bytes)")
                            except Exception as e:
                                print(f"[{self.router_id}]   ✗ Failed to parse fragment {other_frag_num}: {e}")
                
                # Fetch parity
                parity_interest = InterestPacket(
                    name=f"{base_name}:parity[{stripe_set}]",
                    user_id=interest.user_id,
                    operation='READ'
                )
                
                parity_resp = self.comm_module.send_and_wait(
                    parity_interest.to_json(),
                    parity_node['host'],
                    parity_node['port'],
                    timeout=5
                )
                
                parity_size = 0
                stored_frag_sizes = {}  # Fragment sizes from parity metadata
                if parity_resp:
                    try:
                        resp_data = _json.loads(parity_resp.decode('utf-8', errors='ignore') if isinstance(parity_resp, bytes) else parity_resp)
                        if resp_data.get('data_payload'):
                            parity_data = base64.b64decode(resp_data['data_payload'])
                            parity_size = len(parity_data)
                            recovery_data.append(parity_data)
                            
                            # Parse sizes metadata from response name
                            resp_name = resp_data.get('name', '')
                            if ':sizes[' in resp_name:
                                import re
                                sizes_match = re.search(r':sizes\[([^\]]*)\]', resp_name)
                                if sizes_match:
                                    sizes_str = sizes_match.group(1)
                                    for pair in sizes_str.split(','):
                                        if '=' in pair:
                                            k, v = pair.split('=')
                                            stored_frag_sizes[int(k)] = int(v)
                                    print(f"[{self.router_id}]   ✓ Got parity with sizes metadata: {stored_frag_sizes}")
                            
                            print(f"[{self.router_id}]   ✓ Got parity from {parity_node['name']} ({parity_size} bytes)")
                    except Exception as e:
                        print(f"[{self.router_id}]   ✗ Failed to parse parity: {e}")
                
                # Recover using XOR
                # Check if this is the last fragment in an incomplete stripe
                # (e.g., fragment 61 of 61 with 2 data nodes per stripe - it's the only fragment in its stripe)
                frags_in_this_stripe = min(data_nodes, total_frags - (stripe_set * data_nodes))
                is_incomplete_stripe = (len(recovery_data) == 1 and frags_in_this_stripe == 1)
                
                if len(recovery_data) >= data_nodes or is_incomplete_stripe:
                    # For incomplete last stripe with only parity, parity IS the data
                    # (since XOR of single fragment = parity)
                    if is_incomplete_stripe and len(recovery_data) == 1:
                        # recovery_data[0] is the parity, which equals the single fragment
                        recovered = recovery_data[0]
                        print(f"[{self.router_id}] ✓ RAID 5 RECOVERY: Last fragment in incomplete stripe - parity = data")
                    else:
                        recovered = self._compute_xor_parity(recovery_data)
                    
                    # Determine correct fragment size using stored metadata
                    # The parity response includes the original sizes of all fragments in the stripe
                    if frag_idx in stored_frag_sizes:
                        original_size = stored_frag_sizes[frag_idx]
                        if len(recovered) > original_size:
                            print(f"[{self.router_id}]   Truncating recovered fragment from {len(recovered)} to {original_size} bytes")
                            recovered = recovered[:original_size]
                    elif other_frag_sizes:
                        # Fallback: use peer fragment size if no metadata
                        peer_size = other_frag_sizes[0][1]
                        if frag_idx != total_frags and len(recovered) > peer_size:
                            recovered = recovered[:peer_size]
                    
                    print(f"[{self.router_id}] ✓ RAID 5 RECOVERY: Reconstructed fragment {frag_idx} ({len(recovered)} bytes)")
                    
                    # Return recovered data as DataPacket
                    dp = DataPacket(
                        name=interest.name,
                        data_payload=recovered,
                        data_length=len(recovered)
                    )
                    return dp.to_json()
                else:
                    print(f"[{self.router_id}] ✗ RAID 5 RECOVERY FAILED: Not enough data for recovery (got {len(recovery_data)}, need {data_nodes})")
                    return self._create_error_response(f"RAID 5: Recovery failed - not enough data")
        else:
            # Non-fragmented request - need to get fragment 1 to determine total
            # For RAID 5, fragment 1 is in stripe set 0, which has parity on node 2 (last node)
            # So fragment 1 should be on node 0 (ST5-A)
            
            # Calculate which node has fragment 1
            stripe_set_0 = 0
            parity_node_idx_0 = (num_nodes - 1 - (stripe_set_0 % num_nodes))  # Node 2 for stripe 0
            data_node_indices_0 = [i for i in range(num_nodes) if i != parity_node_idx_0]
            frag1_node_idx = data_node_indices_0[0]  # Fragment 1 is position 0 in stripe
            frag1_node = raid_nodes[frag1_node_idx]
            
            print(f"[{self.router_id}] RAID 5: Fragment 1 should be on {frag1_node['name']}")
            
            read_interest = InterestPacket(
                name=interest.name,
                user_id=interest.user_id,
                operation='READ',
                auth_key=interest.auth_key
            )
            
            resp = self.comm_module.send_and_wait(
                read_interest.to_json(),
                frag1_node['host'],
                frag1_node['port'],
                timeout=5
            )
            
            if resp:
                print(f"[{self.router_id}] ✓ RAID 5: Got response from {frag1_node['name']}")
                return resp if isinstance(resp, str) else resp.decode('utf-8', errors='ignore')
            else:
                # Fragment 1's node is down - need to get total from another node and recover frag 1
                print(f"[{self.router_id}] ⚠ RAID 5: {frag1_node['name']} down, checking other nodes for file info...")
                
                # Query other nodes to find one that has the file metadata
                total_frags = None
                for i, node in enumerate(raid_nodes):
                    if i == frag1_node_idx:
                        continue  # Skip the failed node
                    
                    # Send a metadata query by requesting any fragment
                    # The node will return fragment info including total
                    query_interest = InterestPacket(
                        name=interest.name,
                        user_id=interest.user_id,
                        operation='READ'
                    )
                    
                    query_resp = self.comm_module.send_and_wait(
                        query_interest.to_json(),
                        node['host'],
                        node['port'],
                        timeout=5
                    )
                    
                    if query_resp:
                        try:
                            resp_str = query_resp.decode('utf-8', errors='ignore') if isinstance(query_resp, bytes) else query_resp
                            resp_data = _json.loads(resp_str)
                            resp_name = resp_data.get('name', '')
                            # Parse total from response name like /file:[1/1393]
                            if ':[' in resp_name and '/' in resp_name.split(':[')[1]:
                                total_str = resp_name.split(':[')[1].split('/')[1].rstrip(']')
                                total_frags = int(total_str)
                                print(f"[{self.router_id}] ✓ RAID 5: Got total_fragments={total_frags} from {node['name']}")
                                break
                        except Exception as e:
                            print(f"[{self.router_id}]   Could not parse response from {node['name']}: {e}")
                
                if total_frags:
                    # Now we know the total - request fragment 1 with proper notation
                    # This will trigger parity recovery in the fragment-specific handler
                    frag1_interest = InterestPacket(
                        name=f"{interest.name}:[1/{total_frags}]",
                        user_id=interest.user_id,
                        operation='READ',
                        auth_key=interest.auth_key
                    )
                    
                    # Recursively handle this as a fragmented request (will trigger recovery)
                    return self._read_raid5_fragment(frag1_interest)
                else:
                    return self._create_error_response(f"RAID 5: Could not determine file info - all nodes failed or no metadata")
    
    def _read_raid6_fragment(self, interest):
        """RAID 6 READ: Route to correct data node, with dual parity recovery if nodes fail.
        
        RAID 6 distributes data with rotating P and Q parities (4 nodes: A, B, C, D):
        - Stripe 0: Frag 1→A, Frag 2→B, P→D, Q→C
        - Stripe 1: Frag 3→A, Frag 4→D, P→C, Q→B
        - etc.
        
        Can recover from up to 2 node failures using P and Q parities.
        """
        from common import DataPacket, InterestPacket, parse_fragment_notation
        import json as _json
        import base64
        
        try:
            from fib_config import RAID_GROUPS
            raid_nodes = RAID_GROUPS.get('raid6', {}).get('nodes', [])
        except ImportError:
            print(f"[{self.router_id}] ERROR: Could not import RAID_GROUPS for RAID 6 read")
            return self._create_error_response("RAID 6 configuration not available")
        
        num_nodes = len(raid_nodes)  # Should be 4
        data_nodes_per_stripe = num_nodes - 2  # 2 data nodes per stripe
        
        if num_nodes < 4:
            print(f"[{self.router_id}] RAID 6: Not enough nodes configured")
            return self._create_error_response("RAID 6: Need at least 4 nodes")
        
        frag_info = parse_fragment_notation(interest.name)
        
        if frag_info and frag_info.get('is_fragment'):
            frag_idx = frag_info['index']  # 1-based
            total_frags = frag_info['total']
            base_name = frag_info['base_name']
            
            # Calculate which stripe set this fragment belongs to
            stripe_set = (frag_idx - 1) // data_nodes_per_stripe
            position_in_stripe = (frag_idx - 1) % data_nodes_per_stripe
            
            # Parity nodes rotate
            p_node_idx = (num_nodes - 1 - (stripe_set % num_nodes)) % num_nodes
            q_node_idx = (num_nodes - 2 - (stripe_set % num_nodes)) % num_nodes
            
            # Data nodes are the remaining
            data_node_indices = [i for i in range(num_nodes) if i != p_node_idx and i != q_node_idx]
            target_node_idx = data_node_indices[position_in_stripe]
            target_node = raid_nodes[target_node_idx]
            
            print(f"[{self.router_id}] ★ RAID 6 READ: Fragment {frag_idx} → {target_node['name']} (stripe {stripe_set})")
            
            # Try to read from the target node
            read_interest = InterestPacket(
                name=interest.name,
                user_id=interest.user_id,
                operation='READ',
                auth_key=interest.auth_key
            )
            
            resp = self.comm_module.send_and_wait(
                read_interest.to_json(),
                target_node['host'],
                target_node['port'],
                timeout=5
            )
            
            if resp:
                print(f"[{self.router_id}] ✓ RAID 6 READ: Got fragment from {target_node['name']}")
                return resp if isinstance(resp, str) else resp.decode('utf-8', errors='ignore')
            else:
                # Node failed - try parity recovery
                print(f"[{self.router_id}] ⚠ RAID 6 READ: {target_node['name']} failed, attempting recovery...")
                
                recovery_data = []
                other_frag_sizes = []
                stored_frag_sizes = {}
                
                # Fetch other data fragment(s) in this stripe
                stripe_start = stripe_set * data_nodes_per_stripe + 1
                for i in range(data_nodes_per_stripe):
                    other_frag_num = stripe_start + i
                    if other_frag_num != frag_idx and other_frag_num <= total_frags:
                        other_position = i
                        other_node_idx = data_node_indices[other_position]
                        other_node = raid_nodes[other_node_idx]
                        
                        fetch_interest = InterestPacket(
                            name=f"{base_name}:[{other_frag_num}/{total_frags}]",
                            user_id=interest.user_id,
                            operation='READ'
                        )
                        
                        other_resp = self.comm_module.send_and_wait(
                            fetch_interest.to_json(),
                            other_node['host'],
                            other_node['port'],
                            timeout=5
                        )
                        
                        if other_resp:
                            try:
                                resp_data = _json.loads(other_resp.decode('utf-8', errors='ignore') if isinstance(other_resp, bytes) else other_resp)
                                if resp_data.get('data_payload'):
                                    frag_data = base64.b64decode(resp_data['data_payload'])
                                    recovery_data.append(frag_data)
                                    other_frag_sizes.append((other_frag_num, len(frag_data)))
                                    print(f"[{self.router_id}]   ✓ Got fragment {other_frag_num} from {other_node['name']}")
                            except Exception as e:
                                print(f"[{self.router_id}]   ✗ Failed to parse fragment {other_frag_num}: {e}")
                
                # Try to fetch P parity
                p_node = raid_nodes[p_node_idx]
                p_data = None
                p_interest = InterestPacket(
                    name=f"{base_name}:parity_p[{stripe_set}]",
                    user_id=interest.user_id,
                    operation='READ'
                )
                
                p_resp = self.comm_module.send_and_wait(
                    p_interest.to_json(),
                    p_node['host'],
                    p_node['port'],
                    timeout=5
                )
                
                if p_resp:
                    try:
                        resp_data = _json.loads(p_resp.decode('utf-8', errors='ignore') if isinstance(p_resp, bytes) else p_resp)
                        if resp_data.get('data_payload'):
                            p_data = base64.b64decode(resp_data['data_payload'])
                            
                            # Parse sizes metadata
                            resp_name = resp_data.get('name', '')
                            if ':sizes[' in resp_name:
                                import re
                                sizes_match = re.search(r':sizes\[([^\]]*)\]', resp_name)
                                if sizes_match:
                                    for pair in sizes_match.group(1).split(','):
                                        if '=' in pair:
                                            k, v = pair.split('=')
                                            stored_frag_sizes[int(k)] = int(v)
                            
                            print(f"[{self.router_id}]   ✓ Got P parity from {p_node['name']} ({len(p_data)} bytes)")
                    except Exception as e:
                        print(f"[{self.router_id}]   ✗ Failed to get P parity: {e}")
                
                # Try to fetch Q parity (backup if P fails)
                q_node = raid_nodes[q_node_idx]
                q_data = None
                q_interest = InterestPacket(
                    name=f"{base_name}:parity_q[{stripe_set}]",
                    user_id=interest.user_id,
                    operation='READ'
                )
                
                q_resp = self.comm_module.send_and_wait(
                    q_interest.to_json(),
                    q_node['host'],
                    q_node['port'],
                    timeout=5
                )
                
                if q_resp:
                    try:
                        resp_data = _json.loads(q_resp.decode('utf-8', errors='ignore') if isinstance(q_resp, bytes) else q_resp)
                        if resp_data.get('data_payload'):
                            q_data = base64.b64decode(resp_data['data_payload'])
                            print(f"[{self.router_id}]   ✓ Got Q parity from {q_node['name']} ({len(q_data)} bytes)")
                    except Exception as e:
                        print(f"[{self.router_id}]   ✗ Failed to get Q parity: {e}")
                
                # Check if this is the last fragment in an incomplete stripe
                frags_in_this_stripe = min(data_nodes_per_stripe, total_frags - (stripe_set * data_nodes_per_stripe))
                is_incomplete_stripe = (len(recovery_data) == 0 and frags_in_this_stripe == 1)
                
                # Recover using available parities
                if (len(recovery_data) >= 1 and (p_data or q_data)) or (is_incomplete_stripe and p_data):
                    # For incomplete last stripe with only 1 fragment, P parity IS the data
                    if is_incomplete_stripe and p_data:
                        recovered = p_data
                        print(f"[{self.router_id}] ✓ RAID 6 RECOVERY: Last fragment in incomplete stripe - P parity = data")
                    elif p_data:
                        # Use P parity first (simpler XOR recovery), fall back to Q
                        recovery_data.append(p_data)
                        recovered = self._compute_xor_parity(recovery_data)
                        print(f"[{self.router_id}] ✓ RAID 6 RECOVERY: Used P parity")
                    else:
                        # Use Q parity recovery
                        known_idx = 0 if position_in_stripe == 1 else 1
                        recovered = self._recover_with_pq(None, q_data, recovery_data[0], known_idx, position_in_stripe, data_nodes_per_stripe)
                        print(f"[{self.router_id}] ✓ RAID 6 RECOVERY: Used Q parity")
                    
                    # Truncate to stored size if available
                    if frag_idx in stored_frag_sizes:
                        original_size = stored_frag_sizes[frag_idx]
                        if len(recovered) > original_size:
                            recovered = recovered[:original_size]
                    
                    print(f"[{self.router_id}] ✓ RAID 6 RECOVERY: Reconstructed fragment {frag_idx} ({len(recovered)} bytes)")
                    
                    dp = DataPacket(
                        name=interest.name,
                        data_payload=recovered,
                        data_length=len(recovered)
                    )
                    return dp.to_json()
                else:
                    print(f"[{self.router_id}] ✗ RAID 6 RECOVERY FAILED: Not enough data")
                    return self._create_error_response("RAID 6: Recovery failed - not enough data")
        else:
            # Non-fragmented request - find fragment 1
            stripe_set_0 = 0
            p_node_idx_0 = (num_nodes - 1 - (stripe_set_0 % num_nodes)) % num_nodes
            q_node_idx_0 = (num_nodes - 2 - (stripe_set_0 % num_nodes)) % num_nodes
            data_node_indices_0 = [i for i in range(num_nodes) if i != p_node_idx_0 and i != q_node_idx_0]
            frag1_node_idx = data_node_indices_0[0]
            frag1_node = raid_nodes[frag1_node_idx]
            
            print(f"[{self.router_id}] RAID 6: Fragment 1 should be on {frag1_node['name']}")
            
            read_interest = InterestPacket(
                name=interest.name,
                user_id=interest.user_id,
                operation='READ',
                auth_key=interest.auth_key
            )
            
            resp = self.comm_module.send_and_wait(
                read_interest.to_json(),
                frag1_node['host'],
                frag1_node['port'],
                timeout=5
            )
            
            if resp:
                return resp if isinstance(resp, str) else resp.decode('utf-8', errors='ignore')
            else:
                # Try other nodes
                total_frags = None
                for i, node in enumerate(raid_nodes):
                    if i == frag1_node_idx:
                        continue
                    
                    query_interest = InterestPacket(
                        name=interest.name,
                        user_id=interest.user_id,
                        operation='READ'
                    )
                    
                    query_resp = self.comm_module.send_and_wait(
                        query_interest.to_json(),
                        node['host'],
                        node['port'],
                        timeout=5
                    )
                    
                    if query_resp:
                        try:
                            resp_str = query_resp.decode('utf-8', errors='ignore') if isinstance(query_resp, bytes) else query_resp
                            resp_data = _json.loads(resp_str)
                            resp_name = resp_data.get('name', '')
                            if ':[' in resp_name and '/' in resp_name.split(':[')[1]:
                                total_str = resp_name.split(':[')[1].split('/')[1].rstrip(']')
                                total_frags = int(total_str)
                                print(f"[{self.router_id}] ✓ RAID 6: Got total_fragments={total_frags} from {node['name']}")
                                break
                        except Exception:
                            pass
                
                if total_frags:
                    frag1_interest = InterestPacket(
                        name=f"{interest.name}:[1/{total_frags}]",
                        user_id=interest.user_id,
                        operation='READ',
                        auth_key=interest.auth_key
                    )
                    return self._read_raid6_fragment(frag1_interest)
                else:
                    return self._create_error_response("RAID 6: Could not determine file info")

    def _forward_to_storage(self, interest, next_hop):
        """Forward Interest to actual storage node"""
        try:
            # Parse host:port
            host, port = next_hop.split(':')
            port = int(port)
            
            self._log_debug(f"📤 Forwarding Interest to {host}:{port}", "interest")
            
            # Send Interest to storage node using send_and_wait for reliability
            response = self.comm_module.send_and_wait(interest.to_json(), host, port)
            
            if response:
                self._log_debug(f"📥 Received response from storage node", "data")
                return response
            else:
                self._log_debug(f"⏱️ Storage node timeout", "error")
                return None
                
        except Exception as e:
            self._log_debug(f"❌ Forward error: {e}", "error")
            return None

    def _forward_to_next_hop(self, interest, route_or_next_hop, timeout: float = None, retry_on_failure: bool = True):
        """Generic forwarder: accepts a RoutingEntry or 'host:port' string and forwards Interest.
        
        Args:
            interest: InterestPacket to forward
            route_or_next_hop: RoutingEntry object or 'host:port' string
            timeout: Optional timeout override (default uses 10s for auth, 5s otherwise)
            retry_on_failure: If True, attempt failover to alternate nodes for storage requests
        """
        try:
            # Accept either a RoutingEntry-like object or a string
            if hasattr(route_or_next_hop, 'next_hop'):
                next_hop = route_or_next_hop.next_hop
            else:
                next_hop = route_or_next_hop

            host, port = next_hop.split(':')
            port = int(port)

            # Use longer timeout for auth requests (may involve DB operations)
            if timeout is None:
                if interest.name.startswith('/dlsu/server/auth') or interest.operation in ('PERMISSION', 'WRITE', 'DELETE'):
                    timeout = 15.0  # Auth requests need longer timeout for DB operations
                else:
                    timeout = 5.0

            self._log_debug(f"📤 Forwarding Interest to next hop {host}:{port} (timeout={timeout}s)", "interest")
            
            # Use send_and_wait for synchronous request-response (more reliable on Windows)
            response = self.comm_module.send_and_wait(interest.to_json(), host, port, timeout=timeout)

            if response:
                self._log_debug(f"📥 Received response from {host}:{port}", "data")
                return response
            else:
                self._log_debug(f"⏱️ Timeout from {host}:{port}", "error")
                
                # Attempt failover for storage requests only
                if retry_on_failure and '/dlsu/storage/' in getattr(interest, 'name', ''):
                    return self._attempt_failover(interest, next_hop, timeout)
                
                return None

        except Exception as e:
            self._log_debug(f"❌ _forward_to_next_hop error: {e}", "error")
            return None
    
    def _attempt_failover(self, interest, failed_hop: str, timeout: float = 5.0):
        """Attempt to forward to alternate storage nodes when primary fails.
        
        This provides automatic failover within RAID groups.
        """
        try:
            from fib_config import RAID_GROUPS
            
            failed_host, failed_port = failed_hop.split(':')
            failed_port = int(failed_port)
            
            # Find which RAID group this node belongs to
            for group_name, config in RAID_GROUPS.items():
                for node in config['nodes']:
                    if node['host'] == failed_host and node['port'] == failed_port:
                        # Found the group - try other nodes
                        self._log_control(f"[FAILOVER] Primary {failed_hop} failed, trying alternates in {group_name}")
                        
                        for alt_node in config['nodes']:
                            if alt_node['host'] == failed_host and alt_node['port'] == failed_port:
                                continue  # Skip the failed node
                            
                            alt_hop = f"{alt_node['host']}:{alt_node['port']}"
                            self._log_debug(f"[FAILOVER] Trying {alt_node['name']} at {alt_hop}", "routing")
                            
                            response = self.comm_module.send_and_wait(
                                interest.to_json(), 
                                alt_node['host'], 
                                alt_node['port'], 
                                timeout=timeout
                            )
                            
                            if response:
                                self._log_control(f"[FAILOVER] ✓ Success via {alt_node['name']}")
                                return response
                        
                        self._log_debug(f"[FAILOVER] ✗ All nodes in {group_name} failed", "error")
                        return None
            
            # Node not found in any RAID group - no failover possible
            self._log_debug(f"[FAILOVER] No failover available for {failed_hop}", "error")
            return None
            
        except ImportError:
            self._log_debug("[FAILOVER] RAID_GROUPS not available", "error")
            return None
        except Exception as e:
            self._log_debug(f"[FAILOVER] Error: {e}", "error")
            return None

    def _strip_fragment_notation(self, resource_name: str) -> str:
        """Utility: strip fragment notation from resource names.
        Example: /files/data.txt:[1/10] -> /files/data.txt
        """
        try:
            if not resource_name:
                return ''
            if ':[' in resource_name:
                return resource_name.split(':[')[0]
            return resource_name
        except Exception:
            return resource_name or ''
    
    def _invalidate_cache_by_prefix(self, base_name: str):
        """Invalidate all cached fragments that start with the given base name.
        
        When a file is written or deleted, we need to invalidate ALL cached fragments.
        Cache keys for fragments look like: /dlsu/storage/file.txt:[1/100]
        This method removes all entries starting with /dlsu/storage/file.txt
        """
        if not base_name:
            return
        
        try:
            cache = self.processing_module.content_store
            # Use the built-in remove_by_prefix method
            if hasattr(cache, 'remove_by_prefix'):
                count = cache.remove_by_prefix(base_name)
                if count > 0:
                    self._log_control(f"[CACHE] Invalidated {count} entries for {base_name}")
            else:
                # Fallback for older ContentStore without remove_by_prefix
                if hasattr(cache, 'store'):
                    keys_to_remove = [k for k in cache.store.keys() if k.startswith(base_name)]
                    for key in keys_to_remove:
                        cache.remove(key)
                    if keys_to_remove:
                        self._log_control(f"[CACHE] Invalidated {len(keys_to_remove)} entries for {base_name}")
        except Exception as e:
            self._log_debug(f"[CACHE] Error invalidating fragments: {e}", "error")
    
    def _route_data_packet(self, data_packet, source: str):
        """Route Data packet back to requester"""
        self._log_debug(f"📦 DATA packet: {data_packet.name}", "data")
        self._log_debug(f"  Length: {data_packet.data_length} bytes, Checksum: {data_packet.checksum[:8]}...", "content")
        
        # Determine faces and operation from PIT
        entry = self.pit.get(data_packet.name)
        faces = set()
        base_name = None
        operation = None
        if entry:
            faces = entry.get('faces', set()).copy()
            operation = entry.get('operation', '').upper()
        # If no direct match, handle fragment notation by using base name
        if not faces and ':[' in data_packet.name:
            base_name = data_packet.name.split(':[' ,1)[0]
            entry = self.pit.get(base_name)
            if entry:
                faces = entry.get('faces', set()).copy()
                operation = entry.get('operation', '').upper()
        
        # Cache handling based on operation:
        # - ONLY cache READ responses (not WRITE/DELETE/etc)
        # - Skip auth/error responses (they're specific to individual requests)
        # - WRITE/DELETE invalidate existing cache for this resource
        is_auth_response = data_packet.name.startswith('/dlsu/server/auth') or data_packet.name == '/error'
        is_server_response = data_packet.name.startswith('/dlsu/server/')
        
        if is_auth_response or is_server_response:
            self._log_debug(f"[CACHE] Skipped auth/server response: {data_packet.name}", "data")
        elif operation == 'READ':
            # Note: Caching for READ is now handled in the R2 permission handler
            # This path is for Data packets routed via generic FIB (non-auth path)
            # Use the actual data_packet.name (which includes fragment notation if fragmented)
            # NOT stripped name, so each fragment is cached separately
            cache_key = data_packet.name
            if not data_packet.data_payload.startswith(b'ERROR'):
                self.processing_module.content_store.put(cache_key, data_packet.data_payload)
                self._log_control(f"[CACHE] Stored (READ): {cache_key}")
        elif operation in ('WRITE', 'WRITE_DATA', 'DELETE'):
            # Invalidate cache for WRITE/WRITE_DATA/DELETE operations using proper remove() method
            cache_key = self._strip_fragment_notation(data_packet.name)
            self.processing_module.content_store.remove(cache_key)
            # Also try the exact name if different
            if data_packet.name != cache_key:
                self.processing_module.content_store.remove(data_packet.name)
        else:
            self._log_debug(f"[CACHE] Skipped (op={operation}): {data_packet.name}", "data")

        if faces:
            for face in list(faces):
                try:
                    host, port_s = face.split(":")
                    port = int(port_s)
                    self._log_debug(f"Forwarding Data {data_packet.name} to {host}:{port}", "data")
                    # Use non-blocking send so we don't stall
                    try:
                        self.comm_module.send(data_packet.to_json(), host, port)
                    except Exception as e:
                        self._log_debug(f"Failed to send Data to {face}: {e}", "error")
                except Exception as e:
                    self._log_debug(f"Invalid face in PIT: {face} ({e})", "error")

            # Clean up PIT entry only when this is the final fragment
            try:
                if ':[' in data_packet.name:
                    # Parse index/total and only delete when index == total
                    try:
                        base_name, frag = data_packet.name.split(':[' ,1)
                        frag_info = frag.rstrip(']')
                        idx_s, total_s = frag_info.split('/')
                        idx = int(idx_s)
                        total = int(total_s)
                    except Exception:
                        idx = 1
                        total = 1

                    if idx >= total:
                        # final fragment -> remove base PIT entry and fragment entry
                        if base_name in self.pit:
                            del self.pit[base_name]
                        if data_packet.name in self.pit:
                            del self.pit[data_packet.name]
                else:
                    # Non-fragment: safe to remove PIT entry
                    if data_packet.name in self.pit:
                        del self.pit[data_packet.name]
            except Exception:
                pass

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
    
    def _compute_xor_parity(self, data_blocks: list) -> bytes:
        """Compute XOR parity across multiple data blocks.
        
        Used for RAID 5 parity calculation.
        All blocks are XORed together to produce parity.
        
        Args:
            data_blocks: List of bytes objects to XOR together
            
        Returns:
            Parity bytes (same length as longest block, shorter blocks zero-padded)
        """
        if not data_blocks:
            return b''
        
        # Find maximum length
        max_len = max(len(b) for b in data_blocks)
        
        # Initialize parity as zeros
        parity = bytearray(max_len)
        
        # XOR each block into parity
        for block in data_blocks:
            for i, byte in enumerate(block):
                parity[i] ^= byte
        
        return bytes(parity)
    
    def _compute_q_parity(self, data_blocks: list) -> bytes:
        """Compute Q parity for RAID 6 using weighted XOR.
        
        This is a simplified Reed-Solomon-like calculation.
        Each block is multiplied by a coefficient (2^i in GF(2^8)) before XOR.
        This allows recovery from 2 simultaneous failures when combined with P parity.
        
        For simplicity, we use a rotation-based scheme:
        Q = (block0 rotated 1) XOR (block1 rotated 2) XOR ...
        
        Args:
            data_blocks: List of bytes objects
            
        Returns:
            Q parity bytes
        """
        if not data_blocks:
            return b''
        
        max_len = max(len(b) for b in data_blocks)
        q_parity = bytearray(max_len)
        
        for block_idx, block in enumerate(data_blocks):
            # Apply a simple coefficient: rotate bits by (block_idx + 1)
            # This creates mathematical diversity for Q vs P
            rotation = (block_idx + 1) % 8
            for i, byte in enumerate(block):
                # Rotate byte left by 'rotation' bits
                rotated = ((byte << rotation) | (byte >> (8 - rotation))) & 0xFF
                q_parity[i] ^= rotated
        
        return bytes(q_parity)
    
    def _xor_cipher(self, data: bytes, key_hex: str) -> bytes:
        """XOR cipher for encrypting/decrypting data with a hex-encoded key.
        
        Used for encrypting parity blocks in RAID 5/6 to match encrypted fragments.
        XOR is symmetric - same function for encrypt and decrypt.
        
        Args:
            data: Data bytes to encrypt/decrypt
            key_hex: Hex-encoded encryption key
            
        Returns:
            XOR-encrypted/decrypted bytes
        """
        if not key_hex:
            return data
        try:
            key = bytes.fromhex(key_hex)
            result = bytearray(len(data))
            key_len = len(key)
            for i, byte in enumerate(data):
                result[i] = byte ^ key[i % key_len]
            return bytes(result)
        except Exception as e:
            print(f"[{self.router_id}] XOR cipher error: {e}")
            return data
    
    def _recover_with_pq(self, p_data: bytes, q_data: bytes, known_block: bytes, 
                          known_idx: int, missing_idx: int, num_blocks: int) -> bytes:
        """Recover a missing data block using P and Q parities.
        
        When one data block is missing:
        - If we have P: missing = P XOR other_data (same as RAID 5)
        - If we have Q: can verify or use as backup
        
        When two blocks are missing (including parity):
        - Use both P and Q equations to solve for missing data
        
        Args:
            p_data: P parity bytes (may be None)
            q_data: Q parity bytes (may be None)
            known_block: The known data block in the stripe
            known_idx: Index of the known block (0-based)
            missing_idx: Index of the missing block we want to recover
            num_blocks: Total number of data blocks per stripe
            
        Returns:
            Recovered data block bytes
        """
        if p_data is not None:
            # Use P parity for recovery (XOR method)
            max_len = max(len(p_data), len(known_block))
            recovered = bytearray(max_len)
            
            # missing = P XOR known
            for i in range(len(p_data)):
                recovered[i] = p_data[i]
            for i in range(len(known_block)):
                recovered[i] ^= known_block[i]
            
            return bytes(recovered)
        
        elif q_data is not None:
            # Use Q parity for recovery (inverse rotation)
            max_len = max(len(q_data), len(known_block))
            recovered = bytearray(max_len)
            
            # First, remove known block's contribution from Q
            known_rotation = (known_idx + 1) % 8
            q_minus_known = bytearray(len(q_data))
            for i in range(len(q_data)):
                q_minus_known[i] = q_data[i]
            for i, byte in enumerate(known_block):
                rotated = ((byte << known_rotation) | (byte >> (8 - known_rotation))) & 0xFF
                q_minus_known[i] ^= rotated
            
            # Now inverse-rotate to get missing block
            missing_rotation = (missing_idx + 1) % 8
            for i in range(len(q_minus_known)):
                byte = q_minus_known[i]
                # Rotate right to undo the left rotation
                unrotated = ((byte >> missing_rotation) | (byte << (8 - missing_rotation))) & 0xFF
                recovered[i] = unrotated
            
            return bytes(recovered)
        
        return b''

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