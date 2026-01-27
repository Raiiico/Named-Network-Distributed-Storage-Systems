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
from fib_config import get_fib_config, get_port_for_router

# Import GUI if available
try:
    from debug_gui import DebugGUI
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False
    print("Warning: debug_gui.py not found. Running without GUI.")


class Router:
    def __init__(self, router_id: str, host: str = "127.0.0.1", port: int = None, use_gui: bool = True):
        self.router_id = router_id
        self.node_name = f"Router-{router_id}"
        
        # Auto-determine port based on router ID if not specified
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
        self._storage_nodes = [
            ('127.0.0.1', 9001, 0),  # ST1 - RAID 0
            ('127.0.0.1', 9002, 1),  # ST2 - RAID 1
            ('127.0.0.1', 9003, 5),  # ST3 - RAID 5
            ('127.0.0.1', 9004, 6),  # ST4 - RAID 6
        ]
        self._storage_index = 0
        self._storage_lock = threading.Lock()
        
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
        
        # Step 1: Check local Content Store for cached data (skip for auth)
        cached_data = None
        if not is_auth_interest:
            try:
                cached_data = self.processing_module.content_store.get(interest.name)
            except Exception:
                cached_data = None

            # If cached, serve directly (do not add PIT or forward)
            if cached_data:
                self.stats["cache_hits"] += 1
                self._log_debug(f"📥 Cache HIT for {interest.name}", "data")
                return self._create_data_response(interest.name, cached_data)

        self.stats["cache_misses"] += 1

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
        try:
            self.pit[pit_key] = {'faces': set([source]), 'timestamp': time.time(), 'forwarded': False}
            self._log_debug(f"[PIT] Created entry for {pit_key} from {source}", "pit")
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
                # Permission patterns: /dlsu/server/permission/grant:<resource>:<target>
                name = interest.name
                if name.startswith('/dlsu/server/permission/grant'):
                    # parse grant request
                    try:
                        _, rest = name.split('/dlsu/server/permission/grant', 1)
                        rest = rest.lstrip(':')
                        parts = rest.split(':') if rest else []
                        resource = parts[0] if len(parts) > 0 else None
                        target_user = parts[1] if len(parts) > 1 else None
                        payload = {
                            'action': 'grant',
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
                    try:
                        _, rest = name.split('/dlsu/server/permission/revoke', 1)
                        rest = rest.lstrip(':')
                        parts = rest.split(':') if rest else []
                        resource = parts[0] if len(parts) > 0 else None
                        target_user = parts[1] if len(parts) > 1 else None
                        payload = {
                            'action': 'revoke',
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
                    # request list of files owned by user
                    payload = {'action': 'myfiles', 'user_id': interest.user_id, 'password': interest.auth_key}
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

                elif name.startswith('/dlsu/server/auth'):
                    # Direct auth check request from client - forward Interest as-is to server
                    server_route = self.routing_module.lookup_route('/dlsu/server')
                    if server_route:
                        return self._forward_to_next_hop(interest, server_route)

            # For other operations (READ/WRITE), perform auth check with server
            server_route = self.routing_module.lookup_route('/dlsu/server')
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
                        except Exception:
                            auth_allowed = ("AUTHORIZED" in payload or "SUCCESS" in payload)
                            storage_location = None
                            storage_node = None
                            is_new_file = True

                    if auth_allowed:
                        # If WRITE: return authorization + assignment, do not forward
                        if interest.operation.upper() == 'WRITE':
                            if storage_location and not is_new_file:
                                # File exists - use the existing storage location
                                self._log_debug(f"📦 File exists at {storage_location} ({storage_node}) - using existing location", "permission")
                                assigned_hostport = storage_location
                            else:
                                # New file - use round-robin selection OR RAID preference
                                raid_pref = self._parse_raid_preference(interest)
                                assigned_hostport = self._select_storage_node(raid_pref)
                                self._log_debug(f"📦 New file - assigned storage via round-robin: {assigned_hostport}", "permission")
                            
                            msg = {'authorized': True, 'assigned_storage': assigned_hostport, 'storage_node': storage_node, 'is_new_file': is_new_file}
                            from common import DataPacket
                            import json as _json
                            dp = DataPacket(name=interest.name, data_payload=_json.dumps(msg).encode('utf-8'))
                            return dp.to_json()
                        elif interest.operation.upper() == 'DELETE':
                            # DELETE: First ask server to delete from DB (validates ownership), then forward to storage
                            # Send delete_file action to server
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
                                        storage_locs = delete_result.get('storage_locations', [])
                                        if storage_locs:
                                            for loc in storage_locs:
                                                loc_host = loc.get('host', '127.0.0.1')
                                                loc_port = loc.get('port', 9001)
                                                try:
                                                    self._forward_to_next_hop(interest, f"{loc_host}:{loc_port}")
                                                except Exception:
                                                    pass
                                        msg = {'success': True, 'deleted': resource_to_check, 'message': 'File deleted from DB and storage'}
                                        dp = DataPacket(name=interest.name, data_payload=_json.dumps(msg).encode('utf-8'))
                                        return dp.to_json()
                                    else:
                                        # Delete denied (not owner or not found)
                                        return self._create_error_response(delete_result if isinstance(delete_result, str) else _json.dumps(delete_result))
                                except Exception as e:
                                    return self._create_error_response(f"Delete error: {e}")
                            else:
                                return self._create_error_response("Delete failed: no response from server")
                        else:
                            # READ: use server's storage location if provided, otherwise FIB lookup
                            if storage_location:
                                self._log_debug(f"✅ Authorized - forwarding READ to {storage_location} ({storage_node})", "data")
                                return self._forward_to_next_hop(interest, storage_location)
                            else:
                                storage_route = self.routing_module.lookup_route(interest.name)
                                if storage_route:
                                    self._log_debug(f"✅ Authorized - forwarding to storage via FIB", "data")
                                    return self._forward_to_next_hop(interest, storage_route)
                                else:
                                    return self._create_error_response("No storage route found")
                    else:
                        return self._create_error_response("Permission denied")

                except Exception as e:
                    return self._create_error_response(f"Permission denied (auth error: {e})")

        # Generic forwarding for routers (use FIB lookup)
        route = self.routing_module.lookup_route(interest.name)
        if route:
            self._log_debug(f"📤 Forwarding Interest via FIB to {route.next_hop if hasattr(route, 'next_hop') else route}", "interest")
            return self._forward_to_next_hop(interest, route)

        return None
    
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

    def _forward_to_next_hop(self, interest, route_or_next_hop, timeout: float = None):
        """Generic forwarder: accepts a RoutingEntry or 'host:port' string and forwards Interest.
        
        Args:
            interest: InterestPacket to forward
            route_or_next_hop: RoutingEntry object or 'host:port' string
            timeout: Optional timeout override (default uses 10s for auth, 5s otherwise)
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
                return None

        except Exception as e:
            self._log_debug(f"❌ _forward_to_next_hop error: {e}", "error")
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
    
    def _route_data_packet(self, data_packet, source: str):
        """Route Data packet back to requester"""
        self._log_debug(f"📦 DATA packet: {data_packet.name}", "data")
        self._log_debug(f"  Length: {data_packet.data_length} bytes, Checksum: {data_packet.checksum[:8]}...", "content")
        
        # Cache the data packet (skip auth responses - they're specific to individual requests)
        is_auth_response = data_packet.name.startswith('/dlsu/server/auth') or data_packet.name == '/error'
        if not is_auth_response:
            self.processing_module.content_store.put(data_packet.name, data_packet.data_payload)
            self._log_control(f"[CACHE] Stored: {data_packet.name}")
        else:
            self._log_debug(f"[CACHE] Skipped auth/error response: {data_packet.name}", "data")

        # Determine faces from PIT
        entry = self.pit.get(data_packet.name)
        faces = set()
        base_name = None
        if entry:
            faces = entry.get('faces', set()).copy()
        # If no direct match, handle fragment notation by using base name
        if not faces and ':[' in data_packet.name:
            base_name = data_packet.name.split(':[' ,1)[0]
            entry = self.pit.get(base_name)
            if entry:
                faces = entry.get('faces', set()).copy()

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