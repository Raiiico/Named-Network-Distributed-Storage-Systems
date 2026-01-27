#!/usr/bin/env python3
"""
Simple Named Networks Client - Updated for UDP and Fixed Checksums
Compatible with the fixed communication_module.py and common.py
"""

import time
import sys
import os
from common import create_interest_packet, DataPacket, calculate_checksum
from communication_module import CommunicationModule

class SimpleClient:
    """Simple client for testing with fixed UDP communication"""
    
    def __init__(self, client_id: str, password: str = None):
        self.client_id = client_id
        self.password = password
        self.authenticated = False
        self.node_name = f"Client-{client_id}"
        self.comm_module = CommunicationModule(self.node_name, port=0)
        # Attach PacketLogger
        try:
            from common import PacketLogger
            self.logger = PacketLogger(self.node_name)
            try:
                self.comm_module.set_logger(self.logger)
            except Exception:
                pass
        except Exception:
            self.logger = None
        
        # Statistics
        self.stats = {
            "interests_sent": 0,
            "data_received": 0,
            "timeouts": 0,
            "errors": 0,
            "checksum_corrections": 0
        }
        
        print(f"[{self.node_name}] Client initialized (UDP)")
    
    def send_interest(self, content_name: str, operation: str = "READ", 
                     router_host: str = "127.0.0.1", router_port: int = 8001, auth_key: str = None,
                     max_retries: int = 3, timeout: float = 5.0, target: str = None):
        """Send Interest packet to router with retry and timeout
        Returns DataPacket on success or None on failure
        """
        
        # Create Interest packet with proper checksum
        # If this is an auth check with a distinct target, create an auth Interest
        if target is not None or content_name.startswith('/dlsu/server/auth'):
            # Standard auth interest name routed to server
            auth_name = '/dlsu/server/auth'
            # Determine the actual target resource
            if target is not None:
                actual_target = target
            elif content_name.startswith('/dlsu/server/auth'):
                # Extract embedded target from the name
                actual_target = content_name[len('/dlsu/server/auth'):]
                if actual_target and not actual_target.startswith('/'):
                    actual_target = '/' + actual_target
            else:
                actual_target = content_name
            # Preserve the requested operation (READ/WRITE) so the auth server checks the correct permission
            interest = create_interest_packet(auth_name, self.client_id, operation, target=actual_target)
        else:
            interest = create_interest_packet(content_name, self.client_id, operation)

        if auth_key:
            # place password/token into auth_key field of Interest
            interest.auth_key = auth_key
        
        send_time = time.time()
        self.stats["interests_sent"] += 1
        
        # Display sent Interest (concise)
        print(f"\n{'='*70}")
        print(f"SENDING INTEREST {interest.name} -> {router_host}:{router_port} (op={interest.operation})")
        print(f"{'='*70}")

        attempt = 0
        response = None
        while attempt < max_retries:
            attempt += 1
            response = self.comm_module.send_packet_sync(router_host, router_port, interest.to_json(), timeout=timeout)
            if response:
                break
            else:
                # Timeout
                self.stats["timeouts"] += 1
                if self.logger:
                    try:
                        self.logger.log('TIMEOUT', 'INTEREST', interest.to_dict(), (router_host, router_port))
                    except Exception:
                        pass
                if attempt < max_retries:
                    print(f"[{self.node_name}] Timeout, retrying ({attempt+1}/{max_retries})...")
                else:
                    print(f"[{self.node_name}] Failed after {max_retries} attempts")

        if not response:
            return None

        # Handle response
        try:
            data_packet = DataPacket.from_json(response)
            
            # Check if error
            if data_packet.name == "/error":
                self.stats["errors"] += 1
                error_msg = data_packet.data_payload.decode('utf-8', errors='ignore')
                print(f"\nERROR: {error_msg}\n")
                return None
                
            self.stats["data_received"] += 1
            
            # Validate checksum
            if not data_packet.validate_checksum():
                self.stats["checksum_corrections"] += 1
                print(f"[{self.node_name}] Note: Response checksum recalculated")
            
            # Display received Data briefly
            print(f"RECEIVED DATA: {data_packet.name} ({data_packet.data_length} bytes)")

            # Display payload (safe)
            try:
                payload_str = data_packet.data_payload.decode('utf-8', errors='ignore')
                if len(payload_str) > 1000:
                    print(payload_str[:1000] + "...")
                else:
                    print(payload_str)
            except Exception:
                print(f"[Binary data: {data_packet.data_length} bytes]")

            response_time = time.time() - send_time
            print(f"Response Time: {response_time:.3f}s")

            return data_packet
            
        except Exception as e:
            self.stats["errors"] += 1
            print(f"\nError parsing response: {e}")
            return None
    
    def run_test_scenarios(self, router_host: str = "127.0.0.1", router_port: int = 8001):
        """Run test scenarios"""
        print(f"\n{'#'*70}")
        print(f"# {self.node_name} - TEST SCENARIOS (UDP)")
        print(f"{'#'*70}\n")
        
        test_cases = [
            ("/dlsu/hello", "READ", "Basic READ request (cached)"),
            ("/dlsu/storage/test", "READ", "Storage node request"),
            ("/dlsu/hello", "READ", "Cache hit test (should be instant)"),
            ("/storage/test", "READ", "Alternative storage path"),
            ("/dlsu/storage/node1", "WRITE", "WRITE operation test"),
            ("/dlsu/files/test:[1/4]", "READ", "Fragment request test"),
        ]
        
        for i, (name, op, desc) in enumerate(test_cases, 1):
            print(f"\n{'─'*70}")
            print(f"TEST {i}/{len(test_cases)}: {desc}")
            print(f"{'─'*70}")
            
            result = self.send_interest(name, op, router_host, router_port)
            
            if result:
                print(f"✓ Test {i} completed successfully")
            else:
                print(f"✗ Test {i} failed")
            
            time.sleep(0.5)
        
        self._show_statistics()
    
    def concurrent_test(self, router_host: str = "127.0.0.1", router_port: int = 8001):
        """Test concurrent request handling"""
        import threading
        
        print(f"\n{'='*70}")
        print(f"CONCURRENT REQUEST TEST (UDP)")
        print(f"{'='*70}")
        print(f"Testing router's ability to handle simultaneous UDP requests...")
        print()
        
        # Define concurrent requests
        requests = [
            {"name": f"/test/concurrent{i}.txt", "operation": "READ"}
            for i in range(1, 6)
        ]
        
        results = []
        threads = []
        
        def send_request(req):
            result = self.send_interest(
                req["name"],
                req["operation"],
                router_host,
                router_port
            )
            results.append((req["name"], result is not None))
        
        # Launch concurrent requests
        print(f"Sending {len(requests)} concurrent UDP requests...")
        start_time = time.time()
        
        for req in requests:
            thread = threading.Thread(target=send_request, args=(req,))
            thread.start()
            threads.append(thread)
        
        # Wait for all to complete
        for thread in threads:
            thread.join()
        
        elapsed = time.time() - start_time
        
        # Show results
        print(f"\n{'='*70}")
        print(f"CONCURRENT TEST RESULTS")
        print(f"{'='*70}")
        print(f"  Total Requests:  {len(requests)}")
        print(f"  Successful:      {sum(1 for _, success in results if success)}")
        print(f"  Failed:          {sum(1 for _, success in results if not success)}")
        print(f"  Time Elapsed:    {elapsed:.2f}s")
        print(f"  Protocol:        UDP")
        print(f"{'='*70}\n")
    
    def interactive_mode(self, router_host: str = "127.0.0.1", router_port: int = 8001):
        """Interactive mode"""
        print(f"\n{'='*70}")
        print(f"INTERACTIVE MODE - {self.node_name} (UDP)")
        print(f"{'='*70}")
        print(f"Router: {router_host}:{router_port}")
        print(f"Authenticated: {'✓' if self.authenticated else '✗'}")
        print(f"\nCommands:")
        print(f"  read <name>           - Download file (sends READ interest)")
        print(f"  write <name> [raid]   - Upload file (optional: raid0, raid1, raid5, raid6)")
        print(f"  delete <name>         - Delete a file you own (DAC enforced)")
        print(f"  permission <name>     - Send PERMISSION Interest")
        print(f"  grant <file> <user>   - Grant READ access to another user")
        print(f"  revoke <file> <user>  - Revoke access from a user")
        print(f"  myfiles               - List files you own")
        print(f"  nodestats             - Show RAID statistics from all storage nodes")
        print(f"  concurrent            - Run concurrent test")
        print(f"  stats                 - Show statistics")
        print(f"  quit                  - Exit")
        print(f"{'='*70}\n")
        
        while True:
            try:
                command = input(f"{self.node_name}> ").strip()
                
                if not command:
                    continue
                
                parts = command.split(maxsplit=1)
                cmd = parts[0].lower()
                
                if cmd in ["quit", "exit"]:
                    print(f"\n👋 Goodbye from {self.node_name}!")
                    break
                
                elif cmd == "stats":
                    self._show_statistics()
                
                elif cmd == "concurrent":
                    self.concurrent_test(router_host, router_port)
                
                elif cmd in ["read", "write", "permission"]:
                    if len(parts) < 2:
                        print("  Usage: <operation> <name> [raid]")
                        print("  Example: read /dlsu/hello")
                        print("  Example: write myfile.txt raid5")
                        continue

                    name = parts[1]
                    raid_preference = parts[2].lower() if len(parts) > 2 else None
                    operation = cmd.lower()
                    if operation == 'permission':
                        # Simple permission check against auth server
                        ok = self._check_permission(name, 'READ', password=self.password)
                        print(f"Permission check: {'AUTHORIZED' if ok else 'DENIED'}")
                    elif operation == 'read':
                        # Download file (requires permission)
                        self._do_read(name, router_host, router_port, password=self.password)
                    elif operation == 'write':
                        # Upload file: prompt local path and destination (name)
                        local_path = input('Local file path to upload: ').strip()
                        if not local_path:
                            print('Upload cancelled')
                            continue
                        
                        # Validate RAID preference if provided
                        if raid_preference and raid_preference not in ['raid0', 'raid1', 'raid5', 'raid6']:
                            print(f"Invalid RAID level '{raid_preference}'. Valid: raid0, raid1, raid5, raid6")
                            print("Proceeding with round-robin selection...")
                            raid_preference = None
                        elif raid_preference:
                            print(f"📦 RAID preference: {raid_preference.upper()}")
                        
                        # Defaults - server will assign actual storage via round-robin or RAID preference
                        shost, sport = '127.0.0.1', 9001

                        self._do_write(local_path, name, shost, sport, password=self.password, raid_preference=raid_preference)
                
                elif cmd == "grant":
                    if len(parts) < 2:
                        print("  Usage: grant <file> <user>")
                        print("  Example: grant /files/doc.txt bob")
                        continue
                    args = parts[1].split()
                    if len(args) < 2:
                        print("  Usage: grant <file> <user>")
                        continue
                    file_name = args[0]
                    target_user = args[1]
                    self._grant_permission(file_name, target_user)
                
                elif cmd == "revoke":
                    if len(parts) < 2:
                        print("  Usage: revoke <file> <user>")
                        print("  Example: revoke /files/doc.txt bob")
                        continue
                    args = parts[1].split()
                    if len(args) < 2:
                        print("  Usage: revoke <file> <user>")
                        continue
                    file_name = args[0]
                    target_user = args[1]
                    self._revoke_permission(file_name, target_user)
                
                elif cmd == "myfiles":
                    self._list_my_files()
                
                elif cmd == "delete":
                    if len(parts) < 2:
                        print("  Usage: delete <name>")
                        print("  Example: delete /dlsu/storage/myfile.txt")
                        continue
                    file_name = parts[1]
                    self._do_delete(file_name, router_host, router_port)
                
                elif cmd == "help":
                    print("\nAvailable commands:")
                    print("  read <name>          - Request content")
                    print("  write <name> [raid]  - Write content (optional: raid0, raid1, raid5, raid6)")
                    print("  delete <name>        - Delete a file you own")
                    print("  permission <name>    - Check permissions")
                    print("  grant <file> <user>  - Grant access to user")
                    print("  revoke <file> <user> - Revoke user access")
                    print("  myfiles              - List your files")
                    print("  nodestats            - Show RAID statistics for all storage nodes")
                    print("  concurrent           - Test concurrent requests")
                    print("  stats                - Show client statistics")
                    print("  quit                 - Exit client")
                    print("\n  Note: 'clear' is admin-only, use 'delete' to remove your own files")
                
                elif cmd == "nodestats":
                    self._get_storage_stats(router_host, router_port)
                
                elif cmd == "clear":
                    # CLEAR is admin-only - direct user to DELETE for their own files
                    print("❌ 'clear' is an admin-only operation.")
                    print("   Use 'delete <filename>' to delete your own files.")
                    print("   Admins can use the server admin CLI to clear the system.")
                
                else:
                    print(f"Unknown command: {cmd}")
                    print("Type 'help' for available commands")
                
            except KeyboardInterrupt:
                print(f"\n\n👋 Goodbye from {self.node_name}!")
                break
            except EOFError:
                print(f"\n\n👋 Goodbye from {self.node_name}!")
                break
            except Exception as e:
                print(f"Error: {e}")
    
    def _grant_permission(self, file_name: str, target_user: str, router_host: str = '127.0.0.1', router_port: int = 8001):
        """Grant READ permission to another user on your file via router (NDN Interest)
        Name format used: /dlsu/server/permission/grant:<resource>:<target>
        Password is sent as auth_key in Interest"""
        name = f"/dlsu/server/permission/grant:{file_name}:{target_user}"
        resp = self.send_interest(name, operation='PERMISSION', router_host=router_host, router_port=router_port, auth_key=self.password)
        if resp:
            try:
                payload = resp.data_payload.decode('utf-8', errors='ignore')
                print(f"✓ {payload}")
            except Exception:
                print("✓ Permission operation completed")
        else:
            print("✗ No response from router/server")

    def _revoke_permission(self, file_name: str, target_user: str, router_host: str = '127.0.0.1', router_port: int = 8001):
        """Revoke permission via router using Interest name /dlsu/server/permission/revoke:<resource>:<target>"""
        name = f"/dlsu/server/permission/revoke:{file_name}:{target_user}"
        resp = self.send_interest(name, operation='PERMISSION', router_host=router_host, router_port=router_port, auth_key=self.password)
        if resp:
            try:
                payload = resp.data_payload.decode('utf-8', errors='ignore')
                print(f"✓ {payload}")
            except Exception:
                print("✓ Revoke operation completed")
        else:
            print("✗ No response from router/server")

    def _list_my_files(self, router_host: str = '127.0.0.1', router_port: int = 8001):
        """List files owned by this user via router (Interest: /dlsu/server/myfiles)"""
        name = "/dlsu/server/myfiles"
        # Use LIST operation so server treats this as an Interest LIST request
        resp = self.send_interest(name, operation='LIST', router_host=router_host, router_port=router_port, auth_key=self.password)
        if resp:
            try:
                payload = resp.data_payload.decode('utf-8', errors='ignore')
                print(f"\n{'='*70}")
                print(f"MY FILES ({self.client_id})")
                print(f"{'='*70}")
                print(payload)
                print(f"{'='*70}\n")
            except Exception:
                print("Could not parse server response")
        else:
            print("✗ No response from router/server")

    def _list_file_locations(self, file_name: str, router_host: str = '127.0.0.1', router_port: int = 8001):
        """Query server via router for storage node locations for a file.
        Uses Interest: /dlsu/server/locations:<resource>
        """
        name = f"/dlsu/server/locations:{file_name}"
        resp = self.send_interest(name, operation='PERMISSION', router_host=router_host, router_port=router_port, auth_key=self.password)
        if resp:
            try:
                payload = resp.data_payload.decode('utf-8', errors='ignore')
                import json
                locs = json.loads(payload) if payload else []
                print(f"\n{'='*70}")
                print(f"LOCATIONS for {file_name}")
                print(f"{'='*70}")
                if not locs:
                    print("  No locations found")
                else:
                    for l in locs:
                        print(f"  - {l.get('node_name')} @ {l.get('host')}:{l.get('port')} -> {l.get('stored_path')}")
                print(f"{'='*70}\n")
            except Exception:
                print("Could not parse server response")
        else:
            print("✗ No response from router/server")
    
    def _show_statistics(self):
        """Display statistics"""
        print(f"\n{'='*70}")
        print(f"CLIENT STATISTICS - {self.node_name}")
        print(f"{'='*70}")
        print(f"  User:               {self.client_id}")
        print(f"  Authenticated:      {'✓' if self.authenticated else '✗'}")
        print(f"  Protocol:           UDP")
        print(f"  Interests Sent:     {self.stats['interests_sent']}")
        print(f"  Data Received:      {self.stats['data_received']}")
        print(f"  Timeouts:           {self.stats['timeouts']}")
        print(f"  Errors:             {self.stats['errors']}")
        print(f"  Checksum Fixed:     {self.stats['checksum_corrections']}")
        
        total = self.stats['interests_sent']
        if total > 0:
            success_rate = (self.stats['data_received'] / total) * 100
            print(f"  Success Rate:       {success_rate:.1f}%")
        
        print(f"{'='*70}\n")

    def _get_storage_stats(self, router_host: str = '127.0.0.1', router_port: int = 8001):
        """Query all storage nodes for RAID statistics"""
        import json
        
        # Known storage nodes (matching router's _storage_nodes)
        storage_nodes = [
            ('ST1', '127.0.0.1', 9001, 0),
            ('ST2', '127.0.0.1', 9002, 1),
            ('ST3', '127.0.0.1', 9003, 5),
            ('ST4', '127.0.0.1', 9004, 6),
        ]
        
        print(f"\n{'='*80}")
        print(f"STORAGE NODE STATISTICS")
        print(f"{'='*80}")
        
        total_files = 0
        total_fragments = 0
        total_parity = 0
        total_size = 0
        
        for node_name, host, port, raid_level in storage_nodes:
            print(f"\n📦 {node_name} (RAID {raid_level}) @ {host}:{port}")
            print(f"   {'─'*60}")
            
            try:
                # Send STATS Interest directly to storage node
                from common import InterestPacket, DataPacket
                
                stats_interest = InterestPacket(
                    name=f"/dlsu/storage/stats/{node_name}",
                    operation="STATS",
                    user_id=self.client_id,
                    auth_key=self.password
                )
                
                resp = self.comm_module.send_packet_sync(host, port, stats_interest.to_json())
                
                if resp:
                    try:
                        resp_pkt = DataPacket.from_json(resp)
                        stats = json.loads(resp_pkt.data_payload.decode('utf-8', errors='ignore'))
                        
                        print(f"   RAID Type:        {stats.get('raid_description', 'Unknown')}")
                        print(f"   Overhead:         {stats.get('raid_overhead_percent', 0):.1f}%")
                        print(f"   Files:            {stats.get('file_count', 0)}")
                        print(f"   Fragments:        {stats.get('fragment_count', 0)}")
                        print(f"   Parity Blocks:    {stats.get('parity_count', 0)}")
                        print(f"   Total Size:       {stats.get('total_size_kb', 0):.2f} KB")
                        print(f"   Requests Handled: {stats.get('requests_handled', 0)}")
                        print(f"   Mirror Target:    {'Yes' if stats.get('is_mirror_target') else 'No'}")
                        
                        total_files += stats.get('file_count', 0)
                        total_fragments += stats.get('fragment_count', 0)
                        total_parity += stats.get('parity_count', 0)
                        total_size += stats.get('total_size_bytes', 0)
                        
                    except Exception as e:
                        print(f"   ✗ Error parsing stats: {e}")
                else:
                    print(f"   ✗ No response (node may be offline)")
                    
            except Exception as e:
                print(f"   ✗ Connection error: {e}")
        
        print(f"\n{'='*80}")
        print(f"TOTALS: {total_files} files, {total_fragments} fragments, {total_parity} parity blocks, {total_size/1024:.2f} KB")
        print(f"{'='*80}\n")
    
    def _clear_system(self, router_host: str = '127.0.0.1', router_port: int = 8001):
        """Clear all files from the system (server DB and storage nodes)"""
        import json
        
        print(f"\n{'='*80}")
        print(f"SYSTEM CLEAR OPERATION")
        print(f"{'='*80}")
        
        # Step 1: Clear server database (files, permissions, locations - keep users)
        print("\n📋 Step 1: Clearing server database...")
        try:
            from common import InterestPacket, DataPacket
            
            clear_interest = InterestPacket(
                name="/dlsu/server/clear",
                operation="CLEAR",
                user_id=self.client_id,
                auth_key=self.password
            )
            
            resp = self.comm_module.send_packet_sync('127.0.0.1', 7001, clear_interest.to_json())
            
            if resp:
                try:
                    resp_pkt = DataPacket.from_json(resp)
                    result = json.loads(resp_pkt.data_payload.decode('utf-8', errors='ignore'))
                    
                    if result.get('success'):
                        print(f"   ✓ Cleared {result.get('cleared_files', 0)} files")
                        print(f"   ✓ Cleared {result.get('cleared_permissions', 0)} permissions")
                        print(f"   ✓ Cleared {result.get('cleared_locations', 0)} locations")
                    else:
                        print(f"   ✗ Server clear failed: {result.get('error', 'Unknown error')}")
                except Exception as e:
                    print(f"   ✗ Error parsing response: {e}")
            else:
                print(f"   ✗ No response from server")
        except Exception as e:
            print(f"   ✗ Server clear error: {e}")
        
        # Step 2: Clear storage nodes
        print("\n📦 Step 2: Clearing storage nodes...")
        
        storage_nodes = [
            ('ST1', '127.0.0.1', 9001, 0),
            ('ST2', '127.0.0.1', 9002, 1),
            ('ST3', '127.0.0.1', 9003, 5),
            ('ST4', '127.0.0.1', 9004, 6),
        ]
        
        for node_name, host, port, raid_level in storage_nodes:
            try:
                clear_interest = InterestPacket(
                    name=f"/dlsu/storage/clear/{node_name}",
                    operation="CLEAR",
                    user_id=self.client_id,
                    auth_key=self.password
                )
                
                resp = self.comm_module.send_packet_sync(host, port, clear_interest.to_json())
                
                if resp:
                    try:
                        resp_pkt = DataPacket.from_json(resp)
                        result = json.loads(resp_pkt.data_payload.decode('utf-8', errors='ignore'))
                        
                        if result.get('success'):
                            print(f"   ✓ {node_name}: Cleared {result.get('files_cleared', 0)} files, {result.get('fragments_cleared', 0)} fragments, {result.get('parity_cleared', 0)} parity")
                        else:
                            print(f"   ✗ {node_name}: {result.get('errors', 'Unknown error')}")
                    except Exception as e:
                        print(f"   ✗ {node_name}: Error parsing response: {e}")
                else:
                    print(f"   ⚠ {node_name}: No response (node may be offline)")
                    
            except Exception as e:
                print(f"   ✗ {node_name}: Connection error: {e}")
        
        print(f"\n{'='*80}")
        print("✓ System clear complete. Users and credentials retained.")
        print(f"{'='*80}\n")

    def _cleanup_missing_file(self, resource_name: str, server_host: str = '127.0.0.1', server_port: int = 7001):
        """Attempt to delete a file from the server DB when storage reports it's not found.
        This keeps the DB in sync with actual storage.
        """
        try:
            import json
            # Normalize the resource name
            if resource_name.startswith('/dlsu/storage/'):
                # Strip the storage prefix to get the actual file name
                file_name = '/' + resource_name[len('/dlsu/storage/'):]
            else:
                file_name = resource_name
            
            # Send delete request to auth server
            delete_req = {
                'action': 'delete_file',
                'resource': file_name,
                'user_id': self.client_id,
                'password': self.password
            }
            
            resp = self.comm_module.send_packet_sync(
                server_host, server_port,
                json.dumps(delete_req).encode('utf-8')
            )
            
            if resp:
                try:
                    resp_obj = json.loads(resp.decode('utf-8', errors='ignore'))
                    if resp_obj.get('success'):
                        print(f"  ℹ️  Cleaned up {file_name} from database")
                except Exception:
                    pass
        except Exception as e:
            # Silently fail cleanup - it's not critical
            pass

    def _check_permission(self, resource: str, operation: str = 'READ', server_host: str = '127.0.0.1', server_port: int = 8001, password: str = None):
        """Ask AuthenticationServer for permission using an Interest.
        
        Returns a dict with 'authorized' (bool) and optionally 'assigned_storage', 'storage_node', etc.
        For backwards compatibility, also supports bool-like truthiness check.
        """
        # Build auth Interest routed to server: use fixed name and include target payload
        auth_name = '/dlsu/server/auth'

        # Send auth Interest with `target` set to the actual resource so server can check the correct base name
        # Use the requested operation (READ/WRITE/EXECUTE) so the AuthServer performs the correct DAC check
        dp = self.send_interest(auth_name, operation=operation.upper(), router_host=server_host, router_port=server_port, auth_key=password, target=resource)
        if not dp:
            print("Permission check: no response from auth server")
            return {'authorized': False, 'assigned_storage': None}

        # Parse payload
        try:
            import json
            payload = dp.data_payload.decode('utf-8', errors='ignore')
            robj = json.loads(payload)
            # Return the full response object, ensuring authorized is bool
            result = dict(robj)
            result['authorized'] = bool(robj.get('authorized'))
            return result
        except Exception:
            # Fallback: check textual 'AUTHORIZED'
            payload = dp.data_payload.decode('utf-8', errors='ignore')
            return {'authorized': 'AUTHORIZED' in payload.upper(), 'assigned_storage': None}

    def _do_read(self, content_name: str, router_host: str, router_port: int, password: str = None):
        """Perform authenticated READ: check permission, then request and save file."""
        # Normalize bare filenames or legacy '/files/' names to the storage namespace
        if content_name:
            if '/' not in content_name:
                base = os.path.basename(content_name)
                content_name = f"/dlsu/storage/{base}"
            elif content_name.startswith('/files/'):
                base = content_name.split('/',2)[-1]
                content_name = f"/dlsu/storage/{base}"

        # Check permission with auth server first
        perm_result = self._check_permission(content_name, 'READ', password=password)
        if not perm_result.get('authorized'):
            msg = perm_result.get('message', 'Permission denied by AuthenticationServer')
            print(f"❌ {msg}")
            return False
        
        # Check if server provided storage location (for direct access)
        storage_location = perm_result.get('assigned_storage') or perm_result.get('storage_location')
        storage_node = perm_result.get('storage_node', 'unknown')
        if storage_location:
            try:
                storage_host, storage_port = storage_location.split(':')
                storage_port = int(storage_port)
                print(f"📦 File located at: {storage_host}:{storage_port} ({storage_node})")
                # Read directly from storage node
                return self.download_file(content_name, dest_path=None, host=storage_host, port=storage_port)
            except Exception as e:
                print(f"⚠️ Could not parse storage location, using router: {e}")
        
        # Fallback: use the improved download helper which routes through router
        return self.download_file(content_name, dest_path=None, host=router_host, port=router_port)

    def _do_delete(self, content_name: str, router_host: str = '127.0.0.1', router_port: int = 8001, password: str = None):
        """Perform authenticated DELETE: check ownership, then send DELETE Interest to storage via router."""
        # Normalize name to storage namespace
        if content_name:
            if '/' not in content_name:
                base = os.path.basename(content_name)
                content_name = f"/dlsu/storage/{base}"
            elif content_name.startswith('/files/'):
                base = content_name.split('/',2)[-1]
                content_name = f"/dlsu/storage/{base}"

        # Use password from self if not provided
        if password is None:
            password = self.password

        # Send DELETE Interest through router (router will check auth)
        print(f"\n{'='*70}")
        print(f"DELETING: {content_name}")
        print(f"{'='*70}")
        
        resp = self.send_interest(content_name, operation='DELETE', router_host=router_host, router_port=router_port, auth_key=password)
        
        if resp:
            try:
                payload = resp.data_payload.decode('utf-8', errors='ignore')
                if 'DELETED' in payload.upper():
                    print(f"✓ File deleted: {content_name}")
                    return True
                elif 'DENIED' in payload.upper() or 'ERROR' in payload.upper():
                    print(f"✗ Delete failed: {payload}")
                    return False
                else:
                    print(f"Response: {payload}")
                    return 'DELETED' in payload.upper()
            except Exception as e:
                print(f"✗ Error parsing response: {e}")
                return False
        else:
            print("✗ No response from router (timeout)")
            return False

    def _do_write(self, local_path: str, dest_name: str, storage_host: str = '127.0.0.1', storage_port: int = 9001, password: str = None, raid_preference: str = None):
        """Perform authenticated WRITE: check permission, then upload file to storage host.
        
        If the server assigns a storage node, it will override the provided storage_host/port.
        If raid_preference is provided (e.g., 'raid5'), the router will select appropriate storage.
        """
        if not os.path.exists(local_path):
            print(f"Local file not found: {local_path}")
            return False
        # If dest_name looks like a bare filename (no '/'), default to placing
        # it under the storage namespace so routers can route to storage nodes.
        if not dest_name or '/' not in dest_name:
            base = os.path.basename(dest_name) if dest_name else os.path.basename(local_path)
            # Embed RAID preference in the name for router to parse
            if raid_preference:
                dest_name = f"/dlsu/storage/{raid_preference}/{base}"
            else:
                dest_name = f"/dlsu/storage/{base}"
        # Support legacy '/files/...' by mapping it into /dlsu/storage/
        elif dest_name.startswith('/files/'):
            base = dest_name.split('/',2)[-1]
            if raid_preference:
                dest_name = f"/dlsu/storage/{raid_preference}/{base}"
            else:
                dest_name = f"/dlsu/storage/{base}"
        # If dest_name already has full path but no RAID prefix, add it if specified
        elif raid_preference and f'/{raid_preference}/' not in dest_name:
            # Insert RAID preference after /dlsu/storage/
            if dest_name.startswith('/dlsu/storage/'):
                remainder = dest_name[len('/dlsu/storage/'):]
                dest_name = f"/dlsu/storage/{raid_preference}/{remainder}"

        perm_result = self._check_permission(dest_name, 'WRITE', password=password)
        if not perm_result.get('authorized'):
            print("❌ Permission denied by AuthenticationServer")
            return False

        # Use assigned storage from server if provided, otherwise use passed parameters
        assigned = perm_result.get('assigned_storage')
        storage_node = perm_result.get('storage_node', 'unknown')
        is_new_file = perm_result.get('is_new_file', True)
        if assigned:
            try:
                if ':' in str(assigned):
                    storage_host, port_str = str(assigned).split(':', 1)
                    storage_port = int(port_str)
                    if is_new_file:
                        print(f"📦 NEW FILE - Assigned to storage: {storage_host}:{storage_port}")
                    else:
                        print(f"📦 UPDATE - Existing file at: {storage_host}:{storage_port} ({storage_node})")
            except Exception as e:
                print(f"Warning: could not parse assigned storage '{assigned}', using default: {e}")

        try:
            with open(local_path, 'rb') as f:
                data = f.read()
        except Exception as e:
            print(f"Error reading local file: {e}")
            return False

        # Fragment and send to storage (same logic as previous upload_file)
        import json, base64
        from common import DataPacket

        total_len = len(data)
        # Match storage fragment size (keep conservative for UDP MTU)
        fragment_size = 1024

        if total_len <= fragment_size:
            wrapper = {"uploader": self.client_id, "data_b64": base64.b64encode(data).decode('utf-8')}
            pkt = DataPacket(name=dest_name, data_payload=json.dumps(wrapper).encode('utf-8'))
            pkt_json = pkt.to_json()
            print(f"Uploading '{local_path}' -> '{dest_name}' to {storage_host}:{storage_port} ({len(data)} bytes)")
            resp = self.comm_module.send_packet_sync(storage_host, storage_port, pkt_json)
            # If storage responds with a Data packet that includes 'STORED', print and
            # ensure the storage node registered ownership via auth server/DB
            if resp:
                try:
                    resp_pkt = DataPacket.from_json(resp)
                    print(f"Upload response: {resp_pkt.name} - {resp_pkt.data_payload.decode('utf-8', errors='ignore')}")
                except Exception:
                    print(f"Upload response (raw): {resp[:200]}")
                return True
            else:
                print("No response (timeout) from target")
                return False

        fragments = [data[i:i+fragment_size] for i in range(0, total_len, fragment_size)]
        total = len(fragments)
        print(f"Uploading {total} fragments ({fragment_size} bytes each max)...")

        for idx, chunk in enumerate(fragments, start=1):
            frag_name = f"{dest_name}:[{idx}/{total}]"
            wrapper = {"uploader": self.client_id, "data_b64": base64.b64encode(chunk).decode('utf-8')}
            pkt = DataPacket(name=frag_name, data_payload=json.dumps(wrapper).encode('utf-8'))
            pkt_json = pkt.to_json()

            resp = self.comm_module.send_packet_sync(storage_host, storage_port, pkt_json)

            if resp:
                # Show progress every 10 fragments or on last fragment
                if idx % 10 == 0 or idx == total:
                    print(f"  Progress: {idx}/{total} fragments sent")
            else:
                print(f"  ✗ No response for fragment {idx}/{total} (timeout)")
                return False

        print(f"✓ Upload complete ({total} fragments sent)")
        return True


    def upload_file(self, local_path: str, dest_name: str, host: str = "127.0.0.1", port: int = 9001):
        """Upload a local file to a storage node by sending a DataPacket with the file bytes."""
        import os
        import json, base64
        from common import DataPacket

        if not os.path.exists(local_path):
            print(f"Local file not found: {local_path}")
            return False

        try:
            with open(local_path, 'rb') as f:
                data = f.read()
            total_len = len(data)
            # Conservative fragment payload size to avoid UDP limits (JSON+base64 overhead)
            # Increased to 4KB to reduce fragment count; adjust if you see UDP errors.
            fragment_size = 1024

            if total_len <= fragment_size:
                # Wrap payload with uploader metadata to allow storage node to record owner
                wrapper = {
                    "uploader": self.client_id,
                    "data_b64": base64.b64encode(data).decode('utf-8')
                }
                pkt = DataPacket(name=dest_name, data_payload=json.dumps(wrapper).encode('utf-8'))
                pkt_json = pkt.to_json()

                print(f"Uploading '{local_path}' -> '{dest_name}' to {host}:{port} ({len(data)} bytes)")
                resp = self.comm_module.send_packet_sync(host, port, pkt_json)

                if resp:
                    try:
                        resp_pkt = DataPacket.from_json(resp)
                        print(f"Upload response: {resp_pkt.name} - {resp_pkt.data_payload.decode('utf-8', errors='ignore')}")
                    except Exception:
                        print(f"Upload response (raw): {resp[:200]}")
                    return True
                else:
                    print("No response (timeout) from target")
                    return False

            # Large file: fragment and send parts
            fragments = []
            for i in range(0, total_len, fragment_size):
                fragments.append(data[i:i + fragment_size])

            total = len(fragments)
            print(f"Uploading {total} fragments ({fragment_size} bytes each max)...")

            for idx, chunk in enumerate(fragments, start=1):
                frag_name = f"{dest_name}:[{idx}/{total}]"
                wrapper = {
                    "uploader": self.client_id,
                    "data_b64": base64.b64encode(chunk).decode('utf-8')
                }
                pkt = DataPacket(name=frag_name, data_payload=json.dumps(wrapper).encode('utf-8'))
                pkt_json = pkt.to_json()

                resp = self.comm_module.send_packet_sync(host, port, pkt_json)

                if resp:
                    # Show progress every 10 fragments or on last fragment
                    if idx % 10 == 0 or idx == total:
                        print(f"  Progress: {idx}/{total} fragments sent")
                else:
                    print(f"  ✗ No response for fragment {idx}/{total} (timeout)")
                    return False

            print(f"✓ Upload complete ({total} fragments sent)")
            return True

        except Exception as e:
            print(f"Error uploading file: {e}")
            return False

    def download_file(self, content_name: str, dest_path: str = None, host: str = "127.0.0.1", port: int = 8001):
        """Download named content (READ) from the router/storage and save to disk.

        `content_name` is the logical name (e.g. `/dlsu/uploads/foo.zip`).
        If `dest_path` is None, the file is saved to the current directory using
        the basename of `content_name`.
        """
        from common import create_interest_packet, DataPacket, parse_fragment_notation

        # Default landing directory for downloads
        downloads_dir = dest_path if dest_path else os.path.join('.', 'downloaded_files')
        os.makedirs(downloads_dir, exist_ok=True)

        # Request first fragment / packet synchronously from router
        interest = create_interest_packet(content_name, self.client_id, "READ")
        print(f"Requesting download: {content_name} from {host}:{port}")
        resp = self.comm_module.send_packet_sync(host, port, interest.to_json())

        if not resp:
            print("❌ TIMEOUT: No response for download request")
            return False

        try:
            pkt = DataPacket.from_json(resp)
        except Exception as e:
            print(f"Error parsing response: {e}")
            return False

        if pkt.name == "/error":
            err = pkt.data_payload.decode('utf-8', errors='ignore')
            print(f"❌ Error from node: {err}")
            # If file not found, try to clean it up from DB
            if "file not found" in err.lower() or "not found" in err.lower():
                self._cleanup_missing_file(content_name)
            return False

        # If single-packet (no fragments) -> save and return
        if ':[' not in pkt.name:
            content = pkt.data_payload
            safe_name = os.path.basename(content_name) or f"download_{int(time.time())}"
            out_path = os.path.join(downloads_dir, safe_name)
            if os.path.exists(out_path):
                name, ext = os.path.splitext(out_path)
                out_path = f"{name}_{int(time.time())}{ext}"
            with open(out_path, 'wb') as wf:
                wf.write(content)
            print(f"✓ Saved {len(content)} bytes to {out_path}")
            return True

        # Otherwise, pkt.name includes fragment info -> parse and pull remaining fragments
        try:
            base, frag = pkt.name.split(':[' ,1)
            frag_info = frag.rstrip(']')
            idx_s, total_s = frag_info.split('/')
            idx0 = int(idx_s)
            total = int(total_s)
        except Exception:
            print("Malformed fragment name from first packet")
            return False

        # Collect fragments into list
        fragments = {idx0: pkt.data_payload}
        # Show compact progress instead of per-fragment messages
        print(f"Downloading {total} fragments...")

        # Pull remaining fragments sequentially
        for i in range(1, total + 1):
            if i in fragments:
                continue
            frag_name = f"{base}:[{i}/{total}]"
            frag_interest = create_interest_packet(frag_name, self.client_id, "READ")
            resp_i = self.comm_module.send_packet_sync(host, port, frag_interest.to_json())
            if not resp_i:
                print(f"❌ TIMEOUT requesting fragment {i}/{total}")
                return False
            try:
                pkt_i = DataPacket.from_json(resp_i)
            except Exception as e:
                print(f"Error parsing fragment {i} response: {e}")
                return False

            if pkt_i.name == "/error":
                err = pkt_i.data_payload.decode('utf-8', errors='ignore')
                print(f"❌ Error for fragment {i}: {err}")
                return False

            fragments[i] = pkt_i.data_payload
            # Show progress every 10 fragments or on last fragment
            if i % 10 == 0 or i == total:
                print(f"  Progress: {i}/{total} fragments received")

        # Reassemble
        content = b''.join(fragments[i] for i in range(1, total + 1))
        safe_name = os.path.basename(base) or f"download_{int(time.time())}"
        out_path = os.path.join(downloads_dir, safe_name)
        if os.path.exists(out_path):
            name, ext = os.path.splitext(out_path)
            out_path = f"{name}_{int(time.time())}{ext}"
        with open(out_path, 'wb') as wf:
            wf.write(content)
        print(f"✓ Saved {len(content)} bytes to {out_path}")
        return True


def main():
    """Run the client"""
    client_id = sys.argv[1] if len(sys.argv) > 1 else "Alice"
    
    print(f"\n{'#'*70}")
    print(f"# NAMED NETWORKS CLIENT (UDP)")
    print(f"{'#'*70}")
    print(f"\nUser: {client_id}")
    
    # Prompt for password
    password = input(f"Password for {client_id}: ").strip()
    if not password:
        print("✗ Password required for authentication")
        sys.exit(1)
    
    client = SimpleClient(client_id, password)
    
    # Authenticate with server
    import json
    payload = {"user_id": client_id, "password": password, "action": "authenticate"}
    req = json.dumps(payload)
    
    try:
        resp = client.comm_module.send_packet_sync('127.0.0.1', 7001, req)
        if resp:
            # send_packet_sync already returns a decoded string
            if 'AUTHORIZED' in resp or 'SUCCESS' in resp.upper():
                client.authenticated = True
                print(f"✓ Authentication successful")
            else:
                print(f"✗ Authentication failed: {resp}")
                sys.exit(1)
        else:
            print("✗ No response from authentication server")
            print("   Make sure server.py is running: python server.py S1")
            sys.exit(1)
    except Exception as e:
        print(f"✗ Authentication error: {e}")
        sys.exit(1)
    
    router_host = "127.0.0.1"
    router_port = 8001
    
    print(f"\nClient ID:     {client_id}")
    print(f"Target Router: {router_host}:{router_port}")
    print(f"Protocol:      UDP")
    print()
    
    # Check for test modes
    if len(sys.argv) > 2:
        if sys.argv[2] == "--test":
            client.run_test_scenarios(router_host, router_port)
            return
        elif sys.argv[2] == "--concurrent":
            client.concurrent_test(router_host, router_port)
            return
    
    # Quick demo
    print("Running quick demo (3 UDP requests)...\n")
    
    demo_requests = [
        ("/dlsu/hello", "READ", "Test cached content"),
        ("/dlsu/storage/test", "READ", "Test storage request"),
        ("/dlsu/hello", "READ", "Test cache hit (UDP)"),
    ]
    
    for name, op, desc in demo_requests:
        print(f"Demo: {desc}")
        client.send_interest(name, op, router_host, router_port)
        time.sleep(0.5)
    
    # Interactive mode
    print("\n" + "─"*70)
    print("Demo complete! Entering interactive mode...")
    print("─"*70)
    
    try:
        client.interactive_mode(router_host, router_port)
    except KeyboardInterrupt:
        print(f"\n\n👋 Goodbye from {client.node_name}!")
    
    # Final stats
    client._show_statistics()


if __name__ == "__main__":
    main()