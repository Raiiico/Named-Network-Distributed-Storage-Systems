#!/usr/bin/env python3
"""
Routing Module - Named Networks Framework
Handles static routing with Forwarding Information Base (FIB)
Implements longest prefix matching for content names
"""

import threading
from typing import Dict, Optional, List, Tuple

class RoutingEntry:
    """Single routing entry in the FIB"""
    def __init__(self, prefix: str, next_hop: str, interface: str, hop_count: int = 1):
        self.prefix = prefix
        self.next_hop = next_hop  # IP:Port
        self.interface = interface
        self.hop_count = hop_count
        self.priority = 1

class RoutingModule:
    """
    Routing Module implementing static FIB with longest prefix matching
    Routes Interest packets based on content names
    """
    
    def __init__(self, node_name: str):
        self.node_name = node_name
        
        # Forwarding Information Base (FIB) - static routing table
        self.fib: Dict[str, RoutingEntry] = {}
        self._fib_lock = threading.Lock()
        
        # Default routes for different content types
        self._initialize_default_routes()
        
        # Statistics
        self.stats = {
            "total_lookups": 0,
            "successful_matches": 0,
            "default_route_used": 0,
            "longest_prefix_matches": 0
        }
        
        print(f"[{self.node_name}][ROUTING] Routing Module initialized")
    
    def _initialize_default_routes(self):
        """Initialize default static routes"""
        # Default routes for common content prefixes
        default_routes = [
            # Storage node routes
            ("/dlsu/storage/node1", "127.0.0.1:9001", "eth0"),
            ("/dlsu/storage/node2", "127.0.0.1:9002", "eth0"),
            ("/dlsu/storage/node3", "127.0.0.1:9003", "eth0"),
            ("/dlsu/storage/node4", "127.0.0.1:9004", "eth0"),
            
            # General storage route
            ("/dlsu/storage", "127.0.0.1:9001", "eth0"),
            
            # Public content routes
            ("/dlsu/public", "127.0.0.1:9001", "eth0"),
            ("/dlsu/hello", "127.0.0.1:9001", "eth0"),
            
            # User directories
            ("/dlsu/alice", "127.0.0.1:9002", "eth0"),
            ("/dlsu/bob", "127.0.0.1:9003", "eth0"),
            
            # Shared content
            ("/dlsu/shared", "127.0.0.1:9004", "eth0"),
        ]
        
        for prefix, next_hop, interface in default_routes:
            self.add_route(prefix, next_hop, interface)
        
        print(f"[{self.node_name}][ROUTING] Initialized {len(default_routes)} default routes")
    
    def add_route(self, prefix: str, next_hop: str, interface: str, hop_count: int = 1):
        """Add a route to the FIB"""
        with self._fib_lock:
            entry = RoutingEntry(prefix, next_hop, interface, hop_count)
            self.fib[prefix] = entry
            print(f"[{self.node_name}][ROUTING] Added route: {prefix} -> {next_hop}")
    
    def remove_route(self, prefix: str):
        """Remove a route from the FIB"""
        with self._fib_lock:
            if prefix in self.fib:
                del self.fib[prefix]
                print(f"[{self.node_name}][ROUTING] Removed route: {prefix}")
    
    def lookup_route(self, content_name: str) -> Optional[RoutingEntry]:
        """
        Perform longest prefix matching on content name
        Returns the best matching route entry
        """
        self.stats["total_lookups"] += 1
        
        with self._fib_lock:
            best_match = None
            longest_prefix_length = 0
            
            # Find longest matching prefix
            for prefix, entry in self.fib.items():
                if content_name.startswith(prefix):
                    prefix_length = len(prefix)
                    if prefix_length > longest_prefix_length:
                        longest_prefix_length = prefix_length
                        best_match = entry
                        self.stats["longest_prefix_matches"] += 1
            
            if best_match:
                self.stats["successful_matches"] += 1
                print(f"[{self.node_name}][ROUTING] Route found for {content_name}: {best_match.next_hop}")
                return best_match
            else:
                # Try default route
                default_entry = self._get_default_route()
                if default_entry:
                    self.stats["default_route_used"] += 1
                    print(f"[{self.node_name}][ROUTING] Using default route for {content_name}: {default_entry.next_hop}")
                    return default_entry
                
                print(f"[{self.node_name}][ROUTING] No route found for {content_name}")
                return None
    
    def _get_default_route(self) -> Optional[RoutingEntry]:
        """Get default route (first storage node)"""
        default_routes = ["/dlsu/storage/node1", "/dlsu/storage"]
        for route in default_routes:
            if route in self.fib:
                return self.fib[route]
        return None
    
    def get_next_hop(self, content_name: str) -> Optional[str]:
        """Get next hop address for content name"""
        route_entry = self.lookup_route(content_name)
        return route_entry.next_hop if route_entry else None
    
    def get_interface(self, content_name: str) -> Optional[str]:
        """Get interface for content name"""
        route_entry = self.lookup_route(content_name)
        return route_entry.interface if route_entry else None
    
    def get_routing_info(self, content_name: str) -> Optional[Tuple[str, str]]:
        """Get both next hop and interface for content name"""
        route_entry = self.lookup_route(content_name)
        if route_entry:
            return (route_entry.next_hop, route_entry.interface)
        return None
    
    def show_fib(self):
        """Display the Forwarding Information Base"""
        print(f"\n=== {self.node_name} Forwarding Information Base ===")
        with self._fib_lock:
            if not self.fib:
                print("No routes configured")
                return
            
            print(f"{'Prefix':<30} {'Next Hop':<20} {'Interface':<10} {'Hops':<5}")
            print("-" * 70)
            
            # Sort by prefix length (longest first) for display
            sorted_routes = sorted(self.fib.items(), key=lambda x: len(x[0]), reverse=True)
            
            for prefix, entry in sorted_routes:
                print(f"{prefix:<30} {entry.next_hop:<20} {entry.interface:<10} {entry.hop_count:<5}")
        
        print("=" * 70)
    
    def get_routing_stats(self) -> Dict:
        """Get routing statistics"""
        return {
            **self.stats,
            "total_routes": len(self.fib),
            "success_rate": (self.stats["successful_matches"] / max(1, self.stats["total_lookups"]))
        }
    
    def show_stats(self):
        """Display routing statistics"""
        stats = self.get_routing_stats()
        print(f"\n=== {self.node_name} Routing Statistics ===")
        print(f"Total lookups: {stats['total_lookups']}")
        print(f"Successful matches: {stats['successful_matches']}")
        print(f"Default route used: {stats['default_route_used']}")
        print(f"Longest prefix matches: {stats['longest_prefix_matches']}")
        print(f"Total routes in FIB: {stats['total_routes']}")
        print(f"Success rate: {stats['success_rate']:.1%}")
        print("=" * 50)