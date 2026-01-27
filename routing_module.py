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
        # Each prefix may have multiple RoutingEntry objects (for load balancing)
        self.fib: Dict[str, List[RoutingEntry]] = {}
        self._fib_lock = threading.Lock()
        # Round-robin counters per prefix
        self._rr_counters: Dict[str, int] = {}
        
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
        """Initialize default static routes - REMOVED"""
        # Don't initialize anything here
        print(f"[{self.node_name}][ROUTING] FIB empty - waiting for configuration")

    def load_fib_from_config(self, routes_config):
        """
        Load FIB from external configuration
        routes_config: list of tuples (prefix, next_hop, interface, hop_count)
        """
        print(f"[{self.node_name}][ROUTING] Loading FIB configuration...")
        
        for route in routes_config:
            prefix, next_hop, interface, hop_count = route
            self.add_route(prefix, next_hop, interface, hop_count)
        
        print(f"[{self.node_name}][ROUTING] Loaded {len(routes_config)} routes")
    
    def add_route(self, prefix: str, next_hop: str, interface: str, hop_count: int = 1):
        """Add a route to the FIB. Multiple routes per prefix are allowed for load-balancing."""
        with self._fib_lock:
            entry = RoutingEntry(prefix, next_hop, interface, hop_count)
            if prefix not in self.fib:
                self.fib[prefix] = []
            self.fib[prefix].append(entry)
            # Initialize round-robin counter if needed
            if prefix not in self._rr_counters:
                self._rr_counters[prefix] = 0
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
            best_match_prefix = None
            best_match_entry = None
            longest_prefix_length = 0

            # Find longest matching prefix
            for prefix, entries in self.fib.items():
                if content_name.startswith(prefix):
                    prefix_length = len(prefix)
                    if prefix_length > longest_prefix_length:
                        longest_prefix_length = prefix_length
                        best_match_prefix = prefix
                        self.stats["longest_prefix_matches"] += 1

            if best_match_prefix:
                entries = self.fib.get(best_match_prefix, [])
                if not entries:
                    return None
                # Round-robin selection
                idx = self._rr_counters.get(best_match_prefix, 0) % len(entries)
                selected = entries[idx]
                # advance counter
                self._rr_counters[best_match_prefix] = (self._rr_counters.get(best_match_prefix, 0) + 1) % max(1, len(entries))

                self.stats["successful_matches"] += 1
                print(f"[{self.node_name}][ROUTING] Route found for {content_name}: {selected.next_hop} (via {best_match_prefix})")
                return selected
            else:
                # Try default route
                default_entry = self._get_default_route()
                if default_entry:
                    self.stats["default_route_used"] += 1
                    print(f"[{self.node_name}][ROUTING] Using default route for {content_name}: {default_entry.next_hop}")
                    return default_entry
                
                print(f"[{self.node_name}][ROUTING] No route found for {content_name}")
                return None
    def clear_fib(self):
        """Clear all FIB entries"""
        with self._fib_lock:
            self.fib.clear()
            self._rr_counters.clear()
        print(f"[{self.node_name}][ROUTING] FIB cleared")
    
    def _get_default_route(self) -> Optional[RoutingEntry]:
        """Get default route (first matching storage route)"""
        default_routes = ["/dlsu/storage/node1", "/dlsu/storage"]
        for route in default_routes:
            if route in self.fib and self.fib[route]:
                # Return round-robin selected entry for the default route
                entries = self.fib[route]
                idx = self._rr_counters.get(route, 0) % len(entries)
                selected = entries[idx]
                self._rr_counters[route] = (self._rr_counters.get(route, 0) + 1) % max(1, len(entries))
                return selected
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
            
            print(f"{ 'Prefix':<30} {'Next Hop(s)':<40} {'Interface':<10} {'Hops':<5}")
            print("-" * 90)

            # Sort by prefix length (longest first) for display
            sorted_routes = sorted(self.fib.items(), key=lambda x: len(x[0]), reverse=True)

            for prefix, entries in sorted_routes:
                next_hops = ', '.join(e.next_hop for e in entries)
                interfaces = ','.join(e.interface for e in entries)
                hops = ','.join(str(e.hop_count) for e in entries)
                print(f"{prefix:<30} {next_hops:<40} {interfaces:<10} {hops:<5}")
        
        
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