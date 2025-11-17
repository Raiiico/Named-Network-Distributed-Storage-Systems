#!/usr/bin/env python3
"""
FIB Configuration for Different Routers
Each router gets different static routes based on topology position

Required Topology:
Client 1 ↔ Router 1
Client 2 ↔ Router 1
Router 1 ↔ Router 2
Router 2 ↔ Server
Storage Node 1 ↔ Router 2
Storage Node 2 ↔ Router 2
"""

def get_fib_config(router_name: str):
    """
    Get FIB configuration based on router name
    Returns list of (prefix, next_hop, interface, hop_count)
    
    Content names we're using:
    /dlsu/storage/node1
    /dlsu/storage/node2
    /dlsu/storage
    /dlsu/alice
    /dlsu/bob
    /dlsu/router1
    /dlsu/router2
    /dlsu/server
    """
    
    configs = {
        "R1": [
            # Router1 FIB - Connects to Clients and Router2
            # All content is forwarded to Router2 (the hub connecting to server/storage)
            ("/dlsu/router2", "127.0.0.1:8002", "eth1", 1),  # Direct to R2
            ("/dlsu/server", "127.0.0.1:8002", "eth1", 2),   # Via R2
            ("/dlsu/storage/node1", "127.0.0.1:8002", "eth1", 3),  # Via R2
            ("/dlsu/storage/node2", "127.0.0.1:8002", "eth1", 3),  # Via R2
            ("/dlsu/storage", "127.0.0.1:8002", "eth1", 3),  # Via R2
            ("/dlsu/alice", "127.0.0.1:8002", "eth1", 3),    # Via R2 (user files)
            ("/dlsu/bob", "127.0.0.1:8002", "eth1", 3),      # Via R2 (user files)
            ("/dlsu", "127.0.0.1:8002", "eth1", 2),          # Default: everything goes to R2
        ],
        
        "R2": [
            # Router2 FIB - Connects to R1, Server, and Storage Nodes
            ("/dlsu/router1", "127.0.0.1:8001", "eth0", 1),  # Back to R1 (for responses)
            ("/dlsu/server", "127.0.0.1:7001", "eth2", 1),   # Direct to Server
            ("/dlsu/storage/node1", "127.0.0.1:9001", "eth3", 1),  # Direct to ST1
            ("/dlsu/storage/node2", "127.0.0.1:9002", "eth4", 1),  # Direct to ST2
            ("/dlsu/storage", "127.0.0.1:9001", "eth3", 1),  # Default storage -> ST1
            ("/dlsu/alice", "127.0.0.1:9001", "eth3", 1),    # Alice's files on ST1
            ("/dlsu/bob", "127.0.0.1:9002", "eth4", 1),      # Bob's files on ST2
        ]
    }
    
    return configs.get(router_name, [])


def get_port_for_router(router_name: str):
    """Get the port number for a router"""
    ports = {
        "R1": 8001,
        "R2": 8002
    }
    return ports.get(router_name, 8001)


def get_router_role(router_name: str):
    """Get description of router's role in topology"""
    roles = {
        "R1": "Edge Router - Connects to Clients, forwards to R2",
        "R2": "Core Router - Connects to Server and Storage Nodes"
    }
    return roles.get(router_name, "Unknown Router")


# Test the configuration
if __name__ == "__main__":
    print("="*70)
    print("FIB CONFIGURATION TEST")
    print("="*70)
    
    for router in ["R1", "R2"]:
        print(f"\n{router} Configuration:")
        print(f"  Port: {get_port_for_router(router)}")
        print(f"  Role: {get_router_role(router)}")
        print(f"  FIB Entries:")
        
        routes = get_fib_config(router)
        print(f"  {'Prefix':<25} {'Next Hop':<20} {'Interface':<10} {'Hops'}")
        print(f"  {'-'*65}")
        
        for prefix, next_hop, interface, hop_count in routes:
            print(f"  {prefix:<25} {next_hop:<20} {interface:<10} {hop_count}")
    
    print("\n" + "="*70)