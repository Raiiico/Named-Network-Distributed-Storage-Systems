#!/usr/bin/env python3
"""
FIB Configuration for Different Routers
Each router gets different static routes based on topology position

Required Topology:
Client 1 ↔ Router 1
Client 2 ↔ Router 1
Router 1 ↔ Router 2
Router 2 ↔ Server
Storage Nodes (RAID Groups) ↔ Router 2

RAID Group Port Allocation:
- RAID 0 (Striping): ST0-A (9001), ST0-B (9002)
- RAID 1 (Mirroring): ST1-A (9003), ST1-B (9004)
- RAID 5 (Single Parity): ST5-A (9005), ST5-B (9006), ST5-C (9007)
- RAID 6 (Double Parity): ST6-A (9008), ST6-B (9009), ST6-C (9010), ST6-D (9011)

NOTE: IP addresses are now configured in network_config.py
      Edit network_config.json to change IPs for VM deployment.
"""

# Import network configuration
try:
    from network_config import (
        ROUTER_CONFIG, SERVER_CONFIG, CLIENT_CONFIG,
        STORAGE_RAID0, STORAGE_RAID1, STORAGE_RAID5, STORAGE_RAID6,
        generate_raid_groups, generate_fib_r1, generate_fib_r2,
        get_router, get_server
    )
    _USE_NETWORK_CONFIG = True
except ImportError:
    _USE_NETWORK_CONFIG = False
    print("[fib_config] Warning: network_config.py not found, using hardcoded defaults")

# RAID Group Configuration - used by server for storage assignment
if _USE_NETWORK_CONFIG:
    RAID_GROUPS = generate_raid_groups()
else:
    # Fallback to hardcoded config
    RAID_GROUPS = {
        'raid0': {
            'level': 'raid0',
            'min_nodes': 2,
            'nodes': [
                {'name': 'ST0-A', 'host': '127.0.0.1', 'port': 9001},
                {'name': 'ST0-B', 'host': '127.0.0.1', 'port': 9002},
            ]
        },
        'raid1': {
            'level': 'raid1',
            'min_nodes': 2,
            'nodes': [
                {'name': 'ST1-A', 'host': '127.0.0.1', 'port': 9003},
                {'name': 'ST1-B', 'host': '127.0.0.1', 'port': 9004},
            ]
        },
        'raid5': {
            'level': 'raid5',
            'min_nodes': 3,
            'nodes': [
                {'name': 'ST5-A', 'host': '127.0.0.1', 'port': 9005},
                {'name': 'ST5-B', 'host': '127.0.0.1', 'port': 9006},
                {'name': 'ST5-C', 'host': '127.0.0.1', 'port': 9007},
            ]
        },
        'raid6': {
            'level': 'raid6',
            'min_nodes': 4,
            'nodes': [
                {'name': 'ST6-A', 'host': '127.0.0.1', 'port': 9008},
                {'name': 'ST6-B', 'host': '127.0.0.1', 'port': 9009},
                {'name': 'ST6-C', 'host': '127.0.0.1', 'port': 9010},
                {'name': 'ST6-D', 'host': '127.0.0.1', 'port': 9011},
            ]
        }
    }

# Default RAID level when user doesn't specify
DEFAULT_RAID_LEVEL = 'raid1'

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
    
    # Use network_config if available
    if _USE_NETWORK_CONFIG:
        if router_name == "R1":
            return generate_fib_r1()
        elif router_name == "R2":
            return generate_fib_r2()
        return []
    
    # Fallback to hardcoded config
    configs = {
        "R1": [
            # Router1 FIB - Edge router connecting clients (Alice/Bob) and R2
            # Client prefixes point to local clients; other prefixes forward to R2
            ("/dlsu/alice", "127.0.0.1:6001", "eth0", 1),    # Alice (client)
            ("/dlsu/bob", "127.0.0.1:6002", "eth0", 1),      # Bob (client)
            ("/dlsu/router2", "127.0.0.1:8002", "eth1", 1),  # To R2 (core)
            ("/dlsu/server", "127.0.0.1:8002", "eth1", 2),   # Via R2 to server
            ("/dlsu/storage", "127.0.0.1:8002", "eth1", 2),  # All storage via R2
            ("/dlsu", "127.0.0.1:8002", "eth1", 2),          # Default: forward to R2
        ],
        
        "R2": [
            # Router2 FIB - Core router connecting R1, Server and Storage nodes
            ("/dlsu/router1", "127.0.0.1:8001", "eth0", 1),  # Back to R1
            ("/dlsu/server", "127.0.0.1:7001", "eth1", 1),   # Direct to Server
            
            # RAID 0 nodes (Striping)
            ("/dlsu/storage/ST0-A", "127.0.0.1:9001", "eth2", 1),
            ("/dlsu/storage/ST0-B", "127.0.0.1:9002", "eth3", 1),
            
            # RAID 1 nodes (Mirroring)
            ("/dlsu/storage/ST1-A", "127.0.0.1:9003", "eth4", 1),
            ("/dlsu/storage/ST1-B", "127.0.0.1:9004", "eth5", 1),
            
            # RAID 5 nodes (Single Parity)
            ("/dlsu/storage/ST5-A", "127.0.0.1:9005", "eth6", 1),
            ("/dlsu/storage/ST5-B", "127.0.0.1:9006", "eth7", 1),
            ("/dlsu/storage/ST5-C", "127.0.0.1:9007", "eth8", 1),
            
            # RAID 6 nodes (Double Parity)
            ("/dlsu/storage/ST6-A", "127.0.0.1:9008", "eth9", 1),
            ("/dlsu/storage/ST6-B", "127.0.0.1:9009", "eth10", 1),
            ("/dlsu/storage/ST6-C", "127.0.0.1:9010", "eth11", 1),
            ("/dlsu/storage/ST6-D", "127.0.0.1:9011", "eth12", 1),
            
            # Legacy node routes (for backward compatibility)
            ("/dlsu/storage/node1", "127.0.0.1:9001", "eth2", 1),
            ("/dlsu/storage/node2", "127.0.0.1:9002", "eth3", 1),
            ("/dlsu/storage/node3", "127.0.0.1:9003", "eth4", 1),
            ("/dlsu/storage/node4", "127.0.0.1:9004", "eth5", 1),
            
            # RAID-specific prefixes for explicit routing
            ("/dlsu/storage/raid0", "127.0.0.1:9001", "eth2", 1),
            ("/dlsu/storage/raid1", "127.0.0.1:9003", "eth4", 1),
            ("/dlsu/storage/raid5", "127.0.0.1:9005", "eth6", 1),
            ("/dlsu/storage/raid6", "127.0.0.1:9008", "eth9", 1),
            
            # Default storage route (server coordinates actual assignment)
            ("/dlsu/storage", "127.0.0.1:9003", "eth4", 1),
            
            # Client prefixes reachable via R1 (so replies are forwarded back)
            ("/dlsu/alice", "127.0.0.1:8001", "eth0", 2),
            ("/dlsu/bob", "127.0.0.1:8001", "eth0", 2),
        ]
    }
    
    return configs.get(router_name, [])


def get_port_for_router(router_name: str):
    """Get the port number for a router"""
    if _USE_NETWORK_CONFIG:
        router = get_router(router_name)
        return router.get('port', 8001)
    
    # Fallback
    ports = {
        "R1": 8001,
        "R2": 8002
    }
    return ports.get(router_name, 8001)


def get_host_for_router(router_name: str):
    """Get the host IP for a router"""
    if _USE_NETWORK_CONFIG:
        router = get_router(router_name)
        return router.get('host', '127.0.0.1')
    return '127.0.0.1'


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