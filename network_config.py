"""
Network Configuration for Named Networks Framework
===================================================

This file contains all network addresses and ports for the distributed system.
Edit this file to configure IP addresses when deploying across multiple VMs.

Default configuration assumes all nodes run on localhost (127.0.0.1).
For VM deployment, change the IP addresses to match your network setup.

Node Types:
- Router R1 (edge): Clients connect here
- Router R2 (core): Connects to server and storage
- Server: Authentication and authorization
- Storage Nodes: RAID 0, 1, 5, 6 configurations
"""

import os
import json

# =============================================================================
# CONFIGURATION FILE PATH (optional external config)
# =============================================================================
# If this file exists, it will override the defaults below
CONFIG_FILE_PATH = os.path.join(os.path.dirname(__file__), 'network_config.json')

# =============================================================================
# DEFAULT HOST (change this for single-host deployment)
# =============================================================================
DEFAULT_HOST = '127.0.0.1'

# =============================================================================
# ROUTER CONFIGURATION
# =============================================================================
ROUTER_CONFIG = {
    'R1': {
        'name': 'R1',
        'host': DEFAULT_HOST,
        'port': 8001,
        'description': 'Edge router (client-facing)'
    },
    'R2': {
        'name': 'R2', 
        'host': DEFAULT_HOST,
        'port': 8002,
        'description': 'Core router (server/storage-facing)'
    }
}

# =============================================================================
# SERVER CONFIGURATION
# =============================================================================
SERVER_CONFIG = {
    'S1': {
        'name': 'S1',
        'host': DEFAULT_HOST,
        'port': 7001,
        'description': 'Authentication/Authorization Server'
    }
}

# =============================================================================
# STORAGE NODE CONFIGURATION
# =============================================================================
# RAID 0 - Striping (2 nodes)
STORAGE_RAID0 = {
    'ST0-A': {'name': 'ST0-A', 'host': DEFAULT_HOST, 'port': 9001, 'raid_level': 0},
    'ST0-B': {'name': 'ST0-B', 'host': DEFAULT_HOST, 'port': 9002, 'raid_level': 0},
}

# RAID 1 - Mirroring (2 nodes)
STORAGE_RAID1 = {
    'ST1-A': {'name': 'ST1-A', 'host': DEFAULT_HOST, 'port': 9003, 'raid_level': 1},
    'ST1-B': {'name': 'ST1-B', 'host': DEFAULT_HOST, 'port': 9004, 'raid_level': 1},
}

# RAID 5 - Striping with distributed parity (3 nodes)
STORAGE_RAID5 = {
    'ST5-A': {'name': 'ST5-A', 'host': DEFAULT_HOST, 'port': 9005, 'raid_level': 5},
    'ST5-B': {'name': 'ST5-B', 'host': DEFAULT_HOST, 'port': 9006, 'raid_level': 5},
    'ST5-C': {'name': 'ST5-C', 'host': DEFAULT_HOST, 'port': 9007, 'raid_level': 5},
}

# RAID 6 - Striping with dual parity (4 nodes)
STORAGE_RAID6 = {
    'ST6-A': {'name': 'ST6-A', 'host': DEFAULT_HOST, 'port': 9008, 'raid_level': 6},
    'ST6-B': {'name': 'ST6-B', 'host': DEFAULT_HOST, 'port': 9009, 'raid_level': 6},
    'ST6-C': {'name': 'ST6-C', 'host': DEFAULT_HOST, 'port': 9010, 'raid_level': 6},
    'ST6-D': {'name': 'ST6-D', 'host': DEFAULT_HOST, 'port': 9011, 'raid_level': 6},
}

# Combined storage configuration
STORAGE_CONFIG = {
    **STORAGE_RAID0,
    **STORAGE_RAID1, 
    **STORAGE_RAID5,
    **STORAGE_RAID6,
}

# =============================================================================
# CLIENT CONFIGURATION (for reference)
# =============================================================================
CLIENT_CONFIG = {
    'alice': {'name': 'alice', 'host': DEFAULT_HOST, 'port': 6001},
    'bob': {'name': 'bob', 'host': DEFAULT_HOST, 'port': 6002},
}

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_router(router_id: str) -> dict:
    """Get router configuration by ID (R1 or R2)"""
    return ROUTER_CONFIG.get(router_id, ROUTER_CONFIG['R1'])

def get_server(server_id: str = 'S1') -> dict:
    """Get server configuration"""
    return SERVER_CONFIG.get(server_id, SERVER_CONFIG['S1'])

def get_storage_node(node_id: str) -> dict:
    """Get storage node configuration by ID"""
    return STORAGE_CONFIG.get(node_id, None)

def get_storage_nodes_by_raid(raid_level: int) -> list:
    """Get all storage nodes for a specific RAID level"""
    if raid_level == 0:
        return list(STORAGE_RAID0.values())
    elif raid_level == 1:
        return list(STORAGE_RAID1.values())
    elif raid_level == 5:
        return list(STORAGE_RAID5.values())
    elif raid_level == 6:
        return list(STORAGE_RAID6.values())
    return []

def get_default_router_address() -> tuple:
    """Get default router (R1) host and port for clients"""
    r1 = ROUTER_CONFIG['R1']
    return (r1['host'], r1['port'])

def get_server_address() -> tuple:
    """Get server host and port"""
    s1 = SERVER_CONFIG['S1']
    return (s1['host'], s1['port'])

def get_router_address(router_id: str = 'R1') -> tuple:
    """Get router host and port by ID"""
    router = ROUTER_CONFIG.get(router_id, ROUTER_CONFIG['R1'])
    return (router['host'], router['port'])

def get_all_storage_addresses() -> list:
    """Get list of all storage node addresses as (host, port, raid_level) tuples"""
    return [(n['host'], n['port'], n['raid_level']) for n in STORAGE_CONFIG.values()]

# =============================================================================
# LOAD EXTERNAL CONFIG (if exists)
# =============================================================================

def _load_external_config():
    """Load configuration from external JSON file if it exists"""
    global DEFAULT_HOST, ROUTER_CONFIG, SERVER_CONFIG
    global STORAGE_RAID0, STORAGE_RAID1, STORAGE_RAID5, STORAGE_RAID6, STORAGE_CONFIG
    global CLIENT_CONFIG
    
    if os.path.exists(CONFIG_FILE_PATH):
        try:
            with open(CONFIG_FILE_PATH, 'r') as f:
                config = json.load(f)
            
            if 'default_host' in config:
                DEFAULT_HOST = config['default_host']
            
            if 'routers' in config:
                for k, v in config['routers'].items():
                    if k in ROUTER_CONFIG:
                        ROUTER_CONFIG[k].update(v)
            
            if 'servers' in config:
                for k, v in config['servers'].items():
                    if k in SERVER_CONFIG:
                        SERVER_CONFIG[k].update(v)
            
            if 'storage' in config:
                for k, v in config['storage'].items():
                    if k in STORAGE_CONFIG:
                        STORAGE_CONFIG[k].update(v)
                        # Update RAID-specific dicts too
                        if k.startswith('ST0'):
                            STORAGE_RAID0[k].update(v)
                        elif k.startswith('ST1'):
                            STORAGE_RAID1[k].update(v)
                        elif k.startswith('ST5'):
                            STORAGE_RAID5[k].update(v)
                        elif k.startswith('ST6'):
                            STORAGE_RAID6[k].update(v)
            
            if 'clients' in config:
                for k, v in config['clients'].items():
                    if k in CLIENT_CONFIG:
                        CLIENT_CONFIG[k].update(v)
            
            print(f"[NetworkConfig] Loaded external config from {CONFIG_FILE_PATH}")
        except Exception as e:
            print(f"[NetworkConfig] Warning: Could not load {CONFIG_FILE_PATH}: {e}")

# Load external config on module import
_load_external_config()

# =============================================================================
# GENERATE FIB ENTRIES (for router use)
# =============================================================================

def generate_fib_r1() -> list:
    """Generate FIB entries for Router R1 (edge router)"""
    r2 = ROUTER_CONFIG['R2']
    entries = [
        ("/dlsu/alice", f"{CLIENT_CONFIG['alice']['host']}:{CLIENT_CONFIG['alice']['port']}", "eth0", 1),
        ("/dlsu/bob", f"{CLIENT_CONFIG['bob']['host']}:{CLIENT_CONFIG['bob']['port']}", "eth0", 1),
        ("/dlsu/router2", f"{r2['host']}:{r2['port']}", "eth1", 1),
        ("/dlsu/server", f"{r2['host']}:{r2['port']}", "eth1", 2),
        ("/dlsu/storage", f"{r2['host']}:{r2['port']}", "eth1", 2),
        ("/dlsu", f"{r2['host']}:{r2['port']}", "eth1", 2),
    ]
    return entries

def generate_fib_r2() -> list:
    """Generate FIB entries for Router R2 (core router)"""
    r1 = ROUTER_CONFIG['R1']
    s1 = SERVER_CONFIG['S1']
    
    entries = [
        ("/dlsu/router1", f"{r1['host']}:{r1['port']}", "eth0", 1),
        ("/dlsu/server", f"{s1['host']}:{s1['port']}", "eth1", 1),
    ]
    
    # Add storage node entries
    eth_idx = 2
    for node_id, node in STORAGE_CONFIG.items():
        entries.append((f"/dlsu/storage/{node_id}", f"{node['host']}:{node['port']}", f"eth{eth_idx}", 1))
        eth_idx += 1
    
    # Add RAID level shortcuts
    raid0_node = list(STORAGE_RAID0.values())[0]
    raid1_node = list(STORAGE_RAID1.values())[0]
    raid5_node = list(STORAGE_RAID5.values())[0]
    raid6_node = list(STORAGE_RAID6.values())[0]
    
    entries.extend([
        ("/dlsu/storage/raid0", f"{raid0_node['host']}:{raid0_node['port']}", "eth2", 1),
        ("/dlsu/storage/raid1", f"{raid1_node['host']}:{raid1_node['port']}", "eth4", 1),
        ("/dlsu/storage/raid5", f"{raid5_node['host']}:{raid5_node['port']}", "eth6", 1),
        ("/dlsu/storage/raid6", f"{raid6_node['host']}:{raid6_node['port']}", "eth9", 1),
    ])
    
    # Default storage route
    entries.append(("/dlsu/storage", f"{raid1_node['host']}:{raid1_node['port']}", "eth4", 1))
    
    # Client return routes
    entries.extend([
        ("/dlsu/alice", f"{r1['host']}:{r1['port']}", "eth0", 2),
        ("/dlsu/bob", f"{r1['host']}:{r1['port']}", "eth0", 2),
    ])
    
    return entries

def generate_raid_groups() -> dict:
    """Generate RAID_GROUPS configuration for fib_config.py"""
    return {
        'raid0': {
            'level': 'raid0',
            'min_nodes': 2,
            'nodes': [{'name': n['name'], 'host': n['host'], 'port': n['port']} 
                      for n in STORAGE_RAID0.values()]
        },
        'raid1': {
            'level': 'raid1',
            'min_nodes': 2,
            'nodes': [{'name': n['name'], 'host': n['host'], 'port': n['port']} 
                      for n in STORAGE_RAID1.values()]
        },
        'raid5': {
            'level': 'raid5',
            'min_nodes': 3,
            'nodes': [{'name': n['name'], 'host': n['host'], 'port': n['port']} 
                      for n in STORAGE_RAID5.values()]
        },
        'raid6': {
            'level': 'raid6',
            'min_nodes': 4,
            'nodes': [{'name': n['name'], 'host': n['host'], 'port': n['port']} 
                      for n in STORAGE_RAID6.values()]
        },
    }

# =============================================================================
# PRINT CONFIGURATION (for debugging)
# =============================================================================

def print_config():
    """Print current network configuration"""
    print("\n" + "="*60)
    print("NETWORK CONFIGURATION")
    print("="*60)
    
    print("\n--- Routers ---")
    for rid, r in ROUTER_CONFIG.items():
        print(f"  {rid}: {r['host']}:{r['port']} ({r['description']})")
    
    print("\n--- Servers ---")
    for sid, s in SERVER_CONFIG.items():
        print(f"  {sid}: {s['host']}:{s['port']} ({s['description']})")
    
    print("\n--- Storage Nodes ---")
    print("  RAID 0 (Striping):")
    for nid, n in STORAGE_RAID0.items():
        print(f"    {nid}: {n['host']}:{n['port']}")
    print("  RAID 1 (Mirroring):")
    for nid, n in STORAGE_RAID1.items():
        print(f"    {nid}: {n['host']}:{n['port']}")
    print("  RAID 5 (Distributed Parity):")
    for nid, n in STORAGE_RAID5.items():
        print(f"    {nid}: {n['host']}:{n['port']}")
    print("  RAID 6 (Dual Parity):")
    for nid, n in STORAGE_RAID6.items():
        print(f"    {nid}: {n['host']}:{n['port']}")
    
    print("\n" + "="*60 + "\n")

if __name__ == '__main__':
    print_config()
