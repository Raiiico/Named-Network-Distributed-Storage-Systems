# Named Networks Framework - AI Coding Agent Instructions

## Project Overview
This is a Named Data Networking (NDN) research prototype implementing hub-and-spoke topology with authentication, RAID storage, and Discretionary Access Control (DAC). Built in Python using UDP for stateless packet forwarding.

## Architecture: Interest/Data Paradigm

### Core Communication Flow
```
Client → Router1 → Router2 → Server/Storage → Router2 → Router1 → Client
```

**Critical**: All communication uses **Interest/Data packets** (not traditional request/response):
- Clients send `InterestPacket` with hierarchical names (e.g., `/dlsu/storage/file.txt`)
- Nodes respond with `DataPacket` containing requested content
- Routers cache Data packets in Content Store for efficiency
- Pending Interest Table (PIT) tracks request sources for return routing

### Module Architecture Pattern

All nodes follow this **modular pipeline**:
1. **CommunicationModule** - UDP transport (port binding, packet buffering)
2. **ParsingModule** - JSON deserialization, packet classification
3. **ProcessingModule** - Business logic (permission checks, cache lookup)
4. **RoutingModule** - FIB-based forwarding (routers only)

**Module interfaces are connected via callbacks**:
```python
# Example from router.py:
comm_module.set_packet_handler(parsing_module.handle_packet)
parsing_module.set_processing_handler(self._handle_parsed_packet)
```

Never call modules directly - always use registered handlers to maintain loose coupling.

## Critical Naming Conventions

### Content Name Routing (FIB Prefixes)
All Interest names **must** start with `/dlsu/` to match Forwarding Information Base (FIB) entries:

**✅ Correct:**
- `/dlsu/storage/file.txt` - Routes to storage nodes
- `/dlsu/server/auth/dlsu/storage/file.txt` - Routes to auth server

**❌ Wrong:**
- `/server/auth/...` - No FIB match, router returns error
- `/storage/file.txt` - Missing `/dlsu/` prefix

See `fib_config.py` for complete routing table. Router1 (R1) is edge router; Router2 (R2) is core router connecting to server/storage.

### Fragment Notation
Large files use fragment suffix: `/dlsu/storage/bigfile.pdf:[1/4]`
- Storage nodes send fragments separately
- Clients reassemble using base name from PIT
- **Never cache fragment Data** - routers skip caching for `:[n/total]` names

## Authentication Flow (3-Step Process)

**CRITICAL**: All READ/WRITE operations require authentication before storage access:

```python
# Step 1: Client checks permission
auth_interest = InterestPacket(
    name="/dlsu/server/auth/dlsu/storage/file.txt",  # Must use /dlsu/server prefix!
    operation="PERMISSION",
    user_id="alice",
    auth_key="password123"  # Password in auth_key field
)

# Step 2: Router2 forwards to Server (127.0.0.1:7001)
# Server validates: authenticate_user(user, password) + check_permission(resource, user, operation)

# Step 3: If authorized, original Interest forwarded to storage
```

**Common bug**: Forgetting `/dlsu/` prefix in auth names causes FIB routing failure (see `documents/FIXES_APPLIED.md`).

## Storage: RAID Module Pattern

### RAID Levels & Port Allocation
```python
ST1 (RAID 0): port 9001  # Striping, no redundancy
ST2 (RAID 1): port 9002  # Mirroring
ST3 (RAID 5): port 9003  # Single parity
ST4 (RAID 6): port 9004  # Double parity
```

### Storage Module Methods
```python
storage_module.store_file(file_name, content_bytes)  # Returns StorageResponse
storage_module.retrieve_file(file_name)  # Applies RAID reconstruction
```

Files are stored in `storage_{node_id}_raid{level}/` with subdirectories:
- `files/` - Complete files (RAID 0/1) or metadata (RAID 5/6)
- `fragments/` - Data chunks for striping
- `parity/` - Parity blocks (RAID 5/6)
- `metadata/` - JSON metadata with RAID parameters

## Database Layer (SQLite)

Security and file metadata use `db.py` abstraction:
```python
db = Database('named_networks.db')
db.init_schema()  # Creates users, files, permissions, storage_nodes tables
db.create_user('alice', password_hash)
db.add_file('/dlsu/storage/file.txt', owner='alice')
db.grant_permission('alice', '/dlsu/storage/file.txt', 'READ', 'bob')
```

**Key pattern**: SecurityModule delegates to DB when available:
```python
if self.db is not None:
    return self.db.check_permission(user_id, resource_name, perm_str)
# Fallback to in-memory ACLs
```

## Testing & Development Workflow

### Launch Full Topology (4 terminals)
```powershell
# Terminal 1: Router (hub)
python router.py R1

# Terminal 2: Storage
python storage_node.py ST1 0 9001

# Terminal 3: Auth Server
python server.py

# Terminal 4: Client
python simple_client.py Alice
```

### No pytest Tests
**Important**: The `tests/` directory contains standalone test scripts, **not pytest suites**. Run with:
```powershell
python tests/test_auth_e2e.py
python tests/test_dac.py
```
These create temporary DB instances and mock components. Never assume pytest conventions.

### GUI Debugging
`debug_gui.py` provides real-time packet visualization (Tkinter):
- Red = Interest packets
- Blue = Data packets
- Orange = Errors
- Left panel shows FIB/PIT/Cache stats

Router automatically launches GUI if available (disable with `use_gui=False`).

## Common Pitfalls

1. **Port conflicts**: Check `fib_config.py` for port allocations. Routers, server, storage each have fixed ports.

2. **Checksum validation**: All packets use SHA-256 checksums. Calculate with `calculate_checksum(name|user_id|operation)` from `common.py`.

3. **PIT cleanup**: Always call `pit.remove_entry()` after Data packet sent, or memory leaks occur.

4. **Nonce removed**: Per adviser feedback, nonce field was removed. Do not add duplicate detection based on nonce.

5. **TCP vs UDP**: Entire system uses UDP despite some legacy TCP code in archive. Never create TCP sockets in main modules.

6. **Password encoding**: SecurityModule uses XOR "encryption" (reversible encoding) per user requirement - not bcrypt/SHA-256 hashing.

## Key Files Reference

- `common.py` - InterestPacket, DataPacket, ContentStore, PIT classes
- `fib_config.py` - Static routing tables for R1/R2
- `router.py` - Hub router with auth integration
- `storage_node.py` - RAID-aware storage backend
- `server.py` - Authentication/authorization server (SecurityModule)
- `security_module.py` - DAC, user management, auth tokens
- `db.py` - SQLite persistence layer
- `documents/FIXES_APPLIED.md` - Critical auth routing bug fixes

## Project-Specific Patterns

### Error Responses
Always return JSON DataPacket for errors:
```python
error_data = DataPacket(
    name=interest.name,
    data_payload=json.dumps({"error": "Permission denied"}).encode()
)
return error_data.to_json()
```

### Module Initialization Order
1. Create CommunicationModule (binds UDP socket)
2. Create ParsingModule, ProcessingModule, RoutingModule
3. Connect interfaces via `set_*_handler()` methods
4. Call `comm_module.start()` last

### Logging Convention
Use node_name prefix in all logs:
```python
print(f"[{self.node_name}][ROUTING] FIB lookup for {name}")
```

## Thesis Context
This prototype validates hub-and-spoke NDN topology for academic research. Design decisions prioritize **demonstration clarity** over production optimization:
- UDP chosen to match NDN stateless principles
- Static FIB (no dynamic routing protocols)
- Simple XOR cipher (not cryptographically secure)
- Tkinter GUI for real-time visualization

When suggesting improvements, maintain research demonstration focus rather than production hardening.
