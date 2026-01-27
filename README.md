# Named Networks Framework - Hub-and-Spoke Implementation
## Complete System with Authentication Flow

---

## System Architecture

### Current Implementation Status

**Working Components:**
- Router (hub) - Packet forwarding and caching
- Storage Node - RAID storage with file management
- Client - Interest/Data communication
- GUI Debugger - Real-time packet visualization

**Authentication Flow:**
```
Client → Router → Server (auth) → Router → Storage
```

### Network Topology
```
    Client-Alice    Client-Bob
         |              |
         └─── Router ───┘
              |    |
           Server  Storage
```

---

## Quick Start

### Prerequisites
```bash
# Verify Python 3.8+
python --version

# Test Tkinter (GUI)
python -m tkinter
```

### Launch Complete System

#### Terminal 1: Router (Hub)
```bash
python router.py R1
```
- Starts on port 8001
- Central packet forwarding
- Content caching
- GUI debugging interface

#### Terminal 2: Storage Node
```bash
python storage_node.py ST1 0 9001
```
- RAID 0 storage
- Pre-loaded test files
- Responds to forwarded requests

#### Terminal 3: Client Alice
```bash
python simple_client.py Alice
```

#### Terminal 4: Client Bob (Concurrent Testing)
```bash
python simple_client.py Bob
```

---

## System Components

### 1. Router (router.py)
**Role:** Central hub for all communication
- **Packet Forwarding:** Routes Interest packets between nodes
- **Content Caching:** Stores frequently accessed content
- **Protocol:** UDP-based Named Data Network
- **GUI Integration:** Real-time packet visualization

**Key Features:**
- FIB (Forwarding Information Base) routing
- PIT (Pending Interest Table) duplicate tracking  
- Content Store with cache hit/miss logic
- Nonce-based request matching

### 2. Storage Node (storage_node.py)
**Role:** RAID storage with file management
- **Storage Type:** Configurable RAID levels (0,1,5,6)
- **File Operations:** Read, Write, Permission validation
- **Response Format:** Structured storage confirmations

**Pre-loaded Test Files:**
- `/dlsu/hello` - Basic cached content
- `/dlsu/storage/test` - Storage-specific content
- `/storage/test` - Alternative storage path

### 3. Client (simple_client.py)
**Role:** User interface for content requests
- **Operations:** READ, WRITE, PERMISSION
- **Protocol:** UDP Interest/Data exchange
- **Features:** Interactive mode, concurrent testing

### 4. Common Module (common.py)
**Role:** Shared data structures and utilities
- **Packet Types:** InterestPacket, DataPacket
- **Validation:** Standardized checksum (SHA-256)
- **Utilities:** Nonce generation, content validation

---

## Key Concepts

### Named Data Networking (NDN)
**Interest/Data Paradigm:**
```
Client sends: Interest(/dlsu/hello, nonce=12345)
Router responds: Data(/dlsu/hello, content="Hello World")
```

### Nonce Purpose
The nonce serves critical functions:

1. **Duplicate Detection:**
   ```
   Interest(/file, nonce=12345) - first time
   Interest(/file, nonce=12345) - duplicate (ignored)
   ```

2. **Request-Response Matching:**
   ```
   Alice: Interest(/data, nonce=11111)
   Bob:   Interest(/data, nonce=22222)
   Router matches responses to correct clients
   ```

3. **Interest Aggregation:**
   ```
   Multiple clients request same content
   Router forwards single Interest to storage
   Distributes response to all requesters
   ```

### Cache Behavior
**Cache Miss:** Content not in router cache, forwards to storage
**Cache Hit:** Content in router cache, immediate response

Test cache behavior:
```bash
read /dlsu/hello    # Cache miss (slower)
read /dlsu/hello    # Cache hit (instant)
```

---

## Testing Scenarios

### 1. Basic Transaction Flow
```bash
# In client:
read /dlsu/hello
```
**Expected:** Interest → Router → Storage → Data → Client

### 2. Cache Demonstration
```bash
read /dlsu/storage/test    # Miss: ~50ms
read /dlsu/storage/test    # Hit: ~5ms
```

### 3. Concurrent Client Testing
```bash
# Alice (Terminal 3):
read /files/alice.txt

# Bob (Terminal 4) - simultaneously:
read /files/bob.txt
```
**Verification:** Router GUI shows separate packet flows, no mixing

### 4. Write Operations
```bash
write /storage/newfile
```
**Expected:** Storage node confirms write operation

### 5. Fragment Requests
```bash
read /files/document.pdf:[1/4]
```
**Expected:** Fragment notation recognized and processed

---

## Authentication Flow (Architecture)

**Current Status:** Implemented router-storage flow
**Missing:** Server authentication integration

**Planned Flow:**
```
1. Client → Router (Interest)
2. Router → Server (Permission check)
3. Server → Router (Auth response)
4. Router → Storage (if authorized)
5. Storage → Router (Data)
6. Router → Client (Data)
```

---

## GUI Debugging Features

### Dual-Panel Interface
**Left Panel:** Control Messages
- FIB routing table
- PIT entries
- Content Store status
- System statistics

**Right Panel:** Packet Debugging  
- Interest packets (RED)
- Data packets (BLUE)
- Error messages (ORANGE)
- Timestamps for trace analysis

### Filters
- Toggle packet type visibility
- Export logs for documentation
- Real-time statistics

---

## Technical Specifications

### Protocol Details
- **Transport:** UDP (connectionless)
- **Packet Format:** JSON serialization
- **Checksum:** SHA-256 (8-character hash)
- **Naming:** Hierarchical paths (e.g., /dlsu/storage/file)

### Port Allocation
- Router: 8001 (fixed)
- Storage: 9001 (fixed)
- Server: 7001 (fixed)
- Clients: Ephemeral (auto-assigned)

### File Structure
```
named_networks/
├── router.py              # Central hub
├── storage_node.py        # RAID storage
├── simple_client.py       # User interface
├── common.py              # Shared utilities
├── communication_module.py # UDP networking
├── parsing_module.py      # Packet validation
├── processing_module.py   # Business logic
├── routing_module.py      # FIB management
└── debug_gui.py           # Visualization
```

---

## Troubleshooting

### Common Issues

**"Address already in use"**
```bash
# Kill existing processes:
lsof -ti:8001 | xargs kill -9    # Router
lsof -ti:9001 | xargs kill -9    # Storage
```

**"No response from router"**
```bash
# Verify router is running:
netstat -an | grep 8001
```

**GUI not appearing**
```bash
# Test Tkinter:
python -m tkinter
# If fails, install: sudo apt-get install python3-tk
```

### Performance Verification

**Cache Hit Rate:** Should be >30% with repeated requests
**Response Time:** Cache hits <10ms, misses <100ms
**Success Rate:** Should be >95% under normal conditions

---

## Implementation Notes

### Deviations from Original Design
These changes are documented for Chapter 5:

1. **Protocol Change:** TCP → UDP (NDN alignment)
2. **Topology:** Multi-router → Hub-spoke (validation first)
3. **Checksum:** Custom → SHA-256 (consistency)
4. **Error Handling:** Fail-fast → Auto-correction (robustness)

### Technology Justifications

**Python:** Rapid prototyping, cross-platform compatibility
**UDP:** Stateless packet forwarding matches NDN principles
**JSON:** Human-readable debugging, easy parsing
**Tkinter:** Built-in GUI, fast deployment for visualization
**SHA-256:** Cryptographic security, consistent validation

---

## Demo Checklist

Before presenting to adviser:

**Working Demonstrations:**
- [ ] All 4 components start without errors
- [ ] Interest/Data flow visible in GUI
- [ ] Cache hit/miss behavior clear
- [ ] Concurrent clients work correctly
- [ ] Storage node responds to all requests
- [ ] No packet mixing between clients
- [ ] Clean logs without warnings

**Key Metrics:**
- [ ] Success rate >95%
- [ ] Cache hit rate >30%
- [ ] Response times consistent
- [ ] UDP protocol throughout

---

## Next Steps

### Short-term (Current Sprint)
1. Server node integration for authentication
2. Complete permission validation flow
3. Enhanced concurrent testing

### Medium-term (Next Sprint)  
1. Multiple storage nodes
2. Load balancing between storage
3. Fragment distribution testing

### Long-term (Future Sprints)
1. Multi-router topology
2. Dynamic routing protocols
3. Advanced RAID implementations

---

## Unused / Archival (Suggested) 📁

**Files / folders identified as candidates for archival or removal:**
- `improved_client_gui.py` — alternate/improved client GUI; **no references found** in the repository. Archive if not needed for demos.
- `improved_debug_gui.py` — alternate debug GUI; **no references found**. Archive if unused.
- `__MACOSX/` and files named `._*` — macOS metadata and duplicate artifacts; **safe to delete**.

**Recommended actions:**
1. Move alternates to an `archive/` folder (keeps history and prevents accidental deletion):
   ```bash
   mkdir -p archive
   git mv improved_client_gui.py improved_debug_gui.py archive/ || mv improved_client_gui.py improved_debug_gui.py archive/
   ```
2. Remove macOS artifacts:
   ```bash
   git rm -r __MACOSX/ || rm -r __MACOSX/
   ```
3. Commit with a clear message (e.g., "archive: move unused GUIs; remove macOS artifacts") so changes are reversible.

**Note:** Demo/test scripts (e.g., `test_*.py`, `security_module_tester.py`, `router_raid_demonstration.py`, `router_raid_aware.py`) are intentionally **kept** for demonstration and testing and should not be removed unless you decide to archive them as well.

If you'd like, I can move the files into `archive/` and add a short note in the README describing the change (safe git-friendly change).

## Contact

For questions about implementation details or testing procedures, refer to the individual module documentation within each Python file.

**System Status:** Ready for demonstration with hub-and-spoke topology and storage integration.