#!/usr/bin/env python3
"""
Named Networks Framework - Common Components
FIXED: Nonce removed per adviser feedback
"""

import json
import time
import hashlib
import threading
import queue
from dataclasses import dataclass
from typing import Dict, List, Optional
from enum import Enum


def get_optimal_fragment_size(file_size_bytes: int) -> int:
    """
    Returns optimal fragment size based on file size to reduce fragment count.
    
    Adaptive sizing with UDP-safe limits:
    - Small files (<1MB): 4KB fragments
    - Medium files (1-10MB): 8KB fragments  
    - Large files (>10MB): 8KB fragments
    
    IMPORTANT: UDP has practical size limits much smaller than the theoretical 64KB max.
    Windows default UDP buffer is typically 8-16KB. We use 8KB max to ensure reliable
    delivery across all platforms without requiring SO_SNDBUF/SO_RCVBUF socket changes.
    
    For a 10MB file: ~1,280 fragments (8KB) vs ~10,000 fragments (1KB) = 8x improvement.
    """
    ONE_MB = 1024 * 1024
    TEN_MB = 10 * ONE_MB
    
    if file_size_bytes < ONE_MB:
        return 4 * 1024      # 4KB for small files
    else:
        return MAX_UDP_FRAGMENT_SIZE  # 8KB for medium and large files


# Maximum safe UDP fragment size to avoid WinError 10040 (datagram too large)
MAX_UDP_FRAGMENT_SIZE = 8192  # 8KB - safe across all platforms


class PacketType(Enum):
    INTEREST = "INTEREST"
    DATA = "DATA"

@dataclass
class InterestPacket:
    """Interest packet for Named Networks - Storage Protocol Extension

    Extended to support direct-reply addresses (`reply_host` and `reply_port`)
    so a requester can indicate where to receive pushed fragments. Also includes
    an optional `reply_tcp_port` field that allows clients to advertise a TCP
    listener port for reliable large-file transfers (TCP fallback).
    
    For WRITE_DATA operations, `write_payload` carries the base64-encoded data.
    """
    packet_type: str = "INTEREST"
    name: str = ""                    # Hierarchical content name
    user_id: str = ""                 # User identifier
    operation: str = "READ"           # READ, WRITE, WRITE_DATA, PERMISSION, DELETE
    auth_key: Optional[str] = None    # One-time authentication key
    read_token: Optional[str] = None  # Multi-use token for fragment access (avoids re-auth)
    reply_host: Optional[str] = None  # Optional host where replies should be pushed (UDP)
    reply_port: Optional[int] = None  # Optional port where replies should be pushed (UDP)
    reply_tcp_host: Optional[str] = None # Optional TCP host for large transfers (preserve client host)
    reply_tcp_port: Optional[int] = None  # Optional TCP port for large transfers
    checksum: str = ""                # Packet integrity
    # Optional target resource for special Interests (e.g., auth checks)
    target: Optional[str] = None
    # Write payload for WRITE_DATA operations (base64-encoded data)
    write_payload: Optional[str] = None
    # Target storage for WRITE_DATA operations (host:port assigned during WRITE auth)
    target_storage: Optional[str] = None
    
    def to_json(self):
        """Serialize to JSON with standardized checksum"""
        # Include reply addresses in checksum if present for integrity
        parts = []
        if self.reply_host and self.reply_port:
            parts.append(f"{self.reply_host}:{self.reply_port}")
        if self.reply_tcp_host and self.reply_tcp_port:
            parts.append(f"tcp:{self.reply_tcp_host}:{self.reply_tcp_port}")
        reply_part = "|" + ":".join(parts) if parts else ""
        checksum_content = f"{self.name}|{self.user_id}|{self.operation}{reply_part}"
        self.checksum = calculate_checksum(checksum_content)
        
        obj = {
            "type": self.packet_type,
            "name": self.name,
            "user_id": self.user_id,
            "operation": self.operation,
            "auth_key": self.auth_key,
            "read_token": self.read_token,
            "reply_host": self.reply_host,
            "reply_port": self.reply_port,
            "reply_tcp_host": self.reply_tcp_host,
            "reply_tcp_port": self.reply_tcp_port,
            "checksum": self.checksum
        }
        if self.target:
            obj["target"] = self.target
        if self.write_payload:
            obj["write_payload"] = self.write_payload
        if self.target_storage:
            obj["target_storage"] = self.target_storage
        return json.dumps(obj)
    
    @classmethod
    def from_json(cls, json_str):
        """Deserialize from JSON with checksum validation"""
        data = json.loads(json_str)

        # Create packet
        packet = cls(
            packet_type=data.get("type", "INTEREST"),
            name=data.get("name", ""),
            user_id=data.get("user_id", ""),
            operation=data.get("operation", "READ"),
            auth_key=data.get("auth_key"),
            read_token=data.get("read_token"),
            reply_host=data.get("reply_host"),
            reply_port=data.get("reply_port"),
            reply_tcp_host=data.get("reply_tcp_host"),
            reply_tcp_port=data.get("reply_tcp_port"),
            checksum=data.get("checksum", ""),
            target=data.get("target"),
            write_payload=data.get("write_payload"),
            target_storage=data.get("target_storage")
        )

        return packet

    def to_bytes(self) -> bytes:
        """Serialize to bytes for UDP send"""
        return self.to_json().encode('utf-8')

    @classmethod
    def from_bytes(cls, b: bytes):
        """Deserialize from bytes"""
        return cls.from_json(b.decode('utf-8'))
    
    def validate_checksum(self) -> bool:
        """Validate packet checksum"""
        parts = []
        if self.reply_host and self.reply_port:
            parts.append(f"{self.reply_host}:{self.reply_port}")
        if self.reply_tcp_port:
            parts.append(f"tcp:{self.reply_tcp_port}")
        reply_part = "|" + ":".join(parts) if parts else ""
        expected_content = f"{self.name}|{self.user_id}|{self.operation}{reply_part}"
        expected_checksum = calculate_checksum(expected_content)
        return self.checksum == expected_checksum

@dataclass
class DataPacket:
    """Data packet for Named Networks responses

    Extended with optional push metadata to help detect and avoid forwarding loops
    when storage pushes fragments over UDP. Fields:
      - hop_count: increments at each forwarding hop
      - push_id: unique identifier for a particular push transfer
    """
    packet_type: str = "DATA"
    name: str = ""                    # Content name
    data_payload: bytes = b""         # Actual content
    data_length: int = 0              # Payload length
    checksum: str = ""                # Content checksum
    hop_count: int = 0                 # Optional hop-count for push-loop detection
    push_id: Optional[str] = None      # Optional push session id (UUID)
    
    def to_json(self):
        """Serialize to JSON with standardized checksum"""
        # Calculate checksum from payload
        if isinstance(self.data_payload, bytes):
            payload_str = self.data_payload.decode('utf-8', errors='ignore')
        else:
            payload_str = str(self.data_payload)
        
        self.checksum = calculate_checksum(payload_str)
        self.data_length = len(self.data_payload)
        
        # Encode payload as base64 for JSON transport
        import base64
        payload_b64 = base64.b64encode(self.data_payload).decode('utf-8')
        
        obj = {
            "type": self.packet_type,
            "name": self.name,
            "data_payload": payload_b64,
            "data_length": self.data_length,
            "checksum": self.checksum,
            "hop_count": getattr(self, 'hop_count', 0)
        }
        if getattr(self, 'push_id', None):
            obj["push_id"] = self.push_id
        
        return json.dumps(obj)
    
    @classmethod
    def from_json(cls, json_str):
        """Deserialize from JSON"""
        data = json.loads(json_str)
        
        # Decode base64 payload
        import base64
        try:
            payload_b64 = data.get("data_payload", "")
            if payload_b64:
                payload_bytes = base64.b64decode(payload_b64)
            else:
                payload_bytes = b""
        except:
            # Fallback for non-base64 data
            payload_str = data.get("data_payload", "")
            payload_bytes = payload_str.encode('utf-8') if isinstance(payload_str, str) else payload_str
        
        return cls(
            packet_type=data.get("type", "DATA"),
            name=data.get("name", ""),
            data_payload=payload_bytes,
            data_length=data.get("data_length", len(payload_bytes)),
            checksum=data.get("checksum", ""),
            hop_count=data.get("hop_count", 0),
            push_id=data.get("push_id")
        )
    
    def validate_checksum(self) -> bool:
        """Validate data packet checksum"""
        if isinstance(self.data_payload, bytes):
            payload_str = self.data_payload.decode('utf-8', errors='ignore')
        else:
            payload_str = str(self.data_payload)
        
        expected_checksum = calculate_checksum(payload_str)
        return self.checksum == expected_checksum

    def to_dict(self) -> dict:
        """Dictionary representation of DataPacket"""
        return {
            "type": self.packet_type,
            "name": self.name,
            "data_length": self.data_length,
            "checksum": self.checksum,
            "hop_count": self.hop_count,
            "push_id": getattr(self, 'push_id', None)
        }

    def to_bytes(self) -> bytes:
        """Serialize to bytes"""
        return self.to_json().encode('utf-8')

    @classmethod
    def from_bytes(cls, b: bytes):
        """Deserialize from bytes"""
        return cls.from_json(b.decode('utf-8'))

class ContentStore:
    """Content Store - caches named data with LRU eviction and max size limit.
    
    NDN-style cache: simple name → data mapping.
    - Lookup is pure name matching (no timestamp/checksum validation)
    - Eviction is LRU-based when max_size is reached
    - Invalidation is explicit (on WRITE/DELETE operations)
    """
    def __init__(self, max_size: int = 2000):
        # Default 2000 entries: supports ~16MB file with 8KB fragments (2000 * 8KB = 16MB)
        self.store: Dict[str, bytes] = {}
        self.access_order: List[str] = []  # LRU tracking - most recent at end
        self.max_size = max_size
        self._lock = threading.Lock()
    
    def get(self, name: str) -> Optional[bytes]:
        """Retrieve content by name and update access order (LRU).
        
        Simple name-based lookup following NDN principles:
        - If name exists in store, return data
        - No timestamp validation
        - No checksum validation
        - No staleness checks
        """
        with self._lock:
            if name in self.store:
                # Update access order - move to end (most recently used)
                if name in self.access_order:
                    self.access_order.remove(name)
                self.access_order.append(name)
                return self.store[name]
            return None
    
    def put(self, name: str, content: bytes):
        """Store content with name, evicting LRU if at max capacity.
        
        Simple storage: just name → bytes mapping.
        """
        with self._lock:
            if isinstance(content, str):
                content = content.encode('utf-8')
            
            # If already cached, just update
            if name in self.store:
                self.store[name] = content
                # Update access order
                if name in self.access_order:
                    self.access_order.remove(name)
                self.access_order.append(name)
                return
            
            # Evict LRU entries if at max capacity
            while len(self.store) >= self.max_size and self.access_order:
                lru_name = self.access_order.pop(0)  # Remove oldest (first)
                if lru_name in self.store:
                    del self.store[lru_name]
            
            self.store[name] = content
            self.access_order.append(name)
    
    def remove(self, name: str) -> bool:
        """Remove a specific entry from cache (for invalidation)"""
        with self._lock:
            removed = False
            if name in self.store:
                del self.store[name]
                removed = True
            if name in self.access_order:
                self.access_order.remove(name)
            return removed
    
    def has(self, name: str) -> bool:
        """Check if content exists"""
        with self._lock:
            return name in self.store
    
    def size(self) -> int:
        """Get number of cached items"""
        with self._lock:
            return len(self.store)
    
    def remove_by_prefix(self, prefix: str) -> int:
        """Remove all entries whose names start with the given prefix.
        
        Used for cache invalidation when a file is written or deleted.
        E.g., remove_by_prefix("/dlsu/storage/file.txt") removes:
          - /dlsu/storage/file.txt
          - /dlsu/storage/file.txt:[1/100]
          - /dlsu/storage/file.txt:[2/100]
          - etc.
        
        Returns the number of entries removed.
        """
        with self._lock:
            keys_to_remove = [k for k in self.store.keys() if k.startswith(prefix)]
            for key in keys_to_remove:
                del self.store[key]
                if key in self.access_order:
                    self.access_order.remove(key)
            return len(keys_to_remove)
    
    def list_cached(self) -> List[str]:
        """List all cached names (for debugging)"""
        with self._lock:
            return list(self.store.keys())

class PendingInterestTable:
    """Pending Interest Table - tracks forwarded interests"""
    def __init__(self):
        self.table: Dict[str, List[str]] = {}
        self._lock = threading.Lock()
    
    def add_entry(self, name: str, incoming_face: str):
        """Add PIT entry for Interest"""
        with self._lock:
            if name not in self.table:
                self.table[name] = []
            self.table[name].append(incoming_face)
            print(f"[PIT] Added entry: {name} -> {incoming_face}")
    
    def get_faces(self, name: str) -> List[str]:
        """Get all faces for Interest name"""
        with self._lock:
            return self.table.get(name, []).copy()
    
    def remove_entry(self, name: str):
        """Remove PIT entry when Data arrives"""
        with self._lock:
            if name in self.table:
                del self.table[name]
                print(f"[PIT] Removed entry: {name}")
    
    def size(self) -> int:
        """Get number of pending interests"""
        with self._lock:
            return len(self.table)

def calculate_checksum(data: str) -> str:
    """
    Standardized checksum calculation using SHA-256
    """
    if isinstance(data, bytes):
        data = data.decode('utf-8', errors='ignore')
    
    # Use SHA-256 for consistency and security
    hash_obj = hashlib.sha256(data.encode('utf-8'))
    
    # Return first 8 characters for brevity
    return hash_obj.hexdigest()[:8]

def validate_content_name(name: str) -> bool:
    """Validate hierarchical content name format"""
    if not name.startswith('/'):
        return False
    
    # Check for valid characters
    import re
    valid_pattern = r'^[/a-zA-Z0-9._-]+$'
    return bool(re.match(valid_pattern, name))

def parse_fragment_notation(name: str) -> Optional[dict]:
    """Parse fragment notation from content name.

    Returns a dict containing both legacy keys (`index`, `total`) used across the
    codebase and the newer, clearer keys (`fragment_index`, `total_fragments`) so
    callers can migrate safely.
    """
    import re
    pattern = r'^(.+):\[(\d+)/(\d+)\]$'
    match = re.match(pattern, name)

    if match:
        base_name = match.group(1)
        index = int(match.group(2))
        total = int(match.group(3))

        return {
            "base_name": base_name,
            "index": index,
            "total": total,
            "is_fragment": True,
            "fragment_index": index,
            "total_fragments": total
        }

    # Not a fragment
    return {
        "base_name": name,
        "is_fragment": False,
        "fragment_index": 0,
        "total_fragments": 1,
        "index": 0,
        "total": 1
    }


def create_fragment_name(base_name: str, index: int, total: int) -> str:
    """Create fragment notation: /path/file.pdf:[1/4]"""
    return f"{base_name}:[{index}/{total}]"

# Compatibility functions for existing code
def create_interest_packet(name: str, user_id: str, operation: str = "READ", reply_host: str = None, reply_port: int = None, reply_tcp_host: str = None, reply_tcp_port: int = None, target: str = None) -> InterestPacket:
    """Create Interest packet with proper checksum (NO NONCE).

    Optional: provide `reply_host` and `reply_port` to request that the
    storage node push fragments directly to that address (persistent UDP socket).
    Optionally provide `reply_tcp_host` and `reply_tcp_port` to advertise a TCP listener for a
    reliable large-file transfer (TCP fallback).

    `target` can be used to carry the original resource (e.g., when issuing an auth Interest
    with name `/dlsu/server/auth` and `target` set to "/dlsu/storage/file.txt").
    """
    return InterestPacket(
        name=name,
        user_id=user_id,
        operation=operation,
        reply_host=reply_host,
        reply_port=reply_port,
        reply_tcp_host=reply_tcp_host,
        reply_tcp_port=reply_tcp_port,
        target=target
    )

def create_data_packet(name: str, content: str) -> DataPacket:
    """Create Data packet with proper checksum"""
    content_bytes = content.encode('utf-8') if isinstance(content, str) else content
    
    return DataPacket(
        name=name,
        data_payload=content_bytes,
        data_length=len(content_bytes)
    )

class PacketLogger:
    """Simple packet logger that writes to console and per-node files"""
    def __init__(self, node_name: str, log_dir: str = "logs"):
        import os
        from datetime import datetime
        self.node_name = node_name
        self.log_dir = log_dir
        os.makedirs(self.log_dir, exist_ok=True)
        self.log_file = f"{self.log_dir}/{self.node_name}_{datetime.now().strftime('%Y%m%d')}.log"

    def log(self, direction: str, packet_type: str, packet: dict, remote_addr: tuple):
        from datetime import datetime
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        if packet_type == "INTEREST":
            details = f"name={packet.get('name')} user={packet.get('user_id')} op={packet.get('operation')}"
        elif packet_type == "DATA":
            details = f"name={packet.get('name')} status={packet.get('status','OK')}"
        else:
            details = str(packet)
        addr_label = "from" if direction == "RECV" else "to"
        entry = f"[{timestamp}] [{self.node_name}] [{direction}] [{packet_type}] {details} {addr_label}={remote_addr[0]}:{remote_addr[1]}"
        try:
            print(entry)
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(entry + '\n')
        except Exception:
            # avoid raising from logger
            pass

    def export(self, output_path: str):
        import shutil, os
        if os.path.exists(self.log_file):
            shutil.copy(self.log_file, output_path)

# Test checksum consistency
if __name__ == "__main__":
    print("Testing checksum consistency (NO NONCE)...")
    
    # Test Interest packet
    interest = create_interest_packet("/test/file", "alice", "READ")
    print(f"Interest checksum: {interest.checksum}")
    
    # Serialize and deserialize
    json_str = interest.to_json()
    interest2 = InterestPacket.from_json(json_str)
    
    print(f"Original valid: {interest.validate_checksum()}")
    print(f"Deserialized valid: {interest2.validate_checksum()}")
    print(f"Checksums match: {interest.checksum == interest2.checksum}")
    
    # Test Data packet
    data = create_data_packet("/test/file", "Hello World")
    print(f"Data checksum: {data.checksum}")
    print(f"Data valid: {data.validate_checksum()}")