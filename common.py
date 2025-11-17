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

class PacketType(Enum):
    INTEREST = "INTEREST"
    DATA = "DATA"

@dataclass
class InterestPacket:
    """Interest packet for Named Networks - Storage Protocol Extension"""
    packet_type: str = "INTEREST"
    name: str = ""                    # Hierarchical content name
    user_id: str = ""                 # User identifier
    operation: str = "READ"           # READ, WRITE, PERMISSION
    auth_key: Optional[str] = None    # One-time authentication key
    checksum: str = ""                # Packet integrity
    
    def to_json(self):
        """Serialize to JSON with standardized checksum"""
        # Calculate checksum from deterministic content (NO NONCE)
        checksum_content = f"{self.name}|{self.user_id}|{self.operation}"
        self.checksum = calculate_checksum(checksum_content)
        
        return json.dumps({
            "type": self.packet_type,
            "name": self.name,
            "user_id": self.user_id,
            "operation": self.operation,
            "auth_key": self.auth_key,
            "checksum": self.checksum
        })
    
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
            checksum=data.get("checksum", "")
        )
        
        return packet
    
    def validate_checksum(self) -> bool:
        """Validate packet checksum"""
        expected_content = f"{self.name}|{self.user_id}|{self.operation}"
        expected_checksum = calculate_checksum(expected_content)
        return self.checksum == expected_checksum

@dataclass
class DataPacket:
    """Data packet for Named Networks responses"""
    packet_type: str = "DATA"
    name: str = ""                    # Content name
    data_payload: bytes = b""         # Actual content
    data_length: int = 0              # Payload length
    checksum: str = ""                # Content checksum
    
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
        
        return json.dumps({
            "type": self.packet_type,
            "name": self.name,
            "data_payload": payload_b64,
            "data_length": self.data_length,
            "checksum": self.checksum
        })
    
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
            checksum=data.get("checksum", "")
        )
    
    def validate_checksum(self) -> bool:
        """Validate data packet checksum"""
        if isinstance(self.data_payload, bytes):
            payload_str = self.data_payload.decode('utf-8', errors='ignore')
        else:
            payload_str = str(self.data_payload)
        
        expected_checksum = calculate_checksum(payload_str)
        return self.checksum == expected_checksum

class ContentStore:
    """Content Store - caches named data"""
    def __init__(self):
        self.store: Dict[str, bytes] = {}
        self.timestamps: Dict[str, float] = {}
        self._lock = threading.Lock()
    
    def get(self, name: str) -> Optional[bytes]:
        """Retrieve content by name"""
        with self._lock:
            return self.store.get(name)
    
    def put(self, name: str, content: bytes):
        """Store content with name"""
        with self._lock:
            if isinstance(content, str):
                content = content.encode('utf-8')
            
            self.store[name] = content
            self.timestamps[name] = time.time()
            print(f"[CS] Cached content for: {name}")
    
    def has(self, name: str) -> bool:
        """Check if content exists"""
        with self._lock:
            return name in self.store
    
    def size(self) -> int:
        """Get number of cached items"""
        with self._lock:
            return len(self.store)

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
    """Parse fragment notation from content name"""
    # Pattern: /path/to/file:[index/total]
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
            "is_fragment": True
        }
    
    return None

# Compatibility functions for existing code
def create_interest_packet(name: str, user_id: str, operation: str = "READ") -> InterestPacket:
    """Create Interest packet with proper checksum (NO NONCE)"""
    return InterestPacket(
        name=name,
        user_id=user_id,
        operation=operation
    )

def create_data_packet(name: str, content: str) -> DataPacket:
    """Create Data packet with proper checksum"""
    content_bytes = content.encode('utf-8') if isinstance(content, str) else content
    
    return DataPacket(
        name=name,
        data_payload=content_bytes,
        data_length=len(content_bytes)
    )

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