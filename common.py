#!/usr/bin/env python3
"""
Named Networks Framework - Common Components
Communication and Parsing Module Components
"""

import json
import time
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
    nonce: int = 0                    # Duplicate detection
    checksum: str = ""                # Packet integrity
    
    def to_json(self):
        return json.dumps({
            "type": self.packet_type,
            "name": self.name,
            "user_id": self.user_id,
            "operation": self.operation,
            "auth_key": self.auth_key,
            "nonce": self.nonce,
            "checksum": self.checksum
        })
    
    @classmethod
    def from_json(cls, json_str):
        data = json.loads(json_str)
        return cls(
            packet_type=data.get("type", "INTEREST"),
            name=data.get("name", ""),
            user_id=data.get("user_id", ""),
            operation=data.get("operation", "READ"),
            auth_key=data.get("auth_key"),
            nonce=data.get("nonce", 0),
            checksum=data.get("checksum", "")
        )

@dataclass
class DataPacket:
    """Data packet for Named Networks - Storage Protocol Extension"""
    packet_type: str = "DATA"
    name: str = ""                    # Matching content name
    data_payload: bytes = b""         # File content or metadata
    data_length: int = 0              # Payload size
    checksum: str = ""                # Packet integrity
    
    def to_json(self):
        # Convert bytes to base64 for JSON serialization
        import base64
        payload_b64 = base64.b64encode(self.data_payload).decode('utf-8') if self.data_payload else ""
        
        return json.dumps({
            "type": self.packet_type,
            "name": self.name,
            "data_payload": payload_b64,
            "data_length": self.data_length,
            "checksum": self.checksum
        })
    
    @classmethod
    def from_json(cls, json_str):
        import base64
        data = json.loads(json_str)
        
        # Convert base64 back to bytes
        payload_b64 = data.get("data_payload", "")
        data_payload = base64.b64decode(payload_b64.encode('utf-8')) if payload_b64 else b""
        
        return cls(
            packet_type=data.get("type", "DATA"),
            name=data.get("name", ""),
            data_payload=data_payload,
            data_length=data.get("data_length", 0),
            checksum=data.get("checksum", "")
        )

class ContentStore:
    """Content Store for caching data packets"""
    def __init__(self):
        self.store: Dict[str, bytes] = {}
        self.timestamps: Dict[str, float] = {}
        self._lock = threading.Lock()
    
    def get(self, name: str) -> Optional[bytes]:
        with self._lock:
            return self.store.get(name)
    
    def put(self, name: str, content: bytes):
        with self._lock:
            self.store[name] = content
            self.timestamps[name] = time.time()
            print(f"[CS] Cached content for: {name}")
    
    def has(self, name: str) -> bool:
        with self._lock:
            return name in self.store

class PendingInterestTable:
    """Pending Interest Table - tracks forwarded interests"""
    def __init__(self):
        self.table: Dict[str, List[str]] = {}
        self._lock = threading.Lock()
    
    def add_entry(self, name: str, incoming_face: str):
        with self._lock:
            if name not in self.table:
                self.table[name] = []
            self.table[name].append(incoming_face)
            print(f"[PIT] Added entry: {name} -> {incoming_face}")
    
    def get_faces(self, name: str) -> List[str]:
        with self._lock:
            return self.table.get(name, []).copy()
    
    def remove_entry(self, name: str):
        with self._lock:
            if name in self.table:
                del self.table[name]
                print(f"[PIT] Removed entry: {name}")

def generate_nonce():
    """Generate a simple nonce for Interest packets"""
    return int(time.time() * 1000) % 100000

def calculate_checksum(data: str) -> str:
    """Simple checksum calculation"""
    return str(hash(data) % 65536)