#!/usr/bin/env python3
"""
Named Networks Framework - Common Components
Shared classes and utilities for Interest/Data packets and network tables
"""

import json
import time
from dataclasses import dataclass
from typing import Dict, List, Optional
from enum import Enum

class PacketType(Enum):
    INTEREST = "INTEREST"
    DATA = "DATA"

@dataclass
class InterestPacket:
    """Interest packet for Named Networks"""
    packet_type: str = "INTEREST"
    name: str = ""
    user_id: str = ""
    nonce: int = 0
    
    def to_json(self):
        return json.dumps({
            "type": self.packet_type,
            "name": self.name,
            "user_id": self.user_id,
            "nonce": self.nonce
        })
    
    @classmethod
    def from_json(cls, json_str):
        data = json.loads(json_str)
        return cls(
            packet_type=data["type"],
            name=data["name"],
            user_id=data["user_id"],
            nonce=data["nonce"]
        )

@dataclass
class DataPacket:
    """Data packet for Named Networks"""
    packet_type: str = "DATA"
    name: str = ""
    payload: str = ""
    checksum: str = ""
    
    def to_json(self):
        return json.dumps({
            "type": self.packet_type,
            "name": self.name,
            "payload": self.payload,
            "checksum": self.checksum
        })
    
    @classmethod
    def from_json(cls, json_str):
        data = json.loads(json_str)
        return cls(
            packet_type=data["type"],
            name=data["name"],
            payload=data["payload"],
            checksum=data["checksum"]
        )

class ContentStore:
    """Content Store for caching data packets"""
    def __init__(self):
        self.store: Dict[str, str] = {}
    
    def get(self, name: str) -> Optional[str]:
        return self.store.get(name)
    
    def put(self, name: str, content: str):
        self.store[name] = content
        print(f"[CS] Cached content for: {name}")

class PendingInterestTable:
    """Pending Interest Table - tracks forwarded interests"""
    def __init__(self):
        self.table: Dict[str, List[str]] = {}
    
    def add_entry(self, name: str, incoming_face: str):
        if name not in self.table:
            self.table[name] = []
        self.table[name].append(incoming_face)
        print(f"[PIT] Added entry: {name} -> {incoming_face}")
    
    def get_faces(self, name: str) -> List[str]:
        return self.table.get(name, [])
    
    def remove_entry(self, name: str):
        if name in self.table:
            del self.table[name]
            print(f"[PIT] Removed entry: {name}")

class ForwardingInformationBase:
    """Forwarding Information Base - static routing table"""
    def __init__(self):
        self.fib: Dict[str, str] = {}
    
    def add_route(self, prefix: str, next_hop: str):
        self.fib[prefix] = next_hop
        print(f"[FIB] Added route: {prefix} -> {next_hop}")
    
    def lookup(self, name: str) -> Optional[str]:
        """Longest prefix match lookup"""
        best_match = ""
        next_hop = None
        for prefix, hop in self.fib.items():
            if name.startswith(prefix) and len(prefix) > len(best_match):
                best_match = prefix
                next_hop = hop
        return next_hop

def generate_nonce():
    """Generate a simple nonce for Interest packets"""
    return int(time.time() * 1000) % 10000