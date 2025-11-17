#!/usr/bin/env python3
"""
Storage Module - Named Networks Framework
Core module for RAID implementation, file management, and storage operations
Used by Storage Nodes to handle actual file storage and retrieval
"""

import os
import time
import hashlib
import threading
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum

class RAIDLevel(Enum):
    RAID0 = 0  # Striping
    RAID1 = 1  # Mirroring
    RAID5 = 5  # Single Parity
    RAID6 = 6  # Double Parity

@dataclass
class FileMetadata:
    """Metadata for stored files"""
    file_name: str
    original_size: int
    stored_size: int
    raid_level: int
    checksum: str
    stored_at: float
    file_path: str
    fragments: Dict[int, str] = None  # For fragmented files
    
    def __post_init__(self):
        if self.fragments is None:
            self.fragments = {}

@dataclass
class StorageResponse:
    """Response structure for storage operations"""
    success: bool
    content: Optional[bytes] = None
    metadata: Optional[FileMetadata] = None
    error: Optional[str] = None
    storage_info: Optional[Dict] = None

class StorageModule:
    """
    Storage Module implementing RAID algorithms and file management
    This module handles the actual storage operations for a specific RAID level
    """
    
    def __init__(self, node_name: str, raid_level: int, storage_path: str):
        self.node_name = node_name
        self.raid_level = RAIDLevel(raid_level)
        self.storage_path = storage_path
        
        # File management
        self.stored_files: Dict[str, FileMetadata] = {}
        # Fragment size used for reassembly/fragmenting large files when sending
        # over UDP. Increased from 1KB to 4KB to reduce fragment count while
        # staying conservative for UDP datagram sizes (base64 increases size).
        self.fragment_size = 4096  # 4KB fragments
        self._storage_lock = threading.Lock()
        
        # RAID configuration
        self.raid_config = {
            RAIDLevel.RAID0: {"description": "Striping", "redundancy": 0},
            RAIDLevel.RAID1: {"description": "Mirroring", "redundancy": 1},
            RAIDLevel.RAID5: {"description": "Single Parity", "redundancy": 1},
            RAIDLevel.RAID6: {"description": "Double Parity", "redundancy": 2}
        }
        
        # Statistics
        self.stats = {
            "files_stored": 0,
            "files_retrieved": 0,
            "bytes_written": 0,
            "bytes_read": 0,
            "raid_operations": 0,
            "parity_calculations": 0,
            "error_corrections": 0
        }
        
        # Initialize storage
        self._initialize_storage()
        
        print(f"[{self.node_name}][STORAGE] Storage Module initialized for RAID {raid_level}")
    
    def _initialize_storage(self):
        """Initialize storage directory structure"""
        os.makedirs(self.storage_path, exist_ok=True)
        
        # Create subdirectories for different file types
        subdirs = ["files", "fragments", "parity", "metadata"]
        for subdir in subdirs:
            os.makedirs(os.path.join(self.storage_path, subdir), exist_ok=True)
        
        print(f"[{self.node_name}][STORAGE] Storage initialized at {self.storage_path}")
    
    def store_file(self, file_name: str, content: bytes) -> StorageResponse:
        """
        Store file using the configured RAID level
        Main entry point for file storage operations
        """
        try:
            print(f"[{self.node_name}][STORAGE] Storing file: {file_name} ({len(content)} bytes) with RAID {self.raid_level.value}")
            
            # Apply RAID-specific processing
            processed_content, storage_info = self._apply_raid_write(content, file_name)
            
            # Generate storage path using the original basename so uploaded
            # hierarchical names like '/dlsu/uploads/foo.zip' become 'foo.zip'
            base_name = os.path.basename(file_name) or file_name
            safe_base = self._sanitize_filename(base_name)
            file_path = os.path.join(self.storage_path, "files", safe_base)

            # If a file with the same safe name already exists, avoid clobbering
            # by appending a timestamp suffix before the extension.
            if os.path.exists(file_path):
                name, ext = os.path.splitext(safe_base)
                timestamp = int(time.time())
                safe_base = f"{name}_{timestamp}{ext}"
                file_path = os.path.join(self.storage_path, "files", safe_base)
            
            # Write processed content to disk
            with open(file_path, 'wb') as f:
                f.write(processed_content)
            
            # Create and store metadata
            metadata = FileMetadata(
                file_name=file_name,
                original_size=len(content),
                stored_size=len(processed_content),
                raid_level=self.raid_level.value,
                checksum=hashlib.md5(content).hexdigest(),
                stored_at=time.time(),
                file_path=file_path
            )
            
            # Store metadata
            with self._storage_lock:
                self.stored_files[file_name] = metadata
            
            # Update statistics
            self.stats["files_stored"] += 1
            self.stats["bytes_written"] += len(content)
            self.stats["raid_operations"] += 1
            
            print(f"[{self.node_name}][STORAGE] Successfully stored {file_name}")
            
            return StorageResponse(
                success=True,
                metadata=metadata,
                storage_info=storage_info
            )
            
        except Exception as e:
            print(f"[{self.node_name}][STORAGE] Error storing file {file_name}: {e}")
            return StorageResponse(
                success=False,
                error=f"Storage error: {str(e)}"
            )
    
    def retrieve_file(self, file_name: str) -> StorageResponse:
        """
        Retrieve file and apply RAID-specific processing
        Main entry point for file retrieval operations
        """
        try:
            print(f"[{self.node_name}][STORAGE] Retrieving file: {file_name}")
            
            # Get file metadata
            with self._storage_lock:
                metadata = self.stored_files.get(file_name)
            
            if not metadata:
                return StorageResponse(
                    success=False,
                    error="File not found"
                )
            
            # Read stored content
            with open(metadata.file_path, 'rb') as f:
                stored_content = f.read()
            
            # Apply RAID-specific read processing
            original_content = self._apply_raid_read(stored_content, metadata)
            
            # Verify integrity
            calculated_checksum = hashlib.md5(original_content).hexdigest()
            if calculated_checksum != metadata.checksum:
                print(f"[{self.node_name}][STORAGE] Warning: Checksum mismatch for {file_name}")
                self.stats["error_corrections"] += 1
            
            # Update statistics
            self.stats["files_retrieved"] += 1
            self.stats["bytes_read"] += len(original_content)
            
            print(f"[{self.node_name}][STORAGE] Successfully retrieved {file_name} ({len(original_content)} bytes)")
            
            return StorageResponse(
                success=True,
                content=original_content,
                metadata=metadata
            )
            
        except Exception as e:
            print(f"[{self.node_name}][STORAGE] Error retrieving file {file_name}: {e}")
            return StorageResponse(
                success=False,
                error=f"Retrieval error: {str(e)}"
            )
    
    def _apply_raid_write(self, content: bytes, file_name: str) -> Tuple[bytes, Dict]:
        """Apply RAID-specific write processing"""
        storage_info = {"raid_level": self.raid_level.value}
        
        if self.raid_level == RAIDLevel.RAID0:
            # RAID 0: Store as-is (striping would be handled at router level)
            processed_content = content
            storage_info["processing"] = "stored_as_is"
            
        elif self.raid_level == RAIDLevel.RAID1:
            # RAID 1: Store complete copy (mirroring)
            processed_content = content
            storage_info["processing"] = "mirrored_copy"
            
        elif self.raid_level == RAIDLevel.RAID5:
            # RAID 5: Add parity information
            processed_content = self._add_parity_raid5(content)
            storage_info["processing"] = "single_parity_added"
            storage_info["parity_bytes"] = len(processed_content) - len(content)
            self.stats["parity_calculations"] += 1
            
        elif self.raid_level == RAIDLevel.RAID6:
            # RAID 6: Add double parity information
            processed_content = self._add_parity_raid6(content)
            storage_info["processing"] = "double_parity_added"
            storage_info["parity_bytes"] = len(processed_content) - len(content)
            self.stats["parity_calculations"] += 2
            
        else:
            processed_content = content
            storage_info["processing"] = "unknown_raid"
        
        return processed_content, storage_info
    
    def _apply_raid_read(self, content: bytes, metadata: FileMetadata) -> bytes:
        """Apply RAID-specific read processing"""
        
        if self.raid_level == RAIDLevel.RAID0:
            # RAID 0: Return as-is
            return content
            
        elif self.raid_level == RAIDLevel.RAID1:
            # RAID 1: Return mirrored content
            return content
            
        elif self.raid_level == RAIDLevel.RAID5:
            # RAID 5: Extract content and verify parity
            return self._extract_parity_raid5(content)
            
        elif self.raid_level == RAIDLevel.RAID6:
            # RAID 6: Extract content and verify double parity
            return self._extract_parity_raid6(content)
            
        else:
            return content
    
    def _add_parity_raid5(self, content: bytes) -> bytes:
        """Add single parity for RAID 5"""
        # Simple XOR parity calculation
        parity = 0
        for byte in content:
            parity ^= byte
        
        # Create parity block (simplified - in real RAID 5, parity is distributed)
        parity_block = bytes([parity])
        
        print(f"[{self.node_name}][STORAGE] RAID 5: Added parity byte {parity}")
        
        return content + parity_block
    
    def _add_parity_raid6(self, content: bytes) -> bytes:
        """Add double parity for RAID 6"""
        # P parity (XOR-based like RAID 5)
        p_parity = 0
        for byte in content:
            p_parity ^= byte
        
        # Q parity (Reed-Solomon-like, simplified)
        q_parity = 0
        for i, byte in enumerate(content):
            q_parity ^= (byte * (i + 1)) % 256
        
        # Create dual parity blocks
        parity_blocks = bytes([p_parity, q_parity])
        
        print(f"[{self.node_name}][STORAGE] RAID 6: Added P={p_parity}, Q={q_parity}")
        
        return content + parity_blocks
    
    def _extract_parity_raid5(self, content: bytes) -> bytes:
        """Extract original content from RAID 5 with parity verification"""
        if len(content) <= 1:
            return content
        
        # Separate content and parity
        original_content = content[:-1]
        stored_parity = content[-1]
        
        # Verify parity
        calculated_parity = 0
        for byte in original_content:
            calculated_parity ^= byte
        
        if calculated_parity != stored_parity:
            print(f"[{self.node_name}][STORAGE] RAID 5: Parity mismatch! Stored={stored_parity}, Calculated={calculated_parity}")
            self.stats["error_corrections"] += 1
        else:
            print(f"[{self.node_name}][STORAGE] RAID 5: Parity verification successful")
        
        return original_content
    
    def _extract_parity_raid6(self, content: bytes) -> bytes:
        """Extract original content from RAID 6 with dual parity verification"""
        if len(content) <= 2:
            return content
        
        # Separate content and dual parity
        original_content = content[:-2]
        stored_p_parity = content[-2]
        stored_q_parity = content[-1]
        
        # Verify P parity
        calculated_p_parity = 0
        for byte in original_content:
            calculated_p_parity ^= byte
        
        # Verify Q parity
        calculated_q_parity = 0
        for i, byte in enumerate(original_content):
            calculated_q_parity ^= (byte * (i + 1)) % 256
        
        p_valid = calculated_p_parity == stored_p_parity
        q_valid = calculated_q_parity == stored_q_parity
        
        if not p_valid or not q_valid:
            print(f"[{self.node_name}][STORAGE] RAID 6: Parity mismatch! P={p_valid}, Q={q_valid}")
            self.stats["error_corrections"] += 1
        else:
            print(f"[{self.node_name}][STORAGE] RAID 6: Dual parity verification successful")
        
        return original_content
    
    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename for filesystem storage"""
        # Replace path separators and unsafe characters
        safe_name = filename.replace('/', '_').replace('\\', '_')
        safe_name = safe_name.replace(':', '_').replace('*', '_')
        safe_name = safe_name.replace('?', '_').replace('"', '_')
        safe_name = safe_name.replace('<', '_').replace('>', '_')
        safe_name = safe_name.replace('|', '_')
        
        # Add timestamp if filename is too generic
        if safe_name in ['', '_', '__']:
            safe_name = f"file_{int(time.time())}"
        
        return safe_name
    
    def fragment_file(self, content: bytes) -> Dict[int, bytes]:
        """Fragment large files into smaller chunks"""
        fragments = {}
        fragment_index = 0
        
        for i in range(0, len(content), self.fragment_size):
            fragment_data = content[i:i + self.fragment_size]
            fragments[fragment_index] = fragment_data
            fragment_index += 1
        
        print(f"[{self.node_name}][STORAGE] Fragmented file into {len(fragments)} fragments")
        return fragments
    
    def reassemble_fragments(self, fragments: Dict[int, bytes]) -> bytes:
        """Reassemble file from fragments"""
        sorted_fragments = sorted(fragments.items())
        return b''.join([frag_data for _, frag_data in sorted_fragments])
    
    def delete_file(self, file_name: str) -> StorageResponse:
        """Delete file from storage"""
        try:
            with self._storage_lock:
                metadata = self.stored_files.get(file_name)
                
                if not metadata:
                    return StorageResponse(
                        success=False,
                        error="File not found"
                    )
                
                # Remove physical file
                if os.path.exists(metadata.file_path):
                    os.remove(metadata.file_path)
                
                # Remove from metadata
                del self.stored_files[file_name]
            
            print(f"[{self.node_name}][STORAGE] Successfully deleted {file_name}")
            
            return StorageResponse(success=True)
            
        except Exception as e:
            print(f"[{self.node_name}][STORAGE] Error deleting file {file_name}: {e}")
            return StorageResponse(
                success=False,
                error=f"Deletion error: {str(e)}"
            )
    
    def list_files(self) -> List[FileMetadata]:
        """List all stored files"""
        with self._storage_lock:
            return list(self.stored_files.values())
    
    def get_storage_info(self) -> Dict[str, Any]:
        """Get storage module information"""
        total_files = len(self.stored_files)
        total_size = sum(metadata.original_size for metadata in self.stored_files.values())
        
        return {
            "raid_level": self.raid_level.value,
            "raid_description": self.raid_config[self.raid_level]["description"],
            "storage_path": self.storage_path,
            "total_files": total_files,
            "total_size_bytes": total_size,
            "fragment_size": self.fragment_size,
            **self.stats
        }
    
    def show_stats(self):
        """Display storage module statistics"""
        info = self.get_storage_info()
        
        print(f"\n=== {self.node_name} Storage Module Statistics ===")
        print(f"RAID Level: {info['raid_level']} ({info['raid_description']})")
        print(f"Storage Path: {info['storage_path']}")
        print(f"Files Stored: {info['files_stored']}")
        print(f"Files Retrieved: {info['files_retrieved']}")
        print(f"Total Files: {info['total_files']}")
        print(f"Total Size: {info['total_size_bytes']} bytes")
        print(f"Bytes Written: {info['bytes_written']}")
        print(f"Bytes Read: {info['bytes_read']}")
        print(f"RAID Operations: {info['raid_operations']}")
        print(f"Parity Calculations: {info['parity_calculations']}")
        print(f"Error Corrections: {info['error_corrections']}")
        print("=" * 60)