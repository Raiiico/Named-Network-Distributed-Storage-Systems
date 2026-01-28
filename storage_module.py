#!/usr/bin/env python3
"""
Storage Module - Named Networks Framework
Core module for RAID implementation, file management, and storage operations
Used by Storage Nodes to handle actual file storage and retrieval
Includes XOR encryption for data-at-rest security
"""

import os
import time
import hashlib
import threading
import json
import secrets
import base64
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
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
    parity_paths: Dict[str, str] = None  # For RAID 5/6 parity files
    encryption_key: str = None  # XOR encryption key (hex encoded)
    is_encrypted: bool = False  # Whether file is encrypted
    
    def __post_init__(self):
        if self.fragments is None:
            self.fragments = {}
        if self.parity_paths is None:
            self.parity_paths = {}

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
        # over UDP. To avoid OS/UDP datagram-too-large (MTU) issues on localhost
        # and to account for base64+JSON overhead, keep fragments conservative.
        self.fragment_size = 4096  # 5KB fragments (safe for UDP transport)
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

        # Load persisted metadata (if any) so stored files persist across restarts
        try:
            self._load_existing_metadata()
            # Log summary of discovered files
            file_count = len(self.stored_files)
            if file_count > 0:
                print(f"[{self.node_name}][STORAGE] ✓ Discovered {file_count} existing files on disk")
                for fname in list(self.stored_files.keys())[:5]:  # Show first 5
                    print(f"[{self.node_name}][STORAGE]   - {fname}")
                if file_count > 5:
                    print(f"[{self.node_name}][STORAGE]   ... and {file_count - 5} more")
            else:
                print(f"[{self.node_name}][STORAGE] No existing files found on disk")
        except Exception as e:
            print(f"[{self.node_name}][STORAGE] Warning: failed to load existing metadata: {e}")
        
        print(f"[{self.node_name}][STORAGE] Storage Module initialized for RAID {raid_level}")
    
    # ==================== XOR ENCRYPTION ====================
    
    def _generate_xor_key(self, key_length: int = 32) -> bytes:
        """Generate a random XOR key for file encryption"""
        return secrets.token_bytes(key_length)
    
    def _xor_cipher(self, data: bytes, key: bytes) -> bytes:
        """
        XOR cipher implementation for file encryption/decryption
        XOR is symmetric: encrypt and decrypt use the same operation
        """
        # Repeat key to match data length
        extended_key = (key * ((len(data) // len(key)) + 1))[:len(data)]
        # XOR each byte
        result = bytes([data[i] ^ extended_key[i] for i in range(len(data))])
        return result
    
    def encrypt_content(self, content: bytes) -> Tuple[bytes, str]:
        """
        Encrypt content using XOR cipher
        Returns: (encrypted_content, key_hex)
        """
        key = self._generate_xor_key(32)  # 256-bit key
        encrypted = self._xor_cipher(content, key)
        key_hex = key.hex()  # Convert key to hex string for storage/transmission
        return encrypted, key_hex
    
    def decrypt_content(self, encrypted_content: bytes, key_hex: str) -> bytes:
        """
        Decrypt content using XOR cipher
        Args:
            encrypted_content: The encrypted bytes
            key_hex: The hex-encoded encryption key
        Returns: decrypted content
        """
        key = bytes.fromhex(key_hex)
        decrypted = self._xor_cipher(encrypted_content, key)
        return decrypted

    # ==================== STORAGE OPERATIONS ====================
    
    def _initialize_storage(self):
        """Initialize storage directory structure"""
        os.makedirs(self.storage_path, exist_ok=True)
        
        # Create subdirectories for different file types
        subdirs = ["files", "fragments", "parity", "metadata"]
        for subdir in subdirs:
            os.makedirs(os.path.join(self.storage_path, subdir), exist_ok=True)
        
        print(f"[{self.node_name}][STORAGE] Storage initialized at {self.storage_path}")
    
    def store_file(self, file_name: str, content: bytes, encrypt: bool = True) -> StorageResponse:
        """
        Store file using the configured RAID level
        Main entry point for file storage operations
        
        Args:
            file_name: Logical name for the file
            content: Raw file content bytes
            encrypt: Whether to encrypt the content (default True)
        
        Returns:
            StorageResponse with encryption_key in storage_info if encrypted
        """
        try:
            print(f"[{self.node_name}][STORAGE] Storing file: {file_name} ({len(content)} bytes) with RAID {self.raid_level.value}")
            
            # XOR encrypt content before storage
            encryption_key = None
            content_to_store = content
            if encrypt:
                content_to_store, encryption_key = self.encrypt_content(content)
                print(f"[{self.node_name}][STORAGE] File encrypted with XOR (key: {encryption_key[:16]}...)")
            
            # Apply RAID-specific processing
            processed_content, storage_info = self._apply_raid_write(content_to_store, file_name)
            
            # Add encryption info to storage_info
            storage_info['encrypted'] = encrypt
            if encryption_key:
                storage_info['encryption_key'] = encryption_key
            
            # Generate storage path using the original basename so uploaded
            # hierarchical names like '/dlsu/uploads/foo.zip' become 'foo.zip'
            base_name = os.path.basename(file_name) or file_name
            safe_base = self._sanitize_filename(base_name)
            file_path = os.path.join(self.storage_path, "files", safe_base)

            # Check if this file already exists in our index - if so, UPDATE it (overwrite)
            with self._storage_lock:
                existing_meta = self.stored_files.get(file_name)
            
            if existing_meta and existing_meta.file_path and os.path.exists(existing_meta.file_path):
                # Update existing file - use the same path
                file_path = existing_meta.file_path
                print(f"[{self.node_name}][STORAGE] Updating existing file at {file_path}")
            
            # Write processed content to disk (create or overwrite)
            with open(file_path, 'wb') as f:
                f.write(processed_content)
            
            # Create and store metadata (include encryption info)
            metadata = FileMetadata(
                file_name=file_name,
                original_size=len(content),
                stored_size=len(processed_content),
                raid_level=self.raid_level.value,
                checksum=hashlib.md5(content).hexdigest(),  # Checksum of ORIGINAL content
                stored_at=time.time(),
                file_path=file_path,
                encryption_key=encryption_key,
                is_encrypted=encrypt
            )
            
            # Store metadata
            with self._storage_lock:
                self.stored_files[file_name] = metadata
            
            # Write metadata JSON for persistence
            # NOTE: We do NOT store encryption key in local metadata - it goes to server only
            try:
                meta_dir = os.path.join(self.storage_path, 'metadata')
                os.makedirs(meta_dir, exist_ok=True)
                safe_name = os.path.basename(metadata.file_path) if metadata.file_path else self._sanitize_filename(file_name)
                meta_path = os.path.join(meta_dir, f"{safe_name}.json")
                meta = {
                    "original_name": file_name,
                    "stored_path": metadata.file_path,
                    "checksum": metadata.checksum,
                    "size": metadata.original_size,
                    "stored_at": time.strftime('%Y-%m-%d %H:%M:%S'),
                    "fragments": {},
                    "is_encrypted": encrypt
                    # encryption_key intentionally NOT stored locally - sent to server
                }
                with open(meta_path, 'w', encoding='utf-8') as mf:
                    json.dump(meta, mf, indent=2)
            except Exception as e:
                print(f"[{self.node_name}][STORAGE] Warning: failed to write metadata JSON: {e}")

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
    
    def retrieve_file(self, file_name: str, decryption_key: str = None) -> StorageResponse:
        """
        Retrieve file and apply RAID-specific processing
        Main entry point for file retrieval operations
        
        Args:
            file_name: The logical name of the file to retrieve
            decryption_key: Optional hex-encoded XOR key for decryption.
                           If file is encrypted and key not provided, returns encrypted content.
        
        Returns:
            StorageResponse with decrypted content if key provided, else encrypted content
        """
        try:
            print(f"[{self.node_name}][STORAGE] Retrieving file: {file_name}")
            
            # Get file metadata from in-memory index
            with self._storage_lock:
                metadata = self.stored_files.get(file_name)
            
            # If not in memory, try to find it on disk by scanning metadata files
            if not metadata:
                print(f"[{self.node_name}][STORAGE] Not in memory, searching disk...")
                metadata = self._find_file_on_disk(file_name)
                if metadata:
                    # Cache it for future use
                    with self._storage_lock:
                        self.stored_files[file_name] = metadata
            
            if not metadata:
                print(f"[{self.node_name}][STORAGE] File not found: {file_name}")
                return StorageResponse(
                    success=False,
                    error=f"File not found: {file_name}"
                )
            
            # Read stored content
            # If file was stored as fragments, reassemble from fragment files
            if metadata.fragments:
                parts = []
                # fragments is a dict index -> fragment_path
                for idx in sorted(metadata.fragments.keys()):
                    frag_path = metadata.fragments[idx]
                    with open(frag_path, 'rb') as ff:
                        parts.append(ff.read())
                stored_content = b''.join(parts)
            else:
                if not metadata.file_path or not os.path.exists(metadata.file_path):
                    return StorageResponse(
                        success=False,
                        error=f"File path not found: {metadata.file_path}"
                    )
                with open(metadata.file_path, 'rb') as f:
                    stored_content = f.read()
            
            # Apply RAID-specific read processing
            original_content = self._apply_raid_read(stored_content, metadata)
            
            # Handle decryption if file is encrypted
            is_encrypted = getattr(metadata, 'is_encrypted', False)
            if is_encrypted:
                if decryption_key:
                    # Decrypt content using provided key
                    original_content = self.decrypt_content(original_content, decryption_key)
                    print(f"[{self.node_name}][STORAGE] Decrypted content with provided key")
                else:
                    # No key provided - return encrypted content
                    # This allows storage to return data without knowing the key
                    print(f"[{self.node_name}][STORAGE] File is encrypted, no key provided - returning encrypted content")
            
            # Verify integrity (only if we decrypted or file wasn't encrypted)
            if not is_encrypted or decryption_key:
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
    
    def _compute_fragment_parity_raid5(self, fragments: List[bytes]) -> bytes:
        """Compute XOR parity across multiple fragments for RAID 5.
        
        Returns a parity block that is the XOR of all fragments (padded to same length).
        """
        if not fragments:
            return b''
        
        # Find max fragment length and pad all to same size
        max_len = max(len(f) for f in fragments)
        padded = [f + b'\x00' * (max_len - len(f)) for f in fragments]
        
        # XOR all fragments together
        parity = bytearray(max_len)
        for frag in padded:
            for i, byte in enumerate(frag):
                parity[i] ^= byte
        
        return bytes(parity)
    
    def _compute_fragment_parity_raid6(self, fragments: List[bytes]) -> Tuple[bytes, bytes]:
        """Compute P (XOR) and Q (Reed-Solomon-like) parity for RAID 6.
        
        Returns (P_parity, Q_parity) blocks.
        """
        if not fragments:
            return b'', b''
        
        # Find max fragment length and pad all to same size
        max_len = max(len(f) for f in fragments)
        padded = [f + b'\x00' * (max_len - len(f)) for f in fragments]
        
        # P parity: XOR of all fragments
        p_parity = bytearray(max_len)
        for frag in padded:
            for i, byte in enumerate(frag):
                p_parity[i] ^= byte
        
        # Q parity: weighted XOR (simplified Reed-Solomon)
        q_parity = bytearray(max_len)
        for frag_idx, frag in enumerate(padded):
            weight = frag_idx + 1
            for i, byte in enumerate(frag):
                q_parity[i] ^= (byte * weight) % 256
        
        return bytes(p_parity), bytes(q_parity)
    
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

    def store_raid0_fragment(self, file_name: str, fragment_index: int, total_fragments: int, fragment_data: bytes) -> StorageResponse:
        """Store a single RAID 0 fragment without waiting for all fragments.
        
        For RAID 0 striping, each storage node only receives a subset of fragments.
        This method stores individual fragments and updates metadata incrementally.
        
        Args:
            file_name: Base file name (without fragment notation)
            fragment_index: 1-based fragment index
            total_fragments: Total number of fragments in the complete file
            fragment_data: The fragment content bytes
            
        Returns:
            StorageResponse indicating success/failure
        """
        try:
            base_name = os.path.basename(file_name) or file_name
            safe_base = self._sanitize_filename(base_name)
            
            frag_dir = os.path.join(self.storage_path, 'fragments')
            os.makedirs(frag_dir, exist_ok=True)
            
            # Store fragment file with index/total naming
            frag_fname = f"{safe_base}_[{fragment_index}_{total_fragments}]"
            frag_path = os.path.join(frag_dir, frag_fname)
            
            with open(frag_path, 'wb') as ff:
                ff.write(fragment_data)
            
            # Update or create metadata for this file
            with self._storage_lock:
                existing_meta = self.stored_files.get(file_name)
                
                if existing_meta and hasattr(existing_meta, 'fragments') and existing_meta.fragments:
                    # Add to existing fragments map
                    existing_meta.fragments[fragment_index] = frag_path
                    # Update stored size
                    existing_meta.stored_size = existing_meta.stored_size + len(fragment_data)
                    metadata = existing_meta
                else:
                    # Create new metadata for this file
                    metadata = FileMetadata(
                        file_name=file_name,
                        original_size=-1,  # Unknown for RAID 0 partial storage
                        stored_size=len(fragment_data),
                        raid_level=0,  # RAID 0
                        checksum='',  # Cannot compute until all fragments available
                        stored_at=time.time(),
                        file_path='',
                        fragments={fragment_index: frag_path}
                    )
                    # Track total fragments expected
                    metadata.total_fragments = total_fragments
                
                self.stored_files[file_name] = metadata
            
            # Also persist metadata to disk for recovery after restart
            meta_dir = os.path.join(self.storage_path, 'metadata')
            os.makedirs(meta_dir, exist_ok=True)
            meta_path = os.path.join(meta_dir, f"{safe_base}_raid0.json")
            
            # Load existing metadata if present, then update
            disk_meta = {}
            if os.path.exists(meta_path):
                try:
                    with open(meta_path, 'r') as f:
                        disk_meta = json.load(f)
                except:
                    disk_meta = {}
            
            if 'fragments' not in disk_meta:
                disk_meta['fragments'] = {}
            disk_meta['fragments'][str(fragment_index)] = frag_path
            disk_meta['total_fragments'] = total_fragments
            disk_meta['file_name'] = file_name
            disk_meta['raid_level'] = 0
            disk_meta['updated_at'] = time.time()
            
            with open(meta_path, 'w') as f:
                json.dump(disk_meta, f, indent=2)
            
            self.stats["files_stored"] += 1
            self.stats["bytes_written"] += len(fragment_data)
            self.stats["raid_operations"] += 1
            
            print(f"[{self.node_name}][STORAGE] RAID 0: Fragment {fragment_index}/{total_fragments} stored at {frag_path}")
            
            return StorageResponse(success=True, metadata=metadata)
            
        except Exception as e:
            return StorageResponse(success=False, error=f"RAID 0 fragment storage error: {e}")

    def store_fragments(self, file_name: str, fragments: Dict[int, bytes]) -> StorageResponse:
        """Store fragments on disk under `fragments/` and record metadata.

        `fragments` is a dict mapping 1-based index -> bytes for that fragment.
        The method writes each fragment as a separate file and records their
        paths in metadata.fragments. It computes checksum over the reassembled
        original content for integrity.
        
        For RAID 5/6, also generates and stores parity blocks.
        """
        try:
            # Reassemble in memory to compute checksum and sizes
            ordered = [fragments[i] for i in sorted(fragments.keys())]
            assembled = b''.join(ordered)

            base_name = os.path.basename(file_name) or file_name
            safe_base = self._sanitize_filename(base_name)

            frag_dir = os.path.join(self.storage_path, 'fragments')
            parity_dir = os.path.join(self.storage_path, 'parity')
            os.makedirs(frag_dir, exist_ok=True)
            os.makedirs(parity_dir, exist_ok=True)

            # Check if this file already has fragments - if so, delete old ones first
            with self._storage_lock:
                existing_meta = self.stored_files.get(file_name)
            if existing_meta and hasattr(existing_meta, 'fragments') and existing_meta.fragments:
                # Delete old fragment files to allow overwrite
                for old_idx, old_path in existing_meta.fragments.items():
                    if os.path.exists(old_path):
                        try:
                            os.remove(old_path)
                            print(f"[{self.node_name}][STORAGE] Removed old fragment: {old_path}")
                        except Exception as e:
                            print(f"[{self.node_name}][STORAGE] Warning: Could not remove old fragment {old_path}: {e}")
                # Also delete old parity files if they exist
                if hasattr(existing_meta, 'parity_paths') and existing_meta.parity_paths:
                    for parity_key, parity_path in existing_meta.parity_paths.items():
                        if os.path.exists(parity_path):
                            try:
                                os.remove(parity_path)
                                print(f"[{self.node_name}][STORAGE] Removed old parity: {parity_path}")
                            except Exception:
                                pass

            fragments_map = {}
            total_stored = 0
            for idx in sorted(fragments.keys()):
                frag_fname = f"{safe_base}_[{idx}_{len(fragments)}]"
                frag_path = os.path.join(frag_dir, frag_fname)
                # Overwrite existing fragment file (we already cleaned up old fragments above)
                with open(frag_path, 'wb') as ff:
                    ff.write(fragments[idx])
                fragments_map[idx] = frag_path
                total_stored += len(fragments[idx])

            # For RAID 5/6, compute and store parity blocks
            parity_paths = {}
            if self.raid_level == RAIDLevel.RAID5:
                # Compute XOR parity across all fragments
                parity_data = self._compute_fragment_parity_raid5(list(ordered))
                parity_path = os.path.join(parity_dir, f"{safe_base}_parity.bin")
                with open(parity_path, 'wb') as pf:
                    pf.write(parity_data)
                parity_paths['p'] = parity_path
                total_stored += len(parity_data)
                self.stats["parity_calculations"] += 1
                print(f"[{self.node_name}][STORAGE] RAID 5: Stored parity for {file_name} ({len(parity_data)} bytes)")
            elif self.raid_level == RAIDLevel.RAID6:
                # Compute P and Q parity
                p_parity, q_parity = self._compute_fragment_parity_raid6(list(ordered))
                p_path = os.path.join(parity_dir, f"{safe_base}_parity_p.bin")
                q_path = os.path.join(parity_dir, f"{safe_base}_parity_q.bin")
                with open(p_path, 'wb') as pf:
                    pf.write(p_parity)
                with open(q_path, 'wb') as qf:
                    qf.write(q_parity)
                parity_paths['p'] = p_path
                parity_paths['q'] = q_path
                total_stored += len(p_parity) + len(q_parity)
                self.stats["parity_calculations"] += 2
                print(f"[{self.node_name}][STORAGE] RAID 6: Stored dual parity for {file_name}")

            metadata = FileMetadata(
                file_name=file_name,
                original_size=len(assembled),
                stored_size=total_stored,
                raid_level=self.raid_level.value,
                checksum=hashlib.md5(assembled).hexdigest(),
                stored_at=time.time(),
                file_path='',
                fragments=fragments_map
            )
            # Store parity paths in metadata for recovery
            metadata.parity_paths = parity_paths if parity_paths else None

            with self._storage_lock:
                self.stored_files[file_name] = metadata

            self.stats["files_stored"] += 1
            self.stats["bytes_written"] += len(assembled)
            self.stats["raid_operations"] += 1

            return StorageResponse(success=True, metadata=metadata)

        except Exception as e:
            return StorageResponse(success=False, error=f"Fragment store error: {e}")

    def _find_file_on_disk(self, file_name: str) -> Optional[FileMetadata]:
        """Search disk metadata files to find a file by its original name.
        
        This is a fallback when the file isn't in the in-memory index.
        Returns FileMetadata if found, None otherwise.
        """
        meta_dir = os.path.join(self.storage_path, 'metadata')
        if not os.path.isdir(meta_dir):
            return None
        
        # Also try direct file lookup by basename
        base_name = os.path.basename(file_name) or file_name
        safe_base = self._sanitize_filename(base_name)
        direct_path = os.path.join(self.storage_path, 'files', safe_base)
        
        # First, check for RAID 0 metadata file (named *_raid0.json)
        raid0_meta_path = os.path.join(meta_dir, f"{safe_base}_raid0.json")
        if os.path.exists(raid0_meta_path):
            try:
                with open(raid0_meta_path, 'r', encoding='utf-8') as mf:
                    meta = json.load(mf)
                original_name = meta.get('file_name', file_name)
                fragments_map = meta.get('fragments', {}) or {}
                total_fragments = meta.get('total_fragments', len(fragments_map))
                
                # Convert fragment keys to int
                frag_paths = {}
                for k, v in fragments_map.items():
                    try:
                        frag_paths[int(k)] = v
                    except Exception:
                        pass
                
                if frag_paths:
                    file_meta = FileMetadata(
                        file_name=original_name,
                        original_size=-1,  # Unknown for RAID 0 partial storage
                        stored_size=sum(os.path.getsize(p) for p in frag_paths.values() if os.path.exists(p)),
                        raid_level=0,  # RAID 0
                        checksum='',
                        stored_at=meta.get('updated_at', time.time()),
                        file_path='',
                        fragments=frag_paths
                    )
                    file_meta.total_fragments = total_fragments
                    print(f"[{self.node_name}][STORAGE] Found RAID 0 fragments on disk: {original_name} ({len(frag_paths)}/{total_fragments} fragments)")
                    return file_meta
            except Exception as e:
                print(f"[{self.node_name}][STORAGE] Error reading RAID 0 metadata {raid0_meta_path}: {e}")
        
        for fname in os.listdir(meta_dir):
            if not fname.endswith('.json'):
                continue
            meta_path = os.path.join(meta_dir, fname)
            try:
                with open(meta_path, 'r', encoding='utf-8') as mf:
                    meta = json.load(mf)
                original_name = meta.get('original_name', '')
                
                # Match by original name or by base name
                if original_name == file_name or os.path.basename(original_name) == os.path.basename(file_name):
                    stored_path = meta.get('stored_path', '')
                    
                    # Handle RAID 0 fragment-only metadata (no stored_path)
                    fragments_map = meta.get('fragments', {}) or {}
                    if not stored_path and fragments_map:
                        # RAID 0 fragment storage - no full file path
                        frag_paths = {}
                        for k, v in fragments_map.items():
                            try:
                                frag_paths[int(k)] = v
                            except Exception:
                                pass
                        
                        if frag_paths:
                            file_meta = FileMetadata(
                                file_name=original_name,
                                original_size=-1,
                                stored_size=sum(os.path.getsize(p) for p in frag_paths.values() if os.path.exists(p)),
                                raid_level=0,
                                checksum='',
                                stored_at=time.time(),
                                file_path='',
                                fragments=frag_paths
                            )
                            file_meta.total_fragments = meta.get('total_fragments', len(frag_paths))
                            print(f"[{self.node_name}][STORAGE] Found RAID 0 fragments: {original_name}")
                            return file_meta
                    
                    if stored_path and os.path.exists(stored_path):
                        frag_paths = {}
                        for k, v in fragments_map.items():
                            try:
                                frag_paths[int(k)] = v
                            except Exception:
                                pass
                        
                        file_meta = FileMetadata(
                            file_name=original_name,
                            original_size=meta.get('size', 0),
                            stored_size=os.path.getsize(stored_path),
                            raid_level=self.raid_level.value,
                            checksum=meta.get('checksum', ''),
                            stored_at=os.path.getmtime(stored_path),
                            file_path=stored_path,
                            fragments=frag_paths if frag_paths else None
                        )
                        print(f"[{self.node_name}][STORAGE] Found file on disk: {original_name} -> {stored_path}")
                        return file_meta
            except Exception as e:
                print(f"[{self.node_name}][STORAGE] Error reading metadata {meta_path}: {e}")
        
        # Try direct file path if it exists
        if os.path.exists(direct_path):
            print(f"[{self.node_name}][STORAGE] Found file directly: {direct_path}")
            try:
                file_meta = FileMetadata(
                    file_name=file_name,
                    original_size=os.path.getsize(direct_path),
                    stored_size=os.path.getsize(direct_path),
                    raid_level=self.raid_level.value,
                    checksum='',
                    stored_at=os.path.getmtime(direct_path),
                    file_path=direct_path,
                    fragments=None
                )
                return file_meta
            except Exception as e:
                print(f"[{self.node_name}][STORAGE] Error reading direct file: {e}")
        
        return None

    def _load_existing_metadata(self):
        """Load existing metadata JSON files and reconstruct `self.stored_files`.

        This ensures that files stored on disk (in `files/` and `fragments/`) are
        available after a restart.
        """
        meta_dir = os.path.join(self.storage_path, 'metadata')
        if not os.path.isdir(meta_dir):
            return

        for fname in os.listdir(meta_dir):
            if not fname.endswith('.json'):
                continue
            meta_path = os.path.join(meta_dir, fname)
            try:
                with open(meta_path, 'r', encoding='utf-8') as mf:
                    meta = json.load(mf)
                original_name = meta.get('original_name') or ('/' + os.path.splitext(fname)[0])
                stored_path = meta.get('stored_path', '')
                checksum = meta.get('checksum', '')
                size = meta.get('size', 0)
                fragments_map = meta.get('fragments', {}) or {}

                # Convert fragments map values to absolute paths
                frag_paths = {}
                for k, v in fragments_map.items():
                    try:
                        frag_paths[int(k)] = v
                    except Exception:
                        pass

                file_meta = FileMetadata(
                    file_name=original_name,
                    original_size=size,
                    stored_size=os.path.getsize(stored_path) if stored_path and os.path.exists(stored_path) else size,
                    raid_level=self.raid_level.value,
                    checksum=checksum,
                    stored_at=os.path.getmtime(stored_path) if stored_path and os.path.exists(stored_path) else time.time(),
                    file_path=stored_path,
                    fragments=frag_paths
                )

                with self._storage_lock:
                    self.stored_files[original_name] = file_meta

                print(f"[{self.node_name}][STORAGE] Loaded metadata for {original_name}")
            except Exception as e:
                print(f"[{self.node_name}][STORAGE] Warning: failed to load metadata {meta_path}: {e}")

        # Also scan the files directory for any files that don't have metadata JSON
        files_dir = os.path.join(self.storage_path, 'files')
        if os.path.isdir(files_dir):
            for fname in os.listdir(files_dir):
                fpath = os.path.join(files_dir, fname)
                if not os.path.isfile(fpath):
                    continue
                # Determine original name conservatively
                guessed_original = '/' + fname
                if guessed_original not in self.stored_files:
                    try:
                        size = os.path.getsize(fpath)
                        # Use context manager to avoid ResourceWarning for unclosed files
                        checksum = ""
                        try:
                            import hashlib as _hash
                            with open(fpath, 'rb') as fh:
                                m = _hash.md5()
                                for chunk in iter(lambda: fh.read(8192), b''):
                                    m.update(chunk)
                                checksum = m.hexdigest()
                        except Exception as _e:
                            print(f"[{self.node_name}][STORAGE] Warning: checksum compute failed for {fpath}: {_e}")

                        fm = FileMetadata(
                            file_name=guessed_original,
                            original_size=size,
                            stored_size=size,
                            raid_level=self.raid_level.value,
                            checksum=checksum,
                            stored_at=os.path.getmtime(fpath),
                            file_path=fpath,
                            fragments={}
                        )
                        with self._storage_lock:
                            self.stored_files[guessed_original] = fm
                        print(f"[{self.node_name}][STORAGE] Recovered file entry for {guessed_original} (from files/)")
                    except Exception as e:
                        print(f"[{self.node_name}][STORAGE] Warning: failed to recover file {fpath}: {e}")

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
    
    def retrieve_fragment(self, file_name: str, fragment_index: int) -> StorageResponse:
        """Retrieve a single fragment directly from disk (efficient for large files).
        
        For files stored as fragments, this reads only the requested fragment file
        instead of reassembling the entire file. This is MUCH faster for large files.
        
        Args:
            file_name: The base file name (without fragment notation)
            fragment_index: 1-based fragment index to retrieve
            
        Returns:
            StorageResponse with fragment content or error
        """
        try:
            # Get file metadata
            with self._storage_lock:
                metadata = self.stored_files.get(file_name)
            
            if not metadata:
                metadata = self._find_file_on_disk(file_name)
                if metadata:
                    with self._storage_lock:
                        self.stored_files[file_name] = metadata
            
            if not metadata:
                return StorageResponse(success=False, error=f"File not found: {file_name}")
            
            # If file has fragment paths, read directly from disk
            if metadata.fragments and fragment_index in metadata.fragments:
                frag_path = metadata.fragments[fragment_index]
                if os.path.exists(frag_path):
                    with open(frag_path, 'rb') as ff:
                        frag_content = ff.read()
                    return StorageResponse(
                        success=True,
                        content=frag_content,
                        metadata=metadata,
                        storage_info={"fragment_index": fragment_index, "total_fragments": len(metadata.fragments)}
                    )
                else:
                    return StorageResponse(success=False, error=f"Fragment file not found: {frag_path}")
            
            # Fallback: If not stored as fragments, read full file and slice
            # This handles non-fragment files or legacy storage
            if metadata.file_path and os.path.exists(metadata.file_path):
                with open(metadata.file_path, 'rb') as f:
                    content = f.read()
                
                # Calculate fragment boundaries
                from common import MAX_UDP_FRAGMENT_SIZE
                frag_size = MAX_UDP_FRAGMENT_SIZE
                total_frags = (len(content) + frag_size - 1) // frag_size
                
                if 1 <= fragment_index <= total_frags:
                    start = (fragment_index - 1) * frag_size
                    end = min(start + frag_size, len(content))
                    frag_content = content[start:end]
                    return StorageResponse(
                        success=True,
                        content=frag_content,
                        metadata=metadata,
                        storage_info={"fragment_index": fragment_index, "total_fragments": total_frags}
                    )
                else:
                    return StorageResponse(success=False, error=f"Fragment index {fragment_index} out of range (1-{total_frags})")
            
            return StorageResponse(success=False, error=f"No valid storage path for {file_name}")
            
        except Exception as e:
            return StorageResponse(success=False, error=f"Fragment retrieval error: {e}")
    
    def get_fragment_info(self, file_name: str) -> Optional[Dict]:
        """Get fragment information for a file without reading content.
        
        Returns dict with total_fragments and fragment_size if file is large,
        or None if file is small/single-packet.
        """
        with self._storage_lock:
            metadata = self.stored_files.get(file_name)
        
        if not metadata:
            metadata = self._find_file_on_disk(file_name)
        
        if not metadata:
            return None
        
        # If stored as fragments, use fragment count
        if metadata.fragments:
            # For RAID 0, we store only a subset of fragments but know the total
            total_frags = len(metadata.fragments)
            if hasattr(metadata, 'total_fragments') and metadata.total_fragments:
                total_frags = metadata.total_fragments
            
            # Also return which specific fragments this node has (for RAID 0)
            available_fragments = list(metadata.fragments.keys())
            
            return {
                "total_fragments": total_frags,
                "fragment_size": 8192,  # MAX_UDP_FRAGMENT_SIZE
                "total_size": metadata.original_size,
                "available_fragments": available_fragments  # Which fragments this node has
            }
        
        # Otherwise calculate based on file size
        from common import MAX_UDP_FRAGMENT_SIZE
        frag_size = MAX_UDP_FRAGMENT_SIZE
        if metadata.original_size <= frag_size:
            return None  # Single packet, no fragmentation needed
        
        total_frags = (metadata.original_size + frag_size - 1) // frag_size
        return {
            "total_fragments": total_frags,
            "fragment_size": frag_size,
            "total_size": metadata.original_size
        }

    def delete_file(self, file_name: str) -> StorageResponse:
        """Delete file from storage including all fragments and parity files"""
        try:
            with self._storage_lock:
                metadata = self.stored_files.get(file_name)
                
                if not metadata:
                    return StorageResponse(
                        success=False,
                        error="File not found"
                    )
                
                fragments_deleted = 0
                parity_deleted = 0
                
                # Remove fragment files if they exist
                if hasattr(metadata, 'fragments') and metadata.fragments:
                    for frag_idx, frag_path in metadata.fragments.items():
                        if frag_path and os.path.exists(frag_path):
                            try:
                                os.remove(frag_path)
                                fragments_deleted += 1
                            except Exception as e:
                                print(f"[{self.node_name}][STORAGE] Warning: Could not delete fragment {frag_path}: {e}")
                
                # Remove parity files if they exist
                if hasattr(metadata, 'parity_paths') and metadata.parity_paths:
                    for parity_key, parity_path in metadata.parity_paths.items():
                        if parity_path and os.path.exists(parity_path):
                            try:
                                os.remove(parity_path)
                                parity_deleted += 1
                            except Exception as e:
                                print(f"[{self.node_name}][STORAGE] Warning: Could not delete parity {parity_path}: {e}")
                
                # Remove main physical file
                if hasattr(metadata, 'file_path') and metadata.file_path and os.path.exists(metadata.file_path):
                    os.remove(metadata.file_path)
                
                # Remove metadata JSON files (including RAID 0 metadata)
                try:
                    safe_name = self._sanitize_filename(os.path.basename(file_name) or file_name)
                    meta_path = os.path.join(self.storage_path, 'metadata', f"{safe_name}.json")
                    if os.path.exists(meta_path):
                        os.remove(meta_path)
                    # Also remove RAID 0 specific metadata
                    raid0_meta_path = os.path.join(self.storage_path, 'metadata', f"{safe_name}_raid0.json")
                    if os.path.exists(raid0_meta_path):
                        os.remove(raid0_meta_path)
                        print(f"[{self.node_name}][STORAGE]   - RAID 0 metadata removed")
                except Exception:
                    pass
                
                # Remove from in-memory index
                del self.stored_files[file_name]
            
            print(f"[{self.node_name}][STORAGE] Successfully deleted {file_name}")
            if fragments_deleted > 0:
                print(f"[{self.node_name}][STORAGE]   - Fragments removed: {fragments_deleted}")
            if parity_deleted > 0:
                print(f"[{self.node_name}][STORAGE]   - Parity files removed: {parity_deleted}")
            
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