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
import json
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
    parity_paths: Dict[str, str] = None  # For RAID 5/6 parity files
    
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
        except Exception as e:
            print(f"[{self.node_name}][STORAGE] Warning: failed to load existing metadata: {e}")
        
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
            
            # Write metadata JSON for persistence
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
                    "fragments": {}
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
    
    def retrieve_file(self, file_name: str) -> StorageResponse:
        """
        Retrieve file and apply RAID-specific processing
        Main entry point for file retrieval operations
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

            fragments_map = {}
            total_stored = 0
            for idx in sorted(fragments.keys()):
                frag_fname = f"{safe_base}_[{idx}_{len(fragments)}]"
                frag_path = os.path.join(frag_dir, frag_fname)
                # If exists, append timestamp
                if os.path.exists(frag_path):
                    name, ext = os.path.splitext(frag_fname)
                    frag_fname = f"{name}_{int(time.time())}{ext}"
                    frag_path = os.path.join(frag_dir, frag_fname)
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
                    if stored_path and os.path.exists(stored_path):
                        fragments_map = meta.get('fragments', {}) or {}
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