#!/usr/bin/env python3
"""
Processing Module - Named Networks Framework
Handles core business logic for Interest/Data packet processing
Coordinates with Security and Storage modules
"""

import time
import threading
from typing import Optional, Dict, Any
from dataclasses import dataclass
from common import InterestPacket, DataPacket, ContentStore, PendingInterestTable, calculate_checksum

@dataclass
class ProcessingResponse:
    """Response structure for processing operations"""
    success: bool
    data_packet: Optional[DataPacket] = None
    error_message: Optional[str] = None
    cache_updated: bool = False

class ProcessingModule:
    """
    Processing Module implementing core named networks business logic
    Coordinates file access, permission validation, and response generation
    """
    
    def __init__(self, node_name: str):
        self.node_name = node_name
        self.content_store = ContentStore()
        self.pit = PendingInterestTable()
        
        # Module interfaces
        self.security_handler: Optional[callable] = None
        self.storage_handler: Optional[callable] = None
        self.communication_handler: Optional[callable] = None
        
        # Processing statistics
        self.stats = {
            "total_interests_processed": 0,
            "total_data_packets_processed": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "permission_denials": 0,
            "successful_retrievals": 0
        }
        
        print(f"[{self.node_name}][PROCESSING] Processing Module initialized")
    
    def set_security_handler(self, handler: callable):
        """Set interface to Security Module"""
        self.security_handler = handler
        print(f"[{self.node_name}][PROCESSING] Security handler registered")
    
    def set_storage_handler(self, handler: callable):
        """Set interface to Storage Module"""
        self.storage_handler = handler
        print(f"[{self.node_name}][PROCESSING] Storage handler registered")
    
    def set_communication_handler(self, handler: callable):
        """Set interface to Communication Module for responses"""
        self.communication_handler = handler
        print(f"[{self.node_name}][PROCESSING] Communication handler registered")
    
    def handle_parsed_packet(self, packet, source: str, packet_type: str) -> Optional[str]:
        """
        Main entry point from Parsing Module
        Processes Interest and Data packets according to thesis specifications
        """
        try:
            if packet_type == "interest":
                return self._process_interest_packet(packet, source)
            elif packet_type == "data":
                return self._process_data_packet(packet, source)
            else:
                print(f"[{self.node_name}][PROCESSING] Unknown packet type: {packet_type}")
                return self._create_error_response("Unknown packet type")
                
        except Exception as e:
            print(f"[{self.node_name}][PROCESSING] Error processing packet: {e}")
            return self._create_error_response(f"Processing error: {str(e)}")
    
    def _process_interest_packet(self, interest: InterestPacket, source: str) -> Optional[str]:
        """
        Process Interest packet following thesis workflow:
        1. Check Content Store
        2. Validate permissions (even for cached content)
        3. Forward if needed or respond directly
        """
        self.stats["total_interests_processed"] += 1
        
        print(f"[{self.node_name}][PROCESSING] Processing Interest: {interest.name}")
        print(f"[{self.node_name}][PROCESSING] Operation: {interest.operation}, User: {interest.user_id}")
        
        # Add to PIT for response routing
        self.pit.add_entry(interest.name, source)
        
        # Step 1: Check Content Store
        cached_content = self.content_store.get(interest.name)
        
        if cached_content:
            print(f"[{self.node_name}][PROCESSING] Content Store HIT for: {interest.name}")
            self.stats["cache_hits"] += 1
            
            # Step 2: Validate permissions even for cached content (reactive permission check)
            if self._validate_permissions(interest):
                # Serve cached content
                response = self._create_data_response(interest.name, cached_content)
                self._cleanup_pit_entry(interest.name)
                self.stats["successful_retrievals"] += 1
                return response
            else:
                # Permission denied for cached content
                self.stats["permission_denials"] += 1
                self._cleanup_pit_entry(interest.name)
                return self._create_permission_denied_response(interest.name)
        
        else:
            print(f"[{self.node_name}][PROCESSING] Content Store MISS for: {interest.name}")
            self.stats["cache_misses"] += 1
            
            # Step 3: Handle based on operation type
            return self._handle_operation_request(interest, source)
    
    def _handle_operation_request(self, interest: InterestPacket, source: str) -> Optional[str]:
        """Handle different operation types according to thesis specifications"""
        
        if interest.operation == "READ":
            return self._handle_read_operation(interest, source)
        elif interest.operation == "WRITE":
            return self._handle_write_operation(interest, source)
        elif interest.operation == "PERMISSION":
            return self._handle_permission_operation(interest, source)
        else:
            self._cleanup_pit_entry(interest.name)
            return self._create_error_response(f"Unsupported operation: {interest.operation}")
    
    def _handle_read_operation(self, interest: InterestPacket, source: str) -> Optional[str]:
        """Handle READ operation - retrieve file from storage"""
        
        # Validate permissions first
        if not self._validate_permissions(interest):
            self.stats["permission_denials"] += 1
            self._cleanup_pit_entry(interest.name)
            return self._create_permission_denied_response(interest.name)
        
        # Forward to storage if we have storage handler
        if self.storage_handler:
            try:
                storage_response = self.storage_handler(interest, "retrieve")
                
                if storage_response and storage_response.get("success"):
                    content = storage_response.get("content", b"")
                    
                    # Cache the retrieved content
                    self.content_store.put(interest.name, content)
                    
                    # Create response
                    response = self._create_data_response(interest.name, content)
                    self._cleanup_pit_entry(interest.name)
                    self.stats["successful_retrievals"] += 1
                    return response
                else:
                    error_msg = storage_response.get("error", "Storage retrieval failed")
                    self._cleanup_pit_entry(interest.name)
                    return self._create_error_response(error_msg)
                    
            except Exception as e:
                print(f"[{self.node_name}][PROCESSING] Storage handler error: {e}")
                self._cleanup_pit_entry(interest.name)
                return self._create_error_response("Storage system error")
        
        # No storage handler - generate simple response for testing
        test_content = f"Generated content for {interest.name} requested by {interest.user_id}"
        content_bytes = test_content.encode('utf-8')
        
        # Cache the generated content
        self.content_store.put(interest.name, content_bytes)
        
        response = self._create_data_response(interest.name, content_bytes)
        self._cleanup_pit_entry(interest.name)
        self.stats["successful_retrievals"] += 1
        return response
    
    def _handle_write_operation(self, interest: InterestPacket, source: str) -> Optional[str]:
        """Handle WRITE operation - coordinate storage placement"""
        
        # Validate write permissions
        if not self._validate_permissions(interest):
            self.stats["permission_denials"] += 1
            self._cleanup_pit_entry(interest.name)
            return self._create_permission_denied_response(interest.name)
        
        # For write operations, we typically return storage location info
        if self.storage_handler:
            try:
                storage_response = self.storage_handler(interest, "allocate")
                
                if storage_response and storage_response.get("success"):
                    location_info = storage_response.get("location", "storage_node_1")
                    response_content = f"WRITE_GRANTED:{location_info}"
                    
                    response = self._create_data_response(
                        interest.name, 
                        response_content.encode('utf-8')
                    )
                    self._cleanup_pit_entry(interest.name)
                    return response
                else:
                    error_msg = storage_response.get("error", "Storage allocation failed")
                    self._cleanup_pit_entry(interest.name)
                    return self._create_error_response(error_msg)
                    
            except Exception as e:
                print(f"[{self.node_name}][PROCESSING] Storage allocation error: {e}")
                self._cleanup_pit_entry(interest.name)
                return self._create_error_response("Storage allocation error")
        
        # Simple response for testing without storage module
        response_content = f"WRITE_GRANTED:test_storage_node"
        response = self._create_data_response(interest.name, response_content.encode('utf-8'))
        self._cleanup_pit_entry(interest.name)
        return response
    
    def _handle_permission_operation(self, interest: InterestPacket, source: str) -> Optional[str]:
        """Handle PERMISSION operation - modify access controls"""
        
        # Permission operations require special validation
        if self.security_handler:
            try:
                permission_response = self.security_handler(interest, "modify_permission")
                
                if permission_response and permission_response.get("success"):
                    response_content = "PERMISSION_UPDATED"
                else:
                    response_content = "PERMISSION_DENIED"
                
                response = self._create_data_response(
                    interest.name, 
                    response_content.encode('utf-8')
                )
                self._cleanup_pit_entry(interest.name)
                return response
                
            except Exception as e:
                print(f"[{self.node_name}][PROCESSING] Permission handler error: {e}")
                self._cleanup_pit_entry(interest.name)
                return self._create_error_response("Permission system error")
        
        # Simple response for testing
        response_content = "PERMISSION_UPDATED"
        response = self._create_data_response(interest.name, response_content.encode('utf-8'))
        self._cleanup_pit_entry(interest.name)
        return response
    
    def _process_data_packet(self, data_packet: DataPacket, source: str) -> Optional[str]:
        """Process incoming Data packet"""
        self.stats["total_data_packets_processed"] += 1
        
        print(f"[{self.node_name}][PROCESSING] Received Data packet: {data_packet.name}")
        print(f"[{self.node_name}][PROCESSING] Data length: {data_packet.data_length} bytes")
        
        # Cache the incoming data
        self.content_store.put(data_packet.name, data_packet.data_payload)
        
        # Check if this satisfies any pending interests
        faces = self.pit.get_faces(data_packet.name)
        for face in faces:
            print(f"[{self.node_name}][PROCESSING] Forwarding Data to: {face}")
            # In a real implementation, forward to the requesting face
        
        self.pit.remove_entry(data_packet.name)
        return "ACK"  # Simple acknowledgment
    
    def _validate_permissions(self, interest: InterestPacket) -> bool:
        """
        Validate user permissions using Security Module
        Implements reactive permission checking per thesis
        """
        if self.security_handler:
            try:
                auth_response = self.security_handler(interest, "validate")
                return auth_response and auth_response.get("authorized", False)
            except Exception as e:
                print(f"[{self.node_name}][PROCESSING] Permission validation error: {e}")
                return False
        
        # For testing without security module - allow all operations
        return True
    
    def _create_data_response(self, name: str, content: bytes) -> str:
        """Create Data packet response"""
        data_packet = DataPacket(
            name=name,
            data_payload=content,
            data_length=len(content),
            checksum=calculate_checksum(content.decode('utf-8', errors='ignore'))
        )
        return data_packet.to_json()
    
    def _create_permission_denied_response(self, name: str) -> str:
        """Create permission denied response"""
        error_message = "Permission denied"
        data_packet = DataPacket(
            name="/error/permission_denied",
            data_payload=error_message.encode('utf-8'),
            data_length=len(error_message),
            checksum="permission_error"
        )
        return data_packet.to_json()
    
    def _create_error_response(self, error_message: str) -> str:
        """Create error Data packet response"""
        data_packet = DataPacket(
            name="/error",
            data_payload=error_message.encode('utf-8'),
            data_length=len(error_message),
            checksum="error"
        )
        return data_packet.to_json()
    
    def _cleanup_pit_entry(self, name: str):
        """Remove PIT entry after processing"""
        self.pit.remove_entry(name)
    
    def get_processing_stats(self) -> Dict[str, Any]:
        """Get processing statistics for monitoring"""
        return {
            **self.stats,
            "content_store_entries": len(self.content_store.store),
            "pit_entries": len(self.pit.table),
            "cache_hit_ratio": self.stats["cache_hits"] / max(1, self.stats["cache_hits"] + self.stats["cache_misses"])
        }
    
    def show_stats(self):
        """Display processing statistics"""
        stats = self.get_processing_stats()
        print(f"\n=== {self.node_name} Processing Statistics ===")
        print(f"Total Interest packets processed: {stats['total_interests_processed']}")
        print(f"Total Data packets processed: {stats['total_data_packets_processed']}")
        print(f"Cache hits: {stats['cache_hits']}")
        print(f"Cache misses: {stats['cache_misses']}")
        print(f"Cache hit ratio: {stats['cache_hit_ratio']:.2%}")
        print(f"Permission denials: {stats['permission_denials']}")
        print(f"Successful retrievals: {stats['successful_retrievals']}")
        print(f"Content Store entries: {stats['content_store_entries']}")
        print(f"PIT entries: {stats['pit_entries']}")
        print("=" * 50)