#!/usr/bin/env python3
"""
Parsing Module - Named Networks Framework
Handles Interest/Data packet parsing and validation
Interfaces with Communication Module and Processing Module
"""

import json
import re
from typing import Optional, Tuple, Dict, Any
from common import InterestPacket, DataPacket, PacketType, calculate_checksum

class ParsingModule:
    """
    Parsing Module for Named Networks Framework
    Decodes network packets and extracts routing metadata
    """
    
    def __init__(self, node_name: str):
        self.node_name = node_name
        self.processing_handler: Optional[callable] = None
        print(f"[{self.node_name}][PARSING] Parsing Module initialized")
    
    def set_processing_handler(self, handler: callable):
        """Set handler for processed packets (Processing Module interface)"""
        self.processing_handler = handler
        print(f"[{self.node_name}][PARSING] Processing handler registered")
    
    def handle_packet(self, raw_packet: str, source: str) -> Optional[str]:
        """
        Main entry point from Communication Module
        Parses packet and forwards to Processing Module
        """
        try:
            # Step 1: Packet Classification
            packet_type = self._classify_packet(raw_packet)
            if not packet_type:
                return self._create_error_response("Invalid packet format")
            
            print(f"[{self.node_name}][PARSING] Processing {packet_type} packet from {source}")
            
            # Step 2: Parse based on type
            if packet_type == PacketType.INTEREST:
                return self._handle_interest_packet(raw_packet, source)
            elif packet_type == PacketType.DATA:
                return self._handle_data_packet(raw_packet, source)
            else:
                return self._create_error_response("Unknown packet type")
                
        except Exception as e:
            print(f"[{self.node_name}][PARSING] Error handling packet: {e}")
            return self._create_error_response(f"Parsing error: {str(e)}")
    
    def _classify_packet(self, raw_packet: str) -> Optional[PacketType]:
        """Classify packet type from raw data"""
        try:
            packet_data = json.loads(raw_packet)
            packet_type_str = packet_data.get("type", "").upper()
            
            if packet_type_str == "INTEREST":
                return PacketType.INTEREST
            elif packet_type_str == "DATA":
                return PacketType.DATA
            else:
                return None
                
        except (json.JSONDecodeError, KeyError):
            return None
    
    def _handle_interest_packet(self, raw_packet: str, source: str) -> Optional[str]:
        """Handle Interest packet parsing and validation"""
        try:
            # Parse Interest packet
            interest_packet = InterestPacket.from_json(raw_packet)
            
            # Validation
            validation_result = self._validate_interest_packet(interest_packet)
            if not validation_result["valid"]:
                return self._create_error_response(f"Invalid Interest: {validation_result['error']}")
            
            # Fragment support check
            fragment_info = self._parse_fragment_notation(interest_packet.name)
            if fragment_info:
                print(f"[{self.node_name}][PARSING] Fragment request: {fragment_info['base_name']} [{fragment_info['index']}/{fragment_info['total']}]")
            
            print(f"[{self.node_name}][PARSING] Valid Interest for: {interest_packet.name}")
            print(f"[{self.node_name}][PARSING] Operation: {interest_packet.operation}, User: {interest_packet.user_id}")
            
            # Forward to Processing Module if handler is set
            if self.processing_handler:
                return self.processing_handler(interest_packet, source, "interest")
            else:
                # Simple response for testing without Processing Module
                return self._create_simple_data_response(interest_packet.name, "Hello from router!")
                
        except Exception as e:
            print(f"[{self.node_name}][PARSING] Error parsing Interest packet: {e}")
            return self._create_error_response(f"Interest parsing error: {str(e)}")
    
    def _handle_data_packet(self, raw_packet: str, source: str) -> Optional[str]:
        """Handle Data packet parsing and validation"""
        try:
            # Parse Data packet
            data_packet = DataPacket.from_json(raw_packet)
            
            # Validation
            validation_result = self._validate_data_packet(data_packet)
            if not validation_result["valid"]:
                return self._create_error_response(f"Invalid Data: {validation_result['error']}")
            
            print(f"[{self.node_name}][PARSING] Valid Data for: {data_packet.name}")
            print(f"[{self.node_name}][PARSING] Payload size: {data_packet.data_length} bytes")
            
            # Forward to Processing Module if handler is set
            if self.processing_handler:
                return self.processing_handler(data_packet, source, "data")
            else:
                # Simple ACK response
                return "ACK"
                
        except Exception as e:
            print(f"[{self.node_name}][PARSING] Error parsing Data packet: {e}")
            return self._create_error_response(f"Data parsing error: {str(e)}")
    
    def _validate_interest_packet(self, packet: InterestPacket) -> Dict[str, Any]:
        """Validate Interest packet structure and content"""
        
        # Check required fields
        if not packet.name:
            return {"valid": False, "error": "Missing content name"}
        
        if not packet.user_id:
            return {"valid": False, "error": "Missing user ID"}
        
        # Validate hierarchical name structure
        if not self._validate_content_name(packet.name):
            return {"valid": False, "error": "Invalid content name format"}
        
        # Validate operation type
        valid_operations = ["READ", "WRITE", "PERMISSION"]
        if packet.operation not in valid_operations:
            return {"valid": False, "error": f"Invalid operation: {packet.operation}"}
        
        # Checksum validation (if provided)
        if packet.checksum:
            expected_checksum = calculate_checksum(packet.name + packet.user_id + packet.operation)
            if packet.checksum != expected_checksum:
                print(f"[{self.node_name}][PARSING] Warning: Checksum mismatch")
        
        return {"valid": True}
    
    def _validate_data_packet(self, packet: DataPacket) -> Dict[str, Any]:
        """Validate Data packet structure and content"""
        
        # Check required fields
        if not packet.name:
            return {"valid": False, "error": "Missing content name"}
        
        # Validate data length consistency
        if packet.data_length != len(packet.data_payload):
            return {"valid": False, "error": "Data length mismatch"}
        
        # Validate content name
        if not self._validate_content_name(packet.name):
            return {"valid": False, "error": "Invalid content name format"}
        
        return {"valid": True}
    
    def _validate_content_name(self, name: str) -> bool:
        """Validate hierarchical content name structure"""
        # Must start with /
        if not name.startswith('/'):
            return False
        
        # Check for valid hierarchical structure
        # Pattern: /organization/department/resource or with fragment notation
        pattern = r'^/[\w-]+(/[\w-]+)*(\:\[\d+/\d+\])?$'
        return bool(re.match(pattern, name))
    
    def _parse_fragment_notation(self, name: str) -> Optional[Dict[str, Any]]:
        """Parse fragment notation from content name"""
        # Pattern: /path/to/file:[index/total]
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
    
    def _create_error_response(self, error_message: str) -> str:
        """Create error Data packet response"""
        error_packet = DataPacket(
            name="/error",
            data_payload=error_message.encode('utf-8'),
            data_length=len(error_message),
            checksum="error"
        )
        return error_packet.to_json()
    
    def _create_simple_data_response(self, name: str, content: str) -> str:
        """Create simple Data packet response for testing"""
        data_packet = DataPacket(
            name=name,
            data_payload=content.encode('utf-8'),
            data_length=len(content),
            checksum=calculate_checksum(content)
        )
        return data_packet.to_json()
    
    def get_parsing_stats(self) -> Dict[str, int]:
        """Get parsing statistics (for monitoring)"""
        # In a real implementation, this would track various metrics
        return {
            "total_packets_parsed": 0,
            "interest_packets": 0,
            "data_packets": 0,
            "parsing_errors": 0,
            "validation_failures": 0
        }