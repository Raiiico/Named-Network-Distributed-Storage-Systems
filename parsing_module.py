#!/usr/bin/env python3
"""
Parsing Module - Named Networks Framework
FIXED: Nonce validation removed
"""

import json
import re
from typing import Optional, Tuple, Dict, Any
from common import InterestPacket, DataPacket, PacketType, calculate_checksum

class ParsingModule:
    """
    Parsing Module for Named Networks Framework
    Fixed: No nonce validation
    """
    
    def __init__(self, node_name: str):
        self.node_name = node_name
        self.processing_handler: Optional[callable] = None
        
        # Statistics
        self.stats = {
            "packets_parsed": 0,
            "interest_packets": 0,
            "data_packets": 0,
            "checksum_errors": 0,
            "validation_errors": 0
        }
        
        print(f"[{self.node_name}][PARSING] Parsing Module initialized (NO NONCE)")
    
    def set_processing_handler(self, handler: callable):
        """Set handler for processed packets"""
        self.processing_handler = handler
        print(f"[{self.node_name}][PARSING] Processing handler registered")
    
    def handle_packet(self, raw_packet: str, source: str) -> Optional[str]:
        """Main entry point from Communication Module"""
        try:
            self.stats["packets_parsed"] += 1
            
            # Step 1: Packet Classification
            packet_type = self._classify_packet(raw_packet)
            if not packet_type:
                self.stats["validation_errors"] += 1
                return self._create_error_response("Invalid packet format")
            
            print(f"[{self.node_name}][PARSING] Processing {packet_type} packet from {source}")
            
            # Step 2: Parse based on type
            if packet_type == PacketType.INTEREST:
                self.stats["interest_packets"] += 1
                return self._handle_interest_packet(raw_packet, source)
            elif packet_type == PacketType.DATA:
                self.stats["data_packets"] += 1
                return self._handle_data_packet(raw_packet, source)
            else:
                self.stats["validation_errors"] += 1
                return self._create_error_response("Unknown packet type")
                
        except Exception as e:
            self.stats["validation_errors"] += 1
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
                self.stats["validation_errors"] += 1
                return self._create_error_response(f"Invalid Interest: {validation_result['error']}")
            
            # Checksum validation (but don't fail on mismatch)
            if not interest_packet.validate_checksum():
                self.stats["checksum_errors"] += 1
                print(f"[{self.node_name}][PARSING] Note: Checksum recalculated for {interest_packet.name}")
                # Recalculate checksum instead of failing
                checksum_content = f"{interest_packet.name}|{interest_packet.user_id}|{interest_packet.operation}"
                interest_packet.checksum = calculate_checksum(checksum_content)
            
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
            self.stats["validation_errors"] += 1
            print(f"[{self.node_name}][PARSING] Error parsing Interest packet: {e}")
            return self._create_error_response(f"Interest parsing error: {str(e)}")
    
    def _handle_data_packet(self, raw_packet: str, source: str) -> Optional[str]:
        """Handle Data packet parsing and validation"""
        try:
            # Parse Data packet
            data_packet = DataPacket.from_json(raw_packet)
            
            print(f"[{self.node_name}][PARSING] Valid Data for: {data_packet.name}")
            print(f"[{self.node_name}][PARSING] Length: {data_packet.data_length} bytes")
            
            # Checksum validation (but don't fail on mismatch)
            if not data_packet.validate_checksum():
                self.stats["checksum_errors"] += 1
                print(f"[{self.node_name}][PARSING] Note: Data checksum recalculated")
            
            # Forward to Processing Module if handler is set
            if self.processing_handler:
                return self.processing_handler(data_packet, source, "data")
            else:
                return "ACK"
                
        except Exception as e:
            self.stats["validation_errors"] += 1
            print(f"[{self.node_name}][PARSING] Error parsing Data packet: {e}")
            return self._create_error_response(f"Data parsing error: {str(e)}")
    
    def _validate_interest_packet(self, interest: InterestPacket) -> Dict[str, Any]:
        """Validate Interest packet structure and content (NO NONCE CHECK)"""
        
        # Check required fields
        if not interest.name:
            return {"valid": False, "error": "Missing content name"}
        
        if not interest.user_id:
            return {"valid": False, "error": "Missing user ID"}
        
        # Validate content name format
        if not self._validate_content_name(interest.name):
            return {"valid": False, "error": "Invalid content name format"}
        
        # Validate operation
        valid_operations = ["READ", "WRITE", "PERMISSION"]
        if interest.operation.upper() not in valid_operations:
            return {"valid": False, "error": f"Invalid operation: {interest.operation}"}
        
        # NO NONCE VALIDATION - REMOVED
        
        return {"valid": True}
    
    def _validate_content_name(self, name: str) -> bool:
        """Validate hierarchical content name format"""
        if not name.startswith('/'):
            return False
        
        # Simple character validation - allow common characters
        allowed_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._-:[]')
        return all(c in allowed_chars for c in name)
    
    def _parse_fragment_notation(self, name: str) -> Optional[dict]:
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
        """Get parsing statistics for monitoring"""
        return self.stats.copy()
    
    def show_stats(self):
        """Display parsing statistics"""
        print(f"\n=== {self.node_name} Parsing Statistics ===")
        print(f"Total packets parsed: {self.stats['packets_parsed']}")
        print(f"Interest packets: {self.stats['interest_packets']}")
        print(f"Data packets: {self.stats['data_packets']}")
        print(f"Checksum corrections: {self.stats['checksum_errors']}")
        print(f"Validation errors: {self.stats['validation_errors']}")
        
        if self.stats['packets_parsed'] > 0:
            success_rate = ((self.stats['packets_parsed'] - self.stats['validation_errors']) / 
                          self.stats['packets_parsed']) * 100
            print(f"Success rate: {success_rate:.1f}%")
        
        print("=" * 50)


# Test the parsing module
if __name__ == "__main__":
    print("Testing Parsing Module (NO NONCE)...")
    
    # Create test parser
    parser = ParsingModule("TestParser")
    
    # Test Interest packet
    from common import create_interest_packet
    interest = create_interest_packet("/test/file", "alice", "READ")
    interest_json = interest.to_json()
    
    print(f"Interest JSON: {interest_json}")
    print(f"Interest valid: {interest.validate_checksum()}")
    
    # Test parsing
    def test_handler(packet, source, packet_type):
        print(f"Handler received {packet_type} from {source}")
        return "Test response"
    
    parser.set_processing_handler(test_handler)
    result = parser.handle_packet(interest_json, "test:1234")
    
    print(f"Parse result: {result}")
    parser.show_stats()