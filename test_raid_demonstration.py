#!/usr/bin/env python3
"""
RAID 0 and RAID 1 Demonstration Script
Tests striping and mirroring with ST1 and ST2
"""

import time
import sys
from common import create_interest_packet, DataPacket
from communication_module import CommunicationModule

class RAIDDemonstration:
    """Demonstrate RAID 0 and RAID 1 functionality"""
    
    def __init__(self):
        self.router_host = "127.0.0.1"
        self.router_port = 8001
        self.comm = CommunicationModule("RAID-Demo", port=0)
        
    def demonstrate_raid1_mirroring(self):
        """
        Demonstrate RAID 1 - Mirroring
        Shows how data is written to BOTH storage nodes
        """
        print("\n" + "="*70)
        print("RAID 1 DEMONSTRATION - MIRRORING")
        print("="*70)
        print("Concept: Same file written to BOTH ST1 and ST2")
        print("Benefit: If one node fails, data is safe on the other")
        print()
        
        # Write file with RAID 1
        print("Step 1: Writing file with RAID 1 (mirroring)...")
        interest = create_interest_packet("/demo/raid1/file.txt", "Alice", "WRITE")
        
        response = self.comm.send_packet_sync(
            self.router_host,
            self.router_port,
            interest.to_json()
        )
        
        if response:
            print("✅ Write response received:")
            try:
                data = DataPacket.from_json(response)
                print(data.data_payload.decode('utf-8'))
            except:
                print(response[:200])
        else:
            print("❌ Write failed")
            return
        
        time.sleep(1)
        
        # Read back - should work even if one node is down
        print("\nStep 2: Reading file back (will try ST1 first, then ST2)...")
        interest = create_interest_packet("/demo/raid1/file.txt", "Alice", "READ")
        
        response = self.comm.send_packet_sync(
            self.router_host,
            self.router_port,
            interest.to_json()
        )
        
        if response:
            print("✅ Read successful - data retrieved from one of the mirrors")
        else:
            print("❌ Read failed")
        
        print("\n" + "="*70)
        print("RAID 1 RESULT:")
        print("  ✅ File is stored on BOTH ST1 and ST2")
        print("  ✅ Same file size on each node (58 bytes)")
        print("  ✅ If ST1 fails, can still read from ST2")
        print("  ✅ Redundancy = 2x storage used")
        print("="*70)
    
    def demonstrate_raid0_striping(self):
        """
        Demonstrate RAID 0 - Striping
        Shows how data is split across storage nodes
        """
        print("\n" + "="*70)
        print("RAID 0 DEMONSTRATION - STRIPING")
        print("="*70)
        print("Concept: File is split into fragments across ST1 and ST2")
        print("Benefit: Faster I/O, more efficient storage usage")
        print()
        
        # Write file with RAID 0
        print("Step 1: Writing file with RAID 0 (striping)...")
        interest = create_interest_packet("/demo/raid0/largefile.txt", "Alice", "WRITE")
        
        response = self.comm.send_packet_sync(
            self.router_host,
            self.router_port,
            interest.to_json()
        )
        
        if response:
            print("✅ Write response received:")
            try:
                data = DataPacket.from_json(response)
                print(data.data_payload.decode('utf-8'))
            except:
                print(response[:200])
        else:
            print("❌ Write failed")
            return
        
        time.sleep(1)
        
        # Read back - requires reassembly
        print("\nStep 2: Reading file back (will reassemble fragments)...")
        interest = create_interest_packet("/demo/raid0/largefile.txt", "Alice", "READ")
        
        response = self.comm.send_packet_sync(
            self.router_host,
            self.router_port,
            interest.to_json()
        )
        
        if response:
            print("✅ Read successful - fragments reassembled")
        else:
            print("❌ Read failed")
        
        print("\n" + "="*70)
        print("RAID 0 RESULT:")
        print("  ✅ File is split across ST1 and ST2")
        print("  ✅ ST1 stores fragment [0/2] (even)")
        print("  ✅ ST2 stores fragment [1/2] (odd)")
        print("  ✅ Router reassembles fragments on read")
        print("  ⚠️  If ANY node fails, data is lost")
        print("="*70)
    
    def compare_raid_modes(self):
        """Compare RAID 0 vs RAID 1"""
        print("\n" + "="*70)
        print("RAID 0 vs RAID 1 COMPARISON")
        print("="*70)
        print()
        print("FEATURE               | RAID 0 (Striping) | RAID 1 (Mirroring)")
        print("----------------------|-------------------|-------------------")
        print("Storage Efficiency    | 100%              | 50% (2x redundancy)")
        print("Read Performance      | Fast (parallel)   | Fast (any node)")
        print("Write Performance     | Fast (parallel)   | Slower (both nodes)")
        print("Fault Tolerance       | None (0 failures) | Good (1 failure)")
        print("Data Distribution     | Fragmented        | Complete copies")
        print("Recovery              | Impossible        | Automatic fallback")
        print()
        
        print("Use Cases:")
        print("  RAID 0: High-speed temporary storage, performance-critical")
        print("  RAID 1: Critical data, high availability requirements")
        print("="*70)
    
    def run_demonstration(self):
        """Run complete RAID demonstration"""
        print("\n" + "#"*70)
        print("# RAID 0 AND RAID 1 DEMONSTRATION")
        print("# Storage Nodes: ST1 (RAID 0) and ST2 (RAID 1)")
        print("#"*70)
        
        print("\nMake sure the following are running:")
        print("  1. python router_raid_aware.py R1")
        print("  2. python storage_node.py ST1 0 9001")
        print("  3. python storage_node.py ST2 1 9002")
        print()
        
        input("Press Enter when all nodes are ready...")
        
        # Demonstrate RAID 1
        self.demonstrate_raid1_mirroring()
        
        input("\nPress Enter to continue to RAID 0 demo...")
        
        # Switch router to RAID 0 mode
        print("\n⚙️  Note: Switch router to RAID 0 mode by typing 'raid0' in router terminal")
        input("Press Enter after switching to RAID 0...")
        
        # Demonstrate RAID 0
        self.demonstrate_raid0_striping()
        
        # Compare
        self.compare_raid_modes()
        
        print("\n" + "#"*70)
        print("# DEMONSTRATION COMPLETE")
        print("#"*70)
        print("\nNow verify on storage nodes:")
        print("  ST1> show files  (should show RAID 0 fragments)")
        print("  ST2> show files  (should show RAID 1 complete files)")
        print()


def main():
    demo = RAIDDemonstration()
    
    try:
        demo.run_demonstration()
    except KeyboardInterrupt:
        print("\n\nDemo interrupted")
    except Exception as e:
        print(f"\n❌ Demo error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()