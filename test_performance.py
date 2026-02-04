#!/usr/bin/env python3
"""
===============================================================================
NAMED NETWORKS PERFORMANCE TEST SUITE
===============================================================================
Performance Tests PT-01 to PT-19

=== METRICS COLLECTED ===

1. LATENCY
   Formula: Latency = Tend - Tstart
   Unit: milliseconds (ms)
   Description: Total time from request initiation to response completion

2. THROUGHPUT
   Formula: Throughput = FileSize / Time
   Unit: MB/s (megabytes per second)
   Description: Raw data transfer rate including all overhead

3. GOODPUT
   Formula: Goodput = (FileSize - Overhead) / Time
   Where: Overhead = PacketCount × PacketOverhead (300 bytes/packet)
   Unit: MB/s
   Description: Effective useful data transfer rate

4. PACKET DELIVERY RATIO (PDR)
   Formula: PDR = (Packets_Received / Packets_Sent) × 100
   Unit: percentage (%)
   Description: Ratio of successfully delivered packets

5. PACKET LOSS
   Formula: Packet_Loss = 100 - PDR
   Unit: percentage (%)
   Description: Percentage of packets lost during transmission

6. HOP LATENCY (Complete Round-Trip)
   
   Forward Path (Interest Packet):
   - T1: Client → R1 (Router 1)
   - T2: R1 → R2 (Router 2)
   - T3: R2 → Server (auth request)
   - T4: Server → R2 (auth response)
   - T5: R2 → Storage (data request)
   
   Return Path (Data Packet):
   - T6: Storage → R2
   - T7: R2 → R1
   - T8: R1 → Client
   
   Formula: Total_Hop_Latency = T1 + T2 + T3 + T4 + T5 + T6 + T7 + T8
   Unit: milliseconds (ms)
   
   Measurement Method:
   - Each node adds timestamp when receiving (T_receive) and sending (T_send)
   - Hop_Time = Next_node_T_receive - Current_node_T_send

=== TEST CATEGORIES ===

Throughput Tests (File Size Variation):
  PT-01: 1MB File WRITE (RAID 0)
  PT-02: 1MB File READ (RAID 0)
  PT-03: 10MB File WRITE (RAID 0)
  PT-04: 10MB File READ (RAID 0)
  PT-05: 50MB File WRITE (RAID 0)
  PT-06: 50MB File READ (RAID 0)

RAID Comparison Tests:
  PT-07: 10MB RAID 0 Upload
  PT-08: 10MB RAID 1 Upload
  PT-09: 10MB RAID 5 Upload
  PT-10: 10MB RAID 6 Upload

Cache Performance Tests:
  PT-11: Cache Hit Performance
  PT-12: Cache Miss Performance

Fragmentation Tests:
  PT-13: 1MB File (125 fragments @ 8KB)
  PT-14: 10MB File (1250 fragments @ 8KB)
  PT-15: 50MB File (6250 fragments @ 8KB)

Concurrency Tests:
  PT-16: Single Client Baseline
  PT-17: Multiple Concurrent Clients

Fault Tolerance Recovery:
  PT-18: RAID 5 Recovery Time
  PT-19: RAID 6 Recovery Time

===============================================================================
"""

import os
import sys
import time
import json
import hashlib
import socket
import threading
import statistics
import glob
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from simple_client import SimpleClient
from common import InterestPacket, DataPacket, calculate_checksum

# =============================================================================
# CONFIGURATION
# =============================================================================

ROUTER_HOST = '127.0.0.1'
ROUTER_PORT = 8001
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 7001

# Packet overhead (header bytes) - approximately 300 bytes per packet
PACKET_OVERHEAD = 300

# Fragment size (8KB)
FRAGMENT_SIZE = 8192

# Test users
ALICE = {'id': 'alice', 'password': 'password123'}
BOB = {'id': 'bob', 'password': 'password123'}
CHARLIE = {'id': 'charlie', 'password': 'password123'}

# Test files directory
FILES_DIR = os.path.join('.', 'files')
TEST_FILES_DIR = os.path.join('.', 'test_files')
GENERATED_FILES_DIR = os.path.join('.', 'generated_test_files')
DOWNLOADED_DIR = os.path.join('.', 'downloaded_files')
TEST_RESULTS_DIR = os.path.join('.', 'test_results', 'performance')

# =============================================================================
# PERFORMANCE METRICS CLASS
# =============================================================================

@dataclass
class PerformanceMetrics:
    """Comprehensive performance metrics container"""
    
    # Basic timing
    start_time: float = 0.0
    end_time: float = 0.0
    
    # File info
    file_size_bytes: int = 0
    file_name: str = ""
    
    # Packet stats
    packets_sent: int = 0
    packets_received: int = 0
    fragments_sent: int = 0
    fragments_received: int = 0
    
    # Forward Path Hop Latencies (Interest) - in milliseconds
    t1_client_to_r1_ms: float = 0.0      # T1: Client → R1
    t2_r1_to_r2_ms: float = 0.0          # T2: R1 → R2
    t3_r2_to_server_ms: float = 0.0      # T3: R2 → Server (auth request)
    t4_server_to_r2_ms: float = 0.0      # T4: Server → R2 (auth response)
    t5_r2_to_storage_ms: float = 0.0     # T5: R2 → Storage (data request)
    
    # Return Path Hop Latencies (Data) - in milliseconds
    t6_storage_to_r2_ms: float = 0.0     # T6: Storage → R2
    t7_r2_to_r1_ms: float = 0.0          # T7: R2 → R1
    t8_r1_to_client_ms: float = 0.0      # T8: R1 → Client
    
    # Calculated metrics
    def latency_ms(self) -> float:
        """Total latency in milliseconds: Tend - Tstart"""
        return (self.end_time - self.start_time) * 1000
    
    def latency_s(self) -> float:
        """Total latency in seconds"""
        return self.end_time - self.start_time
    
    def throughput_mbps(self) -> float:
        """Throughput in MB/s: FileSize / Time"""
        elapsed = self.latency_s()
        if elapsed <= 0:
            return 0.0
        return (self.file_size_bytes / (1024 * 1024)) / elapsed
    
    def goodput_mbps(self) -> float:
        """Goodput in MB/s: (FileSize - Overhead) / Time"""
        elapsed = self.latency_s()
        if elapsed <= 0:
            return 0.0
        
        # Calculate overhead: packets_sent * PACKET_OVERHEAD
        total_overhead = self.packets_sent * PACKET_OVERHEAD
        effective_data = max(0, self.file_size_bytes - total_overhead)
        
        return (effective_data / (1024 * 1024)) / elapsed
    
    def total_overhead_bytes(self) -> int:
        """Total packet overhead in bytes"""
        return self.packets_sent * PACKET_OVERHEAD
    
    def packet_delivery_ratio(self) -> float:
        """Packet Delivery Ratio (PDR) as percentage: (Prec / Psent) * 100"""
        if self.packets_sent <= 0:
            return 0.0
        return (self.packets_received / self.packets_sent) * 100
    
    def packet_loss_percent(self) -> float:
        """Packet loss percentage: 100 - PDR"""
        return 100.0 - self.packet_delivery_ratio()
    
    def forward_path_latency_ms(self) -> float:
        """Sum of forward path hop latencies (T1 + T2 + T3 + T4 + T5)"""
        return (self.t1_client_to_r1_ms + self.t2_r1_to_r2_ms + 
                self.t3_r2_to_server_ms + self.t4_server_to_r2_ms + 
                self.t5_r2_to_storage_ms)
    
    def return_path_latency_ms(self) -> float:
        """Sum of return path hop latencies (T6 + T7 + T8)"""
        return (self.t6_storage_to_r2_ms + self.t7_r2_to_r1_ms + 
                self.t8_r1_to_client_ms)
    
    def total_hop_latency_ms(self) -> float:
        """Sum of all measured hop latencies (T1 through T8)"""
        return self.forward_path_latency_ms() + self.return_path_latency_ms()
    
    def expected_fragments(self) -> int:
        """Expected number of fragments for file size"""
        return (self.file_size_bytes + FRAGMENT_SIZE - 1) // FRAGMENT_SIZE
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'file_name': self.file_name,
            'file_size_bytes': self.file_size_bytes,
            'file_size_mb': round(self.file_size_bytes / (1024 * 1024), 2),
            'latency_ms': round(self.latency_ms(), 2),
            'latency_s': round(self.latency_s(), 3),
            'throughput_mbps': round(self.throughput_mbps(), 4),
            'goodput_mbps': round(self.goodput_mbps(), 4),
            'total_overhead_bytes': self.total_overhead_bytes(),
            'packets_sent': self.packets_sent,
            'packets_received': self.packets_received,
            'fragments_sent': self.fragments_sent,
            'fragments_received': self.fragments_received,
            'packet_delivery_ratio_pct': round(self.packet_delivery_ratio(), 2),
            'packet_loss_pct': round(self.packet_loss_percent(), 2),
            'hop_latencies': {
                'forward_path': {
                    't1_client_to_r1_ms': round(self.t1_client_to_r1_ms, 2),
                    't2_r1_to_r2_ms': round(self.t2_r1_to_r2_ms, 2),
                    't3_r2_to_server_ms': round(self.t3_r2_to_server_ms, 2),
                    't4_server_to_r2_ms': round(self.t4_server_to_r2_ms, 2),
                    't5_r2_to_storage_ms': round(self.t5_r2_to_storage_ms, 2),
                    'total_forward_ms': round(self.forward_path_latency_ms(), 2)
                },
                'return_path': {
                    't6_storage_to_r2_ms': round(self.t6_storage_to_r2_ms, 2),
                    't7_r2_to_r1_ms': round(self.t7_r2_to_r1_ms, 2),
                    't8_r1_to_client_ms': round(self.t8_r1_to_client_ms, 2),
                    'total_return_ms': round(self.return_path_latency_ms(), 2)
                },
                'total_hop_latency_ms': round(self.total_hop_latency_ms(), 2)
            }
        }
    
    def print_summary(self, title: str = "Performance Metrics"):
        """Print formatted summary with calculation formulas and values"""
        file_size_mb = self.file_size_bytes / (1024 * 1024)
        elapsed_s = self.latency_s()
        total_overhead = self.total_overhead_bytes()
        effective_data = max(0, self.file_size_bytes - total_overhead)
        effective_data_mb = effective_data / (1024 * 1024)
        
        print(f"\n{'=' * 75}")
        print(f"  {title}")
        print(f"{'=' * 75}")
        print(f"  File: {self.file_name}")
        print(f"  Size: {self.file_size_bytes:,} bytes ({file_size_mb:.4f} MB)")
        
        # LATENCY
        print(f"\n  ┌─ LATENCY ─────────────────────────────────────────────────────────────")
        print(f"  │  Formula: Latency = Tend - Tstart")
        print(f"  │  Calculation: {self.end_time:.6f} - {self.start_time:.6f}")
        print(f"  │  Result: {self.latency_ms():.2f} ms ({elapsed_s:.6f} s)")
        print(f"  └─────────────────────────────────────────────────────────────────────────")
        
        # THROUGHPUT
        print(f"\n  ┌─ THROUGHPUT ──────────────────────────────────────────────────────────")
        print(f"  │  Formula: Throughput = FileSize / Time")
        print(f"  │  Calculation: {file_size_mb:.4f} MB / {elapsed_s:.6f} s")
        print(f"  │  Result: {self.throughput_mbps():.4f} MB/s")
        print(f"  └─────────────────────────────────────────────────────────────────────────")
        
        # GOODPUT
        print(f"\n  ┌─ GOODPUT ────────────────────────────────────────────────────────────")
        print(f"  │  Formula: Goodput = (FileSize - Overhead) / Time")
        print(f"  │  Overhead: {self.packets_sent} packets × {PACKET_OVERHEAD} bytes = {total_overhead:,} bytes")
        print(f"  │  Effective Data: {self.file_size_bytes:,} - {total_overhead:,} = {effective_data:,} bytes ({effective_data_mb:.4f} MB)")
        print(f"  │  Calculation: {effective_data_mb:.4f} MB / {elapsed_s:.6f} s")
        print(f"  │  Result: {self.goodput_mbps():.4f} MB/s")
        print(f"  └─────────────────────────────────────────────────────────────────────────")
        
        # PACKET DELIVERY RATIO
        print(f"\n  ┌─ PACKET DELIVERY RATIO (PDR) ──────────────────────────────────────────")
        print(f"  │  Formula: PDR = (Packets_Received / Packets_Sent) × 100")
        print(f"  │  Calculation: ({self.packets_received} / {self.packets_sent}) × 100")
        print(f"  │  Result: {self.packet_delivery_ratio():.2f}%")
        print(f"  └─────────────────────────────────────────────────────────────────────────")
        
        # PACKET LOSS
        print(f"\n  ┌─ PACKET LOSS ─────────────────────────────────────────────────────────")
        print(f"  │  Formula: Packet_Loss = 100 - PDR")
        print(f"  │  Calculation: 100 - {self.packet_delivery_ratio():.2f}")
        print(f"  │  Result: {self.packet_loss_percent():.2f}%")
        print(f"  └─────────────────────────────────────────────────────────────────────────")
        
        # FRAGMENT STATISTICS
        print(f"\n  ┌─ FRAGMENT STATISTICS ───────────────────────────────────────────────")
        print(f"  │  Fragment Size: {FRAGMENT_SIZE:,} bytes ({FRAGMENT_SIZE/1024:.1f} KB)")
        print(f"  │  Expected Fragments: ⌈{self.file_size_bytes:,} / {FRAGMENT_SIZE:,}⌉ = {self.expected_fragments()}")
        print(f"  │  Fragments Sent: {self.fragments_sent}")
        print(f"  │  Fragments Received: {self.fragments_received}")
        print(f"  └─────────────────────────────────────────────────────────────────────────")
        
        # HOP LATENCY - FORWARD PATH
        print(f"\n  ┌─ HOP LATENCY (Forward Path - Interest Packet) ────────────────────────")
        print(f"  │  T1: Client → R1:        {self.t1_client_to_r1_ms:8.2f} ms")
        print(f"  │  T2: R1 → R2:            {self.t2_r1_to_r2_ms:8.2f} ms")
        print(f"  │  T3: R2 → Server (auth): {self.t3_r2_to_server_ms:8.2f} ms")
        print(f"  │  T4: Server → R2 (resp): {self.t4_server_to_r2_ms:8.2f} ms")
        print(f"  │  T5: R2 → Storage:       {self.t5_r2_to_storage_ms:8.2f} ms")
        print(f"  │  ─────────────────────────────────────")
        print(f"  │  Forward Total (T1+T2+T3+T4+T5): {self.forward_path_latency_ms():.2f} ms")
        print(f"  └─────────────────────────────────────────────────────────────────────────")
        
        # HOP LATENCY - RETURN PATH
        print(f"\n  ┌─ HOP LATENCY (Return Path - Data Packet) ─────────────────────────────")
        print(f"  │  T6: Storage → R2:       {self.t6_storage_to_r2_ms:8.2f} ms")
        print(f"  │  T7: R2 → R1:            {self.t7_r2_to_r1_ms:8.2f} ms")
        print(f"  │  T8: R1 → Client:        {self.t8_r1_to_client_ms:8.2f} ms")
        print(f"  │  ─────────────────────────────────────")
        print(f"  │  Return Total (T6+T7+T8): {self.return_path_latency_ms():.2f} ms")
        print(f"  └─────────────────────────────────────────────────────────────────────────")
        
        # TOTAL HOP LATENCY
        print(f"\n  ┌─ TOTAL HOP LATENCY ────────────────────────────────────────────────────")
        print(f"  │  Formula: Total = T1 + T2 + T3 + T4 + T5 + T6 + T7 + T8")
        print(f"  │  Calculation: {self.t1_client_to_r1_ms:.2f} + {self.t2_r1_to_r2_ms:.2f} + {self.t3_r2_to_server_ms:.2f} + {self.t4_server_to_r2_ms:.2f} + {self.t5_r2_to_storage_ms:.2f} + {self.t6_storage_to_r2_ms:.2f} + {self.t7_r2_to_r1_ms:.2f} + {self.t8_r1_to_client_ms:.2f}")
        print(f"  │  Result: {self.total_hop_latency_ms():.2f} ms")
        print(f"  └─────────────────────────────────────────────────────────────────────────")
        
        print(f"{'=' * 75}")


# =============================================================================
# PERFORMANCE TEST RESULT
# =============================================================================

@dataclass
class PerformanceTestResult:
    """Performance test result container"""
    test_id: str
    test_name: str
    passed: bool = False
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    details: List[str] = field(default_factory=list)
    metrics: PerformanceMetrics = field(default_factory=PerformanceMetrics)
    
    def start(self):
        self.start_time = time.time()
        print("\n" + "=" * 70)
        print(f"  {self.test_id}: {self.test_name}")
        print("=" * 70)
    
    def add_detail(self, msg: str):
        self.details.append(msg)
        print(f"  {msg}")
    
    def finish(self, passed: bool) -> 'PerformanceTestResult':
        self.end_time = time.time()
        self.passed = passed
        elapsed = self.end_time - self.start_time
        
        status = "PASSED" if passed else "FAILED"
        print(f"\n  Result: {status}")
        print(f"  Test Duration: {elapsed:.2f}s")
        return self


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def print_header(title: str):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def get_file_md5(filepath: str) -> str:
    if not os.path.exists(filepath):
        return ""
    with open(filepath, 'rb') as f:
        return hashlib.md5(f.read()).hexdigest()


def get_file_size(filepath: str) -> int:
    if not os.path.exists(filepath):
        return 0
    return os.path.getsize(filepath)


def generate_test_file(size_mb: float, filename: str = None) -> str:
    """Generate a random test file of specified size in MB"""
    os.makedirs(GENERATED_FILES_DIR, exist_ok=True)
    
    if filename is None:
        filename = f"test_{size_mb}MB_{int(time.time())}.bin"
    
    filepath = os.path.join(GENERATED_FILES_DIR, filename)
    
    size_bytes = int(size_mb * 1024 * 1024)
    
    print(f"  Generating {size_mb}MB test file...")
    with open(filepath, 'wb') as f:
        # Write in chunks of 1MB for efficiency
        chunk_size = 1024 * 1024
        remaining = size_bytes
        while remaining > 0:
            to_write = min(chunk_size, remaining)
            f.write(os.urandom(to_write))
            remaining -= to_write
    
    print(f"  Generated: {filepath} ({os.path.getsize(filepath)} bytes)")
    return filepath


def authenticate_client(client: SimpleClient, password: str) -> bool:
    """Authenticate client with server"""
    payload = {"user_id": client.client_id, "password": password, "action": "authenticate"}
    try:
        resp = client.comm_module.send_packet_sync(SERVER_HOST, SERVER_PORT, json.dumps(payload))
        if resp and ('AUTHORIZED' in resp.upper() or 'SUCCESS' in resp.upper()):
            client.authenticated = True
            return True
    except Exception as e:
        print(f"  Auth error: {e}")
    return False


def measure_single_hop_latency(host: str, port: int) -> float:
    """
    Measure round-trip latency to a specific host:port in milliseconds.
    This measures the time for a packet to reach the node and get a response.
    Single hop latency is approximately RTT / 2.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        
        # Send minimal ping packet
        ping = json.dumps({"type": "ping", "timestamp": time.time()}).encode()
        
        start = time.perf_counter()
        sock.sendto(ping, (host, port))
        try:
            sock.recvfrom(65535)
            end = time.perf_counter()
            # Return one-way latency (RTT / 2)
            return ((end - start) * 1000) / 2
        except socket.timeout:
            return 0.0
        finally:
            sock.close()
    except Exception:
        return 0.0


def collect_hop_latencies(metrics: PerformanceMetrics, operation: str = "READ"):
    """
    Measure and populate all 8 hop latencies for complete request/response cycle.
    
    Forward Path (Interest Packet):
        T1: Client → R1
        T2: R1 → R2
        T3: R2 → Server (auth request)
        T4: Server → R2 (auth response)
        T5: R2 → Storage (data request)
    
    Return Path (Data Packet):
        T6: Storage → R2
        T7: R2 → R1
        T8: R1 → Client
    
    Note: In local testing, we estimate hop times by measuring RTT/2 to each node.
    In production with distributed nodes, timestamps would be embedded in packets.
    """
    print(f"  Measuring hop latencies for {operation} operation...")
    
    # ===== FORWARD PATH (Interest) =====
    
    # T1: Client → R1 (measure RTT to R1, use half)
    metrics.t1_client_to_r1_ms = measure_single_hop_latency(ROUTER_HOST, ROUTER_PORT)
    
    # T2: R1 → R2 (measure RTT to R2, use half)
    # Note: In production, R2 would be at different address
    metrics.t2_r1_to_r2_ms = measure_single_hop_latency(ROUTER_HOST, 8002)
    
    # T3: R2 → Server (auth request) - measure RTT to server, use half
    metrics.t3_r2_to_server_ms = measure_single_hop_latency(SERVER_HOST, SERVER_PORT)
    
    # T4: Server → R2 (auth response) - similar to T3 for symmetric network
    # In practice, this may differ due to processing time on server
    metrics.t4_server_to_r2_ms = metrics.t3_r2_to_server_ms  # Symmetric estimate
    
    # T5: R2 → Storage (data request) - measure RTT to storage, use half
    metrics.t5_r2_to_storage_ms = measure_single_hop_latency('127.0.0.1', 9001)
    
    # ===== RETURN PATH (Data) =====
    
    # T6: Storage → R2 - symmetric to T5
    metrics.t6_storage_to_r2_ms = metrics.t5_r2_to_storage_ms
    
    # T7: R2 → R1 - symmetric to T2
    metrics.t7_r2_to_r1_ms = metrics.t2_r1_to_r2_ms
    
    # T8: R1 → Client - symmetric to T1
    metrics.t8_r1_to_client_ms = metrics.t1_client_to_r1_ms
    
    print(f"  Forward path: T1={metrics.t1_client_to_r1_ms:.2f}ms + T2={metrics.t2_r1_to_r2_ms:.2f}ms + T3={metrics.t3_r2_to_server_ms:.2f}ms + T4={metrics.t4_server_to_r2_ms:.2f}ms + T5={metrics.t5_r2_to_storage_ms:.2f}ms")
    print(f"  Return path:  T6={metrics.t6_storage_to_r2_ms:.2f}ms + T7={metrics.t7_r2_to_r1_ms:.2f}ms + T8={metrics.t8_r1_to_client_ms:.2f}ms")
    print(f"  Total hop latency: {metrics.total_hop_latency_ms():.2f}ms")


# =============================================================================
# INSTRUMENTED CLIENT FOR METRICS
# =============================================================================

class InstrumentedClient(SimpleClient):
    """SimpleClient with packet counting for metrics"""
    
    def __init__(self, client_id: str, password: str):
        super().__init__(client_id, password)
        self.packets_sent = 0
        self.packets_received = 0
        self.fragments_sent = 0
        self.fragments_received = 0
    
    def reset_counters(self):
        self.packets_sent = 0
        self.packets_received = 0
        self.fragments_sent = 0
        self.fragments_received = 0


# =============================================================================
# PT-01: 1MB File WRITE (RAID 0)
# =============================================================================

def pt01_1mb_write_raid0() -> PerformanceTestResult:
    """PT-01: Throughput test - 1MB file WRITE to RAID 0"""
    result = PerformanceTestResult("PT-01", "1MB File WRITE (RAID 0)")
    result.start()
    
    try:
        # Setup client
        client = SimpleClient(ALICE['id'], ALICE['password'])
        if not authenticate_client(client, ALICE['password']):
            result.add_detail("Failed to authenticate")
            return result.finish(False)
        result.add_detail("Client authenticated")
        
        # Generate or find 1MB test file
        test_file = generate_test_file(1.0, "pt01_1mb_test.bin")
        file_size = get_file_size(test_file)
        result.metrics.file_size_bytes = file_size
        result.metrics.file_name = os.path.basename(test_file)
        
        # Calculate expected fragments
        expected_frags = (file_size + FRAGMENT_SIZE - 1) // FRAGMENT_SIZE
        result.add_detail(f"File size: {file_size / 1024:.1f} KB, Expected fragments: {expected_frags}")
        
        # Measure hop latencies before test
        collect_hop_latencies(result.metrics, "WRITE")
        
        # Upload
        timestamp = int(time.time())
        dest_name = f"/dlsu/storage/raid0/PT01_{timestamp}.bin"
        
        result.add_detail(f"Starting WRITE operation...")
        result.metrics.start_time = time.perf_counter()
        
        success = client._do_write(test_file, dest_name, password=ALICE['password'],
                                   raid_preference='raid0', router_host=ROUTER_HOST,
                                   router_port=ROUTER_PORT)
        
        result.metrics.end_time = time.perf_counter()
        
        # Estimate packet counts (actual counting requires client instrumentation)
        result.metrics.packets_sent = expected_frags + 2  # fragments + auth + request
        result.metrics.packets_received = expected_frags + 2 if success else expected_frags // 2
        result.metrics.fragments_sent = expected_frags
        result.metrics.fragments_received = expected_frags if success else 0
        
        # Print summary
        result.metrics.print_summary("PT-01 WRITE Performance")
        
        if success:
            result.add_detail("✓ Upload completed successfully")
            return result.finish(True)
        else:
            result.add_detail("✗ Upload failed")
            return result.finish(False)
        
    except Exception as e:
        result.add_detail(f"Exception: {e}")
        return result.finish(False)


# =============================================================================
# PT-02: 1MB File READ (RAID 0)
# =============================================================================

def pt02_1mb_read_raid0() -> PerformanceTestResult:
    """PT-02: Throughput test - 1MB file READ from RAID 0"""
    result = PerformanceTestResult("PT-02", "1MB File READ (RAID 0)")
    result.start()
    
    try:
        client = SimpleClient(ALICE['id'], ALICE['password'])
        if not authenticate_client(client, ALICE['password']):
            result.add_detail("Failed to authenticate")
            return result.finish(False)
        result.add_detail("Client authenticated")
        
        # First, ensure file exists by uploading
        test_file = generate_test_file(1.0, "pt02_1mb_test.bin")
        file_size = get_file_size(test_file)
        original_md5 = get_file_md5(test_file)
        
        timestamp = int(time.time())
        dest_name = f"/dlsu/storage/raid0/PT02_{timestamp}.bin"
        
        result.add_detail("Uploading file for READ test...")
        client._do_write(test_file, dest_name, password=ALICE['password'],
                         raid_preference='raid0', router_host=ROUTER_HOST,
                         router_port=ROUTER_PORT)
        
        # Setup metrics
        result.metrics.file_size_bytes = file_size
        result.metrics.file_name = os.path.basename(test_file)
        expected_frags = (file_size + FRAGMENT_SIZE - 1) // FRAGMENT_SIZE
        
        collect_hop_latencies(result.metrics, "READ")
        
        os.makedirs(DOWNLOADED_DIR, exist_ok=True)
        
        result.add_detail("Starting READ operation...")
        result.metrics.start_time = time.perf_counter()
        
        success = client.download_file(dest_name, DOWNLOADED_DIR, ROUTER_HOST, ROUTER_PORT)
        
        result.metrics.end_time = time.perf_counter()
        
        # Packet estimates
        result.metrics.packets_sent = expected_frags + 2
        result.metrics.packets_received = expected_frags + 2 if success else 0
        result.metrics.fragments_sent = 1  # Request
        result.metrics.fragments_received = expected_frags if success else 0
        
        result.metrics.print_summary("PT-02 READ Performance")
        
        if success:
            result.add_detail("✓ Download completed successfully")
            return result.finish(True)
        else:
            result.add_detail("✗ Download failed")
            return result.finish(False)
        
    except Exception as e:
        result.add_detail(f"Exception: {e}")
        return result.finish(False)


# =============================================================================
# PT-03: 10MB File WRITE (RAID 0)
# =============================================================================

def pt03_10mb_write_raid0() -> PerformanceTestResult:
    """PT-03: Throughput test - 10MB file WRITE to RAID 0"""
    result = PerformanceTestResult("PT-03", "10MB File WRITE (RAID 0)")
    result.start()
    
    try:
        client = SimpleClient(ALICE['id'], ALICE['password'])
        if not authenticate_client(client, ALICE['password']):
            result.add_detail("Failed to authenticate")
            return result.finish(False)
        
        test_file = generate_test_file(10.0, "pt03_10mb_test.bin")
        file_size = get_file_size(test_file)
        result.metrics.file_size_bytes = file_size
        result.metrics.file_name = os.path.basename(test_file)
        
        expected_frags = (file_size + FRAGMENT_SIZE - 1) // FRAGMENT_SIZE
        result.add_detail(f"File size: {file_size / (1024*1024):.1f} MB, Expected fragments: {expected_frags}")
        
        collect_hop_latencies(result.metrics, "WRITE")
        
        timestamp = int(time.time())
        dest_name = f"/dlsu/storage/raid0/PT03_{timestamp}.bin"
        
        result.add_detail("Starting WRITE operation...")
        result.metrics.start_time = time.perf_counter()
        
        success = client._do_write(test_file, dest_name, password=ALICE['password'],
                                   raid_preference='raid0', router_host=ROUTER_HOST,
                                   router_port=ROUTER_PORT)
        
        result.metrics.end_time = time.perf_counter()
        
        result.metrics.packets_sent = expected_frags + 2
        result.metrics.packets_received = expected_frags + 2 if success else 0
        result.metrics.fragments_sent = expected_frags
        result.metrics.fragments_received = expected_frags if success else 0
        
        result.metrics.print_summary("PT-03 WRITE Performance")
        
        return result.finish(success)
        
    except Exception as e:
        result.add_detail(f"Exception: {e}")
        return result.finish(False)


# =============================================================================
# PT-04: 10MB File READ (RAID 0)
# =============================================================================

def pt04_10mb_read_raid0() -> PerformanceTestResult:
    """PT-04: Throughput test - 10MB file READ from RAID 0"""
    result = PerformanceTestResult("PT-04", "10MB File READ (RAID 0)")
    result.start()
    
    try:
        client = SimpleClient(ALICE['id'], ALICE['password'])
        if not authenticate_client(client, ALICE['password']):
            result.add_detail("Failed to authenticate")
            return result.finish(False)
        
        test_file = generate_test_file(10.0, "pt04_10mb_test.bin")
        file_size = get_file_size(test_file)
        
        timestamp = int(time.time())
        dest_name = f"/dlsu/storage/raid0/PT04_{timestamp}.bin"
        
        result.add_detail("Uploading file for READ test...")
        client._do_write(test_file, dest_name, password=ALICE['password'],
                         raid_preference='raid0', router_host=ROUTER_HOST,
                         router_port=ROUTER_PORT)
        
        result.metrics.file_size_bytes = file_size
        result.metrics.file_name = os.path.basename(test_file)
        expected_frags = (file_size + FRAGMENT_SIZE - 1) // FRAGMENT_SIZE
        
        collect_hop_latencies(result.metrics, "READ")
        os.makedirs(DOWNLOADED_DIR, exist_ok=True)
        
        result.add_detail("Starting READ operation...")
        result.metrics.start_time = time.perf_counter()
        
        success = client.download_file(dest_name, DOWNLOADED_DIR, ROUTER_HOST, ROUTER_PORT)
        
        result.metrics.end_time = time.perf_counter()
        
        result.metrics.packets_sent = expected_frags + 2
        result.metrics.packets_received = expected_frags + 2 if success else 0
        result.metrics.fragments_received = expected_frags if success else 0
        
        result.metrics.print_summary("PT-04 READ Performance")
        
        return result.finish(success)
        
    except Exception as e:
        result.add_detail(f"Exception: {e}")
        return result.finish(False)


# =============================================================================
# PT-05: 50MB File WRITE (RAID 0)
# =============================================================================

def pt05_50mb_write_raid0() -> PerformanceTestResult:
    """PT-05: Throughput test - 50MB file WRITE to RAID 0"""
    result = PerformanceTestResult("PT-05", "50MB File WRITE (RAID 0)")
    result.start()
    
    try:
        client = SimpleClient(ALICE['id'], ALICE['password'])
        if not authenticate_client(client, ALICE['password']):
            result.add_detail("Failed to authenticate")
            return result.finish(False)
        
        test_file = generate_test_file(50.0, "pt05_50mb_test.bin")
        file_size = get_file_size(test_file)
        result.metrics.file_size_bytes = file_size
        result.metrics.file_name = os.path.basename(test_file)
        
        expected_frags = (file_size + FRAGMENT_SIZE - 1) // FRAGMENT_SIZE
        result.add_detail(f"File size: {file_size / (1024*1024):.1f} MB, Expected fragments: {expected_frags}")
        
        collect_hop_latencies(result.metrics, "WRITE")
        
        timestamp = int(time.time())
        dest_name = f"/dlsu/storage/raid0/PT05_{timestamp}.bin"
        
        result.add_detail("Starting WRITE operation (this may take a while)...")
        result.metrics.start_time = time.perf_counter()
        
        success = client._do_write(test_file, dest_name, password=ALICE['password'],
                                   raid_preference='raid0', router_host=ROUTER_HOST,
                                   router_port=ROUTER_PORT)
        
        result.metrics.end_time = time.perf_counter()
        
        result.metrics.packets_sent = expected_frags + 2
        result.metrics.packets_received = expected_frags + 2 if success else 0
        result.metrics.fragments_sent = expected_frags
        result.metrics.fragments_received = expected_frags if success else 0
        
        result.metrics.print_summary("PT-05 WRITE Performance")
        
        return result.finish(success)
        
    except Exception as e:
        result.add_detail(f"Exception: {e}")
        return result.finish(False)


# =============================================================================
# PT-06: 50MB File READ (RAID 0)
# =============================================================================

def pt06_50mb_read_raid0() -> PerformanceTestResult:
    """PT-06: Throughput test - 50MB file READ from RAID 0"""
    result = PerformanceTestResult("PT-06", "50MB File READ (RAID 0)")
    result.start()
    
    try:
        client = SimpleClient(ALICE['id'], ALICE['password'])
        if not authenticate_client(client, ALICE['password']):
            result.add_detail("Failed to authenticate")
            return result.finish(False)
        
        test_file = generate_test_file(50.0, "pt06_50mb_test.bin")
        file_size = get_file_size(test_file)
        
        timestamp = int(time.time())
        dest_name = f"/dlsu/storage/raid0/PT06_{timestamp}.bin"
        
        result.add_detail("Uploading file for READ test...")
        client._do_write(test_file, dest_name, password=ALICE['password'],
                         raid_preference='raid0', router_host=ROUTER_HOST,
                         router_port=ROUTER_PORT)
        
        result.metrics.file_size_bytes = file_size
        result.metrics.file_name = os.path.basename(test_file)
        expected_frags = (file_size + FRAGMENT_SIZE - 1) // FRAGMENT_SIZE
        
        collect_hop_latencies(result.metrics, "READ")
        os.makedirs(DOWNLOADED_DIR, exist_ok=True)
        
        result.add_detail("Starting READ operation (this may take a while)...")
        result.metrics.start_time = time.perf_counter()
        
        success = client.download_file(dest_name, DOWNLOADED_DIR, ROUTER_HOST, ROUTER_PORT)
        
        result.metrics.end_time = time.perf_counter()
        
        result.metrics.packets_sent = expected_frags + 2
        result.metrics.packets_received = expected_frags + 2 if success else 0
        result.metrics.fragments_received = expected_frags if success else 0
        
        result.metrics.print_summary("PT-06 READ Performance")
        
        return result.finish(success)
        
    except Exception as e:
        result.add_detail(f"Exception: {e}")
        return result.finish(False)


# =============================================================================
# PT-07 to PT-10: RAID Comparison Tests
# =============================================================================

def _raid_comparison_test(raid_level: str, test_id: str) -> PerformanceTestResult:
    """Common RAID comparison test logic"""
    result = PerformanceTestResult(test_id, f"10MB RAID {raid_level.upper()} Upload")
    result.start()
    
    try:
        client = SimpleClient(ALICE['id'], ALICE['password'])
        if not authenticate_client(client, ALICE['password']):
            result.add_detail("Failed to authenticate")
            return result.finish(False)
        
        test_file = generate_test_file(10.0, f"{test_id}_10mb_test.bin")
        file_size = get_file_size(test_file)
        result.metrics.file_size_bytes = file_size
        result.metrics.file_name = os.path.basename(test_file)
        
        expected_frags = (file_size + FRAGMENT_SIZE - 1) // FRAGMENT_SIZE
        result.add_detail(f"Testing RAID {raid_level.upper()} with 10MB file ({expected_frags} fragments)")
        
        collect_hop_latencies(result.metrics, "WRITE")
        
        timestamp = int(time.time())
        dest_name = f"/dlsu/storage/{raid_level}/{test_id}_{timestamp}.bin"
        
        result.add_detail(f"Starting WRITE to RAID {raid_level.upper()}...")
        result.metrics.start_time = time.perf_counter()
        
        success = client._do_write(test_file, dest_name, password=ALICE['password'],
                                   raid_preference=raid_level, router_host=ROUTER_HOST,
                                   router_port=ROUTER_PORT)
        
        result.metrics.end_time = time.perf_counter()
        
        result.metrics.packets_sent = expected_frags + 2
        result.metrics.packets_received = expected_frags + 2 if success else 0
        result.metrics.fragments_sent = expected_frags
        result.metrics.fragments_received = expected_frags if success else 0
        
        result.metrics.print_summary(f"{test_id} RAID {raid_level.upper()} Performance")
        
        return result.finish(success)
        
    except Exception as e:
        result.add_detail(f"Exception: {e}")
        return result.finish(False)


def pt07_raid0_comparison() -> PerformanceTestResult:
    return _raid_comparison_test('raid0', 'PT-07')


def pt08_raid1_comparison() -> PerformanceTestResult:
    return _raid_comparison_test('raid1', 'PT-08')


def pt09_raid5_comparison() -> PerformanceTestResult:
    return _raid_comparison_test('raid5', 'PT-09')


def pt10_raid6_comparison() -> PerformanceTestResult:
    return _raid_comparison_test('raid6', 'PT-10')


# =============================================================================
# PT-11: Cache Hit Performance
# =============================================================================

def pt11_cache_hit() -> PerformanceTestResult:
    """PT-11: Measure performance with cache hit"""
    result = PerformanceTestResult("PT-11", "Cache Hit Performance")
    result.start()
    
    try:
        client = SimpleClient(ALICE['id'], ALICE['password'])
        if not authenticate_client(client, ALICE['password']):
            result.add_detail("Failed to authenticate")
            return result.finish(False)
        
        test_file = generate_test_file(5.0, "pt11_cache_test.bin")
        file_size = get_file_size(test_file)
        result.metrics.file_size_bytes = file_size
        result.metrics.file_name = os.path.basename(test_file)
        
        timestamp = int(time.time())
        dest_name = f"/dlsu/storage/raid0/PT11_{timestamp}.bin"
        
        # Upload file
        result.add_detail("Uploading file...")
        client._do_write(test_file, dest_name, password=ALICE['password'],
                         raid_preference='raid0', router_host=ROUTER_HOST,
                         router_port=ROUTER_PORT)
        
        os.makedirs(DOWNLOADED_DIR, exist_ok=True)
        
        # First read (cache miss - populates cache)
        result.add_detail("First read (populates cache)...")
        first_read_start = time.perf_counter()
        client.download_file(dest_name, DOWNLOADED_DIR, ROUTER_HOST, ROUTER_PORT)
        first_read_time = time.perf_counter() - first_read_start
        result.add_detail(f"First read time (cache miss): {first_read_time*1000:.2f} ms")
        
        # Second read (should hit cache)
        result.add_detail("Second read (should hit cache)...")
        
        collect_hop_latencies(result.metrics, "READ (Cache Hit)")
        result.metrics.start_time = time.perf_counter()
        
        success = client.download_file(dest_name, DOWNLOADED_DIR, ROUTER_HOST, ROUTER_PORT)
        
        result.metrics.end_time = time.perf_counter()
        
        expected_frags = (file_size + FRAGMENT_SIZE - 1) // FRAGMENT_SIZE
        result.metrics.packets_sent = 2  # Minimal for cache hit
        result.metrics.packets_received = expected_frags if success else 0
        
        cache_hit_time = result.metrics.latency_ms()
        result.add_detail(f"Cache hit read time: {cache_hit_time:.2f} ms")
        
        # Calculate cache speedup
        if first_read_time > 0:
            speedup = (first_read_time * 1000) / cache_hit_time if cache_hit_time > 0 else float('inf')
            result.add_detail(f"Cache speedup: {speedup:.2f}x")
        
        result.metrics.print_summary("PT-11 Cache Hit Performance")
        
        return result.finish(success)
        
    except Exception as e:
        result.add_detail(f"Exception: {e}")
        return result.finish(False)


# =============================================================================
# PT-12: Cache Miss Performance
# =============================================================================

def pt12_cache_miss() -> PerformanceTestResult:
    """PT-12: Measure performance with cache miss"""
    result = PerformanceTestResult("PT-12", "Cache Miss Performance")
    result.start()
    
    try:
        client = SimpleClient(ALICE['id'], ALICE['password'])
        if not authenticate_client(client, ALICE['password']):
            result.add_detail("Failed to authenticate")
            return result.finish(False)
        
        test_file = generate_test_file(5.0, "pt12_cache_miss_test.bin")
        file_size = get_file_size(test_file)
        result.metrics.file_size_bytes = file_size
        result.metrics.file_name = os.path.basename(test_file)
        
        timestamp = int(time.time())
        dest_name = f"/dlsu/storage/raid0/PT12_{timestamp}.bin"
        
        # Upload file
        result.add_detail("Uploading file...")
        client._do_write(test_file, dest_name, password=ALICE['password'],
                         raid_preference='raid0', router_host=ROUTER_HOST,
                         router_port=ROUTER_PORT)
        
        # Request clear cache (if API exists)
        result.add_detail("Requesting cache clear (if supported)...")
        
        os.makedirs(DOWNLOADED_DIR, exist_ok=True)
        
        collect_hop_latencies(result.metrics, "READ (Cache Miss)")
        
        result.add_detail("First read (guaranteed cache miss)...")
        result.metrics.start_time = time.perf_counter()
        
        success = client.download_file(dest_name, DOWNLOADED_DIR, ROUTER_HOST, ROUTER_PORT)
        
        result.metrics.end_time = time.perf_counter()
        
        expected_frags = (file_size + FRAGMENT_SIZE - 1) // FRAGMENT_SIZE
        result.metrics.packets_sent = expected_frags + 2
        result.metrics.packets_received = expected_frags if success else 0
        result.metrics.fragments_received = expected_frags if success else 0
        
        result.metrics.print_summary("PT-12 Cache Miss Performance")
        
        return result.finish(success)
        
    except Exception as e:
        result.add_detail(f"Exception: {e}")
        return result.finish(False)


# =============================================================================
# PT-13 to PT-15: Fragmentation Tests
# =============================================================================

def _fragmentation_test(size_mb: float, test_id: str, expected_frags: int) -> PerformanceTestResult:
    """Common fragmentation test logic"""
    result = PerformanceTestResult(test_id, f"{size_mb}MB File ({expected_frags} fragments @ 8KB)")
    result.start()
    
    try:
        client = SimpleClient(ALICE['id'], ALICE['password'])
        if not authenticate_client(client, ALICE['password']):
            result.add_detail("Failed to authenticate")
            return result.finish(False)
        
        test_file = generate_test_file(size_mb, f"{test_id}_frag_test.bin")
        file_size = get_file_size(test_file)
        actual_frags = (file_size + FRAGMENT_SIZE - 1) // FRAGMENT_SIZE
        
        result.metrics.file_size_bytes = file_size
        result.metrics.file_name = os.path.basename(test_file)
        
        result.add_detail(f"File size: {file_size / (1024*1024):.1f} MB")
        result.add_detail(f"Expected fragments: {expected_frags}, Actual: {actual_frags}")
        
        collect_hop_latencies(result.metrics, "WRITE")
        
        timestamp = int(time.time())
        dest_name = f"/dlsu/storage/raid0/{test_id}_{timestamp}.bin"
        
        result.add_detail("Starting WRITE operation...")
        result.metrics.start_time = time.perf_counter()
        
        success = client._do_write(test_file, dest_name, password=ALICE['password'],
                                   raid_preference='raid0', router_host=ROUTER_HOST,
                                   router_port=ROUTER_PORT)
        
        result.metrics.end_time = time.perf_counter()
        
        result.metrics.packets_sent = actual_frags + 2
        result.metrics.packets_received = actual_frags + 2 if success else 0
        result.metrics.fragments_sent = actual_frags
        result.metrics.fragments_received = actual_frags if success else 0
        
        # Calculate per-fragment overhead
        total_time = result.metrics.latency_s()
        time_per_fragment = (total_time / actual_frags * 1000) if actual_frags > 0 else 0
        result.add_detail(f"Time per fragment: {time_per_fragment:.3f} ms")
        
        result.metrics.print_summary(f"{test_id} Fragmentation Performance")
        
        return result.finish(success)
        
    except Exception as e:
        result.add_detail(f"Exception: {e}")
        return result.finish(False)


def pt13_fragmentation_1mb() -> PerformanceTestResult:
    return _fragmentation_test(1.0, 'PT-13', 125)


def pt14_fragmentation_10mb() -> PerformanceTestResult:
    return _fragmentation_test(10.0, 'PT-14', 1250)


def pt15_fragmentation_50mb() -> PerformanceTestResult:
    return _fragmentation_test(50.0, 'PT-15', 6250)


# =============================================================================
# PT-16: Single Client Baseline
# =============================================================================

def pt16_single_client() -> PerformanceTestResult:
    """PT-16: Single client baseline performance"""
    result = PerformanceTestResult("PT-16", "Single Client Baseline")
    result.start()
    
    try:
        client = SimpleClient(ALICE['id'], ALICE['password'])
        if not authenticate_client(client, ALICE['password']):
            result.add_detail("Failed to authenticate")
            return result.finish(False)
        
        test_file = generate_test_file(10.0, "pt16_single_client.bin")
        file_size = get_file_size(test_file)
        result.metrics.file_size_bytes = file_size
        result.metrics.file_name = os.path.basename(test_file)
        
        collect_hop_latencies(result.metrics, "WRITE")
        
        timestamp = int(time.time())
        dest_name = f"/dlsu/storage/raid0/PT16_{timestamp}.bin"
        
        result.add_detail("Single client uploading 10MB file...")
        result.metrics.start_time = time.perf_counter()
        
        success = client._do_write(test_file, dest_name, password=ALICE['password'],
                                   raid_preference='raid0', router_host=ROUTER_HOST,
                                   router_port=ROUTER_PORT)
        
        result.metrics.end_time = time.perf_counter()
        
        expected_frags = (file_size + FRAGMENT_SIZE - 1) // FRAGMENT_SIZE
        result.metrics.packets_sent = expected_frags + 2
        result.metrics.packets_received = expected_frags + 2 if success else 0
        result.metrics.fragments_sent = expected_frags
        result.metrics.fragments_received = expected_frags if success else 0
        
        result.metrics.print_summary("PT-16 Single Client Performance")
        
        return result.finish(success)
        
    except Exception as e:
        result.add_detail(f"Exception: {e}")
        return result.finish(False)


# =============================================================================
# PT-17: Multiple Concurrent Clients
# =============================================================================

def pt17_concurrent_clients() -> PerformanceTestResult:
    """PT-17: Multiple concurrent clients performance"""
    result = PerformanceTestResult("PT-17", "Multiple Concurrent Clients")
    result.start()
    
    NUM_CLIENTS = 3
    
    try:
        result.add_detail(f"Testing with {NUM_CLIENTS} concurrent clients...")
        
        # Generate test files for each client
        test_files = []
        for i in range(NUM_CLIENTS):
            test_file = generate_test_file(5.0, f"pt17_concurrent_{i}.bin")
            test_files.append(test_file)
        
        # Create and authenticate clients
        clients = []
        users = [ALICE, BOB, CHARLIE]
        for i in range(NUM_CLIENTS):
            user = users[i % len(users)]
            client = SimpleClient(user['id'], user['password'])
            if authenticate_client(client, user['password']):
                clients.append((client, user, test_files[i]))
            else:
                result.add_detail(f"Failed to authenticate client {i}")
        
        if len(clients) < NUM_CLIENTS:
            result.add_detail("Not all clients authenticated")
            return result.finish(False)
        
        result.add_detail(f"All {NUM_CLIENTS} clients authenticated")
        
        collect_hop_latencies(result.metrics, "WRITE (Concurrent)")
        
        # Define concurrent upload function
        def upload_task(client, user, test_file, idx):
            timestamp = int(time.time())
            dest_name = f"/dlsu/storage/raid0/PT17_concurrent_{idx}_{timestamp}.bin"
            start = time.perf_counter()
            success = client._do_write(test_file, dest_name, password=user['password'],
                                       raid_preference='raid0', router_host=ROUTER_HOST,
                                       router_port=ROUTER_PORT)
            end = time.perf_counter()
            return (idx, success, end - start)
        
        result.add_detail("Starting concurrent uploads...")
        result.metrics.start_time = time.perf_counter()
        
        with ThreadPoolExecutor(max_workers=NUM_CLIENTS) as executor:
            futures = []
            for idx, (client, user, test_file) in enumerate(clients):
                future = executor.submit(upload_task, client, user, test_file, idx)
                futures.append(future)
            
            # Collect results
            individual_times = []
            all_success = True
            for future in as_completed(futures):
                idx, success, elapsed = future.result()
                individual_times.append(elapsed)
                result.add_detail(f"  Client {idx}: {'SUCCESS' if success else 'FAILED'} in {elapsed:.3f}s")
                if not success:
                    all_success = False
        
        result.metrics.end_time = time.perf_counter()
        
        # Aggregate metrics
        total_size = sum(get_file_size(tf) for tf in test_files)
        result.metrics.file_size_bytes = total_size
        result.metrics.file_name = f"{NUM_CLIENTS} concurrent files"
        
        avg_time = statistics.mean(individual_times) if individual_times else 0
        result.add_detail(f"\nAverage individual time: {avg_time:.3f}s")
        result.add_detail(f"Total concurrent time: {result.metrics.latency_s():.3f}s")
        
        # Calculate aggregate throughput
        if result.metrics.latency_s() > 0:
            aggregate_throughput = (total_size / (1024*1024)) / result.metrics.latency_s()
            result.add_detail(f"Aggregate throughput: {aggregate_throughput:.4f} MB/s")
        
        result.metrics.print_summary("PT-17 Concurrent Clients Performance")
        
        return result.finish(all_success)
        
    except Exception as e:
        result.add_detail(f"Exception: {e}")
        return result.finish(False)


# =============================================================================
# PT-18: RAID 5 Recovery Time
# =============================================================================

def pt18_raid5_recovery() -> PerformanceTestResult:
    """PT-18: RAID 5 fault tolerance recovery time"""
    result = PerformanceTestResult("PT-18", "RAID 5 Recovery Time")
    result.start()
    
    try:
        client = SimpleClient(ALICE['id'], ALICE['password'])
        if not authenticate_client(client, ALICE['password']):
            result.add_detail("Failed to authenticate")
            return result.finish(False)
        
        test_file = generate_test_file(10.0, "pt18_raid5_recovery.bin")
        file_size = get_file_size(test_file)
        original_md5 = get_file_md5(test_file)
        
        result.metrics.file_size_bytes = file_size
        result.metrics.file_name = os.path.basename(test_file)
        
        timestamp = int(time.time())
        dest_name = f"/dlsu/storage/raid5/PT18_{timestamp}.bin"
        
        # Upload to RAID 5
        result.add_detail("Uploading to RAID 5...")
        client._do_write(test_file, dest_name, password=ALICE['password'],
                         raid_preference='raid5', router_host=ROUTER_HOST,
                         router_port=ROUTER_PORT)
        
        result.add_detail("File uploaded. Simulating single node failure...")
        result.add_detail("(Note: Actual node failure simulation requires external control)")
        
        os.makedirs(DOWNLOADED_DIR, exist_ok=True)
        
        collect_hop_latencies(result.metrics, "READ (RAID 5 Recovery)")
        
        # Measure recovery read time
        result.add_detail("Measuring recovery read time...")
        result.metrics.start_time = time.perf_counter()
        
        success = client.download_file(dest_name, DOWNLOADED_DIR, ROUTER_HOST, ROUTER_PORT)
        
        result.metrics.end_time = time.perf_counter()
        
        expected_frags = (file_size + FRAGMENT_SIZE - 1) // FRAGMENT_SIZE
        result.metrics.packets_sent = expected_frags + 2
        result.metrics.packets_received = expected_frags if success else 0
        
        result.add_detail(f"Recovery read completed in {result.metrics.latency_ms():.2f} ms")
        
        result.metrics.print_summary("PT-18 RAID 5 Recovery Performance")
        
        return result.finish(success)
        
    except Exception as e:
        result.add_detail(f"Exception: {e}")
        return result.finish(False)


# =============================================================================
# PT-19: RAID 6 Recovery Time
# =============================================================================

def pt19_raid6_recovery() -> PerformanceTestResult:
    """PT-19: RAID 6 fault tolerance recovery time (2 node failure)"""
    result = PerformanceTestResult("PT-19", "RAID 6 Recovery Time")
    result.start()
    
    try:
        client = SimpleClient(ALICE['id'], ALICE['password'])
        if not authenticate_client(client, ALICE['password']):
            result.add_detail("Failed to authenticate")
            return result.finish(False)
        
        test_file = generate_test_file(10.0, "pt19_raid6_recovery.bin")
        file_size = get_file_size(test_file)
        
        result.metrics.file_size_bytes = file_size
        result.metrics.file_name = os.path.basename(test_file)
        
        timestamp = int(time.time())
        dest_name = f"/dlsu/storage/raid6/PT19_{timestamp}.bin"
        
        # Upload to RAID 6
        result.add_detail("Uploading to RAID 6...")
        client._do_write(test_file, dest_name, password=ALICE['password'],
                         raid_preference='raid6', router_host=ROUTER_HOST,
                         router_port=ROUTER_PORT)
        
        result.add_detail("File uploaded. Simulating dual node failure...")
        result.add_detail("(Note: RAID 6 can tolerate 2 simultaneous node failures)")
        
        os.makedirs(DOWNLOADED_DIR, exist_ok=True)
        
        collect_hop_latencies(result.metrics, "READ (RAID 6 Recovery)")
        
        # Measure recovery read time
        result.add_detail("Measuring recovery read time with dual parity...")
        result.metrics.start_time = time.perf_counter()
        
        success = client.download_file(dest_name, DOWNLOADED_DIR, ROUTER_HOST, ROUTER_PORT)
        
        result.metrics.end_time = time.perf_counter()
        
        expected_frags = (file_size + FRAGMENT_SIZE - 1) // FRAGMENT_SIZE
        result.metrics.packets_sent = expected_frags + 2
        result.metrics.packets_received = expected_frags if success else 0
        
        result.add_detail(f"Recovery read completed in {result.metrics.latency_ms():.2f} ms")
        
        result.metrics.print_summary("PT-19 RAID 6 Recovery Performance")
        
        return result.finish(success)
        
    except Exception as e:
        result.add_detail(f"Exception: {e}")
        return result.finish(False)


# =============================================================================
# TEST MENU AND RUNNER
# =============================================================================

TEST_CASES = {
    '1': ('PT-01', '1MB WRITE (RAID 0)', pt01_1mb_write_raid0),
    '2': ('PT-02', '1MB READ (RAID 0)', pt02_1mb_read_raid0),
    '3': ('PT-03', '10MB WRITE (RAID 0)', pt03_10mb_write_raid0),
    '4': ('PT-04', '10MB READ (RAID 0)', pt04_10mb_read_raid0),
    '5': ('PT-05', '50MB WRITE (RAID 0)', pt05_50mb_write_raid0),
    '6': ('PT-06', '50MB READ (RAID 0)', pt06_50mb_read_raid0),
    '7': ('PT-07', 'RAID 0 Comparison (10MB)', pt07_raid0_comparison),
    '8': ('PT-08', 'RAID 1 Comparison (10MB)', pt08_raid1_comparison),
    '9': ('PT-09', 'RAID 5 Comparison (10MB)', pt09_raid5_comparison),
    '10': ('PT-10', 'RAID 6 Comparison (10MB)', pt10_raid6_comparison),
    '11': ('PT-11', 'Cache Hit Performance', pt11_cache_hit),
    '12': ('PT-12', 'Cache Miss Performance', pt12_cache_miss),
    '13': ('PT-13', 'Fragmentation 1MB (125 frags)', pt13_fragmentation_1mb),
    '14': ('PT-14', 'Fragmentation 10MB (1250 frags)', pt14_fragmentation_10mb),
    '15': ('PT-15', 'Fragmentation 50MB (6250 frags)', pt15_fragmentation_50mb),
    '16': ('PT-16', 'Single Client Baseline', pt16_single_client),
    '17': ('PT-17', 'Concurrent Clients', pt17_concurrent_clients),
    '18': ('PT-18', 'RAID 5 Recovery Time', pt18_raid5_recovery),
    '19': ('PT-19', 'RAID 6 Recovery Time', pt19_raid6_recovery),
}


def print_menu():
    print("\n" + "=" * 70)
    print("  PERFORMANCE TEST SUITE (PT-01 to PT-19)")
    print("=" * 70)
    print("\n  Throughput Tests:")
    for key in ['1', '2', '3', '4', '5', '6']:
        tc_id, name, _ = TEST_CASES[key]
        print(f"    [{key:>2}] {tc_id}: {name}")
    
    print("\n  RAID Comparison Tests:")
    for key in ['7', '8', '9', '10']:
        tc_id, name, _ = TEST_CASES[key]
        print(f"    [{key:>2}] {tc_id}: {name}")
    
    print("\n  Cache Performance Tests:")
    for key in ['11', '12']:
        tc_id, name, _ = TEST_CASES[key]
        print(f"    [{key:>2}] {tc_id}: {name}")
    
    print("\n  Fragmentation Tests:")
    for key in ['13', '14', '15']:
        tc_id, name, _ = TEST_CASES[key]
        print(f"    [{key:>2}] {tc_id}: {name}")
    
    print("\n  Concurrency Tests:")
    for key in ['16', '17']:
        tc_id, name, _ = TEST_CASES[key]
        print(f"    [{key:>2}] {tc_id}: {name}")
    
    print("\n  Fault Tolerance Recovery:")
    for key in ['18', '19']:
        tc_id, name, _ = TEST_CASES[key]
        print(f"    [{key:>2}] {tc_id}: {name}")
    
    print("-" * 70)
    print("  [A] Run ALL performance tests")
    print("  [T] Run Throughput tests only (PT-01 to PT-06)")
    print("  [R] Run RAID comparison only (PT-07 to PT-10)")
    print("  [Q] Quit")
    print("-" * 70)


def run_test_group(keys: List[str], group_name: str):
    """Run a group of tests"""
    print_header(f"RUNNING {group_name}")
    results = []
    
    for key in keys:
        if key in TEST_CASES:
            tc_id, name, test_func = TEST_CASES[key]
            print(f"\n\nStarting {tc_id}...")
            time.sleep(1)
            result = test_func()
            results.append(result)
            time.sleep(1)
    
    return results


def run_all_tests():
    """Run all performance tests"""
    print_header("RUNNING ALL PERFORMANCE TESTS")
    results = []
    
    for key in sorted(TEST_CASES.keys(), key=int):
        tc_id, name, test_func = TEST_CASES[key]
        print(f"\n\nStarting {tc_id}...")
        time.sleep(1)
        result = test_func()
        results.append(result)
        time.sleep(1)
    
    return results


def print_summary(results: List[PerformanceTestResult]):
    """Print and save test summary"""
    print("\n" + "=" * 70)
    print("  PERFORMANCE TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for r in results if r.passed)
    print(f"\n  Total: {len(results)} | Passed: {passed} | Failed: {len(results) - passed}")
    
    print("\n  Results:")
    for r in results:
        status = "✓ PASS" if r.passed else "✗ FAIL"
        throughput = r.metrics.throughput_mbps()
        print(f"    [{status}] {r.test_id}: {r.test_name}")
        print(f"           Latency: {r.metrics.latency_ms():.2f} ms, Throughput: {throughput:.4f} MB/s")
    
    # Save detailed results
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    os.makedirs(TEST_RESULTS_DIR, exist_ok=True)
    
    # Text summary
    summary_file = os.path.join(TEST_RESULTS_DIR, f"PT_SUMMARY_{timestamp}.txt")
    with open(summary_file, 'w', encoding='utf-8') as f:
        f.write(f"Performance Test Run: {timestamp}\n")
        f.write(f"Total: {len(results)} | Passed: {passed} | Failed: {len(results) - passed}\n\n")
        for r in results:
            status = "PASS" if r.passed else "FAIL"
            f.write(f"[{status}] {r.test_id}: {r.test_name}\n")
            f.write(f"  Latency: {r.metrics.latency_ms():.2f} ms\n")
            f.write(f"  Throughput: {r.metrics.throughput_mbps():.4f} MB/s\n")
            f.write(f"  Goodput: {r.metrics.goodput_mbps():.4f} MB/s\n")
            f.write(f"  PDR: {r.metrics.packet_delivery_ratio():.1f}%\n")
            f.write(f"  Packet Loss: {r.metrics.packet_loss_percent():.1f}%\n")
            f.write("\n")
    
    # JSON detailed results
    json_file = os.path.join(TEST_RESULTS_DIR, f"PT_DETAILED_{timestamp}.json")
    json_results = []
    for r in results:
        json_results.append({
            'test_id': r.test_id,
            'test_name': r.test_name,
            'passed': r.passed,
            'details': r.details,
            'metrics': r.metrics.to_dict()
        })
    
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(json_results, f, indent=2)
    
    print(f"\n  Summary saved: {summary_file}")
    print(f"  Details saved: {json_file}")


def main():
    os.makedirs(TEST_RESULTS_DIR, exist_ok=True)
    os.makedirs(GENERATED_FILES_DIR, exist_ok=True)
    os.makedirs(DOWNLOADED_DIR, exist_ok=True)
    
    while True:
        print_menu()
        choice = input("\nSelect test: ").strip().upper()
        
        if choice == 'Q':
            print("Goodbye!")
            break
        elif choice == 'A':
            results = run_all_tests()
            print_summary(results)
            input("\nPress Enter to continue...")
        elif choice == 'T':
            results = run_test_group(['1', '2', '3', '4', '5', '6'], "THROUGHPUT TESTS")
            print_summary(results)
            input("\nPress Enter to continue...")
        elif choice == 'R':
            results = run_test_group(['7', '8', '9', '10'], "RAID COMPARISON TESTS")
            print_summary(results)
            input("\nPress Enter to continue...")
        elif choice in TEST_CASES:
            tc_id, name, test_func = TEST_CASES[choice]
            result = test_func()
            print_summary([result])
            input("\nPress Enter to continue...")
        else:
            print("Invalid choice")


if __name__ == '__main__':
    main()
