#!/usr/bin/env python3
"""
Named Networks Framework Demo
Demonstrates the complete system running together
"""

import threading
import time
import sys
from server import NamedNetworksServer
from router import NamedNetworksRouter
from client import NamedNetworksClient

def run_demo():
    """Run a complete demo of the Named Networks framework"""
    print("=== Named Networks Framework Demo ===")
    print("Based on: Distributed Storage Protocol following the Named Networking Framework")
    print("DLSU Thesis Implementation\n")
    
    # Start server
    print("1. Starting Named Networks Server...")
    server = NamedNetworksServer()
    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    time.sleep(1)
    
    # Start router
    print("2. Starting Named Networks Router...")
    router = NamedNetworksRouter("R1")
    router_thread = threading.Thread(target=router.start, daemon=True)
    router_thread.start()
    time.sleep(1)
    
    print("3. Network topology established:")
    print("   Client -> Router (127.0.0.1:8001) -> Server (127.0.0.1:8002)")
    print("   Using hierarchical content naming\n")
    
    # Create clients
    print("4. Creating clients...")
    alice = NamedNetworksClient("Alice")
    bob = NamedNetworksClient("Bob")
    time.sleep(0.5)
    
    # Demo scenarios
    print("=== Demo Scenarios ===\n")
    
    # Scenario 1: Basic content retrieval
    print("Scenario 1: Basic Content Retrieval")
    print("-" * 40)
    alice.send_interest("/dlsu/hello")
    time.sleep(1)
    bob.send_interest("/dlsu/goks/welcome")
    time.sleep(1)
    print()
    
    # Scenario 2: Caching demonstration
    print("Scenario 2: Content Caching (Router CS)")
    print("-" * 40)
    print("Alice requests content (will be cached at router):")
    alice.send_interest("/dlsu/thesis/info")
    time.sleep(1)
    
    print("\nBob requests same content (should be served from cache):")
    bob.send_interest("/dlsu/thesis/info")
    time.sleep(1)
    print()
    
    # Scenario 3: Error handling
    print("Scenario 3: Error Handling")
    print("-" * 40)
    alice.send_interest("/nonexistent/content")
    time.sleep(1)
    print()
    
    # Scenario 4: Multiple clients accessing different content
    print("Scenario 4: Concurrent Access")
    print("-" * 40)
    
    def alice_requests():
        alice.send_interest("/dlsu/storage/node1")
        time.sleep(0.5)
        alice.send_interest("/server/status")
    
    def bob_requests():
        time.sleep(0.2)  # Slight delay
        bob.send_interest("/dlsu/storage/node2")
        time.sleep(0.5)
        bob.send_interest("/server/time")
    
    # Run concurrent requests
    alice_thread = threading.Thread(target=alice_requests)
    bob_thread = threading.Thread(target=bob_requests)
    
    alice_thread.start()
    bob_thread.start()
    
    alice_thread.join()
    bob_thread.join()
    
    time.sleep(1)
    
    # Show router status
    print("\n=== Final Router Status ===")
    router.show_status()
    
    print("\n=== Demo Complete ===")
    print("Key features demonstrated:")
    print("- Hierarchical content naming (/dlsu/goks/...)")
    print("- Interest/Data packet exchange")
    print("- Content Store caching at router")
    print("- Longest prefix match routing")
    print("- Error handling for missing content")
    print("- Concurrent client access")
    
    # Cleanup
    print("\nCleaning up...")
    server.stop()
    router.stop()

def run_interactive_demo():
    """Run an interactive demo"""
    print("=== Named Networks Interactive Demo ===\n")
    
    # Start infrastructure
    server = NamedNetworksServer()
    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    time.sleep(0.5)
    
    router = NamedNetworksRouter("R1")
    router_thread = threading.Thread(target=router.start, daemon=True)
    router_thread.start()
    time.sleep(0.5)
    
    print("Infrastructure started. You can now run clients in separate terminals:")
    print("  python client.py Alice")
    print("  python client.py Bob")
    print("\nPress Ctrl+C to stop the demo...")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down demo...")
        router.show_status()
        server.stop()
        router.stop()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--interactive":
        run_interactive_demo()
    else:
        run_demo()