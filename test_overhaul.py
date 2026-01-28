#!/usr/bin/env python3
"""
Quick test script to verify all operations work after the overhaul.
Run this after starting the topology with launch_topology.py

Tests:
1. READ - Should work (was already working)
2. WRITE - Upload a file
3. MYFILES - List user's files
4. GRANT - Grant permission to another user
5. REVOKE - Revoke permission
6. DELETE - Delete a file (if implemented)
"""

import time
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from simple_client import SimpleClient

def test_all_operations():
    """Run through all operations to verify they work"""
    
    print("=" * 70)
    print("NDN-CVSMS OPERATION TEST SUITE")
    print("=" * 70)
    print("\nMake sure the topology is running (launch_topology.py)")
    print("Press Enter to start tests...")
    input()
    
    # Create test client
    client = SimpleClient("alice", "password123")
    router_host = "127.0.0.1"
    router_port = 8001
    
    results = {}
    
    # Test 1: READ (should already work)
    print("\n" + "=" * 70)
    print("TEST 1: READ OPERATION")
    print("=" * 70)
    try:
        resp = client.send_interest("/dlsu/hello", "READ", router_host, router_port)
        if resp:
            print("✓ READ: SUCCESS")
            results["READ"] = "PASS"
        else:
            print("✗ READ: FAILED (timeout or error)")
            results["READ"] = "FAIL"
    except Exception as e:
        print(f"✗ READ: EXCEPTION - {e}")
        results["READ"] = "ERROR"
    
    time.sleep(0.5)
    
    # Test 2: MYFILES (list user's files)
    print("\n" + "=" * 70)
    print("TEST 2: MYFILES OPERATION")
    print("=" * 70)
    try:
        resp = client.send_interest("/dlsu/server/myfiles", "LIST", router_host, router_port, auth_key="password123")
        if resp:
            print("✓ MYFILES: SUCCESS")
            try:
                payload = resp.data_payload.decode('utf-8', errors='ignore')
                print(f"  Response: {payload[:200]}...")
            except:
                pass
            results["MYFILES"] = "PASS"
        else:
            print("✗ MYFILES: FAILED (timeout or error)")
            results["MYFILES"] = "FAIL"
    except Exception as e:
        print(f"✗ MYFILES: EXCEPTION - {e}")
        results["MYFILES"] = "ERROR"
    
    time.sleep(0.5)
    
    # Test 3: WRITE - Check auth only (we won't actually upload for this quick test)
    print("\n" + "=" * 70)
    print("TEST 3: WRITE AUTH CHECK")
    print("=" * 70)
    try:
        # Check permission for WRITE
        perm_result = client._check_permission("/dlsu/storage/test_write.txt", "WRITE", password="password123")
        if perm_result.get('authorized'):
            print("✓ WRITE AUTH: SUCCESS (authorized)")
            print(f"  Assigned storage: {perm_result.get('assigned_storage')}")
            results["WRITE_AUTH"] = "PASS"
        else:
            print("✗ WRITE AUTH: FAILED (not authorized)")
            results["WRITE_AUTH"] = "FAIL"
    except Exception as e:
        print(f"✗ WRITE AUTH: EXCEPTION - {e}")
        results["WRITE_AUTH"] = "ERROR"
    
    time.sleep(0.5)
    
    # Test 4: GRANT permission
    print("\n" + "=" * 70)
    print("TEST 4: GRANT PERMISSION")
    print("=" * 70)
    try:
        name = "/dlsu/server/permission/grant:/dlsu/storage/test_write.txt:bob"
        resp = client.send_interest(name, "PERMISSION", router_host, router_port, auth_key="password123")
        if resp:
            print("✓ GRANT: SUCCESS")
            try:
                payload = resp.data_payload.decode('utf-8', errors='ignore')
                print(f"  Response: {payload[:200]}")
            except:
                pass
            results["GRANT"] = "PASS"
        else:
            print("✗ GRANT: FAILED (timeout or error)")
            results["GRANT"] = "FAIL"
    except Exception as e:
        print(f"✗ GRANT: EXCEPTION - {e}")
        results["GRANT"] = "ERROR"
    
    time.sleep(0.5)
    
    # Test 5: REVOKE permission
    print("\n" + "=" * 70)
    print("TEST 5: REVOKE PERMISSION")
    print("=" * 70)
    try:
        name = "/dlsu/server/permission/revoke:/dlsu/storage/test_write.txt:bob"
        resp = client.send_interest(name, "PERMISSION", router_host, router_port, auth_key="password123")
        if resp:
            print("✓ REVOKE: SUCCESS")
            try:
                payload = resp.data_payload.decode('utf-8', errors='ignore')
                print(f"  Response: {payload[:200]}")
            except:
                pass
            results["REVOKE"] = "PASS"
        else:
            print("✗ REVOKE: FAILED (timeout or error)")
            results["REVOKE"] = "FAIL"
    except Exception as e:
        print(f"✗ REVOKE: EXCEPTION - {e}")
        results["REVOKE"] = "ERROR"
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for v in results.values() if v == "PASS")
    failed = sum(1 for v in results.values() if v == "FAIL")
    errors = sum(1 for v in results.values() if v == "ERROR")
    
    for test_name, result in results.items():
        symbol = "✓" if result == "PASS" else "✗"
        print(f"  {symbol} {test_name}: {result}")
    
    print(f"\nTotal: {passed} passed, {failed} failed, {errors} errors")
    print("=" * 70)
    
    return passed, failed, errors


if __name__ == "__main__":
    test_all_operations()
