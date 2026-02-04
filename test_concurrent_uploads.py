#!/usr/bin/env python3
"""Concurrency test script

Scenarios:
  - scenario_independent_uploads: Alice and Bob upload several different files concurrently
  - scenario_simultaneous_update: Alice and Bob both write to the same destination at the same time

Usage:
  python tests/test_concurrent_uploads.py [router_host] [router_port]

Notes:
- Make sure server.py, router.py and storage nodes are running.
- This script uses SimpleClient from simple_client.py and does actual network requests to the router/server on the default ports.
"""

import threading
import time
import os
import sys
from simple_client import SimpleClient

# File list (relative paths under project root)
FILES_DIR = os.path.join('.', 'files')
TEST_FILES = [
    'ace.png',
    'GPUZ.exe',
    'SteamSetup.exe',
    'zeri.jpg',
    'ViberSetup.exe'
]

# Defaults
ROUTER_HOST = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
ROUTER_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8001
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 7001

# Credentials - adjust if needed
ALICE = {'id': 'alice', 'password': 'password123'}
BOB = {'id': 'bob', 'password': 'password123'}

# Utility: authenticate a client via the server control API (same as simple_client.main())
def authenticate_client(client, password):
    payload = {"user_id": client.client_id, "password": password, "action": "authenticate"}
    import json
    try:
        resp = client.comm_module.send_packet_sync(SERVER_HOST, SERVER_PORT, json.dumps(payload))
        if resp and ('AUTHORIZED' in resp or 'SUCCESS' in resp.upper() or 'AUTHORIZED' in resp.upper()):
            client.authenticated = True
            return True
    except Exception as e:
        print(f"Auth error for {client.client_id}: {e}")
    return False


def scenario_independent_uploads(router_host, router_port, raid_preference='raid1'):
    print('\n=== Scenario: Independent Concurrent Uploads ===')
    alice = SimpleClient(ALICE['id'], ALICE['password'])
    bob = SimpleClient(BOB['id'], BOB['password'])

    print('Authenticating clients...')
    authenticate_client(alice, ALICE['password'])
    authenticate_client(bob, BOB['password'])

    threads = []
    results = []
    lock = threading.Lock()

    def upload_task(client, local_file, dest_name):
        start = time.time()
        ok = client._do_write(local_file, dest_name, password=client.password, raid_preference=raid_preference, router_host=router_host, router_port=router_port)
        elapsed = time.time() - start
        with lock:
            results.append((client.client_id, os.path.basename(local_file), dest_name, ok, elapsed))

    # Start tasks for both clients uploading different files
    for i, fname in enumerate(TEST_FILES):
        local_path = os.path.join(FILES_DIR, fname)
        # Alice uploads half, Bob uploads half (interleave)
        if i % 2 == 0:
            dest = f"/dlsu/storage/{raid_preference}/{fname}"
            t = threading.Thread(target=upload_task, args=(alice, local_path, dest), daemon=True)
        else:
            dest = f"/dlsu/storage/{raid_preference}/{fname}"
            t = threading.Thread(target=upload_task, args=(bob, local_path, dest), daemon=True)
        threads.append(t)
        t.start()
        # small stagger to increase overlap
        time.sleep(0.05)

    # Wait for completion
    for t in threads:
        t.join(timeout=300)

    print('\nResults:')
    for r in results:
        print(f"  {r[0]:6} uploaded {r[1]:15} -> {r[2]:40} | ok={r[3]} | {r[4]:.2f}s")

    # Ask clients to list own files
    print('\nMy files (Alice):')
    alice._list_my_files(router_host, router_port)
    print('\nMy files (Bob):')
    bob._list_my_files(router_host, router_port)


def scenario_simultaneous_update(router_host, router_port, raid_preference='raid1'):
    print('\n=== Scenario: Simultaneous Updates to the Same File ===')
    alice = SimpleClient(ALICE['id'], ALICE['password'])
    bob = SimpleClient(BOB['id'], BOB['password'])

    print('Authenticating clients...')
    authenticate_client(alice, ALICE['password'])
    authenticate_client(bob, BOB['password'])

    # Use GPUZ.exe as the shared file (exists in files/)
    shared_local = os.path.join(FILES_DIR, 'GPUZ.exe')
    dest_name = f"/dlsu/storage/{raid_preference}/GPUZ_shared.exe"

    # Copy or tweak local files to simulate different contents (optional)
    alice_local = shared_local
    bob_local = shared_local

    # Barrier to attempt simultaneous start
    start_barrier = threading.Barrier(3)

    results = []
    lock = threading.Lock()

    def alice_task():
        start_barrier.wait()
        s = time.time()
        ok = alice._do_write(alice_local, dest_name, password=alice.password, raid_preference=raid_preference, router_host=router_host, router_port=router_port)
        with lock:
            results.append(('Alice', ok, time.time()-s))

    def bob_task():
        start_barrier.wait()
        s = time.time()
        ok = bob._do_write(bob_local, dest_name, password=bob.password, raid_preference=raid_preference, router_host=router_host, router_port=router_port)
        with lock:
            results.append(('Bob', ok, time.time()-s))

    ta = threading.Thread(target=alice_task, daemon=True)
    tb = threading.Thread(target=bob_task, daemon=True)
    ta.start()
    tb.start()

    # Release barrier
    start_barrier.wait()

    ta.join(timeout=300)
    tb.join(timeout=300)

    print('\nSimultaneous update results:')
    for r in results:
        print(f"  {r[0]:6} ok={r[1]} time={r[2]:.2f}s")

    # Check file location and owner listing
    print('\nChecking ownership & locations after simultaneous updates...')
    alice._list_my_files(router_host, router_port)
    bob._list_my_files(router_host, router_port)


if __name__ == '__main__':
    print('Starting concurrency tests')
    scenario_independent_uploads(ROUTER_HOST, ROUTER_PORT)
    # Wait a short time to allow background registration tasks to finish
    time.sleep(5)
    scenario_simultaneous_update(ROUTER_HOST, ROUTER_PORT)
    print('\nDone')
