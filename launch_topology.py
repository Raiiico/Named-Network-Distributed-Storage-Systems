#!/usr/bin/env python3
"""
Named Networks Topology Launcher
Launches complete two-router topology with server and storage nodes
"""

import subprocess
import sys
import time
import os
import signal
from pathlib import Path

class TopologyLauncher:
    """Launch complete Named Networks topology"""
    
    def __init__(self):
        self.processes = []
        self.config = {
            "server": {
                "script": "server.py",
                "args": ["S1"],
                "port": 7001,
                "wait": 2
            },
            "router1": {
                "script": "router.py",
                "args": ["R1"],
                "port": 8001,
                "wait": 2
            },
            "router2": {
                "script": "router.py",
                "args": ["R2"],
                "port": 8002,
                "wait": 2
            },
            "storage1": {
                "script": "storage_node.py",
                "args": ["ST1", "0", "9001"],
                "port": 9001,
                "wait": 2
            },
            "storage2": {
                "script": "storage_node.py",
                "args": ["ST2", "1", "9002"],
                "port": 9002,
                "wait": 2
            },
            "client_alice": {
                "script": "simple_client.py",  # or simple_client.py
                "args": ["alice"],
                "wait": 1
            },
            "client_bob": {
                "script": "simple_client.py",  # or simple_client.py
                "args": ["bob"],
                "wait": 1
            }
        }
    
    def check_files_exist(self):
        """Verify all required files exist"""
        required_files = [
            "common.py",
            "communication_module.py",
            "parsing_module.py",
            "processing_module.py",
            "routing_module.py",
            "fib_config.py",
            "server.py",
            "router.py",
            "storage_node.py",
            "storage_module.py",
        ]
        
        missing = []
        for file in required_files:
            if not Path(file).exists():
                missing.append(file)
        
        if missing:
            print("❌ Missing required files:")
            for file in missing:
                print(f"   - {file}")
            return False
        
        print("✅ All required files present")
        return True
    
    def launch_node(self, node_name, config, background=True):
        """Launch a single node"""
        script = config["script"]
        args = config["args"]
        wait_time = config.get("wait", 2)
        
        print(f"\n🚀 Launching {node_name}...")
        print(f"   Command: python {script} {' '.join(args)}")
        
        try:
            if sys.platform == "win32":
                # Windows - launch in new console window
                if background:
                    cmd = ["start", "cmd", "/k", "python", script] + args
                    process = subprocess.Popen(cmd, shell=True)
                else:
                    cmd = ["python", script] + args
                    process = subprocess.Popen(cmd, creationflags=subprocess.CREATE_NEW_CONSOLE)
            
            elif sys.platform == "darwin":
                # macOS - launch in new Terminal window
                if background:
                    cmd = ["osascript", "-e", 
                          f'tell app "Terminal" to do script "cd {os.getcwd()} && python3 {script} {" ".join(args)}"']
                    process = subprocess.Popen(cmd)
                else:
                    cmd = ["python3", script] + args
                    process = subprocess.Popen(cmd)
            
            else:
                # Linux - try multiple terminal emulators
                if background:
                    terminals = [
                        ["gnome-terminal", "--", "python3", script] + args,
                        ["xterm", "-e", "python3", script] + args,
                        ["konsole", "-e", "python3", script] + args,
                        ["xfce4-terminal", "-e", f"python3 {script} {' '.join(args)}"],
                    ]
                    
                    process = None
                    for term_cmd in terminals:
                        try:
                            process = subprocess.Popen(term_cmd)
                            break
                        except FileNotFoundError:
                            continue
                    
                    if process is None:
                        print(f"   ⚠️  Could not find terminal. Launching in background...")
                        process = subprocess.Popen(["python3", script] + args)
                else:
                    cmd = ["python3", script] + args
                    process = subprocess.Popen(cmd)
            
            self.processes.append((node_name, process))
            print(f"   ✅ {node_name} launched (PID: {process.pid})")
            time.sleep(wait_time)
            return True
            
        except Exception as e:
            print(f"   ❌ Failed to launch {node_name}: {e}")
            return False
    
    def launch_topology(self, include_clients=True):
        """Launch complete topology"""
        print("="*70)
        print("NAMED NETWORKS - TWO-ROUTER TOPOLOGY LAUNCHER")
        print("="*70)
        print("\nTopology:")
        print("  Client Alice ←→ Router1 ←→ Router2 ←→ Server")
        print("  Client Bob   ←→         ↑            ↑")
        print("                          |            |")
        print("                    Storage1      Storage2")
        print()
        
        # Check files
        if not self.check_files_exist():
            print("\n❌ Cannot launch - missing files")
            return False
        
        print("\n" + "="*70)
        print("LAUNCHING NODES IN ORDER...")
        print("="*70)
        
        success = True
        
        # 1. Launch Server
        print("\n📍 STEP 1: Launch Server (Authentication)")
        success &= self.launch_node("Server", self.config["server"])
        
        # 2. Launch Router 1
        print("\n📍 STEP 2: Launch Router 1 (Edge Router)")
        success &= self.launch_node("Router1", self.config["router1"])
        
        # 3. Launch Router 2
        print("\n📍 STEP 3: Launch Router 2 (Core Router)")
        success &= self.launch_node("Router2", self.config["router2"])
        
        # 4. Launch Storage Nodes
        print("\n📍 STEP 4: Launch Storage Nodes")
        success &= self.launch_node("Storage1", self.config["storage1"])
        success &= self.launch_node("Storage2", self.config["storage2"])
        
        if not success:
            print("\n❌ Failed to launch all nodes")
            return False
        
        # Wait for everything to initialize
        print("\n⏳ Waiting for all nodes to initialize...")
        time.sleep(3)
        
        print("\n" + "="*70)
        print("✅ TOPOLOGY LAUNCHED SUCCESSFULLY")
        print("="*70)
        print("\nRunning Nodes:")
        print(f"  Server:    127.0.0.1:7001")
        print(f"  Router1:   127.0.0.1:8001")
        print(f"  Router2:   127.0.0.1:8002")
        print(f"  Storage1:  127.0.0.1:9001 (RAID 0)")
        print(f"  Storage2:  127.0.0.1:9002 (RAID 1)")
        print("="*70)
        
        # Launch clients if requested
        if include_clients:
            print("\n📍 STEP 5: Launch Clients")
            input("\nPress Enter to launch Client Alice and Bob...")
            
            self.launch_node("Client-Alice", self.config["client_alice"])
            time.sleep(1)
            self.launch_node("Client-Bob", self.config["client_bob"])
            
            print("\n✅ All clients launched!")
        else:
            print("\n✅ Infrastructure ready. Launch clients manually when needed.")
        
        return True
    
    def shutdown(self):
        """Shutdown all launched processes"""
        if not self.processes:
            print("\nNo processes to shutdown")
            return
        
        print("\n\n🛑 Shutting down topology...")
        print("="*70)
        
        for node_name, process in reversed(self.processes):
            try:
                print(f"   Terminating {node_name} (PID: {process.pid})")
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    print(f"   Force killing {node_name}")
                    process.kill()
            except Exception as e:
                print(f"   Error stopping {node_name}: {e}")
        
        print("="*70)
        print("✅ All processes terminated")
    
    def interactive_mode(self):
        """Interactive menu for topology management"""
        while True:
            print("\n" + "="*70)
            print("TOPOLOGY MANAGEMENT MENU")
            print("="*70)
            print("1. Launch additional client")
            print("2. Show topology status")
            print("3. Shutdown topology")
            print("4. Exit (leave topology running)")
            print()
            
            try:
                choice = input("Select option (1-4): ").strip()
                
                if choice == "1":
                    client_id = input("Enter client ID (e.g., Charlie, David): ").strip()
                    if client_id:
                        config = {
                            "script": "client_gui.py",
                            "args": [client_id],
                            "wait": 1
                        }
                        self.launch_node(f"Client-{client_id}", config)
                
                elif choice == "2":
                    print("\n📊 Topology Status:")
                    print(f"   Total processes: {len(self.processes)}")
                    for i, (node_name, proc) in enumerate(self.processes, 1):
                        status = "Running" if proc.poll() is None else "Stopped"
                        print(f"   {i}. {node_name} (PID {proc.pid}): {status}")
                
                elif choice == "3":
                    confirm = input("Shutdown all nodes? (yes/no): ").strip().lower()
                    if confirm == "yes":
                        self.shutdown()
                        break
                
                elif choice == "4":
                    print("\n✅ Exiting launcher (nodes still running)")
                    print("   Note: Nodes will continue in background")
                    break
                
                else:
                    print("❌ Invalid option")
                    
            except KeyboardInterrupt:
                print("\n\nInterrupted")
                break
            except Exception as e:
                print(f"❌ Error: {e}")


def main():
    """Main entry point"""
    print("\n" + "#"*70)
    print("# NAMED NETWORKS TOPOLOGY LAUNCHER")
    print("# Two-Router Hub-and-Spoke Architecture")
    print("#"*70)
    
    launcher = TopologyLauncher()
    
    # Handle Ctrl+C gracefully
    def signal_handler(sig, frame):
        print("\n\n⚠️  Interrupt received!")
        launcher.shutdown()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        # Ask user preference
        print("\nLaunch options:")
        print("1. Launch infrastructure + clients (recommended)")
        print("2. Launch infrastructure only (launch clients manually)")
        print("3. Exit")
        
        choice = input("\nSelect option (1-3): ").strip()
        
        if choice == "1":
            if launcher.launch_topology(include_clients=True):
                print("\n✅ Full topology is running!")
                print("\nYou can now:")
                print("  • Test communication between clients")
                print("  • Send requests to /dlsu/hello")
                print("  • Monitor packet flows in router GUIs")
                print("\nPress Ctrl+C to enter management menu...")
                
                try:
                    time.sleep(999999)
                except KeyboardInterrupt:
                    print("\n")
                    launcher.interactive_mode()
            else:
                print("\n❌ Topology launch failed")
                launcher.shutdown()
        
        elif choice == "2":
            if launcher.launch_topology(include_clients=False):
                print("\n✅ Infrastructure is running!")
                print("\nManually launch clients with:")
                print("  python client_gui.py Alice")
                print("  python client_gui.py Bob")
                print("\nPress Ctrl+C to enter management menu...")
                
                try:
                    time.sleep(999999)
                except KeyboardInterrupt:
                    print("\n")
                    launcher.interactive_mode()
            else:
                print("\n❌ Topology launch failed")
                launcher.shutdown()
        
        else:
            print("\n👋 Exiting without launching")
    
    except Exception as e:
        print(f"\n❌ Error: {e}")
        launcher.shutdown()
    finally:
        print("\n👋 Topology launcher exiting")


if __name__ == "__main__":
    main()