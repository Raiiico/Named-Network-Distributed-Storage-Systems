#!/usr/bin/env python3
"""
Hub-and-Spoke Topology Launcher
Minimal topology: 1 Router + 1 Client + 1 Server + 1 Storage
All with integrated debugging GUI
"""

import subprocess
import sys
import time
import os
from pathlib import Path

class TopologyLauncher:
    """Launch minimal hub-and-spoke topology for testing"""
    
    def __init__(self):
        self.processes = []
        self.config = {
            "router": {"port": 8001, "script": "router.py", "args": ["R1"]},
            "server": {"port": 7001, "script": "server.py", "args": ["S1"]},
            "storage": {"port": 9001, "script": "storage_node.py", "args": ["ST1", "0"]},
            "client": {"script": "simple_client.py", "args": ["Alice"]}
        }
    
    def check_files_exist(self):
        """Verify all required files exist"""
        required_files = [
            "debug_gui.py",
            "common.py",
            "communication_module.py",
            "parsing_module.py",
            "processing_module.py",
            "routing_module.py",
            "storage_module.py",
            "router.py",
            "server.py",
            "storage_node.py",
            "simple_client.py"
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
        
        print("✓ All required files present")
        return True
    
    def launch_node(self, node_type, script, args, wait_time=2):
        """Launch a single node"""
        print(f"\n🚀 Launching {node_type}...")
        print(f"   Script: {script}")
        print(f"   Args: {' '.join(args)}")
        
        try:
            # Launch in new terminal/window based on OS
            if sys.platform == "win32":
                # Windows
                cmd = ["start", "cmd", "/k", "python", script] + args
                process = subprocess.Popen(cmd, shell=True)
            elif sys.platform == "darwin":
                # macOS
                cmd = ["osascript", "-e", 
                      f'tell app "Terminal" to do script "cd {os.getcwd()} && python3 {script} {" ".join(args)}"']
                process = subprocess.Popen(cmd)
            else:
                # Linux - try multiple terminal emulators
                terminals = [
                    ["gnome-terminal", "--", "python3", script] + args,
                    ["xterm", "-e", "python3", script] + args,
                    ["konsole", "-e", "python3", script] + args,
                    ["xfce4-terminal", "-e", f"python3 {script} {' '.join(args)}"]
                ]
                
                process = None
                for term_cmd in terminals:
                    try:
                        process = subprocess.Popen(term_cmd)
                        break
                    except FileNotFoundError:
                        continue
                
                if process is None:
                    print(f"⚠️  Could not find suitable terminal. Launching in background...")
                    process = subprocess.Popen(["python3", script] + args)
            
            self.processes.append(process)
            print(f"✓ {node_type} launched (PID: {process.pid})")
            time.sleep(wait_time)
            return True
            
        except Exception as e:
            print(f"❌ Failed to launch {node_type}: {e}")
            return False
    
    def launch_topology(self):
        """Launch complete hub-and-spoke topology"""
        print("="*70)
        print("NAMED NETWORKS - HUB-AND-SPOKE TOPOLOGY")
        print("="*70)
        print("\nTopology: 1 Router (hub) + 1 Client + 1 Server + 1 Storage")
        print("         All nodes connected to Router as the central hub")
        print()
        
        # Check files
        if not self.check_files_exist():
            return False
        
        # Launch sequence
        success = True
        
        # 1. Launch Router (must be first - it's the hub)
        success &= self.launch_node(
            "Router",
            self.config["router"]["script"],
            self.config["router"]["args"],
            wait_time=3
        )
        
        # 2. Launch Server
        success &= self.launch_node(
            "Server",
            self.config["server"]["script"],
            self.config["server"]["args"],
            wait_time=2
        )
        
        # 3. Launch Storage Node
        success &= self.launch_node(
            "Storage Node",
            self.config["storage"]["script"],
            self.config["storage"]["args"],
            wait_time=2
        )
        
        if not success:
            print("\n❌ Failed to launch all nodes")
            return False
        
        # Wait for all nodes to initialize
        print("\n⏳ Waiting for nodes to initialize...")
        time.sleep(3)
        
        print("\n" + "="*70)
        print("✓ HUB-AND-SPOKE TOPOLOGY LAUNCHED SUCCESSFULLY")
        print("="*70)
        print("\nNode Configuration:")
        print(f"  Router:  localhost:{self.config['router']['port']}")
        print(f"  Server:  localhost:{self.config['server']['port']}")
        print(f"  Storage: localhost:{self.config['storage']['port']}")
        print("\nTopology Structure:")
        print("         Client")
        print("           |")
        print("         Router  (Hub)")
        print("        /      \\")
        print("    Server    Storage")
        print("\n" + "="*70)
        
        # 4. Now launch Client (interactive mode)
        print("\n🎯 Ready to launch Client for testing...")
        print("   Press Enter to launch Client, or Ctrl+C to exit")
        try:
            input()
            self.launch_node(
                "Client",
                self.config["client"]["script"],
                self.config["client"]["args"],
                wait_time=1
            )
        except KeyboardInterrupt:
            print("\nSkipping client launch")
        
        return True
    
    def shutdown(self):
        """Shutdown all launched processes"""
        print("\n\n🛑 Shutting down topology...")
        for i, process in enumerate(self.processes, 1):
            try:
                print(f"   Terminating process {i}/{len(self.processes)} (PID: {process.pid})")
                process.terminate()
                process.wait(timeout=3)
            except:
                try:
                    process.kill()
                except:
                    pass
        
        print("✓ All processes terminated")
    
    def interactive_mode(self):
        """Interactive menu for topology management"""
        while True:
            print("\n" + "="*70)
            print("TOPOLOGY MANAGEMENT")
            print("="*70)
            print("1. Launch additional Client")
            print("2. Show topology status")
            print("3. Shutdown topology")
            print("4. Exit (leave topology running)")
            print()
            
            try:
                choice = input("Select option (1-4): ").strip()
                
                if choice == "1":
                    client_id = input("Enter client ID (e.g., Bob, Charlie): ").strip()
                    if client_id:
                        self.launch_node(
                            f"Client-{client_id}",
                            "simple_client.py",
                            [client_id],
                            wait_time=1
                        )
                
                elif choice == "2":
                    print("\n📊 Topology Status:")
                    print(f"   Active processes: {len(self.processes)}")
                    for i, proc in enumerate(self.processes, 1):
                        status = "Running" if proc.poll() is None else "Stopped"
                        print(f"   {i}. PID {proc.pid}: {status}")
                
                elif choice == "3":
                    confirm = input("Are you sure? (yes/no): ").strip().lower()
                    if confirm == "yes":
                        self.shutdown()
                        break
                
                elif choice == "4":
                    print("\n✓ Exiting launcher (topology still running)")
                    print("  Note: Nodes will continue running in background")
                    break
                
                else:
                    print("Invalid option")
                    
            except KeyboardInterrupt:
                print("\n\nInterrupted")
                break
            except Exception as e:
                print(f"Error: {e}")


def main():
    """Main entry point"""
    launcher = TopologyLauncher()
    
    try:
        # Launch topology
        if launcher.launch_topology():
            print("\n✓ Topology is running")
            print("\nYou can now:")
            print("  - Test with the Client interface")
            print("  - Check each node's debugging GUI")
            print("  - Monitor packet flows in real-time")
            print("\nPress Ctrl+C to enter management menu...")
            
            # Wait for interrupt
            try:
                time.sleep(999999)
            except KeyboardInterrupt:
                print("\n")
                launcher.interactive_mode()
        else:
            print("\n❌ Topology launch failed")
            launcher.shutdown()
    
    except Exception as e:
        print(f"\n❌ Error: {e}")
        launcher.shutdown()
    finally:
        print("\n👋 Topology launcher exiting")


if __name__ == "__main__":
    main()