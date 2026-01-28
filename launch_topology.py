import subprocess
import platform
import time

# List of commands to run - full RAID topology
# RAID 0 (Striping): ST0-A, ST0-B on ports 9001, 9002
# RAID 1 (Mirroring): ST1-A, ST1-B on ports 9003, 9004
# RAID 5 (Single Parity): ST5-A, ST5-B, ST5-C on ports 9005, 9006, 9007
# RAID 6 (Double Parity): ST6-A, ST6-B, ST6-C, ST6-D on ports 9008-9011
commands = [
    ["python", "server.py", "S1"],
    ["python", "router.py", "R1"],
    ["python", "router.py", "R2"],
    # RAID 0 - Striping (2 nodes)
    ["python", "storage_node.py", "ST0-A", "0", "9001"],
    ["python", "storage_node.py", "ST0-B", "0", "9002"],
    # RAID 1 - Mirroring (2 nodes)
    ["python", "storage_node.py", "ST1-A", "1", "9003"],
    ["python", "storage_node.py", "ST1-B", "1", "9004"],
    # RAID 5 - Single Parity (3 nodes)
    ["python", "storage_node.py", "ST5-A", "5", "9005"],
    ["python", "storage_node.py", "ST5-B", "5", "9006"],
    ["python", "storage_node.py", "ST5-C", "5", "9007"],
    # RAID 6 - Double Parity (4 nodes)
    ["python", "storage_node.py", "ST6-A", "6", "9008"],
    ["python", "storage_node.py", "ST6-B", "6", "9009"],
    ["python", "storage_node.py", "ST6-C", "6", "9010"],
    ["python", "storage_node.py", "ST6-D", "6", "9011"],
    # Client
    ["python", "simple_client.py", "alice"]
]

# Minimal topology (for quick testing) - just RAID 1
commands_minimal = [
    ["python", "server.py", "S1"],
    ["python", "router.py", "R1"],
    ["python", "router.py", "R2"],
    ["python", "storage_node.py", "ST1-A", "1", "9003"],
    ["python", "storage_node.py", "ST1-B", "1", "9004"],
    ["python", "simple_client.py", "alice"]
]

def launch_terminal(cmd_list):
    system = platform.system()
    
    if system == "Windows":
        # 'start' opens a new cmd window; 'python' runs the script
        # We use ['cmd', '/c'] to ensure the window stays or closes as needed
        subprocess.Popen(["start", "cmd", "/k"] + cmd_list, shell=True)
        
    elif system == "Darwin":  # macOS
        # Uses AppleScript to tell Terminal to do a new script
        cmd_str = " ".join(cmd_list)
        applescript = f'tell application "Terminal" to do script "cd {subprocess.os.getcwd()} && {cmd_str}"'
        subprocess.Popen(["osascript", "-e", applescript])
        
    else:  # Linux (assuming gnome-terminal, common in Ubuntu)
        # For other terminals, change 'gnome-terminal' to 'xterm' or 'konsole'
        subprocess.Popen(["gnome-terminal", "--"] + cmd_list)

# Check for command-line args
import sys
if len(sys.argv) > 1 and sys.argv[1] == 'minimal':
    print("Launching MINIMAL topology (RAID 1 only, 6 nodes)...")
    selected_commands = commands_minimal
else:
    print("Launching FULL RAID topology (11 storage nodes)...")
    print("  Use 'python launch_topology.py minimal' for minimal setup")
    selected_commands = commands

print(f"\nStarting {len(selected_commands)} nodes in separate windows...")

for cmd in selected_commands:
    launch_terminal(cmd)
    time.sleep(0.3)  # Brief pause to keep window order sane

print("Done.")
print("\nTopology:")
print("  Client → R1 (8001) → R2 (8002) → Server (7001)")
print("  R2 → Storage Nodes (see fib_config.py for RAID groups)")