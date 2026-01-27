import subprocess
import platform
import time

# List of commands to run
commands = [
    ["python", "server.py", "S1"],
    ["python", "router.py", "R1"],
    ["python", "router.py", "R2"],
    ["python", "storage_node.py", "ST1", "0", "9001"],
    ["python", "storage_node.py", "ST2", "1", "9002"],
    ["python", "storage_node.py", "ST3", "5", "9003"],
    ["python", "storage_node.py", "ST4", "6", "9004"],
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

print(f"Launching {len(commands)} nodes in separate windows...")

for cmd in commands:
    launch_terminal(cmd)
    time.sleep(0.3)  # Brief pause to keep window order sane

print("Done.")