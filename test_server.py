import socket
import threading
import time
import json

# Define test cases
TEST_CASES = [
    {"user": "alice", "password": "password123", "resource": "/files/alice_document.txt", "operation": "READ", "expected": "Request authorized"},
    {"user": "bob", "password": "password123", "resource": "/files/alice_document.txt", "operation": "READ", "expected": "Permission denied"},
    {"user": "alice", "password": "password123", "resource": "/files/shared_document.txt", "operation": "READ", "expected": "Request authorized"},
    {"user": "bob", "password": "password123", "resource": "/files/shared_document.txt", "operation": "READ", "expected": "Request authorized"},
    {"user": "alice", "password": "password123", "resource": "/files/secure_document.txt", "operation": "WRITE", "expected": "Request authorized"},
    {"user": "bob", "password": "password123", "resource": "/files/secure_document.txt", "operation": "WRITE", "expected": "Permission denied"},
    {"user": "alice", "password": "wrongpassword", "resource": "/files/alice_document.txt", "operation": "READ", "expected": "Authentication failed"},
]

# Function to simulate a client request
def simulate_request(user, password, resource, operation):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
        client_socket.settimeout(5)  # Set a 5-second timeout

        # Send data as a JSON object
        request_data = {
            "packet_type": "INTEREST",
            "name": resource,
            "user_id": user,
            "password": password,
            "operation": operation,
            "auth_key": None,
            "nonce": 0
        }
        client_socket.sendto(json.dumps(request_data).encode(), ("127.0.0.1", 7001))

        try:
            response, _ = client_socket.recvfrom(1024)
            return response.decode()
        except socket.timeout:
            return json.dumps({"status": "error", "message": "Request timed out"})

# Function to run the server in a separate thread
def run_server():
    import server  # Import the server module
    server.AuthenticationServer("127.0.0.1", 7001).start()

def _is_udp_port_free(host: str, port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind((host, port))
        s.close()
        return True
    except OSError:
        return False

# Start server thread only if the port is free. If another server is
# already running on the port, assume it's handling requests.
if _is_udp_port_free("127.0.0.1", 7001):
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    # Give server a moment to bind
    time.sleep(1)
else:
    print("Port 7001 is in use; assuming an external server is running")

# Allow the server to start (if running manually)
time.sleep(1)

# Run test cases
for i, test in enumerate(TEST_CASES, 1):
    print(f"Running Test Case {i}: {test}")
    response = simulate_request(test["user"], test["password"], test["resource"], test["operation"])
    print(f"Response: {response}")
    assert test["expected"] in response, f"Test Case {i} Failed! Expected: {test['expected']}, Got: {response}"

print("\nAll test cases passed!")