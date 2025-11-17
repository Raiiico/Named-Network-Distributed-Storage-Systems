from security_module import SecurityModule, PermissionLevel
from common import InterestPacket
import socket
import json
import traceback

class AuthenticationServer:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.security_module = SecurityModule("AuthServer")
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Example: UDP

    def start(self):
        self.socket.bind((self.host, self.port))
        print(f"Server started on {self.host}:{self.port}")
        while True:
            data, addr = self.socket.recvfrom(1024)  # Receive request
            response = self.handle_request(data)
            try:
                print(f"[SERVER] Sending response to {addr}: {response}")
                self.socket.sendto(response, addr)  # Send response
            except Exception as e:
                print(f"[SERVER] Error sending response to {addr}: {e}")

    def handle_request(self, data: bytes) -> bytes:
        try:
            print(f"[SERVER] Received data: {data}")  # Debugging: Log received data

            # Ensure data is not empty
            if not data:
                raise ValueError("Received empty data")

            # Parse the request into a dict so we can extract password without
            # passing unexpected kwargs into InterestPacket
            data_dict = json.loads(data.decode())
            password = data_dict.pop("password", None)

            # Create InterestPacket from remaining fields
            request = InterestPacket(**data_dict)
            print(f"[SERVER] Parsed request: {request}")  # Debugging: Log parsed request

            user_id = request.user_id
            resource = request.name
            operation = request.operation

            # Authenticate user using provided password (or empty -> fail)
            auth_result = self.security_module.authenticate_user(user_id, password or "")
            print(f"[SERVER] Authentication result: {auth_result}")  # Debugging: Log auth result

            if not auth_result.success:
                return json.dumps({"status": "error", "message": "Authentication failed"}).encode()

            # Map operation string to PermissionLevel enum
            try:
                required_perm = PermissionLevel[operation]
            except Exception:
                required_perm = PermissionLevel.READ

            # Check permissions
            permission_result = self.security_module.check_permission(resource, user_id, required_perm)
            print(f"[SERVER] Permission result: {permission_result}")  # Debugging: Log permission result

            if not permission_result.authorized:
                return json.dumps({"status": "error", "message": "Permission denied"}).encode()

            # Success
            return json.dumps({"status": "success", "message": "Request authorized"}).encode()
        except ValueError as ve:
            print(f"[SERVER] ValueError: {ve}")
            return json.dumps({"status": "error", "message": str(ve)}).encode()
        except Exception as e:
            print(f"[SERVER] Error handling request: {e}")
            print(traceback.format_exc())
            return json.dumps({"status": "error", "message": "Server error"}).encode()

if __name__ == "__main__":
    server = AuthenticationServer("127.0.0.1", 7001)
    server.start()