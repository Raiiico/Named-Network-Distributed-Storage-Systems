"""
Security Module - Named Networks Framework
Implements Discretionary Access Control (DAC), encryption, and authentication
"""

import hashlib
import time
import threading
import secrets
import base64
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum
# XOR cipher implementation - no external dependencies needed


class PermissionLevel(Enum):
    """Permission levels for DAC"""
    NONE = 0
    READ = 1
    WRITE = 2
    EXECUTE = 4
    ADMIN = 7  # READ + WRITE + EXECUTE


class AuthenticationStatus(Enum):
    """Authentication status"""
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"
    INVALID_KEY = "INVALID_KEY"


@dataclass
class User:
    """User account information"""
    user_id: str
    password_hash: str
    created_at: float
    last_login: Optional[float] = None
    is_active: bool = True
    groups: Set[str] = None
    
    def __post_init__(self):
        if self.groups is None:
            self.groups = set()


@dataclass
class AccessControlEntry:
    """Single ACL entry for a resource"""
    user_id: str
    permissions: int  # Bitmask of PermissionLevel values
    granted_by: str
    granted_at: float


@dataclass
class ResourceACL:
    """Access Control List for a resource"""
    resource_name: str
    owner: str
    created_at: float
    acl_entries: Dict[str, AccessControlEntry]  # user_id -> ACE
    is_public: bool = False
    
    def __post_init__(self):
        if not hasattr(self, 'acl_entries') or self.acl_entries is None:
            self.acl_entries = {}


@dataclass
class AuthToken:
    """One-time authentication token"""
    token: str
    user_id: str
    resource_name: str
    operation: str
    issued_at: float
    expires_at: float
    is_used: bool = False


@dataclass
class SecurityResponse:
    """Response from security operations"""
    success: bool
    user_id: Optional[str] = None
    authorized: bool = False
    message: Optional[str] = None
    auth_token: Optional[str] = None
    encrypted_data: Optional[bytes] = None
    decrypted_data: Optional[bytes] = None


class SecurityModule:
    """
    Security Module implementing:
    - Discretionary Access Control (DAC)
    - Encryption/Decryption
    - User Authentication
    - Permission Management
    """
    
    def __init__(self, node_name: str):
        self.node_name = node_name
        
        # User management
        self.users: Dict[str, User] = {}
        self.user_lock = threading.Lock()
        
        # Access Control Lists (DAC)
        self.resource_acls: Dict[str, ResourceACL] = {}
        self.acl_lock = threading.Lock()
        
        # Authentication tokens (one-time keys)
        self.auth_tokens: Dict[str, AuthToken] = {}
        self.token_lock = threading.Lock()
        
        # Encryption key (XOR cipher)
        self.encryption_key = self._generate_xor_key(32)  # 32 bytes = 256 bits
        
        # User groups
        self.groups: Dict[str, Set[str]] = {}  # group_name -> set of user_ids
        self.group_lock = threading.Lock()
        
        # Security policies
        self.token_ttl = 300  # Token valid for 5 minutes
        self.password_min_length = 6
        self.max_login_attempts = 3
        self.login_attempts: Dict[str, int] = {}
        
        # Statistics
        self.stats = {
            "total_users": 0,
            "total_resources": 0,
            "auth_attempts": 0,
            "auth_successes": 0,
            "auth_failures": 0,
            "permission_checks": 0,
            "permission_grants": 0,
            "permission_denials": 0,
            "tokens_issued": 0,
            "tokens_used": 0,
            "encryptions": 0,
            "decryptions": 0
        }
        
        # Initialize default users and groups
        self._initialize_defaults()
        
        print(f"[{self.node_name}][SECURITY] Security Module initialized")
        print(f"[{self.node_name}][SECURITY] DAC, Encryption, and Authentication enabled")
    
    def _initialize_defaults(self):
        """Initialize default users and groups"""
        # Create default users
        default_users = [
            ("alice", "password123"),
            ("bob", "password123"),
            ("admin", "admin123")
        ]
        
        for user_id, password in default_users:
            self.create_user(user_id, password)
        
        # Create default groups
        self.create_group("users")
        self.create_group("admins")
        
        # Add users to groups
        self.add_user_to_group("alice", "users")
        self.add_user_to_group("bob", "users")
        self.add_user_to_group("admin", "admins")
        
        print(f"[{self.node_name}][SECURITY] Created {len(default_users)} default users")
        print(f"[{self.node_name}][SECURITY] Created 2 default groups")
    
    # ==================== USER MANAGEMENT ====================
    
    def create_user(self, user_id: str, password: str) -> SecurityResponse:
        """Create a new user account"""
        if len(password) < self.password_min_length:
            return SecurityResponse(
                success=False,
                message=f"Password must be at least {self.password_min_length} characters"
            )
        
        with self.user_lock:
            if user_id in self.users:
                return SecurityResponse(
                    success=False,
                    message="User already exists"
                )
            
            # Hash password
            password_hash = self._hash_password(password)
            
            # Create user
            user = User(
                user_id=user_id,
                password_hash=password_hash,
                created_at=time.time(),
                groups=set()
            )
            
            self.users[user_id] = user
            self.stats["total_users"] += 1
            
            print(f"[{self.node_name}][SECURITY] User created: {user_id}")
            
            return SecurityResponse(
                success=True,
                user_id=user_id,
                message="User created successfully"
            )
    
    def authenticate_user(self, user_id: str, password: str) -> SecurityResponse:
        """Authenticate user with password"""
        self.stats["auth_attempts"] += 1
        
        # Check login attempts
        if self.login_attempts.get(user_id, 0) >= self.max_login_attempts:
            self.stats["auth_failures"] += 1
            return SecurityResponse(
                success=False,
                message="Account locked due to too many failed attempts"
            )
        
        with self.user_lock:
            user = self.users.get(user_id)
            
            if not user:
                self.stats["auth_failures"] += 1
                self._increment_login_attempts(user_id)
                return SecurityResponse(
                    success=False,
                    message="Invalid credentials"
                )
            
            if not user.is_active:
                self.stats["auth_failures"] += 1
                return SecurityResponse(
                    success=False,
                    message="Account is inactive"
                )
            
            # Verify password
            password_hash = self._hash_password(password)
            
            if password_hash != user.password_hash:
                self.stats["auth_failures"] += 1
                self._increment_login_attempts(user_id)
                return SecurityResponse(
                    success=False,
                    message="Invalid credentials"
                )
            
            # Authentication successful
            user.last_login = time.time()
            self.login_attempts[user_id] = 0  # Reset attempts
            self.stats["auth_successes"] += 1
            
            print(f"[{self.node_name}][SECURITY] User authenticated: {user_id}")
            
            return SecurityResponse(
                success=True,
                user_id=user_id,
                authorized=True,
                message="Authentication successful"
            )
    
    def _increment_login_attempts(self, user_id: str):
        """Track failed login attempts"""
        self.login_attempts[user_id] = self.login_attempts.get(user_id, 0) + 1
    
    def _hash_password(self, password: str) -> str:
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode('utf-8')).hexdigest()
    
    def change_password(self, user_id: str, old_password: str, new_password: str) -> SecurityResponse:
        """Change user password"""
        # Authenticate with old password
        auth_result = self.authenticate_user(user_id, old_password)
        
        if not auth_result.success:
            return SecurityResponse(
                success=False,
                message="Authentication failed"
            )
        
        if len(new_password) < self.password_min_length:
            return SecurityResponse(
                success=False,
                message=f"Password must be at least {self.password_min_length} characters"
            )
        
        with self.user_lock:
            user = self.users[user_id]
            user.password_hash = self._hash_password(new_password)
            
            print(f"[{self.node_name}][SECURITY] Password changed for: {user_id}")
            
            return SecurityResponse(
                success=True,
                message="Password changed successfully"
            )
    
    # ==================== GROUP MANAGEMENT ====================
    
    def create_group(self, group_name: str) -> bool:
        """Create a new group"""
        with self.group_lock:
            if group_name in self.groups:
                return False
            
            self.groups[group_name] = set()
            print(f"[{self.node_name}][SECURITY] Group created: {group_name}")
            return True
    
    def add_user_to_group(self, user_id: str, group_name: str) -> bool:
        """Add user to a group"""
        with self.group_lock:
            if group_name not in self.groups:
                return False
            
            self.groups[group_name].add(user_id)
            
            with self.user_lock:
                if user_id in self.users:
                    self.users[user_id].groups.add(group_name)
            
            print(f"[{self.node_name}][SECURITY] Added {user_id} to group {group_name}")
            return True
    
    def get_user_groups(self, user_id: str) -> Set[str]:
        """Get all groups a user belongs to"""
        with self.user_lock:
            user = self.users.get(user_id)
            if user:
                return user.groups.copy()
            return set()
    
    # ==================== ACCESS CONTROL (DAC) ====================
    
    def create_resource_acl(self, resource_name: str, owner: str) -> SecurityResponse:
        """Create Access Control List for a new resource"""
        with self.acl_lock:
            if resource_name in self.resource_acls:
                return SecurityResponse(
                    success=False,
                    message="Resource ACL already exists"
                )
            
            # Create ACL with owner having full permissions
            acl = ResourceACL(
                resource_name=resource_name,
                owner=owner,
                created_at=time.time(),
                acl_entries={},
                is_public=False
            )
            
            # Grant owner full permissions
            owner_ace = AccessControlEntry(
                user_id=owner,
                permissions=PermissionLevel.ADMIN.value,
                granted_by="system",
                granted_at=time.time()
            )
            
            acl.acl_entries[owner] = owner_ace
            # If the resource name indicates a shared resource, make it public
            if "shared" in resource_name.lower():
                acl.is_public = True

            self.resource_acls[resource_name] = acl
            self.stats["total_resources"] += 1
            
            print(f"[{self.node_name}][SECURITY] Created ACL for: {resource_name} (owner: {owner})")
            
            return SecurityResponse(
                success=True,
                message="Resource ACL created"
            )
    
    def grant_permission(self, resource_name: str, user_id: str, 
                        permissions: int, granted_by: str) -> SecurityResponse:
        """Grant permissions to a user for a resource (DAC)"""
        with self.acl_lock:
            acl = self.resource_acls.get(resource_name)
            
            if not acl:
                return SecurityResponse(
                    success=False,
                    message="Resource not found"
                )
            
            # Verify grantor has admin permissions
            if not self._has_permission(acl, granted_by, PermissionLevel.ADMIN.value):
                return SecurityResponse(
                    success=False,
                    message="Insufficient permissions to grant access"
                )
            
            # Create or update ACE
            ace = AccessControlEntry(
                user_id=user_id,
                permissions=permissions,
                granted_by=granted_by,
                granted_at=time.time()
            )
            
            acl.acl_entries[user_id] = ace
            self.stats["permission_grants"] += 1
            
            print(f"[{self.node_name}][SECURITY] Granted permissions to {user_id} on {resource_name}")
            
            return SecurityResponse(
                success=True,
                message="Permissions granted"
            )
    
    def revoke_permission(self, resource_name: str, user_id: str, 
                         revoked_by: str) -> SecurityResponse:
        """Revoke user permissions for a resource"""
        with self.acl_lock:
            acl = self.resource_acls.get(resource_name)
            
            if not acl:
                return SecurityResponse(
                    success=False,
                    message="Resource not found"
                )
            
            # Verify revoker has admin permissions
            if not self._has_permission(acl, revoked_by, PermissionLevel.ADMIN.value):
                return SecurityResponse(
                    success=False,
                    message="Insufficient permissions to revoke access"
                )
            
            # Cannot revoke owner's permissions
            if user_id == acl.owner:
                return SecurityResponse(
                    success=False,
                    message="Cannot revoke owner's permissions"
                )
            
            # Remove ACE
            if user_id in acl.acl_entries:
                del acl.acl_entries[user_id]
                print(f"[{self.node_name}][SECURITY] Revoked permissions for {user_id} on {resource_name}")
            
            return SecurityResponse(
                success=True,
                message="Permissions revoked"
            )
    
    def check_permission(self, resource_name: str, user_id: str, 
                        required_permission: PermissionLevel) -> SecurityResponse:
        """Check if user has required permission for resource"""
        self.stats["permission_checks"] += 1
        
        # Acquire the ACL reference under lock, but avoid holding the lock
        # while calling create_resource_acl (which also acquires the same lock).
        with self.acl_lock:
            acl = self.resource_acls.get(resource_name)

        if not acl:
            # Resource doesn't exist - create it with user as owner
            self.create_resource_acl(resource_name, user_id)
            self.stats["permission_grants"] += 1
            return SecurityResponse(
                success=True,
                authorized=True,
                message="Resource created with user as owner"
            )

        # Check if resource is public
        if acl.is_public and required_permission == PermissionLevel.READ:
            self.stats["permission_grants"] += 1
            return SecurityResponse(
                success=True,
                authorized=True,
                message="Public resource - read access granted"
            )

        # Check user permissions
        has_perm = self._has_permission(acl, user_id, required_permission.value)

        if has_perm:
            self.stats["permission_grants"] += 1
            print(f"[{self.node_name}][SECURITY] ✓ Permission granted: {user_id} -> {resource_name} ({required_permission.name})")
            return SecurityResponse(
                success=True,
                authorized=True,
                message="Permission granted"
            )
        else:
            self.stats["permission_denials"] += 1
            print(f"[{self.node_name}][SECURITY] ✗ Permission denied: {user_id} -> {resource_name} ({required_permission.name})")
            return SecurityResponse(
                success=True,
                authorized=False,
                message="Permission denied"
            )
    
    def _has_permission(self, acl: ResourceACL, user_id: str, required_permission: int) -> bool:
        """Check if user has required permission in ACL"""
        # Owner has all permissions
        if user_id == acl.owner:
            return True
        
        # Check direct user permissions
        ace = acl.acl_entries.get(user_id)
        if ace:
            return (ace.permissions & required_permission) == required_permission
        
        # Check group permissions
        user_groups = self.get_user_groups(user_id)
        for group in user_groups:
            ace = acl.acl_entries.get(f"group:{group}")
            if ace and (ace.permissions & required_permission) == required_permission:
                return True
        
        return False
    
    def set_resource_public(self, resource_name: str, is_public: bool, 
                           modified_by: str) -> SecurityResponse:
        """Set resource as public or private"""
        with self.acl_lock:
            acl = self.resource_acls.get(resource_name)
            
            if not acl:
                return SecurityResponse(
                    success=False,
                    message="Resource not found"
                )
            
            # Verify modifier has admin permissions
            if not self._has_permission(acl, modified_by, PermissionLevel.ADMIN.value):
                return SecurityResponse(
                    success=False,
                    message="Insufficient permissions"
                )
            
            acl.is_public = is_public
            
            status = "public" if is_public else "private"
            print(f"[{self.node_name}][SECURITY] Set {resource_name} as {status}")
            
            return SecurityResponse(
                success=True,
                message=f"Resource set as {status}"
            )
    
    # ==================== AUTHENTICATION TOKENS ====================
    
    def issue_auth_token(self, user_id: str, resource_name: str, 
                        operation: str) -> SecurityResponse:
        """Issue one-time authentication token"""
        # Generate secure token
        token = secrets.token_urlsafe(32)
        
        # Create token entry
        auth_token = AuthToken(
            token=token,
            user_id=user_id,
            resource_name=resource_name,
            operation=operation,
            issued_at=time.time(),
            expires_at=time.time() + self.token_ttl,
            is_used=False
        )
        
        with self.token_lock:
            self.auth_tokens[token] = auth_token
            self.stats["tokens_issued"] += 1
        
        print(f"[{self.node_name}][SECURITY] Issued auth token for {user_id} -> {resource_name}")
        
        return SecurityResponse(
            success=True,
            user_id=user_id,
            auth_token=token,
            message="Authentication token issued"
        )
    
    def validate_auth_token(self, token: str, resource_name: str, 
                           operation: str) -> SecurityResponse:
        """Validate and consume one-time authentication token"""
        with self.token_lock:
            auth_token = self.auth_tokens.get(token)
            
            if not auth_token:
                return SecurityResponse(
                    success=False,
                    authorized=False,
                    message="Invalid token"
                )
            
            # Check if already used
            if auth_token.is_used:
                return SecurityResponse(
                    success=False,
                    authorized=False,
                    message="Token already used"
                )
            
            # Check if expired
            if time.time() > auth_token.expires_at:
                return SecurityResponse(
                    success=False,
                    authorized=False,
                    message="Token expired"
                )
            
            # Validate resource and operation
            if auth_token.resource_name != resource_name or auth_token.operation != operation:
                return SecurityResponse(
                    success=False,
                    authorized=False,
                    message="Token not valid for this operation"
                )
            
            # Mark token as used
            auth_token.is_used = True
            self.stats["tokens_used"] += 1
            
            print(f"[{self.node_name}][SECURITY] ✓ Token validated: {auth_token.user_id} -> {resource_name}")
            
            return SecurityResponse(
                success=True,
                user_id=auth_token.user_id,
                authorized=True,
                message="Token valid"
            )
    
    # ==================== ENCRYPTION (XOR CIPHER) ====================
    
    def _generate_xor_key(self, key_length: int) -> bytes:
        """Generate a random XOR key"""
        return secrets.token_bytes(key_length)
    
    def _xor_cipher(self, data: bytes, key: bytes) -> bytes:
        """
        XOR cipher implementation
        XOR is symmetric: encrypt and decrypt use the same operation
        """
        # Repeat key to match data length if needed
        extended_key = (key * ((len(data) // len(key)) + 1))[:len(data)]
        
        # XOR each byte
        result = bytes([data[i] ^ extended_key[i] for i in range(len(data))])
        
        return result
    
    def encrypt_data(self, data: bytes) -> SecurityResponse:
        """Encrypt data using XOR cipher"""
        try:
            # Add a simple header to verify successful decryption
            header = b"ENC:"
            data_with_header = header + data
            
            # XOR encryption
            encrypted = self._xor_cipher(data_with_header, self.encryption_key)
            
            # Encode as base64 for safe transmission
            encrypted_b64 = base64.b64encode(encrypted)
            
            self.stats["encryptions"] += 1
            
            print(f"[{self.node_name}][SECURITY] Encrypted {len(data)} bytes -> {len(encrypted_b64)} bytes (XOR)")
            
            return SecurityResponse(
                success=True,
                encrypted_data=encrypted_b64,
                message="Data encrypted successfully with XOR cipher"
            )
        except Exception as e:
            return SecurityResponse(
                success=False,
                message=f"Encryption error: {str(e)}"
            )
    
    def decrypt_data(self, encrypted_data: bytes) -> SecurityResponse:
        """Decrypt data using XOR cipher"""
        try:
            # Decode from base64
            encrypted = base64.b64decode(encrypted_data)
            
            # XOR decryption (same operation as encryption)
            decrypted_with_header = self._xor_cipher(encrypted, self.encryption_key)
            
            # Verify header
            header = b"ENC:"
            if not decrypted_with_header.startswith(header):
                return SecurityResponse(
                    success=False,
                    message="Decryption failed: Invalid key or corrupted data"
                )
            
            # Remove header
            decrypted = decrypted_with_header[len(header):]
            
            self.stats["decryptions"] += 1
            
            print(f"[{self.node_name}][SECURITY] Decrypted {len(encrypted_data)} bytes -> {len(decrypted)} bytes (XOR)")
            
            return SecurityResponse(
                success=True,
                decrypted_data=decrypted,
                message="Data decrypted successfully with XOR cipher"
            )
        except Exception as e:
            return SecurityResponse(
                success=False,
                message=f"Decryption error: {str(e)}"
            )
    
    # ==================== MONITORING & REPORTING ====================
    
    def get_user_permissions(self, user_id: str) -> Dict[str, int]:
        """Get all permissions for a user across all resources"""
        permissions = {}
        
        with self.acl_lock:
            for resource_name, acl in self.resource_acls.items():
                ace = acl.acl_entries.get(user_id)
                if ace:
                    permissions[resource_name] = ace.permissions
                elif user_id == acl.owner:
                    permissions[resource_name] = PermissionLevel.ADMIN.value
        
        return permissions
    
    def get_resource_acl_info(self, resource_name: str) -> Optional[Dict]:
        """Get ACL information for a resource"""
        with self.acl_lock:
            acl = self.resource_acls.get(resource_name)
            
            if not acl:
                return None
            
            return {
                "resource_name": resource_name,
                "owner": acl.owner,
                "is_public": acl.is_public,
                "created_at": acl.created_at,
                "num_entries": len(acl.acl_entries),
                "entries": {
                    user_id: {
                        "permissions": ace.permissions,
                        "granted_by": ace.granted_by,
                        "granted_at": ace.granted_at
                    }
                    for user_id, ace in acl.acl_entries.items()
                }
            }
    
    def get_security_stats(self) -> Dict:
        """Get security module statistics"""
        return {
            **self.stats,
            "active_tokens": len([t for t in self.auth_tokens.values() if not t.is_used]),
            "auth_success_rate": (self.stats["auth_successes"] / max(1, self.stats["auth_attempts"])) * 100,
            "permission_grant_rate": (self.stats["permission_grants"] / max(1, self.stats["permission_checks"])) * 100
        }
    
    def show_stats(self):
        """Display security statistics"""
        stats = self.get_security_stats()
        
        print(f"\n=== {self.node_name} Security Statistics ===")
        print(f"Users: {self.stats['total_users']}")
        print(f"Resources: {self.stats['total_resources']}")
        print(f"Auth Attempts: {self.stats['auth_attempts']}")
        print(f"Auth Success Rate: {stats['auth_success_rate']:.1f}%")
        print(f"Permission Checks: {self.stats['permission_checks']}")
        print(f"Permission Grant Rate: {stats['permission_grant_rate']:.1f}%")
        print(f"Tokens Issued: {self.stats['tokens_issued']}")
        print(f"Tokens Used: {self.stats['tokens_used']}")
        print(f"Active Tokens: {stats['active_tokens']}")
        print(f"Encryptions: {self.stats['encryptions']}")
        print(f"Decryptions: {self.stats['decryptions']}")
        print("=" * 50)


# Test the security module
if __name__ == "__main__":
    print("Testing Security Module...")
    
    security = SecurityModule("Test-Security")
    
    # Test user authentication
    print("\n=== Testing Authentication ===")
    result = security.authenticate_user("alice", "password123")
    print(f"Auth result: {result.success}, {result.message}")
    
    # Test permission check
    print("\n=== Testing DAC ===")
    result = security.check_permission("/files/test.txt", "alice", PermissionLevel.READ)
    print(f"Permission result: {result.authorized}, {result.message}")
    
    # Grant permission to bob
    result = security.grant_permission("/files/test.txt", "bob", PermissionLevel.READ.value, "alice")
    print(f"Grant result: {result.success}, {result.message}")
    
    # Check bob's permission
    result = security.check_permission("/files/test.txt", "bob", PermissionLevel.READ)
    print(f"Bob's permission: {result.authorized}")
    
    # Test encryption
    print("\n=== Testing Encryption ===")
    data = b"Secret message"
    result = security.encrypt_data(data)
    print(f"Encrypted: {result.encrypted_data[:20]}...")
    
    result = security.decrypt_data(result.encrypted_data)
    print(f"Decrypted: {result.decrypted_data}")
    
    # Test auth tokens
    print("\n=== Testing Auth Tokens ===")
    result = security.issue_auth_token("alice", "/files/secure.txt", "READ")
    print(f"Token issued: {result.auth_token[:20]}...")
    
    result = security.validate_auth_token(result.auth_token, "/files/secure.txt", "READ")
    print(f"Token valid: {result.authorized}, User: {result.user_id}")
    
    # Show statistics
    security.show_stats()


class AuthenticationServer:
    """Simple UDP-based Authentication/Authorization server wrapper
    around the SecurityModule. Listens for JSON requests and returns a
    short textual response containing either 'AUTHORIZED' or 'DENIED' so
    that the router's string checks continue to work.

    Expected request JSON fields (from router/test harness):
      - packet_type (optional)
      - name: resource name
      - user_id: user requesting access
      - password: plaintext password (optional)
      - operation: READ/WRITE
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 7001):
        import socket
        # Lazy import DB getters to avoid circular imports at module import time
        try:
            from db import get_db
            self.db = get_db()
            # Ensure schema exists
            self.db.init_schema()
        except Exception:
            self.db = None

        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Pass DB into the external SecurityModule so permissions persist
        try:
            from security_module import SecurityModule as ExternalSecurityModule
            self.security = ExternalSecurityModule("Auth-Server", db=self.db)
        except Exception:
            # Fallback to local SecurityModule if import fails
            self.security = SecurityModule("Auth-Server")
        self._running = False

        # If DB present, sync security caches and migrate default passwords to the current encoding
        if self.db is not None:
            try:
                # Ensure in-memory cache reflects DB
                if hasattr(self.security, 'sync_from_db'):
                    self.security.sync_from_db()

                # Migrate default users' passwords to the module's XOR encoding so admin CLI and auth work consistently
                try:
                    self._migrate_default_passwords()
                except Exception as e:
                    print(f"[AuthServer] Default password migration warning: {e}")

                # Re-sync after potential migration
                if hasattr(self.security, 'sync_from_db'):
                    self.security.sync_from_db()
            except Exception as e:
                print(f"[AuthServer] DB sync/migrate failed: {e}")

        # Attach PacketLogger for request/response logging
        try:
            from common import PacketLogger
            self.logger = PacketLogger(self.security.node_name)
        except Exception:
            self.logger = None

    def start(self):
        import threading
        try:
            self.socket.bind((self.host, self.port))
            # If port 0 was used, update to the actual bound port
            try:
                self.port = self.socket.getsockname()[1]
            except Exception:
                pass
        except Exception as e:
            print(f"[AuthServer] Failed to bind {self.host}:{self.port}: {e}")
            raise

        self._running = True
        t = threading.Thread(target=self._serve_forever, daemon=True)
        t.start()
        print(f"[AuthServer] Listening on {self.host}:{self.port}")

    def stop(self):
        self._running = False
        try:
            self.socket.close()
        except Exception:
            pass

    def _serve_forever(self):
        import json
        from common import DataPacket, InterestPacket
        print(f"[AuthServer] Server thread started")
        while self._running:
            try:
                print(f"[AuthServer] Waiting for data...")
                data, addr = self.socket.recvfrom(65536)
                print(f"[AuthServer] Received {len(data)} bytes from {addr}")

                # Try to parse JSON first
                parsed = None
                try:
                    parsed = json.loads(data.decode('utf-8'))
                    print(f"[AuthServer] Parsed request: {parsed}")
                except Exception as e:
                    print(f"[AuthServer] JSON parse error: {e}")
                    parsed = None

                # Log via PacketLogger if present
                try:
                    if hasattr(self, 'logger') and parsed is not None:
                        pkt_type = parsed.get('type','').upper() if isinstance(parsed, dict) else 'UNKNOWN'
                        self.logger.log('RECV', pkt_type, parsed, addr)
                except Exception:
                    pass

                # If this was an Interest packet, handle Interest semantics and always reply with DataPacket
                if isinstance(parsed, dict) and parsed.get('type','').upper() == 'INTEREST':
                    try:
                        interest = InterestPacket.from_json(json.dumps(parsed))
                        # Map fields
                        resource = interest.name
                        user_id = interest.user_id.lower() if interest.user_id else None  # Normalize to lowercase
                        password = interest.auth_key
                        operation = (interest.operation or '').upper()

                        # Handle LIST (myfiles)
                        if operation == 'LIST' and ('/server/myfiles' in resource or '/dlsu/server/myfiles' in resource):
                            # authenticate
                            if not user_id or not password:
                                payload = {'error': 'Missing user_id or password', 'authorized': False}
                                dp = DataPacket(name=resource, data_payload=json.dumps(payload).encode('utf-8'))
                                resp = dp.to_json()
                                self.socket.sendto(resp.encode('utf-8'), addr)
                                # log send
                                try:
                                    if hasattr(self, 'logger'):
                                        self.logger.log('SEND', 'DATA', json.loads(resp), addr)
                                except Exception as _e:
                                    print(f"[AuthServer] PacketLogger SEND failed: {_e}")
                                continue

                            auth = self.security.authenticate_user(user_id, password)
                            if not auth.success:
                                payload = {'error': 'Authentication failed', 'authorized': False}
                                dp = DataPacket(name=resource, data_payload=json.dumps(payload).encode('utf-8'))
                                resp = dp.to_json()
                                self.socket.sendto(resp.encode('utf-8'), addr)
                                try:
                                    if hasattr(self, 'logger'):
                                        self.logger.log('SEND', 'DATA', json.loads(resp), addr)
                                except Exception:
                                    pass
                                continue

                            # Query DB for user files and validate existence via file_locations
                            try:
                                entries = []
                                if self.db is not None:
                                    raw_entries = self.db.get_user_files(user_id)
                                    for e in raw_entries:
                                        fname = e.get('name')

                                        # Verify file still exists in DB
                                        file_meta = self.db.get_file_by_name(fname)
                                        if not file_meta:
                                            # Stale entry - skip and remove any orphaned permissions
                                            print(f"[AuthServer] Warning: stale file entry for {fname} (removed)")
                                            try:
                                                self.db.delete_file(fname)
                                            except Exception:
                                                pass
                                            continue

                                        # Verify there are active file locations
                                        locs = self.db.get_file_locations(fname)
                                        if not locs:
                                            # No known storage locations - treat as deleted and remove from DB
                                            print(f"[AuthServer] Warning: file {fname} has no known locations, deleting DB entry")
                                            try:
                                                self.db.delete_file(fname)
                                            except Exception:
                                                pass
                                            continue

                                        # Include file (owner/permission info already present in e)
                                        entries.append({'name': fname, 'permission': e.get('permission'), 'owner': e.get('owner')})
                                else:
                                    # Fallback: use in-memory ACLs (legacy)
                                    for res_name, acl in self.security.resource_acls.items():
                                        if acl.owner == user_id:
                                            entries.append({'name': res_name, 'permission': 'OWNER', 'owner': user_id})
                                        else:
                                            ace = acl.acl_entries.get(user_id)
                                            if ace:
                                                perm_label = 'READ' if (ace.permissions & PermissionLevel.READ.value) else 'WRITE'
                                                entries.append({'name': res_name, 'permission': perm_label, 'owner': acl.owner})

                                payload = {'files': entries}
                                dp = DataPacket(name=resource, data_payload=json.dumps(payload).encode('utf-8'))
                                resp = dp.to_json()
                                self.socket.sendto(resp.encode('utf-8'), addr)
                                try:
                                    if hasattr(self, 'logger'):
                                        self.logger.log('SEND', 'DATA', json.loads(resp), addr)
                                except Exception:
                                    pass
                            except Exception as e:
                                payload = {'error': str(e)}
                                dp = DataPacket(name=resource, data_payload=json.dumps(payload).encode('utf-8'))
                                resp = dp.to_json()
                                self.socket.sendto(resp.encode('utf-8'), addr)
                                try:
                                    if hasattr(self, 'logger'):
                                        self.logger.log('SEND', 'DATA', json.loads(resp), addr)
                                except Exception:
                                    pass

                            continue

                        # Handle INFO
                        if operation == 'INFO' and ('/server/info' in resource or '/dlsu/server/info' in resource):
                            try:
                                payload = {'server_status': 'OK', 'storage_nodes': []}
                                if self.db is not None:
                                    # simple query for storage nodes
                                    try:
                                        cur = self.db._conn.cursor()
                                        cur.execute("SELECT node_name, host, port, raid_mode, active FROM storage_nodes")
                                        payload['storage_nodes'] = [dict(r) for r in cur.fetchall()]
                                    except Exception:
                                        payload['storage_nodes'] = []
                                dp = DataPacket(name=resource, data_payload=json.dumps(payload).encode('utf-8'))
                                resp = dp.to_json()
                                self.socket.sendto(resp.encode('utf-8'), addr)
                                try:
                                    if hasattr(self, 'logger'):
                                        self.logger.log('SEND', 'DATA', json.loads(resp), addr)
                                except Exception:
                                    pass
                            except Exception as e:
                                payload = {'error': str(e)}
                                dp = DataPacket(name=resource, data_payload=json.dumps(payload).encode('utf-8'))
                                resp = dp.to_json()
                                self.socket.sendto(resp.encode('utf-8'), addr)
                                try:
                                    if hasattr(self, 'logger'):
                                        self.logger.log('SEND', 'DATA', json.loads(resp), addr)
                                except Exception:
                                    pass
                            continue

                        # Handle CLEAR (admin reset - delete files but keep users)
                        if operation == 'CLEAR' and ('/server/clear' in resource or '/dlsu/server/clear' in resource):
                            try:
                                # Authenticate user
                                if not user_id or not password:
                                    payload = {'error': 'Missing credentials', 'success': False}
                                    dp = DataPacket(name=resource, data_payload=json.dumps(payload).encode('utf-8'))
                                    resp = dp.to_json()
                                    self.socket.sendto(resp.encode('utf-8'), addr)
                                    continue

                                auth = self.security.authenticate_user(user_id, password)
                                if not auth.success:
                                    payload = {'error': 'Authentication failed', 'success': False}
                                    dp = DataPacket(name=resource, data_payload=json.dumps(payload).encode('utf-8'))
                                    resp = dp.to_json()
                                    self.socket.sendto(resp.encode('utf-8'), addr)
                                    continue

                                # Perform clear operation
                                cleared_files = 0
                                cleared_permissions = 0
                                cleared_locations = 0
                                storage_nodes_cleared = []

                                if self.db is not None:
                                    # Clear file_locations table
                                    try:
                                        with self.db._connect() as conn:
                                            cursor = conn.cursor()
                                            cursor.execute("SELECT COUNT(*) FROM file_locations")
                                            cleared_locations = cursor.fetchone()[0]
                                            cursor.execute("DELETE FROM file_locations")
                                            conn.commit()
                                    except Exception as e:
                                        print(f"[AuthServer] CLEAR: Error clearing file_locations: {e}")

                                    # Clear permissions table
                                    try:
                                        with self.db._connect() as conn:
                                            cursor = conn.cursor()
                                            cursor.execute("SELECT COUNT(*) FROM permissions")
                                            cleared_permissions = cursor.fetchone()[0]
                                            cursor.execute("DELETE FROM permissions")
                                            conn.commit()
                                    except Exception as e:
                                        print(f"[AuthServer] CLEAR: Error clearing permissions: {e}")

                                    # Clear files table
                                    try:
                                        with self.db._connect() as conn:
                                            cursor = conn.cursor()
                                            cursor.execute("SELECT COUNT(*) FROM files")
                                            cleared_files = cursor.fetchone()[0]
                                            cursor.execute("DELETE FROM files")
                                            conn.commit()
                                    except Exception as e:
                                        print(f"[AuthServer] CLEAR: Error clearing files: {e}")

                                    # Get storage nodes to clear
                                    try:
                                        with self.db._connect() as conn:
                                            cursor = conn.cursor()
                                            cursor.execute("SELECT node_name, host, port FROM storage_nodes WHERE active = 1")
                                            storage_nodes_cleared = [dict(r) for r in cursor.fetchall()]
                                    except Exception:
                                        pass

                                # Also clear in-memory ACLs
                                self.security.resource_acls.clear()

                                print(f"[AuthServer] CLEAR: Removed {cleared_files} files, {cleared_permissions} permissions, {cleared_locations} locations")
                                
                                payload = {
                                    'success': True,
                                    'cleared_files': cleared_files,
                                    'cleared_permissions': cleared_permissions,
                                    'cleared_locations': cleared_locations,
                                    'storage_nodes': storage_nodes_cleared,
                                    'message': 'System cleared. Users retained. Send CLEAR to storage nodes to delete physical files.'
                                }
                                dp = DataPacket(name=resource, data_payload=json.dumps(payload).encode('utf-8'))
                                resp = dp.to_json()
                                self.socket.sendto(resp.encode('utf-8'), addr)
                                try:
                                    if hasattr(self, 'logger'):
                                        self.logger.log('SEND', 'DATA', json.loads(resp), addr)
                                except Exception:
                                    pass
                            except Exception as e:
                                payload = {'error': str(e), 'success': False}
                                dp = DataPacket(name=resource, data_payload=json.dumps(payload).encode('utf-8'))
                                resp = dp.to_json()
                                self.socket.sendto(resp.encode('utf-8'), addr)
                            continue

                        # Special handling: auth checks addressed to /dlsu/server/auth (including legacy embedded forms)
                        if resource and resource.startswith('/dlsu/server/auth'):
                            try:
                                # Prefer explicit target set by router, else fall back to name
                                resource_to_check = interest.target if getattr(interest, 'target', None) else resource
                                print(f"[AuthServer] Auth check: resource_to_check={resource_to_check}, operation={operation}, user={user_id}")
                                
                                # Normalize to base name
                                base_resource = self._strip_fragment_notation(resource_to_check)

                                # Legacy compatibility: strip embedded /dlsu/server/auth if present
                                if base_resource and base_resource.startswith("/dlsu/server/auth"):
                                    base_resource = base_resource[len("/dlsu/server/auth"):]
                                    if base_resource.startswith('/'):
                                        base_resource = base_resource[1:]
                                    base_resource = '/' + base_resource if base_resource else '/'
                                
                                print(f"[AuthServer] Normalized base_resource={base_resource}")

                                # Map requested operation from Interest (router preserves original op)
                                from security_module import PermissionLevel
                                op_check = (interest.operation or 'READ').upper()
                                if op_check == 'WRITE':
                                    perm = self.security.check_permission(base_resource, user_id, PermissionLevel.WRITE)
                                elif op_check == 'EXECUTE':
                                    perm = self.security.check_permission(base_resource, user_id, PermissionLevel.EXECUTE)
                                elif op_check == 'DELETE':
                                    # DELETE requires ADMIN (ownership) permission
                                    perm = self.security.check_permission(base_resource, user_id, PermissionLevel.ADMIN)
                                else:
                                    perm = self.security.check_permission(base_resource, user_id, PermissionLevel.READ)

                                resp_obj = {
                                    "status": "authorized" if perm.authorized else "denied",
                                    "authorized": bool(perm.authorized),
                                    "message": (f"AUTHORIZED: {user_id} -> {base_resource} ({op_check})" if perm.authorized else f"DENIED: {user_id} -> {base_resource} ({op_check})")
                                }
                                
                                # If authorized, look up file storage location from DB
                                if perm.authorized and self.db is not None:
                                    try:
                                        # Check if file exists in DB and get its location
                                        file_locations = self.db.get_file_locations(base_resource)
                                        if file_locations:
                                            # File exists - return its storage location
                                            loc = file_locations[0]  # Primary location
                                            resp_obj['storage_location'] = f"{loc.get('host')}:{loc.get('port')}"
                                            resp_obj['storage_node'] = loc.get('node_name')
                                            resp_obj['is_new_file'] = False
                                            print(f"[AuthServer] File {base_resource} found at {resp_obj['storage_location']}")
                                        else:
                                            # File doesn't exist - mark as new for WRITE operations
                                            if op_check == 'WRITE':
                                                resp_obj['is_new_file'] = True
                                                print(f"[AuthServer] File {base_resource} is NEW - router will assign storage")
                                            elif op_check == 'READ':
                                                # For READ, file must exist
                                                resp_obj['authorized'] = False
                                                resp_obj['status'] = 'denied'
                                                resp_obj['message'] = f"File not found: {base_resource}"
                                                print(f"[AuthServer] READ denied - file {base_resource} not found")
                                    except Exception as loc_err:
                                        print(f"[AuthServer] Error looking up file location: {loc_err}")

                                reply_name = interest.name if getattr(interest, 'name', None) else f"/dlsu/server/auth{base_resource}"
                                dp = DataPacket(name=reply_name, data_payload=json.dumps(resp_obj).encode('utf-8'))
                                response_bytes = dp.to_json().encode('utf-8')
                                from datetime import datetime
                                ts = datetime.now().strftime('%H:%M:%S.%f')[:-3]
                                print(f"[{ts}][AuthServer] Sending auth response ({len(response_bytes)} bytes) to {addr[0]}:{addr[1]}: {resp_obj}")
                                try:
                                    sent_bytes = self.socket.sendto(response_bytes, addr)
                                    ts2 = datetime.now().strftime('%H:%M:%S.%f')[:-3]
                                    print(f"[{ts2}][AuthServer] Auth response sent successfully ({sent_bytes} bytes sent to {addr[0]}:{addr[1]})")
                                except Exception as send_err:
                                    import traceback
                                    print(f"[AuthServer] ERROR sending auth response: {send_err}")
                                    traceback.print_exc()
                            except Exception as e:
                                print(f"[AuthServer] Auth check exception: {e}")
                                import traceback
                                traceback.print_exc()
                                payload = {'error': str(e), 'authorized': False}
                                dp = DataPacket(name=resource or '/server', data_payload=json.dumps(payload).encode('utf-8'))
                                try:
                                    self.socket.sendto(dp.to_json().encode('utf-8'), addr)
                                except Exception as send_err2:
                                    print(f"[AuthServer] ERROR sending error response: {send_err2}")
                            continue

                        # Unknown Interest operation: reply with error Data
                        payload = {'error': 'Unsupported Interest operation or resource', 'operation': operation}
                        dp = DataPacket(name=resource or '/server', data_payload=json.dumps(payload).encode('utf-8'))
                        resp = dp.to_json()
                        self.socket.sendto(resp.encode('utf-8'), addr)
                        try:
                            if hasattr(self, 'logger'):
                                self.logger.log('SEND', 'DATA', json.loads(resp), addr)
                        except Exception:
                            pass
                        continue

                    except Exception as e:
                        # Malformed Interest - reply with error Data
                        payload = {'error': f'Interest processing error: {e}'}
                        dp = DataPacket(name='/error', data_payload=json.dumps(payload).encode('utf-8'))
                        resp = dp.to_json()
                        self.socket.sendto(resp.encode('utf-8'), addr)
                        try:
                            if hasattr(self, 'logger'):
                                self.logger.log('SEND', 'DATA', json.loads(resp), addr)
                        except Exception:
                            pass
                        continue

                # Fallback to legacy action-based JSON handling
                # Normalize request dict for legacy handlers
                if parsed is None:
                    req = {}
                else:
                    req = parsed

                action = req.get('action', '').lower()
                resource = req.get('name') or req.get('resource') or req.get('resource_name')
                user_id = (req.get('user_id') or req.get('user') or '').lower() or None  # Normalize to lowercase
                password = req.get('password') or req.get('auth_key')
                operation = req.get('operation') or req.get('op') or 'READ'

                if action:
                    print(f"[AuthServer] Legacy action handler: action={action}, resource={resource}")

                # Simple authentication
                if action == 'authenticate':
                    if user_id and password:
                        auth = self.security.authenticate_user(user_id, password)
                        if auth.success:
                            resp_text = f"AUTHORIZED: Authentication successful for {user_id}"
                        else:
                            resp_text = f"DENIED: {auth.message}"
                    else:
                        resp_text = "DENIED: Missing user_id or password"
                    self.socket.sendto(resp_text.encode('utf-8'), addr)
                    continue

                elif action == 'grant':
                    # Grant permission: owner grants target_user access to resource
                    owner = req.get('owner')
                    target_user = req.get('target_user')
                    if not all([owner, target_user, resource, password]):
                        resp_text = "DENIED: Missing parameters (owner, target_user, resource, password)"
                        self.socket.sendto(resp_text.encode('utf-8'), addr)
                        continue
                    
                    # Authenticate owner
                    auth = self.security.authenticate_user(owner, password)
                    if not auth.success:
                        resp_text = f"DENIED: Authentication failed for {owner}"
                        self.socket.sendto(resp_text.encode('utf-8'), addr)
                        continue
                    
                    # Grant READ permission
                    from security_module import PermissionLevel
                    result = self.security.grant_permission(resource, target_user, PermissionLevel.READ.value, owner)
                    if result.success:
                        resp_text = f"SUCCESS: Granted READ access to {target_user} on {resource}"
                    else:
                        resp_text = f"FAILED: {result.message}"
                    self.socket.sendto(resp_text.encode('utf-8'), addr)
                    continue

                elif action == 'revoke':
                    # Revoke permission
                    owner = req.get('owner')
                    target_user = req.get('target_user')
                    if not all([owner, target_user, resource, password]):
                        resp_text = "DENIED: Missing parameters"
                        self.socket.sendto(resp_text.encode('utf-8'), addr)
                        continue
                    
                    auth = self.security.authenticate_user(owner, password)
                    if not auth.success:
                        resp_text = f"DENIED: Authentication failed"
                        self.socket.sendto(resp_text.encode('utf-8'), addr)
                        continue
                    
                    result = self.security.revoke_permission(resource, target_user, owner)
                    if result.success:
                        resp_text = f"SUCCESS: Revoked access for {target_user} on {resource}"
                    else:
                        resp_text = f"FAILED: {result.message}"
                    self.socket.sendto(resp_text.encode('utf-8'), addr)
                    continue

                elif action == 'delete_file':
                    # User requesting to delete a file (DAC - only owner can delete)
                    if not resource:
                        resp_text = "DENIED: Missing resource name"
                        self.socket.sendto(resp_text.encode('utf-8'), addr)
                        continue
                    
                    base_resource = self._strip_fragment_notation(resource)
                    
                    # Check ownership via DB (DAC - only owner can delete)
                    if self.db is not None:
                        file_record = self.db.get_file_by_name(base_resource)
                        if not file_record:
                            resp_obj = {'success': False, 'message': f"File not found: {base_resource}"}
                        else:
                            # Get owner from DB
                            try:
                                owner_user = self.db.get_user_by_id(file_record.get('owner_id'))
                                owner_name = owner_user.get('username', '').lower() if owner_user else ''
                            except Exception:
                                owner_name = ''
                            
                            if user_id and owner_name != user_id.lower():
                                resp_obj = {'success': False, 'message': f"DENIED: Only the owner ({owner_name}) can delete this file"}
                            else:
                                # Owner confirmed - get storage locations first
                                locations = self.db.get_file_locations(base_resource)
                                try:
                                    self.db.delete_file(base_resource)
                                    print(f"[AuthServer] Deleted file {base_resource} from DB")
                                    resp_obj = {
                                        'success': True,
                                        'deleted': base_resource,
                                        'storage_locations': locations
                                    }
                                except Exception as e:
                                    resp_obj = {'success': False, 'message': f"ERROR: {e}"}
                    else:
                        # Fallback to security module
                        result = self.security.delete_file(resource, user_id)
                        resp_obj = {
                            'success': result.success,
                            'message': result.message
                        }
                    self.socket.sendto(json.dumps(resp_obj).encode('utf-8'), addr)
                    continue

                elif action == 'list_owned':
                    # List files owned by user (owner-only)
                    if not user_id or not password:
                        resp_text = "DENIED: Missing user_id or password"
                        self.socket.sendto(resp_text.encode('utf-8'), addr)
                        continue

                    auth = self.security.authenticate_user(user_id, password)
                    if not auth.success:
                        resp_text = f"DENIED: Authentication failed"
                        self.socket.sendto(resp_text.encode('utf-8'), addr)
                        continue

                    # Prefer DB-backed listing
                    if self.db is not None:
                        try:
                            files = self.db.list_files(owner=user_id)
                            if files:
                                resp_text = "\n".join(f"  - {f['name']}" for f in files)
                            else:
                                resp_text = "  No files owned"
                        except Exception as e:
                            resp_text = f"ERROR: {e}"
                    else:
                        # Fallback to in-memory ACL listing
                        owned_files = []
                        for res_name, acl in self.security.resource_acls.items():
                            if acl.owner == user_id:
                                owned_files.append(res_name)
                        if owned_files:
                            resp_text = "\n".join(f"  - {f}" for f in owned_files)
                        else:
                            resp_text = "  No files owned"

                    self.socket.sendto(resp_text.encode('utf-8'), addr)
                    continue

                elif action == 'myfiles':
                    # List files owned by OR readable by user (aggregated)
                    if not user_id or not password:
                        resp_text = "DENIED: Missing user_id or password"
                        self.socket.sendto(resp_text.encode('utf-8'), addr)
                        continue

                    auth = self.security.authenticate_user(user_id, password)
                    if not auth.success:
                        resp_text = f"DENIED: Authentication failed"
                        self.socket.sendto(resp_text.encode('utf-8'), addr)
                        continue

                    # Use DB to get owner + permission-based listings
                    try:
                        if self.db is not None:
                            entries = self.db.get_user_files(user_id)
                            # Normalize entries to textual payload
                            if entries:
                                resp_text = json.dumps(entries)
                            else:
                                resp_text = json.dumps([])
                        else:
                            # Fallback: scan in-memory ACLs and permissions
                            entries = []
                            for res_name, acl in self.security.resource_acls.items():
                                if acl.owner == user_id:
                                    entries.append({'name': res_name, 'owner': user_id, 'permission': 'OWNER'})
                                else:
                                    ace = acl.acl_entries.get(user_id)
                                    if ace:
                                        # Map ACE permissions to READ/WRITE label
                                        perm_label = 'READ' if (ace.permissions & PermissionLevel.READ.value) else 'WRITE'
                                        entries.append({'name': res_name, 'owner': acl.owner, 'permission': perm_label})
                            resp_text = json.dumps(entries)
                    except Exception as e:
                        resp_text = f"ERROR: {e}"

                    self.socket.sendto(resp_text.encode('utf-8'), addr)
                    continue

                elif action == 'get_file_locations' or action == 'file_locations':
                    # Return storage node locations for a given file (requires auth and READ permission)
                    resource = req.get('resource') or req.get('file')
                    if not resource:
                        resp_text = "DENIED: Missing resource name"
                        self.socket.sendto(resp_text.encode('utf-8'), addr)
                        continue

                    if not user_id or not password:
                        resp_text = "DENIED: Missing user_id or password"
                        self.socket.sendto(resp_text.encode('utf-8'), addr)
                        continue

                    auth = self.security.authenticate_user(user_id, password)
                    if not auth.success:
                        resp_text = f"DENIED: Authentication failed"
                        self.socket.sendto(resp_text.encode('utf-8'), addr)
                        continue

                    # Check read permission via DB
                    try:
                        perm = self.db.check_permission(user_id, resource, 'READ') if self.db is not None else {'authorized': True}
                        if not perm.get('authorized'):
                            resp_text = "DENIED: No READ permission for resource"
                            self.socket.sendto(resp_text.encode('utf-8'), addr)
                            continue
                    except Exception:
                        resp_text = "DENIED: Permission check error"
                        self.socket.sendto(resp_text.encode('utf-8'), addr)
                        continue

                    # Fetch locations from DB
                    try:
                        if self.db is not None:
                            locations = self.db.get_file_locations(resource)
                            resp_text = json.dumps(locations)
                        else:
                            resp_text = json.dumps([])
                    except Exception as e:
                        resp_text = f"ERROR: {e}"

                    self.socket.sendto(resp_text.encode('utf-8'), addr)
                    continue

                elif action == 'register_file':
                    # Register file ownership (from storage node)
                    owner = req.get('owner')
                    if not resource or not owner:
                        resp_text = "DENIED: Missing resource or owner"
                        self.socket.sendto(resp_text.encode('utf-8'), addr)
                        continue

                    # Strip fragment notation to get base name
                    base_resource = self._strip_fragment_notation(resource)

                    # Prefer DB registration when available
                    if self.db is not None:
                        try:
                            self.db.add_file(base_resource, owner)
                            resp_text = f"SUCCESS: Registered {base_resource} (owner: {owner}) in DB"
                        except Exception:
                            # Likely already exists; treat as informational
                            resp_text = f"INFO: {base_resource} already registered"
                    else:
                        # Fallback: Create ACL in-memory
                        result = self.security.create_resource_acl(base_resource, owner)
                        if result.success:
                            resp_text = f"SUCCESS: ACL created for {base_resource} (owner: {owner})"
                        else:
                            resp_text = f"INFO: ACL already exists for {base_resource}"

                    self.socket.sendto(resp_text.encode('utf-8'), addr)
                    continue

                elif action == 'register_location':
                    # Storage node registering that it holds a file (records location)
                    print(f"[AuthServer] >>> REGISTER_LOCATION action received: {req}")
                    node_name = req.get('node_name') or req.get('storage_node')
                    host = req.get('host')
                    port = req.get('port')
                    stored_path = req.get('stored_path')
                    owner = req.get('owner')  # Optional owner for file creation
                    # Normalize owner to lowercase for DB consistency
                    if owner:
                        owner = owner.lower()
                    if not resource or not node_name:
                        resp_text = "DENIED: Missing resource or node_name"
                        self.socket.sendto(resp_text.encode('utf-8'), addr)
                        continue
                    base_resource = self._strip_fragment_notation(resource)
                    if self.db is not None:
                        try:
                            # Ensure node record exists (or is updated) with host/port
                            self.db.register_storage_node(node_name, host, port)
                            
                            # Check if file exists; if not, create with owner if provided
                            existing_file = self.db.get_file_by_name(base_resource)
                            if not existing_file and owner:
                                try:
                                    self.db.add_file(base_resource, owner, size=0, storage_path=stored_path)
                                    print(f"[AuthServer] Created file entry for {base_resource} with owner {owner}")
                                except Exception as e:
                                    print(f"[AuthServer] Warning: could not create file entry: {e}")
                            
                            # Add file location with host/port for node
                            self.db.add_file_location(base_resource, node_name, stored_path, host=host, port=port)
                            resp_text = f"SUCCESS: Registered location for {base_resource} on node {node_name}"
                            print(f"[AuthServer] {resp_text}")
                        except Exception as e:
                            resp_text = f"ERROR: {e}"
                    else:
                        resp_text = "INFO: No DB present; cannot persist location"
                    self.socket.sendto(resp_text.encode('utf-8'), addr)
                    continue

                elif action == 'clear_node_files':
                    # Storage node notifying that it cleared all files - remove DB records
                    node_name = req.get('node_name')
                    cleared_files = req.get('cleared_files', [])
                    if self.db is not None and cleared_files:
                        removed_count = 0
                        for file_name in cleared_files:
                            try:
                                # Remove file and its locations from DB
                                self.db.delete_file(file_name)
                                removed_count += 1
                            except Exception as e:
                                print(f"[AuthServer] Warning: could not delete file record {file_name}: {e}")
                        resp_text = f"SUCCESS: Removed {removed_count} file records from DB"
                        print(f"[AuthServer] {resp_text}")
                    else:
                        resp_text = "INFO: No files to clear or no DB"
                    self.socket.sendto(resp_text.encode('utf-8'), addr)
                    continue

                # Default: permission check
                # Optional authentication step using password (uses password or auth_key)
                if password and user_id:
                    auth = self.security.authenticate_user(user_id, password)
                    if not auth.success:
                        # Send DENIED as a Data packet for visibility at routers
                        from common import DataPacket
                        payload = {"status": "denied", "authorized": False, "message": f"Authentication failed for {user_id}"}
                        dp = DataPacket(name=resource or f"/server/auth{user_id}", data_payload=json.dumps(payload).encode('utf-8'))
                        try:
                            self.socket.sendto(dp.to_json().encode('utf-8'), addr)
                        except Exception:
                            pass
                        continue

                # If resource not provided, deny
                if not resource or not user_id:
                    from common import DataPacket
                    payload = {"status": "denied", "authorized": False, "message": "Missing resource or user"}
                    dp = DataPacket(name="/error", data_payload=json.dumps(payload).encode('utf-8'))
                    try:
                        self.socket.sendto(dp.to_json().encode('utf-8'), addr)
                    except Exception:
                        pass
                    continue

                # Determine the resource to check: prefer explicit `target` (from router), else fall back to name
                resource_to_check = None
                if resource and resource == '/dlsu/server/auth' and getattr(interest, 'target', None):
                    resource_to_check = interest.target
                else:
                    # Fall back to legacy behavior: resource may embed the target in its name
                    resource_to_check = resource

                # Strip fragment notation to get base name for permission check
                base_resource = self._strip_fragment_notation(resource_to_check)
                
                # If still has an embedded /dlsu/server/auth, strip it (legacy compatibility)
                if base_resource and base_resource.startswith("/dlsu/server/auth"):
                    base_resource = base_resource[len("/dlsu/server/auth"):]
                    if base_resource.startswith('/'):
                        base_resource = base_resource[1:]
                    base_resource = '/' + base_resource if base_resource else '/'

                # Map operation to PermissionLevel and check permission accordingly
                from security_module import PermissionLevel
                op = (operation or 'READ').upper()
                if op == 'WRITE':
                    perm = self.security.check_permission(base_resource, user_id, PermissionLevel.WRITE)
                elif op == 'EXECUTE':
                    perm = self.security.check_permission(base_resource, user_id, PermissionLevel.EXECUTE)
                else:
                    # Default to READ for READ, PERMISSION, and unknown ops
                    perm = self.security.check_permission(base_resource, user_id, PermissionLevel.READ)

                # Prepare DataPacket payload for router visibility
                from common import DataPacket
                resp_obj = {
                    "status": "authorized" if perm.authorized else "denied",
                    "authorized": bool(perm.authorized),
                    "message": (f"AUTHORIZED: {user_id} -> {base_resource} ({op})" if perm.authorized else f"DENIED: {user_id} -> {base_resource} ({op})")
                }

                # Reply using the incoming Interest name so routers can match PITs (typically '/dlsu/server/auth')
                reply_name = interest.name if getattr(interest, 'name', None) else f"/dlsu/server/auth{base_resource}"
                dp = DataPacket(name=reply_name, data_payload=json.dumps(resp_obj).encode('utf-8'))

                try:
                    self.socket.sendto(dp.to_json().encode('utf-8'), addr)
                except Exception:
                    pass

            except OSError:
                break
            except Exception as e:
                print(f"[AuthServer] Error handling request: {e}")
                continue
    
    def _strip_fragment_notation(self, resource_name: str) -> str:
        """Strip fragment notation from resource name to get base name.
        Example: /files/data.txt:[1/10] -> /files/data.txt
        """
        if ':[' in resource_name:
            return resource_name.split(':[')[0]
        return resource_name

    def _migrate_default_passwords(self):
        """Ensure default users (alice, bob, admin) have passwords stored using the current XOR encoding."""
        defaults = [("alice", "password123"), ("bob", "password123"), ("admin", "admin123")]
        for u, pwd in defaults:
            try:
                # compute encoded password using the running SecurityModule instance
                # SecurityModule._hash_password uses XOR encoding now
                hashed = self.security._hash_password(pwd)
                try:
                    # If user exists, update password to new encoded value
                    self.db.update_user_password(u, hashed)
                    print(f"[AuthServer] Migrated password for user: {u}")
                except Exception:
                    # If user doesn't exist, create it with the encoded password
                    try:
                        self.db.create_user(u, hashed)
                        print(f"[AuthServer] Created missing default user: {u}")
                    except Exception as e:
                        print(f"[AuthServer] Failed to create/update default user {u}: {e}")
            except Exception as e:
                print(f"[AuthServer] Error migrating password for {u}: {e}")

    def admin_cli(self):
        """Interactive admin CLI for server management"""
        print("\n" + "="*70)
        print("ADMIN CLI - Authentication Server")
        print("="*70)
        print("Commands:")
        print("  list users         - List all users")
        print("  list files         - List all files and owners")
        print("  list security      - Show security table (ACLs)")
        print("  grant <file> <user> - Override and grant access")
        print("  revoke <file> <user> - Override and revoke access")
        print("  show passwords     - Show encrypted passwords (XOR)")
        print("  clear all          - CLEAR ALL files, permissions, locations (ADMIN ONLY)")
        print("  stats              - Show security statistics")
        print("  quit               - Stop server")
        print("="*70 + "\n")
        
        while self._running:
            try:
                cmd = input("admin> ").strip().lower()
                
                if cmd in ["quit", "exit"]:
                    break
                
                elif cmd == "list users":
                    self._admin_list_users()
                
                elif cmd == "list files":
                    self._admin_list_files()
                
                elif cmd == "list security":
                    self._admin_list_security()
                
                elif cmd == "show passwords":
                    self._admin_show_passwords()
                
                elif cmd == "stats":
                    self.security.show_stats()
                
                elif cmd.startswith("grant"):
                    parts = cmd.split()
                    if len(parts) >= 3:
                        file_name = parts[1]
                        user = parts[2]
                        self._admin_grant(file_name, user)
                    else:
                        print("Usage: grant <file> <user>")
                
                elif cmd.startswith("revoke"):
                    parts = cmd.split()
                    if len(parts) >= 3:
                        file_name = parts[1]
                        user = parts[2]
                        self._admin_revoke(file_name, user)
                    else:
                        print("Usage: revoke <file> <user>")
                
                elif cmd == "help" or cmd == "?":
                    print("\\nAvailable commands:")
                    print("  list users, list files, list security")
                    print("  grant <file> <user>, revoke <file> <user>")
                    print("  show passwords, stats, clear all, quit")
                
                elif cmd == "clear all":
                    confirm = input("⚠️  This will DELETE ALL FILES, PERMISSIONS, and LOCATIONS. Type 'YES' to confirm: ").strip()
                    if confirm == 'YES':
                        self._admin_clear_all()
                    else:
                        print("Clear cancelled.")
                
                elif cmd:
                    print(f"Unknown command: {cmd}. Type 'help' for commands.")
            
            except (KeyboardInterrupt, EOFError):
                print()
                break
            except Exception as e:
                print(f"Error: {e}")
    
    def _admin_list_users(self):
        """List all users (DB-backed when available)"""
        print("\n" + "="*70)
        print("USERS")
        print("="*70)
        if self.db is not None:
            try:
                users = self.db.list_users()
                if not users:
                    print("  No users in DB")
                else:
                    for u in users:
                        uname = u['username']
                        created = u.get('created_at')
                        print(f"  {uname:15} | created_at: {created}")
            except Exception as e:
                print(f"  ERROR reading DB: {e}")
        else:
            if not self.security.users:
                print("  No users")
            else:
                for user_id, user in self.security.users.items():
                    status = "Active" if user.is_active else "Inactive"
                    groups = ", ".join(user.groups) if user.groups else "None"
                    print(f"  {user_id:15} | {status:8} | Groups: {groups}")
        print("="*70 + "\n")
    
    def _admin_list_files(self):
        """List all files and their owners (DB-backed when available)"""
        print("\n" + "="*70)
        print("FILES AND OWNERS")
        print("="*70)
        if self.db is not None:
            try:
                files = self.db.list_files()
                if not files:
                    print("  No files in DB")
                else:
                    for f in files:
                        public = ""
                        print(f"  {f['name']:40} | Owner: {f['owner']}{public}")
            except Exception as e:
                print(f"  ERROR reading DB: {e}")
        else:
            if not self.security.resource_acls:
                print("  No files tracked")
            else:
                for res_name, acl in self.security.resource_acls.items():
                    public = " (PUBLIC)" if acl.is_public else ""
                    print(f"  {res_name:40} | Owner: {acl.owner}{public}")
        print("="*70 + "\n")
    
    def _admin_list_security(self):
        """Show complete security table (ACLs) - DB-backed when available"""
        print("\n" + "="*70)
        print("SECURITY TABLE (Access Control Lists)")
        print("="*70)
        if self.db is not None:
            try:
                perms = self.db.list_permissions()
                if not perms:
                    print("  No explicit permissions in DB")
                else:
                    current = None
                    for p in perms:
                        if current != p['file_name']:
                            current = p['file_name']
                            print(f"\nResource: {current}")
                        granted_by = p.get('granted_by') or 'db'
                        print(f"  {p['grantee']:15} | Permissions: {p['permission']} | Granted by: {granted_by}")
            except Exception as e:
                print(f"  ERROR reading DB: {e}")
        else:
            if not self.security.resource_acls:
                print("  No ACLs")
            else:
                for res_name, acl in self.security.resource_acls.items():
                    print(f"\nResource: {res_name}")
                    print(f"  Owner: {acl.owner}")
                    print(f"  Public: {acl.is_public}")
                    print(f"  ACL Entries:")
                    if not acl.acl_entries:
                        print("    (none)")
                    else:
                        for uid, ace in acl.acl_entries.items():
                            perms = []
                            if ace.permissions & 1: perms.append("READ")
                            if ace.permissions & 2: perms.append("WRITE")
                            if ace.permissions & 4: perms.append("EXECUTE")
                            perm_str = ", ".join(perms) if perms else "NONE"
                            print(f"    {uid:15} | Permissions: {perm_str} | Granted by: {ace.granted_by}")
        print("="*70 + "\n")
    
    def _admin_show_passwords(self):
        """Show stored passwords (hex) and decoded plaintext using XOR when DB is available"""
        print("\n" + "="*70)
        print("STORED PASSWORDS")
        print("="*70)
        if self.db is not None:
            try:
                users = self.db.list_users()
                if not users:
                    print("  No users in DB")
                else:
                    for u in users:
                        uname = u['username']
                        stored = u.get('password_hash','')
                        decoded = ''
                        if hasattr(self.security, '_xor_decode') and stored:
                            decoded = self.security._xor_decode(stored)
                        print(f"  {uname:15} | stored: {stored[:64]} | decoded: {decoded}")
            except Exception as e:
                print(f"  ERROR reading DB: {e}")
        else:
            if not self.security.users:
                print("  No users")
            else:
                for user_id, user in self.security.users.items():
                    print(f"  {user_id:15} | stored: {user.password_hash[:64]}")
        print("="*70 + "\n")
    
    def _admin_grant(self, file_name: str, user: str):
        """Admin override to grant permission"""
        from security_module import PermissionLevel
        result = self.security.grant_permission(file_name, user, PermissionLevel.READ.value, "admin")
        if result.success:
            print(f"✓ Granted READ access to {user} on {file_name}")
        else:
            print(f"✗ Failed: {result.message}")
    
    def _admin_revoke(self, file_name: str, user: str):
        """Admin override to revoke permission"""
        result = self.security.revoke_permission(file_name, user, "admin")
        if result.success:
            print(f"✓ Revoked access for {user} on {file_name}")
        else:
            print(f"✗ Failed: {result.message}")

    def _admin_clear_all(self):
        """Admin-only: Clear all files, permissions, and locations from DB (keeps users).
        Also sends CLEAR requests to all storage nodes."""
        print("\n" + "="*70)
        print("CLEARING ALL DATA (Admin Only)")
        print("="*70)
        
        cleared_files = 0
        cleared_perms = 0
        cleared_locs = 0
        
        if self.db is not None:
            try:
                # Get counts before clearing
                files = self.db.list_files()
                file_count = len(files)
                
                # Clear file_locations first (foreign key)
                cur = self.db._conn.cursor()
                cur.execute("DELETE FROM file_locations")
                cleared_locs = cur.rowcount
                
                # Clear permissions
                cur.execute("DELETE FROM permissions")
                cleared_perms = cur.rowcount
                
                # Clear files
                cur.execute("DELETE FROM files")
                cleared_files = cur.rowcount
                
                self.db._conn.commit()
                
                print(f"  ✓ Cleared {cleared_files} files from DB")
                print(f"  ✓ Cleared {cleared_perms} permissions from DB")
                print(f"  ✓ Cleared {cleared_locs} file locations from DB")
                
            except Exception as e:
                print(f"  ✗ Error clearing DB: {e}")
        
        # Send CLEAR to all known storage nodes
        storage_nodes = [
            ('127.0.0.1', 9001, 'ST1'),
            ('127.0.0.1', 9002, 'ST2'),
            ('127.0.0.1', 9003, 'ST3'),
            ('127.0.0.1', 9004, 'ST4'),
        ]
        
        import socket
        for host, port, name in storage_nodes:
            try:
                from common import InterestPacket
                clear_interest = InterestPacket(
                    name="/dlsu/storage/clear",
                    operation="CLEAR",
                    user_id="admin"
                )
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3)
                sock.sendto(clear_interest.to_json().encode('utf-8'), (host, port))
                try:
                    resp, _ = sock.recvfrom(65535)
                    print(f"  ✓ Cleared storage node {name} ({host}:{port})")
                except socket.timeout:
                    print(f"  ⚠ Storage node {name} not responding ({host}:{port})")
                sock.close()
            except Exception as e:
                print(f"  ⚠ Could not clear {name}: {e}")
        
        print("="*70 + "\n")


if __name__ == "__main__":
    import sys
    # CLI: python server.py S1  -> start AuthenticationServer
    if len(sys.argv) > 1 and sys.argv[1].upper().startswith('S'):
        host = '127.0.0.1'
        port = 7001
        srv = AuthenticationServer(host, port)
        try:
            srv.start()
            print("="*70)
            print("Authentication Server Started")
            print("="*70)
            print(f"Listening on {host}:{port}")
            print("Starting admin CLI interface...")
            print("="*70 + "\n")
            
            # Run admin CLI
            srv.admin_cli()
            
        except KeyboardInterrupt:
            print("\nShutting down...")
        finally:
            srv.stop()
            print("Authentication server stopped")
    else:
        print("Usage: python server.py S1   # start AuthenticationServer on 127.0.0.1:7001")