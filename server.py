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