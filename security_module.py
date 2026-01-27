#!/usr/bin/env python3
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

    If a `db` (Database) instance is provided, authoritative user and permission
    operations will be executed against the DB. In-memory structures remain as
    a lightweight cache/fallback for compatibility.
    """
    
    def __init__(self, node_name: str, db: Optional[object] = None):
        self.node_name = node_name
        self.db = db
        
        # User management (in-memory cache)
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
        """Initialize default users and groups

        Default users are created in the DB if a DB is provided; otherwise they
        are created in the in-memory store as before.
        """
        # Create default users
        default_users = [
            ("alice", "password123"),
            ("bob", "password123"),
            ("admin", "admin123")
        ]
        
        for user_id, password in default_users:
            # create_user will use DB when available
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
        """Create a new user account. If DB present, create in DB, otherwise use in-memory store."""
        if len(password) < self.password_min_length:
            return SecurityResponse(
                success=False,
                message=f"Password must be at least {self.password_min_length} characters"
            )

        password_hash = self._hash_password(password)

        with self.user_lock:
            # If DB present, delegate to DB
            if self.db is not None:
                try:
                    # Database expects a hashed password
                    db_res = self.db.create_user(user_id, password_hash)
                    # Keep local cache in sync
                    user = User(
                        user_id=user_id,
                        password_hash=password_hash,
                        created_at=time.time(),
                        groups=set()
                    )
                    self.users[user_id] = user
                    self.stats["total_users"] += 1

                    print(f"[{self.node_name}][SECURITY] User created in DB: {user_id}")
                    return SecurityResponse(success=True, user_id=user_id, message="User created successfully (db)")
                except Exception as e:
                    # DB integrity error (user exists) - try to load from DB into cache
                    try:
                        existing = self.db.get_user(user_id)
                        if existing:
                            user = User(
                                user_id=user_id,
                                password_hash=existing.get('password_hash',''),
                                created_at=existing.get('created_at', time.time()),
                                groups=set()
                            )
                            self.users[user_id] = user
                            print(f"[{self.node_name}][SECURITY] User exists in DB, loaded into cache: {user_id}")
                            return SecurityResponse(success=True, user_id=user_id, message="User exists (loaded from db)")
                    except Exception:
                        pass
                    return SecurityResponse(success=False, message=str(e))

            # Fallback to in-memory
            if user_id in self.users:
                return SecurityResponse(success=False, message="User already exists")

            user = User(
                user_id=user_id,
                password_hash=password_hash,
                created_at=time.time(),
                groups=set()
            )

            self.users[user_id] = user
            self.stats["total_users"] += 1

            print(f"[{self.node_name}][SECURITY] User created: {user_id}")
            return SecurityResponse(success=True, user_id=user_id, message="User created successfully")
    
    def authenticate_user(self, user_id: str, password: str) -> SecurityResponse:
        """Authenticate user with password. Uses DB when available."""
        self.stats["auth_attempts"] += 1

        # Check login attempts
        if self.login_attempts.get(user_id, 0) >= self.max_login_attempts:
            self.stats["auth_failures"] += 1
            return SecurityResponse(success=False, message="Account locked due to too many failed attempts")

        # If DB present, query DB
        if self.db is not None:
            db_user = self.db.get_user(user_id)
            if not db_user:
                self.stats["auth_failures"] += 1
                self._increment_login_attempts(user_id)
                return SecurityResponse(success=False, message="Invalid credentials")

            # Try XOR-based comparison first (current scheme)
            password_hash_xor = self._hash_password(password)
            stored = db_user.get('password_hash','')
            if stored == password_hash_xor:
                self.login_attempts[user_id] = 0
                self.stats["auth_successes"] += 1
                print(f"[{self.node_name}][SECURITY] User authenticated (db, xor): {user_id}")
                return SecurityResponse(success=True, user_id=user_id, authorized=True, message="Authentication successful")

            # Fallback: support older SHA-256 stored hashes (upgrade path)
            sha_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
            if stored == sha_hash:
                # Migrate stored hash to XOR-encoded form for future compatibility
                try:
                    self.db.update_user_password(user_id, password_hash_xor)
                    print(f"[{self.node_name}][SECURITY] Migrated password storage for user: {user_id}")
                except Exception:
                    pass
                self.login_attempts[user_id] = 0
                self.stats["auth_successes"] += 1
                print(f"[{self.node_name}][SECURITY] User authenticated (db, sha-fallback): {user_id}")
                return SecurityResponse(success=True, user_id=user_id, authorized=True, message="Authentication successful (migrated)")

            # If neither matched, fail
            self.stats["auth_failures"] += 1
            self._increment_login_attempts(user_id)
            return SecurityResponse(success=False, message="Invalid credentials")

        # Fallback to in-memory
        with self.user_lock:
            user = self.users.get(user_id)

            if not user:
                self.stats["auth_failures"] += 1
                self._increment_login_attempts(user_id)
                return SecurityResponse(success=False, message="Invalid credentials")

            if not user.is_active:
                self.stats["auth_failures"] += 1
                return SecurityResponse(success=False, message="Account is inactive")

            # Verify password
            password_hash = self._hash_password(password)

            if password_hash != user.password_hash:
                self.stats["auth_failures"] += 1
                self._increment_login_attempts(user_id)
                return SecurityResponse(success=False, message="Invalid credentials")

            # Authentication successful
            user.last_login = time.time()
            self.login_attempts[user_id] = 0  # Reset attempts
            self.stats["auth_successes"] += 1

            print(f"[{self.node_name}][SECURITY] User authenticated: {user_id}")
            return SecurityResponse(success=True, user_id=user_id, authorized=True, message="Authentication successful")
    
    def _increment_login_attempts(self, user_id: str):
        """Track failed login attempts"""
        self.login_attempts[user_id] = self.login_attempts.get(user_id, 0) + 1
    
    def _xor_encode(self, password: str) -> str:
        """Encode password using XOR with the module's encryption key and return hex string."""
        key = self.encryption_key
        b = password.encode('utf-8')
        x = bytes([b[i] ^ key[i % len(key)] for i in range(len(b))])
        return x.hex()

    def _xor_decode(self, hex_str: str) -> str:
        """Decode hex string produced by _xor_encode back to plaintext."""
        try:
            data = bytes.fromhex(hex_str)
        except Exception:
            return ''
        key = self.encryption_key
        b = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
        try:
            return b.decode('utf-8')
        except Exception:
            return ''

    def _hash_password(self, password: str) -> str:
        """XOR-encode the password (legacy docs call it 'encryption').
        Note: This is intentionally a reversible encoding per user request.
        """
        return self._xor_encode(password)

    def _perm_str_to_bits(self, perm: str) -> int:
        """Convert DB permission string to PermissionLevel bitmask."""
        if perm == 'OWNER':
            return PermissionLevel.ADMIN.value
        if perm == 'WRITE':
            return PermissionLevel.WRITE.value
        return PermissionLevel.READ.value

    def sync_from_db(self):
        """Populate in-memory users and ACL structures from DB when present."""
        if self.db is None:
            return
        # Load users
        try:
            users = self.db.list_users()
            with self.user_lock:
                for u in users:
                    username = u['username']
                    self.users[username] = User(
                        user_id=username,
                        password_hash=u.get('password_hash',''),
                        created_at=u.get('created_at', time.time()),
                        groups=set()
                    )
                self.stats['total_users'] = len(self.users)
        except Exception:
            pass

        # Load resource ACLs from files+permissions tables
        self.sync_acls_from_db()

    def sync_acls_from_db(self):
        if self.db is None:
            return
        try:
            files = self.db.list_files()
            # create ACL objects
            with self.acl_lock:
                for f in files:
                    name = f['name']
                    owner = f['owner']
                    acl = ResourceACL(resource_name=name, owner=owner, created_at=time.time(), acl_entries={}, is_public=False)
                    self.resource_acls[name] = acl
                # Attach permissions
                perms = self.db.list_permissions()
                for p in perms:
                    fname = p['file_name']
                    grantee = p['grantee']
                    perm_bits = self._perm_str_to_bits(p['permission'])
                    granted_by = p.get('granted_by') or 'db'
                    ace = AccessControlEntry(user_id=grantee, permissions=perm_bits, granted_by=granted_by, granted_at=p.get('granted_at', time.time()))
                    if fname not in self.resource_acls:
                        # create placeholder ACL if file missing
                        self.resource_acls[fname] = ResourceACL(resource_name=fname, owner='unknown', created_at=time.time(), acl_entries={}, is_public=False)
                    self.resource_acls[fname].acl_entries[grantee] = ace
        except Exception:
            pass
    
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
        """Create Access Control List for a new resource. Uses DB when available."""
        # If DB is available, create persistent file record
        if self.db is not None:
            try:
                self.db.add_file(resource_name, owner)
                # Sync cache
                if hasattr(self, 'sync_acls_from_db'):
                    self.sync_acls_from_db()
                self.stats["total_resources"] += 1
                print(f"[{self.node_name}][SECURITY] Created file record in DB: {resource_name} (owner: {owner})")
                return SecurityResponse(success=True, message="File record created in DB")
            except Exception as e:
                return SecurityResponse(success=False, message=str(e))

        with self.acl_lock:
            if resource_name in self.resource_acls:
                return SecurityResponse(
                    success=False,
                    message="Resource ACL already exists"
                )

            # Create ACL with owner having full permissions (in-memory fallback)
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
            self.resource_acls[resource_name] = acl
            self.stats["total_resources"] += 1

            print(f"[{self.node_name}][SECURITY] Created ACL for: {resource_name} (owner: {owner})")

            return SecurityResponse(
                success=True,
                message="Resource ACL created"
            )

    def _permission_int_to_str(self, permissions: int) -> str:
        """Convert internal permission int to DB permission string."""
        # ADMIN = full bits (e.g., 7). Check for admin explicitly.
        if (permissions & PermissionLevel.ADMIN.value) == PermissionLevel.ADMIN.value:
            return 'OWNER'
        if (permissions & PermissionLevel.WRITE.value) == PermissionLevel.WRITE.value:
            return 'WRITE'
        if (permissions & PermissionLevel.READ.value) == PermissionLevel.READ.value:
            return 'READ'
        return 'READ'

    def grant_permission(self, resource_name: str, user_id: str, 
                        permissions: int, granted_by: str) -> SecurityResponse:
        """Grant permissions to a user for a resource (DAC).

        When DB is available, store the permission in the DB; otherwise use
        in-memory ACLs as before.
        """
        perm_str = self._permission_int_to_str(permissions)

        # If DB available, delegate with permission checks
        if self.db is not None:
            try:
                # Verify grantor has OWNER permissions in DB
                check = self.db.check_permission(granted_by, resource_name, 'OWNER')
                if not check.get('authorized'):
                    return SecurityResponse(success=False, message='Insufficient permissions to grant access')

                res = self.db.grant_permission(resource_name, user_id, perm_str, granted_by)
                # Sync cache
                if hasattr(self, 'sync_acls_from_db'):
                    self.sync_acls_from_db()
                self.stats['permission_grants'] += 1
                return SecurityResponse(success=True, message=f'Granted {perm_str} to {user_id} for {resource_name}')
            except Exception as e:
                return SecurityResponse(success=False, message=str(e))

        # Fallback to in-memory ACL
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
            
            ace = AccessControlEntry(
                user_id=user_id,
                permissions=permissions,
                granted_by=granted_by,
                granted_at=time.time()
            )
            acl.acl_entries[user_id] = ace
            self.stats['permission_grants'] += 1
            print(f"[{self.node_name}][SECURITY] Granted permissions to {user_id} on {resource_name}")
            return SecurityResponse(success=True, message="Permission granted")
            
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
        # If DB present, perform revoke in DB
        if self.db is not None:
            try:
                # Verify revoker has OWNER permissions
                check = self.db.check_permission(revoked_by, resource_name, 'OWNER')
                if not check.get('authorized'):
                    return SecurityResponse(success=False, message='Insufficient permissions to revoke access')

                # Prevent revoking owner's own perms
                file = self.db.get_file_by_name(resource_name)
                if file and file.get('owner') == user_id:
                    return SecurityResponse(success=False, message="Cannot revoke owner's permissions")

                res = self.db.revoke_permission(resource_name, user_id)
                # Sync cache
                if hasattr(self, 'sync_acls_from_db'):
                    self.sync_acls_from_db()
                return SecurityResponse(success=True, message=f"Revoked permissions for {user_id} on {resource_name}")
            except Exception as e:
                return SecurityResponse(success=False, message=str(e))

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

    def delete_file(self, resource_name: str, deleted_by: str) -> SecurityResponse:
        """Delete a file from the system (DB and/or in-memory ACLs).
        Useful for cleanup when storage reports file not found or for administrative removal.
        """
        # If DB present, delete from DB
        if self.db is not None:
            try:
                res = self.db.delete_file(resource_name)
                # Sync cache
                if hasattr(self, 'sync_acls_from_db'):
                    self.sync_acls_from_db()
                return SecurityResponse(success=True, message=f"Deleted file {resource_name} from DB")
            except Exception as e:
                return SecurityResponse(success=False, message=str(e))

        # Fallback: delete from in-memory ACLs
        with self.acl_lock:
            if resource_name in self.resource_acls:
                del self.resource_acls[resource_name]
                print(f"[{self.node_name}][SECURITY] Deleted file {resource_name}")
                return SecurityResponse(success=True, message=f"Deleted file {resource_name}")
            else:
                return SecurityResponse(success=True, message=f"File {resource_name} not found")
    
    def _perm_enum_to_str(self, perm: PermissionLevel) -> str:
        if perm == PermissionLevel.WRITE or perm == PermissionLevel.ADMIN:
            return 'WRITE'
        if perm == PermissionLevel.READ:
            return 'READ'
        return 'READ'

    def check_permission(self, resource_name: str, user_id: str, 
                        required_permission: PermissionLevel) -> SecurityResponse:
        """Check if user has required permission for resource (DB-aware).
        
        DAC semantics: 
        - User can WRITE to non-existent resources (creates them as owner)
        - Owners can grant/revoke access to their files
        - Others can READ if owner granted READ permission
        """
        self.stats["permission_checks"] += 1
        print(f"[{self.node_name}][SECURITY] check_permission: resource={resource_name}, user={user_id}, level={required_permission}")

        # If DB present, delegate to DB
        if self.db is not None:
            perm_str = self._perm_enum_to_str(required_permission)
            db_res = self.db.check_permission(user_id, resource_name, perm_str)
            print(f"[{self.node_name}][SECURITY] DB check result: {db_res}")
            
            # If file doesn't exist and user is trying to WRITE, allow it (create with user as owner)
            if not db_res.get('success') and db_res.get('message') == 'file not found':
                print(f"[{self.node_name}][SECURITY] File not found, checking if auto-create for WRITE: required_permission={required_permission}")
                if required_permission == PermissionLevel.WRITE or required_permission == PermissionLevel.ADMIN:
                    try:
                        # Auto-create file with user as owner
                        print(f"[{self.node_name}][SECURITY] Attempting to create file {resource_name} with owner {user_id}")
                        self.db.add_file(resource_name, user_id)
                        if hasattr(self, 'sync_acls_from_db'):
                            self.sync_acls_from_db()
                        self.stats["permission_grants"] += 1
                        print(f"[{self.node_name}][SECURITY] ✓ Created file {resource_name} with owner: {user_id}")
                        return SecurityResponse(
                            success=True,
                            authorized=True,
                            message="File created with user as owner (WRITE access granted)"
                        )
                    except Exception as e:
                        print(f"[{self.node_name}][SECURITY] ✗ Auto-create failed: {e}")
                        # File might already exist (race condition), check again
                        db_res = self.db.check_permission(user_id, resource_name, perm_str)
                        if db_res.get('success') and db_res.get('authorized'):
                            return SecurityResponse(success=True, authorized=True, message=db_res.get('message'))
                        # Still failed, deny
                        print(f"[{self.node_name}][SECURITY] ✗ Re-check also failed, denying WRITE")
                        return SecurityResponse(success=False, authorized=False, message=str(e))
                # READ on non-existent file is denied
                return SecurityResponse(success=False, authorized=False, message=db_res.get('message'))
            
            if not db_res.get('success'):
                return SecurityResponse(success=False, authorized=False, message=db_res.get('message'))
            return SecurityResponse(success=True, authorized=db_res.get('authorized', False), message=db_res.get('message'))

        with self.acl_lock:
            acl = self.resource_acls.get(resource_name)
            
            if not acl:
                # Resource doesn't exist - allow WRITE (user becomes owner)
                # For READ on non-existent resource, deny
                if required_permission == PermissionLevel.WRITE or required_permission == PermissionLevel.ADMIN:
                    self.create_resource_acl(resource_name, user_id)
                    self.stats["permission_grants"] += 1
                    print(f"[{self.node_name}][SECURITY] ✓ Created file {resource_name} with owner: {user_id}")
                    return SecurityResponse(
                        success=True,
                        authorized=True,
                        message="Resource created with user as owner"
                    )
                else:
                    # READ on non-existent resource denied
                    self.stats["permission_denials"] += 1
                    return SecurityResponse(
                        success=False,
                        authorized=False,
                        message="Resource not found"
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
                    success=False,
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
        # If DB present, update metadata JSON field
        if self.db is not None:
            try:
                # Verify modifier has OWNER permissions
                check = self.db.check_permission(modified_by, resource_name, 'OWNER')
                if not check.get('authorized'):
                    return SecurityResponse(success=False, message='Insufficient permissions')
                # Set metadata flag
                meta = {'is_public': bool(is_public)}
                self.db.set_file_metadata(resource_name, meta)
                if hasattr(self, 'sync_acls_from_db'):
                    self.sync_acls_from_db()
                status = "public" if is_public else "private"
                print(f"[{self.node_name}][SECURITY] Set {resource_name} as {status} (DB)")
                return SecurityResponse(success=True, message=f"Resource set as {status}")
            except Exception as e:
                return SecurityResponse(success=False, message=str(e))

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
        """Get all permissions for a user across all resources (DB-backed when available)"""
        permissions = {}
        if self.db is not None:
            try:
                entries = self.db.get_user_files(user_id)
                for e in entries:
                    perm_label = e.get('permission','READ')
                    if perm_label == 'OWNER':
                        permissions[e['name']] = PermissionLevel.ADMIN.value
                    elif perm_label == 'WRITE':
                        permissions[e['name']] = PermissionLevel.WRITE.value
                    else:
                        permissions[e['name']] = PermissionLevel.READ.value
                return permissions
            except Exception:
                return {}

        with self.acl_lock:
            for resource_name, acl in self.resource_acls.items():
                ace = acl.acl_entries.get(user_id)
                if ace:
                    permissions[resource_name] = ace.permissions
                elif user_id == acl.owner:
                    permissions[resource_name] = PermissionLevel.ADMIN.value
        
        return permissions
    
    def get_resource_acl_info(self, resource_name: str) -> Optional[Dict]:
        """Get ACL information for a resource (DB-backed when available)"""
        if self.db is not None:
            try:
                f = self.db.get_file_by_name(resource_name)
                if not f:
                    return None
                meta = self.db.get_file_metadata(resource_name) or {}
                # permissions for resource
                perms = [p for p in self.db.list_permissions() if p['file_name'] == resource_name]
                entries = {}
                for p in perms:
                    # Map permission strings to bitmask
                    if p['permission'] == 'OWNER':
                        bits = PermissionLevel.ADMIN.value
                    elif p['permission'] == 'WRITE':
                        bits = PermissionLevel.WRITE.value
                    else:
                        bits = PermissionLevel.READ.value
                    entries[p['grantee']] = {
                        'permissions': bits,
                        'granted_by': p.get('granted_by') or 'db',
                        'granted_at': p.get('granted_at')
                    }
                return {
                    'resource_name': resource_name,
                    'owner': f.get('owner'),
                    'is_public': bool(meta.get('is_public', False)),
                    'created_at': f.get('created_at'),
                    'num_entries': len(entries),
                    'entries': entries
                }
            except Exception:
                return None

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