"""Database access layer for Named Networks prototype.

Provides a small, well-tested API for users, files, permissions and storage nodes
using SQLite for persistence. Keep functions small and return plain dicts.

Usage:
    from db import Database
    db = Database('named_networks.db')
    db.init_schema()
    db.create_user('alice', password_hash)
    db.add_file('/files/alice.txt', 'alice')
    files = db.get_user_files('alice')
"""

from __future__ import annotations

import sqlite3
import json
import time
from typing import Optional, List, Dict, Any

DEFAULT_DB_PATH = "named_networks.db"
DEFAULT_TIMEOUT = 30.0  # Increased timeout for multi-process access
MAX_RETRIES = 5
RETRY_DELAY = 0.2  # seconds between retries

class Database:
    def __init__(self, db_path: str = DEFAULT_DB_PATH, timeout: float = DEFAULT_TIMEOUT):
        self.db_path = db_path
        self.timeout = timeout
        # Use per-operation connections instead of persistent connection
        # This avoids lock contention in multi-process environments
        self._conn = None  # Lazy connection
        self._init_connection()

    def _init_connection(self):
        """Initialize a new connection if needed."""
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path, timeout=self.timeout, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._ensure_pragmas()

    def _get_fresh_connection(self):
        """Get a fresh connection for write operations to avoid lock issues."""
        conn = sqlite3.connect(self.db_path, timeout=self.timeout, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("PRAGMA foreign_keys = ON;")
        cur.execute("PRAGMA journal_mode = WAL;")
        cur.execute(f"PRAGMA busy_timeout = {int(self.timeout * 1000)};")
        conn.commit()
        return conn

    def _ensure_pragmas(self):
        cur = self._conn.cursor()
        # Foreign keys and WAL for concurrency
        cur.execute("PRAGMA foreign_keys = ON;")
        cur.execute("PRAGMA journal_mode = WAL;")
        # Set busy timeout at SQLite level (milliseconds) for better concurrency
        cur.execute(f"PRAGMA busy_timeout = {int(self.timeout * 1000)};")
        self._conn.commit()

    def _execute_with_retry(self, operation, *args, **kwargs):
        """Execute a database write operation with fresh connection and retry logic."""
        last_error = None
        for attempt in range(MAX_RETRIES):
            conn = None
            try:
                # Use fresh connection for each write attempt
                conn = self._get_fresh_connection()
                return operation(conn, *args, **kwargs)
            except sqlite3.OperationalError as e:
                if "locked" in str(e).lower() or "busy" in str(e).lower():
                    last_error = e
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(RETRY_DELAY * (attempt + 1))  # Exponential backoff
                        continue
                raise
            finally:
                if conn:
                    try:
                        conn.close()
                    except Exception:
                        pass
        raise last_error if last_error else sqlite3.OperationalError("Database operation failed")

    def close(self):
        try:
            if self._conn:
                self._conn.close()
                self._conn = None
        except Exception:
            pass

    def init_schema(self):
        self._init_connection()
        cur = self._conn.cursor()
        cur.executescript("""
        BEGIN;

        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            size INTEGER DEFAULT 0,
            storage_path TEXT,
            metadata TEXT,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
            grantee_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            permission TEXT NOT NULL CHECK(permission IN ('READ','WRITE','OWNER')),
            granted_by INTEGER REFERENCES users(id),
            granted_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS storage_nodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_name TEXT UNIQUE,
            host TEXT,
            port INTEGER,
            raid_mode TEXT,
            active INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS file_fragments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
            fragment_index INTEGER NOT NULL,
            storage_node_id INTEGER REFERENCES storage_nodes(id),
            size INTEGER DEFAULT 0
        );

        -- Track which storage nodes hold a given file (one entry per location)
        CREATE TABLE IF NOT EXISTS file_locations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
            storage_node_id INTEGER NOT NULL REFERENCES storage_nodes(id),
            stored_path TEXT,
            last_seen INTEGER NOT NULL
        );

        INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES (1, strftime('%s','now'));

        COMMIT;
        """)
        self._conn.commit()

    # User helpers
    def create_user(self, username: str, password_hash: str, salt: Optional[str] = None) -> Dict[str, Any]:
        def _do_create(conn):
            cur = conn.cursor()
            now = int(time.time())
            try:
                cur.execute(
                    "INSERT INTO users (username, password_hash, salt, created_at) VALUES (?, ?, ?, ?)",
                    (username, password_hash, salt, now),
                )
                conn.commit()
                return dict(id=cur.lastrowid, username=username, created_at=now)
            except sqlite3.IntegrityError as e:
                raise
        return self._execute_with_retry(_do_create)

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        self._init_connection()
        cur = self._conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        return dict(row) if row else None

    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get user by ID."""
        self._init_connection()
        cur = self._conn.cursor()
        cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        return dict(row) if row else None

    # File helpers
    def add_file(self, name: str, owner_username: str, size: int = 0, storage_path: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        def _do_add(conn):
            owner = self.get_user(owner_username)
            if not owner:
                raise ValueError(f"Owner user not found: {owner_username}")
            now = int(time.time())
            cur = conn.cursor()
            meta_json = json.dumps(metadata) if metadata is not None else None
            cur.execute(
                "INSERT INTO files (name, owner_id, size, storage_path, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (name, owner['id'], size, storage_path, meta_json, now)
            )
            conn.commit()
            return dict(id=cur.lastrowid, name=name, owner_id=owner['id'], created_at=now)
        return self._execute_with_retry(_do_add)

    def get_file_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        self._init_connection()
        cur = self._conn.cursor()
        cur.execute("SELECT f.*, u.username as owner FROM files f JOIN users u ON f.owner_id = u.id WHERE f.name = ?", (name,))
        row = cur.fetchone()
        return dict(row) if row else None

    def grant_permission(self, file_name: str, grantee_username: str, permission: str, granted_by_username: Optional[str] = None) -> Dict[str, Any]:
        def _do_grant(conn):
            if permission not in ('READ', 'WRITE', 'OWNER'):
                raise ValueError('Invalid permission')
            file = self.get_file_by_name(file_name)
            if not file:
                raise ValueError('File not found')
            grantee = self.get_user(grantee_username)
            if not grantee:
                raise ValueError('Grantee user not found')
            granter = self.get_user(granted_by_username) if granted_by_username else None
            granted_by = granter['id'] if granter else None
            now = int(time.time())
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO permissions (file_id, grantee_user_id, permission, granted_by, granted_at) VALUES (?, ?, ?, ?, ?)",
                (file['id'], grantee['id'], permission, granted_by, now)
            )
            conn.commit()
            return dict(id=cur.lastrowid, file_id=file['id'], grantee_user_id=grantee['id'], permission=permission, granted_at=now)
        return self._execute_with_retry(_do_grant)

    def check_permission(self, username: str, file_name: str, required: str) -> Dict[str, Any]:
        # required is one of READ/WRITE/OWNER
        self._init_connection()
        file = self.get_file_by_name(file_name)
        if not file:
            return {'success': False, 'authorized': False, 'message': 'file not found'}
        user = self.get_user(username)
        if not user:
            return {'success': False, 'authorized': False, 'message': 'user not found'}
        # Owner has all permissions
        if file['owner_id'] == user['id']:
            return {'success': True, 'authorized': True, 'message': 'owner'}
        cur = self._conn.cursor()
        cur.execute(
            "SELECT permission FROM permissions WHERE file_id = ? AND grantee_user_id = ? ORDER BY id DESC",
            (file['id'], user['id'])
        )
        row = cur.fetchone()
        if not row:
            return {'success': True, 'authorized': False, 'message': 'no permission'}
        perm = row['permission']
        if required == 'READ' and perm in ('READ', 'WRITE', 'OWNER'):
            return {'success': True, 'authorized': True, 'message': perm}
        if required == 'WRITE' and perm in ('WRITE', 'OWNER'):
            return {'success': True, 'authorized': True, 'message': perm}
        return {'success': True, 'authorized': False, 'message': perm}

    def get_user_files(self, username: str) -> List[Dict[str, Any]]:
        """Return files owned by or readable by username. Each entry has name, owner, permission.
        - If owner => permission OWNER
        - If permission exists => use that permission (map to READ or WRITE shown)
        """
        self._init_connection()
        user = self.get_user(username)
        if not user:
            return []
        cur = self._conn.cursor()
        # Files owned by user
        cur.execute(
            "SELECT f.id, f.name, u.username as owner, 'OWNER' as permission FROM files f JOIN users u ON f.owner_id = u.id WHERE f.owner_id = ?",
            (user['id'],)
        )
        rows = [dict(r) for r in cur.fetchall()]
        # Files where user has explicit permission (READ or WRITE/OWNER) - exclude ones already included
        cur.execute(
            "SELECT f.id, f.name, ou.username as owner, p.permission FROM permissions p JOIN files f ON p.file_id = f.id JOIN users ou ON f.owner_id = ou.id WHERE p.grantee_user_id = ?",
            (user['id'],)
        )
        for r in cur.fetchall():
            rec = dict(r)
            # If already added as owner, skip
            if any(x['id'] == rec['id'] for x in rows):
                continue
            # Normalize to READ-only label for listing
            if rec['permission'] == 'WRITE' or rec['permission'] == 'OWNER':
                perm_label = 'WRITE'
            else:
                perm_label = 'READ'
            rows.append({'id': rec['id'], 'name': rec['name'], 'owner': rec['owner'], 'permission': perm_label})
        return rows

    def list_files(self, owner: Optional[str] = None, readable_by: Optional[str] = None) -> List[Dict[str, Any]]:
        self._init_connection()
        cur = self._conn.cursor()
        clauses = []
        params = []
        if owner:
            clauses.append("f.owner_id = (SELECT id FROM users WHERE username = ?)")
            params.append(owner)
        if readable_by:
            # any file that user owns or has READ permission
            clauses.append("(f.owner_id = (SELECT id FROM users WHERE username = ?) OR f.id IN (SELECT file_id FROM permissions WHERE grantee_user_id = (SELECT id FROM users WHERE username = ?) AND permission IN ('READ', 'WRITE', 'OWNER'))) ")
            params.extend([readable_by, readable_by])
        if not clauses:
            cur.execute("SELECT f.id, f.name, u.username as owner FROM files f JOIN users u ON f.owner_id = u.id")
        else:
            query = "SELECT f.id, f.name, u.username as owner FROM files f JOIN users u ON f.owner_id = u.id WHERE " + " AND ".join(clauses)
            cur.execute(query, params)
        return [dict(r) for r in cur.fetchall()]

    def list_users(self) -> List[Dict[str, Any]]:
        """Return all users (username, password_hash, salt, created_at)"""
        self._init_connection()
        cur = self._conn.cursor()
        cur.execute("SELECT username, password_hash, salt, created_at FROM users")
        return [dict(r) for r in cur.fetchall()]

    def update_user_password(self, username: str, password_hash: str, salt: Optional[str] = None) -> bool:
        """Update password_hash (and optional salt) for an existing user.
        Raises ValueError if user does not exist.
        """
        self._init_connection()
        cur = self._conn.cursor()
        cur.execute("UPDATE users SET password_hash = ?, salt = ? WHERE username = ?", (password_hash, salt, username))
        if cur.rowcount == 0:
            raise ValueError(f"User not found: {username}")
        self._conn.commit()
        return True

    def list_permissions(self) -> List[Dict[str, Any]]:
        """Return all explicit permissions with file name, grantee, permission, granted_by and timestamp"""
        self._init_connection()
        cur = self._conn.cursor()
        cur.execute(
            "SELECT f.name as file_name, u.username as grantee, p.permission, gu.username as granted_by, p.granted_at "
            "FROM permissions p JOIN files f ON p.file_id = f.id JOIN users u ON p.grantee_user_id = u.id LEFT JOIN users gu ON p.granted_by = gu.id ORDER BY f.name"
        )
        return [dict(r) for r in cur.fetchall()]

    # Storage node helpers
    def register_storage_node(self, node_name: str, host: Optional[str] = None, port: Optional[int] = None, raid_mode: Optional[str] = None) -> Dict[str, Any]:
        """Register or update a storage node record and return it"""
        self._init_connection()
        cur = self._conn.cursor()
        # Check if node exists
        cur.execute("SELECT id FROM storage_nodes WHERE node_name = ?", (node_name,))
        existing = cur.fetchone()
        if existing:
            # Update existing node with new host/port if provided
            if host is not None and port is not None:
                cur.execute(
                    "UPDATE storage_nodes SET host = ?, port = ?, raid_mode = COALESCE(?, raid_mode), active = 1 WHERE node_name = ?",
                    (host, port, raid_mode, node_name)
                )
        else:
            # Insert new node
            cur.execute(
                "INSERT INTO storage_nodes (node_name, host, port, raid_mode, active) VALUES (?, ?, ?, ?, 1)",
                (node_name, host, port, raid_mode)
            )
        self._conn.commit()
        cur.execute("SELECT * FROM storage_nodes WHERE node_name = ?", (node_name,))
        row = cur.fetchone()
        return dict(row) if row else None

    def get_storage_node_by_name(self, node_name: str) -> Optional[Dict[str, Any]]:
        self._init_connection()
        cur = self._conn.cursor()
        cur.execute("SELECT * FROM storage_nodes WHERE node_name = ?", (node_name,))
        row = cur.fetchone()
        return dict(row) if row else None

    def list_storage_nodes(self) -> List[Dict[str, Any]]:
        """Return all registered storage nodes"""
        self._init_connection()
        cur = self._conn.cursor()
        cur.execute("SELECT node_name, host, port, raid_mode, active FROM storage_nodes")
        return [dict(r) for r in cur.fetchall()]

    def add_file_location(self, file_name: str, node_name: str, stored_path: Optional[str] = None, host: Optional[str] = None, port: Optional[int] = None) -> Dict[str, Any]:
        """Record that a storage node holds a file. If the file does not exist, create with owner 'system'."""
        print(f"[DB] add_file_location called: file={file_name}, node={node_name}, host={host}, port={port}")
        self._init_connection()
        file = self.get_file_by_name(file_name)
        if not file:
            # create a system owner if necessary
            try:
                system_user = self.get_user('system')
                if not system_user:
                    # create system user with empty password hash
                    self.create_user('system', '')
            except Exception:
                pass
            # create file with system owner
            try:
                self.add_file(file_name, 'system', size=0, storage_path=stored_path)
                file = self.get_file_by_name(file_name)
            except Exception as e:
                raise
        node = self.get_storage_node_by_name(node_name)
        if not node:
            node = self.register_storage_node(node_name, host=host, port=port)
        elif host and port:
            # Update existing node with host/port if provided
            node = self.register_storage_node(node_name, host=host, port=port)
        now = int(time.time())
        cur = self._conn.cursor()
        print(f"[DB] Inserting file_location: file_id={file['id']}, node_id={node['id']}, stored_path={stored_path}")
        cur.execute(
            "INSERT INTO file_locations (file_id, storage_node_id, stored_path, last_seen) VALUES (?, ?, ?, ?)",
            (file['id'], node['id'], stored_path, now)
        )
        self._conn.commit()
        print(f"[DB] file_location inserted successfully, last_rowid={cur.lastrowid}")
        return {'success': True, 'file_id': file['id'], 'storage_node_id': node['id'], 'stored_path': stored_path}

    def get_file_locations(self, file_name: str) -> List[Dict[str, Any]]:
        """Return a list of storage nodes and stored_path entries for a file"""
        self._init_connection()
        file = self.get_file_by_name(file_name)
        if not file:
            return []
        cur = self._conn.cursor()
        cur.execute(
            "SELECT ln.node_name, ln.host, ln.port, fl.stored_path, fl.last_seen FROM file_locations fl JOIN storage_nodes ln ON fl.storage_node_id = ln.id WHERE fl.file_id = ?",
            (file['id'],)
        )
        return [dict(r) for r in cur.fetchall()]

    def revoke_permission(self, file_name: str, grantee_username: str) -> Dict[str, Any]:
        """Revoke a grantee's permission on a file. Returns dict with success and affected count."""
        def _do_revoke(conn):
            file = self.get_file_by_name(file_name)
            if not file:
                raise ValueError('File not found')
            grantee = self.get_user(grantee_username)
            if not grantee:
                raise ValueError('Grantee user not found')
            cur = conn.cursor()
            cur.execute(
                "DELETE FROM permissions WHERE file_id = ? AND grantee_user_id = ?",
                (file['id'], grantee['id'])
            )
            affected = cur.rowcount
            conn.commit()
            return {'success': True, 'affected': affected}
        return self._execute_with_retry(_do_revoke)

    def delete_file(self, file_name: str) -> Dict[str, Any]:
        """Delete a file and all its permissions/locations from the database.
        Useful for cleanup when storage reports file not found.
        Returns dict with success and affected count.
        """
        def _do_delete(conn):
            file = self.get_file_by_name(file_name)
            if not file:
                return {'success': True, 'affected': 0, 'message': 'File not found in DB'}
            
            cur = conn.cursor()
            # Delete all permissions first (foreign key)
            cur.execute("DELETE FROM permissions WHERE file_id = ?", (file['id'],))
            perm_affected = cur.rowcount
            # Delete all file locations (foreign key)
            cur.execute("DELETE FROM file_locations WHERE file_id = ?", (file['id'],))
            loc_affected = cur.rowcount
            # Delete the file
            cur.execute("DELETE FROM files WHERE id = ?", (file['id'],))
            file_affected = cur.rowcount
            conn.commit()
            return {'success': True, 'affected': file_affected + perm_affected + loc_affected, 'message': f'Deleted file, {perm_affected} permissions, {loc_affected} locations'}
        return self._execute_with_retry(_do_delete)

    def set_file_metadata(self, file_name: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Set/merge metadata JSON for a file."""
        self._init_connection()
        file = self.get_file_by_name(file_name)
        if not file:
            raise ValueError('File not found')
        cur = self._conn.cursor()
        cur.execute("SELECT metadata FROM files WHERE id = ?", (file['id'],))
        row = cur.fetchone()
        existing = json.loads(row['metadata']) if row and row['metadata'] else {}
        existing.update(metadata)
        meta_json = json.dumps(existing)
        cur.execute("UPDATE files SET metadata = ? WHERE id = ?", (meta_json, file['id']))
        self._conn.commit()
        return {'success': True, 'metadata': existing}

    def get_file_metadata(self, file_name: str) -> Optional[Dict[str, Any]]:
        self._init_connection()
        file = self.get_file_by_name(file_name)
        if not file:
            return None
        cur = self._conn.cursor()
        cur.execute("SELECT metadata FROM files WHERE id = ?", (file['id'],))
        row = cur.fetchone()
        return json.loads(row['metadata']) if row and row['metadata'] else {}

# Module helpers
_default_db: Optional[Database] = None

def get_db(db_path: Optional[str] = None) -> Database:
    global _default_db
    if _default_db is None:
        _default_db = Database(db_path or DEFAULT_DB_PATH)
    return _default_db


def create_db_for_path(path: str) -> Database:
    """Utility: create and init a DB for a given path (used in tests/scripts)"""
    db = Database(path)
    db.init_schema()
    return db

if __name__ == "__main__":
    # quick smoke test
    import tempfile
    import os
    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.close()
    path = tmp.name
    print("Creating DB at", path)
    db = Database(path)
    db.init_schema()
    db.create_user('alice','hash')
    db.create_user('bob','hash2')
    db.add_file('/files/alice.txt','alice')
    db.grant_permission('/files/alice.txt','bob','READ','alice')
    print('alice files:', db.get_user_files('alice'))
    print('bob files:', db.get_user_files('bob'))
    db.close()
    os.unlink(path)
