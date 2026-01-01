"""
Database module for VPN Control Plane.
Uses SQLite with async support via aiosqlite.
"""
import aiosqlite
import os
from datetime import datetime
from pathlib import Path

# Database path - relative to project root
DB_PATH = Path(__file__).parent.parent / "data" / "users.db"


async def init_db():
    """Initialize database with required tables."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    async with aiosqlite.connect(DB_PATH) as db:
        # Users table - stores VPN user metadata
        await db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                public_key TEXT UNIQUE NOT NULL,
                assigned_ip TEXT UNIQUE NOT NULL,
                client_os TEXT DEFAULT 'android' CHECK(client_os IN ('android', 'linux', 'ios', 'windows', 'macos')),
                status TEXT DEFAULT 'active' CHECK(status IN ('active', 'disabled')),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Admin table - single admin user
        await db.execute("""
            CREATE TABLE IF NOT EXISTS admin (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)
        
        await db.commit()


async def get_db():
    """Get database connection."""
    return await aiosqlite.connect(DB_PATH)


async def get_all_users():
    """Fetch all VPN users."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT id, username, public_key, assigned_ip, client_os, status, created_at FROM users ORDER BY created_at DESC"
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


async def get_user_by_username(username: str):
    """Fetch a single user by username."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None


async def create_user(username: str, public_key: str, assigned_ip: str, client_os: str = 'android'):
    """Insert a new VPN user."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO users (username, public_key, assigned_ip, client_os) VALUES (?, ?, ?, ?)",
            (username, public_key, assigned_ip, client_os)
        )
        await db.commit()


async def update_user_status(username: str, status: str):
    """Update user status (active/disabled)."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE users SET status = ? WHERE username = ?",
            (status, username)
        )
        await db.commit()


async def delete_user(username: str):
    """Delete a user from database."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM users WHERE username = ?", (username,))
        await db.commit()


async def get_used_ips():
    """Get all assigned IP addresses."""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("SELECT assigned_ip FROM users")
        rows = await cursor.fetchall()
        return {row[0] for row in rows}


async def get_admin():
    """Get admin user."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM admin WHERE id = 1")
        row = await cursor.fetchone()
        return dict(row) if row else None


async def create_admin(username: str, password_hash: str):
    """Create or update admin user."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT INTO admin (id, username, password_hash) VALUES (1, ?, ?)
               ON CONFLICT(id) DO UPDATE SET username = ?, password_hash = ?""",
            (username, password_hash, username, password_hash)
        )
        await db.commit()
