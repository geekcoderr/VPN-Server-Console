from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, Integer, DateTime, Text, BigInteger, func, Boolean
from datetime import datetime
from typing import Optional
import os

from .config import DB_HOST, DB_PORT, DB_USER, DB_PASS, DB_NAME

# MySQL Async URL
DATABASE_URL = f"mysql+aiomysql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

engine = create_async_engine(DATABASE_URL, echo=False, pool_pre_ping=True)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

class Base(DeclarativeBase):
    pass

class Admin(Base):
    __tablename__ = "admin"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    totp_secret: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    public_key: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    private_key: Mapped[Optional[str]] = mapped_column(Text, nullable=True) # Stored for viewing (as requested)
    assigned_ip: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    client_os: Mapped[str] = mapped_column(String(50), default="android")
    status: Mapped[str] = mapped_column(String(20), default="active")
    
    # Advanced Tracking
    total_rx: Mapped[int] = mapped_column(BigInteger, default=0)
    total_tx: Mapped[int] = mapped_column(BigInteger, default=0)
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_endpoint: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    
    # Access Control
    acl_profile: Mapped[str] = mapped_column(String(50), default="full") # full, internet-only, lan-only

class Session(Base):
    __tablename__ = "vpn_sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False)  # Foreign Key logic handled in code
    public_key: Mapped[str] = mapped_column(String(255), nullable=False)
    start_time: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    end_time: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    bytes_rx: Mapped[int] = mapped_column(BigInteger, default=0)
    bytes_tx: Mapped[int] = mapped_column(BigInteger, default=0)
    is_active: Mapped[bool] = mapped_column(Integer, default=1) # 1=Active, 0=Closed

class UserInvite(Base):
    __tablename__ = "user_invites"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    token: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    otp: Mapped[Optional[str]] = mapped_column(String(6), nullable=True)
    otp_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())

from sqlalchemy import text

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        
        # Migrations
        try:
            # 1. last_endpoint
            result = await conn.execute(text("SHOW COLUMNS FROM users LIKE 'last_endpoint'"))
            if not result.fetchone():
                print("Migration: Adding 'last_endpoint' column...")
                await conn.execute(text("ALTER TABLE users ADD COLUMN last_endpoint VARCHAR(255) NULL"))
            
            # 2. private_key
            result = await conn.execute(text("SHOW COLUMNS FROM users LIKE 'private_key'"))
            if not result.fetchone():
                print("Migration: Adding 'private_key' column...")
                await conn.execute(text("ALTER TABLE users ADD COLUMN private_key TEXT NULL"))
                
            # 3. acl_profile
            result = await conn.execute(text("SHOW COLUMNS FROM users LIKE 'acl_profile'"))
            if not result.fetchone():
                print("Migration: Adding 'acl_profile' column...")
                await conn.execute(text("ALTER TABLE users ADD COLUMN acl_profile VARCHAR(50) DEFAULT 'full'"))
            
        except Exception as e:
            print(f"Migration error: {e}")

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

from sqlalchemy import select, update, delete

async def get_admin():
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(Admin).filter(Admin.id == 1))
        admin = result.scalar_one_or_none()
        return {
            "id": admin.id, 
            "username": admin.username, 
            "password_hash": admin.password_hash,
            "totp_secret": admin.totp_secret
        } if admin else None

async def create_admin(username: str, password_hash: str):
    async with AsyncSessionLocal() as session:
        admin = Admin(id=1, username=username, password_hash=password_hash)
        await session.merge(admin)
        await session.commit()

async def get_all_users():
    """Unified: Get all user ORM objects."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).order_by(User.created_at.desc()))
        return result.scalars().all()

async def get_user_by_username(username: str):
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).filter(User.username == username))
        return result.scalar_one_or_none()

async def get_user_by_ip(ip: str):
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).filter(User.assigned_ip == ip))
        return result.scalar_one_or_none()

async def create_user(username: str, public_key: str, private_key: str, assigned_ip: str, client_os: str = 'android', acl_profile: str = 'full'):
    async with AsyncSessionLocal() as session:
        user = User(
            username=username, 
            public_key=public_key, 
            private_key=private_key, 
            assigned_ip=assigned_ip, 
            client_os=client_os,
            acl_profile=acl_profile
        )
        session.add(user)
        await session.commit()

async def update_user_status(username: str, status: str):
    async with AsyncSessionLocal() as session:
        await session.execute(update(User).where(User.username == username).values(status=status))
        await session.commit()

async def delete_user(username: str):
    async with AsyncSessionLocal() as session:
        await session.execute(delete(User).where(User.username == username))
        await session.commit()

async def get_used_ips():
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User.assigned_ip))
        return {row[0] for row in result.all()}

async def db_health_check() -> bool:
    """Verify DB connectivity with retries."""
    import asyncio
    for i in range(5):
        try:
            async with AsyncSessionLocal() as session:
                await session.execute(text("SELECT 1"))
                return True
        except Exception as e:
            print(f"📡 Waiting for MySQL... (Attempt {i+1}/5): {e}")
            await asyncio.sleep(2)
    return False
