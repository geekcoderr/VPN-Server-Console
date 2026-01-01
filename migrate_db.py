import asyncio
import aiosqlite
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import init_db, AsyncSessionLocal, User, Admin, engine
from pathlib import Path
from datetime import datetime

SQLITE_DB = Path("data/users.db")

async def migrate():
    if not SQLITE_DB.exists():
        print(f"Error: SQLite database {SQLITE_DB} not found.")
        return

    print("Initializing MySQL schema...")
    await init_db()

    print(f"Reading from {SQLITE_DB}...")
    async with aiosqlite.connect(SQLITE_DB) as sldb:
        sldb.row_factory = aiosqlite.Row
        
        # Migrate Admins
        cursor = await sldb.execute("SELECT * FROM admin")
        sqlite_admins = await cursor.fetchall()
        
        async with AsyncSessionLocal() as mysession:
            for sa in sqlite_admins:
                print(f"Migrating admin: {sa['username']}")
                admin = Admin(
                    id=sa['id'],
                    username=sa['username'],
                    password_hash=sa['password_hash']
                )
                await mysession.merge(admin)
            
            # Migrate Users
            cursor = await sldb.execute("SELECT * FROM users")
            sqlite_users = await cursor.fetchall()
            
            for su in sqlite_users:
                print(f"Migrating user: {su['username']}")
                # Handle possible missing columns or different formats
                user = User(
                    username=su['username'],
                    public_key=su['public_key'],
                    assigned_ip=su['assigned_ip'],
                    client_os=su.get('client_os', 'android'),
                    status=su.get('status', 'active'),
                    created_at=datetime.fromisoformat(su['created_at']) if isinstance(su['created_at'], str) else datetime.now()
                )
                mysession.add(user)
            
            await mysession.commit()
            print("Migration completed successfully!")

if __name__ == "__main__":
    asyncio.run(migrate())
