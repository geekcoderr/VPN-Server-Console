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
                sa_dict = dict(sa)
                print(f"Migrating admin: {sa_dict['username']}")
                admin = Admin(
                    id=sa_dict['id'],
                    username=sa_dict['username'],
                    password_hash=sa_dict['password_hash']
                )
                await mysession.merge(admin)
            
            # Migrate Users
            cursor = await sldb.execute("SELECT * FROM users")
            sqlite_users = await cursor.fetchall()
            
            for su in sqlite_users:
                su_dict = dict(su)
                print(f"Migrating user: {su_dict['username']}")
                # Handle possible missing columns or different formats
                user = User(
                    username=su_dict['username'],
                    public_key=su_dict['public_key'],
                    assigned_ip=su_dict['assigned_ip'],
                    client_os=su_dict.get('client_os', 'android'),
                    status=su_dict.get('status', 'active'),
                    created_at=datetime.fromisoformat(su_dict['created_at']) if isinstance(su_dict['created_at'], str) else datetime.now()
                )
                mysession.add(user)
            
            await mysession.commit()
            print("Migration completed successfully!")

if __name__ == "__main__":
    asyncio.run(migrate())
