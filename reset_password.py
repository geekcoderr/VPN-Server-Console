
import asyncio
import sys
import bcrypt
import aiosqlite
from app.config import DATABASE_URL

async def reset_password(new_password):
    # Hash password directly with bcrypt
    password_bytes = new_password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt).decode('utf-8')
    
    print(f"Connecting to database...")
    async with aiosqlite.connect(DATABASE_URL) as db:
        await db.execute("UPDATE admin SET password_hash = ? WHERE username = 'geek'", (hashed,))
        await db.commit()
    print(f"Password for 'geek' updated successfully!")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python reset_password.py <new_password>")
        sys.exit(1)
        
    new_pass = sys.argv[1]
    asyncio.run(reset_password(new_pass))
