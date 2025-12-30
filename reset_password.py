
import asyncio
import sys
from passlib.context import CryptContext
from app.database import init_db, get_db

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

async def reset_password(new_password):
    hashed = pwd_context.hash(new_password)
    
    await init_db()
    async with await get_db() as db:
        await db.execute("UPDATE admin SET password_hash = ? WHERE username = 'geek'", (hashed,))
        await db.commit()
    print(f"Password for 'geek' updated successfully!")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python reset_password.py <new_password>")
        sys.exit(1)
        
    new_pass = sys.argv[1]
    asyncio.run(reset_password(new_pass))
