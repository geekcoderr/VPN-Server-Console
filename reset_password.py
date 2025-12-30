
import asyncio
import sys
import bcrypt
import aiosqlite
from pathlib import Path

# Calculate DB path relative to this script
PROJECT_ROOT = Path(__file__).parent
DB_PATH = PROJECT_ROOT / "data" / "users.db"

async def reset_password(new_password):
    # Hash password directly with bcrypt
    password_bytes = new_password.lower().encode('utf-8')  # Ensure consistency if needed, though password usually case-sensitive
    # Actually, don't lower case password, keep it as is.
    password_bytes = new_password.encode('utf-8')
    
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt).decode('utf-8')
    
    print(f"Connecting to database at {DB_PATH}...")
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("UPDATE admin SET password_hash = ? WHERE username = 'geek'", (hashed,))
        await db.commit()
    print(f"Password for 'geek' updated successfully!")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python reset_password.py <new_password>")
        sys.exit(1)
        
    new_pass = sys.argv[1]
    asyncio.run(reset_password(new_pass))
