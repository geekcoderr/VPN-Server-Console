import asyncio
import sys
import bcrypt
import aiosqlite
import argparse
from pathlib import Path

# Calculate DB path relative to this script
PROJECT_ROOT = Path(__file__).parent
DB_PATH = PROJECT_ROOT / "data" / "users.db"

async def reset_password(username, new_password):
    password_bytes = new_password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt).decode('utf-8')
    
    print(f"Connecting to database at {DB_PATH}...")
    async with aiosqlite.connect(DB_PATH) as db:
        # Update if exists, otherwise it will just complete
        await db.execute(
            "UPDATE admin SET username = ?, password_hash = ? WHERE id = 1", 
            (username, hashed)
        )
        await db.commit()
    print(f"Credentials for '{username}' updated successfully!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Reset VPN Admin Credentials")
    parser.add_argument("--username", required=True, help="New admin username")
    parser.add_argument("--password", required=True, help="New admin password")
    
    args = parser.parse_args()
    asyncio.run(reset_password(args.username, args.password))
