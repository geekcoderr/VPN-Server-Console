import asyncio
import sys
import bcrypt
import argparse
from app.database import create_admin, init_db

async def reset_password(username, new_password):
    # Ensure tables exist
    await init_db()
    
    password_bytes = new_password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt).decode('utf-8')
    
    print(f"Updating credentials for '{username}' in MySQL...")
    await create_admin(username, hashed)
    print(f"Credentials for '{username}' updated successfully!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Reset VPN Admin Credentials")
    parser.add_argument("--username", required=True, help="New admin username")
    parser.add_argument("--password", required=True, help="New admin password")
    
    args = parser.parse_args()
    asyncio.run(reset_password(args.username, args.password))
