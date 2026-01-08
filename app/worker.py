import asyncio
import redis.asyncio as redis
import json
from datetime import datetime
from .config import REDIS_HOST, REDIS_PORT, REDIS_DB, SMTP_USER
from .database import get_user_by_ip
from .email import send_email

async def alert_worker():
    print("🚨 Alert Worker Started...")
    try:
        r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB)
        await r.ping()
        print("✅ Connected to Redis.")
    except Exception as e:
        print(f"❌ Redis Connection Failed: {e}")
        return

    while True:
        try:
            # Blocking pop from queue
            # blpop returns a tuple (key, value)
            item = await r.blpop("alert_queue", timeout=5)
            if item:
                _, data_bytes = item
                data = json.loads(data_bytes)
                
                # Data: { "ip": "...", "domain": "...", "timestamp": ... }
                user_ip = data.get("ip")
                domain = data.get("domain")
                
                # Resolve User
                user = await get_user_by_ip(user_ip)
                username = user.username if user else "Unknown"
                
                print(f"⚠️  ALERT: User {username} ({user_ip}) visited {domain} at {datetime.now()}")
                
                # Send Email Alert
                subject = f"🚨 Security Alert: {username} visited {domain}"
                body = f"User: {username}\nIP: {user_ip}\nDomain: {domain}\nTime: {datetime.now()}\n\nThis is an automated security alert."
                send_email(SMTP_USER, subject, body)
                
        except Exception as e:
            print(f"Worker Error: {e}")
            await asyncio.sleep(5)

if __name__ == "__main__":
    asyncio.run(alert_worker())
