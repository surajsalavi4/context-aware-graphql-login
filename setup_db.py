import sqlite3
import redis
import os

def setup_database():
    print("Setting up SQLite Database...")
    if os.path.exists('data.db'):
        os.remove('data.db')
        print("Removed existing data.db")

    conn = sqlite3.connect('data.db')
    cursor = conn.cursor()

    # Create tables
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS organizations (
            id TEXT PRIMARY KEY,
            domain TEXT,
            name TEXT,
            login_policy TEXT,
            restricted_ips TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            identifier TEXT PRIMARY KEY,
            secret TEXT,
            mfa_secret TEXT
        )
    ''')
    
    # Mock Organizations
    org_data = [
        ('1', 'normal.com', 'Normal Org', None, None),
        ('2', 'mfa.com', 'MFA Org', 'MFA', None),
        ('3', 'blocked.com', 'Blocked Org', 'IP_RESTRICTED', '10.0.0.0/8'), # 127.0.0.1 is safe, 10.0.0.5 blocked
        ('4', 'mfa-missing.com', 'MFA Missing Org', 'MFA', None),
    ]
    cursor.executemany(
        'INSERT INTO organizations (id, domain, name, login_policy, restricted_ips) VALUES (?, ?, ?, ?, ?)',
        org_data
    )

    # Mock Users
    user_data = [
        ('user@normal.com', 'password123', None),
        ('user@mfa.com', 'password123', 'JBSWY3DPEHPK3PXP'), # Valid Base32 Secret
        ('user@mfa-missing.com', 'password123', None), # No secret set
        ('user@blocked.com', 'password123', None),
    ]
    cursor.executemany(
        'INSERT INTO users (identifier, secret, mfa_secret) VALUES (?, ?, ?)',
        user_data
    )
    
    conn.commit()
    conn.close()
    print("SQLite Database Setup Complete.")

    print("Setting up Redis Data...")
    try:
        r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
        r.flushdb() # Clear existing keys
        
        # Re-populate Redis from SQLite logic (simplifying here by manually setting)
        for org in org_data:
            org_id, domain, name, policy, ips = org
            key = f"organization:{domain}"
            mapping = {
                "id": str(org_id),
                "name": str(name),
                "login_policy": str(policy) if policy else "",
                "restricted_ips": str(ips) if ips else ""
            }
            r.hset(key, mapping=mapping)
        
        r.close()
        print("Redis Data Setup Complete.")
    except redis.exceptions.ConnectionError:
        print("Warning: Redis is not accessible. Skipping Redis setup.")
    except Exception as e:
        print(f"Warning: Failed to setup Redis: {e}")

if __name__ == "__main__":
    setup_database()
