import sqlite3
import redis
import ipaddress
import jwt
import pyotp
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Any
import logging

# Logger
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

# JWT Configuration
JWT_SECRET = "supersecretkey" # Move to env variable
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

def get_domain(email: str) -> str:
    return email.split('@')[1].lower()


def is_client_ip_restricted(client_ip: str, restricted_ips_str: str) -> bool:
    try:
        # Handle potential comma-separated list
        blocked_ips = [ip.strip() for ip in restricted_ips_str.split(',') if ip.strip()]
        
        client_addr = ipaddress.ip_address(client_ip)
        
        for blocked_ip in blocked_ips:
            try:
                # Check if it's a network
                if ipaddress.ip_network(blocked_ip, strict=False).supernet_of(ipaddress.ip_network(f"{client_ip}/32")):
                     return True
                # Or exact match
                if client_addr == ipaddress.ip_address(blocked_ip):
                     return True
            except ValueError:
                # Try as simple address match if network parsing fails
                if client_ip == blocked_ip:
                    return True
        return False

    except ValueError:
        # If client IP is invalid, return True (restricted/unsafe)
        return True


def create_tokens(identifier: str) -> Dict[str, str]:
    access_payload = {
        "sub": identifier,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        "type": "access"
    }
    refresh_payload = {
        "sub": identifier,
        "exp": datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        "type": "refresh"
    }
    
    return {
        "access_token": jwt.encode(access_payload, JWT_SECRET, algorithm=JWT_ALGORITHM),
        "refresh_token": jwt.encode(refresh_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    }


def get_organization_by_domain(domain: str):
    r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
    try:
        key = f"organization:{domain}"
        if r.exists(key):
            return r.hgetall(key)
        return None
    finally:
        r.close()


def verify_user_credentials(identifier: str, secret: str) -> bool:
    try:
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('SELECT secret FROM users WHERE identifier = ?', (identifier,))
        result = cursor.fetchone()
        conn.close()
        
        if result and result[0] == secret:
            return True
        return False
    except Exception as e:
        logger.error(f"Database error during user verification: {e}")
        return False


def get_user_mfa_secret(identifier: str) -> Optional[str]:
    try:
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('SELECT mfa_secret FROM users WHERE identifier = ?', (identifier,))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None
    except Exception as e:
        logger.error(f"Database error getting MFA secret: {e}")
        return None
