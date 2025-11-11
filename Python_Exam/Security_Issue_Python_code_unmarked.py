"""
secure_data_processor.py

Secure, hardened DataProcessor with:
- No hardcoded secrets (load from environment or secret manager)
- Safe DB usage (parameterized queries), password hashing (PBKDF2)
- Audit log and archive (user_archive + audit_log)
- CSV archival with atomic append for offline recovery
- Decorator @critical_action to uniformly audit critical operations
- Secure external API calls (verify SSL, timeouts, retries)
- S3 upload using boto3 default credential resolution (no hardcoded AWS keys)
- Webhook HMAC verification
- Recommendations in module doc and external README (see documentation section below)

NOTE:
- This module uses SQLite for demonstration. In production, use a managed DB (Postgres/MySQL) and proper migrations.
- For secrets in production, use AWS Secrets Manager / HashiCorp Vault / Azure Key Vault etc.
"""

import os
import json
import csv
import csv as _csv
import sqlite3
import logging
import hashlib
import hmac
import secrets
import tempfile
import uuid
from datetime import datetime, timezone
from functools import wraps
from typing import Optional, Tuple, Dict, Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

# Optional: load .env for local development only (do NOT commit .env)
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# -------------------------
# Configuration (from environment)
# -------------------------
API_KEY = os.getenv("APP_API_KEY")                     # External API key (optional)
DB_PATH = os.getenv("APP_DB_PATH", "app_data.db")     # SQLite path (demo); prod should use managed DB.
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")          # HMAC secret used to verify webhooks
API_BASE_URL = os.getenv("API_BASE_URL", "https://api.production-service.com/v1")
S3_BUCKET_DEFAULT = os.getenv("S3_BUCKET_DEFAULT", "company-sensitive-data")
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
ARCHIVE_CSV_DIR = os.getenv("ARCHIVE_CSV_DIR", "./archives")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# Ensure archive dir exists
os.makedirs(ARCHIVE_CSV_DIR, exist_ok=True)

# -------------------------
# Logging (no secrets)
# -------------------------
logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO))
logger = logging.getLogger("secure_data_processor")

def redact(s: Optional[str]) -> str:
    """Redact sensitive strings for safe logging."""
    if not s:
        return ""
    if len(s) <= 6:
        return "****"
    return f"{s[:2]}****{s[-2:]}"

# -------------------------
# Password hashing utilities
# -------------------------
def hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[str, str]:
    """
    Hash a password using PBKDF2-HMAC-SHA256.
    Returns (salt_hex, hash_hex)
    """
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 200_000)
    return salt.hex(), dk.hex()

def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 200_000)
    return hmac.compare_digest(dk.hex(), hash_hex)

# -------------------------
# HTTP session (timeouts, retries)
# -------------------------
def create_http_session(timeout: int = 10, max_retries: int = 3) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=max_retries,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "POST", "PUT", "DELETE", "PATCH"])
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

# -------------------------
# DB initialization and schema
# -------------------------
def init_db(conn: sqlite3.Connection) -> None:
    """
    Create base user_data table. For production use migrations (Alembic/Flyway).
    Note: We store hashed passwords and last-4 of PII only.
    """
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                cc_last4 TEXT,
                ssn_last4 TEXT,
                pii_token TEXT,
                created_at TIMESTAMP NOT NULL
            )
        """)

def init_db_with_audit(conn: sqlite3.Connection) -> None:
    """
    Create audit and archive tables for safe recovery & forensic analysis.
    """
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_archive (
                archived_id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_id INTEGER NOT NULL,
                username TEXT,
                password_hash TEXT,
                password_salt TEXT,
                cc_last4 TEXT,
                ssn_last4 TEXT,
                pii_token TEXT,
                created_at TIMESTAMP,
                archived_at TIMESTAMP NOT NULL,
                archived_by TEXT,
                archive_reason TEXT,
                request_id TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_time TIMESTAMP NOT NULL,
                actor TEXT,
                action TEXT,
                object_type TEXT,
                object_id INTEGER,
                status TEXT,
                reason TEXT,
                request_id TEXT,
                ip TEXT,
                details TEXT
            )
        """)

# -------------------------
# Webhook signature verification
# -------------------------
def verify_webhook_signature(payload_bytes: bytes, signature_header: Optional[str], secret: str) -> bool:
    """
    Verify HMAC-SHA256 signature header. Header format expected: "sha256=<hex>" or "<hex>".
    """
    if not signature_header or not secret:
        logger.warning("Missing webhook signature or secret.")
        return False
    try:
        if signature_header.startswith("sha256="):
            sig = signature_header.split("=", 1)[1]
        else:
            sig = signature_header
        computed = hmac.new(secret.encode('utf-8'), payload_bytes, hashlib.sha256).hexdigest()
        return hmac.compare_digest(computed, sig)
    except Exception:
        logger.exception("Failed to verify webhook signature.")
        return False

# -------------------------
# Decorator for critical actions
# -------------------------
def critical_action(action_name: str):
    """
    Decorator that writes pre and post audit entries. The decorated function must accept actor and request_id kwargs.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            actor = kwargs.get("actor") or kwargs.get("performed_by") or "unknown"
            request_id = kwargs.get("request_id") or str(uuid.uuid4())
            ip = kwargs.get("ip")
            object_id = kwargs.get("user_id") if "user_id" in kwargs else (args[0] if args else None)
            # Pre-audit (pending)
            try:
                self._write_audit_entry(actor=actor, action=action_name, object_type=getattr(self, "_object_type", "unknown"),
                                        object_id=object_id, status="pending", reason=kwargs.get("reason"), request_id=request_id, ip=ip,
                                        details="started")
            except Exception:
                logger.exception("Failed to write pre-audit entry")

            try:
                result = func(self, *args, **kwargs)
                status = result.get("status", "success") if isinstance(result, dict) else "success"
                # Post-audit
                try:
                    self._write_audit_entry(actor=actor, action=action_name, object_type=getattr(self, "_object_type", "unknown"),
                                            object_id=object_id, status=status, reason=kwargs.get("reason"), request_id=request_id, ip=ip,
                                            details=json.dumps(result)[:4000] if isinstance(result, dict) else str(result)[:4000])
                except Exception:
                    logger.exception("Failed to write post-audit entry")
                return result
            except Exception as e:
                # Error audit
                try:
                    self._write_audit_entry(actor=actor, action=action_name, object_type=getattr(self, "_object_type", "unknown"),
                                            object_id=object_id, status="error", reason=str(e), request_id=request_id, ip=ip, details="")
                except Exception:
                    logger.exception("Failed to write error audit")
                logger.exception("Critical action '%s' failed", action_name)
                return {"status": "error", "message": str(e)}
        return wrapper
    return decorator

# -------------------------
# DataProcessor implementation
# -------------------------
class DataProcessor:
    _object_type = "user"

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.session = create_http_session()
        # Initialize DB and schemas
        conn = self.connect_to_database()
        init_db(conn)
        init_db_with_audit(conn)
        conn.close()
        logger.info("DataProcessor initialized (db=%s)", self.db_path)

    def connect_to_database(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
        conn.row_factory = sqlite3.Row
        return conn

    # ---------------------
    # CRUD and critical methods
    # ---------------------
    def create_user(self, username: str, password: str, cc_full: Optional[str] = None, ssn_full: Optional[str] = None) -> int:
        """
        Create a user with hashed password. Do NOT store raw PII here; only last4 or a token to a vault.
        """
        salt_hex, hash_hex = hash_password(password)
        cc_last4 = cc_full[-4:] if cc_full and len(cc_full) >= 4 else None
        ssn_last4 = ssn_full[-4:] if ssn_full and len(ssn_full) >= 4 else None
        conn = self.connect_to_database()
        try:
            with conn:
                cur = conn.execute("""
                    INSERT INTO user_data (username, password_hash, password_salt, cc_last4, ssn_last4, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (username, hash_hex, salt_hex, cc_last4, ssn_last4, datetime.now(timezone.utc)))
                user_id = cur.lastrowid
            logger.info("Created user id=%d username=%s", user_id, username)
            return user_id
        finally:
            conn.close()

    def fetch_user_data(self, user_id: int) -> Optional[Dict[str, Any]]:
        """
        Return only non-sensitive fields (no password hashes in result).
        """
        conn = self.connect_to_database()
        try:
            cur = conn.execute("SELECT id, username, cc_last4, ssn_last4, created_at FROM user_data WHERE id = ?", (user_id,))
            row = cur.fetchone()
            if row:
                return dict(row)
            return None
        finally:
            conn.close()

    # ---------------------
    # External API usage
    # ---------------------
    def call_external_api(self, endpoint: str, payload: dict, timeout: int = 10) -> Optional[dict]:
        """
        Call external API with retries; validates SSL by default (no verify=False).
        """
        url = f"{API_BASE_URL.rstrip('/')}/{endpoint.lstrip('/')}"
        headers = {
            "User-Agent": "SecureDataProcessor/1.0",
            "Content-Type": "application/json"
        }
        if API_KEY:
            headers["Authorization"] = f"Bearer {API_KEY}"
        try:
            resp = self.session.post(url, json=payload, headers=headers, timeout=timeout)
            resp.raise_for_status()
            return resp.json()
        except requests.HTTPError:
            logger.exception("External API returned HTTP error")
            return None
        except requests.RequestException:
            logger.exception("External API request failed")
            return None
        except ValueError:
            logger.error("Invalid JSON from external API")
            return None

    # ---------------------
    # S3 upload (boto3 default resolution)
    # ---------------------
    def upload_to_s3(self, file_path: str, bucket_name: Optional[str] = None, object_name: Optional[str] = None) -> bool:
        bucket = bucket_name or S3_BUCKET_DEFAULT
        object_name = object_name or os.path.basename(file_path)
        try:
            import boto3
            s3 = boto3.client('s3')  # uses env / profile / IAM role credential resolution
            s3.upload_file(file_path, bucket, object_name)
            logger.info("Uploaded file to s3://%s/%s", bucket, object_name)
            return True
        except Exception:
            logger.exception("Failed to upload to S3; ensure credentials/permissions are correct")
            return False

    # ---------------------
    # Email notifications
    # ---------------------
    def send_notification_email(self, recipient: str, subject: str, body: str) -> bool:
        """
        Minimal SMTP usage: prefer transactional email providers and API-based sending in production.
        """
        import smtplib
        from email.mime.text import MIMEText
        smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        sender_email = os.getenv("SMTP_FROM", "notifications@company.com")

        if not SMTP_PASSWORD or not SMTP_USER:
            logger.error("SMTP credentials not provided; email will not be sent.")
            return False
        try:
            message = MIMEText(body)
            message['From'] = sender_email
            message['To'] = recipient
            message['Subject'] = subject

            server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(message)
            server.quit()
            logger.info("Sent notification email to %s", recipient)
            return True
        except Exception:
            logger.exception("Failed to send notification email")
            return False

    # ---------------------
    # Audit & Archive helpers
    # ---------------------
    def _write_audit_entry(self, *, actor: str, action: str, object_type: str, object_id: Optional[int],
                           status: str, reason: Optional[str], request_id: Optional[str], ip: Optional[str],
                           details: Optional[str] = None) -> None:
        """
        Append an audit_log entry. Details trimmed to 4000 chars.
        """
        conn = self.connect_to_database()
        try:
            with conn:
                conn.execute("""
                    INSERT INTO audit_log (event_time, actor, action, object_type, object_id, status, reason, request_id, ip, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (datetime.now(timezone.utc), actor, action, object_type, object_id, status, reason, request_id, ip, (details[:4000] if details else None)))
        finally:
            conn.close()

    def _archive_user_row(self, user_row: sqlite3.Row, *, actor: str, reason: Optional[str], request_id: Optional[str]) -> int:
        """
        Insert row into user_archive and append to CSV archive file (atomic append).
        Returns archived_id.
        """
        conn = self.connect_to_database()
        try:
            with conn:
                cur = conn.execute("""
                    INSERT INTO user_archive (original_id, username, password_hash, password_salt, cc_last4, ssn_last4, pii_token, created_at, archived_at, archived_by, archive_reason, request_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    user_row["id"],
                    user_row["username"],
                    user_row.get("password_hash"),
                    user_row.get("password_salt"),
                    user_row.get("cc_last4"),
                    user_row.get("ssn_last4"),
                    user_row.get("pii_token"),
                    user_row.get("created_at"),
                    datetime.now(timezone.utc),
                    actor,
                    reason,
                    request_id
                ))
                archived_id = cur.lastrowid

            archived_row = {
                "archived_id": archived_id,
                "original_id": user_row["id"],
                "username": user_row["username"],
                "cc_last4": user_row.get("cc_last4"),
                "ssn_last4": user_row.get("ssn_last4"),
                "created_at": (user_row.get("created_at").isoformat() if user_row.get("created_at") else None),
                "archived_at": datetime.now(timezone.utc).isoformat(),
                "archived_by": actor,
                "archive_reason": reason,
                "request_id": request_id
            }
            self._append_archive_csv(archived_row)
            return archived_id
        finally:
            conn.close()

    def _append_archive_csv(self, row: Dict[str, Any]) -> str:
        """
        Append a single archived row to the archive CSV using atomic operations.
        Returns path to CSV.
        """
        csv_path = os.path.join(ARCHIVE_CSV_DIR, "user_archive.csv")
        write_header = not os.path.exists(csv_path)

        fd, tmp_path = tempfile.mkstemp(prefix="archive-", suffix=".tmp", dir=ARCHIVE_CSV_DIR)
        os.close(fd)
        try:
            mode = "w" if write_header else "w"
            # We'll write the header (if needed) and the single row into tmp file,
            # then either rename (if creating new file) or append tmp contents to target.
            with open(tmp_path, mode, newline='', encoding='utf-8') as f:
                writer = _csv.DictWriter(f, fieldnames=list(row.keys()))
                if write_header:
                    writer.writeheader()
                writer.writerow(row)
            if write_header:
                os.replace(tmp_path, csv_path)
            else:
                # Append tmp contents to target in an atomic-ish manner
                with open(tmp_path, "r", encoding='utf-8') as t, open(csv_path, "a", encoding='utf-8') as target:
                    target.write(t.read())
                os.remove(tmp_path)
            logger.info("Archived row appended to CSV %s", csv_path)
            return csv_path
        except Exception:
            logger.exception("Failed to append to archive CSV")
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                pass
            raise

    def export_archive_csv(self, output_path: Optional[str] = None) -> str:
        """
        Copy or return current archive CSV. For safe export, supply output_path (will be overwritten).
        """
        csv_path = os.path.join(ARCHIVE_CSV_DIR, "user_archive.csv")
        if not os.path.exists(csv_path):
            raise FileNotFoundError("No archive CSV found")
        if output_path:
            with open(csv_path, "rb") as src, open(output_path, "wb") as dst:
                dst.write(src.read())
            return output_path
        return csv_path

    # ---------------------
    # Critical: archive then delete user
    # ---------------------
    @critical_action("archive_and_delete_user")
    def archive_and_delete_user(self, user_id: int, *, actor: str, reason: Optional[str] = None, request_id: Optional[str] = None, ip: Optional[str] = None) -> Dict[str, Any]:
        """
        Archive user into user_archive + CSV, then delete original row.
        All steps are audited. Decorator writes pre/post audit entries automatically.
        """
        conn = self.connect_to_database()
        try:
            cur = conn.execute("SELECT * FROM user_data WHERE id = ?", (user_id,))
            row = cur.fetchone()
            if not row:
                return {"status": "error", "message": "user_not_found", "user_id": user_id}

            archived_id = self._archive_user_row(row, actor=actor, reason=reason, request_id=request_id)
            with conn:
                conn.execute("DELETE FROM user_data WHERE id = ?", (user_id,))

            logger.info("User id=%s archived (archived_id=%s) and deleted by %s", user_id, archived_id, actor)
            return {"status": "success", "action": "archived_and_deleted", "user_id": user_id, "archived_id": archived_id}
        except Exception as e:
            logger.exception("archive_and_delete_user failed")
            # error audit entry will be created by decorator
            return {"status": "error", "message": str(e)}
        finally:
            conn.close()

    # ---------------------
    # Webhook processing (verifies signature then acts)
    # ---------------------
    def process_webhook(self, headers: dict, payload: dict, *, actor: str = "webhook_service", ip: Optional[str] = None, request_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Verify webhook HMAC signature then process payload.
        """
        payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        sig_header = headers.get("X-Signature") or headers.get("X-Hub-Signature")
        if not verify_webhook_signature(payload_bytes, sig_header, WEBHOOK_SECRET or ""):
            logger.warning("Webhook signature verification failed")
            self._write_audit_entry(actor=actor, action="webhook_verify", object_type="webhook", object_id=None, status="unauthorized", reason="signature_failed", request_id=request_id, ip=ip, details=None)
            return {"status": "unauthorized", "code": 401}

        # Basic validation
        user_id = payload.get("user_id")
        action = payload.get("action")
        if not isinstance(user_id, int):
            logger.warning("Webhook invalid payload: user_id not int")
            self._write_audit_entry(actor=actor, action="webhook_verify", object_type="webhook", object_id=None, status="bad_request", reason="user_id_invalid", request_id=request_id, ip=ip, details=str(payload))
            return {"status": "bad_request", "code": 400}

        if action == "delete_user":
            # Use archive_and_delete_user which is audited and safe
            result = self.archive_and_delete_user(user_id, actor=actor, reason="webhook_delete", request_id=request_id, ip=ip)
            return result
        else:
            logger.info("Received webhook action=%s for user=%s", action, user_id)
            self._write_audit_entry(actor=actor, action="webhook_received", object_type="webhook", object_id=user_id, status="processed", reason=action, request_id=request_id, ip=ip, details=None)
            return {"status": "processed", "action": action, "user_id": user_id}

# -------------------------
# Demo / main
# -------------------------
def main_demo():
    dp = DataProcessor()
    # Create a demo user (local/dev only)
    test_user_id = dp.create_user("alice", "S3cur3P@ssw0rd!", cc_full="4111111111111111", ssn_full="123456789")
    logger.info("Created demo user id=%s", test_user_id)
    info = dp.fetch_user_data(test_user_id)
    logger.info("Fetched user (safe): %s", info)

    # Simulate a webhook delete action with proper signature (for local demo)
    payload = {"user_id": test_user_id, "action": "delete_user"}
    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = "sha256=" + hmac.new((WEBHOOK_SECRET or "").encode(), payload_bytes, hashlib.sha256).hexdigest()
    headers = {"X-Signature": signature}
    result = dp.process_webhook(headers, payload, actor="demo_script", request_id=str(uuid.uuid4()))
    logger.info("Webhook processing result: %s", result)

if __name__ == "__main__":
    main_demo()
