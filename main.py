"""
Todo Service API (FastAPI + SQLite)

Engineering rules follow harness/AGENTS.md:
- Secrets come from environment variables (CWE-798)
- Every SQL statement uses parameter binding with `?` (CWE-89)
- Passwords use salted PBKDF2-HMAC-SHA256 (CWE-327)
- Set-based O(1) lookups instead of nested loops
- SQLite WAL mode + busy_timeout for concurrent writers (CWE-400)

Environment variables:
  ADMIN_PASSWORD     admin login password (if unset, a random one is generated
                     at startup and printed to the console - dev only)
  APP_DB_FILE        SQLite file path (default: service.db)
  ADMIN_TOKEN_TTL    admin token lifetime in seconds (default: 3600)
"""

import hashlib
import hmac
import logging
import os
import secrets
import sqlite3
import threading
import time
from typing import List, Optional

from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger("todo_service")
logging.basicConfig(level=logging.INFO)

APP_NAME = "Todo Service API"
APP_VERSION = "1.0.0"

BLOCKED_TAGS = ["spam", "ad", "private", "temp"]
BLOCKED_TAG_SET = frozenset(BLOCKED_TAGS)  # built once, O(1) membership checks

PBKDF2_ITERATIONS = 200_000

app = FastAPI(title=APP_NAME, version=APP_VERSION)


# =====================================================================
# Configuration (read from the environment, never hardcoded)
# =====================================================================
def get_db_file() -> str:
    return os.getenv("APP_DB_FILE", "service.db")


_generated_admin_secret: Optional[str] = None
_config_lock = threading.Lock()


def get_admin_secret() -> str:
    """Admin password from env; falls back to a random per-process value."""
    global _generated_admin_secret
    from_env = os.getenv("ADMIN_PASSWORD")
    if from_env:
        return from_env
    with _config_lock:
        if _generated_admin_secret is None:
            _generated_admin_secret = secrets.token_urlsafe(16)
            logger.warning(
                "ADMIN_PASSWORD is not set. Generated a temporary admin password "
                "for this process: %s", _generated_admin_secret
            )
        return _generated_admin_secret


def get_token_ttl() -> int:
    try:
        return int(os.getenv("ADMIN_TOKEN_TTL", "3600"))
    except ValueError:
        logger.warning("Invalid ADMIN_TOKEN_TTL; using 3600 seconds")
        return 3600


# =====================================================================
# Database
# =====================================================================
def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(get_db_file(), timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db() -> None:
    conn = get_db_connection()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content TEXT,
                owner_username TEXT NOT NULL,
                status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS todos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT DEFAULT '',
                is_completed INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                tags TEXT DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_todos_created_at ON todos(created_at);
            """
        )
        conn.commit()
    finally:
        conn.close()


init_db()


# =====================================================================
# Security helpers
# =====================================================================
def hash_credential(raw_secret: str, salt: Optional[bytes] = None) -> str:
    """Salted PBKDF2-HMAC-SHA256. Stored as '<salt_hex>$<digest_hex>'."""
    salt = salt if salt is not None else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", raw_secret.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return salt.hex() + "$" + digest.hex()


def verify_credential(raw_secret: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False
    candidate = hash_credential(raw_secret, salt).split("$", 1)[1]
    return hmac.compare_digest(candidate, digest_hex)


_admin_tokens: dict = {}  # token -> expiry epoch seconds
_token_lock = threading.Lock()


def issue_admin_token() -> str:
    token = secrets.token_urlsafe(32)
    with _token_lock:
        _admin_tokens[token] = time.time() + get_token_ttl()
    return token


def require_admin(token: Optional[str]) -> None:
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing admin token")
    with _token_lock:
        expiry = _admin_tokens.get(token)
        if expiry is not None and expiry < time.time():
            del _admin_tokens[token]
            expiry = None
    if expiry is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid or expired admin token")


def extract_token(authorization: Optional[str], x_auth_token: Optional[str]) -> Optional[str]:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return x_auth_token


def escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


# =====================================================================
# Utilities
# =====================================================================
def deduplicate_records(records: list) -> list:
    """Order-preserving dedup by id using a set: O(N)."""
    seen = set()
    unique_items = []
    for item in records:
        key = item.get("id")
        if key not in seen:
            seen.add(key)
            unique_items.append(item)
    return unique_items


def parse_tags(raw: Optional[str]) -> List[str]:
    if not raw:
        return []
    return [t.strip().lower() for t in raw.split(",") if t.strip()]


def is_blocked(tags: List[str]) -> bool:
    return any(tag in BLOCKED_TAG_SET for tag in tags)


def row_to_todo(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "title": row["title"],
        "description": row["description"],
        "is_completed": bool(row["is_completed"]),
        "created_at": row["created_at"],
        "tags": parse_tags(row["tags"]),
    }


# =====================================================================
# Schemas
# =====================================================================
class UserRegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=128)


class ItemCreateRequest(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    content: Optional[str] = ""


class TodoCreateRequest(BaseModel):
    title: str = Field(max_length=200)
    description: Optional[str] = Field(default="", max_length=2000)
    is_completed: bool = False
    tags: Optional[str] = Field(default="", max_length=500)

    @field_validator("title")
    @classmethod
    def title_not_blank(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("title must not be empty")
        return v


class AdminLoginRequest(BaseModel):
    password: str = Field(min_length=1, max_length=256)


# =====================================================================
# Base endpoints
# =====================================================================
@app.get("/")
def health_check():
    return {"status": "healthy", "app": APP_NAME, "version": APP_VERSION}


@app.post("/api/auth/register", status_code=status.HTTP_201_CREATED)
def register_user(req: UserRegisterRequest):
    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (req.username, hash_credential(req.password)),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already exists")
    finally:
        conn.close()
    return {"success": True, "message": "User registered successfully", "username": req.username}


@app.post("/api/auth/login")
def login_user(req: UserRegisterRequest):
    conn = get_db_connection()
    try:
        user = conn.execute(
            "SELECT id, username, role, password_hash FROM users WHERE username = ?",
            (req.username,),
        ).fetchone()
    finally:
        conn.close()
    if not user or not verify_credential(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return {
        "success": True,
        "user": {"id": user["id"], "username": user["username"], "role": user["role"]},
    }


@app.get("/api/items")
def search_items(keyword: Optional[str] = None):
    conn = get_db_connection()
    try:
        if keyword:
            pattern = "%" + escape_like(keyword) + "%"
            rows = conn.execute(
                "SELECT * FROM items WHERE title LIKE ? ESCAPE '\\' OR content LIKE ? ESCAPE '\\'",
                (pattern, pattern),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM items").fetchall()
    finally:
        conn.close()
    results = deduplicate_records([dict(r) for r in rows])
    return {"total": len(results), "items": results}


@app.post("/api/items", status_code=status.HTTP_201_CREATED)
def create_item(
    req: ItemCreateRequest,
    x_auth_token: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    require_admin(extract_token(authorization, x_auth_token))
    conn = get_db_connection()
    try:
        cur = conn.execute(
            "INSERT INTO items (title, content, owner_username) VALUES (?, ?, ?)",
            (req.title, req.content, "admin"),
        )
        conn.commit()
        item_id = cur.lastrowid
    finally:
        conn.close()
    return {"success": True, "item_id": item_id, "title": req.title}


# =====================================================================
# Todo endpoints
# =====================================================================
@app.get("/todos")
def list_todos():
    conn = get_db_connection()
    try:
        rows = conn.execute("SELECT * FROM todos ORDER BY id").fetchall()
    finally:
        conn.close()
    todos = [row_to_todo(r) for r in rows]
    return {"total": len(todos), "todos": todos}


@app.post("/todos", status_code=status.HTTP_201_CREATED)
def create_todo(req: TodoCreateRequest):
    tags_csv = ",".join(parse_tags(req.tags))
    conn = get_db_connection()
    try:
        cur = conn.execute(
            "INSERT INTO todos (title, description, is_completed, tags) VALUES (?, ?, ?, ?)",
            (req.title, req.description or "", int(req.is_completed), tags_csv),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM todos WHERE id = ?", (cur.lastrowid,)).fetchone()
    finally:
        conn.close()
    return row_to_todo(row)


@app.get("/todos/search")
def search_todos(q: str):
    keyword = q.strip()
    if not keyword:
        raise HTTPException(status_code=400, detail="Query parameter q must not be empty")
    pattern = "%" + escape_like(keyword) + "%"
    conn = get_db_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM todos WHERE title LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\' ORDER BY id",
            (pattern, pattern),
        ).fetchall()
    finally:
        conn.close()
    todos = [row_to_todo(r) for r in rows]
    return {"total": len(todos), "todos": todos}


@app.get("/todos/filtered")
def filtered_todos():
    conn = get_db_connection()
    try:
        rows = conn.execute("SELECT * FROM todos ORDER BY id").fetchall()
    finally:
        conn.close()
    todos = [t for t in (row_to_todo(r) for r in rows) if not is_blocked(t["tags"])]
    return {"total": len(todos), "blocked_tags": BLOCKED_TAGS, "todos": todos}


@app.get("/todos/{todo_id}")
def get_todo(todo_id: int):
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM todos WHERE id = ?", (todo_id,)).fetchone()
    finally:
        conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="Todo not found")
    return row_to_todo(row)


@app.post("/admin/login")
def admin_login(req: AdminLoginRequest):
    if not hmac.compare_digest(req.password.encode("utf-8"), get_admin_secret().encode("utf-8")):
        raise HTTPException(status_code=401, detail="Invalid admin password")
    return {"access_token": issue_admin_token(), "token_type": "bearer", "expires_in": get_token_ttl()}


@app.delete("/admin/todos/{todo_id}")
def admin_delete_todo(
    todo_id: int,
    authorization: Optional[str] = Header(None),
    x_auth_token: Optional[str] = Header(None),
):
    require_admin(extract_token(authorization, x_auth_token))
    conn = get_db_connection()
    try:
        cur = conn.execute("DELETE FROM todos WHERE id = ?", (todo_id,))
        conn.commit()
        deleted = cur.rowcount
    finally:
        conn.close()
    if deleted == 0:
        raise HTTPException(status_code=404, detail="Todo not found")
    return {"success": True, "deleted_id": todo_id}
