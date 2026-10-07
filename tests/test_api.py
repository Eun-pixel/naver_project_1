import os
import sqlite3

import pytest
from fastapi.testclient import TestClient

ADMIN_PW = "test-admin-pass-123"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("APP_DB_FILE", str(tmp_path / "test.db"))
    monkeypatch.setenv("ADMIN_PASSWORD", ADMIN_PW)
    import main

    main.init_db()
    with main._token_lock:
        main._admin_tokens.clear()
    return TestClient(main.app)


def admin_token(client):
    res = client.post("/admin/login", json={"password": ADMIN_PW})
    assert res.status_code == 200
    return res.json()["access_token"]


# ---------- CRUD ----------
def test_create_and_list_todos(client):
    res = client.post("/todos", json={"title": "Buy milk", "description": "2L", "tags": "home, Shop"})
    assert res.status_code == 201
    body = res.json()
    assert body["title"] == "Buy milk"
    assert body["is_completed"] is False
    assert body["tags"] == ["home", "shop"]

    listing = client.get("/todos").json()
    assert listing["total"] == 1
    assert listing["todos"][0]["id"] == body["id"]

    assert client.get(f"/todos/{body['id']}").status_code == 200
    assert client.get("/todos/9999").status_code == 404


# ---------- Search ----------
def test_search_by_title_and_description(client):
    client.post("/todos", json={"title": "Study FastAPI", "description": ""})
    client.post("/todos", json={"title": "Gym", "description": "leg day with fastapi podcast"})
    client.post("/todos", json={"title": "Cook", "description": "pasta"})
    res = client.get("/todos/search", params={"q": "fastapi"})
    assert res.status_code == 200
    assert res.json()["total"] == 2


def test_search_rejects_blank_query(client):
    assert client.get("/todos/search", params={"q": "   "}).status_code == 400


def test_search_like_wildcards_are_literal(client):
    client.post("/todos", json={"title": "100% done"})
    client.post("/todos", json={"title": "plain"})
    assert client.get("/todos/search", params={"q": "%"}).json()["total"] == 1


# ---------- SQL injection ----------
def test_sql_injection_in_search_is_harmless(client):
    client.post("/todos", json={"title": "secret task"})
    payload = "' OR '1'='1"
    res = client.get("/todos/search", params={"q": payload})
    assert res.status_code == 200
    assert res.json()["total"] == 0  # treated as literal text, not SQL


def test_sql_injection_in_create_does_not_drop_table(client):
    evil = "x'); DROP TABLE todos; --"
    res = client.post("/todos", json={"title": evil, "description": evil})
    assert res.status_code == 201
    assert res.json()["title"] == evil
    conn = sqlite3.connect(os.environ["APP_DB_FILE"])
    try:
        count = conn.execute("SELECT COUNT(*) FROM todos").fetchone()[0]
    finally:
        conn.close()
    assert count == 1


def test_sql_injection_in_user_login_fails(client):
    client.post("/api/auth/register", json={"username": "alice", "password": "alice-pass-1"})
    res = client.post("/api/auth/login", json={"username": "alice' --", "password": "whatever-123"})
    assert res.status_code == 401


# ---------- Admin auth ----------
def test_admin_login_wrong_password(client):
    assert client.post("/admin/login", json={"password": "nope"}).status_code == 401


def test_admin_delete_requires_valid_token(client):
    todo_id = client.post("/todos", json={"title": "to delete"}).json()["id"]
    assert client.delete(f"/admin/todos/{todo_id}").status_code == 401
    bad = client.delete(f"/admin/todos/{todo_id}", headers={"Authorization": "Bearer forged"})
    assert bad.status_code == 403
    assert client.get(f"/todos/{todo_id}").status_code == 200


def test_admin_delete_with_valid_token(client):
    todo_id = client.post("/todos", json={"title": "to delete"}).json()["id"]
    token = admin_token(client)
    res = client.delete(f"/admin/todos/{todo_id}", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert client.get(f"/todos/{todo_id}").status_code == 404
    again = client.delete(f"/admin/todos/{todo_id}", headers={"Authorization": f"Bearer {token}"})
    assert again.status_code == 404


def test_expired_admin_token_rejected(client, monkeypatch):
    monkeypatch.setenv("ADMIN_TOKEN_TTL", "-1")
    token = admin_token(client)
    todo_id = client.post("/todos", json={"title": "x"}).json()["id"]
    res = client.delete(f"/admin/todos/{todo_id}", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 403


# ---------- Blocked tag filtering ----------
def test_filtered_excludes_blocked_tags(client):
    client.post("/todos", json={"title": "ok", "tags": "work,home"})
    client.post("/todos", json={"title": "spammy", "tags": "work, SPAM"})
    client.post("/todos", json={"title": "ad", "tags": "ad"})
    client.post("/todos", json={"title": "notags"})
    res = client.get("/todos/filtered").json()
    assert {t["title"] for t in res["todos"]} == {"ok", "notags"}


# ---------- Input validation ----------
@pytest.mark.parametrize("title", ["", "   "])
def test_empty_title_rejected(client, title):
    assert client.post("/todos", json={"title": title}).status_code == 422


def test_missing_title_rejected(client):
    assert client.post("/todos", json={"description": "no title"}).status_code == 422


def test_too_long_title_rejected(client):
    assert client.post("/todos", json={"title": "a" * 201}).status_code == 422


# ---------- Users & crypto ----------
def test_register_login_and_salted_hash(client):
    import main

    assert client.post("/api/auth/register", json={"username": "bob", "password": "bob-pass-1"}).status_code == 201
    assert client.post("/api/auth/register", json={"username": "bob", "password": "bob-pass-1"}).status_code == 400
    assert client.post("/api/auth/login", json={"username": "bob", "password": "bob-pass-1"}).status_code == 200
    assert client.post("/api/auth/login", json={"username": "bob", "password": "wrong-pass"}).status_code == 401

    h1 = main.hash_credential("same-password")
    h2 = main.hash_credential("same-password")
    assert h1 != h2  # random salt
    assert main.verify_credential("same-password", h1)
    assert not main.verify_credential("same-password", "malformed")


def test_items_endpoints(client):
    assert client.post("/api/items", json={"title": "x"}).status_code == 401
    token = admin_token(client)
    res = client.post("/api/items", json={"title": "Note", "content": "50% off"}, headers={"X-Auth-Token": token})
    assert res.status_code == 201
    assert client.get("/api/items", params={"keyword": "50%"}).json()["total"] == 1
    assert client.get("/api/items").json()["total"] == 1


def test_wal_mode_enabled(client):
    import main

    conn = main.get_db_connection()
    try:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    finally:
        conn.close()


def test_dedup_preserves_order():
    import main

    rows = [{"id": 2}, {"id": 1}, {"id": 2}, {"id": 3}, {"id": 1}]
    assert [r["id"] for r in main.deduplicate_records(rows)] == [2, 1, 3]
