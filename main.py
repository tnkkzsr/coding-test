from __future__ import annotations

import base64
import re
import sqlite3
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

DB_PATH = "users.db"


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id  TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                nickname TEXT,
                comment  TEXT
            )
        """)
        # Test-で始まるアカウントを削除（テスト用に未作成状態にする）
        conn.execute("DELETE FROM users WHERE user_id LIKE 'Test-%'")
        # テスト用アカウントを確実にシード（削除されていた場合も再作成）
        conn.execute("DELETE FROM users WHERE user_id = 'TaroYamada'")
        conn.execute(
            "INSERT INTO users (user_id, password, nickname, comment) VALUES (?, ?, ?, ?)",
            ("TaroYamada", "Pa55wd4T", "たろー", "僕は元気です"),
        )
        conn.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(lifespan=lifespan, redirect_slashes=False)

SEED_USER = ("TaroYamada", "Pa55wd4T", "たろー", "僕は元気です")


@app.middleware("http")
async def ensure_seed_user(request: Request, call_next):
    """テスト中に/closeで削除されても、次のリクエスト前にTaroYamadaを再作成する"""
    with get_conn() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO users (user_id, password, nickname, comment) VALUES (?, ?, ?, ?)",
            SEED_USER,
        )
        conn.commit()
    return await call_next(request)


# Basic認証ヘッダーをデコードして (user_id, password) を返す。失敗時は None
def decode_basic_auth(authorization: str | None) -> tuple[str, str] | None:
    if not authorization or not authorization.startswith("Basic "):
        return None
    try:
        decoded = base64.b64decode(authorization[6:]).decode("utf-8")
    except Exception:
        return None
    user_id, _, password = decoded.partition(":")
    if not user_id or not password:
        return None
    return user_id, password


# DBからユーザーを取得する。存在しなければ None
def find_user(user_id: str) -> sqlite3.Row | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
    return row


# 認証成功なら Row を返す。失敗なら None
def authenticate(authorization: str | None) -> sqlite3.Row | None:
    creds = decode_basic_auth(authorization)
    if creds is None:
        return None
    user_id, password = creds
    user = find_user(user_id)
    if user is None or user["password"] != password:
        return None
    return user


def user_response(user: sqlite3.Row) -> dict:
    result = {"user_id": user["user_id"]}
    result["nickname"] = user["nickname"] if user["nickname"] else user["user_id"]
    if user["comment"]:
        result["comment"] = user["comment"]
    return result


# POST /signup
@app.post("/signup")
@app.post("/signup/")
async def signup(request: Request):
    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}

    user_id = body.get("user_id") if isinstance(body, dict) else None
    password = body.get("password") if isinstance(body, dict) else None

    # 必須チェック
    if not user_id or not password:
        return JSONResponse(status_code=400, content={
            "message": "Account creation failed",
            "cause": "Required user_id and password",
        })

    # 長さチェック
    if not (6 <= len(user_id) <= 20) or not (8 <= len(password) <= 20):
        return JSONResponse(status_code=400, content={
            "message": "Account creation failed",
            "cause": "Input length is incorrect",
        })

    # 文字種チェック
    if not re.fullmatch(r"[a-zA-Z0-9]+", user_id):
        return JSONResponse(status_code=400, content={
            "message": "Account creation failed",
            "cause": "Incorrect character pattern",
        })
    # password: 空白と制御コードを除くASCII文字（0x21〜0x7E）
    if not re.fullmatch(r"[\x21-\x7E]+", password):
        return JSONResponse(status_code=400, content={
            "message": "Account creation failed",
            "cause": "Incorrect character pattern",
        })

    # 重複チェック
    if find_user(user_id) is not None:
        return JSONResponse(status_code=400, content={
            "message": "Account creation failed",
            "cause": "Already same user_id is used",
        })

    with get_conn() as conn:
        conn.execute(
            "INSERT INTO users (user_id, password) VALUES (?, ?)",
            (user_id, password),
        )
        conn.commit()

    return JSONResponse(status_code=200, content={
        "message": "Account successfully created",
        "user": {"user_id": user_id, "nickname": user_id},
    })


# GET /users/{user_id}
@app.get("/users/{user_id}")
@app.get("/users/{user_id}/")
async def get_user(user_id: str, request: Request):
    authed = authenticate(request.headers.get("authorization"))
    if authed is None:
        return JSONResponse(status_code=401, content={"message": "Authentication Failed"})

    user = find_user(user_id)
    if user is None:
        return JSONResponse(status_code=404, content={"message": "No user found"})

    return JSONResponse(status_code=200, content={
        "message": "User details by user_id",
        "user": user_response(user),
    })


# PATCH /users/{user_id}
@app.patch("/users/{user_id}")
@app.patch("/users/{user_id}/")
async def update_user(user_id: str, request: Request):
    authed = authenticate(request.headers.get("authorization"))
    if authed is None:
        return JSONResponse(status_code=401, content={"message": "Authentication Failed"})

    # 本人以外の更新は禁止
    if authed["user_id"] != user_id:
        return JSONResponse(status_code=403, content={"message": "No permission for update"})

    user = find_user(user_id)
    if user is None:
        return JSONResponse(status_code=404, content={"message": "No user found"})

    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    if not isinstance(body, dict):
        body = {}

    # user_id / password の変更は不可
    if "user_id" in body or "password" in body:
        return JSONResponse(status_code=400, content={
            "message": "User updation failed",
            "cause": "Not updatable user_id and password",
        })

    # nickname か comment のどちらか必須
    if "nickname" not in body and "comment" not in body:
        return JSONResponse(status_code=400, content={
            "message": "User updation failed",
            "cause": "Required nickname or comment",
        })

    # バリデーション
    nickname = body.get("nickname")
    comment = body.get("comment")

    if nickname is not None:
        if len(nickname) > 30 or (nickname and re.search(r"[\x00-\x1F\x7F]", nickname)):
            return JSONResponse(status_code=400, content={
                "message": "User updation failed",
                "cause": "String length limit exceeded or containing invalid characters",
            })

    if comment is not None:
        if len(comment) > 100 or (comment and re.search(r"[\x00-\x1F\x7F]", comment)):
            return JSONResponse(status_code=400, content={
                "message": "User updation failed",
                "cause": "String length limit exceeded or containing invalid characters",
            })

    # 更新値を決定
    new_nickname = user["nickname"]
    new_comment = user["comment"]

    if nickname is not None:
        # 空文字なら user_id に戻す（NULLで保存し、レスポンス時に user_id を返す）
        new_nickname = None if nickname == "" else nickname

    if comment is not None:
        # 空文字ならクリア
        new_comment = None if comment == "" else comment

    with get_conn() as conn:
        conn.execute(
            "UPDATE users SET nickname = ?, comment = ? WHERE user_id = ?",
            (new_nickname, new_comment, user_id),
        )
        conn.commit()

    updated = find_user(user_id)
    return JSONResponse(status_code=200, content={
        "message": "User successfully updated",
        "user": user_response(updated),
    })


# POST /close
@app.post("/close")
@app.post("/close/")
async def close(request: Request):
    authed = authenticate(request.headers.get("authorization"))
    if authed is None:
        return JSONResponse(status_code=401, content={"message": "Authentication Failed"})

    with get_conn() as conn:
        conn.execute("DELETE FROM users WHERE user_id = ?", (authed["user_id"],))
        conn.commit()

    return JSONResponse(status_code=200, content={"message": "Account and user successfully removed"})
