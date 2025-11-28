import os
import sqlite3
import hashlib
from datetime import datetime
from typing import List

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

DB_PATH = os.getenv("DB_PATH", "svs_booking.db")
PASSWORD_SALT = os.getenv("PASSWORD_SALT", "change-me-super-secret-salt")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "change-this-admin-token")

app = FastAPI(title="SVS 3043 Booking API")


# ---------- DB helpers ----------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    # Buffs table now has an "enabled" flag
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS buffs (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            note TEXT DEFAULT '',
            sort_order INTEGER NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1
        );
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS slots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            buff_id TEXT NOT NULL,
            slot_code TEXT NOT NULL,
            alliance TEXT NOT NULL,
            name TEXT NOT NULL,
            pwd_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(buff_id, slot_code),
            FOREIGN KEY(buff_id) REFERENCES buffs(id) ON DELETE CASCADE
        );
        """
    )

    # Seed some default buffs if table empty
    cur.execute("SELECT COUNT(*) AS c FROM buffs;")
    if cur.fetchone()["c"] == 0:
        default_buffs = [
            ("buff-1", "Day 1 – Research", "", 1, 1),
            ("buff-2", "Day 2 – Construction", "", 2, 1),
            ("buff-3", "Day 3 – Training", "", 3, 1),
            ("buff-4", "Day 4 – Kill Event", "", 4, 1),
        ]
        cur.executemany(
            "INSERT INTO buffs (id, name, note, sort_order, enabled) VALUES (?, ?, ?, ?, ?);",
            default_buffs,
        )

    conn.commit()
    conn.close()


def hash_password(password: str) -> str:
    data = (PASSWORD_SALT + password).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


# ---------- Pydantic models ----------

class BuffOut(BaseModel):
    PK: str
    Name: str
    Note: str


class SlotOut(BaseModel):
    PK: str
    SK: str
    Alliance: str
    Name: str


class SlotCreate(BaseModel):
    PK: str
    SK: str
    Alliance: str
    Name: str
    Password: str


class SlotDelete(BaseModel):
    Password: str


class AdminResetRequest(BaseModel):
    adminToken: str
    buffId: str | None = None  # if None → reset all buffs


class AdminBuffOut(BaseModel):
    PK: str
    Name: str
    Note: str
    Enabled: bool
    SortOrder: int


class AdminBuffUpdate(BaseModel):
    adminToken: str
    buffId: str
    name: str
    note: str | None = ""
    enabled: bool


# ---------- CORS ----------

origins = os.getenv("CORS_ORIGINS", "*").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


# ---------- Startup ----------

@app.on_event("startup")
def on_startup():
    init_db()


# ---------- Public endpoints (used by booking page) ----------

@app.get("/buffs", response_model=List[BuffOut])
def get_buffs():
    """
    Public: only return ENABLED buffs, ordered.
    """
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, name, note FROM buffs WHERE enabled = 1 ORDER BY sort_order;"
    )
    rows = cur.fetchall()
    conn.close()

    return [
        BuffOut(PK=row["id"], Name=row["name"], Note=row["note"])
        for row in rows
    ]


@app.get("/slots/{buff_id}", response_model=List[SlotOut])
def get_slots_for_buff(buff_id: str):
    conn = get_db()
    cur = conn.cursor()

    # Ensure buff exists (even if disabled; admin might still inspect bookings)
    cur.execute("SELECT id FROM buffs WHERE id = ?;", (buff_id,))
    if cur.fetchone() is None:
        conn.close()
        return []  # unknown buff → no slots

    cur.execute(
        """
        SELECT buff_id, slot_code, alliance, name
        FROM slots
        WHERE buff_id = ?
        ORDER BY slot_code;
        """,
        (buff_id,),
    )
    rows = cur.fetchall()
    conn.close()

    return [
        SlotOut(PK=row["buff_id"], SK=row["slot_code"],
                Alliance=row["alliance"], Name=row["name"])
        for row in rows
    ]


@app.post("/slots")
def create_slot(slot: SlotCreate):
    conn = get_db()
    cur = conn.cursor()

    # Check buff exists AND is enabled (don't allow booking disabled buff)
    cur.execute(
        "SELECT id, enabled FROM buffs WHERE id = ?;",
        (slot.PK,),
    )
    row = cur.fetchone()
    if row is None:
        conn.close()
        return "Unknown buff (PK)"
    if row["enabled"] != 1:
        conn.close()
        return "This day is currently disabled"

    # Check if slot already booked
    cur.execute(
        "SELECT id FROM slots WHERE buff_id = ? AND slot_code = ?;",
        (slot.PK, slot.SK),
    )
    if cur.fetchone() is not None:
        conn.close()
        return "Slot already booked"

    pwd_hash = hash_password(slot.Password)
    now = datetime.utcnow().isoformat() + "Z"

    cur.execute(
        """
        INSERT INTO slots (buff_id, slot_code, alliance, name, pwd_hash, created_at)
        VALUES (?, ?, ?, ?, ?, ?);
        """,
        (slot.PK, slot.SK, slot.Alliance.strip(), slot.Name.strip(), pwd_hash, now),
    )
    conn.commit()
    conn.close()

    return "OK"


@app.delete("/slots/{buff_id}/{slot_id}")
def delete_slot(buff_id: str, slot_id: str, body: SlotDelete):
    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT id, pwd_hash
        FROM slots
        WHERE buff_id = ? AND slot_code = ?;
        """,
        (buff_id, slot_id),
    )
    row = cur.fetchone()
    if row is None:
        conn.close()
        return "Slot not found"

    expected_hash = row["pwd_hash"]
    if hash_password(body.Password) != expected_hash:
        conn.close()
        return "Incorrect password"

    cur.execute("DELETE FROM slots WHERE id = ?;", (row["id"],))
    conn.commit()
    conn.close()

    return "OK"


# ---------- Admin endpoints ----------

@app.post("/admin/reset")
def admin_reset(payload: AdminResetRequest):
    """
    Admin-only: wipe bookings.
    - If buffId is provided → delete bookings only for that buff.
    - If buffId is omitted or empty → delete ALL bookings.
    """
    if payload.adminToken != ADMIN_TOKEN:
        return "Invalid admin token"

    conn = get_db()
    cur = conn.cursor()

    if payload.buffId and payload.buffId.strip():
        buff_id = payload.buffId.strip()

        cur.execute("SELECT id FROM buffs WHERE id = ?;", (buff_id,))
        if cur.fetchone() is None:
            conn.close()
            return f"Buff '{buff_id}' not found"

        cur.execute("DELETE FROM slots WHERE buff_id = ?;", (buff_id,))
        deleted = cur.rowcount
        conn.commit()
        conn.close()
        return f"OK – deleted {deleted} bookings for {buff_id}"
    else:
        cur.execute("DELETE FROM slots;")
        deleted = cur.rowcount
        conn.commit()
        conn.close()
        return f"OK – deleted {deleted} bookings for ALL buffs"


@app.get("/admin/buffs", response_model=List[AdminBuffOut])
def admin_get_buffs(adminToken: str):
    """
    Admin: list ALL buffs including disabled ones.
    """
    if adminToken != ADMIN_TOKEN:
        # Single string so admin page can show it as message
        return [AdminBuffOut(PK="ERR", Name="Invalid admin token",
                             Note="", Enabled=False, SortOrder=0)]

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, name, note, sort_order, enabled FROM buffs ORDER BY sort_order;"
    )
    rows = cur.fetchall()
    conn.close()

    return [
        AdminBuffOut(
            PK=row["id"],
            Name=row["name"],
            Note=row["note"],
            Enabled=bool(row["enabled"]),
            SortOrder=row["sort_order"],
        )
        for row in rows
    ]


@app.post("/admin/buffs/update")
def admin_update_buff(payload: AdminBuffUpdate):
    """
    Admin: update buff name/note/enabled.
    """
    if payload.adminToken != ADMIN_TOKEN:
        return "Invalid admin token"

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "SELECT id FROM buffs WHERE id = ?;",
        (payload.buffId,),
    )
    if cur.fetchone() is None:
        conn.close()
        return f"Buff '{payload.buffId}' not found"

    cur.execute(
        """
        UPDATE buffs
        SET name = ?, note = ?, enabled = ?
        WHERE id = ?;
        """,
        (payload.name.strip(), (payload.note or "").strip(),
         1 if payload.enabled else 0, payload.buffId),
    )
    conn.commit()
    conn.close()

    return "OK"
