import csv
import io
import json
import re
import shlex
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, request, jsonify, render_template, Response

BASE_DIR = Path(__file__).parent
INSTANCE_DIR = BASE_DIR / "instance"
DB_PATH = INSTANCE_DIR / "ccm.db"

INSTANCE_DIR.mkdir(exist_ok=True)

app = Flask(__name__)


# ── Database ──────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    with get_db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS targets (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            name         TEXT    NOT NULL UNIQUE,
            description  TEXT,
            created_at   TEXT    DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS entries (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id         INTEGER REFERENCES targets(id) ON DELETE SET NULL,
            username          TEXT,
            password          TEXT,
            password_is_blank INTEGER NOT NULL DEFAULT 0,
            host              TEXT,
            domain            TEXT,
            service           TEXT,
            hash_type         TEXT,
            hash              TEXT,
            notes             TEXT,
            tags              TEXT,
            created_at        TEXT DEFAULT (datetime('now')),
            updated_at        TEXT DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_entries_target   ON entries(target_id);
        CREATE INDEX IF NOT EXISTS idx_entries_username ON entries(username);
        CREATE INDEX IF NOT EXISTS idx_entries_password ON entries(password);
        CREATE INDEX IF NOT EXISTS idx_entries_hash      ON entries(hash);
        """)

        entry_cols = {row["name"] for row in conn.execute("PRAGMA table_info(entries)")}
        if "password_is_blank" not in entry_cols:
            conn.execute("ALTER TABLE entries ADD COLUMN password_is_blank INTEGER NOT NULL DEFAULT 0")


init_db()


# ── Reuse-detection SQL fragments ────────────────────────────────────────────
# Password/hash reuse is computed globally (independent of the current target
# filter) — the whole point is to catch a password/hash showing up on more
# than one target.

# A "locked" password (password_is_blank = 1) is a *confirmed* empty password —
# distinct from password IS NULL, which just means "not found yet". Everywhere
# below that asks "does this entry have a password", a locked-blank password
# counts as yes, and all locked-blank entries are treated as sharing the same
# (empty) value for reuse-detection purposes — a password sprayed as blank
# across several accounts is exactly the kind of thing worth flagging.
_HAS_PASSWORD_VALUE_EXPR = "(password_is_blank = 1 OR (password IS NOT NULL AND TRIM(password) != ''))"

_PW_REUSE_EXPR = (
    "CASE WHEN (entries.password_is_blank = 1 OR (entries.password IS NOT NULL AND TRIM(entries.password) != '')) "
    "THEN (SELECT COUNT(*) FROM entries e2 WHERE "
    "  (entries.password_is_blank = 1 AND e2.password_is_blank = 1) OR "
    "  (entries.password_is_blank = 0 AND e2.password_is_blank = 0 AND e2.password = entries.password)"
    ") ELSE 0 END"
)
_HASH_REUSE_EXPR = (
    "CASE WHEN entries.hash IS NOT NULL AND TRIM(entries.hash) != '' "
    "THEN (SELECT COUNT(*) FROM entries e2 WHERE e2.hash = entries.hash) "
    "ELSE 0 END"
)
_HAS_USERPASS_EXPR = (
    f"(username IS NOT NULL AND TRIM(username) != '' AND {_HAS_PASSWORD_VALUE_EXPR})"
)


# ── Search query parser ───────────────────────────────────────────────────────

_SEARCH_TOKEN_RE = re.compile(r'^(-?)([A-Za-z_]+):(.+)$')

_OP_STRING = {
    'user': 'username', 'username': 'username',
    'pass': 'password', 'password': 'password',
    'host': 'host',
    'domain': 'domain',
    'service': 'service',
    'hashtype': 'hash_type',
    'hash': 'hash',
}

_YESNO = lambda v: v.lower() in ('yes', 'true', '1', 'y')


def parse_search_query(search_str: str):
    conditions, params, plain_terms = [], [], []

    try:
        tokens = shlex.split(search_str)
    except ValueError:
        tokens = search_str.split()

    for token in tokens:
        m = _SEARCH_TOKEN_RE.match(token)
        if not m:
            plain_terms.append(token)
            continue

        negate = m.group(1) == '-'
        op = m.group(2).lower()
        value = m.group(3)
        NOT = "NOT " if negate else ""

        if op in _OP_STRING:
            like = value.replace('*', '%')
            conditions.append(f"LOWER({_OP_STRING[op]}) {NOT}LIKE LOWER(?)")
            params.append(like)

        elif op == 'notes':
            yes = _YESNO(value)
            if yes ^ negate:
                conditions.append("(notes IS NOT NULL AND TRIM(notes) != '')")
            else:
                conditions.append("(notes IS NULL OR TRIM(notes) = '')")

        elif op == 'tag':
            pat = f'%"{value.replace("*", "%")}"%'
            if negate:
                conditions.append("(tags IS NULL OR tags NOT LIKE ?)")
            else:
                conditions.append("(tags IS NOT NULL AND tags LIKE ?)")
            params.append(pat)

        elif op == 'target':
            like = value.replace('*', '%')
            sub = "target_id IN (SELECT id FROM targets WHERE LOWER(name) LIKE LOWER(?))"
            conditions.append(f"{'NOT ' if negate else ''}{sub}")
            params.append(like)

        elif op == 'reused':
            yes = _YESNO(value)
            cond = f"({_PW_REUSE_EXPR}) > 1"
            conditions.append(cond if (yes ^ negate) else f"NOT {cond}")

        elif op == 'reusedhash':
            yes = _YESNO(value)
            cond = f"({_HASH_REUSE_EXPR}) > 1"
            conditions.append(cond if (yes ^ negate) else f"NOT {cond}")

        elif op == 'userpass':
            yes = _YESNO(value)
            conditions.append(_HAS_USERPASS_EXPR if (yes ^ negate) else f"NOT {_HAS_USERPASS_EXPR}")

        elif op == 'blankpass':
            yes = _YESNO(value)
            cond = "password_is_blank = 1"
            conditions.append(cond if (yes ^ negate) else f"NOT ({cond})")

        else:
            plain_terms.append(token)

    for term in plain_terms:
        like = '%' + term.replace('*', '%') + '%'
        conditions.append(
            "(username LIKE ? OR password LIKE ? OR host LIKE ? OR domain LIKE ? "
            "OR service LIKE ? OR hash_type LIKE ? OR hash LIKE ? OR notes LIKE ? OR tags LIKE ?)"
        )
        params.extend([like] * 9)

    return conditions, params


_SORT_EXPRS = {
    "username":   "LOWER(COALESCE(entries.username, ''))",
    "host":       "LOWER(COALESCE(entries.host, ''))",
    "domain":     "LOWER(COALESCE(entries.domain, ''))",
    "service":    "LOWER(COALESCE(entries.service, ''))",
    "hash_type":  "LOWER(COALESCE(entries.hash_type, ''))",
    "created_at": "entries.created_at",
    "updated_at": "entries.updated_at",
}


def build_entry_filter(p):
    """Shared by /api/entries and /api/entries/export so they never drift apart.

    target_id is only applied when explicitly given (a selected sidebar facet,
    or a target: operator) — with no target selected, search covers every
    target, per the intended UX.
    """
    raw_target = p.get("target_id", "").strip()
    search = p.get("search", "").strip()
    notes_only = p.get("notes_only", "").lower() in ("1", "true")
    reused_only = p.get("reused_only", "").lower() in ("1", "true")
    userpass_only = p.get("userpass_only", "").lower() in ("1", "true")

    where, params = ["1=1"], []

    if raw_target == "none":
        where.append("target_id IS NULL")
    elif raw_target:
        try:
            where.append("target_id = ?")
            params.append(int(raw_target))
        except ValueError:
            pass

    if search:
        conds, sparams = parse_search_query(search)
        where.extend(conds)
        params.extend(sparams)

    if notes_only:
        where.append("(notes IS NOT NULL AND TRIM(notes) != '')")

    if reused_only:
        where.append(f"(({_PW_REUSE_EXPR}) > 1 OR ({_HASH_REUSE_EXPR}) > 1)")

    if userpass_only:
        where.append(_HAS_USERPASS_EXPR)

    sort_by = p.get("sort_by", "").strip()
    sort_dir = p.get("sort_dir", "desc").lower()
    if sort_dir not in ("asc", "desc"):
        sort_dir = "desc"
    if sort_by and sort_by in _SORT_EXPRS:
        order_sql = f"{_SORT_EXPRS[sort_by]} {sort_dir.upper()} NULLS LAST, entries.id DESC"
    else:
        order_sql = "entries.created_at DESC, entries.id DESC"

    return " AND ".join(where), params, order_sql


_LIST_COLUMNS = f"""
    entries.id, entries.target_id, targets.name AS target_name,
    entries.username, entries.password, entries.password_is_blank,
    entries.host, entries.domain, entries.service,
    entries.hash_type, entries.hash, entries.notes, entries.tags,
    entries.created_at, entries.updated_at,
    ({_PW_REUSE_EXPR}) AS password_reuse_count,
    ({_HASH_REUSE_EXPR}) AS hash_reuse_count
"""


def _row_to_entry(row):
    d = dict(row)
    d["tags"] = json.loads(d.get("tags") or "[]")
    d["password_is_blank"] = bool(d.get("password_is_blank"))
    d["password_reuse_count"] = d.get("password_reuse_count") or 0
    d["hash_reuse_count"] = d.get("hash_reuse_count") or 0
    return d


# ── Routes: pages ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ── Routes: targets ───────────────────────────────────────────────────────────

@app.route("/api/targets")
def api_list_targets():
    with get_db() as conn:
        rows = conn.execute("""
            SELECT t.*, COUNT(e.id) AS entry_count
            FROM targets t
            LEFT JOIN entries e ON e.target_id = t.id
            GROUP BY t.id
            ORDER BY LOWER(t.name)
        """).fetchall()
        unassigned = conn.execute(
            "SELECT COUNT(*) FROM entries WHERE target_id IS NULL"
        ).fetchone()[0]
    return jsonify({
        "targets": [dict(r) for r in rows],
        "unassigned_count": unassigned,
    })


@app.route("/api/targets", methods=["POST"])
def api_create_target():
    body = request.get_json(silent=True) or {}
    name = str(body.get("name", "")).strip()
    description = str(body.get("description", "")).strip() or None
    if not name:
        return jsonify(error="Name is required"), 400
    try:
        with get_db() as conn:
            cur = conn.execute(
                "INSERT INTO targets (name, description) VALUES (?, ?)",
                (name, description),
            )
            tid = cur.lastrowid
    except sqlite3.IntegrityError:
        return jsonify(error="A target with that name already exists"), 409
    return jsonify({"id": tid, "name": name, "description": description}), 201


@app.route("/api/targets/<int:tid>", methods=["PATCH"])
def api_update_target(tid):
    body = request.get_json(silent=True) or {}
    with get_db() as conn:
        row = conn.execute("SELECT * FROM targets WHERE id=?", (tid,)).fetchone()
        if not row:
            return jsonify(error="Not found"), 404
        name = body.get("name", row["name"])
        name = str(name).strip()
        if not name:
            return jsonify(error="Name cannot be empty"), 400
        description = body.get("description", row["description"])
        description = (str(description).strip() or None) if description is not None else None
        try:
            conn.execute(
                "UPDATE targets SET name=?, description=? WHERE id=?",
                (name, description, tid),
            )
        except sqlite3.IntegrityError:
            return jsonify(error="A target with that name already exists"), 409
    return jsonify({"id": tid, "name": name, "description": description})


@app.route("/api/targets/<int:tid>", methods=["DELETE"])
def api_delete_target(tid):
    with get_db() as conn:
        row = conn.execute("SELECT 1 FROM targets WHERE id=?", (tid,)).fetchone()
        if not row:
            return jsonify(error="Not found"), 404
        conn.execute("DELETE FROM targets WHERE id=?", (tid,))
    return jsonify(ok=True)


# ── Routes: entries ────────────────────────────────────────────────────────────

@app.route("/api/entries")
def api_list_entries():
    p = request.args
    page = max(1, p.get("page", 1, type=int))
    per_page = min(200, max(10, p.get("per_page", 50, type=int)))

    sql_where, params, order_sql = build_entry_filter(p)
    offset = (page - 1) * per_page

    with get_db() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) FROM entries WHERE {sql_where}", params
        ).fetchone()[0]

        rows = conn.execute(
            f"""SELECT {_LIST_COLUMNS}
                FROM entries LEFT JOIN targets ON targets.id = entries.target_id
                WHERE {sql_where}
                ORDER BY {order_sql}
                LIMIT ? OFFSET ?""",
            params + [per_page, offset],
        ).fetchall()

    return jsonify({
        "total": total,
        "page": page,
        "per_page": per_page,
        "entries": [_row_to_entry(r) for r in rows],
    })


REQUIRED_ANY = ("username", "password", "hash")
EDITABLE_FIELDS = ("username", "password", "host", "domain", "service",
                   "hash_type", "hash", "notes")


def _clean(v):
    if v is None:
        return None
    v = str(v).strip()
    return v or None


def _timestamp_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _apply_password_lock(body, values):
    """A locked password (password_is_blank=true in the request) is a
    *confirmed* empty password, stored as a real empty string rather than
    being collapsed to None by _clean() like a merely-omitted field would be."""
    if body.get("password_is_blank"):
        values["password"] = ""
        values["password_is_blank"] = True
    else:
        values["password_is_blank"] = False


def _values_has_password(values):
    return bool(values.get("password_is_blank")) or bool((values.get("password") or "").strip())


def _row_has_password(row):
    return bool(row["password_is_blank"]) or bool((row["password"] or "").strip())


def _insert_entry(conn, target_id, values, tags):
    cur = conn.execute(
        """INSERT INTO entries (target_id, username, password, password_is_blank, host, domain,
                                 service, hash_type, hash, notes, tags)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (target_id, values.get("username"), values.get("password"),
         int(bool(values.get("password_is_blank"))), values.get("host"),
         values.get("domain"), values.get("service"), values.get("hash_type"), values.get("hash"),
         values.get("notes"), json.dumps(tags) if tags else None),
    )
    return cur.lastrowid


def _merge_or_create_entry(conn, target_id, values, tags):
    """Create a new entry, or merge into an existing one with the same username
    in the same target — shared by the single "Add Entry" form, PATCH updates
    that change the username, and bulk import, so all three behave identically:

      - no existing username match (in this target)              -> insert
      - existing already has a value in a field we're setting     -> insert   (a second, distinct finding)
      - existing has the *other* credential field set, not this   -> annotate (flag #check + note, don't overwrite)
      - existing has neither password nor hash                    -> update in place, filling in what's given

    A locked (confirmed-blank) password counts as "has a password" throughout,
    same as any other set value.

    Returns (action, entry_id) where action is 'inserted', 'updated', or 'annotated'.
    """
    username = values.get("username")
    existing = None
    if username:
        existing = conn.execute(
            "SELECT * FROM entries WHERE username = ? AND target_id IS ?",
            (username, target_id),
        ).fetchone()

    if not existing:
        return ("inserted", _insert_entry(conn, target_id, values, tags))

    pw_conflict = _values_has_password(values) and _row_has_password(existing)
    hash_conflict = bool(values.get("hash")) and bool((existing["hash"] or "").strip())
    if pw_conflict or hash_conflict:
        return ("inserted", _insert_entry(conn, target_id, values, tags))

    pw_flag = _values_has_password(values) and bool((existing["hash"] or "").strip())
    hash_flag = bool(values.get("hash")) and _row_has_password(existing)

    if pw_flag or hash_flag:
        note_bits = []
        if pw_flag:
            pw_display = "(blank)" if values.get("password_is_blank") else values["password"]
            note_bits.append(f"Possible password: {pw_display}")
        if hash_flag:
            note_bits.append(f"Possible hash: {values['hash']}")
        if values.get("notes"):
            note_bits.append(values["notes"])
        note_line = f"[{_timestamp_now()}] " + "; ".join(note_bits)
        prev_notes = existing["notes"]
        new_notes = f"{prev_notes}\n{note_line}" if prev_notes else note_line

        set_parts, params = ["notes=?"], [new_notes]
        for f in ("host", "domain", "service"):
            if values.get(f):
                set_parts.append(f"{f}=?")
                params.append(values[f])

        cur_tags = json.loads(existing["tags"] or "[]")
        for t in (["check"] + tags):
            if t not in cur_tags:
                cur_tags.append(t)
        set_parts.append("tags=?")
        params.append(json.dumps(cur_tags) if cur_tags else None)

        set_parts.append("updated_at=datetime('now')")
        conn.execute(f"UPDATE entries SET {', '.join(set_parts)} WHERE id=?", params + [existing["id"]])
        return ("annotated", existing["id"])

    # Existing has neither password nor hash -> fill in whatever was provided.
    set_parts, params = [], []
    if values.get("password_is_blank"):
        set_parts += ["password=?", "password_is_blank=?"]
        params += ["", 1]
    elif values.get("password"):
        set_parts.append("password=?")
        params.append(values["password"])
    for f in ("host", "domain", "service", "hash_type", "hash"):
        if values.get(f):
            set_parts.append(f"{f}=?")
            params.append(values[f])
    if values.get("notes"):
        prev_notes = existing["notes"]
        new_notes = f"{prev_notes}\n{values['notes']}" if prev_notes else values["notes"]
        set_parts.append("notes=?")
        params.append(new_notes)
    if tags:
        cur_tags = json.loads(existing["tags"] or "[]")
        merged = list(dict.fromkeys(cur_tags + tags))
        set_parts.append("tags=?")
        params.append(json.dumps(merged) if merged else None)

    if not set_parts:
        return ("updated", existing["id"])

    set_parts.append("updated_at=datetime('now')")
    conn.execute(f"UPDATE entries SET {', '.join(set_parts)} WHERE id=?", params + [existing["id"]])
    return ("updated", existing["id"])


@app.route("/api/entries", methods=["POST"])
def api_create_entry():
    body = request.get_json(silent=True) or {}

    values = {f: _clean(body.get(f)) for f in EDITABLE_FIELDS}
    _apply_password_lock(body, values)
    if not (values["username"] or values["hash"] or _values_has_password(values)):
        return jsonify(error="Entry needs at least a username, password, or hash"), 400

    target_id = body.get("target_id")
    target_id = int(target_id) if target_id else None

    tags = body.get("tags") or []
    if not isinstance(tags, list):
        tags = []
    tags = list(dict.fromkeys(t.strip().lstrip('#') for t in tags if isinstance(t, str) and t.strip()))

    with get_db() as conn:
        if target_id and not conn.execute("SELECT 1 FROM targets WHERE id=?", (target_id,)).fetchone():
            return jsonify(error="Unknown target_id"), 400
        action, eid = _merge_or_create_entry(conn, target_id, values, tags)

    resp = api_get_entry(eid).get_json()
    resp["_merge_action"] = action
    status = 201 if action == "inserted" else 200
    return jsonify(resp), status


@app.route("/api/entries/<int:eid>")
def api_get_entry(eid):
    with get_db() as conn:
        row = conn.execute(
            f"""SELECT {_LIST_COLUMNS}
                FROM entries LEFT JOIN targets ON targets.id = entries.target_id
                WHERE entries.id=?""",
            (eid,),
        ).fetchone()
        if not row:
            return jsonify(error="Not found"), 404
        d = _row_to_entry(row)

        if d["password_reuse_count"] > 1:
            reuse = conn.execute(
                f"""SELECT entries.id, entries.username, targets.name AS target_name
                    FROM entries LEFT JOIN targets ON targets.id = entries.target_id
                    WHERE entries.password = ? AND entries.id != ?""",
                (row["password"], eid),
            ).fetchall()
            d["reused_password_with"] = [dict(r) for r in reuse]
        else:
            d["reused_password_with"] = []

        if d["hash_reuse_count"] > 1:
            reuse = conn.execute(
                f"""SELECT entries.id, entries.username, targets.name AS target_name
                    FROM entries LEFT JOIN targets ON targets.id = entries.target_id
                    WHERE entries.hash = ? AND entries.id != ?""",
                (row["hash"], eid),
            ).fetchall()
            d["reused_hash_with"] = [dict(r) for r in reuse]
        else:
            d["reused_hash_with"] = []

    return jsonify(d)


@app.route("/api/entries/<int:eid>", methods=["PATCH"])
def api_update_entry(eid):
    body = request.get_json(silent=True) or {}

    with get_db() as conn:
        row = conn.execute("SELECT * FROM entries WHERE id=?", (eid,)).fetchone()
        if not row:
            return jsonify(error="Not found"), 404

        values = {}
        for f in EDITABLE_FIELDS:
            if f in body:
                values[f] = _clean(body[f])
            else:
                values[f] = row[f]

        if "password_is_blank" in body:
            if body.get("password_is_blank"):
                values["password"] = ""
                values["password_is_blank"] = True
            else:
                values["password_is_blank"] = False
        else:
            values["password_is_blank"] = bool(row["password_is_blank"])
            if values["password_is_blank"] and "password" not in body:
                values["password"] = ""

        if not (values["username"] or values["hash"] or _values_has_password(values)):
            return jsonify(error="Entry needs at least a username, password, or hash"), 400

        target_id = row["target_id"]
        if "target_id" in body:
            target_id = int(body["target_id"]) if body["target_id"] else None
            if target_id and not conn.execute("SELECT 1 FROM targets WHERE id=?", (target_id,)).fetchone():
                return jsonify(error="Unknown target_id"), 400

        conn.execute(
            """UPDATE entries SET target_id=?, username=?, password=?, password_is_blank=?, host=?, domain=?,
                                   service=?, hash_type=?, hash=?, notes=?, updated_at=datetime('now')
               WHERE id=?""",
            (target_id, values["username"], values["password"], int(values["password_is_blank"]),
             values["host"], values["domain"], values["service"], values["hash_type"], values["hash"],
             values["notes"], eid),
        )

    return api_get_entry(eid)


@app.route("/api/entries/<int:eid>/tags", methods=["PATCH"])
def api_set_entry_tags(eid):
    body = request.get_json(silent=True) or {}
    raw = body.get("tags", [])
    if not isinstance(raw, list):
        return jsonify(error="tags must be an array"), 400
    cleaned = list(dict.fromkeys(
        t.strip().lstrip('#') for t in raw if isinstance(t, str) and t.strip()
    ))
    with get_db() as conn:
        if not conn.execute("SELECT 1 FROM entries WHERE id=?", (eid,)).fetchone():
            return jsonify(error="Not found"), 404
        conn.execute(
            "UPDATE entries SET tags=?, updated_at=datetime('now') WHERE id=?",
            (json.dumps(cleaned) if cleaned else None, eid),
        )
    return jsonify({"tags": cleaned})


@app.route("/api/entries/<int:eid>", methods=["DELETE"])
def api_delete_entry(eid):
    with get_db() as conn:
        row = conn.execute("SELECT 1 FROM entries WHERE id=?", (eid,)).fetchone()
        if not row:
            return jsonify(error="Not found"), 404
        conn.execute("DELETE FROM entries WHERE id=?", (eid,))
    return jsonify(ok=True)


# ── Bulk edit / delete (apply a change to a set of selected entries) ──────────

def _int_list(raw):
    out = []
    for v in (raw or []):
        try:
            out.append(int(v))
        except (TypeError, ValueError):
            pass
    return list(dict.fromkeys(out))


@app.route("/api/entries/bulk", methods=["PATCH"])
def api_bulk_update_entries():
    body = request.get_json(silent=True) or {}
    ids = _int_list(body.get("ids"))
    if not ids:
        return jsonify(error="No ids provided"), 400

    raw_fields = body.get("fields") or {}
    if not isinstance(raw_fields, dict):
        return jsonify(error="fields must be an object"), 400

    target_id_set = "target_id" in raw_fields
    target_id_val = None
    if target_id_set:
        raw = raw_fields.pop("target_id")
        target_id_val = int(raw) if raw else None

    clean_fields = {f: _clean(v) for f, v in raw_fields.items() if f in EDITABLE_FIELDS}

    tags_add = [t.strip().lstrip('#') for t in (body.get("tags_add") or []) if isinstance(t, str) and t.strip()]
    tags_remove = [t.strip().lstrip('#') for t in (body.get("tags_remove") or []) if isinstance(t, str) and t.strip()]

    if not clean_fields and not target_id_set and not tags_add and not tags_remove:
        return jsonify(error="No changes specified"), 400

    with get_db() as conn:
        if target_id_set and target_id_val and not conn.execute(
            "SELECT 1 FROM targets WHERE id=?", (target_id_val,)
        ).fetchone():
            return jsonify(error="Unknown target_id"), 400

        placeholders = ",".join("?" * len(ids))
        rows = conn.execute(f"SELECT * FROM entries WHERE id IN ({placeholders})", ids).fetchall()
        found_ids = {r["id"] for r in rows}
        not_found = [i for i in ids if i not in found_ids]

        updated_ids = []
        skipped_empty = []
        for r in rows:
            merged = {f: (clean_fields[f] if f in clean_fields else r[f]) for f in REQUIRED_ANY}
            has_password = bool(merged.get("password")) or bool(r["password_is_blank"])
            if not (merged.get("username") or merged.get("hash") or has_password):
                skipped_empty.append(r["id"])
            else:
                updated_ids.append(r["id"])

        if updated_ids and (clean_fields or target_id_set):
            set_parts = [f"{f}=?" for f in clean_fields]
            params = list(clean_fields.values())
            if target_id_set:
                set_parts.append("target_id=?")
                params.append(target_id_val)
            set_parts.append("updated_at=datetime('now')")
            ph2 = ",".join("?" * len(updated_ids))
            conn.execute(
                f"UPDATE entries SET {', '.join(set_parts)} WHERE id IN ({ph2})",
                params + updated_ids,
            )

        if tags_add or tags_remove:
            for r in rows:
                cur_tags = json.loads(r["tags"] or "[]")
                cur_tags = [t for t in cur_tags if t not in tags_remove]
                for t in tags_add:
                    if t not in cur_tags:
                        cur_tags.append(t)
                conn.execute(
                    "UPDATE entries SET tags=?, updated_at=datetime('now') WHERE id=?",
                    (json.dumps(cur_tags) if cur_tags else None, r["id"]),
                )

    return jsonify({
        "updated": len(updated_ids),
        "tagged": len(rows) if (tags_add or tags_remove) else 0,
        "skipped_empty": skipped_empty,
        "not_found": not_found,
    })


@app.route("/api/entries/bulk", methods=["DELETE"])
def api_bulk_delete_entries():
    body = request.get_json(silent=True) or {}
    ids = _int_list(body.get("ids"))
    if not ids:
        return jsonify(error="No ids provided"), 400
    with get_db() as conn:
        placeholders = ",".join("?" * len(ids))
        cur = conn.execute(f"DELETE FROM entries WHERE id IN ({placeholders})", ids)
    return jsonify({"deleted": cur.rowcount})


# ── Bulk import ────────────────────────────────────────────────────────────────

_KNOWN_CSV_FIELDS = {
    "username": "username", "user": "username",
    "password": "password", "pass": "password",
    "host": "host", "ip": "host",
    "domain": "domain",
    "service": "service", "port": "service",
    "hash_type": "hash_type", "hashtype": "hash_type",
    "hash": "hash",
    "notes": "notes", "note": "notes",
    "tags": "tags", "tag": "tags",
    "target": "target", "target_name": "target",
}


def _parse_bulk_lines(text, fmt, default_hash_type):
    rows, skipped, errors = [], 0, []
    for i, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if fmt == "user_pass":
            if ":" not in line:
                skipped += 1
                errors.append(f"line {i}: no ':' separator")
                continue
            user, pw = line.split(":", 1)
            user, pw = user.strip(), pw.strip()
            if not user and not pw:
                skipped += 1
                continue
            rows.append({"username": user or None, "password": pw or None})

        elif fmt == "user_hash":
            if ":" not in line:
                skipped += 1
                errors.append(f"line {i}: no ':' separator")
                continue
            user, h = line.split(":", 1)
            user, h = user.strip(), h.strip()
            if not user and not h:
                skipped += 1
                continue
            rows.append({"username": user or None, "hash": h or None,
                         "hash_type": default_hash_type or None})

        elif fmt == "secretsdump":
            parts = line.split(":")
            if len(parts) < 4:
                skipped += 1
                errors.append(f"line {i}: expected user:rid:lm:nt[:::]")
                continue
            user, nt = parts[0].strip(), parts[3].strip()
            if not user or not nt:
                skipped += 1
                errors.append(f"line {i}: missing username or NT hash")
                continue
            rows.append({"username": user, "hash": nt, "hash_type": "NTLM"})

        else:
            skipped += 1
            errors.append(f"line {i}: unknown format")

    return rows, skipped, errors


def _parse_bulk_csv(text):
    rows, skipped, errors = [], 0, []
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return rows, 0, ["CSV has no header row"]
    field_map = {}
    for col in reader.fieldnames:
        key = _KNOWN_CSV_FIELDS.get(col.strip().lower())
        if key:
            field_map[col] = key
    if not field_map:
        return rows, 0, ["No recognized columns in CSV header " +
                          "(expected some of: username, password, host, domain, service, hash_type, hash, notes, tags)"]

    for i, csv_row in enumerate(reader, start=2):
        entry = {}
        for col, key in field_map.items():
            val = (csv_row.get(col) or "").strip()
            if not val:
                continue
            if key == "tags":
                entry["tags"] = [t.strip().lstrip('#') for t in re.split(r"[;,]", val) if t.strip()]
            else:
                entry[key] = val
        if not entry:
            skipped += 1
            continue
        if not any(entry.get(f) for f in REQUIRED_ANY):
            skipped += 1
            errors.append(f"row {i}: no username, password, or hash")
            continue
        rows.append(entry)

    return rows, skipped, errors


# user_pass / user_hash / secretsdump rows contribute a single credential value
# per username, so they go through the same conflict-aware merge as the "Add
# Entry" form. CSV rows can carry an arbitrary mix of fields, so they're
# always inserted as new entries rather than guessed at.
_MERGE_ELIGIBLE_FORMATS = {"user_pass", "user_hash", "secretsdump"}


@app.route("/api/entries/bulk_import", methods=["POST"])
def api_bulk_import():
    body = request.get_json(silent=True) or {}
    fmt = body.get("format", "")
    text = body.get("text", "") or ""
    target_id = body.get("target_id")
    target_id = int(target_id) if target_id else None
    default_hash_type = _clean(body.get("hash_type"))
    common_tags = body.get("tags") or []
    if not isinstance(common_tags, list):
        common_tags = []
    common_tags = [t.strip().lstrip('#') for t in common_tags if isinstance(t, str) and t.strip()]

    if not text.strip():
        return jsonify(error="No data to import"), 400

    with get_db() as conn:
        if target_id and not conn.execute("SELECT 1 FROM targets WHERE id=?", (target_id,)).fetchone():
            return jsonify(error="Unknown target_id"), 400

        if fmt == "csv":
            rows, skipped, errors = _parse_bulk_csv(text)
        elif fmt in ("user_pass", "user_hash", "secretsdump"):
            rows, skipped, errors = _parse_bulk_lines(text, fmt, default_hash_type)
        else:
            return jsonify(error="Unknown format"), 400

        merge_eligible = fmt in _MERGE_ELIGIBLE_FORMATS

        created = updated = annotated = 0
        for entry in rows:
            row_target_id = target_id
            if entry.get("target") and not target_id:
                trow = conn.execute(
                    "SELECT id FROM targets WHERE LOWER(name)=LOWER(?)", (entry["target"],)
                ).fetchone()
                if trow:
                    row_target_id = trow["id"]

            values = {f: _clean(entry.get(f)) for f in EDITABLE_FIELDS}
            row_tags = list(dict.fromkeys((entry.get("tags") or []) + common_tags))

            if merge_eligible:
                action, _eid = _merge_or_create_entry(conn, row_target_id, values, row_tags)
            else:
                _insert_entry(conn, row_target_id, values, row_tags)
                action = "inserted"

            if action == "inserted":
                created += 1
            elif action == "updated":
                updated += 1
            elif action == "annotated":
                annotated += 1

    return jsonify({
        "created": created,
        "updated": updated,
        "annotated": annotated,
        "skipped": skipped,
        "errors": errors[:50],
    })


# ── Markdown export ──────────────────────────────────────────────────────────

EXPORT_FIELDS = {
    "target_name": "Target",
    "username":    "Username",
    "password":    "Password",
    "host":        "Host",
    "domain":      "Domain",
    "service":     "Service",
    "hash_type":   "Hash Type",
    "hash":        "Hash",
    "tags":        "Tags",
    "notes":       "Notes",
    "created_at":  "Created",
    "updated_at":  "Updated",
}


def _export_field_value(row, field):
    if field == "tags":
        tags = json.loads(row["tags"] or "[]")
        return ", ".join("#" + t for t in tags) if tags else ""
    if field == "password" and row["password_is_blank"]:
        return "(empty)"
    val = row[field]
    return str(val) if val not in (None, "") else ""


def _md_escape(s):
    return s.replace("|", "\\|").replace("\n", " ").strip()


@app.route("/api/entries/export")
def api_export_entries():
    p = request.args
    sql_where, params, order_sql = build_entry_filter(p)

    fields = [f for f in p.get("fields", "").split(",") if f in EXPORT_FIELDS]
    if not fields:
        return jsonify(error="No valid fields selected"), 400

    needed_cols = {"entries.id AS id"}
    for f in fields:
        if f == "target_name":
            needed_cols.add("targets.name AS target_name")
        else:
            needed_cols.add(f"entries.{f} AS {f}")
    if "password" in fields:
        needed_cols.add("entries.password_is_blank AS password_is_blank")

    with get_db() as conn:
        rows = conn.execute(
            f"SELECT {', '.join(sorted(needed_cols))} "
            f"FROM entries LEFT JOIN targets ON targets.id = entries.target_id "
            f"WHERE {sql_where} ORDER BY {order_sql}",
            params,
        ).fetchall()

    headers = [EXPORT_FIELDS[f] for f in fields]
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append(
            "| " + " | ".join(_md_escape(_export_field_value(row, f)) for f in fields) + " |"
        )

    filename = f"ccm-export-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.md"
    return Response(
        "\n".join(lines) + "\n",
        mimetype="text/markdown",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ── Stats ──────────────────────────────────────────────────────────────────────

@app.route("/api/stats")
def api_stats():
    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
        users = conn.execute(
            "SELECT COUNT(DISTINCT username) FROM entries WHERE username IS NOT NULL AND TRIM(username) != ''"
        ).fetchone()[0]
        with_password = conn.execute(
            f"SELECT COUNT(*) FROM entries WHERE {_HAS_PASSWORD_VALUE_EXPR}"
        ).fetchone()[0]
        with_hash = conn.execute(
            "SELECT COUNT(*) FROM entries WHERE hash IS NOT NULL AND TRIM(hash) != ''"
        ).fetchone()[0]
        reused = conn.execute(
            f"SELECT COUNT(*) FROM entries WHERE ({_PW_REUSE_EXPR}) > 1 OR ({_HASH_REUSE_EXPR}) > 1"
        ).fetchone()[0]
        targets = conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0]

    return jsonify({
        "total": total,
        "users": users,
        "with_password": with_password,
        "with_hash": with_hash,
        "reused": reused,
        "targets": targets,
    })


# ── Backup ─────────────────────────────────────────────────────────────────────

@app.route("/api/backup")
def api_backup():
    tmp_path = DB_PATH.parent / f"_backup_{uuid.uuid4().hex}.db"
    try:
        src = sqlite3.connect(DB_PATH)
        dst = sqlite3.connect(tmp_path)
        src.backup(dst)
        src.close()
        dst.close()
        with open(tmp_path, "rb") as fh:
            raw = fh.read()
    finally:
        try:
            tmp_path.unlink()
        except OSError:
            pass

    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    filename = f"ccm-backup-{date_str}.db"
    return Response(
        raw,
        mimetype="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


if __name__ == "__main__":
    app.run(debug=True, port=5050)
