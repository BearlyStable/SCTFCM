# CCM — CTF Credential Manager

A local, web-based scratchpad for credentials found during a CTF or pentest engagement — usernames, passwords, hashes, and the context around them (host, domain, service) — searchable, taggable, and exportable as a Markdown table.

Design and interaction patterns (dark theme, sidebar filters, `key:value` search operators, sortable table + detail panel, Markdown export with column selection) follow [Simple-ADExplorer](example_projects/Simple-ADExplorer).

---

## Features

- **SQLite storage** — everything persists locally in `src/instance/ccm.db`
- **Targets** — group entries by box / domain / engagement, with a sidebar facet list and counts; entries can also be left unassigned
- **Entries** with: username, password, hash type, hash, host/IP, domain, service/port, notes, tags — every field is optional except that an entry needs at least one of username, password, or hash
- **Search** — a search bar with partial/substring matching across every field, plus structured operators (`user:`, `pass:`, `host:`, `domain:`, `service:`, `hashtype:`, `hash:`, `tag:`, `userpass:yes`, `notes:yes`, `target:`, `reused:yes`, `reusedhash:yes`). Search always covers **every target** unless you select one in the sidebar or use the `target:` operator.
- **Password / hash reuse detection** — entries that share a password or hash with another entry (even across targets) are flagged in the table and cross-linked in the detail panel, so finding "where else does this password work" is one click
- **Editable in place** — click any row to open the detail panel and edit every field (including moving an entry to a different target), edit notes, and manage tags; changes save immediately
- **Bulk edit / bulk delete** — tick entries via the row checkboxes (or "select all" on the page) to edit a shared field (target, host, domain, service, hash type) or add/remove tags across all of them at once, or delete them in one go. Only fields you explicitly enable are changed; an entry that would end up with no username, password, or hash is skipped and reported rather than silently emptied.
- **Bulk import** — paste or drop a file to create many entries at once, in one of four formats: `user:pass`, `user:hash`, secretsdump-style (`user:rid:lm:nt:::`, auto-detected as NTLM), or CSV with a header row
- **Toggleable columns** — Password, Host/Domain, Hash, Target, Tags, Notes, and Updated can each be hidden via the "Columns" control when you don't need them visible; the choice is remembered in the browser
- **Markdown export** — export the entries matching the current filters (not just the current page) as a Markdown table, choosing which columns to include
- **Database backup** — download the full SQLite database from the Export dialog
- **Masked credentials** — passwords and hashes are masked in the table by default with a click-to-reveal toggle and a copy button, to avoid shoulder-surfing on a shared screen

---

## Requirements

- Python 3.10+
- `make` (optional, but simplest — used below; works as-is under WSL / Linux / macOS)

## Installation & running

Using the Makefile:

```bash
make setup   # creates .venv and installs dependencies
make run     # starts the server
```

Or manually:

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate
# macOS / Linux / WSL
source .venv/bin/activate

pip install -r requirements.txt
python src/app.py
```

The server starts on **http://localhost:5050**.

Run `make clean` to remove the virtual environment, database, and Python caches. Run `make help` to list all targets.

> **Note:** This application has no authentication and is intended for local/trusted-network use only — the data it stores (plaintext credentials, hashes) is sensitive. Do not expose it to an untrusted network.

---

## Project structure

```
CCM/
├── Makefile
├── requirements.txt
├── src/
│   ├── app.py            # Flask application — SQLite logic, search parser, REST API
│   ├── templates/
│   │   └── index.html    # HTML structure only
│   ├── static/
│   │   ├── style.css     # All custom styles (dark theme)
│   │   └── app.js        # All application logic (state, API calls, rendering)
│   └── instance/         # Created at runtime — contains ccm.db (SQLite)
```

---

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Main web UI |
| `GET` | `/api/targets` | List targets with entry counts |
| `POST` | `/api/targets` | Create a target (`{name, description}`) |
| `PATCH` | `/api/targets/<id>` | Rename / edit a target |
| `DELETE` | `/api/targets/<id>` | Delete a target (its entries become unassigned, not deleted) |
| `GET` | `/api/entries` | List entries with filters, search, sorting, pagination |
| `GET` | `/api/entries/<id>` | Full detail for one entry, including reuse cross-links |
| `POST` | `/api/entries` | Create an entry |
| `PATCH` | `/api/entries/<id>` | Update an entry's fields |
| `PATCH` | `/api/entries/<id>/tags` | Replace an entry's tag list (`{"tags": [...]}`) |
| `DELETE` | `/api/entries/<id>` | Delete an entry |
| `PATCH` | `/api/entries/bulk` | Apply field changes and/or tag add/remove to a set of entries (`{ids, fields, tags_add, tags_remove}`) |
| `DELETE` | `/api/entries/bulk` | Delete a set of entries (`{"ids": [...]}`) |
| `POST` | `/api/entries/bulk_import` | Create many entries from pasted text (see formats below) |
| `GET` | `/api/entries/export` | Download the current filtered view as a Markdown table |
| `GET` | `/api/stats` | Summary counts for the top stats bar |
| `GET` | `/api/backup` | Download the full SQLite database |

### `/api/entries` query parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `target_id` | int or `none` | Restrict to one target, or to unassigned entries |
| `search` | string | Search string — plain text or `key:value` operators (see below) |
| `userpass_only` | `1` | Only entries that have both a username and a password |
| `notes_only` | `1` | Only entries that have a note |
| `reused_only` | `1` | Only entries whose password or hash is reused elsewhere |
| `sort_by` | string | `username`, `host`, `domain`, `service`, `hash_type`, `created_at`, `updated_at` |
| `sort_dir` | `asc` / `desc` | Sort direction (default `desc`) |
| `page` / `per_page` | int | Pagination (`per_page` max `200`) |

## Search operators

Plain text searches every field. Multiple tokens combine with **AND**. Prefix any operator with `-` to negate it. `*` is a wildcard for `user:`, `pass:`, etc.

| Operator | Description | Example |
|----------|-------------|---------|
| `user:` | Username | `user:admin*` |
| `pass:` | Password | `pass:Summer*` |
| `host:` | Host / IP | `host:10.10.10.*` |
| `domain:` | Domain | `domain:corp.local` |
| `service:` | Service / port | `service:smb` |
| `hashtype:` | Hash type | `hashtype:ntlm` |
| `hash:` | Hash value | `hash:8846f7ea*` |
| `userpass:yes/no` | Has both a username and a password | `userpass:yes` |
| `notes:yes/no` | Has a note | `notes:yes` |
| `tag:value` | Tagged with value | `tag:domain-admin` |
| `target:value` | Target name (independent of the sidebar selection) | `target:DC01` |
| `reused:yes/no` | Password reused across entries | `reused:yes` |
| `reusedhash:yes/no` | Hash reused across entries | `reusedhash:yes` |

## Bulk import formats

| Format | Line shape | Notes |
|--------|-----------|-------|
| `user:pass` | `username:password` | One credential pair per line |
| `user:hash` | `username:hash` | Applies the "Hash Type" field (set in the modal) to every row |
| `secretsdump` | `username:rid:lmhash:nthash:::` | Extracts username + NT hash; hash type auto-set to `NTLM` |
| `csv` | Header row + rows | Recognized headers: `username`, `password`, `host`, `domain`, `service`, `hash_type`, `hash`, `notes`, `tags`, `target` (matched by existing target name, case-insensitive) |

A common set of tags and/or a target can be applied to every row of an import.

### What happens when the username already exists

For the `user:pass`, `user:hash`, and `secretsdump` formats, each imported line is checked against existing entries with the **same username in the same target** (unassigned counts as matching unassigned) before deciding what to do:

| Existing entry's state | Result |
|---|---|
| Already has a value in the field you're importing (e.g. it already has a password, and you're importing a password) | A **new, separate entry** is created — treated as a second, distinct finding rather than overwriting a possibly-still-valid credential. |
| Has the *other* credential field set, but not this one (e.g. it has a hash, you're importing a password) | The existing entry is **left as-is**, but gets tagged `#check` and the new value is appended to its Notes (e.g. `Possible password: ...`) — flagged for you to verify and merge by hand, since it's an assumption rather than a certainty. |
| Has neither a password nor a hash yet | The existing entry is **updated in place** with the new value — this is the "I found the password for a known user" case. |

`CSV` import always creates new entries and never merges, since a CSV row can carry an arbitrary mix of fields.

If duplicate usernames already exist within the same target (which can happen via the "always creates a new entry" case above), a later import matching that username will match one of them somewhat arbitrarily — worth cleaning up duplicates via Bulk Edit/Delete before relying on the merge behavior.

---

## License

No license specified — for personal / internal use.
