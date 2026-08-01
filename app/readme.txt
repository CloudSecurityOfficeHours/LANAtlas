## Architecture Rules

1. `api/` calls `services/` only — never `repositories/` or `database/` directly
2. `services/` calls `repositories/` only — never `database/` directly
3. `repositories/` calls `database/` only — all SQL lives here
4. `workers/` follows the same rules as `api/` — calls `services/` only
5. No raw SQL strings outside `repositories/`