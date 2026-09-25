#!/bin/sh
DB="${DB_FILE:-/tmp/trojan_users.db}"
mkdir -p "$(dirname "$DB")"
sqlite3 "$DB" "CREATE TABLE IF NOT EXISTS connections (id INTEGER PRIMARY KEY AUTOINCREMENT, source_ip TEXT UNIQUE, connected_at TEXT DEFAULT CURRENT_TIMESTAMP, last_seen TEXT DEFAULT CURRENT_TIMESTAMP, duration TEXT DEFAULT '00:00:00', status TEXT DEFAULT 'ACTIVE', data_mb REAL DEFAULT 0.0);" 2>/dev/null || true
[ -n "${1:-}" ] && sqlite3 "$DB" "INSERT INTO connections(source_ip,last_seen,status) VALUES ('$1',CURRENT_TIMESTAMP,'ACTIVE') ON CONFLICT(source_ip) DO UPDATE SET last_seen=CURRENT_TIMESTAMP,status='ACTIVE';" 2>/dev/null || true
