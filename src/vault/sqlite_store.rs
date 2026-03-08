use std::path::Path;

use rusqlite::{params, Connection};

/// SQLite-backed storage layer for vault entries and metadata.
pub struct SqliteBackend {
    conn: Connection,
}

impl std::fmt::Debug for SqliteBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SqliteBackend { .. }")
    }
}

impl SqliteBackend {
    /// Create a new SQLite vault file at the given path with schema initialized.
    pub fn create(path: &Path) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;

        conn.execute_batch(
            "CREATE TABLE meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
             CREATE TABLE entries (
                 id TEXT PRIMARY KEY,
                 encrypted_blob BLOB NOT NULL,
                 enc_overview BLOB,
                 enc_details BLOB,
                 updated_at TEXT NOT NULL,
                 deleted INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE audit_log (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 timestamp TEXT NOT NULL,
                 agent_id TEXT,
                 entry_id TEXT,
                 action TEXT NOT NULL,
                 result TEXT NOT NULL,
                 details TEXT
             );
             CREATE TABLE agent_tokens (
                 id TEXT PRIMARY KEY,
                 agent_id TEXT NOT NULL,
                 scopes TEXT NOT NULL,
                 actions TEXT NOT NULL,
                 ttl_seconds INTEGER NOT NULL,
                 max_uses INTEGER,
                 uses INTEGER NOT NULL DEFAULT 0,
                 issued_at TEXT NOT NULL,
                 expires_at TEXT NOT NULL,
                 approved_by TEXT NOT NULL,
                 revoked INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE agent_requests (
                 id TEXT PRIMARY KEY,
                 agent_id TEXT NOT NULL,
                 scopes TEXT NOT NULL,
                 actions TEXT NOT NULL,
                 ttl INTEGER NOT NULL,
                 max_uses INTEGER,
                 reason TEXT NOT NULL,
                 created_at TEXT NOT NULL,
                 status TEXT NOT NULL DEFAULT 'pending'
             );
             CREATE INDEX idx_entries_updated ON entries(updated_at);
             CREATE INDEX idx_audit_timestamp ON audit_log(timestamp);",
        )?;

        Ok(Self { conn })
    }

    /// Open an existing SQLite vault file.
    /// Automatically migrates schema if agent tables are missing.
    pub fn open(path: &Path) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;

        // Migrate: add enc_overview and enc_details columns if missing
        let has_enc_overview: bool = conn
            .prepare("SELECT 1 FROM pragma_table_info('entries') WHERE name='enc_overview'")?
            .exists([])?;
        if !has_enc_overview {
            conn.execute_batch(
                "ALTER TABLE entries ADD COLUMN enc_overview BLOB;
                 ALTER TABLE entries ADD COLUMN enc_details BLOB;",
            )?;
        }

        // Migrate: add agent_tokens and agent_requests tables if missing
        let has_agent_tokens: bool = conn
            .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='agent_tokens'")?
            .exists([])?;
        if !has_agent_tokens {
            conn.execute_batch(
                "CREATE TABLE agent_tokens (
                     id TEXT PRIMARY KEY,
                     agent_id TEXT NOT NULL,
                     scopes TEXT NOT NULL,
                     actions TEXT NOT NULL,
                     ttl_seconds INTEGER NOT NULL,
                     max_uses INTEGER,
                     uses INTEGER NOT NULL DEFAULT 0,
                     issued_at TEXT NOT NULL,
                     expires_at TEXT NOT NULL,
                     approved_by TEXT NOT NULL,
                     revoked INTEGER NOT NULL DEFAULT 0
                 );
                 CREATE TABLE agent_requests (
                     id TEXT PRIMARY KEY,
                     agent_id TEXT NOT NULL,
                     scopes TEXT NOT NULL,
                     actions TEXT NOT NULL,
                     ttl INTEGER NOT NULL,
                     max_uses INTEGER,
                     reason TEXT NOT NULL,
                     created_at TEXT NOT NULL,
                     status TEXT NOT NULL DEFAULT 'pending'
                 );",
            )?;
        }

        Ok(Self { conn })
    }

    /// Set a metadata key-value pair.
    pub fn set_meta(&self, key: &str, value: &[u8]) -> Result<(), rusqlite::Error> {
        self.conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    /// Delete a metadata key.
    pub fn delete_meta(&self, key: &str) -> Result<bool, rusqlite::Error> {
        let rows = self.conn.execute(
            "DELETE FROM meta WHERE key = ?1",
            params![key],
        )?;
        Ok(rows > 0)
    }

    /// Get a metadata value by key.
    pub fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>, rusqlite::Error> {
        let mut stmt = self.conn.prepare("SELECT value FROM meta WHERE key = ?1")?;
        let mut rows = stmt.query(params![key])?;
        match rows.next()? {
            Some(row) => Ok(Some(row.get(0)?)),
            None => Ok(None),
        }
    }

    /// Load all non-deleted entries as (id, encrypted_blob) pairs.
    pub fn load_all_entries(&self) -> Result<Vec<(String, Vec<u8>)>, rusqlite::Error> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, encrypted_blob FROM entries WHERE deleted = 0")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        rows.collect()
    }

    /// Insert or update an entry with split encryption.
    pub fn upsert_entry(
        &self,
        id: &str,
        blob: &[u8],
        updated_at: &str,
    ) -> Result<(), rusqlite::Error> {
        self.conn.execute(
            "INSERT OR REPLACE INTO entries (id, encrypted_blob, updated_at, deleted) VALUES (?1, ?2, ?3, 0)",
            params![id, blob, updated_at],
        )?;
        Ok(())
    }

    /// Insert or update an entry with overview/detail split encryption.
    pub fn upsert_entry_split(
        &self,
        id: &str,
        blob: &[u8],
        enc_overview: &[u8],
        enc_details: &[u8],
        updated_at: &str,
    ) -> Result<(), rusqlite::Error> {
        self.conn.execute(
            "INSERT OR REPLACE INTO entries (id, encrypted_blob, enc_overview, enc_details, updated_at, deleted) VALUES (?1, ?2, ?3, ?4, ?5, 0)",
            params![id, blob, enc_overview, enc_details, updated_at],
        )?;
        Ok(())
    }

    /// Load all non-deleted entry overviews as (id, enc_overview) pairs.
    /// Returns None for enc_overview if the entry was stored before split encryption.
    pub fn load_all_overviews(&self) -> Result<Vec<(String, Option<Vec<u8>>)>, rusqlite::Error> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, enc_overview FROM entries WHERE deleted = 0")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Option<Vec<u8>>>(1)?))
        })?;
        rows.collect()
    }

    /// Load the encrypted details for a specific entry.
    pub fn load_entry_details(&self, id: &str) -> Result<Option<Vec<u8>>, rusqlite::Error> {
        let mut stmt = self
            .conn
            .prepare("SELECT enc_details FROM entries WHERE id = ?1 AND deleted = 0")?;
        let mut rows = stmt.query(params![id])?;
        match rows.next()? {
            Some(row) => Ok(row.get(0)?),
            None => Ok(None),
        }
    }

    /// Hard-delete an entry by ID.
    pub fn hard_delete_entry(&self, id: &str) -> Result<(), rusqlite::Error> {
        self.conn
            .execute("DELETE FROM entries WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// List all non-deleted entry IDs.
    pub fn list_entry_ids(&self) -> Result<Vec<String>, rusqlite::Error> {
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM entries WHERE deleted = 0")?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        rows.collect()
    }

    /// Force a WAL checkpoint (useful before file-copy sync).
    pub fn checkpoint(&self) -> Result<(), rusqlite::Error> {
        self.conn.pragma_update(None, "wal_checkpoint", "TRUNCATE")?;
        Ok(())
    }

    /// Check if a file starts with the SQLite magic bytes.
    pub fn is_sqlite_file(path: &Path) -> bool {
        std::fs::read(path)
            .map(|data| data.len() >= 16 && &data[..16] == b"SQLite format 3\0")
            .unwrap_or(false)
    }

    /// Get a reference to the underlying connection (for transactions).
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    // ---- Agent token storage ----

    /// Store an agent token (insert or replace).
    #[allow(clippy::too_many_arguments)]
    pub fn store_agent_token(
        &self,
        id: &str,
        agent_id: &str,
        scopes_json: &str,
        actions_json: &str,
        ttl_seconds: i64,
        max_uses: Option<i64>,
        uses: i64,
        issued_at: &str,
        expires_at: &str,
        approved_by: &str,
        revoked: bool,
    ) -> Result<(), rusqlite::Error> {
        self.conn.execute(
            "INSERT OR REPLACE INTO agent_tokens (id, agent_id, scopes, actions, ttl_seconds, max_uses, uses, issued_at, expires_at, approved_by, revoked) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![id, agent_id, scopes_json, actions_json, ttl_seconds, max_uses, uses, issued_at, expires_at, approved_by, revoked as i32],
        )?;
        Ok(())
    }

    /// Load all agent tokens.
    pub fn load_agent_tokens(
        &self,
    ) -> Result<Vec<AgentTokenRow>, rusqlite::Error> {
        let mut stmt = self.conn.prepare(
            "SELECT id, agent_id, scopes, actions, ttl_seconds, max_uses, uses, issued_at, expires_at, approved_by, revoked FROM agent_tokens",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(AgentTokenRow {
                id: row.get(0)?,
                agent_id: row.get(1)?,
                scopes: row.get(2)?,
                actions: row.get(3)?,
                ttl_seconds: row.get(4)?,
                max_uses: row.get(5)?,
                uses: row.get(6)?,
                issued_at: row.get(7)?,
                expires_at: row.get(8)?,
                approved_by: row.get(9)?,
                revoked: row.get::<_, i32>(10)? != 0,
            })
        })?;
        rows.collect()
    }

    /// Update uses count for a token.
    pub fn update_token_uses(&self, token_id: &str, uses: i64) -> Result<(), rusqlite::Error> {
        self.conn.execute(
            "UPDATE agent_tokens SET uses = ?1 WHERE id = ?2",
            params![uses, token_id],
        )?;
        Ok(())
    }

    /// Mark a token as revoked.
    pub fn set_token_revoked(&self, token_id: &str) -> Result<(), rusqlite::Error> {
        self.conn.execute(
            "UPDATE agent_tokens SET revoked = 1 WHERE id = ?1",
            params![token_id],
        )?;
        Ok(())
    }

    // ---- Agent request storage ----

    /// Store an agent access request.
    #[allow(clippy::too_many_arguments)]
    pub fn store_agent_request(
        &self,
        id: &str,
        agent_id: &str,
        scopes_json: &str,
        actions_json: &str,
        ttl: i64,
        max_uses: Option<i64>,
        reason: &str,
        created_at: &str,
        status: &str,
    ) -> Result<(), rusqlite::Error> {
        self.conn.execute(
            "INSERT OR REPLACE INTO agent_requests (id, agent_id, scopes, actions, ttl, max_uses, reason, created_at, status) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![id, agent_id, scopes_json, actions_json, ttl, max_uses, reason, created_at, status],
        )?;
        Ok(())
    }

    /// Load all agent requests.
    pub fn load_agent_requests(
        &self,
    ) -> Result<Vec<AgentRequestRow>, rusqlite::Error> {
        let mut stmt = self.conn.prepare(
            "SELECT id, agent_id, scopes, actions, ttl, max_uses, reason, created_at, status FROM agent_requests",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(AgentRequestRow {
                id: row.get(0)?,
                agent_id: row.get(1)?,
                scopes: row.get(2)?,
                actions: row.get(3)?,
                ttl: row.get(4)?,
                max_uses: row.get(5)?,
                reason: row.get(6)?,
                created_at: row.get(7)?,
                status: row.get(8)?,
            })
        })?;
        rows.collect()
    }

    /// Update request status.
    pub fn update_request_status(
        &self,
        request_id: &str,
        status: &str,
    ) -> Result<(), rusqlite::Error> {
        self.conn.execute(
            "UPDATE agent_requests SET status = ?1 WHERE id = ?2",
            params![status, request_id],
        )?;
        Ok(())
    }

    // ---- Audit log storage ----

    /// Record an audit log entry.
    pub fn record_audit(
        &self,
        timestamp: &str,
        agent_id: &str,
        entry_id: &str,
        action: &str,
        result: &str,
        details: Option<&str>,
    ) -> Result<(), rusqlite::Error> {
        self.conn.execute(
            "INSERT INTO audit_log (timestamp, agent_id, entry_id, action, result, details) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![timestamp, agent_id, entry_id, action, result, details],
        )?;
        Ok(())
    }

    /// Load audit log entries, optionally filtered by agent_id, limited to last N.
    pub fn load_audit_entries(
        &self,
        agent_id: Option<&str>,
        last_n: Option<usize>,
    ) -> Result<Vec<AuditRow>, rusqlite::Error> {
        let limit = last_n.unwrap_or(1000) as i64;
        if let Some(aid) = agent_id {
            let mut stmt = self.conn.prepare(
                "SELECT id, timestamp, agent_id, entry_id, action, result, details FROM audit_log WHERE agent_id = ?1 ORDER BY id DESC LIMIT ?2",
            )?;
            let rows = stmt.query_map(params![aid, limit], |row| {
                Ok(AuditRow {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    agent_id: row.get(2)?,
                    entry_id: row.get(3)?,
                    action: row.get(4)?,
                    result: row.get(5)?,
                    details: row.get(6)?,
                })
            })?;
            rows.collect()
        } else {
            let mut stmt = self.conn.prepare(
                "SELECT id, timestamp, agent_id, entry_id, action, result, details FROM audit_log ORDER BY id DESC LIMIT ?1",
            )?;
            let rows = stmt.query_map(params![limit], |row| {
                Ok(AuditRow {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    agent_id: row.get(2)?,
                    entry_id: row.get(3)?,
                    action: row.get(4)?,
                    result: row.get(5)?,
                    details: row.get(6)?,
                })
            })?;
            rows.collect()
        }
    }
}

/// Row data for an agent token read from SQLite.
#[derive(Debug, Clone)]
pub struct AgentTokenRow {
    pub id: String,
    pub agent_id: String,
    pub scopes: String,
    pub actions: String,
    pub ttl_seconds: i64,
    pub max_uses: Option<i64>,
    pub uses: i64,
    pub issued_at: String,
    pub expires_at: String,
    pub approved_by: String,
    pub revoked: bool,
}

/// Row data for an agent request read from SQLite.
#[derive(Debug, Clone)]
pub struct AgentRequestRow {
    pub id: String,
    pub agent_id: String,
    pub scopes: String,
    pub actions: String,
    pub ttl: i64,
    pub max_uses: Option<i64>,
    pub reason: String,
    pub created_at: String,
    pub status: String,
}

/// Row data for an audit log entry read from SQLite.
#[derive(Debug, Clone)]
pub struct AuditRow {
    pub id: i64,
    pub timestamp: String,
    pub agent_id: Option<String>,
    pub entry_id: Option<String>,
    pub action: String,
    pub result: String,
    pub details: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_create_and_open() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");
        SqliteBackend::create(&path).unwrap();
        assert!(path.exists());
        SqliteBackend::open(&path).unwrap();
    }

    #[test]
    fn test_meta_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");
        let db = SqliteBackend::create(&path).unwrap();

        db.set_meta("version", b"2").unwrap();
        assert_eq!(db.get_meta("version").unwrap().unwrap(), b"2");
    }

    #[test]
    fn test_meta_missing() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");
        let db = SqliteBackend::create(&path).unwrap();
        assert!(db.get_meta("nonexistent").unwrap().is_none());
    }

    #[test]
    fn test_delete_meta() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");
        let db = SqliteBackend::create(&path).unwrap();

        db.set_meta("key", b"val").unwrap();
        assert!(db.get_meta("key").unwrap().is_some());

        assert!(db.delete_meta("key").unwrap());
        assert!(db.get_meta("key").unwrap().is_none());
    }

    #[test]
    fn test_delete_meta_nonexistent() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");
        let db = SqliteBackend::create(&path).unwrap();

        assert!(!db.delete_meta("nonexistent").unwrap());
    }

    #[test]
    fn test_meta_overwrite() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");
        let db = SqliteBackend::create(&path).unwrap();

        db.set_meta("key", b"val1").unwrap();
        db.set_meta("key", b"val2").unwrap();
        assert_eq!(db.get_meta("key").unwrap().unwrap(), b"val2");
    }

    #[test]
    fn test_entry_upsert_and_load() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");
        let db = SqliteBackend::create(&path).unwrap();

        db.upsert_entry("id1", b"blob1", "2024-01-01T00:00:00Z")
            .unwrap();
        db.upsert_entry("id2", b"blob2", "2024-01-02T00:00:00Z")
            .unwrap();

        let entries = db.load_all_entries().unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_entry_upsert_overwrites() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");
        let db = SqliteBackend::create(&path).unwrap();

        db.upsert_entry("id1", b"old", "2024-01-01T00:00:00Z")
            .unwrap();
        db.upsert_entry("id1", b"new", "2024-01-02T00:00:00Z")
            .unwrap();

        let entries = db.load_all_entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1, b"new");
    }

    #[test]
    fn test_hard_delete() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");
        let db = SqliteBackend::create(&path).unwrap();

        db.upsert_entry("id1", b"blob", "2024-01-01T00:00:00Z")
            .unwrap();
        db.hard_delete_entry("id1").unwrap();

        let entries = db.load_all_entries().unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_list_entry_ids() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");
        let db = SqliteBackend::create(&path).unwrap();

        db.upsert_entry("a", b"1", "2024-01-01T00:00:00Z")
            .unwrap();
        db.upsert_entry("b", b"2", "2024-01-01T00:00:00Z")
            .unwrap();

        let ids = db.list_entry_ids().unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&"a".to_string()));
        assert!(ids.contains(&"b".to_string()));
    }

    #[test]
    fn test_checkpoint() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");
        let db = SqliteBackend::create(&path).unwrap();
        db.checkpoint().unwrap();
    }

    #[test]
    fn test_is_sqlite_file() {
        let dir = TempDir::new().unwrap();
        let sqlite_path = dir.path().join("test.db");
        SqliteBackend::create(&sqlite_path).unwrap();
        assert!(SqliteBackend::is_sqlite_file(&sqlite_path));

        let non_sqlite = dir.path().join("not.db");
        std::fs::write(&non_sqlite, b"not a sqlite file").unwrap();
        assert!(!SqliteBackend::is_sqlite_file(&non_sqlite));

        assert!(!SqliteBackend::is_sqlite_file(&dir.path().join("missing")));
    }

    #[test]
    fn test_debug_format() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");
        let db = SqliteBackend::create(&path).unwrap();
        assert_eq!(format!("{:?}", db), "SqliteBackend { .. }");
    }

    #[test]
    fn test_agent_token_store_and_load() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");
        let db = SqliteBackend::create(&path).unwrap();

        db.store_agent_token(
            "tok-1", "agent-1", "[\"id1\"]", "[\"read\"]",
            3600, Some(10), 0, "2024-01-01T00:00:00Z",
            "2024-01-01T01:00:00Z", "admin", false,
        ).unwrap();

        let tokens = db.load_agent_tokens().unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].id, "tok-1");
        assert_eq!(tokens[0].agent_id, "agent-1");
        assert_eq!(tokens[0].uses, 0);
        assert!(!tokens[0].revoked);
    }

    #[test]
    fn test_agent_token_update_uses() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");
        let db = SqliteBackend::create(&path).unwrap();

        db.store_agent_token(
            "tok-1", "agent-1", "[]", "[]",
            3600, None, 0, "2024-01-01T00:00:00Z",
            "2024-01-01T01:00:00Z", "admin", false,
        ).unwrap();

        db.update_token_uses("tok-1", 5).unwrap();
        let tokens = db.load_agent_tokens().unwrap();
        assert_eq!(tokens[0].uses, 5);
    }

    #[test]
    fn test_agent_token_revoke() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");
        let db = SqliteBackend::create(&path).unwrap();

        db.store_agent_token(
            "tok-1", "agent-1", "[]", "[]",
            3600, None, 0, "2024-01-01T00:00:00Z",
            "2024-01-01T01:00:00Z", "admin", false,
        ).unwrap();

        db.set_token_revoked("tok-1").unwrap();
        let tokens = db.load_agent_tokens().unwrap();
        assert!(tokens[0].revoked);
    }

    #[test]
    fn test_agent_request_store_and_load() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");
        let db = SqliteBackend::create(&path).unwrap();

        db.store_agent_request(
            "req-1", "agent-1", "[\"id1\"]", "[\"read\"]",
            3600, Some(10), "deploy", "2024-01-01T00:00:00Z", "pending",
        ).unwrap();

        let reqs = db.load_agent_requests().unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].id, "req-1");
        assert_eq!(reqs[0].status, "pending");
    }

    #[test]
    fn test_agent_request_update_status() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");
        let db = SqliteBackend::create(&path).unwrap();

        db.store_agent_request(
            "req-1", "agent-1", "[]", "[]",
            3600, None, "test", "2024-01-01T00:00:00Z", "pending",
        ).unwrap();

        db.update_request_status("req-1", "approved").unwrap();
        let reqs = db.load_agent_requests().unwrap();
        assert_eq!(reqs[0].status, "approved");
    }

    #[test]
    fn test_audit_record_and_load() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");
        let db = SqliteBackend::create(&path).unwrap();

        db.record_audit(
            "2024-01-01T00:00:00Z", "agent-1", "entry-1",
            "read", "success", Some("test details"),
        ).unwrap();
        db.record_audit(
            "2024-01-01T00:01:00Z", "agent-2", "entry-2",
            "use", "denied", None,
        ).unwrap();

        let entries = db.load_audit_entries(None, None).unwrap();
        assert_eq!(entries.len(), 2);

        let filtered = db.load_audit_entries(Some("agent-1"), None).unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].agent_id.as_deref(), Some("agent-1"));
    }

    #[test]
    fn test_audit_load_with_limit() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");
        let db = SqliteBackend::create(&path).unwrap();

        for i in 0..5 {
            db.record_audit(
                &format!("2024-01-01T00:0{}:00Z", i), "agent-1", "entry-1",
                "read", "success", None,
            ).unwrap();
        }

        let entries = db.load_audit_entries(None, Some(3)).unwrap();
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn test_open_migrates_agent_tables() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");

        // Create a DB without agent tables (simulate old v2 schema)
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
             CREATE TABLE entries (id TEXT PRIMARY KEY, encrypted_blob BLOB NOT NULL, updated_at TEXT NOT NULL, deleted INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, agent_id TEXT, entry_id TEXT, action TEXT NOT NULL, result TEXT NOT NULL, details TEXT);",
        ).unwrap();
        drop(conn);

        // Open should migrate
        let db = SqliteBackend::open(&path).unwrap();

        // Should be able to use agent tables now
        db.store_agent_token(
            "tok-1", "agent-1", "[]", "[]",
            3600, None, 0, "2024-01-01T00:00:00Z",
            "2024-01-01T01:00:00Z", "admin", false,
        ).unwrap();
        let tokens = db.load_agent_tokens().unwrap();
        assert_eq!(tokens.len(), 1);
    }

    #[test]
    fn test_open_does_not_duplicate_tables() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");

        // Create with full schema
        SqliteBackend::create(&path).unwrap();

        // Open again should not fail
        let db = SqliteBackend::open(&path).unwrap();
        db.store_agent_token(
            "tok-1", "agent-1", "[]", "[]",
            3600, None, 0, "2024-01-01T00:00:00Z",
            "2024-01-01T01:00:00Z", "admin", false,
        ).unwrap();
        assert_eq!(db.load_agent_tokens().unwrap().len(), 1);
    }

    #[test]
    fn test_agent_token_max_uses_null() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");
        let db = SqliteBackend::create(&path).unwrap();

        db.store_agent_token(
            "tok-1", "agent-1", "[]", "[]",
            3600, None, 0, "2024-01-01T00:00:00Z",
            "2024-01-01T01:00:00Z", "admin", false,
        ).unwrap();

        let tokens = db.load_agent_tokens().unwrap();
        assert!(tokens[0].max_uses.is_none());
    }

    #[test]
    fn test_agent_token_upsert_overwrites() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");
        let db = SqliteBackend::create(&path).unwrap();

        db.store_agent_token(
            "tok-1", "agent-1", "[]", "[]",
            3600, None, 0, "2024-01-01T00:00:00Z",
            "2024-01-01T01:00:00Z", "admin", false,
        ).unwrap();
        db.store_agent_token(
            "tok-1", "agent-2", "[]", "[]",
            7200, None, 5, "2024-01-02T00:00:00Z",
            "2024-01-02T02:00:00Z", "admin", true,
        ).unwrap();

        let tokens = db.load_agent_tokens().unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].agent_id, "agent-2");
        assert_eq!(tokens[0].uses, 5);
        assert!(tokens[0].revoked);
    }
}
