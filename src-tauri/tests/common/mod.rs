//! Common test setup and utilities for integration tests
//!
//! This module provides shared setup code for all integration tests.

use anyhow::Result;
use sqlx::SqlitePool;

/// Initialize test logging (call once per test module)
pub fn init_test_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("nymstr_app_v2=debug,test=debug")
        .with_test_writer()
        .try_init();
}

/// Create a test database with full schema
pub async fn setup_test_db() -> Result<SqlitePool> {
    let pool = SqlitePool::connect("sqlite::memory:").await?;
    nymstr_app_v2_lib::core::db::schema::run_migrations(&pool).await?;
    Ok(pool)
}

/// Create a temporary database file for tests that need persistence
pub async fn setup_persistent_test_db() -> Result<(SqlitePool, tempfile::TempDir)> {
    let temp_dir = tempfile::tempdir()?;
    let db_path = temp_dir.path().join("test.db");
    let pool = SqlitePool::connect(&format!("sqlite:{}", db_path.display())).await?;
    nymstr_app_v2_lib::core::db::schema::run_migrations(&pool).await?;
    Ok((pool, temp_dir))
}

/// Seed test users in the database
pub async fn seed_users(pool: &SqlitePool, users: &[(&str, &str)]) -> Result<()> {
    for (username, public_key) in users {
        sqlx::query(
            "INSERT INTO users (username, display_name, public_key) VALUES (?, ?, ?)",
        )
        .bind(username)
        .bind(username)
        .bind(public_key)
        .execute(pool)
        .await?;
    }
    Ok(())
}

/// Count records in a table
pub async fn count_records(pool: &SqlitePool, table: &str) -> Result<i64> {
    let query = format!("SELECT COUNT(*) FROM {}", table);
    let result: (i64,) = sqlx::query_as(&query).fetch_one(pool).await?;
    Ok(result.0)
}

/// Test context that provides common resources
pub struct TestContext {
    pub db: SqlitePool,
    pub _temp_dir: Option<tempfile::TempDir>,
}

impl TestContext {
    /// Create a new test context with in-memory database
    pub async fn new() -> Result<Self> {
        init_test_logging();
        let db = setup_test_db().await?;
        Ok(Self { db, _temp_dir: None })
    }

    /// Create a new test context with persistent database
    pub async fn persistent() -> Result<Self> {
        init_test_logging();
        let (db, temp_dir) = setup_persistent_test_db().await?;
        Ok(Self {
            db,
            _temp_dir: Some(temp_dir),
        })
    }
}

/// Assert that two messages have the same essential content
#[macro_export]
macro_rules! assert_message_eq {
    ($left:expr, $right:expr) => {
        assert_eq!($left.action, $right.action, "Message actions differ");
        assert_eq!($left.sender, $right.sender, "Message senders differ");
        assert_eq!($left.recipient, $right.recipient, "Message recipients differ");
    };
}

/// Assert that a result is Ok and return the value
#[macro_export]
macro_rules! assert_ok {
    ($expr:expr) => {
        match $expr {
            Ok(val) => val,
            Err(e) => panic!("Expected Ok but got Err: {:?}", e),
        }
    };
}

/// Assert that a result is Err
#[macro_export]
macro_rules! assert_err {
    ($expr:expr) => {
        match $expr {
            Ok(val) => panic!("Expected Err but got Ok: {:?}", val),
            Err(_) => {}
        }
    };
}
