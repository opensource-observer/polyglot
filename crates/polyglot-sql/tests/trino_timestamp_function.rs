//! Trino and Presto have no `timestamp()` function. sqlglot reads one as a
//! timestamp conversion and writes it back as a cast (`no_timestamp_sql`), so a
//! query using it runs once sqlglot has reprinted it; these pin that polyglot's
//! Trino and Presto reprints match.

use polyglot_sql::{transpile, DialectType};

fn reprint(sql: &str, dialect: DialectType) -> String {
    transpile(sql, dialect, dialect)
        .unwrap_or_else(|e| panic!("failed to transpile {sql:?}: {e}"))
        .remove(0)
}

const DIALECTS: [DialectType; 2] = [DialectType::Trino, DialectType::Presto];

#[test]
fn timestamp_of_one_argument_is_a_cast() {
    for dialect in DIALECTS {
        assert_eq!(
            reprint("SELECT TIMESTAMP('2025-09-16 13:51:30.000')", dialect),
            "SELECT CAST('2025-09-16 13:51:30.000' AS TIMESTAMP)",
        );
        assert_eq!(
            reprint("SELECT * FROM t WHERE created_at = timestamp(d)", dialect),
            "SELECT * FROM t WHERE created_at = CAST(d AS TIMESTAMP)",
        );
    }
}

#[test]
fn timestamp_with_a_literal_zone_is_a_cast_at_that_zone() {
    for dialect in DIALECTS {
        assert_eq!(
            reprint("SELECT TIMESTAMP(d, 'America/New_York')", dialect),
            "SELECT AT_TIMEZONE(CAST(d AS TIMESTAMP), 'America/New_York')",
        );
    }
}

#[test]
fn timestamp_with_a_computed_zone_is_left_alone() {
    for dialect in DIALECTS {
        assert_eq!(
            reprint("SELECT TIMESTAMP(d, z)", dialect),
            "SELECT TIMESTAMP(d, z)",
        );
    }
}

#[test]
fn timestamp_types_are_unchanged() {
    for dialect in DIALECTS {
        for sql in [
            "SELECT CAST(d AS TIMESTAMP)",
            "SELECT CAST(d AS TIMESTAMP(3) WITH TIME ZONE)",
        ] {
            assert_eq!(reprint(sql, dialect), sql);
        }
    }
}
