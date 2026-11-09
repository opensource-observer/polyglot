//! In Presto and Trino, two-argument `max(x, n)` / `min(x, n)` is an aggregate:
//! an array of the `n` largest / smallest values of `x`. It is not the scalar
//! `GREATEST`/`LEAST` it means in other dialects, and sqlglot reprints it
//! unchanged.

use polyglot_sql::{transpile, DialectType};

fn reprint(sql: &str, dialect: DialectType) -> String {
    transpile(sql, dialect, dialect)
        .unwrap_or_else(|e| panic!("failed to transpile {sql:?}: {e}"))
        .remove(0)
}

#[test]
fn two_argument_max_and_min_stay_aggregates() {
    for dialect in [DialectType::Trino, DialectType::Presto, DialectType::Athena] {
        for sql in [
            "SELECT MAX(x, 3) FROM t",
            "SELECT MIN(x, 3) FROM t",
            "SELECT k, MAX(x, 2) AS top FROM t GROUP BY k",
        ] {
            assert_eq!(reprint(sql, dialect), sql, "{dialect:?}");
        }
    }
}

#[test]
fn many_argument_max_from_other_dialects_is_still_greatest() {
    assert_eq!(
        transpile(
            "SELECT MAX(a, b, c)",
            DialectType::Generic,
            DialectType::Trino
        )
        .unwrap()
        .remove(0),
        "SELECT GREATEST(a, b, c)",
    );
}
