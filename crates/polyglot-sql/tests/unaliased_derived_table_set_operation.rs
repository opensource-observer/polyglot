//! An unaliased derived table at the end of a set operation's first operand
//! belongs to that operand: the set operation after it is not part of it.

use polyglot_sql::{transpile, DialectType};

fn reprint(sql: &str, dialect: DialectType) -> String {
    transpile(sql, dialect, dialect)
        .unwrap_or_else(|e| panic!("failed to transpile {sql:?}: {e}"))
        .remove(0)
}

#[test]
fn a_set_operation_after_an_unaliased_derived_table_stays_outside_it() {
    for sql in [
        "SELECT 1 AS s, * FROM (SELECT x FROM a) UNION ALL SELECT 2, x FROM b",
        "SELECT 'p' AS side, * FROM (SELECT * FROM a LIMIT 1) UNION ALL SELECT 'l' AS side, * FROM (SELECT * FROM b LIMIT 1) LIMIT 2",
        "SELECT * FROM c, (SELECT x FROM a LIMIT 1) UNION ALL SELECT x FROM b",
        "SELECT y, * FROM (SELECT x FROM a) EXCEPT SELECT y, x FROM b",
    ] {
        for dialect in [DialectType::Trino, DialectType::Generic] {
            assert_eq!(reprint(sql, dialect), sql, "{dialect:?}");
        }
    }
}

#[test]
fn a_parenthesized_set_operation_keeps_its_own_modifiers_inside_its_parens() {
    for sql in [
        "SELECT * FROM ((SELECT 1) UNION (SELECT 2))",
        "SELECT * FROM ((SELECT 1) UNION SELECT 2)",
        "SELECT * FROM (((SELECT 1) UNION SELECT 2) ORDER BY x LIMIT 1 OFFSET 1)",
        "SELECT * FROM ((SELECT 1) AS a UNION ALL (SELECT 2) AS b)",
    ] {
        assert_eq!(reprint(sql, DialectType::Generic), sql);
    }
}
