use polyglot_sql::expressions::ParameterStyle;
use polyglot_sql::{generate, parse, DialectType, Expression};

fn roundtrip_to(sql: &str, expected: &str) -> Expression {
    let ast = parse(sql, DialectType::Trino).expect("parse");
    assert_eq!(
        generate(&ast[0], DialectType::Trino).expect("generate"),
        expected
    );
    ast.into_iter().next().unwrap()
}

#[test]
fn trino_at_name_is_an_at_parameter() {
    let sql = "SELECT @start_dt FROM t";
    let Expression::Select(select) = roundtrip_to(sql, sql) else {
        panic!("expected Select");
    };
    let Expression::Parameter(param) = &select.expressions[0] else {
        panic!(
            "expected Parameter, got {}",
            select.expressions[0].variant_name()
        );
    };
    assert_eq!(param.name.as_deref(), Some("start_dt"));
    assert_eq!(param.style, ParameterStyle::At);
}

#[test]
fn trino_at_macro_function_call_round_trips() {
    // Function names are uppercased on regeneration, as before.
    roundtrip_to(
        "SELECT a FROM t WHERE country = @some_macro_func('x')",
        "SELECT a FROM t WHERE country = @SOME_MACRO_FUNC('x')",
    );
}
