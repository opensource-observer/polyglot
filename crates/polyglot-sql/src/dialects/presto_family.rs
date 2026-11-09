//! Rewrites shared by the Presto and Trino dialects, compiled when either is.

use crate::expressions::{Cast, DataType, Expression, Function, Literal};

/// `TIMESTAMP(x)` as `CAST(x AS TIMESTAMP)`, and `TIMESTAMP(x, 'zone')` naming
/// a known time zone as `AT_TIMEZONE(CAST(x AS TIMESTAMP), 'zone')`, as
/// sqlglot's Presto and Trino generators write it: neither engine has a
/// `timestamp()` function. Any other call (a computed or unknown zone, other
/// arities) is returned unchanged, as sqlglot leaves it.
pub(super) fn timestamp_function_as_cast(f: Function) -> Expression {
    let is_known_zone = |zone: &Expression| match zone {
        Expression::Literal(lit) => match lit.as_ref() {
            Literal::String(name) => crate::time::is_valid_timezone(name),
            _ => false,
        },
        _ => false,
    };
    let cast = |this: Expression| {
        Expression::Cast(Box::new(Cast {
            this,
            to: DataType::Timestamp {
                precision: None,
                timezone: false,
            },
            trailing_comments: Vec::new(),
            double_colon_syntax: false,
            format: None,
            default: None,
            inferred_type: None,
        }))
    };
    match f.args.as_slice() {
        [_] => cast(f.args.into_iter().next().unwrap()),
        [_, zone] if is_known_zone(zone) => {
            let mut args = f.args.into_iter();
            let this = cast(args.next().unwrap());
            let zone = args.next().unwrap();
            Expression::Function(Box::new(Function::new(
                "AT_TIMEZONE".to_string(),
                vec![this, zone],
            )))
        }
        _ => Expression::Function(Box::new(f)),
    }
}
