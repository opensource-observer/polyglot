//! Rewrites shared by the Presto and Trino dialects, compiled when either is.

use crate::expressions::{Cast, DataType, Expression, Function, Literal};

/// `TIMESTAMP(x)` as `CAST(x AS TIMESTAMP)`, and `TIMESTAMP(x, 'zone')` as
/// `AT_TIMEZONE(CAST(x AS TIMESTAMP), 'zone')`, as sqlglot's Presto and Trino
/// generators write it: neither engine has a `timestamp()` function. Any other
/// call (a computed zone, other arities) is returned unchanged.
pub(super) fn timestamp_function_as_cast(f: Function) -> Expression {
    let is_literal_zone = |zone: &Expression| matches!(zone, Expression::Literal(lit) if matches!(lit.as_ref(), Literal::String(_)));
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
        [_, zone] if is_literal_zone(zone) => {
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
