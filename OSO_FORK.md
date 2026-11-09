# The OSO fork of polyglot

This is [`opensource-observer/polyglot`](https://github.com/opensource-observer/polyglot),
a fork of [`tobilg/polyglot`](https://github.com/tobilg/polyglot). OSO's
query rewriter ([`kuma`'s `crates/query-rewriter`](https://github.com/opensource-observer/kuma/tree/main/crates/query-rewriter))
pins `polyglot-sql` from here by git `rev`, so a fix can ship before upstream
releases it. Which gaps exist between polyglot and the sqlglot behaviour OSO
relies on, and how each one is tracked, is in kuma's
[`lib/query-rewriter/POLYGLOT_UPSTREAM.md`](https://github.com/opensource-observer/kuma/blob/main/lib/query-rewriter/POLYGLOT_UPSTREAM.md).

## Branches

- `main` — the latest upstream release we are on, plus every OSO change below.
  PRs target `main`.
- `oso/vX.Y.Z` — the same stack on upstream tag `vX.Y.Z`, kept so an older
  pin stays fetchable. `main` currently equals `oso/v0.13.3`.

Moving to a new upstream release means replaying the stack below onto its tag
as `oso/vX.Y.Z`, then pointing `main` at it. Keep every change as its own
commit so each can still be offered upstream on its own.

## Changes on top of upstream

Based on upstream **v0.13.3**. Every OSO change is one self-contained PR with
its own tests, listed here in that PR; drop a row when upstream ships the
change and the fork moves past it.

| PR  | Change | Area | Upstream |
| --- | ------ | ---- | -------- |
| —   | `Scope::traverse` yields derived-table scopes | scope | not upstream |
| #2  | Observe-only `ScopeVisitor` for scope building | scope | not upstream |
| #3  | A parenthesized set operation in an `IN` list parses as a subquery | parser | not upstream |
| #4  | Set operators after a scalar subquery stay on the enclosing query | parser | not upstream |
| #5  | `Scope::outer_columns` filled for derived-table and CTE alias lists | scope | not upstream |
| #7  | An `ANY`/`ALL` subquery is a single scope | scope | not upstream |
| #8  | `ScopeVisitor::enter_scope` reports input-tree nodes; `scope_query` public | scope | not upstream |
| #9  | Read-only optimizer passes borrow scopes instead of cloning | optimizer | not upstream |
| #10 | A bare query operand is a subquery scope | scope | not upstream |
| #11 | Scope building walks every child field of an expression | scope | not upstream |
| #12 | Relations inside parenthesized joins are registered in their scope | scope | overlaps upstream 0.14's join-group scopes |
| #13 | Aliases of table functions and `MATCH_RECOGNIZE` are registered | scope | not upstream |
| #16 | Trino/Presto `TIMESTAMP(x)` → `CAST(x AS TIMESTAMP)` (sqlglot parity) | dialect | open; not in 0.14.1 |
| #17 | Trino/Presto two-argument `MAX(x, n)`/`MIN(x, n)` stay aggregates (sqlglot parity) | dialect | open; not in 0.14.1 |
| #18 | A set operation after an unaliased derived table stays outside it | parser | open; not in 0.14.1 |

## Adding a change

1. Branch from `main`; one fix per PR, with a regression test under
   `crates/polyglot-sql/tests/` (or in the module's tests).
2. Add the change's row to the table above in the same PR.
3. After it merges, bump kuma's pin (`crates/query-rewriter/Cargo.toml`) to
   the new `main` and follow `POLYGLOT_UPSTREAM.md` there.
