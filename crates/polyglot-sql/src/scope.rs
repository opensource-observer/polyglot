//! Scope Analysis Module
//!
//! This module provides scope analysis for SQL queries, enabling detection of
//! correlated subqueries, column references, and scope relationships.
//!
//! Ported from sqlglot's optimizer/scope.py

use crate::expressions::{Expression, Identifier};
use crate::traversal::ExpressionWalk;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
#[cfg(feature = "bindings")]
use ts_rs::TS;

/// Type of scope in a SQL query
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "bindings", derive(TS))]
#[cfg_attr(feature = "bindings", ts(export))]
pub enum ScopeType {
    /// Root scope of the query
    Root,
    /// Subquery scope (e.g., WHERE x IN (SELECT ...))
    Subquery,
    /// Derived table scope (e.g., FROM (SELECT ...) AS t)
    DerivedTable,
    /// Common Table Expression scope
    Cte,
    /// Union/Intersect/Except scope
    SetOperation,
    /// User-Defined Table Function scope
    Udtf,
}

/// Semantic kind of a source registered in a scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// Root query or statement context
    Root,
    /// Physical table source
    Table,
    /// Derived table/subquery source
    DerivedTable,
    /// Common Table Expression source
    Cte,
    /// Virtual table source such as UNNEST / UDTF
    Virtual,
    /// Unresolved or synthetic fallback source
    Unknown,
}

impl Default for SourceKind {
    fn default() -> Self {
        Self::Unknown
    }
}

/// Unwrap query containers without creating a new lexical context.
///
/// Peels `Cte`, `Subquery`, `Paren`, `Alias`, `Prepare` and
/// `CREATE TABLE ... AS SELECT` wrappers, which is how the scope builder finds
/// the query a scope is built from. Any other expression is returned as is.
///
/// ```
/// use polyglot_sql::{parse, scope_query, DialectType, Expression};
///
/// let ast = parse("SELECT 1 FROM (SELECT 2) AS d", DialectType::Generic).unwrap();
/// let Expression::Select(select) = &ast[0] else { unreachable!() };
/// let derived = &select.from.as_ref().unwrap().expressions[0];
/// assert!(matches!(derived, Expression::Subquery(_)));
/// assert!(matches!(scope_query(derived), Expression::Select(_)));
/// ```
pub fn scope_query(expression: &Expression) -> &Expression {
    match expression {
        Expression::Cte(cte) => scope_query(&cte.this),
        Expression::Subquery(subquery) => scope_query(&subquery.this),
        Expression::Paren(paren) => scope_query(&paren.this),
        Expression::Alias(alias) => scope_query(&alias.this),
        Expression::Prepare(prepare) => scope_query(&prepare.statement),
        Expression::CreateTable(create) if create.as_select.is_some() => {
            scope_query(create.as_select.as_ref().unwrap())
        }
        _ => expression,
    }
}

/// A lightweight resolution view containing only selected sources. CTE
/// declarations remain available, but do not themselves cause ambiguity.
pub(crate) fn selected_reference_scope(scope: &Scope) -> Scope {
    let query = scope_query(&scope.expression);
    let aliases: HashSet<_> = walk_in_scope(query, false)
        .filter_map(|node| match node {
            Expression::Table(table) => {
                Some(table.alias.as_ref().unwrap_or(&table.name).name.clone())
            }
            _ => None,
        })
        .collect();
    let mut selected = Scope::new(query.clone());
    selected.cte_sources = scope.cte_sources.clone();
    selected.sources = scope
        .sources
        .iter()
        .filter(|(name, source)| {
            // Source keys use the spelling of the actual FROM/JOIN binding.
            // Folding here can accidentally retain an unused, quoted CTE.
            source.kind != SourceKind::Cte || aliases.contains(*name)
        })
        .map(|(name, source)| (name.clone(), source.clone()))
        .collect();
    selected
}

/// Information about a source (table or subquery) in a scope
#[derive(Debug, Clone)]
pub struct SourceInfo {
    /// The source expression (Table or subquery)
    pub expression: Expression,
    /// Whether this source is a scope (vs. a plain table)
    pub is_scope: bool,
    /// Semantic source kind for lineage consumers.
    pub kind: SourceKind,
    /// User-written alias, when it should be preserved separately from lineage name.
    pub alias: Option<String>,
    /// Canonical lineage source name, e.g. synthetic `_0` for virtual sources.
    pub lineage_name: Option<String>,
}

impl SourceInfo {
    pub fn new(expression: Expression, is_scope: bool, kind: SourceKind) -> Self {
        Self {
            expression,
            is_scope,
            kind,
            alias: None,
            lineage_name: None,
        }
    }

    pub fn with_alias(mut self, alias: impl Into<String>) -> Self {
        self.alias = Some(alias.into());
        self
    }

    pub fn with_lineage_name(mut self, lineage_name: impl Into<String>) -> Self {
        self.lineage_name = Some(lineage_name.into());
        self
    }
}

/// A column reference found in a scope
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ColumnRef {
    /// The table/alias qualifier (if any)
    pub table: Option<String>,
    /// The column name
    pub name: String,
}

/// Represents a scope in a SQL query
///
/// A scope is the context of a SELECT statement and its sources.
/// Scopes can be nested (subqueries, CTEs, derived tables) and form a tree.
#[derive(Debug, Clone)]
pub struct Scope {
    /// The expression at the root of this scope
    pub expression: Expression,

    /// Type of this scope relative to its parent
    pub scope_type: ScopeType,

    /// Mapping of source names to their info
    pub sources: HashMap<String, SourceInfo>,

    /// Sources from LATERAL views (have access to preceding sources)
    pub lateral_sources: HashMap<String, SourceInfo>,

    /// CTE sources available to this scope
    pub cte_sources: HashMap<String, SourceInfo>,

    /// If this is a derived table or CTE with alias columns, this is that list
    /// e.g., `SELECT * FROM (SELECT ...) AS y(col1, col2)` => ["col1", "col2"]
    pub outer_columns: Vec<String>,

    /// Whether this scope can potentially be correlated
    /// (true for subqueries and UDTFs)
    pub can_be_correlated: bool,

    /// Whether this derived table sees only preceding FROM/JOIN sources.
    pub is_lateral: bool,

    /// Child subquery scopes
    pub subquery_scopes: Vec<Scope>,

    /// Child derived table scopes
    pub derived_table_scopes: Vec<Scope>,

    /// Child CTE scopes
    pub cte_scopes: Vec<Scope>,

    /// Child UDTF (User Defined Table Function) scopes
    pub udtf_scopes: Vec<Scope>,

    /// Never populated, kept for compatibility; derived tables are in
    /// `derived_table_scopes` and UDTFs in `udtf_scopes`
    pub table_scopes: Vec<Scope>,

    /// Union/set operation scopes (left and right)
    pub union_scopes: Vec<Scope>,

    /// Cached columns
    columns_cache: Option<Vec<ColumnRef>>,

    /// Cached external columns
    external_columns_cache: Option<Vec<ColumnRef>>,

    id: Option<ScopeId>,
}

impl Scope {
    /// Create a new root scope
    pub fn new(expression: Expression) -> Self {
        Self {
            expression,
            scope_type: ScopeType::Root,
            sources: HashMap::new(),
            lateral_sources: HashMap::new(),
            cte_sources: HashMap::new(),
            outer_columns: Vec::new(),
            can_be_correlated: false,
            is_lateral: false,
            subquery_scopes: Vec::new(),
            derived_table_scopes: Vec::new(),
            cte_scopes: Vec::new(),
            udtf_scopes: Vec::new(),
            table_scopes: Vec::new(),
            union_scopes: Vec::new(),
            columns_cache: None,
            external_columns_cache: None,
            id: None,
        }
    }

    /// Create a child scope branching from this one
    pub fn branch(&self, expression: Expression, scope_type: ScopeType) -> Self {
        self.branch_with_options(expression, scope_type, None, None, None)
    }

    /// Create a child scope with additional options
    pub fn branch_with_options(
        &self,
        expression: Expression,
        scope_type: ScopeType,
        sources: Option<HashMap<String, SourceInfo>>,
        lateral_sources: Option<HashMap<String, SourceInfo>>,
        outer_columns: Option<Vec<String>>,
    ) -> Self {
        let can_be_correlated = self.can_be_correlated
            || scope_type == ScopeType::Subquery
            || scope_type == ScopeType::Udtf;

        Self {
            expression,
            scope_type,
            sources: sources.unwrap_or_default(),
            lateral_sources: lateral_sources.unwrap_or_default(),
            cte_sources: self.cte_sources.clone(),
            outer_columns: outer_columns.unwrap_or_default(),
            can_be_correlated,
            is_lateral: false,
            subquery_scopes: Vec::new(),
            derived_table_scopes: Vec::new(),
            cte_scopes: Vec::new(),
            udtf_scopes: Vec::new(),
            table_scopes: Vec::new(),
            union_scopes: Vec::new(),
            columns_cache: None,
            external_columns_cache: None,
            id: None,
        }
    }

    /// The id assigned by the build that created this scope, or `None` for a
    /// scope created directly with [`Scope::new`], [`Scope::branch`] or
    /// [`Scope::branch_with_options`].
    pub fn id(&self) -> Option<ScopeId> {
        self.id
    }

    /// Clear all cached properties
    pub fn clear_cache(&mut self) {
        self.columns_cache = None;
        self.external_columns_cache = None;
    }

    /// Add a source to this scope
    pub fn add_source(&mut self, name: String, expression: Expression, is_scope: bool) {
        let kind = if is_scope {
            SourceKind::DerivedTable
        } else {
            SourceKind::Table
        };
        self.add_source_info(name, SourceInfo::new(expression, is_scope, kind));
    }

    /// Add a preconfigured source to this scope
    pub fn add_source_info(&mut self, name: String, info: SourceInfo) {
        self.sources.insert(name, info);
        self.clear_cache();
    }

    /// Add a virtual source such as UNNEST / UDTF.
    pub fn add_virtual_source(&mut self, alias: String, expression: Expression) {
        let lineage_name = self.next_virtual_source_name();
        let info = SourceInfo::new(expression, false, SourceKind::Virtual)
            .with_alias(alias.clone())
            .with_lineage_name(lineage_name);
        self.add_source_info(alias, info);
    }

    fn next_virtual_source_name(&self) -> String {
        let count = self
            .sources
            .values()
            .filter(|source| source.kind == SourceKind::Virtual)
            .count();
        format!("_{}", count)
    }

    /// Add a lateral source to this scope
    pub fn add_lateral_source(&mut self, name: String, expression: Expression, is_scope: bool) {
        let kind = if is_scope {
            SourceKind::DerivedTable
        } else {
            SourceKind::Table
        };
        let info = SourceInfo::new(expression.clone(), is_scope, kind);
        self.sources.insert(name.clone(), info.clone());
        self.lateral_sources.insert(name, info);
        self.clear_cache();
    }

    /// Add a CTE source to this scope
    pub fn add_cte_source(&mut self, name: String, expression: Expression) {
        let info = SourceInfo::new(expression, true, SourceKind::Cte);
        self.cte_sources.insert(name.clone(), info.clone());
        self.sources.insert(name, info);
        self.clear_cache();
    }

    /// Rename a source
    pub fn rename_source(&mut self, old_name: &str, new_name: String) {
        if let Some(source) = self.sources.remove(old_name) {
            self.sources.insert(new_name, source);
        }
        self.clear_cache();
    }

    /// Remove a source
    pub fn remove_source(&mut self, name: &str) {
        self.sources.remove(name);
        self.clear_cache();
    }

    /// Collect all column references in this scope
    pub fn columns(&mut self) -> &[ColumnRef] {
        if self.columns_cache.is_none() {
            let mut columns = Vec::new();
            collect_columns(&self.expression, &mut columns);
            self.columns_cache = Some(columns);
        }
        self.columns_cache.as_ref().unwrap()
    }

    /// Collect projected output column names for this scope's query expression.
    ///
    /// This is intended for result schema style output columns (e.g. UNION
    /// outputs), unlike [`Self::columns`], which returns raw referenced columns.
    pub fn output_columns(&self) -> Vec<String> {
        crate::ast_transforms::get_output_column_names(&self.expression)
    }

    /// Get all source names in this scope
    pub fn source_names(&self) -> HashSet<String> {
        let mut names: HashSet<String> = self.sources.keys().cloned().collect();
        names.extend(self.cte_sources.keys().cloned());
        names
    }

    /// Get columns that reference sources outside this scope
    pub fn external_columns(&mut self) -> Vec<ColumnRef> {
        if self.external_columns_cache.is_some() {
            return self.external_columns_cache.clone().unwrap();
        }

        let source_names = self.source_names();
        let columns = self.columns().to_vec();

        let external: Vec<ColumnRef> = columns
            .into_iter()
            .filter(|col| {
                // A column is external if it has a table qualifier that's not in our sources
                match &col.table {
                    Some(table) => !source_names.contains(table),
                    None => false, // Unqualified columns might be local
                }
            })
            .collect();

        self.external_columns_cache = Some(external.clone());
        external
    }

    /// Get columns that reference sources in this scope (not external)
    pub fn local_columns(&mut self) -> Vec<ColumnRef> {
        let external_set: HashSet<_> = self.external_columns().into_iter().collect();
        let columns = self.columns().to_vec();

        columns
            .into_iter()
            .filter(|col| !external_set.contains(col))
            .collect()
    }

    /// Get unqualified columns (columns without table qualifier)
    pub fn unqualified_columns(&mut self) -> Vec<ColumnRef> {
        self.columns()
            .iter()
            .filter(|c| c.table.is_none())
            .cloned()
            .collect()
    }

    /// Get columns for a specific source
    pub fn source_columns(&mut self, source_name: &str) -> Vec<ColumnRef> {
        self.columns()
            .iter()
            .filter(|col| col.table.as_deref() == Some(source_name))
            .cloned()
            .collect()
    }

    /// Determine if this scope is a correlated subquery
    ///
    /// A subquery is correlated if:
    /// 1. It can be correlated (is a subquery or UDTF), AND
    /// 2. It references columns from outer scopes
    pub fn is_correlated_subquery(&mut self) -> bool {
        self.can_be_correlated && !self.external_columns().is_empty()
    }

    /// Check if this is a subquery scope
    pub fn is_subquery(&self) -> bool {
        self.scope_type == ScopeType::Subquery
    }

    /// Check if this is a derived table scope
    pub fn is_derived_table(&self) -> bool {
        self.scope_type == ScopeType::DerivedTable
    }

    /// Check if this is a CTE scope
    pub fn is_cte(&self) -> bool {
        self.scope_type == ScopeType::Cte
    }

    /// Check if this is the root scope
    pub fn is_root(&self) -> bool {
        self.scope_type == ScopeType::Root
    }

    /// Check if this is a UDTF scope
    pub fn is_udtf(&self) -> bool {
        self.scope_type == ScopeType::Udtf
    }

    /// Check if this is a union/set operation scope
    pub fn is_union(&self) -> bool {
        self.scope_type == ScopeType::SetOperation
    }

    /// Traverse all scopes in this tree (depth-first post-order)
    pub fn traverse(&self) -> Vec<&Scope> {
        let mut result = Vec::new();
        self.traverse_impl(&mut result);
        result
    }

    fn traverse_impl<'a>(&'a self, result: &mut Vec<&'a Scope>) {
        // First traverse children
        for scope in &self.cte_scopes {
            scope.traverse_impl(result);
        }
        for scope in &self.union_scopes {
            scope.traverse_impl(result);
        }
        for scope in &self.derived_table_scopes {
            scope.traverse_impl(result);
        }
        for scope in &self.udtf_scopes {
            scope.traverse_impl(result);
        }
        for scope in &self.subquery_scopes {
            scope.traverse_impl(result);
        }
        // Then add self
        result.push(self);
    }

    /// Count references to each scope in this tree
    pub fn ref_count(&self) -> HashMap<usize, usize> {
        let mut counts: HashMap<usize, usize> = HashMap::new();

        for scope in self.traverse() {
            for (_, source_info) in scope.sources.iter() {
                if source_info.is_scope {
                    let id = &source_info.expression as *const _ as usize;
                    *counts.entry(id).or_insert(0) += 1;
                }
            }
        }

        counts
    }
}

/// Collect all column references from an expression tree
fn collect_columns(expr: &Expression, columns: &mut Vec<ColumnRef>) {
    match expr {
        Expression::Column(col) => {
            columns.push(ColumnRef {
                table: col.table.as_ref().map(|t| t.name.clone()),
                name: col.name.name.clone(),
            });
        }
        Expression::Select(select) => {
            // Collect from SELECT expressions
            for e in &select.expressions {
                collect_columns(e, columns);
            }
            // Collect from JOIN ON / MATCH_CONDITION clauses
            for join in &select.joins {
                if let Some(on) = &join.on {
                    collect_columns(on, columns);
                }
                if let Some(match_condition) = &join.match_condition {
                    collect_columns(match_condition, columns);
                }
            }
            // Collect from WHERE
            if let Some(where_clause) = &select.where_clause {
                collect_columns(&where_clause.this, columns);
            }
            // Collect from HAVING
            if let Some(having) = &select.having {
                collect_columns(&having.this, columns);
            }
            // Collect from ORDER BY
            if let Some(order_by) = &select.order_by {
                for ord in &order_by.expressions {
                    collect_columns(&ord.this, columns);
                }
            }
            // Collect from GROUP BY
            if let Some(group_by) = &select.group_by {
                for e in &group_by.expressions {
                    collect_columns(e, columns);
                }
            }
            // Note: We don't recurse into FROM/JOIN source subqueries here
            // as those create their own scopes.
        }
        // Binary operations
        Expression::And(bin)
        | Expression::Or(bin)
        | Expression::Add(bin)
        | Expression::Sub(bin)
        | Expression::Mul(bin)
        | Expression::Div(bin)
        | Expression::Mod(bin)
        | Expression::Eq(bin)
        | Expression::Neq(bin)
        | Expression::Lt(bin)
        | Expression::Lte(bin)
        | Expression::Gt(bin)
        | Expression::Gte(bin)
        | Expression::BitwiseAnd(bin)
        | Expression::BitwiseOr(bin)
        | Expression::BitwiseXor(bin)
        | Expression::Concat(bin) => {
            collect_columns(&bin.left, columns);
            collect_columns(&bin.right, columns);
        }
        // LIKE/ILIKE operations
        Expression::Like(like) | Expression::ILike(like) => {
            collect_columns(&like.left, columns);
            collect_columns(&like.right, columns);
            if let Some(escape) = &like.escape {
                collect_columns(escape, columns);
            }
        }
        // Unary operations
        Expression::Not(un) | Expression::Neg(un) | Expression::BitwiseNot(un) => {
            collect_columns(&un.this, columns);
        }
        Expression::Function(func) => {
            for arg in &func.args {
                collect_columns(arg, columns);
            }
        }
        Expression::AggregateFunction(agg) => {
            for arg in &agg.args {
                collect_columns(arg, columns);
            }
        }
        Expression::WindowFunction(wf) => {
            collect_columns(&wf.this, columns);
            for e in &wf.over.partition_by {
                collect_columns(e, columns);
            }
            for e in &wf.over.order_by {
                collect_columns(&e.this, columns);
            }
        }
        Expression::Alias(alias) => {
            collect_columns(&alias.this, columns);
        }
        Expression::Case(case) => {
            if let Some(operand) = &case.operand {
                collect_columns(operand, columns);
            }
            for (when_expr, then_expr) in &case.whens {
                collect_columns(when_expr, columns);
                collect_columns(then_expr, columns);
            }
            if let Some(else_clause) = &case.else_ {
                collect_columns(else_clause, columns);
            }
        }
        Expression::Paren(paren) => {
            collect_columns(&paren.this, columns);
        }
        Expression::Ordered(ord) => {
            collect_columns(&ord.this, columns);
        }
        Expression::In(in_expr) => {
            collect_columns(&in_expr.this, columns);
            for e in &in_expr.expressions {
                collect_columns(e, columns);
            }
            // Note: in_expr.query is a subquery - creates its own scope
        }
        Expression::Between(between) => {
            collect_columns(&between.this, columns);
            collect_columns(&between.low, columns);
            collect_columns(&between.high, columns);
        }
        Expression::IsNull(is_null) => {
            collect_columns(&is_null.this, columns);
        }
        Expression::Cast(cast) => {
            collect_columns(&cast.this, columns);
        }
        Expression::Extract(extract) => {
            collect_columns(&extract.this, columns);
        }
        Expression::Exists(_) | Expression::Subquery(_) => {
            // These create their own scopes - don't collect from here
        }
        Expression::Prepare(prepare) => {
            collect_columns(&prepare.statement, columns);
        }
        _ => {
            // For other expressions, we might need to add more cases
        }
    }
}

/// Identifies a scope created by one [`build_scope_with`] call.
///
/// Ids are unique within that call and assigned in creation order, starting
/// with the root scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScopeId(u32);

/// Observes scope construction in [`build_scope_with`].
///
/// Every method has an empty default implementation. A visitor sees the
/// expressions being scoped but never the [`Scope`] tree itself, so it cannot
/// change what is built. Ids reported here match [`Scope::id`] on the finished
/// tree.
///
/// The expressions passed to `enter_scope`, `reference` and `skipped` are nodes
/// of the expression given to [`build_scope_with`], not copies, so a caller may
/// key on their address for as long as it keeps that expression alive. For a
/// derived table or subquery scope, `enter_scope` receives the query inside the
/// wrapper.
///
/// A CTE scope is the one exception. The input holds a CTE as a `Cte` struct in
/// `With::ctes`, not as an `Expression` node, so `enter_scope` receives an
/// owned `Expression::Cte` (equal to [`Scope::expression`]) whose address is
/// not in the input. The CTE's body is an input node: it is `Cte::this` of the
/// matching entry in the input's `With`.
///
/// `enter_scope` and `exit_scope` nest like a stack: a child scope is entered
/// and exited while its parent is open, and every `reference` and `skipped`
/// event belongs to the innermost open scope.
///
/// # Example
///
/// Collect the FROM/JOIN item names of a query in source order:
///
/// ```
/// use polyglot_sql::{build_scope_with, parse, DialectType, Expression, ScopeId, ScopeVisitor};
///
/// #[derive(Default)]
/// struct FromItemNames(Vec<Option<String>>);
///
/// impl ScopeVisitor for FromItemNames {
///     fn reference(
///         &mut self,
///         _scope: ScopeId,
///         _index: usize,
///         _depth: usize,
///         _item: &Expression,
///         registered_as: Option<&str>,
///         _child: Option<ScopeId>,
///     ) {
///         self.0.push(registered_as.map(str::to_string));
///     }
/// }
///
/// let sql = "SELECT * FROM a JOIN (SELECT 1) AS b ON TRUE JOIN a AS c ON TRUE";
/// let ast = parse(sql, DialectType::Generic).unwrap();
/// let mut names = FromItemNames::default();
/// build_scope_with(&ast[0], &mut names);
/// assert_eq!(
///     names.0,
///     [Some("a".to_string()), Some("b".to_string()), Some("c".to_string())]
/// );
/// ```
pub trait ScopeVisitor {
    /// Called when a scope is created, before its contents are processed.
    /// `parent` is the enclosing scope, or `None` for the root.
    fn enter_scope(
        &mut self,
        _id: ScopeId,
        _parent: Option<ScopeId>,
        _scope_type: ScopeType,
        _expression: &Expression,
    ) {
    }

    /// Called once per FROM/JOIN item of `scope`, in source order, including
    /// items whose name collides with an earlier one in [`Scope::sources`].
    ///
    /// It fires once the item is complete: after the item's `skipped` events
    /// and after its child scope, if any, has been entered and exited.
    ///
    /// `index` is the item's position in the scope's pre-order sequence of
    /// FROM items, and `depth` is 0 for top-level items. A parenthesized join
    /// is itself an item; items registered inside it follow it at `depth + 1`.
    /// Currently a parenthesized join is reported as one item with
    /// `registered_as: None` and its contents are reported through `skipped`,
    /// so `depth` is always 0.
    ///
    /// `registered_as` is the key the item was inserted under in
    /// [`Scope::sources`], or `None` when the item yields no source. `child`
    /// is the scope built for the item, if any.
    fn reference(
        &mut self,
        _scope: ScopeId,
        _index: usize,
        _depth: usize,
        _item: &Expression,
        _registered_as: Option<&str>,
        _child: Option<ScopeId>,
    ) {
    }

    /// Called for each subtree of a FROM item that gets no scope and is not
    /// searched for subqueries, such as table-function and `UNNEST`
    /// arguments, `VALUES` row values, `LATERAL` calls, `PIVOT` clauses and
    /// table sample or time-travel arguments. An item the builder does not
    /// handle at all, such as the contents of a parenthesized join, is
    /// reported whole.
    ///
    /// The values of a `VALUES` body that becomes a scope (a derived table,
    /// CTE body, root or set-operation branch) are reported against that
    /// scope. Hive-style `LATERAL VIEW` clauses after the FROM clause are not
    /// FROM items, so their calls are reported after the scope's last
    /// `reference`. A table, derived-table body or CTE body is never
    /// reported as a whole, since each gets a scope.
    fn skipped(&mut self, _scope: ScopeId, _expression: &Expression) {}

    /// Called when a scope is complete.
    fn exit_scope(&mut self, _id: ScopeId) {}
}

/// A [`ScopeVisitor`] that ignores every event.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopScopeVisitor;

impl ScopeVisitor for NoopScopeVisitor {}

/// Build scope tree from an expression
///
/// This traverses the expression tree and builds a hierarchy of Scope objects
/// that track sources and column references at each level.
pub fn build_scope(expression: &Expression) -> Scope {
    build_scope_with(expression, &mut NoopScopeVisitor)
}

/// Build a scope tree like [`build_scope`], reporting its construction to
/// `visitor`.
pub fn build_scope_with(expression: &Expression, visitor: &mut dyn ScopeVisitor) -> Scope {
    build_scope_with_ctes(expression, &HashMap::new(), visitor)
}

/// Build a query scope with CTE definitions inherited from its lexical parent.
pub(crate) fn build_scope_with_ctes(
    expression: &Expression,
    ctes: &HashMap<String, SourceInfo>,
    visitor: &mut dyn ScopeVisitor,
) -> Scope {
    let mut builder = ScopeBuilder {
        visitor,
        next_id: 0,
    };
    let mut root = builder.register(Scope::new(expression.clone()), None, expression);
    root.cte_sources = ctes.clone();
    build_scope_impl(expression, &mut root, &mut builder);
    builder.visitor.exit_scope(built_id(&root));
    root
}

struct ScopeBuilder<'v> {
    visitor: &'v mut dyn ScopeVisitor,
    next_id: u32,
}

impl ScopeBuilder<'_> {
    /// Assigns the next id to a newly created scope and reports it, along with
    /// the `input` node it was built from.
    fn register(&mut self, mut scope: Scope, parent: Option<ScopeId>, input: &Expression) -> Scope {
        let id = ScopeId(self.next_id);
        self.next_id += 1;
        scope.id = Some(id);
        self.visitor
            .enter_scope(id, parent, scope.scope_type, input);
        scope
    }

    fn branch(&mut self, parent: &Scope, expression: &Expression, scope_type: ScopeType) -> Scope {
        self.register(
            parent.branch(expression.clone(), scope_type),
            parent.id,
            expression,
        )
    }

    /// Builds `body` into `child` and reports `child` as complete.
    fn build_child(&mut self, mut child: Scope, body: &Expression) -> Scope {
        build_scope_impl(body, &mut child, self);
        self.visitor.exit_scope(built_id(&child));
        child
    }

    fn skipped(&mut self, scope: &Scope, expression: &Expression) {
        self.visitor.skipped(built_id(scope), expression);
    }

    /// Reports the direct children of `item` as skipped, except those under
    /// the `scoped` fields.
    fn skip_children(&mut self, scope: &Scope, item: &Expression, scoped: &[&str]) {
        use crate::ast_children::ChildPathSegment::Field;

        let id = built_id(scope);
        crate::ast_children::for_each_child(item, |path, child| {
            if !matches!(path.first(), Some(Field(field)) if scoped.contains(field)) {
                self.visitor.skipped(id, child);
            }
        });
    }
}

fn built_id(scope: &Scope) -> ScopeId {
    scope.id.expect("scopes created by a build have an id")
}

fn build_scope_impl(
    expression: &Expression,
    current_scope: &mut Scope,
    builder: &mut ScopeBuilder,
) {
    match expression {
        Expression::Prepare(prepare) => {
            build_scope_impl(&prepare.statement, current_scope, builder);
        }
        Expression::Select(select) => {
            // Process CTEs first
            if let Some(with) = &select.with {
                process_ctes(with, current_scope, builder);
            }

            // Register relations in order. CTE declarations are available for
            // FROM lookup, but only selected preceding bindings are lateral inputs.
            let mut preceding_sources = HashSet::new();
            for (index, table) in select
                .from
                .iter()
                .flat_map(|from| &from.expressions)
                .chain(select.joins.iter().map(|join| &join.this))
                .enumerate()
            {
                let first_child = current_scope.derived_table_scopes.len();
                let name = add_table_to_scope(table, current_scope, &preceding_sources, builder);
                let child = current_scope
                    .derived_table_scopes
                    .get(first_child)
                    .and_then(Scope::id);
                builder.visitor.reference(
                    built_id(current_scope),
                    index,
                    0,
                    table,
                    name.as_deref(),
                    child,
                );
                if let Some(name) = name {
                    preceding_sources.insert(name);
                }
            }

            // Process table-generating lateral views (Hive/Spark style UDTFs).
            for lateral_view in &select.lateral_views {
                add_lateral_view_to_scope(lateral_view, current_scope, builder);
            }

            // Process subqueries in WHERE, SELECT expressions, etc.
            collect_subqueries(expression, current_scope, builder);
        }
        Expression::Union(union) => {
            if let Some(with) = &union.with {
                process_ctes(with, current_scope, builder);
            }

            let left_scope = builder.branch(current_scope, &union.left, ScopeType::SetOperation);
            let left_scope = builder.build_child(left_scope, &union.left);

            let right_scope = builder.branch(current_scope, &union.right, ScopeType::SetOperation);
            let right_scope = builder.build_child(right_scope, &union.right);

            current_scope.union_scopes.push(left_scope);
            current_scope.union_scopes.push(right_scope);
        }
        Expression::Intersect(intersect) => {
            if let Some(with) = &intersect.with {
                process_ctes(with, current_scope, builder);
            }

            let left_scope =
                builder.branch(current_scope, &intersect.left, ScopeType::SetOperation);
            let left_scope = builder.build_child(left_scope, &intersect.left);

            let right_scope =
                builder.branch(current_scope, &intersect.right, ScopeType::SetOperation);
            let right_scope = builder.build_child(right_scope, &intersect.right);

            current_scope.union_scopes.push(left_scope);
            current_scope.union_scopes.push(right_scope);
        }
        Expression::Except(except) => {
            if let Some(with) = &except.with {
                process_ctes(with, current_scope, builder);
            }

            let left_scope = builder.branch(current_scope, &except.left, ScopeType::SetOperation);
            let left_scope = builder.build_child(left_scope, &except.left);

            let right_scope = builder.branch(current_scope, &except.right, ScopeType::SetOperation);
            let right_scope = builder.build_child(right_scope, &except.right);

            current_scope.union_scopes.push(left_scope);
            current_scope.union_scopes.push(right_scope);
        }
        Expression::CreateTable(create) => {
            // Handle CREATE TABLE ... AS [WITH ...] SELECT ...
            // Process CTEs if present
            if let Some(with) = &create.with_cte {
                process_ctes(with, current_scope, builder);
            }
            // Traverse the AS SELECT body
            if let Some(as_select) = &create.as_select {
                build_scope_impl(as_select, current_scope, builder);
            }
        }
        Expression::Subquery(subquery) => {
            build_scope_impl(&subquery.this, current_scope, builder);
        }
        Expression::Paren(paren) => {
            build_scope_impl(&paren.this, current_scope, builder);
        }
        Expression::Values(_) => {
            builder.skip_children(current_scope, expression, &[]);
        }
        _ => {}
    }
}

fn process_ctes(
    with: &crate::expressions::With,
    current_scope: &mut Scope,
    builder: &mut ScopeBuilder,
) {
    for cte in &with.ctes {
        let cte_name = cte.alias.name.clone();
        let cte_expr = Expression::Cte(Box::new(cte.clone()));
        let mut cte_scope = builder.register(
            current_scope.branch(cte_expr.clone(), ScopeType::Cte),
            current_scope.id,
            &cte_expr,
        );
        cte_scope.outer_columns = identifier_names(&cte.columns);

        if with.recursive && cte_body_self_references(cte) {
            cte_scope.add_cte_source(cte_name.clone(), cte_expr.clone());
        }

        let cte_scope = builder.build_child(cte_scope, &cte.this);
        current_scope.add_cte_source(cte_name, cte_expr);
        current_scope.cte_scopes.push(cte_scope);
    }
}

fn cte_body_self_references(cte: &crate::expressions::Cte) -> bool {
    let cte_name = cte.alias.name.as_str();
    !cte.this
        .find_all(|expr| match expr {
            Expression::Table(table) if table.schema.is_none() && table.catalog.is_none() => {
                table.name.name.eq_ignore_ascii_case(cte_name)
            }
            _ => false,
        })
        .is_empty()
}

fn add_table_to_scope(
    expr: &Expression,
    scope: &mut Scope,
    preceding_sources: &HashSet<String>,
    builder: &mut ScopeBuilder,
) -> Option<String> {
    match expr {
        Expression::Table(table) => {
            let name = table
                .alias
                .as_ref()
                .map(|a| a.name.clone())
                .unwrap_or_else(|| table.name.name.clone());
            let cte_source = if table.schema.is_none() && table.catalog.is_none() {
                scope.cte_sources.get(&table.name.name).or_else(|| {
                    scope
                        .cte_sources
                        .iter()
                        .find(|(cte_name, _)| cte_name.eq_ignore_ascii_case(&table.name.name))
                        .map(|(_, source)| source)
                })
            } else {
                None
            };

            if let Some(source) = cte_source {
                scope.add_source_info(name.clone(), source.clone());
            } else {
                let mut source = SourceInfo::new(expr.clone(), false, SourceKind::Table);
                if let Some(alias) = &table.alias {
                    source = source.with_alias(alias.name.clone());
                }
                scope.add_source_info(name.clone(), source);
            }
            builder.skip_children(scope, expr, &[]);
            Some(name)
        }
        Expression::Subquery(subquery) => {
            let name = subquery
                .alias
                .as_ref()
                .map(|a| a.name.clone())
                .unwrap_or_default();

            let mut derived_scope = builder.branch(scope, &subquery.this, ScopeType::DerivedTable);
            derived_scope.outer_columns = identifier_names(&subquery.column_aliases);
            if subquery.lateral {
                derived_scope.is_lateral = true;
                derived_scope.can_be_correlated = true;
                derived_scope.lateral_sources = preceding_sources
                    .iter()
                    .filter_map(|name| {
                        scope
                            .sources
                            .get(name)
                            .map(|source| (name.clone(), source.clone()))
                    })
                    .collect();
            }
            let derived_scope = builder.build_child(derived_scope, &subquery.this);

            scope.add_source(name.clone(), expr.clone(), true);
            scope.derived_table_scopes.push(derived_scope);
            Some(name)
        }
        Expression::Unnest(unnest) => {
            builder.skip_children(scope, expr, &[]);
            if let Some(alias) = &unnest.alias {
                scope.add_virtual_source(alias.name.clone(), expr.clone());
            }
            unnest.alias.as_ref().map(|alias| alias.name.clone())
        }
        Expression::Values(values) => {
            builder.skip_children(scope, expr, &[]);
            let name = values
                .alias
                .as_ref()
                .map(|alias| alias.name.clone())
                .unwrap_or_default();
            scope.add_virtual_source(name.clone(), expr.clone());
            Some(name)
        }
        Expression::Alias(alias) if is_query_like_relation(&alias.this) => {
            let mut derived_scope = builder.branch(scope, &alias.this, ScopeType::DerivedTable);
            derived_scope.outer_columns = identifier_names(&alias.column_aliases);
            let derived_scope = builder.build_child(derived_scope, &alias.this);

            scope.add_source(alias.alias.name.clone(), expr.clone(), true);
            scope.derived_table_scopes.push(derived_scope);
            Some(alias.alias.name.clone())
        }
        Expression::Alias(alias) => match &alias.this {
            Expression::Unnest(_) => {
                builder.skip_children(scope, &alias.this, &[]);
                scope.add_virtual_source(alias.alias.name.clone(), expr.clone());
                Some(alias.alias.name.clone())
            }
            Expression::Function(_) => {
                add_table_to_scope(&alias.this, scope, preceding_sources, builder)
            }
            _ => {
                builder.skipped(scope, expr);
                None
            }
        },
        Expression::Lateral(lateral) => {
            builder.skip_children(scope, expr, &[]);
            if let Some(alias) = &lateral.alias {
                scope.add_virtual_source(alias.clone(), expr.clone());
            }
            lateral.alias.clone()
        }
        Expression::LateralView(lateral_view) => {
            add_lateral_view_to_scope(lateral_view, scope, builder)
        }
        Expression::Pivot(pivot) => {
            let name =
                pivot_source_name(&pivot.this, pivot.alias.as_ref().map(|a| a.name.as_str()));
            scope.add_source_info(
                name.clone(),
                SourceInfo::new(expr.clone(), false, SourceKind::DerivedTable),
            );
            add_pivot_inner_scope(&pivot.this, scope, builder);
            builder.skip_children(scope, expr, &["this"]);
            Some(name)
        }
        Expression::Unpivot(unpivot) => {
            let name = pivot_source_name(
                &unpivot.this,
                unpivot.alias.as_ref().map(|a| a.name.as_str()),
            );
            scope.add_source_info(
                name.clone(),
                SourceInfo::new(expr.clone(), false, SourceKind::DerivedTable),
            );
            add_pivot_inner_scope(&unpivot.this, scope, builder);
            builder.skip_children(scope, expr, &["this"]);
            Some(name)
        }
        Expression::Paren(paren) => {
            add_table_to_scope(&paren.this, scope, preceding_sources, builder)
        }
        Expression::Function(_) => {
            builder.skip_children(scope, expr, &[]);
            None
        }
        other => {
            builder.skipped(scope, other);
            None
        }
    }
}

fn identifier_names(identifiers: &[Identifier]) -> Vec<String> {
    identifiers
        .iter()
        .map(|identifier| identifier.name.clone())
        .collect()
}

fn is_query_like_relation(expr: &Expression) -> bool {
    match expr {
        Expression::Select(_)
        | Expression::Values(_)
        | Expression::Subquery(_)
        | Expression::Union(_)
        | Expression::Intersect(_)
        | Expression::Except(_) => true,
        Expression::Paren(paren) => is_query_like_relation(&paren.this),
        _ => false,
    }
}

fn pivot_source_name(source: &Expression, explicit_alias: Option<&str>) -> String {
    if let Some(alias) = explicit_alias {
        return alias.to_string();
    }

    match source {
        Expression::Table(table) => table
            .alias
            .as_ref()
            .map(|alias| alias.name.clone())
            .unwrap_or_else(|| table.name.name.clone()),
        Expression::Subquery(subquery) => subquery
            .alias
            .as_ref()
            .map(|alias| alias.name.clone())
            .unwrap_or_else(|| "_0".to_string()),
        Expression::Paren(paren) => pivot_source_name(&paren.this, explicit_alias),
        _ => "_0".to_string(),
    }
}

fn add_pivot_inner_scope(source: &Expression, scope: &mut Scope, builder: &mut ScopeBuilder) {
    match source {
        Expression::Subquery(subquery) => {
            let derived_scope = builder.branch(scope, &subquery.this, ScopeType::DerivedTable);
            let derived_scope = builder.build_child(derived_scope, &subquery.this);
            scope.derived_table_scopes.push(derived_scope);
        }
        Expression::Paren(paren) => add_pivot_inner_scope(&paren.this, scope, builder),
        _ => {}
    }
}

fn add_lateral_view_to_scope(
    lateral_view: &crate::expressions::LateralView,
    scope: &mut Scope,
    builder: &mut ScopeBuilder,
) -> Option<String> {
    builder.skipped(scope, &lateral_view.this);
    let alias = lateral_view
        .table_alias
        .as_ref()
        .or_else(|| lateral_view.column_aliases.first())
        .map(|alias| alias.name.clone());

    if let Some(alias) = &alias {
        scope.add_virtual_source(
            alias.clone(),
            Expression::LateralView(Box::new(lateral_view.clone())),
        );
    }
    alias
}

fn collect_subqueries(expr: &Expression, parent_scope: &mut Scope, builder: &mut ScopeBuilder) {
    if matches!(expr, Expression::Select(_)) {
        use crate::ast_children::ChildPathSegment::{Field, Index};

        // Include JOIN predicates, ORDER BY and QUALIFY as well as projections
        // and WHERE, but do not register FROM/JOIN queries again as scalar
        // subqueries (including derived tables without aliases).
        crate::ast_children::for_each_child(expr, |path, child| {
            if !matches!(
                path,
                [Field("from" | "with" | "lateral_views"), ..]
                    | [Field("joins"), Index(_), Field("this"), ..]
            ) {
                collect_subqueries_in_expr(child, parent_scope, builder);
            }
        });
    }
}

fn collect_subqueries_in_expr(
    expr: &Expression,
    parent_scope: &mut Scope,
    builder: &mut ScopeBuilder,
) {
    let mut seen = HashSet::new();
    let walker = WalkInScopeIter::new(expr, false);
    for node in walk_in_scope(expr, false) {
        let operand = match node {
            Expression::Subquery(subquery) if subquery.alias.is_none() => {
                Some(scope_query(&subquery.this))
            }
            Expression::Exists(exists) => Some(&exists.this),
            Expression::In(in_expr) => in_expr.query.as_ref(),
            Expression::Any(quantified) | Expression::All(quantified) => {
                Some(scope_query(&quantified.subquery)).filter(|query| is_bare_query(query))
            }
            _ => None,
        };
        // The walk stops at a bare query, so find it among its parent's children.
        let bare = walker
            .get_children(node)
            .into_iter()
            .filter(|child| is_bare_query(child));

        for query in operand.into_iter().chain(bare) {
            let key = query as *const Expression as usize;
            if !seen.insert(key) {
                continue;
            }

            let sub_scope = builder.branch(parent_scope, query, ScopeType::Subquery);
            let sub_scope = builder.build_child(sub_scope, query);
            parent_scope.subquery_scopes.push(sub_scope);
        }
    }
}

fn is_bare_query(expr: &Expression) -> bool {
    matches!(
        expr,
        Expression::Select(_)
            | Expression::Union(_)
            | Expression::Intersect(_)
            | Expression::Except(_)
    )
}

/// Walk within a scope, yielding expressions without crossing scope boundaries.
///
/// This iterator visits all nodes in the syntax tree, stopping at nodes that
/// start child scopes (CTEs, derived tables, subqueries in FROM/JOIN).
///
/// # Arguments
/// * `expression` - The expression to walk
/// * `bfs` - If true, uses breadth-first search; otherwise uses depth-first search
///
/// # Returns
/// An iterator over expressions within the scope
pub fn walk_in_scope<'a>(
    expression: &'a Expression,
    bfs: bool,
) -> impl Iterator<Item = &'a Expression> {
    WalkInScopeIter::new(expression, bfs)
}

/// Iterator for walking within a scope
struct WalkInScopeIter<'a> {
    queue: VecDeque<&'a Expression>,
    bfs: bool,
}

impl<'a> WalkInScopeIter<'a> {
    fn new(expression: &'a Expression, bfs: bool) -> Self {
        let mut queue = VecDeque::new();
        queue.push_back(expression);
        Self { queue, bfs }
    }

    fn should_stop_at(&self, expr: &Expression, is_root: bool) -> bool {
        if is_root {
            return false;
        }

        // Stop at CTE definitions
        if matches!(expr, Expression::Cte(_)) {
            return true;
        }

        // Stop at subqueries that are derived tables (in FROM/JOIN)
        if let Expression::Subquery(subquery) = expr {
            if subquery.alias.is_some() {
                return true;
            }
        }

        // Stop at standalone SELECT/UNION/etc that would be subqueries
        is_bare_query(expr)
    }

    fn get_children(&self, expr: &'a Expression) -> Vec<&'a Expression> {
        let mut children = Vec::new();

        match expr {
            Expression::Prepare(prepare) => {
                children.push(&prepare.statement);
            }
            Expression::Select(select) => {
                // Walk SELECT expressions
                for e in &select.expressions {
                    children.push(e);
                }
                // Walk FROM (but tables/subqueries create new scopes)
                if let Some(from) = &select.from {
                    for table in &from.expressions {
                        if !self.should_stop_at(table, false) {
                            children.push(table);
                        }
                    }
                }
                // Walk JOINs (but their sources create new scopes)
                for join in &select.joins {
                    if !self.should_stop_at(&join.this, false) {
                        children.push(&join.this);
                    }
                    if let Some(on) = &join.on {
                        children.push(on);
                    }
                    if let Some(condition) = &join.match_condition {
                        children.push(condition);
                    }
                }
                // Walk WHERE
                if let Some(where_clause) = &select.where_clause {
                    children.push(&where_clause.this);
                }
                // Walk GROUP BY
                if let Some(group_by) = &select.group_by {
                    for e in &group_by.expressions {
                        children.push(e);
                    }
                }
                // Walk HAVING
                if let Some(having) = &select.having {
                    children.push(&having.this);
                }
                if let Some(qualify) = &select.qualify {
                    children.push(&qualify.this);
                }
                // Walk ORDER BY
                if let Some(order_by) = &select.order_by {
                    for ord in &order_by.expressions {
                        children.push(&ord.this);
                    }
                }
                // Walk LIMIT
                if let Some(limit) = &select.limit {
                    children.push(&limit.this);
                }
                // Walk OFFSET
                if let Some(offset) = &select.offset {
                    children.push(&offset.this);
                }
            }
            Expression::And(bin)
            | Expression::Or(bin)
            | Expression::Add(bin)
            | Expression::Sub(bin)
            | Expression::Mul(bin)
            | Expression::Div(bin)
            | Expression::Mod(bin)
            | Expression::Eq(bin)
            | Expression::Neq(bin)
            | Expression::Lt(bin)
            | Expression::Lte(bin)
            | Expression::Gt(bin)
            | Expression::Gte(bin)
            | Expression::BitwiseAnd(bin)
            | Expression::BitwiseOr(bin)
            | Expression::BitwiseXor(bin)
            | Expression::Concat(bin) => {
                children.push(&bin.left);
                children.push(&bin.right);
            }
            Expression::Like(like) | Expression::ILike(like) => {
                children.push(&like.left);
                children.push(&like.right);
                if let Some(escape) = &like.escape {
                    children.push(escape);
                }
            }
            Expression::Not(un) | Expression::Neg(un) | Expression::BitwiseNot(un) => {
                children.push(&un.this);
            }
            Expression::Function(func) => {
                for arg in &func.args {
                    children.push(arg);
                }
            }
            Expression::AggregateFunction(agg) => {
                for arg in &agg.args {
                    children.push(arg);
                }
            }
            Expression::WindowFunction(wf) => {
                children.push(&wf.this);
                for e in &wf.over.partition_by {
                    children.push(e);
                }
                for e in &wf.over.order_by {
                    children.push(&e.this);
                }
            }
            Expression::Alias(alias) => {
                children.push(&alias.this);
            }
            Expression::Case(case) => {
                if let Some(operand) = &case.operand {
                    children.push(operand);
                }
                for (when_expr, then_expr) in &case.whens {
                    children.push(when_expr);
                    children.push(then_expr);
                }
                if let Some(else_clause) = &case.else_ {
                    children.push(else_clause);
                }
            }
            Expression::Paren(paren) => {
                children.push(&paren.this);
            }
            Expression::Ordered(ord) => {
                children.push(&ord.this);
            }
            Expression::In(in_expr) => {
                children.push(&in_expr.this);
                for e in &in_expr.expressions {
                    children.push(e);
                }
                // Note: in_expr.query creates a new scope - don't traverse
            }
            Expression::Between(between) => {
                children.push(&between.this);
                children.push(&between.low);
                children.push(&between.high);
            }
            Expression::IsNull(is_null) => {
                children.push(&is_null.this);
            }
            Expression::Cast(cast) => {
                children.push(&cast.this);
            }
            Expression::Extract(extract) => {
                children.push(&extract.this);
            }
            Expression::Coalesce(coalesce) => {
                for e in &coalesce.expressions {
                    children.push(e);
                }
            }
            Expression::NullIf(nullif) => {
                children.push(&nullif.this);
                children.push(&nullif.expression);
            }
            Expression::Table(_table) => {
                // Tables don't have child expressions to traverse within scope
                // (joins are handled at the Select level)
            }
            Expression::TryCatch(try_catch) => {
                for stmt in &try_catch.try_body {
                    children.push(stmt);
                }
                if let Some(catch_body) = &try_catch.catch_body {
                    for stmt in catch_body {
                        children.push(stmt);
                    }
                }
            }
            Expression::Column(_) | Expression::Literal(_) | Expression::Identifier(_) => {
                // Leaf nodes - no children
            }
            // Subqueries and Exists create new scopes - don't traverse into them
            Expression::Subquery(_) | Expression::Exists(_) => {}
            _ => {
                // Use the canonical AST traversal for other scalar expressions
                // (typed functions, field access, filters, etc.). Scope
                // boundaries are still enforced by should_stop_at.
                children.extend(expr.children());
            }
        }

        children
    }
}

impl<'a> Iterator for WalkInScopeIter<'a> {
    type Item = &'a Expression;

    fn next(&mut self) -> Option<Self::Item> {
        let expr = if self.bfs {
            self.queue.pop_front()?
        } else {
            self.queue.pop_back()?
        };

        // Get children that don't cross scope boundaries
        let children = self.get_children(expr);

        if self.bfs {
            for child in children {
                if !self.should_stop_at(child, false) {
                    self.queue.push_back(child);
                }
            }
        } else {
            for child in children.into_iter().rev() {
                if !self.should_stop_at(child, false) {
                    self.queue.push_back(child);
                }
            }
        }

        Some(expr)
    }
}

/// Find the first expression matching the predicate within this scope.
///
/// This does NOT traverse into subscopes.
///
/// # Arguments
/// * `expression` - The root expression
/// * `predicate` - Function that returns true for matching expressions
/// * `bfs` - If true, uses breadth-first search; otherwise depth-first
///
/// # Returns
/// The first matching expression, or None
pub fn find_in_scope<'a, F>(
    expression: &'a Expression,
    predicate: F,
    bfs: bool,
) -> Option<&'a Expression>
where
    F: Fn(&Expression) -> bool,
{
    walk_in_scope(expression, bfs).find(|e| predicate(e))
}

/// Find all expressions matching the predicate within this scope.
///
/// This does NOT traverse into subscopes.
///
/// # Arguments
/// * `expression` - The root expression
/// * `predicate` - Function that returns true for matching expressions
/// * `bfs` - If true, uses breadth-first search; otherwise depth-first
///
/// # Returns
/// A vector of matching expressions
pub fn find_all_in_scope<'a, F>(
    expression: &'a Expression,
    predicate: F,
    bfs: bool,
) -> Vec<&'a Expression>
where
    F: Fn(&Expression) -> bool,
{
    walk_in_scope(expression, bfs)
        .filter(|e| predicate(e))
        .collect()
}

/// Traverse an expression by its "scopes".
///
/// Returns a list of all scopes in depth-first post-order.
///
/// # Arguments
/// * `expression` - The expression to traverse
///
/// # Returns
/// A vector of all scopes found
pub fn traverse_scope(expression: &Expression) -> Vec<Scope> {
    match expression {
        Expression::Select(_)
        | Expression::Union(_)
        | Expression::Intersect(_)
        | Expression::Except(_)
        | Expression::Prepare(_)
        | Expression::CreateTable(_) => {
            let root = build_scope(expression);
            root.traverse().into_iter().cloned().collect()
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::Parser;

    fn parse_and_build_scope(sql: &str) -> Scope {
        let ast = Parser::parse_sql(sql).expect("Failed to parse SQL");
        build_scope(&ast[0])
    }

    #[test]
    fn test_simple_select_scope() {
        let mut scope = parse_and_build_scope("SELECT a, b FROM t");

        assert!(scope.is_root());
        assert!(!scope.can_be_correlated);
        assert!(scope.sources.contains_key("t"));

        let columns = scope.columns();
        assert_eq!(columns.len(), 2);
    }

    #[test]
    fn test_derived_table_scope() {
        let mut scope = parse_and_build_scope("SELECT x.a FROM (SELECT a FROM t) AS x");

        assert!(scope.sources.contains_key("x"));
        assert_eq!(scope.derived_table_scopes.len(), 1);

        let derived = &mut scope.derived_table_scopes[0];
        assert!(derived.is_derived_table());
        assert!(derived.sources.contains_key("t"));
    }

    #[test]
    fn test_lateral_preceding_sources_472() {
        let scope = parse_and_build_scope(
            "WITH c AS (SELECT a FROM t) SELECT n.a FROM t, LATERAL (SELECT t.a) n, c",
        );
        let lateral = &scope.derived_table_scopes[0];
        assert!(lateral.is_lateral);
        assert!(lateral.can_be_correlated);
        assert_eq!(lateral.lateral_sources.len(), 1);
        assert!(lateral.lateral_sources.contains_key("t"));
        assert!(!lateral.sources.contains_key("t"));
        let scope = parse_and_build_scope("SELECT n.a FROM t, (SELECT t.a) n");
        assert!(!scope.derived_table_scopes[0].is_lateral);
        assert!(scope.derived_table_scopes[0].lateral_sources.is_empty());
    }

    #[test]
    fn test_subquery_collection_respects_relation_boundaries() {
        let scope = parse_and_build_scope(
            "SELECT t.a FROM t JOIN (SELECT a FROM s) ON t.a = 1 \
             WHERE EXISTS (SELECT 1 FROM u) ORDER BY (SELECT MAX(a) FROM v)",
        );
        assert_eq!(scope.derived_table_scopes.len(), 1);
        assert_eq!(scope.subquery_scopes.len(), 2);
        let scope = parse_and_build_scope(
            "SELECT t.a FROM t JOIN s ON EXISTS (SELECT 1 FROM u WHERE u.a = t.a)",
        );
        assert_eq!(scope.subquery_scopes.len(), 1);
        assert!(scope.subquery_scopes[0].sources.contains_key("u"));
    }

    #[test]
    fn test_non_correlated_subquery() {
        let mut scope = parse_and_build_scope("SELECT * FROM t WHERE EXISTS (SELECT b FROM s)");

        assert_eq!(scope.subquery_scopes.len(), 1);

        let subquery = &mut scope.subquery_scopes[0];
        assert!(subquery.is_subquery());
        assert!(subquery.can_be_correlated);

        // The subquery references only 's', which is in its own sources
        assert!(subquery.sources.contains_key("s"));
        assert!(!subquery.is_correlated_subquery());
    }

    #[test]
    fn test_correlated_subquery() {
        let mut scope =
            parse_and_build_scope("SELECT * FROM t WHERE EXISTS (SELECT b FROM s WHERE s.x = t.y)");

        assert_eq!(scope.subquery_scopes.len(), 1);

        let subquery = &mut scope.subquery_scopes[0];
        assert!(subquery.is_subquery());
        assert!(subquery.can_be_correlated);

        // The subquery references 't.y' which is external
        let external = subquery.external_columns();
        assert!(!external.is_empty());
        assert!(external.iter().any(|c| c.table.as_deref() == Some("t")));
        assert!(subquery.is_correlated_subquery());
    }

    #[test]
    fn test_cte_scope() {
        let scope = parse_and_build_scope("WITH cte AS (SELECT a FROM t) SELECT * FROM cte");

        assert_eq!(scope.cte_scopes.len(), 1);
        assert!(scope.cte_sources.contains_key("cte"));

        let cte = &scope.cte_scopes[0];
        assert!(cte.is_cte());
    }

    #[test]
    fn test_multiple_sources() {
        let scope = parse_and_build_scope("SELECT t.a, s.b FROM t JOIN s ON t.id = s.id");

        assert!(scope.sources.contains_key("t"));
        assert!(scope.sources.contains_key("s"));
        assert_eq!(scope.sources.len(), 2);
    }

    #[test]
    fn test_aliased_table() {
        let scope = parse_and_build_scope("SELECT x.a FROM t AS x");

        // Should be indexed by alias, not original name
        assert!(scope.sources.contains_key("x"));
        assert!(!scope.sources.contains_key("t"));
    }

    #[test]
    fn test_local_columns() {
        let mut scope = parse_and_build_scope("SELECT t.a, t.b, s.c FROM t JOIN s ON t.id = s.id");

        let local = scope.local_columns();
        // All columns are local since both t and s are in scope.
        // Includes JOIN ON references (t.id, s.id).
        assert_eq!(local.len(), 5);
        assert!(local.iter().all(|c| c.table.is_some()));
    }

    #[test]
    fn test_columns_include_join_on_clause_references() {
        let mut scope = parse_and_build_scope(
            "SELECT o.total FROM orders o JOIN customers c ON c.id = o.customer_id",
        );

        let cols: Vec<String> = scope
            .columns()
            .iter()
            .map(|c| match &c.table {
                Some(t) => format!("{}.{}", t, c.name),
                None => c.name.clone(),
            })
            .collect();

        assert!(cols.contains(&"o.total".to_string()));
        assert!(cols.contains(&"c.id".to_string()));
        assert!(cols.contains(&"o.customer_id".to_string()));
    }

    #[test]
    fn test_unqualified_columns() {
        let mut scope = parse_and_build_scope("SELECT a, b, t.c FROM t");

        let unqualified = scope.unqualified_columns();
        // Only a and b are unqualified
        assert_eq!(unqualified.len(), 2);
        assert!(unqualified.iter().all(|c| c.table.is_none()));
    }

    #[test]
    fn test_source_columns() {
        let mut scope = parse_and_build_scope("SELECT t.a, t.b, s.c FROM t JOIN s ON t.id = s.id");

        let t_cols = scope.source_columns("t");
        // t.a, t.b, and t.id from JOIN condition
        assert!(t_cols.len() >= 2);
        assert!(t_cols.iter().all(|c| c.table.as_deref() == Some("t")));

        let s_cols = scope.source_columns("s");
        // s.c and s.id from JOIN condition
        assert!(s_cols.len() >= 1);
        assert!(s_cols.iter().all(|c| c.table.as_deref() == Some("s")));
    }

    #[test]
    fn test_rename_source() {
        let mut scope = parse_and_build_scope("SELECT a FROM t");

        assert!(scope.sources.contains_key("t"));
        scope.rename_source("t", "new_name".to_string());
        assert!(!scope.sources.contains_key("t"));
        assert!(scope.sources.contains_key("new_name"));
    }

    #[test]
    fn test_remove_source() {
        let mut scope = parse_and_build_scope("SELECT a FROM t");

        assert!(scope.sources.contains_key("t"));
        scope.remove_source("t");
        assert!(!scope.sources.contains_key("t"));
    }

    #[test]
    fn test_walk_in_scope() {
        let ast = Parser::parse_sql("SELECT a, b FROM t WHERE a > 1").expect("Failed to parse");
        let expr = &ast[0];

        // Walk should visit all expressions within the scope
        let walked: Vec<_> = walk_in_scope(expr, true).collect();
        assert!(!walked.is_empty());

        // Should include the root SELECT
        assert!(walked.iter().any(|e| matches!(e, Expression::Select(_))));
        // Should include columns
        assert!(walked.iter().any(|e| matches!(e, Expression::Column(_))));
    }

    #[test]
    fn test_find_in_scope() {
        let ast = Parser::parse_sql("SELECT a, b FROM t WHERE a > 1").expect("Failed to parse");
        let expr = &ast[0];

        // Find the first column
        let found = find_in_scope(expr, |e| matches!(e, Expression::Column(_)), true);
        assert!(found.is_some());
        assert!(matches!(found.unwrap(), Expression::Column(_)));
    }

    #[test]
    fn test_find_all_in_scope() {
        let ast = Parser::parse_sql("SELECT a, b, c FROM t").expect("Failed to parse");
        let expr = &ast[0];

        // Find all columns
        let found = find_all_in_scope(expr, |e| matches!(e, Expression::Column(_)), true);
        assert_eq!(found.len(), 3);
    }

    #[test]
    fn test_traverse_scope() {
        let ast =
            Parser::parse_sql("SELECT a FROM (SELECT b FROM t) AS x").expect("Failed to parse");
        let expr = &ast[0];

        let scopes = traverse_scope(expr);
        // traverse_scope returns all scopes via Scope::traverse
        // which includes derived table and root scopes
        assert!(!scopes.is_empty());
        // The root scope is always included
        assert!(scopes.iter().any(|s| s.is_root()));
    }

    #[test]
    fn test_branch_with_options() {
        let ast = Parser::parse_sql("SELECT a FROM t").expect("Failed to parse");
        let scope = build_scope(&ast[0]);

        let child = scope.branch_with_options(
            ast[0].clone(),
            ScopeType::Subquery, // Use Subquery to test can_be_correlated
            None,
            None,
            Some(vec!["col1".to_string(), "col2".to_string()]),
        );

        assert_eq!(child.outer_columns, vec!["col1", "col2"]);
        assert!(child.can_be_correlated); // Subqueries are correlated
    }

    fn first_from_item(sql: &str) -> Expression {
        let ast = Parser::parse_sql(sql).expect("Failed to parse SQL");
        match &ast[0] {
            Expression::Select(select) => select.from.as_ref().unwrap().expressions[0].clone(),
            other => panic!("expected a SELECT, got {other:?}"),
        }
    }

    #[test]
    fn test_derived_table_outer_columns() {
        let scope = parse_and_build_scope("SELECT q.a FROM (SELECT 1, 2) AS q(a, b)");
        assert_eq!(scope.derived_table_scopes[0].outer_columns, ["a", "b"]);

        let scope = parse_and_build_scope("SELECT q.x FROM (SELECT 1 AS x) AS q");
        assert!(scope.derived_table_scopes[0].outer_columns.is_empty());
    }

    #[test]
    fn test_parenthesized_derived_table_outer_columns() {
        let sql = "SELECT q.a FROM ((SELECT 1)) AS q(a)";
        assert!(matches!(first_from_item(sql), Expression::Alias(_)));

        let scope = parse_and_build_scope(sql);
        assert_eq!(scope.derived_table_scopes[0].outer_columns, ["a"]);
    }

    #[test]
    fn test_cte_outer_columns() {
        let scope = parse_and_build_scope("WITH c(a, b) AS (SELECT 1, 2) SELECT a FROM c");
        assert_eq!(scope.cte_scopes[0].outer_columns, ["a", "b"]);

        let scope = parse_and_build_scope("WITH c AS (SELECT 1 AS x) SELECT x FROM c");
        assert!(scope.cte_scopes[0].outer_columns.is_empty());

        let scope = parse_and_build_scope(
            "WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM c WHERE n < 3) \
             SELECT n FROM c",
        );
        assert_eq!(scope.cte_scopes[0].outer_columns, ["n"]);
    }

    #[test]
    fn test_is_udtf() {
        let ast = Parser::parse_sql("SELECT a FROM t").expect("Failed to parse");
        let scope = Scope::new(ast[0].clone());
        assert!(!scope.is_udtf());

        let root = build_scope(&ast[0]);
        let udtf_scope = root.branch(ast[0].clone(), ScopeType::Udtf);
        assert!(udtf_scope.is_udtf());
    }

    #[test]
    fn test_is_union() {
        let scope = parse_and_build_scope("SELECT a FROM t UNION SELECT b FROM s");

        assert!(scope.is_root());
        assert_eq!(scope.union_scopes.len(), 2);
        // The children are set operation scopes
        assert!(scope.union_scopes[0].is_union());
        assert!(scope.union_scopes[1].is_union());
    }

    #[test]
    fn test_in_parenthesized_set_operation_is_a_subquery_scope() {
        let scope = parse_and_build_scope(
            "SELECT * FROM t WHERE x IN ((SELECT a FROM u) UNION (SELECT b FROM v))",
        );

        assert_eq!(scope.subquery_scopes.len(), 1);
        assert_eq!(scope.subquery_scopes[0].union_scopes.len(), 2);
    }

    #[test]
    fn test_quantified_subquery_is_one_subquery_scope() {
        for sql in [
            "SELECT x FROM t WHERE x = ANY (SELECT k FROM u)",
            "SELECT x FROM t WHERE x > ALL (SELECT k FROM u)",
            "SELECT x FROM t WHERE x <> SOME (SELECT k FROM u)",
            "SELECT x FROM t WHERE x = SOME (SELECT k FROM u)",
            "SELECT x FROM t WHERE x = ANY (((SELECT k FROM u)))",
            "SELECT x FROM t WHERE x = ((SELECT k FROM u))",
            "SELECT x FROM t WHERE x IN (SELECT k FROM u)",
            "SELECT x FROM t WHERE EXISTS (SELECT k FROM u)",
        ] {
            let scope = parse_and_build_scope(sql);
            assert_eq!(scope.subquery_scopes.len(), 1, "{sql}");
            assert!(
                matches!(scope.subquery_scopes[0].expression, Expression::Select(_)),
                "{sql}"
            );
        }
    }

    #[test]
    fn test_function_argument_query_is_one_subquery_scope() {
        use crate::DialectType::{BigQuery, ClickHouse, Generic, PostgreSQL};

        for (dialect, sql) in [
            (Generic, "SELECT ARRAY(SELECT x FROM u) FROM t"),
            (BigQuery, "SELECT ARRAY(SELECT x FROM u) FROM t"),
            (PostgreSQL, "SELECT ARRAY(SELECT x FROM u) FROM t"),
            (
                Generic,
                "SELECT 1 FROM t WHERE LENGTH(ARRAY(SELECT x FROM u)) > 0",
            ),
            (Generic, "SELECT 1 FROM t GROUP BY ARRAY(SELECT x FROM u)"),
            (
                Generic,
                "SELECT 1 FROM t HAVING ARRAY(SELECT x FROM u) = t.a",
            ),
            (Generic, "SELECT 1 FROM t ORDER BY ARRAY(SELECT x FROM u)"),
            (
                Generic,
                "SELECT 1 FROM t JOIN s ON ARRAY(SELECT x FROM u) = s.a",
            ),
            (
                Generic,
                "SELECT 1 FROM t QUALIFY ARRAY(SELECT x FROM u) = t.a",
            ),
            (ClickHouse, "SELECT f(SELECT x FROM u) FROM t"),
        ] {
            let ast = crate::parse(sql, dialect).expect("Failed to parse SQL");
            let scope = build_scope(&ast[0]);
            assert_eq!(scope.subquery_scopes.len(), 1, "{sql}");
            let subquery = &scope.subquery_scopes[0];
            assert!(subquery.is_subquery(), "{sql}");
            assert!(subquery.sources.contains_key("u"), "{sql}");
            assert!(!scope.sources.contains_key("u"), "{sql}");
        }

        let scope =
            parse_and_build_scope("SELECT ARRAY(SELECT x FROM u UNION ALL SELECT y FROM v) FROM t");
        assert_eq!(scope.subquery_scopes.len(), 1);
        assert_eq!(scope.subquery_scopes[0].union_scopes.len(), 2);

        // An array operand of ANY/ALL is not a query, so only its inner query gets a scope.
        for sql in [
            "SELECT 1 FROM t WHERE x = ANY(ARRAY(SELECT y FROM u))",
            "SELECT 1 FROM t WHERE x = ALL(ARRAY(SELECT y FROM u))",
        ] {
            let scope = parse_and_build_scope(sql);
            assert_eq!(scope.subquery_scopes.len(), 1, "{sql}");
            assert!(scope.subquery_scopes[0].is_subquery(), "{sql}");
            assert!(scope.subquery_scopes[0].sources.contains_key("u"), "{sql}");
        }
    }

    #[test]
    fn test_nested_and_mixed_subquery_operands_register_once() {
        let scope = parse_and_build_scope(
            "SELECT ARRAY(SELECT ARRAY(SELECT z FROM w) FROM u), \
                    (SELECT 1 FROM v) \
             FROM t WHERE a IN (SELECT 1 FROM u) AND EXISTS (SELECT 1 FROM u)",
        );
        assert_eq!(scope.subquery_scopes.len(), 4);
        let array_arg = &scope.subquery_scopes[0];
        assert_eq!(array_arg.subquery_scopes.len(), 1);
        assert!(array_arg.subquery_scopes[0].sources.contains_key("w"));
    }

    #[test]
    fn test_visitor_reports_function_argument_query() {
        let (scope, recorder) = record(
            "SELECT ARRAY(SELECT x FROM u) FROM t",
            crate::DialectType::Generic,
        );
        let [root, subquery] = &recorder.entered[..] else {
            panic!("expected a root scope and one subquery scope");
        };
        assert_eq!(scope.subquery_scopes[0].id(), Some(subquery.id));
        assert_eq!(subquery.parent, Some(root.id));
        assert!(matches!(subquery.scope_type, ScopeType::Subquery));
    }

    #[test]
    fn test_union_output_columns() {
        let scope = parse_and_build_scope(
            "SELECT id, name FROM customers UNION ALL SELECT id, name FROM employees",
        );
        assert_eq!(scope.output_columns(), vec!["id", "name"]);
    }

    #[test]
    fn test_clear_cache() {
        let mut scope = parse_and_build_scope("SELECT t.a FROM t");

        // First call populates cache
        let _ = scope.columns();
        assert!(scope.columns_cache.is_some());

        // Clear cache
        scope.clear_cache();
        assert!(scope.columns_cache.is_none());
        assert!(scope.external_columns_cache.is_none());
    }

    #[test]
    fn test_scope_traverse() {
        let scope = parse_and_build_scope(
            "WITH cte AS (SELECT a FROM t) SELECT * FROM cte WHERE EXISTS (SELECT b FROM s)",
        );

        let traversed = scope.traverse();
        // CTE scope, subquery scope, root scope
        assert_eq!(traversed.len(), 3);
    }

    #[test]
    fn test_traverse_scope_nested_derived_tables_post_order() {
        let ast = Parser::parse_sql("SELECT a FROM (SELECT b FROM (SELECT c FROM t) y) x").unwrap();
        let scopes = traverse_scope(&ast[0]);

        let types: Vec<_> = scopes.iter().map(|s| s.scope_type).collect();
        assert_eq!(
            types,
            vec![
                ScopeType::DerivedTable,
                ScopeType::DerivedTable,
                ScopeType::Root
            ]
        );
        assert!(scopes[0].sources.contains_key("t"));
        assert!(scopes[1].sources.contains_key("y"));
        assert!(scopes[2].sources.contains_key("x"));
    }

    #[test]
    fn test_traverse_scope_mixed_scopes_each_once() {
        let ast = Parser::parse_sql(
            "WITH c AS (SELECT a FROM t1) \
             SELECT * FROM (SELECT a FROM c) d \
             WHERE EXISTS (SELECT 1 FROM t2) \
             UNION ALL SELECT a FROM t3",
        )
        .unwrap();
        let scopes = traverse_scope(&ast[0]);

        let count = |scope_type| scopes.iter().filter(|s| s.scope_type == scope_type).count();
        assert_eq!(count(ScopeType::Cte), 1);
        assert_eq!(count(ScopeType::DerivedTable), 1);
        assert_eq!(count(ScopeType::Subquery), 1);
        assert_eq!(count(ScopeType::SetOperation), 2);
        assert_eq!(count(ScopeType::Root), 1);
        assert_eq!(scopes.len(), 6);
    }

    #[test]
    fn test_create_table_as_select_scope() {
        // Simple CTAS
        let scope = parse_and_build_scope("CREATE TABLE out_table AS SELECT 1 AS id FROM src");
        assert!(
            scope.sources.contains_key("src"),
            "CTAS scope should contain the FROM table"
        );
        assert!(
            !scope.sources.contains_key("out_table"),
            "CTAS target table should not be treated as a source"
        );

        // CTAS with multiple FROM tables
        let scope = parse_and_build_scope(
            "CREATE TABLE out_table AS SELECT a.id FROM foo AS a JOIN bar AS b ON a.id = b.id",
        );
        assert!(scope.sources.contains_key("a"));
        assert!(scope.sources.contains_key("b"));
        assert!(
            !scope.sources.contains_key("out_table"),
            "CTAS target table should not be treated as a source"
        );

        // CTAS with CTEs
        let scope = parse_and_build_scope(
            "CREATE TABLE out_table AS WITH cte AS (SELECT 1 AS id FROM src) SELECT * FROM cte",
        );
        assert!(
            scope.sources.contains_key("cte"),
            "CTAS with CTE should resolve CTE as source"
        );
        assert!(
            !scope.sources.contains_key("out_table"),
            "CTAS target table should not be treated as a source"
        );
        assert_eq!(scope.cte_scopes.len(), 1);
    }

    #[derive(Debug, PartialEq)]
    struct Reference {
        scope: ScopeId,
        index: usize,
        depth: usize,
        registered_as: Option<String>,
        child: Option<ScopeId>,
    }

    #[derive(Debug)]
    struct Entered {
        id: ScopeId,
        parent: Option<ScopeId>,
        scope_type: ScopeType,
    }

    /// Records visitor events, asserting that they nest like a stack.
    #[derive(Default)]
    struct Recorder {
        open: Vec<ScopeId>,
        entered: Vec<Entered>,
        references: Vec<Reference>,
        skipped: Vec<Expression>,
    }

    impl Recorder {
        fn assert_innermost(&self, scope: ScopeId) {
            assert_eq!(self.open.last(), Some(&scope));
        }
    }

    impl ScopeVisitor for Recorder {
        fn enter_scope(
            &mut self,
            id: ScopeId,
            parent: Option<ScopeId>,
            scope_type: ScopeType,
            _expression: &Expression,
        ) {
            assert_eq!(parent, self.open.last().copied());
            self.open.push(id);
            self.entered.push(Entered {
                id,
                parent,
                scope_type,
            });
        }

        fn reference(
            &mut self,
            scope: ScopeId,
            index: usize,
            depth: usize,
            _item: &Expression,
            registered_as: Option<&str>,
            child: Option<ScopeId>,
        ) {
            self.assert_innermost(scope);
            self.references.push(Reference {
                scope,
                index,
                depth,
                registered_as: registered_as.map(String::from),
                child,
            });
        }

        fn skipped(&mut self, scope: ScopeId, expression: &Expression) {
            self.assert_innermost(scope);
            self.skipped.push(expression.clone());
        }

        fn exit_scope(&mut self, id: ScopeId) {
            assert_eq!(self.open.pop(), Some(id));
        }
    }

    fn record(sql: &str, dialect: crate::DialectType) -> (Scope, Recorder) {
        let ast = crate::parse(sql, dialect).expect("Failed to parse SQL");
        let mut recorder = Recorder::default();
        let scope = build_scope_with(&ast[0], &mut recorder);
        assert!(recorder.open.is_empty(), "{sql}");
        (scope, recorder)
    }

    #[test]
    fn test_visitor_reports_references() {
        use crate::DialectType::Generic;

        let (scope, recorder) = record(
            "SELECT * FROM a JOIN (SELECT 1) x ON TRUE JOIN LATERAL (SELECT a.c) l ON TRUE",
            Generic,
        );
        let root = scope.id().unwrap();
        let reference = |index, name: &str, child: Option<&Scope>| Reference {
            scope: root,
            index,
            depth: 0,
            registered_as: Some(name.to_string()),
            child: child.map(|child| child.id().unwrap()),
        };
        assert_eq!(
            recorder.references,
            [
                reference(0, "a", None),
                reference(1, "x", Some(&scope.derived_table_scopes[0])),
                reference(2, "l", Some(&scope.derived_table_scopes[1])),
            ]
        );

        let (scope, recorder) = record("SELECT * FROM (SELECT 1), (SELECT 2)", Generic);
        assert_eq!(scope.sources.len(), 1);
        let names: Vec<_> = recorder
            .references
            .iter()
            .filter(|reference| Some(reference.scope) == scope.id())
            .map(|reference| reference.registered_as.as_deref())
            .collect();
        assert_eq!(names, [Some(""), Some("")]);

        let (_, recorder) = record("SELECT * FROM (a JOIN b ON TRUE) JOIN c ON TRUE", Generic);
        let items: Vec<_> = recorder
            .references
            .iter()
            .map(|reference| {
                (
                    reference.index,
                    reference.depth,
                    reference.registered_as.as_deref(),
                )
            })
            .collect();
        assert_eq!(items, [(0, 0, None), (1, 0, Some("c"))]);
    }

    #[test]
    fn test_visitor_reports_skipped() {
        use crate::DialectType::{Generic, Hive, Snowflake};

        // (dialect, sql, skipped subtrees, whether one of them holds a query)
        for (dialect, sql, count, holds_query) in [
            (Generic, "SELECT * FROM UNNEST(arr)", 1, false),
            (
                Generic,
                "SELECT * FROM UNNEST((SELECT [1])) AS x(v)",
                1,
                true,
            ),
            (Generic, "SELECT * FROM f((SELECT 1))", 1, true),
            (Generic, "SELECT * FROM f((SELECT 1)) AS g", 1, true),
            (
                Generic,
                "SELECT * FROM (VALUES ((SELECT 1))) AS v(x)",
                1,
                true,
            ),
            (
                Snowflake,
                "SELECT * FROM VALUES (1), ((SELECT 2)) AS v(x)",
                2,
                true,
            ),
            (
                Snowflake,
                "SELECT * FROM t, LATERAL FLATTEN(input => (SELECT a FROM u))",
                1,
                true,
            ),
            (
                Hive,
                "SELECT * FROM t LATERAL VIEW explode((SELECT a FROM u)) e AS x",
                1,
                true,
            ),
            (
                Snowflake,
                "SELECT * FROM t AT(TIMESTAMP => (SELECT MAX(ts) FROM u))",
                2,
                true,
            ),
            (
                Generic,
                "SELECT * FROM t TABLESAMPLE BERNOULLI (10)",
                1,
                false,
            ),
            (
                Snowflake,
                "SELECT * FROM t PIVOT(SUM(a) FOR b IN (SELECT b FROM u))",
                2,
                true,
            ),
            (
                Generic,
                "SELECT * FROM (a JOIN b ON TRUE) JOIN c ON TRUE",
                1,
                false,
            ),
            (Generic, "SELECT * FROM t, (SELECT 1) d", 0, false),
        ] {
            let (_, recorder) = record(sql, dialect);
            assert_eq!(
                recorder.skipped.len(),
                count,
                "{sql}: {:?}",
                recorder.skipped
            );
            let has_query = recorder.skipped.iter().any(|expression| {
                !expression
                    .find_all(|node| matches!(node, Expression::Select(_)))
                    .is_empty()
            });
            assert_eq!(has_query, holds_query, "{sql}");
        }
    }

    fn child_scopes(scope: &Scope) -> impl Iterator<Item = &Scope> {
        scope
            .cte_scopes
            .iter()
            .chain(&scope.union_scopes)
            .chain(&scope.derived_table_scopes)
            .chain(&scope.udtf_scopes)
            .chain(&scope.subquery_scopes)
    }

    /// Checks every scope of the tree against its `enter_scope` event, removing
    /// the events it matches.
    fn assert_mirrors(scope: &Scope, parent: Option<ScopeId>, entered: &mut Vec<Entered>) {
        let id = scope.id().expect("built scopes have an id");
        let position = entered
            .iter()
            .position(|event| event.id == id)
            .expect("every built scope is entered");
        let event = entered.remove(position);
        assert_eq!((event.parent, event.scope_type), (parent, scope.scope_type));
        for child in child_scopes(scope) {
            assert_mirrors(child, Some(id), entered);
        }
    }

    #[test]
    fn test_visitor_mirrors_tree() {
        use crate::DialectType::{DuckDB, Generic};

        for (dialect, sql) in [
            (
                Generic,
                "WITH c AS (SELECT 1) SELECT * FROM c, (SELECT 2 UNION SELECT 3) d, \
                 LATERAL (SELECT c.x) l WHERE c.x IN (SELECT 1) ORDER BY (SELECT 2)",
            ),
            (
                DuckDB,
                "SELECT * FROM (SELECT region, q, amt FROM sales) \
                 PIVOT(SUM(amt) FOR q IN ('Q1' AS q1))",
            ),
        ] {
            let (scope, mut recorder) = record(sql, dialect);
            let ids: Vec<_> = recorder.entered.iter().map(|event| event.id).collect();
            assert!(ids.windows(2).all(|pair| pair[0] < pair[1]), "{sql}");
            assert_eq!(ids.first().copied(), scope.id(), "{sql}");
            assert_mirrors(&scope, None, &mut recorder.entered);
            assert!(recorder.entered.is_empty(), "{sql}");
        }

        let (scope, recorder) = record(
            "SELECT * FROM (SELECT region, q, amt FROM sales) \
             PIVOT(SUM(amt) FOR q IN ('Q1' AS q1))",
            DuckDB,
        );
        assert_eq!(
            recorder.references.last().unwrap().child,
            scope.derived_table_scopes[0].id()
        );
    }

    /// Records the node `enter_scope` reports for each scope.
    #[derive(Default)]
    struct EnteredNodes(Vec<(ScopeType, *const Expression)>);

    impl ScopeVisitor for EnteredNodes {
        fn enter_scope(
            &mut self,
            _id: ScopeId,
            _parent: Option<ScopeId>,
            scope_type: ScopeType,
            expression: &Expression,
        ) {
            self.0.push((scope_type, expression));
        }
    }

    fn entered_nodes(ast: &Expression, scope_type: ScopeType) -> Vec<*const Expression> {
        let mut visitor = EnteredNodes::default();
        build_scope_with(ast, &mut visitor);
        visitor
            .0
            .into_iter()
            .filter(|(entered, _)| *entered == scope_type)
            .map(|(_, node)| node)
            .collect()
    }

    #[test]
    fn test_visitor_enters_input_nodes() {
        // The two scalar subqueries have identical bodies, so only their
        // addresses tell them apart.
        let ast = crate::parse(
            "SELECT (SELECT 1) AS a, (SELECT 1) AS b",
            Default::default(),
        )
        .expect("Failed to parse SQL");
        let Expression::Select(select) = &ast[0] else {
            panic!("expected a SELECT");
        };
        let expected: Vec<_> = select.expressions.iter().map(scope_query).collect();
        let entered = entered_nodes(&ast[0], ScopeType::Subquery);
        assert_eq!(entered.len(), 2);
        for (entered, expected) in entered.into_iter().zip(expected) {
            assert!(std::ptr::eq(entered, expected));
        }

        let ast = crate::parse("SELECT * FROM (SELECT 1) AS d", Default::default())
            .expect("Failed to parse SQL");
        let Expression::Select(select) = &ast[0] else {
            panic!("expected a SELECT");
        };
        let derived = &select.from.as_ref().unwrap().expressions[0];
        let entered = entered_nodes(&ast[0], ScopeType::DerivedTable);
        assert_eq!(entered.len(), 1);
        assert!(std::ptr::eq(entered[0], scope_query(derived)));

        let ast = crate::parse("WITH c AS (SELECT 1) SELECT * FROM c", Default::default())
            .expect("Failed to parse SQL");
        let Expression::Select(select) = &ast[0] else {
            panic!("expected a SELECT");
        };
        let cte = &select.with.as_ref().unwrap().ctes[0];
        let entered = entered_nodes(&ast[0], ScopeType::Cte);
        assert_eq!(entered.len(), 1);
        assert!(!std::ptr::eq(entered[0], &cte.this));
    }

    #[test]
    fn test_visitor_enters_cte_as_cte_expression() {
        #[derive(Default)]
        struct CteNames(Vec<String>);

        impl ScopeVisitor for CteNames {
            fn enter_scope(
                &mut self,
                _id: ScopeId,
                _parent: Option<ScopeId>,
                scope_type: ScopeType,
                expression: &Expression,
            ) {
                if scope_type == ScopeType::Cte {
                    let Expression::Cte(cte) = expression else {
                        panic!("expected an Expression::Cte");
                    };
                    self.0.push(cte.alias.name.clone());
                }
            }
        }

        let ast = crate::parse(
            "WITH a AS (SELECT 1), b AS (SELECT 2) SELECT * FROM a, b",
            Default::default(),
        )
        .expect("Failed to parse SQL");
        let mut visitor = CteNames::default();
        build_scope_with(&ast[0], &mut visitor);
        assert_eq!(visitor.0, ["a", "b"]);
    }

    #[test]
    fn test_create_table_as_select_traverse() {
        let ast = Parser::parse_sql("CREATE TABLE t AS SELECT a FROM src").unwrap();
        let scopes = traverse_scope(&ast[0]);
        assert!(
            !scopes.is_empty(),
            "traverse_scope should return scopes for CTAS"
        );
    }
}
