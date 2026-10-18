use crate::{DBCore, DbError, DbResult, IndexExpression, Order, Table, Value};
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap};

#[derive(Debug, Clone, PartialEq)]
pub struct SqlResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
}

fn validate_function(name: &str, arguments: usize) -> DbResult<()> {
    match name {
        "lower" | "upper" | "trim" | "length" if arguments == 1 => Ok(()),
        "concat" if arguments > 0 => Ok(()),
        "substr" | "substring" if (2..=3).contains(&arguments) => Ok(()),
        "lower" | "upper" | "trim" | "length" => Err(sql_error(&format!(
            "Funktion {name} erwartet genau ein Argument"
        ))),
        "concat" => Err(sql_error("CONCAT erwartet mindestens ein Argument")),
        "substr" | "substring" => Err(sql_error("SUBSTR erwartet zwei oder drei Argumente")),
        _ => Err(sql_error(&format!("unbekannte Funktion '{name}'"))),
    }
}

#[derive(Debug, Clone)]
pub struct PreparedStatement {
    source: String,
    query: Query,
    parameter_count: usize,
}

#[derive(Debug, Clone)]
struct Query {
    table: String,
    projections: Vec<SelectItem>,
    wildcard: bool,
    predicates: Vec<Predicate>,
    order: Vec<(String, Order)>,
    limit: Option<usize>,
    distinct: bool,
}

#[derive(Debug, Clone)]
struct SelectItem {
    expression: Expr,
    alias: Option<String>,
}

#[derive(Debug, Clone)]
enum Predicate {
    Compare {
        column: String,
        operator: CompareOp,
        value: Expr,
    },
    ExpressionCompare {
        expression: IndexExpression,
        value: Expr,
    },
    IsNull {
        column: String,
        negate: bool,
    },
    Like {
        column: String,
        pattern: Expr,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompareOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone)]
enum Expr {
    Column(String),
    Literal(Value),
    Parameter(usize),
    UnaryMinus(Box<Expr>),
    Binary {
        left: Box<Expr>,
        operator: char,
        right: Box<Expr>,
    },
    Function {
        name: String,
        arguments: Vec<Expr>,
    },
    Case {
        branches: Vec<(Expr, CompareOp, Expr, Expr)>,
        otherwise: Box<Expr>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Identifier(String),
    Number(String),
    String(String),
    Parameter(usize),
    Operator(String),
    LeftParen,
    RightParen,
    Comma,
    Star,
    Semicolon,
}

impl PreparedStatement {
    pub(crate) fn parse(source: &str) -> DbResult<Self> {
        let tokens = tokenize(source)?;
        let mut parser = Parser { tokens, at: 0 };
        let query = parser.query()?;
        let mut parameters = BTreeSet::new();
        query.parameter_indexes(&mut parameters);
        let parameter_count = parameters.last().copied().unwrap_or(0);
        if parameters.iter().copied().ne(1..=parameter_count) {
            return Err(sql_error(
                "Positionsparameter müssen lückenlos bei $1 beginnen",
            ));
        }
        Ok(Self {
            source: source.to_string(),
            query,
            parameter_count,
        })
    }

    pub fn sql(&self) -> &str {
        &self.source
    }

    pub fn parameter_count(&self) -> usize {
        self.parameter_count
    }

    pub fn query(&self, db: &DBCore, parameters: &[Value]) -> DbResult<SqlResult> {
        let bound = self.bind(parameters)?;
        let (query, source_columns, result_columns, projections) = self.query.build(db, &bound)?;
        let raw = query.try_collect_values()?;
        if self.query.wildcard {
            return Ok(SqlResult {
                columns: result_columns,
                rows: raw,
            });
        }
        let indexes: HashMap<&str, usize> = source_columns
            .iter()
            .enumerate()
            .map(|(index, column)| (column.as_str(), index))
            .collect();
        let mut rows = raw
            .iter()
            .map(|row| {
                projections
                    .iter()
                    .map(|expression| evaluate(expression, row, &indexes, &bound))
                    .collect::<DbResult<Vec<_>>>()
            })
            .collect::<DbResult<Vec<_>>>()?;
        if self.query.distinct {
            let mut seen = Vec::new();
            rows.retain(|row| {
                if seen.contains(row) {
                    false
                } else {
                    seen.push(row.clone());
                    true
                }
            });
        }
        Ok(SqlResult {
            columns: result_columns,
            rows,
        })
    }

    pub fn execute(&self, db: &DBCore, parameters: &[Value]) -> DbResult<SqlResult> {
        self.query(db, parameters)
    }

    pub fn explain(&self, db: &DBCore, parameters: &[Value]) -> DbResult<String> {
        let bound = self.bind(parameters)?;
        let (query, _, _, _) = self.query.build(db, &bound)?;
        Ok(query.explain())
    }

    fn bind(&self, parameters: &[Value]) -> DbResult<Vec<Value>> {
        if parameters.len() != self.parameter_count {
            return Err(sql_error(&format!(
                "erwartete {} Parameter, erhalten {}",
                self.parameter_count,
                parameters.len()
            )));
        }
        Ok(parameters.to_vec())
    }
}

impl Query {
    fn build<'a>(
        &self,
        db: &'a DBCore,
        parameters: &[Value],
    ) -> DbResult<(Table<'a>, Vec<String>, Vec<String>, Vec<Expr>)> {
        let schema = db.try_schema(&self.table)?;
        let all_columns: Vec<String> = schema.into_iter().map(|column| column.name).collect();
        let projections: Vec<Expr> = if self.wildcard {
            all_columns.iter().cloned().map(Expr::Column).collect()
        } else {
            self.projections
                .iter()
                .map(|item| item.expression.clone())
                .collect()
        };
        let result_columns = if self.wildcard {
            all_columns.clone()
        } else {
            self.projections
                .iter()
                .map(|item| {
                    item.alias
                        .clone()
                        .unwrap_or_else(|| match &item.expression {
                            Expr::Column(column) => {
                                column.rsplit('.').next().unwrap_or(column).to_string()
                            }
                            _ => expression_name(&item.expression),
                        })
                })
                .collect()
        };

        let mut needed = BTreeSet::new();
        if self.wildcard {
            needed.extend(all_columns.iter().cloned());
        } else {
            for projection in &projections {
                projection.columns(&mut needed);
            }
            for predicate in &self.predicates {
                predicate.columns(&mut needed);
            }
            needed.extend(self.order.iter().map(|(column, _)| column.clone()));
            if needed.is_empty() {
                let first = all_columns
                    .first()
                    .ok_or_else(|| sql_error("Tabelle hat keine Spalten"))?;
                needed.insert(first.clone());
            }
        }
        let source_columns: Vec<String> = needed
            .into_iter()
            .map(|column| normalize_column(&self.table, &column))
            .collect::<DbResult<_>>()?;

        let mut query = db.table(&self.table);
        for predicate in &self.predicates {
            query = match predicate {
                Predicate::Compare {
                    column,
                    operator,
                    value,
                } => {
                    let value = evaluate(value, &[], &HashMap::new(), parameters)?;
                    let value = value.as_input();
                    let column = normalize_column(&self.table, column)?;
                    match operator {
                        CompareOp::Eq => query.where_eq(&column, value),
                        CompareOp::Ne => query.where_ne(&column, value),
                        CompareOp::Lt => query.where_lt(&column, value),
                        CompareOp::Le => query.where_le(&column, value),
                        CompareOp::Gt => query.where_gt(&column, value),
                        CompareOp::Ge => query.where_ge(&column, value),
                    }
                }
                Predicate::ExpressionCompare { expression, value } => {
                    let value = evaluate(value, &[], &HashMap::new(), parameters)?;
                    query.where_expr_eq(
                        normalize_expression(&self.table, expression)?,
                        value.as_input(),
                    )
                }
                Predicate::IsNull { column, negate } => {
                    let column = normalize_column(&self.table, column)?;
                    if *negate {
                        query.where_not_null(&column)
                    } else {
                        query.where_null(&column)
                    }
                }
                Predicate::Like { column, pattern } => {
                    let pattern = evaluate(pattern, &[], &HashMap::new(), parameters)?;
                    let column = normalize_column(&self.table, column)?;
                    match pattern {
                        Value::Text(pattern) => query.where_like(&column, &pattern),
                        Value::Null => query.where_eq(&column, "\0"),
                        value => query.where_like(&column, &value.as_input()),
                    }
                }
            };
        }
        for (index, (column, direction)) in self.order.iter().enumerate() {
            let column = normalize_column(&self.table, column)?;
            query = if index == 0 {
                query.order_by(&column)
            } else {
                query.then_by(&column)
            };
            query = match direction {
                Order::Asc => query.asc(),
                Order::Desc => query.desc(),
            };
        }
        if self.distinct && self.wildcard {
            query = query.distinct();
        }
        if let Some(limit) = self.limit {
            query = query.limit(limit);
        }
        if !self.wildcard {
            let selected: Vec<&str> = source_columns.iter().map(String::as_str).collect();
            query = query.select(&selected);
        }
        Ok((query, source_columns, result_columns, projections))
    }

    fn parameter_indexes(&self, output: &mut BTreeSet<usize>) {
        for item in &self.projections {
            item.expression.parameters(output);
        }
        for predicate in &self.predicates {
            predicate.parameters(output);
        }
    }
}

impl Predicate {
    fn columns(&self, output: &mut BTreeSet<String>) {
        match self {
            Predicate::Compare { column, value, .. } => {
                output.insert(column.clone());
                value.columns(output);
            }
            Predicate::ExpressionCompare { expression, value } => {
                let column = match expression {
                    IndexExpression::Lower(column)
                    | IndexExpression::Upper(column)
                    | IndexExpression::Length(column) => column,
                };
                output.insert(column.clone());
                value.columns(output);
            }
            Predicate::IsNull { column, .. } => {
                output.insert(column.clone());
            }
            Predicate::Like { column, pattern } => {
                output.insert(column.clone());
                pattern.columns(output);
            }
        }
    }

    fn parameters(&self, output: &mut BTreeSet<usize>) {
        match self {
            Predicate::Compare { value, .. } => value.parameters(output),
            Predicate::ExpressionCompare { value, .. } => value.parameters(output),
            Predicate::Like { pattern, .. } => pattern.parameters(output),
            Predicate::IsNull { .. } => {}
        }
    }
}

impl Expr {
    fn columns(&self, output: &mut BTreeSet<String>) {
        match self {
            Expr::Column(column) => {
                output.insert(column.clone());
            }
            Expr::UnaryMinus(expression) => expression.columns(output),
            Expr::Binary { left, right, .. } => {
                left.columns(output);
                right.columns(output);
            }
            Expr::Function { arguments, .. } => {
                for argument in arguments {
                    argument.columns(output);
                }
            }
            Expr::Case {
                branches,
                otherwise,
            } => {
                for (left, _, right, value) in branches {
                    left.columns(output);
                    right.columns(output);
                    value.columns(output);
                }
                otherwise.columns(output);
            }
            Expr::Literal(_) | Expr::Parameter(_) => {}
        }
    }

    fn parameters(&self, output: &mut BTreeSet<usize>) {
        match self {
            Expr::Parameter(position) => {
                output.insert(*position);
            }
            Expr::UnaryMinus(expression) => expression.parameters(output),
            Expr::Binary { left, right, .. } => {
                left.parameters(output);
                right.parameters(output);
            }
            Expr::Function { arguments, .. } => {
                for argument in arguments {
                    argument.parameters(output);
                }
            }
            Expr::Case {
                branches,
                otherwise,
            } => {
                for (left, _, right, value) in branches {
                    left.parameters(output);
                    right.parameters(output);
                    value.parameters(output);
                }
                otherwise.parameters(output);
            }
            Expr::Column(_) | Expr::Literal(_) => {}
        }
    }
}

fn evaluate(
    expression: &Expr,
    row: &[Value],
    columns: &HashMap<&str, usize>,
    parameters: &[Value],
) -> DbResult<Value> {
    match expression {
        Expr::Column(column) => {
            let index = columns
                .get(column.as_str())
                .or_else(|| column.rsplit('.').next().and_then(|name| columns.get(name)))
                .ok_or_else(|| sql_error(&format!("unbekannte Spalte '{column}'")))?;
            row.get(*index)
                .cloned()
                .ok_or_else(|| sql_error("Spaltenposition außerhalb der Zeile"))
        }
        Expr::Literal(value) => Ok(value.clone()),
        Expr::Parameter(position) => parameters
            .get(position - 1)
            .cloned()
            .ok_or_else(|| sql_error(&format!("Parameter ${position} fehlt"))),
        Expr::UnaryMinus(inner) => {
            let value = evaluate(inner, row, columns, parameters)?;
            match value {
                Value::Null => Ok(Value::Null),
                Value::Int(value) => value
                    .checked_neg()
                    .map(Value::Int)
                    .ok_or_else(|| sql_error("Ganzzahlüberlauf")),
                Value::Float(value) => Ok(Value::Float(-value)),
                _ => Err(sql_error("unäres Minus erwartet eine Zahl")),
            }
        }
        Expr::Binary {
            left,
            operator,
            right,
        } => {
            let left = evaluate(left, row, columns, parameters)?;
            let right = evaluate(right, row, columns, parameters)?;
            arithmetic(left, right, *operator)
        }
        Expr::Function { name, arguments } => {
            let values = arguments
                .iter()
                .map(|argument| evaluate(argument, row, columns, parameters))
                .collect::<DbResult<Vec<_>>>()?;
            string_function(name, values)
        }
        Expr::Case {
            branches,
            otherwise,
        } => {
            for (left, operator, right, result) in branches {
                let left = evaluate(left, row, columns, parameters)?;
                let right = evaluate(right, row, columns, parameters)?;
                if compare_values(&left, &right, *operator)? {
                    return evaluate(result, row, columns, parameters);
                }
            }
            evaluate(otherwise, row, columns, parameters)
        }
    }
}

fn arithmetic(left: Value, right: Value, operator: char) -> DbResult<Value> {
    if matches!(left, Value::Null) || matches!(right, Value::Null) {
        return Ok(Value::Null);
    }
    if let (Value::Int(a), Value::Int(b)) = (&left, &right) {
        if operator != '/' {
            let result = match operator {
                '+' => a.checked_add(*b),
                '-' => a.checked_sub(*b),
                '*' => a.checked_mul(*b),
                '%' if *b != 0 => Some(a % b),
                '%' => return Err(sql_error("Modulo durch Null")),
                _ => None,
            }
            .ok_or_else(|| sql_error("Ganzzahlüberlauf"))?;
            return Ok(Value::Int(result));
        }
    }
    let a = numeric(&left)?;
    let b = numeric(&right)?;
    if (operator == '/' || operator == '%') && b == 0.0 {
        return Err(sql_error("Division durch Null"));
    }
    let result = match operator {
        '+' => a + b,
        '-' => a - b,
        '*' => a * b,
        '/' => a / b,
        '%' => a % b,
        _ => return Err(sql_error("unbekannter Rechenoperator")),
    };
    if !result.is_finite() {
        return Err(sql_error("arithmetisches Ergebnis ist nicht endlich"));
    }
    Ok(Value::Float(result))
}

fn numeric(value: &Value) -> DbResult<f64> {
    match value {
        Value::Int(value) => Ok(*value as f64),
        Value::Float(value) if value.is_finite() => Ok(*value),
        Value::Text(value) => value
            .parse::<f64>()
            .ok()
            .filter(|number| number.is_finite())
            .ok_or_else(|| sql_error(&format!("'{value}' ist keine Zahl"))),
        _ => Err(sql_error("Rechenoperation erwartet Zahlen")),
    }
}

fn string_function(name: &str, values: Vec<Value>) -> DbResult<Value> {
    if values.iter().any(|value| matches!(value, Value::Null)) {
        return Ok(Value::Null);
    }
    let strings: Vec<String> = values.iter().map(value_string).collect();
    match name {
        "lower" if strings.len() == 1 => Ok(Value::Text(strings[0].to_lowercase())),
        "upper" if strings.len() == 1 => Ok(Value::Text(strings[0].to_uppercase())),
        "trim" if strings.len() == 1 => Ok(Value::Text(strings[0].trim().to_string())),
        "length" if strings.len() == 1 => Ok(Value::Int(strings[0].chars().count() as i128)),
        "concat" if !strings.is_empty() => Ok(Value::Text(strings.concat())),
        "substr" | "substring" if (2..=3).contains(&strings.len()) => {
            let start = strings[1]
                .parse::<usize>()
                .ok()
                .filter(|start| *start > 0)
                .ok_or_else(|| sql_error("SUBSTR-Startposition muss >= 1 sein"))?;
            let chars: Vec<char> = strings[0].chars().collect();
            let start = (start - 1).min(chars.len());
            let end = if let Some(length) = strings.get(2) {
                let length = length
                    .parse::<usize>()
                    .map_err(|_| sql_error("SUBSTR-Länge muss >= 0 sein"))?;
                start.saturating_add(length).min(chars.len())
            } else {
                chars.len()
            };
            Ok(Value::Text(chars[start..end].iter().collect()))
        }
        "lower" | "upper" | "trim" | "length" => Err(sql_error(&format!(
            "Funktion {name} erwartet genau ein Argument"
        ))),
        "concat" => Err(sql_error("CONCAT erwartet mindestens ein Argument")),
        "substr" | "substring" => Err(sql_error("SUBSTR erwartet zwei oder drei Argumente")),
        _ => Err(sql_error(&format!("unbekannte Funktion '{name}'"))),
    }
}

fn value_string(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::Text(value) | Value::Json(value) => value.clone(),
        _ => value.as_input(),
    }
}

fn compare_values(left: &Value, right: &Value, operator: CompareOp) -> DbResult<bool> {
    if matches!(left, Value::Null) || matches!(right, Value::Null) {
        return Ok(false);
    }
    let ordering = match (left, right) {
        (Value::Int(_), Value::Int(_))
        | (Value::Float(_), Value::Float(_))
        | (Value::Int(_), Value::Float(_))
        | (Value::Float(_), Value::Int(_)) => numeric(left)?.total_cmp(&numeric(right)?),
        _ => value_string(left).cmp(&value_string(right)),
    };
    Ok(match operator {
        CompareOp::Eq => ordering == Ordering::Equal,
        CompareOp::Ne => ordering != Ordering::Equal,
        CompareOp::Lt => ordering == Ordering::Less,
        CompareOp::Le => ordering != Ordering::Greater,
        CompareOp::Gt => ordering == Ordering::Greater,
        CompareOp::Ge => ordering != Ordering::Less,
    })
}

fn expression_name(expression: &Expr) -> String {
    match expression {
        Expr::Column(column) => column.clone(),
        Expr::Function { name, .. } => name.clone(),
        Expr::Case { .. } => "case".into(),
        Expr::Binary { .. } | Expr::UnaryMinus(_) => "expression".into(),
        Expr::Literal(_) => "literal".into(),
        Expr::Parameter(_) => "parameter".into(),
    }
}

fn normalize_column(table: &str, column: &str) -> DbResult<String> {
    match column.split_once('.') {
        Some((qualifier, name)) if qualifier == table && !name.is_empty() => Ok(name.to_string()),
        Some(_) => Err(sql_error(&format!(
            "unbekanntes Tabellenpräfix in '{column}'"
        ))),
        None => Ok(column.to_string()),
    }
}

fn normalize_expression(table: &str, expression: &IndexExpression) -> DbResult<IndexExpression> {
    Ok(match expression {
        IndexExpression::Lower(column) => IndexExpression::Lower(normalize_column(table, column)?),
        IndexExpression::Upper(column) => IndexExpression::Upper(normalize_column(table, column)?),
        IndexExpression::Length(column) => {
            IndexExpression::Length(normalize_column(table, column)?)
        }
    })
}

struct Parser {
    tokens: Vec<Token>,
    at: usize,
}

impl Parser {
    fn query(&mut self) -> DbResult<Query> {
        self.keyword("SELECT")?;
        let distinct = self.consume_keyword("DISTINCT");
        let mut projections = Vec::new();
        let wildcard = self.consume(&Token::Star);
        if !wildcard {
            loop {
                let expression = self.expression(0)?;
                let alias = if self.consume_keyword("AS") {
                    Some(self.identifier()?)
                } else if matches!(self.peek(), Some(Token::Identifier(alias)) if !is_clause(alias))
                {
                    Some(self.identifier()?)
                } else {
                    None
                };
                projections.push(SelectItem { expression, alias });
                if !self.consume(&Token::Comma) {
                    break;
                }
            }
        }
        self.keyword("FROM")?;
        let table = self.identifier()?;
        let mut predicates = Vec::new();
        if self.consume_keyword("WHERE") {
            loop {
                let left = self.expression(0)?;
                let predicate = if self.consume_keyword("IS") {
                    let negate = self.consume_keyword("NOT");
                    self.keyword("NULL")?;
                    let Expr::Column(column) = left else {
                        return Err(sql_error("IS NULL erwartet eine Spalte"));
                    };
                    Predicate::IsNull { column, negate }
                } else if self.consume_keyword("LIKE") {
                    let Expr::Column(column) = left else {
                        return Err(sql_error("LIKE erwartet eine Spalte"));
                    };
                    let pattern = self.expression(0)?;
                    if !pattern.column_names().is_empty() {
                        return Err(sql_error("LIKE-Muster muss ein Wert oder Parameter sein"));
                    }
                    Predicate::Like { column, pattern }
                } else {
                    let operator = self.comparison_operator()?;
                    let value = self.expression(0)?;
                    if !value.column_names().is_empty() {
                        return Err(sql_error("WHERE-Wert darf keine Spalte referenzieren"));
                    }
                    match left {
                        Expr::Column(column) => Predicate::Compare {
                            column,
                            operator,
                            value,
                        },
                        Expr::Function { name, arguments } if operator == CompareOp::Eq => {
                            let [Expr::Column(column)] = arguments.as_slice() else {
                                return Err(sql_error(
                                    "WHERE-Ausdrucksfunktion erwartet eine Spalte",
                                ));
                            };
                            let expression = match name.as_str() {
                                "lower" => IndexExpression::lower(column),
                                "upper" => IndexExpression::upper(column),
                                "length" => IndexExpression::length(column),
                                _ => {
                                    return Err(sql_error(
                                        "WHERE unterstützt LOWER, UPPER oder LENGTH mit =",
                                    ))
                                }
                            };
                            Predicate::ExpressionCompare { expression, value }
                        }
                        _ => {
                            return Err(sql_error(
                                "WHERE-Vergleich muss mit einer Spalte oder einem unterstützten Ausdruck beginnen",
                            ))
                        }
                    }
                };
                predicates.push(predicate);
                if !self.consume_keyword("AND") {
                    break;
                }
            }
        }
        let mut order = Vec::new();
        if self.consume_keyword("ORDER") {
            self.keyword("BY")?;
            loop {
                let column = self.identifier()?;
                let direction = if self.consume_keyword("DESC") {
                    Order::Desc
                } else {
                    self.consume_keyword("ASC");
                    Order::Asc
                };
                order.push((column, direction));
                if !self.consume(&Token::Comma) {
                    break;
                }
            }
        }
        let limit = if self.consume_keyword("LIMIT") {
            let token = self.next().ok_or_else(|| sql_error("LIMIT-Wert fehlt"))?;
            match token {
                Token::Number(value) => Some(
                    value
                        .parse::<usize>()
                        .map_err(|_| sql_error("LIMIT erwartet eine nichtnegative Ganzzahl"))?,
                ),
                _ => return Err(sql_error("LIMIT erwartet eine nichtnegative Ganzzahl")),
            }
        } else {
            None
        };
        self.consume(&Token::Semicolon);
        if self.peek().is_some() {
            return Err(sql_error("unerwartete Tokens nach SELECT-Abfrage"));
        }
        if wildcard && !projections.is_empty() {
            return Err(sql_error(
                "SELECT * kann nicht mit weiteren Ausdrücken kombiniert werden",
            ));
        }
        if !wildcard && projections.is_empty() {
            return Err(sql_error("SELECT braucht mindestens eine Spalte"));
        }
        Ok(Query {
            table,
            projections,
            wildcard,
            predicates,
            order,
            limit,
            distinct,
        })
    }

    fn expression(&mut self, minimum_precedence: u8) -> DbResult<Expr> {
        let mut left = match self.next() {
            Some(Token::Operator(operator)) if operator == "-" => {
                Expr::UnaryMinus(Box::new(self.expression(3)?))
            }
            Some(Token::LeftParen) => {
                let expression = self.expression(0)?;
                self.expect(&Token::RightParen)?;
                expression
            }
            Some(Token::Number(value)) => {
                if value.contains('.') {
                    Expr::Literal(Value::Float(
                        value.parse().map_err(|_| sql_error("ungültige Zahl"))?,
                    ))
                } else {
                    Expr::Literal(Value::Int(
                        value
                            .parse()
                            .map_err(|_| sql_error("Ganzzahl außerhalb des Bereichs"))?,
                    ))
                }
            }
            Some(Token::String(value)) => Expr::Literal(Value::Text(value)),
            Some(Token::Parameter(position)) => Expr::Parameter(position),
            Some(Token::Star) => return Err(sql_error("unerwartetes *")),
            Some(Token::Identifier(name)) if name.eq_ignore_ascii_case("CASE") => {
                self.case_expression()?
            }
            Some(Token::Identifier(name)) if name.eq_ignore_ascii_case("NULL") => {
                Expr::Literal(Value::Null)
            }
            Some(Token::Identifier(name)) if name.eq_ignore_ascii_case("TRUE") => {
                Expr::Literal(Value::Bool(true))
            }
            Some(Token::Identifier(name)) if name.eq_ignore_ascii_case("FALSE") => {
                Expr::Literal(Value::Bool(false))
            }
            Some(Token::Identifier(name)) => {
                if self.consume(&Token::LeftParen) {
                    let mut arguments = Vec::new();
                    if !self.consume(&Token::RightParen) {
                        loop {
                            arguments.push(self.expression(0)?);
                            if self.consume(&Token::RightParen) {
                                break;
                            }
                            self.expect(&Token::Comma)?;
                        }
                    }
                    Expr::Function {
                        name: {
                            let name = name.to_ascii_lowercase();
                            validate_function(&name, arguments.len())?;
                            name
                        },
                        arguments,
                    }
                } else {
                    Expr::Column(name)
                }
            }
            _ => return Err(sql_error("Ausdruck erwartet")),
        };
        loop {
            let symbol = match self.peek() {
                Some(Token::Operator(operator)) => operator.chars().next(),
                Some(Token::Star) => Some('*'),
                _ => None,
            };
            let Some(symbol) = symbol.filter(|c| "+-*/%".contains(*c)) else {
                break;
            };
            let precedence = if matches!(symbol, '*' | '/' | '%') {
                2
            } else {
                1
            };
            if precedence < minimum_precedence {
                break;
            }
            self.at += 1;
            let right = self.expression(precedence + 1)?;
            left = Expr::Binary {
                left: Box::new(left),
                operator: symbol,
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn case_expression(&mut self) -> DbResult<Expr> {
        let mut branches = Vec::new();
        while self.consume_keyword("WHEN") {
            let left = self.expression(0)?;
            let operator = self.comparison_operator()?;
            let right = self.expression(0)?;
            self.keyword("THEN")?;
            let result = self.expression(0)?;
            branches.push((left, operator, right, result));
        }
        let otherwise = if self.consume_keyword("ELSE") {
            self.expression(0)?
        } else {
            Expr::Literal(Value::Null)
        };
        self.keyword("END")?;
        if branches.is_empty() {
            return Err(sql_error("CASE braucht mindestens einen WHEN-Zweig"));
        }
        Ok(Expr::Case {
            branches,
            otherwise: Box::new(otherwise),
        })
    }

    fn comparison_operator(&mut self) -> DbResult<CompareOp> {
        let operator = match self.next() {
            Some(Token::Operator(operator)) => operator,
            _ => return Err(sql_error("Vergleichsoperator erwartet")),
        };
        match operator.as_str() {
            "=" => Ok(CompareOp::Eq),
            "!=" | "<>" => Ok(CompareOp::Ne),
            "<" => Ok(CompareOp::Lt),
            "<=" => Ok(CompareOp::Le),
            ">" => Ok(CompareOp::Gt),
            ">=" => Ok(CompareOp::Ge),
            _ => Err(sql_error("ungültiger Vergleichsoperator")),
        }
    }

    fn keyword(&mut self, expected: &str) -> DbResult<()> {
        if self.consume_keyword(expected) {
            Ok(())
        } else {
            Err(sql_error(&format!("'{expected}' erwartet")))
        }
    }

    fn consume_keyword(&mut self, expected: &str) -> bool {
        match self.peek() {
            Some(Token::Identifier(keyword)) if keyword.eq_ignore_ascii_case(expected) => {
                self.at += 1;
                true
            }
            _ => false,
        }
    }

    fn identifier(&mut self) -> DbResult<String> {
        match self.next() {
            Some(Token::Identifier(identifier)) => Ok(identifier),
            _ => Err(sql_error("Bezeichner erwartet")),
        }
    }

    fn consume(&mut self, expected: &Token) -> bool {
        if self.peek() == Some(expected) {
            self.at += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, expected: &Token) -> DbResult<()> {
        if self.consume(expected) {
            Ok(())
        } else {
            Err(sql_error(&format!("'{expected:?}' erwartet")))
        }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at)
    }

    fn next(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.at).cloned();
        self.at += usize::from(token.is_some());
        token
    }
}

impl Expr {
    fn column_names(&self) -> BTreeSet<String> {
        let mut names = BTreeSet::new();
        self.columns(&mut names);
        names
    }
}

fn tokenize(source: &str) -> DbResult<Vec<Token>> {
    let chars: Vec<char> = source.chars().collect();
    let mut tokens = Vec::new();
    let mut at = 0;
    while at < chars.len() {
        let character = chars[at];
        if character.is_whitespace() {
            at += 1;
            continue;
        }
        if character == '\'' {
            at += 1;
            let mut value = String::new();
            let mut closed = false;
            while at < chars.len() {
                if chars[at] == '\'' {
                    if chars.get(at + 1) == Some(&'\'') {
                        value.push('\'');
                        at += 2;
                    } else {
                        at += 1;
                        closed = true;
                        break;
                    }
                } else {
                    value.push(chars[at]);
                    at += 1;
                }
            }
            if !closed {
                return Err(sql_error("Zeichenkettenliteral nicht abgeschlossen"));
            }
            tokens.push(Token::String(value));
            continue;
        }
        if character == '$' {
            at += 1;
            let start = at;
            while at < chars.len() && chars[at].is_ascii_digit() {
                at += 1;
            }
            let position = chars[start..at]
                .iter()
                .collect::<String>()
                .parse::<usize>()
                .ok()
                .filter(|position| *position > 0)
                .ok_or_else(|| sql_error("Parameter muss die Form $1, $2, ... haben"))?;
            tokens.push(Token::Parameter(position));
            continue;
        }
        if character.is_ascii_digit() {
            let start = at;
            while at < chars.len() && chars[at].is_ascii_digit() {
                at += 1;
            }
            if chars.get(at) == Some(&'.')
                && chars
                    .get(at + 1)
                    .map_or(false, |next| next.is_ascii_digit())
            {
                at += 1;
                while at < chars.len() && chars[at].is_ascii_digit() {
                    at += 1;
                }
            }
            tokens.push(Token::Number(chars[start..at].iter().collect()));
            continue;
        }
        if character.is_ascii_alphabetic() || character == '_' {
            let start = at;
            at += 1;
            while at < chars.len()
                && (chars[at].is_ascii_alphanumeric() || matches!(chars[at], '_' | '.'))
            {
                at += 1;
            }
            tokens.push(Token::Identifier(chars[start..at].iter().collect()));
            continue;
        }
        match character {
            '(' => tokens.push(Token::LeftParen),
            ')' => tokens.push(Token::RightParen),
            ',' => tokens.push(Token::Comma),
            '*' => tokens.push(Token::Star),
            ';' => tokens.push(Token::Semicolon),
            '=' | '!' | '<' | '>' | '+' | '-' | '/' | '%' => {
                let mut operator = character.to_string();
                if matches!(character, '!' | '<' | '>') && chars.get(at + 1) == Some(&'=') {
                    operator.push('=');
                    at += 1;
                } else if character == '<' && chars.get(at + 1) == Some(&'>') {
                    operator.push('>');
                    at += 1;
                }
                if character == '!' && operator == "!" {
                    return Err(sql_error("ungültiger Operator '!'"));
                }
                tokens.push(Token::Operator(operator));
            }
            _ => return Err(sql_error(&format!("unerlaubtes Zeichen '{character}'"))),
        }
        at += 1;
    }
    Ok(tokens)
}

fn is_clause(identifier: &str) -> bool {
    ["FROM", "WHERE", "ORDER", "LIMIT", "ASC", "DESC", "AND"]
        .iter()
        .any(|keyword| identifier.eq_ignore_ascii_case(keyword))
}

fn sql_error(message: &str) -> DbError {
    DbError::Sql(message.to_string())
}
