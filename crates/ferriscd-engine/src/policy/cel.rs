//! A bounded, dependency-free subset of the **Common Expression Language** (`T20.2`).
//!
//! The pre-sync policy gate must evaluate operator-supplied policy expressions with **zero**
//! external process, network, or filesystem access, and it must do so with a *deterministic* cost
//! ceiling: `T20.2` requires "strict per-expression step/fuel limits to prevent CPU exhaustion from
//! malformed policies", and the evaluation itself must be a pure function (no wall clock, no
//! cluster reads) so the same bundle always yields the same verdict.
//!
//! Those two requirements are why this module exists instead of a general-purpose CEL interpreter
//! dependency. A wall-clock timeout would make the verdict machine-speed dependent (and untestable
//! without sleeping); a step counter does not. Every knob is a counter or a size: the expression
//! byte budget, the AST node budget, the nesting budget, the JSON input budget, the output
//! string/collection budgets, and the **fuel** budget. When a budget is exhausted the evaluation
//! *fails* — and the gate treats a failure as a violation ([`super::gate`]), never as an allow.
//!
//! # Fuel measures work, not just nodes visited
//!
//! Fuel is charged for three different things, and the last two are what make the budget a bound on
//! *work* rather than on the shape of the expression:
//!
//! * one unit per AST node evaluated and per comprehension iteration (the size of the policy),
//! * one unit **per JSON node copied**, charged *before* the copy happens, and
//! * one unit **per [`FUEL_BYTES_PER_STEP`] bytes of string payload** a copy or a scan touches
//!   (`T20.2`, finding M-A).
//!
//! Without the second charge a policy could buy an unbounded amount of copying with a handful of
//! steps: `size(object) > 0` is a four-node expression that copies the entire rendered document,
//! so an expression budget of a few dozen steps would "bound" a computation whose real cost is
//! proportional to a resource that may hold thousands of nodes. Charging the copy is what makes the
//! pass-level budget in [`super::gate`] bound wall-work proportional to the bundle. Selection and
//! indexing therefore walk the document **by reference** and charge only for the value they end at,
//! so the common `object.spec.…` path costs the size of its leaf, not of the whole document.
//!
//! The third charge exists because a node count is not a size: one rendered `ConfigMap` value (a
//! single `object.data.<key>` string) is a *single* JSON node whose bytes a copy, an ordering
//! comparison, or a substring search still has to walk. Charging nodes alone would let a policy pay
//! one unit for a megabyte-sized leaf and then make the machine walk it — the same fail-open the
//! node charge was added to close, just at a different granularity. Every byte-proportional
//! operation is therefore priced by [`Env::charge_bytes`] before the work happens.
//!
//! # Supported subset
//!
//! The subset is deliberately small, documented, and closed: anything outside it is a **compile
//! error**, which the gate reports as a violation (fail closed). A policy author therefore learns
//! immediately that an expression is not understood instead of silently getting an allow.
//!
//! | Category | Supported |
//! |---|---|
//! | Literals | `null`, `true`, `false`, integers, doubles, single/double-quoted strings, `[a, b]`, `{"k": v}` |
//! | Roots | `object` (the rendered resource as JSON), `app` (the `Application` facts) |
//! | Selection | `a.b`, `a["b"]`, `a[0]` |
//! | Operators | `!`, `-`, `*`, `/`, `%`, `+`, `-`, `<`, `<=`, `>`, `>=`, `==`, `!=`, `in`, `&&`, `\|\|`, `? :` |
//! | Comprehensions | `list.all(x, p)`, `.exists(x, p)`, `.exists_one(x, p)`, `.filter(x, p)`, `.map(x, e)` |
//! | Functions | `size`, `startsWith`, `endsWith`, `contains`, `lowerAscii`, `upperAscii`, `has(path)` |
//!
//! Deliberately **not** supported (each is a compile error, in both the call and the method form):
//! `matches` and every other regex-based builtin (no regex engine is linked, and hand-rolling one
//! for a security gate would be the wrong trade-off), timestamp/duration construction, `type`
//! conversion, and Kubernetes' own CEL extension libraries. Full CEL conformance is explicitly not
//! a goal: a *closed* subset that fails closed is.
//!
//! # Error messages never carry values
//!
//! Every [`CelError`] is built from type names, field names, and counters — never from an operand's
//! value. That is what makes it safe for the gate to put a CEL error into an
//! `Application.status` condition: a `Secret` value cannot be echoed back by a type error, because
//! no code path formats a value into a message.

use std::cell::Cell;
use std::collections::BTreeMap;

use serde_json::Value;

/// The root variable carrying the rendered resource under evaluation.
pub const OBJECT_ROOT: &str = "object";

/// The root variable carrying the `Application` facts under evaluation.
pub const APP_ROOT: &str = "app";

/// Root variables a policy expression may reference.
pub const ROOT_VARIABLES: [&str; 2] = [OBJECT_ROOT, APP_ROOT];

/// The only functions a policy expression may call.
pub const KNOWN_FUNCTIONS: [&str; 7] = [
    "size",
    "startsWith",
    "endsWith",
    "contains",
    "lowerAscii",
    "upperAscii",
    "has",
];

/// The only comprehension macros a policy expression may use.
pub const KNOWN_MACROS: [&str; 5] = ["all", "exists", "exists_one", "filter", "map"];

/// Maximum length of one compiled policy expression, in bytes.
pub const DEFAULT_MAX_EXPRESSION_BYTES: usize = 2048;
/// Maximum number of AST nodes one expression may compile to.
pub const DEFAULT_MAX_AST_NODES: usize = 512;
/// Maximum expression nesting depth.
pub const DEFAULT_MAX_DEPTH: usize = 32;
/// Fuel: the work **one evaluation** of one expression may do.
///
/// A step is not one AST node: fuel is charged per AST node evaluated and per comprehension
/// iteration, **plus** per JSON node a copy touches and per [`FUEL_BYTES_PER_STEP`] bytes of string
/// payload a copy, a comparison, a scan, or a byte-proportional builtin walks (`T20.2`, findings
/// H1/M-A/M3). The default is sized for a rule over a realistic rendered resource, not for the
/// policy text.
pub const DEFAULT_MAX_STEPS: u64 = 20_000;
/// Maximum size of a string a policy expression may produce.
pub const DEFAULT_MAX_STRING_BYTES: usize = 4096;
/// Maximum length of a list a policy expression may build.
pub const DEFAULT_MAX_COLLECTION_LEN: usize = 4096;
/// Maximum number of JSON nodes a policy evaluation may walk (the redacted resource).
pub const DEFAULT_MAX_JSON_NODES: usize = 20_000;

/// How many bytes of string payload one unit of fuel pays for.
///
/// Fuel is a *work* counter, and a JSON node count is not a size: a single rendered `ConfigMap`
/// value is one node and may be a megabyte long, so a copy, a comparison, or a substring search over
/// it was priced at one unit while the machine walked every byte (`T20.2`, finding M-A). (A
/// `Secret.data` value would be the obvious example, but the gate redacts those to `<redacted>`
/// before the evaluator ever sees them — see [`super::gate`] — so the realistic worst case is a
/// rendered `ConfigMap` blob.) One unit per 256 bytes keeps the counter proportional to that walk
/// while staying coarse enough not to swamp the per-node charge for ordinary manifests (a typical
/// label or image reference costs nothing extra).
pub const FUEL_BYTES_PER_STEP: u64 = 256;

/// Every counter and size the CEL subset enforces.
///
/// All fields are deterministic bounds — nothing here reads a clock, an environment variable, or
/// the cluster — so two runs over the same inputs always reach the same verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CelBudget {
    /// Maximum expression length in bytes.
    pub expression_bytes: usize,
    /// Maximum compiled AST nodes.
    pub ast_nodes: usize,
    /// Maximum nesting depth.
    pub depth: usize,
    /// Fuel: evaluation steps allowed for one evaluation.
    pub steps: u64,
    /// Maximum size of a produced string.
    pub string_bytes: usize,
    /// Maximum length of a produced list.
    pub collection_len: usize,
    /// Maximum JSON nodes one evaluation may walk.
    pub json_nodes: usize,
}

impl Default for CelBudget {
    fn default() -> Self {
        Self {
            expression_bytes: DEFAULT_MAX_EXPRESSION_BYTES,
            ast_nodes: DEFAULT_MAX_AST_NODES,
            depth: DEFAULT_MAX_DEPTH,
            steps: DEFAULT_MAX_STEPS,
            string_bytes: DEFAULT_MAX_STRING_BYTES,
            collection_len: DEFAULT_MAX_COLLECTION_LEN,
            json_nodes: DEFAULT_MAX_JSON_NODES,
        }
    }
}

impl CelBudget {
    /// Returns this budget with a different fuel allowance.
    ///
    /// Used by the gate (per-rule fuel) and by the tests that prove a malformed policy runs out of
    /// fuel deterministically instead of spinning.
    #[must_use]
    pub fn with_steps(mut self, steps: u64) -> Self {
        self.steps = steps;
        self
    }
}

/// Why an expression could not be compiled or evaluated.
///
/// The variants are stable, comparable, and **value-free**: no message formats an operand.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CelError {
    /// The expression is longer than the byte budget.
    #[error("expression is {bytes} bytes, over the {limit}-byte limit")]
    ExpressionTooLong {
        /// The expression length in bytes.
        bytes: usize,
        /// The configured limit.
        limit: usize,
    },

    /// The expression is not syntactically valid in the supported subset.
    #[error("expression does not parse: {message}")]
    Parse {
        /// Value-free parse diagnostic.
        message: String,
    },

    /// The expression uses a construct outside the supported subset.
    #[error("expression uses {what}, which this CEL subset does not support")]
    Unsupported {
        /// The unsupported construct.
        what: String,
    },

    /// The expression references a variable that is not bound.
    #[error("expression references unbound variable {name:?}")]
    UnboundVariable {
        /// The unbound identifier.
        name: String,
    },

    /// The compiled AST is larger than the node budget.
    #[error("expression compiles to {nodes} nodes, over the {limit}-node limit")]
    TooManyNodes {
        /// Node count.
        nodes: usize,
        /// The configured limit.
        limit: usize,
    },

    /// The expression nests deeper than the depth budget.
    #[error("expression nests deeper than the {limit}-level limit")]
    TooDeep {
        /// The configured limit.
        limit: usize,
    },

    /// The evaluation ran out of fuel (the deterministic equivalent of a timeout).
    #[error("evaluation ran out of fuel after {steps} step(s)")]
    FuelExhausted {
        /// Steps that were allowed.
        steps: u64,
    },

    /// The evaluation failed (a type mismatch, a missing field, a budget-exceeding result).
    #[error("evaluation failed: {message}")]
    Eval {
        /// Value-free diagnostic.
        message: String,
    },
}

impl CelError {
    /// Whether this error came from *compilation* rather than evaluation.
    ///
    /// Both fail closed in the gate; the distinction only shapes the operator-facing message
    /// ("fix the expression" vs "fix the input it evaluates against").
    #[must_use]
    pub fn is_compile_error(&self) -> bool {
        !matches!(self, Self::FuelExhausted { .. } | Self::Eval { .. })
    }
}

/// A failed evaluation together with **how much fuel it really spent**.
///
/// An error must not be a free lunch: a policy that burns its whole allowance and *then* errors
/// still consumed that allowance, so the pass-level budget has to be charged for it. Guessing (for
/// example "one step for any failure") would let a rule whose evaluations always error escape the
/// per-pass ceiling entirely, which is why the interpreter reports its own counter instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CelFailure {
    /// What went wrong.
    pub error: CelError,
    /// Steps the failed evaluation consumed before it stopped.
    pub steps: u64,
}

impl CelFailure {
    /// Consumes the failure, returning the underlying error.
    #[must_use]
    pub fn into_error(self) -> CelError {
        self.error
    }
}

impl std::fmt::Display for CelFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Ident(String),
    Int(i64),
    Double(f64),
    Str(String),
    LParen,
    RParen,
    LBracket,
    RBracket,
    LBrace,
    RBrace,
    Dot,
    Comma,
    Colon,
    Question,
    OrOr,
    AndAnd,
    Bang,
    EqEq,
    NotEq,
    Lt,
    Le,
    Gt,
    Ge,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Eof,
}

fn tokenize(source: &str) -> Result<Vec<Token>, CelError> {
    let chars: Vec<char> = source.chars().collect();
    let mut tokens = Vec::new();
    let mut index = 0;

    while let Some(&current) = chars.get(index) {
        match current {
            c if c.is_whitespace() => index += 1,
            '(' => {
                tokens.push(Token::LParen);
                index += 1;
            }
            ')' => {
                tokens.push(Token::RParen);
                index += 1;
            }
            '[' => {
                tokens.push(Token::LBracket);
                index += 1;
            }
            ']' => {
                tokens.push(Token::RBracket);
                index += 1;
            }
            '{' => {
                tokens.push(Token::LBrace);
                index += 1;
            }
            '}' => {
                tokens.push(Token::RBrace);
                index += 1;
            }
            '.' => {
                tokens.push(Token::Dot);
                index += 1;
            }
            ',' => {
                tokens.push(Token::Comma);
                index += 1;
            }
            ':' => {
                tokens.push(Token::Colon);
                index += 1;
            }
            '?' => {
                tokens.push(Token::Question);
                index += 1;
            }
            '+' => {
                tokens.push(Token::Plus);
                index += 1;
            }
            '-' => {
                tokens.push(Token::Minus);
                index += 1;
            }
            '*' => {
                tokens.push(Token::Star);
                index += 1;
            }
            '/' => {
                tokens.push(Token::Slash);
                index += 1;
            }
            '%' => {
                tokens.push(Token::Percent);
                index += 1;
            }
            '&' => {
                if chars.get(index + 1) == Some(&'&') {
                    tokens.push(Token::AndAnd);
                    index += 2;
                } else {
                    return Err(CelError::Unsupported {
                        what: "the `&` operator".to_owned(),
                    });
                }
            }
            '|' => {
                if chars.get(index + 1) == Some(&'|') {
                    tokens.push(Token::OrOr);
                    index += 2;
                } else {
                    return Err(CelError::Unsupported {
                        what: "the `|` operator".to_owned(),
                    });
                }
            }
            '!' => {
                if chars.get(index + 1) == Some(&'=') {
                    tokens.push(Token::NotEq);
                    index += 2;
                } else {
                    tokens.push(Token::Bang);
                    index += 1;
                }
            }
            '=' => {
                if chars.get(index + 1) == Some(&'=') {
                    tokens.push(Token::EqEq);
                    index += 2;
                } else {
                    return Err(CelError::Unsupported {
                        what: "single `=` (use `==`)".to_owned(),
                    });
                }
            }
            '<' => {
                if chars.get(index + 1) == Some(&'=') {
                    tokens.push(Token::Le);
                    index += 2;
                } else {
                    tokens.push(Token::Lt);
                    index += 1;
                }
            }
            '>' => {
                if chars.get(index + 1) == Some(&'=') {
                    tokens.push(Token::Ge);
                    index += 2;
                } else {
                    tokens.push(Token::Gt);
                    index += 1;
                }
            }
            '\'' | '"' => {
                let (literal, next) = lex_string(&chars, index)?;
                tokens.push(Token::Str(literal));
                index = next;
            }
            c if c.is_ascii_digit() => {
                let (token, next) = lex_number(&chars, index)?;
                tokens.push(token);
                index = next;
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let mut end = index;
                while matches!(chars.get(end), Some(c) if c.is_ascii_alphanumeric() || *c == '_') {
                    end += 1;
                }
                tokens.push(Token::Ident(chars[index..end].iter().collect()));
                index = end;
            }
            other => {
                return Err(CelError::Unsupported {
                    what: format!("the character {other:?}"),
                });
            }
        }
    }

    tokens.push(Token::Eof);
    Ok(tokens)
}

fn lex_string(chars: &[char], start: usize) -> Result<(String, usize), CelError> {
    let quote = chars.get(start).copied().unwrap_or('"');
    let mut literal = String::new();
    let mut index = start + 1;
    while let Some(&current) = chars.get(index) {
        match current {
            c if c == quote => return Ok((literal, index + 1)),
            '\\' => {
                let escaped = chars.get(index + 1).copied().ok_or(CelError::Parse {
                    message: "string literal ends with a backslash".to_owned(),
                })?;
                match escaped {
                    'n' => literal.push('\n'),
                    't' => literal.push('\t'),
                    'r' => literal.push('\r'),
                    '\\' => literal.push('\\'),
                    '\'' => literal.push('\''),
                    '"' => literal.push('"'),
                    other => {
                        return Err(CelError::Unsupported {
                            what: format!("the string escape \\{other}"),
                        });
                    }
                }
                index += 2;
            }
            c => {
                literal.push(c);
                index += 1;
            }
        }
    }
    Err(CelError::Parse {
        message: "unterminated string literal".to_owned(),
    })
}

fn lex_number(chars: &[char], start: usize) -> Result<(Token, usize), CelError> {
    let mut end = start;
    while matches!(chars.get(end), Some(c) if c.is_ascii_digit()) {
        end += 1;
    }
    let is_double =
        chars.get(end) == Some(&'.') && matches!(chars.get(end + 1), Some(c) if c.is_ascii_digit());
    if is_double {
        end += 1;
        while matches!(chars.get(end), Some(c) if c.is_ascii_digit()) {
            end += 1;
        }
        let text: String = chars[start..end].iter().collect();
        let value: f64 = text.parse().map_err(|_| CelError::Parse {
            message: "double literal out of range".to_owned(),
        })?;
        return Ok((Token::Double(value), end));
    }
    let text: String = chars[start..end].iter().collect();
    let value: i64 = text.parse().map_err(|_| CelError::Parse {
        message: "integer literal out of range".to_owned(),
    })?;
    Ok((Token::Int(value), end))
}

// ---------------------------------------------------------------------------
// AST
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BinOp {
    Or,
    And,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    In,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Comprehension {
    All,
    Exists,
    ExistsOne,
    Filter,
    Map,
}

#[derive(Debug, Clone, PartialEq)]
enum Expr {
    Literal(Value),
    List(Vec<Expr>),
    Map(Vec<(String, Expr)>),
    Var(String),
    Select(Box<Expr>, String),
    Index(Box<Expr>, Box<Expr>),
    Has(Box<Expr>),
    Call {
        name: String,
        args: Vec<Expr>,
    },
    Not(Box<Expr>),
    Negate(Box<Expr>),
    Binary {
        op: BinOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
    Ternary(Box<Expr>, Box<Expr>, Box<Expr>),
    Comprehension {
        kind: Comprehension,
        target: Box<Expr>,
        variable: String,
        body: Box<Expr>,
    },
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

struct Parser<'a> {
    tokens: &'a [Token],
    position: usize,
    nodes: usize,
    budget: CelBudget,
}

impl<'a> Parser<'a> {
    fn new(tokens: &'a [Token], budget: CelBudget) -> Self {
        Self {
            tokens,
            position: 0,
            nodes: 0,
            budget,
        }
    }

    fn peek(&self) -> &Token {
        self.tokens.get(self.position).unwrap_or(&Token::Eof)
    }

    fn next(&mut self) -> Token {
        let token = self.peek().clone();
        if self.position < self.tokens.len() {
            self.position += 1;
        }
        token
    }

    fn accept(&mut self, expected: &Token) -> bool {
        if self.peek() == expected {
            self.position += 1;
            return true;
        }
        false
    }

    fn expect(&mut self, expected: &Token) -> Result<(), CelError> {
        if self.accept(expected) {
            return Ok(());
        }
        Err(CelError::Parse {
            message: format!("expected {expected:?}, found {:?}", self.peek()),
        })
    }

    fn bump_node(&mut self, depth: usize) -> Result<(), CelError> {
        if depth > self.budget.depth {
            return Err(CelError::TooDeep {
                limit: self.budget.depth,
            });
        }
        self.nodes += 1;
        if self.nodes > self.budget.ast_nodes {
            return Err(CelError::TooManyNodes {
                nodes: self.nodes,
                limit: self.budget.ast_nodes,
            });
        }
        Ok(())
    }

    fn parse(&mut self) -> Result<Expr, CelError> {
        let expr = self.ternary(0)?;
        if !matches!(self.peek(), Token::Eof) {
            return Err(CelError::Parse {
                message: format!("unexpected trailing token {:?}", self.peek()),
            });
        }
        Ok(expr)
    }

    fn ternary(&mut self, depth: usize) -> Result<Expr, CelError> {
        self.bump_node(depth)?;
        let condition = self.or(depth + 1)?;
        if self.accept(&Token::Question) {
            let then_expr = self.ternary(depth + 1)?;
            self.expect(&Token::Colon)?;
            let else_expr = self.ternary(depth + 1)?;
            return Ok(Expr::Ternary(
                Box::new(condition),
                Box::new(then_expr),
                Box::new(else_expr),
            ));
        }
        Ok(condition)
    }

    fn or(&mut self, depth: usize) -> Result<Expr, CelError> {
        let mut lhs = self.and(depth)?;
        while self.accept(&Token::OrOr) {
            let rhs = self.and(depth)?;
            lhs = Expr::Binary {
                op: BinOp::Or,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
        Ok(lhs)
    }

    fn and(&mut self, depth: usize) -> Result<Expr, CelError> {
        let mut lhs = self.relational(depth)?;
        while self.accept(&Token::AndAnd) {
            let rhs = self.relational(depth)?;
            lhs = Expr::Binary {
                op: BinOp::And,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
        Ok(lhs)
    }

    fn relational(&mut self, depth: usize) -> Result<Expr, CelError> {
        let mut lhs = self.additive(depth)?;
        let mut compared = false;
        loop {
            let op = match self.peek() {
                Token::EqEq => BinOp::Eq,
                Token::NotEq => BinOp::Ne,
                Token::Lt => BinOp::Lt,
                Token::Le => BinOp::Le,
                Token::Gt => BinOp::Gt,
                Token::Ge => BinOp::Ge,
                Token::Ident(word) if word == "in" => BinOp::In,
                _ => return Ok(lhs),
            };
            // CEL's relational operators are **non-associative**: `a < b < c` is not CEL at all
            // (the language requires `a < b && b < c`). Parsing it left-associatively would turn a
            // type confusion — `(a < b) < c`, comparing a boolean with anything — into a *runtime*
            // error, or worse into a silently wrong answer, so it is refused here. A parenthesized
            // comparison is unaffected: it is consumed by `primary` as a whole operand.
            if compared {
                return Err(CelError::Parse {
                    message: "chained relational comparison, which CEL does not allow \
                              (non-associative): write `(a < b) && ...`, or parenthesize the first \
                              comparison"
                        .to_owned(),
                });
            }
            compared = true;
            self.position += 1;
            let rhs = self.additive(depth)?;
            lhs = Expr::Binary {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
    }

    fn additive(&mut self, depth: usize) -> Result<Expr, CelError> {
        let mut lhs = self.multiplicative(depth)?;
        loop {
            let op = match self.peek() {
                Token::Plus => BinOp::Add,
                Token::Minus => BinOp::Sub,
                _ => return Ok(lhs),
            };
            self.position += 1;
            let rhs = self.multiplicative(depth)?;
            lhs = Expr::Binary {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
    }

    fn multiplicative(&mut self, depth: usize) -> Result<Expr, CelError> {
        let mut lhs = self.unary(depth)?;
        loop {
            let op = match self.peek() {
                Token::Star => BinOp::Mul,
                Token::Slash => BinOp::Div,
                Token::Percent => BinOp::Mod,
                _ => return Ok(lhs),
            };
            self.position += 1;
            let rhs = self.unary(depth)?;
            lhs = Expr::Binary {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
    }

    fn unary(&mut self, depth: usize) -> Result<Expr, CelError> {
        self.bump_node(depth)?;
        if self.accept(&Token::Bang) {
            let operand = self.unary(depth + 1)?;
            return Ok(Expr::Not(Box::new(operand)));
        }
        if self.accept(&Token::Minus) {
            let operand = self.unary(depth + 1)?;
            return Ok(Expr::Negate(Box::new(operand)));
        }
        self.postfix(depth)
    }

    fn postfix(&mut self, depth: usize) -> Result<Expr, CelError> {
        let mut expr = self.primary(depth)?;
        loop {
            if self.accept(&Token::Dot) {
                let name = match self.next() {
                    Token::Ident(name) => name,
                    other => {
                        return Err(CelError::Parse {
                            message: format!("expected a field or function name, found {other:?}"),
                        });
                    }
                };
                if self.accept(&Token::LParen) {
                    if KNOWN_MACROS.contains(&name.as_str()) {
                        expr = self.macro_call(expr, &name, depth)?;
                        continue;
                    }
                    let mut args = vec![expr];
                    args.extend(self.arguments(depth)?);
                    expr = Expr::Call { name, args };
                    continue;
                }
                self.bump_node(depth)?;
                expr = Expr::Select(Box::new(expr), name);
                continue;
            }
            if self.accept(&Token::LBracket) {
                self.bump_node(depth)?;
                let index = self.ternary(depth + 1)?;
                self.expect(&Token::RBracket)?;
                expr = Expr::Index(Box::new(expr), Box::new(index));
                continue;
            }
            return Ok(expr);
        }
    }

    fn macro_call(&mut self, target: Expr, name: &str, depth: usize) -> Result<Expr, CelError> {
        self.bump_node(depth)?;
        let variable = match self.next() {
            Token::Ident(variable) if variable != "in" => variable,
            other => {
                return Err(CelError::Parse {
                    message: format!(
                        "{name}() takes a bound variable first, found {other:?} (write \
                         `list.{name}(x, ...)`)"
                    ),
                });
            }
        };
        self.expect(&Token::Comma)?;
        let body = self.ternary(depth + 1)?;
        self.expect(&Token::RParen)?;
        let kind = match name {
            "all" => Comprehension::All,
            "exists" => Comprehension::Exists,
            "exists_one" => Comprehension::ExistsOne,
            "filter" => Comprehension::Filter,
            "map" => Comprehension::Map,
            other => {
                return Err(CelError::Unsupported {
                    what: format!("the macro {other}()"),
                });
            }
        };
        Ok(Expr::Comprehension {
            kind,
            target: Box::new(target),
            variable,
            body: Box::new(body),
        })
    }

    fn arguments(&mut self, depth: usize) -> Result<Vec<Expr>, CelError> {
        let mut args = Vec::new();
        if self.accept(&Token::RParen) {
            return Ok(args);
        }
        loop {
            args.push(self.ternary(depth + 1)?);
            if self.accept(&Token::Comma) {
                continue;
            }
            self.expect(&Token::RParen)?;
            return Ok(args);
        }
    }

    fn primary(&mut self, depth: usize) -> Result<Expr, CelError> {
        self.bump_node(depth)?;
        match self.next() {
            Token::Int(value) => Ok(Expr::Literal(Value::from(value))),
            Token::Double(value) => Ok(Expr::Literal(Value::from(value))),
            Token::Str(value) => Ok(Expr::Literal(Value::String(value))),
            Token::LParen => {
                let inner = self.ternary(depth + 1)?;
                self.expect(&Token::RParen)?;
                Ok(inner)
            }
            Token::LBracket => {
                let mut items = Vec::new();
                if self.accept(&Token::RBracket) {
                    return Ok(Expr::List(items));
                }
                loop {
                    items.push(self.ternary(depth + 1)?);
                    if self.accept(&Token::Comma) {
                        if self.accept(&Token::RBracket) {
                            break;
                        }
                        continue;
                    }
                    self.expect(&Token::RBracket)?;
                    break;
                }
                if items.len() > self.budget.collection_len {
                    return Err(CelError::Eval {
                        message: "list literal is over the collection budget".to_owned(),
                    });
                }
                Ok(Expr::List(items))
            }
            Token::LBrace => {
                let mut entries = Vec::new();
                if self.accept(&Token::RBrace) {
                    return Ok(Expr::Map(entries));
                }
                loop {
                    let key = match self.next() {
                        Token::Str(key) | Token::Ident(key) => key,
                        other => {
                            return Err(CelError::Unsupported {
                                what: format!("a non-string map key ({other:?})"),
                            });
                        }
                    };
                    self.expect(&Token::Colon)?;
                    let value = self.ternary(depth + 1)?;
                    entries.push((key, value));
                    if self.accept(&Token::Comma) {
                        if self.accept(&Token::RBrace) {
                            break;
                        }
                        continue;
                    }
                    self.expect(&Token::RBrace)?;
                    break;
                }
                Ok(Expr::Map(entries))
            }
            Token::Ident(name) => match name.as_str() {
                "true" => Ok(Expr::Literal(Value::Bool(true))),
                "false" => Ok(Expr::Literal(Value::Bool(false))),
                "null" => Ok(Expr::Literal(Value::Null)),
                "in" => Err(CelError::Parse {
                    message: "`in` is an operator, not a value".to_owned(),
                }),
                _ => {
                    if self.accept(&Token::LParen) {
                        if name == "has" {
                            let inner = self.ternary(depth + 1)?;
                            self.expect(&Token::RParen)?;
                            return Ok(Expr::Has(Box::new(inner)));
                        }
                        let args = self.arguments(depth)?;
                        return Ok(Expr::Call { name, args });
                    }
                    Ok(Expr::Var(name))
                }
            },
            other => Err(CelError::Parse {
                message: format!("unexpected token {other:?}"),
            }),
        }
    }
}

/// Compiles `source` into a reusable [`Program`] under `budget`.
///
/// # Errors
///
/// [`CelError`] for every construct outside the supported subset, every unbudgeted expression, and
/// every unbound variable. Nothing is evaluated here.
pub fn compile(source: &str) -> Result<Program, CelError> {
    compile_with(source, CelBudget::default())
}

/// Compiles `source` under an explicit budget.
///
/// # Errors
///
/// See [`compile`].
pub fn compile_with(source: &str, budget: CelBudget) -> Result<Program, CelError> {
    if source.len() > budget.expression_bytes {
        return Err(CelError::ExpressionTooLong {
            bytes: source.len(),
            limit: budget.expression_bytes,
        });
    }
    let tokens = tokenize(source)?;
    let mut parser = Parser::new(&tokens, budget);
    let expr = parser.parse()?;
    validate(&expr, &mut Vec::new())?;
    Ok(Program {
        expr,
        nodes: parser.nodes,
        source_length: source.len(),
        budget,
    })
}

/// A compiled, reusable policy expression.
#[derive(Debug, Clone, PartialEq)]
pub struct Program {
    expr: Expr,
    nodes: usize,
    source_length: usize,
    budget: CelBudget,
}

impl Program {
    /// How many AST nodes the compiled expression holds.
    #[must_use]
    pub fn nodes(&self) -> usize {
        self.nodes
    }

    /// The byte length of the source the program was compiled from.
    #[must_use]
    pub fn source_length(&self) -> usize {
        self.source_length
    }

    /// Evaluates the program against `roots` (`object`, `app`, …).
    ///
    /// # Errors
    ///
    /// * [`CelError::FuelExhausted`] when the step budget runs out — the deterministic timeout.
    /// * [`CelError::Eval`] for a type mismatch, a missing field, or a produced value over budget.
    ///
    /// Every error is value-free (see the module docs).
    pub fn evaluate(&self, roots: &BTreeMap<String, Value>) -> Result<Value, CelError> {
        self.evaluate_counting(roots)
            .map(|(value, _steps)| value)
            .map_err(CelFailure::into_error)
    }

    /// Evaluates the program, reporting the steps it spent — including when it failed.
    ///
    /// Cost is a counter, not a clock, so the gate can assert (and charge) it exactly. On failure
    /// the counter is the fuel the failed evaluation really consumed before it stopped; see
    /// [`CelFailure`].
    ///
    /// # Errors
    ///
    /// See [`Self::evaluate`]; the error carries the steps spent.
    pub fn evaluate_counting(
        &self,
        roots: &BTreeMap<String, Value>,
    ) -> Result<(Value, u64), CelFailure> {
        self.evaluate_counting_with(roots, None)
    }

    /// Evaluates the program with the `object` root **borrowed** from the caller.
    ///
    /// The gate evaluates many rules against the same rendered resource. Passing the document by
    /// reference (instead of inserting a clone into `roots` per rule) keeps the per-`(rule,
    /// resource)` cost clone-free, which is what bounds the wall clock over a large bundle: the one
    /// unavoidable copy of the resource happens once, in the caller.
    ///
    /// # Errors
    ///
    /// See [`Self::evaluate`]; the error carries the steps spent.
    pub fn evaluate_counting_with(
        &self,
        roots: &BTreeMap<String, Value>,
        object: Option<&Value>,
    ) -> Result<(Value, u64), CelFailure> {
        for root in roots.keys() {
            if !ROOT_VARIABLES.contains(&root.as_str()) {
                return Err(CelFailure {
                    error: CelError::UnboundVariable { name: root.clone() },
                    steps: 0,
                });
            }
        }
        let mut env = Env {
            roots,
            object,
            locals: Vec::new(),
            steps: Cell::new(0),
            budget: self.budget,
        };
        let value = match env.eval(&self.expr) {
            Ok(value) => value,
            Err(error) => {
                return Err(CelFailure {
                    error,
                    steps: env.steps.get(),
                });
            }
        };
        match check_output(&value, &self.budget) {
            Ok(()) => Ok((value, env.steps.get())),
            Err(error) => Err(CelFailure {
                error,
                steps: env.steps.get(),
            }),
        }
    }
}

fn validate(expr: &Expr, bound: &mut Vec<String>) -> Result<(), CelError> {
    match expr {
        Expr::Literal(_) => Ok(()),
        Expr::List(items) => items.iter().try_for_each(|item| validate(item, bound)),
        Expr::Map(entries) => entries
            .iter()
            .try_for_each(|(_, value)| validate(value, bound)),
        Expr::Var(name) => {
            if ROOT_VARIABLES.contains(&name.as_str()) || bound.iter().any(|b| b == name) {
                return Ok(());
            }
            Err(CelError::UnboundVariable { name: name.clone() })
        }
        Expr::Select(target, _) => validate(target, bound),
        Expr::Index(target, index) => {
            validate(target, bound)?;
            validate(index, bound)
        }
        Expr::Has(inner) => {
            if !is_path(inner) {
                return Err(CelError::Unsupported {
                    what: "has() on a non-path expression".to_owned(),
                });
            }
            validate(inner, bound)
        }
        Expr::Not(inner) | Expr::Negate(inner) => validate(inner, bound),
        Expr::Binary { lhs, rhs, .. } => {
            validate(lhs, bound)?;
            validate(rhs, bound)
        }
        Expr::Ternary(condition, then_expr, else_expr) => {
            validate(condition, bound)?;
            validate(then_expr, bound)?;
            validate(else_expr, bound)
        }
        Expr::Call { name, args } => {
            let expected = match name.as_str() {
                "size" | "lowerAscii" | "upperAscii" => 1,
                "startsWith" | "endsWith" | "contains" => 2,
                // `has()` is a parse-time macro over a path; the method form and a computed
                // argument are refused rather than silently mis-evaluated.
                "has" => {
                    return Err(CelError::Unsupported {
                        what: "has() outside its `has(path)` form".to_owned(),
                    });
                }
                other => {
                    return Err(CelError::Unsupported {
                        what: format!(
                            "the function {other}() (supported: {})",
                            KNOWN_FUNCTIONS.join(", ")
                        ),
                    });
                }
            };
            if args.len() != expected {
                return Err(CelError::Parse {
                    message: format!(
                        "{name}() takes {expected} argument(s), found {}",
                        args.len()
                    ),
                });
            }
            args.iter().try_for_each(|arg| validate(arg, bound))
        }
        Expr::Comprehension {
            target,
            variable,
            body,
            ..
        } => {
            validate(target, bound)?;
            bound.push(variable.clone());
            let outcome = validate(body, bound);
            bound.pop();
            outcome
        }
    }
}

fn is_path(expr: &Expr) -> bool {
    match expr {
        Expr::Var(_) => true,
        Expr::Select(target, _) => is_path(target),
        Expr::Index(target, index) => is_path(target) && matches!(**index, Expr::Literal(_)),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Evaluator
// ---------------------------------------------------------------------------

struct Env<'a> {
    roots: &'a BTreeMap<String, Value>,
    /// The `object` root when the caller borrows the document instead of copying it into `roots`.
    ///
    /// `locals` still win over it, so a comprehension that shadows a name behaves identically.
    object: Option<&'a Value>,
    locals: Vec<(String, Value)>,
    /// Fuel spent so far.
    ///
    /// A `Cell` (not a plain field) so charging needs only `&self`: `eval` holds a borrow of the
    /// document while it charges for the copy it is about to make, and an evaluation is
    /// single-threaded by construction (no `Env` is ever shared).
    steps: Cell<u64>,
    budget: CelBudget,
}

/// The immutable bindings a `Var`/`Select`/`Index` path is resolved against.
///
/// A *view*: it borrows the roots, the borrowed `object` and the comprehension frames, so resolving
/// a path costs one pointer chase per segment and **no** copy until the leaf. That is what keeps an
/// evaluation's cost proportional to the value it reads instead of to the rendered document
/// (`T20.2`, finding H1).
#[derive(Clone, Copy)]
struct Bindings<'s, 'a: 's> {
    roots: &'s BTreeMap<String, Value>,
    object: Option<&'a Value>,
    locals: &'s [(String, Value)],
}

impl<'s, 'a: 's> Bindings<'s, 'a> {
    /// Looks a name up: a comprehension frame first, then the borrowed `object`, then the roots.
    fn lookup(self, name: &str) -> Option<&'s Value> {
        if let Some((_, value)) = self.locals.iter().rev().find(|(bound, _)| bound == name) {
            return Some(value);
        }
        // The borrowed document is the `object` root by construction (`evaluate_counting_with`).
        if name == OBJECT_ROOT
            && let Some(object) = self.object
        {
            return Some(object);
        }
        self.roots.get(name)
    }

    /// Walks a path by reference, cloning nothing.
    ///
    /// The caller guarantees [`is_path`], so every index is a literal and no sub-expression has to
    /// be evaluated — which is exactly why this walk can borrow for its whole length. The errors
    /// are the ones the general evaluator produces for the same chain.
    fn walk(self, expr: &Expr) -> Result<&'s Value, CelError> {
        match expr {
            Expr::Var(name) => self.lookup(name).ok_or_else(|| CelError::Eval {
                message: format!("variable {name:?} is not bound"),
            }),
            Expr::Select(target, field) => select_field(self.walk(target)?, field),
            Expr::Index(target, index) => {
                let base = self.walk(target)?;
                match &**index {
                    Expr::Literal(key) => index_into(base, key),
                    // Unreachable for a compiled path (`is_path` only admits literal indices);
                    // reported rather than panicking because this is runtime code.
                    other => Err(CelError::Eval {
                        message: format!("cannot index with {}", expr_kind(other)),
                    }),
                }
            }
            other => Err(CelError::Eval {
                message: format!("{} is not a path", expr_kind(other)),
            }),
        }
    }
}

impl<'a> Env<'a> {
    fn bindings(&self) -> Bindings<'_, 'a> {
        Bindings {
            roots: self.roots,
            object: self.object,
            locals: &self.locals,
        }
    }

    fn step(&self) -> Result<(), CelError> {
        self.charge(1)
    }

    /// Charges `cost` units of fuel in one go, failing once the allowance is gone.
    ///
    /// Saturating: a document may hold more nodes than the counter can represent in one go, and an
    /// arithmetic overflow here would be a wrap-around — an *increase* in the remaining budget, the
    /// fail-open this counter exists to prevent.
    fn charge(&self, cost: u64) -> Result<(), CelError> {
        let spent = self.steps.get().saturating_add(cost);
        self.steps.set(spent);
        if spent > self.budget.steps {
            return Err(CelError::FuelExhausted {
                steps: self.budget.steps,
            });
        }
        Ok(())
    }

    /// Charges what a deep copy of `value` costs, **before** the copy is made.
    ///
    /// One unit per JSON node **plus** one unit per [`FUEL_BYTES_PER_STEP`] bytes of string payload:
    /// the node count alone prices a megabyte-sized single leaf at one unit (`T20.2`, finding M-A).
    fn bill_clone(&self, value: &Value) -> Result<(), CelError> {
        self.charge(value_nodes(value).saturating_add(value_bytes(value) / FUEL_BYTES_PER_STEP))
    }

    /// Charges what comparing `left` with `right` costs.
    ///
    /// A structural comparison walks both trees, so a policy that compares two large values (or
    /// scans a list with `in`/`contains`) does real work per element. The operands themselves were
    /// already paid for when they were read, so this charges the *scan*: the smaller tree, which is
    /// the floor of what any sensible comparison touches. String payload is priced the same way —
    /// ordering two large strings walks their bytes, and equality only compares up to the first
    /// difference (`T20.2`, finding M-A).
    fn bill_compare(&self, left: &Value, right: &Value) -> Result<(), CelError> {
        self.charge(
            value_nodes(left)
                .min(value_nodes(right))
                .saturating_add(value_bytes(left).min(value_bytes(right)) / FUEL_BYTES_PER_STEP),
        )
    }

    /// Charges for walking `bytes` bytes of string payload, before the walk happens.
    fn charge_bytes(&self, bytes: u64) -> Result<(), CelError> {
        self.charge(bytes / FUEL_BYTES_PER_STEP)
    }

    /// Charges one unit per element a membership test may have to look at, **plus** its bytes.
    ///
    /// Each element is compared with [`equal`], which walks its bytes, so a scan over a list of
    /// large strings costs what those strings contain, not one unit per element (`T20.2`, finding
    /// M-A).
    fn bill_scan(&self, items: &[Value]) -> Result<(), CelError> {
        let bytes = items
            .iter()
            .fold(0_u64, |total, item| total.saturating_add(value_bytes(item)));
        self.charge(
            u64::try_from(items.len())
                .unwrap_or(u64::MAX)
                .saturating_add(bytes / FUEL_BYTES_PER_STEP),
        )
    }

    /// Evaluates a path by reference and copies only the value it ends at.
    fn path(&self, expr: &Expr) -> Result<Value, CelError> {
        let bindings = self.bindings();
        let value = bindings.walk(expr)?;
        self.bill_clone(value)?;
        Ok(value.clone())
    }

    fn eval(&mut self, expr: &Expr) -> Result<Value, CelError> {
        self.step()?;
        match expr {
            Expr::Literal(value) => {
                self.bill_clone(value)?;
                Ok(value.clone())
            }
            Expr::List(items) => {
                let mut values = Vec::with_capacity(items.len());
                for item in items {
                    values.push(self.eval(item)?);
                }
                Ok(Value::Array(values))
            }
            Expr::Map(entries) => {
                let mut map = serde_json::Map::new();
                for (key, value) in entries {
                    map.insert(key.clone(), self.eval(value)?);
                }
                Ok(Value::Object(map))
            }
            Expr::Var(_) => self.path(expr),
            Expr::Select(target, field) => {
                if is_path(expr) {
                    return self.path(expr);
                }
                let base = self.eval(target)?;
                let value = select_field(&base, field)?;
                self.bill_clone(value)?;
                Ok(value.clone())
            }
            Expr::Index(target, index) => {
                if is_path(expr) {
                    return self.path(expr);
                }
                let base = self.eval(target)?;
                let key = self.eval(index)?;
                let value = index_into(&base, &key)?;
                self.bill_clone(value)?;
                Ok(value.clone())
            }
            Expr::Has(inner) => Ok(Value::Bool(self.present(inner)?)),
            Expr::Not(inner) => Ok(Value::Bool(!self.boolean(inner)?)),
            Expr::Negate(inner) => {
                let value = self.eval(inner)?;
                match value {
                    Value::Number(number) if number.is_i64() => number
                        .as_i64()
                        .and_then(i64::checked_neg)
                        .map(Value::from)
                        .ok_or_else(|| CelError::Eval {
                            message: "integer negation overflows".to_owned(),
                        }),
                    Value::Number(number) if number.is_f64() => number
                        .as_f64()
                        .map(|value| Value::from(-value))
                        .ok_or_else(|| CelError::Eval {
                            message: "cannot negate a number".to_owned(),
                        }),
                    other => Err(CelError::Eval {
                        message: format!("cannot negate {}", type_name(&other)),
                    }),
                }
            }
            Expr::Binary { op, lhs, rhs } => self.binary(*op, lhs, rhs),
            Expr::Ternary(condition, then_expr, else_expr) => {
                if self.boolean(condition)? {
                    self.eval(then_expr)
                } else {
                    self.eval(else_expr)
                }
            }
            Expr::Call { name, args } => self.call(name, args),
            Expr::Comprehension {
                kind,
                target,
                variable,
                body,
            } => self.comprehension(*kind, target, variable, body),
        }
    }

    fn boolean(&mut self, expr: &Expr) -> Result<bool, CelError> {
        let value = self.eval(expr)?;
        match value {
            Value::Bool(value) => Ok(value),
            other => Err(CelError::Eval {
                message: format!("expected a boolean, found {}", type_name(&other)),
            }),
        }
    }

    /// Presence test for `has(path)`: walks a selection/index chain without erroring.
    ///
    /// Uses the borrow walk too, so `has(object.spec.template.spec.containers[0].resources.limits)`
    /// does not copy every intermediate level of the document just to answer "is it there?".
    fn present(&self, path: &Expr) -> Result<bool, CelError> {
        self.step()?;
        match path {
            Expr::Var(name) => Ok(self.bindings().lookup(name).is_some()),
            Expr::Select(target, field) => {
                // An absent intermediate is "not present", not an error: that is the whole point
                // of `has()`.
                Ok(match self.absent_ok(target) {
                    Some(Value::Object(map)) => map.contains_key(field),
                    _ => false,
                })
            }
            Expr::Index(target, index) => {
                let Some(base) = self.absent_ok(target) else {
                    return Ok(false);
                };
                // `is_path` only admits literal indices in a `has()` path, so the key never has to
                // be evaluated — and therefore never copies anything.
                match &**index {
                    Expr::Literal(key) => Ok(index_into(base, key).is_ok()),
                    _ => Ok(false),
                }
            }
            _ => {
                // `is_path` rejects this at compile time; treating it as "absent" keeps the
                // evaluator total instead of panicking.
                Ok(false)
            }
        }
    }

    /// Resolves a path by reference, answering `None` when it does not resolve.
    ///
    /// Only [`Self::present`] uses this: `has()` asks about presence, so a missing segment is an
    /// answer rather than an error.
    fn absent_ok(&self, path: &Expr) -> Option<&Value> {
        self.bindings().walk(path).ok()
    }

    fn binary(&mut self, op: BinOp, lhs: &Expr, rhs: &Expr) -> Result<Value, CelError> {
        match op {
            BinOp::And => {
                if !self.boolean(lhs)? {
                    return Ok(Value::Bool(false));
                }
                Ok(Value::Bool(self.boolean(rhs)?))
            }
            BinOp::Or => {
                if self.boolean(lhs)? {
                    return Ok(Value::Bool(true));
                }
                Ok(Value::Bool(self.boolean(rhs)?))
            }
            _ => {
                let left = self.eval(lhs)?;
                let right = self.eval(rhs)?;
                self.apply(op, left, right)
            }
        }
    }

    fn apply(&mut self, op: BinOp, left: Value, right: Value) -> Result<Value, CelError> {
        match op {
            BinOp::Eq => {
                self.bill_compare(&left, &right)?;
                Ok(Value::Bool(equal(&left, &right)))
            }
            BinOp::Ne => {
                self.bill_compare(&left, &right)?;
                Ok(Value::Bool(!equal(&left, &right)))
            }
            BinOp::In => match &right {
                Value::Array(items) => {
                    self.bill_scan(items)?;
                    Ok(Value::Bool(items.iter().any(|item| equal(item, &left))))
                }
                Value::Object(map) => match &left {
                    Value::String(key) => Ok(Value::Bool(map.contains_key(key))),
                    other => Err(CelError::Eval {
                        message: format!(
                            "`in` on a map needs a string key, found {}",
                            type_name(other)
                        ),
                    }),
                },
                other => Err(CelError::Eval {
                    message: format!("`in` needs a list or a map, found {}", type_name(other)),
                }),
            },
            BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge => {
                // Ordering walks both operands (their nodes, and their bytes for strings), so it is
                // charged like a comparison — `T20.2`, finding M-A: it used to charge nothing at
                // all, so `object.data.blob > "m"` over a megabyte leaf was priced at one step.
                self.bill_compare(&left, &right)?;
                let ordering = compare(&left, &right)?;
                let verdict = match op {
                    BinOp::Lt => ordering.is_lt(),
                    BinOp::Le => ordering.is_le(),
                    BinOp::Gt => ordering.is_gt(),
                    BinOp::Ge => ordering.is_ge(),
                    _ => false,
                };
                Ok(Value::Bool(verdict))
            }
            BinOp::Add => match (&left, &right) {
                (Value::String(a), Value::String(b)) => {
                    // A concatenation allocates the bytes of both operands, so it is charged like
                    // any other byte-proportional operation — before the allocation, not after
                    // (`T20.2`, finding M3: `object.data.blob + "x"` was priced at one step).
                    self.charge_bytes(
                        u64::try_from(a.len())
                            .unwrap_or(u64::MAX)
                            .saturating_add(u64::try_from(b.len()).unwrap_or(u64::MAX)),
                    )?;
                    self.bounded_string(format!("{a}{b}")).map(Value::String)
                }
                (Value::Array(a), Value::Array(b)) => {
                    // A concatenation copies both operands: every node **and** every byte of string
                    // payload they hold, exactly like [`Self::bill_clone`] prices one copy. Charging
                    // only `a.len() + b.len()` priced a list of megabyte-sized elements at two units
                    // (`T20.2`, finding M3), which is the node-vs-size fail-open again.
                    self.charge(
                        value_nodes(&left)
                            .saturating_add(value_nodes(&right))
                            .saturating_add(
                                value_bytes(&left).saturating_add(value_bytes(&right))
                                    / FUEL_BYTES_PER_STEP,
                            ),
                    )?;
                    let mut items = a.clone();
                    items.extend(b.iter().cloned());
                    self.bounded_list(items).map(Value::Array)
                }
                _ => arithmetic(op, &left, &right),
            },
            BinOp::Sub | BinOp::Mul | BinOp::Div | BinOp::Mod => arithmetic(op, &left, &right),
            BinOp::And | BinOp::Or => Err(CelError::Eval {
                message: "logical operators need booleans".to_owned(),
            }),
        }
    }

    fn call(&mut self, name: &str, args: &[Expr]) -> Result<Value, CelError> {
        let mut values = Vec::with_capacity(args.len());
        for arg in args {
            values.push(self.eval(arg)?);
        }
        match name {
            "size" => {
                let value = values.first().ok_or_else(|| CelError::Eval {
                    message: "size() needs an argument".to_owned(),
                })?;
                let size = match value {
                    Value::String(text) => {
                        // Counting the characters of a string walks its bytes, so it is charged like
                        // any other byte-proportional operation (`T20.2`, finding M-A).
                        self.charge_bytes(u64::try_from(text.len()).unwrap_or(u64::MAX))?;
                        text.chars().count()
                    }
                    Value::Array(items) => items.len(),
                    Value::Object(map) => map.len(),
                    other => {
                        return Err(CelError::Eval {
                            message: format!("size() does not accept {}", type_name(other)),
                        });
                    }
                };
                Ok(Value::from(i64::try_from(size).unwrap_or(i64::MAX)))
            }
            "startsWith" | "endsWith" | "contains" => {
                let (haystack, needle) = pair(name, &values)?;
                match (haystack, needle) {
                    (Value::String(text), Value::String(pattern)) => {
                        // A substring search walks the haystack: charge its bytes (and the needle's),
                        // not one unit for a single string node (`T20.2`, finding M-A).
                        self.charge_bytes(
                            u64::try_from(text.len())
                                .unwrap_or(u64::MAX)
                                .saturating_add(u64::try_from(pattern.len()).unwrap_or(u64::MAX)),
                        )?;
                        Ok(Value::Bool(match name {
                            "startsWith" => text.starts_with(pattern.as_str()),
                            "endsWith" => text.ends_with(pattern.as_str()),
                            _ => text.contains(pattern.as_str()),
                        }))
                    }
                    (Value::Array(items), needle) if name == "contains" => {
                        self.bill_scan(items)?;
                        Ok(Value::Bool(items.iter().any(|item| equal(item, needle))))
                    }
                    (Value::Object(map), Value::String(key)) if name == "contains" => {
                        Ok(Value::Bool(map.contains_key(key)))
                    }
                    (other, _) => Err(CelError::Eval {
                        message: format!("{name}() does not accept {}", type_name(other)),
                    }),
                }
            }
            "lowerAscii" | "upperAscii" => {
                let value = values.first().ok_or_else(|| CelError::Eval {
                    message: format!("{name}() needs an argument"),
                })?;
                let Value::String(text) = value else {
                    return Err(CelError::Eval {
                        message: format!("{name}() does not accept {}", type_name(value)),
                    });
                };
                // A case mapping allocates a second copy of the string, so it pays for the bytes it
                // is about to write, before writing them (`T20.2`, finding M3).
                self.charge_bytes(u64::try_from(text.len()).unwrap_or(u64::MAX))?;
                let mapped = if name == "lowerAscii" {
                    text.to_ascii_lowercase()
                } else {
                    text.to_ascii_uppercase()
                };
                self.bounded_string(mapped).map(Value::String)
            }
            other => Err(CelError::Unsupported {
                what: format!("the function {other}()"),
            }),
        }
    }

    fn comprehension(
        &mut self,
        kind: Comprehension,
        target: &Expr,
        variable: &str,
        body: &Expr,
    ) -> Result<Value, CelError> {
        let items = match self.eval(target)? {
            Value::Array(items) => items,
            other => {
                return Err(CelError::Eval {
                    message: format!("a comprehension needs a list, found {}", type_name(&other)),
                });
            }
        };
        let mut collected = Vec::new();
        let mut matches = 0_usize;
        for item in items {
            self.step()?;
            self.locals.push((variable.to_owned(), item));
            let outcome = self.eval(body);
            // Recovering the bound value (rather than cloning it into the frame) is what lets
            // `filter()` push **the item**: `list.filter(x, p)` selects list *elements*, so pushing
            // the predicate's boolean was a wrong answer that looked like a working policy.
            let bound = self.pop_binding(variable);
            let outcome = outcome?;
            match kind {
                Comprehension::All => {
                    if !as_boolean(&outcome)? {
                        return Ok(Value::Bool(false));
                    }
                }
                Comprehension::Exists => {
                    if as_boolean(&outcome)? {
                        return Ok(Value::Bool(true));
                    }
                }
                Comprehension::ExistsOne => {
                    if as_boolean(&outcome)? {
                        matches += 1;
                    }
                }
                Comprehension::Filter => {
                    if as_boolean(&outcome)? {
                        collected.push(bound?);
                        self.bounded_list_len(collected.len())?;
                    }
                }
                Comprehension::Map => {
                    collected.push(outcome);
                    self.bounded_list_len(collected.len())?;
                }
            }
        }
        Ok(match kind {
            Comprehension::All => Value::Bool(true),
            Comprehension::Exists => Value::Bool(false),
            Comprehension::ExistsOne => Value::Bool(matches == 1),
            Comprehension::Filter | Comprehension::Map => Value::Array(collected),
        })
    }

    /// Pops the comprehension frame the loop pushed one line earlier, returning the bound value.
    ///
    /// The frame is always there; a mismatch is reported as an evaluation failure rather than
    /// panicking, because this is runtime code and an error still fails closed.
    fn pop_binding(&mut self, variable: &str) -> Result<Value, CelError> {
        match self.locals.pop() {
            Some((bound, value)) if bound == variable => Ok(value),
            Some((bound, value)) => {
                self.locals.push((bound, value));
                Err(CelError::Eval {
                    message: "the comprehension frame does not hold its own variable".to_owned(),
                })
            }
            None => Err(CelError::Eval {
                message: "the comprehension frame is missing".to_owned(),
            }),
        }
    }

    fn bounded_string(&self, value: String) -> Result<String, CelError> {
        if value.len() > self.budget.string_bytes {
            return Err(CelError::Eval {
                message: "produced string is over the size budget".to_owned(),
            });
        }
        Ok(value)
    }

    fn bounded_list(&self, value: Vec<Value>) -> Result<Vec<Value>, CelError> {
        if value.len() > self.budget.collection_len {
            return Err(CelError::Eval {
                message: "produced list is over the size budget".to_owned(),
            });
        }
        Ok(value)
    }

    fn bounded_list_len(&self, len: usize) -> Result<(), CelError> {
        if len > self.budget.collection_len {
            return Err(CelError::Eval {
                message: "produced list is over the size budget".to_owned(),
            });
        }
        Ok(())
    }
}

fn pair<'a>(name: &str, values: &'a [Value]) -> Result<(&'a Value, &'a Value), CelError> {
    match values {
        [haystack, needle] => Ok((haystack, needle)),
        _ => Err(CelError::Eval {
            message: format!("{name}() takes 2 arguments"),
        }),
    }
}

/// Selects `field` from `base`, borrowing instead of copying.
///
/// One implementation for both the borrow walk and the general evaluator, so a path and its
/// non-path equivalent can never disagree about which select errors are fatal.
fn select_field<'v>(base: &'v Value, field: &str) -> Result<&'v Value, CelError> {
    match base {
        Value::Object(map) => map.get(field).ok_or_else(|| CelError::Eval {
            message: format!("no field {field:?} on object"),
        }),
        other => Err(CelError::Eval {
            message: format!("cannot select field {field:?} from {}", type_name(other)),
        }),
    }
}

/// Indexes `base` with `key`, borrowing instead of copying.
fn index_into<'v>(base: &'v Value, key: &Value) -> Result<&'v Value, CelError> {
    match (base, key) {
        (Value::Array(items), Value::Number(_)) => {
            let position = key.as_u64().ok_or_else(|| CelError::Eval {
                message: "list index must be a non-negative integer".to_owned(),
            })?;
            items
                .get(usize::try_from(position).unwrap_or(usize::MAX))
                .ok_or_else(|| CelError::Eval {
                    message: "list index is out of range".to_owned(),
                })
        }
        (Value::Object(map), Value::String(key)) => map.get(key).ok_or_else(|| CelError::Eval {
            message: format!("no field {key:?} on object"),
        }),
        (other, _) => Err(CelError::Eval {
            message: format!("cannot index {}", type_name(other)),
        }),
    }
}

/// How many JSON nodes a deep copy of `value` would touch, saturating.
///
/// The unit the fuel counter charges for a copy. Deliberately coarse (see [`Env::bill_clone`]).
fn value_nodes(value: &Value) -> u64 {
    let mut nodes: u64 = 0;
    let mut stack = vec![value];
    while let Some(current) = stack.pop() {
        nodes = nodes.saturating_add(1);
        match current {
            Value::Array(items) => stack.extend(items.iter()),
            Value::Object(map) => stack.extend(map.values()),
            _ => {}
        }
    }
    nodes
}

/// How many bytes of string payload a deep copy or a scan of `value` would walk, saturating.
///
/// Map keys count too: a copy allocates them as well. Used with [`FUEL_BYTES_PER_STEP`] to price
/// work a node count cannot see (`T20.2`, finding M-A) — one huge string leaf is one node and any
/// number of bytes.
fn value_bytes(value: &Value) -> u64 {
    let mut bytes: u64 = 0;
    let mut stack = vec![value];
    while let Some(current) = stack.pop() {
        match current {
            Value::String(text) => {
                bytes = bytes.saturating_add(u64::try_from(text.len()).unwrap_or(u64::MAX));
            }
            Value::Array(items) => stack.extend(items.iter()),
            Value::Object(map) => {
                for (key, value) in map {
                    bytes = bytes.saturating_add(u64::try_from(key.len()).unwrap_or(u64::MAX));
                    stack.push(value);
                }
            }
            _ => {}
        }
    }
    bytes
}

/// A value-free name for an [`Expr`], used in the two unreachable-path diagnostics.
fn expr_kind(expr: &Expr) -> &'static str {
    match expr {
        Expr::Literal(_) => "a literal",
        Expr::List(_) => "a list literal",
        Expr::Map(_) => "a map literal",
        Expr::Var(_) => "a variable",
        Expr::Select(..) => "a field selection",
        Expr::Index(..) => "an index",
        Expr::Has(_) => "has()",
        Expr::Call { .. } => "a function call",
        Expr::Not(_) => "a negation",
        Expr::Negate(_) => "an arithmetic negation",
        Expr::Binary { .. } => "an operator",
        Expr::Ternary(..) => "a conditional",
        Expr::Comprehension { .. } => "a comprehension",
    }
}

fn as_boolean(value: &Value) -> Result<bool, CelError> {
    match value {
        Value::Bool(value) => Ok(*value),
        other => Err(CelError::Eval {
            message: format!(
                "comprehension body must be a boolean, found {}",
                type_name(other)
            ),
        }),
    }
}

fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(number) if number.is_i64() => "int",
        Value::Number(_) => "double",
        Value::String(_) => "string",
        Value::Array(_) => "list",
        Value::Object(_) => "map",
    }
}

fn equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Number(a), Value::Number(b)) => {
            if let (Some(a), Some(b)) = (a.as_i64(), b.as_i64()) {
                a == b
            } else {
                match (a.as_f64(), b.as_f64()) {
                    (Some(a), Some(b)) => a == b,
                    _ => false,
                }
            }
        }
        _ => left == right,
    }
}

/// Orders two values, exactly for integers.
///
/// `T20.2` (finding M5): integers are compared **as integers**. Casting both sides to `f64` first —
/// the obvious implementation — silently loses precision above 2^53, so `9007199254740993 >
/// 9007199254740992` (and every comparison between two large `int`s that differ in their low bits)
/// would answer `false`, and a policy guarding on a large generation, size, or timestamp would
/// quietly allow what it was written to refuse. A mixed `int`/`double` comparison still goes through
/// `f64`: that is what CEL does, and it is the only total order available across the two types.
fn compare(left: &Value, right: &Value) -> Result<std::cmp::Ordering, CelError> {
    match (left, right) {
        (Value::Number(a), Value::Number(b)) => {
            if let (Some(a), Some(b)) = (a.as_i64(), b.as_i64()) {
                return Ok(a.cmp(&b));
            }
            let (Some(a), Some(b)) = (a.as_f64(), b.as_f64()) else {
                return Err(CelError::Eval {
                    message: "numbers cannot be ordered".to_owned(),
                });
            };
            a.partial_cmp(&b).ok_or_else(|| CelError::Eval {
                message: "numbers cannot be ordered".to_owned(),
            })
        }
        (Value::String(a), Value::String(b)) => Ok(a.as_str().cmp(b.as_str())),
        (a, b) => Err(CelError::Eval {
            message: format!("cannot order {} against {}", type_name(a), type_name(b)),
        }),
    }
}

fn arithmetic(op: BinOp, left: &Value, right: &Value) -> Result<Value, CelError> {
    // Integers stay integers (CEL's `10 / 4 == 2`): truncating division, truncating remainder, and a
    // checked result so an overflow is an error instead of a wrap-around.
    if let (Some(a), Some(b)) = (left.as_i64(), right.as_i64()) {
        let outcome = match op {
            BinOp::Add => a.checked_add(b),
            BinOp::Sub => a.checked_sub(b),
            BinOp::Mul => a.checked_mul(b),
            BinOp::Div => {
                if b == 0 {
                    return Err(CelError::Eval {
                        message: "division by zero".to_owned(),
                    });
                }
                a.checked_div(b)
            }
            BinOp::Mod => {
                if b == 0 {
                    return Err(CelError::Eval {
                        message: "modulo by zero".to_owned(),
                    });
                }
                a.checked_rem(b)
            }
            _ => {
                return Err(CelError::Eval {
                    message: format!("{op:?} is not arithmetic"),
                });
            }
        };
        return outcome.map(Value::from).ok_or_else(|| CelError::Eval {
            message: "integer arithmetic overflows".to_owned(),
        });
    }

    let (Some(a), Some(b)) = (left.as_f64(), right.as_f64()) else {
        return Err(CelError::Eval {
            message: format!(
                "cannot apply {op:?} to {} and {}",
                type_name(left),
                type_name(right)
            ),
        });
    };
    let outcome = match op {
        BinOp::Add => a + b,
        BinOp::Sub => a - b,
        BinOp::Mul => a * b,
        BinOp::Div => {
            if b == 0.0 {
                return Err(CelError::Eval {
                    message: "division by zero".to_owned(),
                });
            }
            a / b
        }
        BinOp::Mod => {
            if b == 0.0 {
                return Err(CelError::Eval {
                    message: "modulo by zero".to_owned(),
                });
            }
            a % b
        }
        _ => {
            return Err(CelError::Eval {
                message: format!("{op:?} is not arithmetic"),
            });
        }
    };
    Ok(Value::from(outcome))
}

/// Rejects produced values larger than the string/collection budgets.
fn check_output(value: &Value, budget: &CelBudget) -> Result<(), CelError> {
    let mut stack = vec![value];
    let mut nodes = 0_usize;
    while let Some(current) = stack.pop() {
        nodes += 1;
        if nodes > budget.json_nodes {
            return Err(CelError::Eval {
                message: "produced value is over the node budget".to_owned(),
            });
        }
        match current {
            Value::String(text) if text.len() > budget.string_bytes => {
                return Err(CelError::Eval {
                    message: "produced string is over the size budget".to_owned(),
                });
            }
            Value::Array(items) => {
                if items.len() > budget.collection_len {
                    return Err(CelError::Eval {
                        message: "produced list is over the size budget".to_owned(),
                    });
                }
                stack.extend(items.iter());
            }
            Value::Object(map) => {
                if map.len() > budget.collection_len {
                    return Err(CelError::Eval {
                        message: "produced map is over the size budget".to_owned(),
                    });
                }
                stack.extend(map.values());
            }
            _ => {}
        }
    }
    Ok(())
}

/// Whether `value` fits inside the JSON node budget (checked before evaluation).
///
/// # Errors
///
/// [`CelError::Eval`] when the document holds more nodes than the budget allows. The walk is
/// iterative, so a pathological nesting depth cannot overflow the stack.
pub fn check_json_bounds(value: &Value, budget: &CelBudget) -> Result<(), CelError> {
    let mut stack = vec![value];
    let mut nodes = 0_usize;
    while let Some(current) = stack.pop() {
        nodes += 1;
        if nodes > budget.json_nodes {
            return Err(CelError::Eval {
                message: "resource is over the policy evaluation node budget".to_owned(),
            });
        }
        match current {
            Value::Array(items) => stack.extend(items.iter()),
            Value::Object(map) => stack.extend(map.values()),
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn object() -> Value {
        json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "web", "namespace": "payments", "labels": { "cost-center": "cc-42" } },
            "spec": {
                "replicas": 2,
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": "app",
                                "image": "ghcr.io/example/app:1.2.3",
                                "securityContext": { "privileged": false },
                                "resources": { "limits": { "cpu": "100m" } }
                            },
                            {
                                "name": "sidecar",
                                "image": "docker.io/library/busybox:1.36",
                                "resources": {}
                            }
                        ]
                    }
                }
            }
        })
    }

    fn roots() -> BTreeMap<String, Value> {
        BTreeMap::from([
            ("object".to_owned(), object()),
            (
                "app".to_owned(),
                json!({ "name": "web", "namespace": "ferriscd-system", "project": "default" }),
            ),
        ])
    }

    fn eval(source: &str) -> Result<Value, CelError> {
        compile(source)?.evaluate(&roots())
    }

    #[test]
    fn the_canonical_policies_evaluate_deterministically() {
        // The three invariants of the roadmap's own example: no privileged container, signed
        // registry, and a required cost-center label.
        let no_privileged = "!object.spec.template.spec.containers.exists(c, \
                             has(c.securityContext) && c.securityContext.privileged == true)";
        assert_eq!(eval(no_privileged), Ok(Value::Bool(true)));

        let signed_registry = "object.spec.template.spec.containers.all(c, \
                               c.image.startsWith(\"ghcr.io/example/\"))";
        assert_eq!(eval(signed_registry), Ok(Value::Bool(false)));

        let cost_center = "has(object.metadata.labels) && \
                           object.metadata.labels.contains(\"cost-center\")";
        assert_eq!(eval(cost_center), Ok(Value::Bool(true)));

        // Determinism: the same program over the same roots answers the same thing, twice.
        let program = compile(no_privileged).expect("must compile");
        let first = program.evaluate(&roots()).expect("must evaluate");
        let second = program.evaluate(&roots()).expect("must evaluate");
        assert_eq!(first, second);
    }

    #[test]
    fn operators_literals_and_functions_behave_like_cel() {
        assert_eq!(eval("1 + 2 * 3 == 7"), Ok(Value::Bool(true)));
        assert_eq!(eval("2 > 1 && 1 <= 1"), Ok(Value::Bool(true)));
        assert_eq!(eval("false || true"), Ok(Value::Bool(true)));
        assert_eq!(eval("!false"), Ok(Value::Bool(true)));
        assert_eq!(eval("-2 < 0"), Ok(Value::Bool(true)));
        assert_eq!(eval("10 % 3 == 1"), Ok(Value::Bool(true)));
        assert_eq!(eval("10 / 4 == 2"), Ok(Value::Bool(true)));
        assert_eq!(eval("\"a\" + \"b\" == \"ab\""), Ok(Value::Bool(true)));
        assert_eq!(
            eval("size(object.spec.template.spec.containers) == 2"),
            Ok(Value::Bool(true))
        );
        assert_eq!(eval("\"abc\".endsWith(\"bc\")"), Ok(Value::Bool(true)));
        assert_eq!(
            eval("\"ABC\".lowerAscii() == \"abc\""),
            Ok(Value::Bool(true))
        );
        assert_eq!(
            eval("\"prod\" in [\"dev\", \"prod\"]"),
            Ok(Value::Bool(true))
        );
        assert_eq!(eval("size([]) == 0"), Ok(Value::Bool(true)));
        assert_eq!(eval("size({}) == 0"), Ok(Value::Bool(true)));
        assert_eq!(
            eval("true ? \"yes\" : \"no\""),
            Ok(Value::String("yes".to_owned()))
        );
        assert_eq!(
            eval("object.spec.template.spec.containers[0].name"),
            Ok(Value::String("app".to_owned()))
        );
        assert_eq!(
            eval("object[\"metadata\"][\"name\"]"),
            Ok(Value::String("web".to_owned()))
        );
        assert_eq!(
            eval("object.spec.template.spec.containers.filter(c, c.name == \"app\").size() == 1"),
            Ok(Value::Bool(true))
        );
        assert_eq!(
            eval("object.spec.template.spec.containers.map(c, c.name)"),
            Ok(json!(["app", "sidecar"]))
        );
        assert_eq!(eval("app.project == \"default\""), Ok(Value::Bool(true)));
        assert_eq!(
            eval("object.spec.template.spec.containers.exists_one(c, c.name == \"app\")"),
            Ok(Value::Bool(true))
        );
    }

    #[test]
    fn has_tests_presence_without_erroring_on_a_missing_path() {
        assert_eq!(
            eval("has(object.spec.template.spec.containers[0].resources.limits)"),
            Ok(Value::Bool(true))
        );
        assert_eq!(
            eval("has(object.spec.template.spec.containers[1].resources.limits)"),
            Ok(Value::Bool(false))
        );
        assert_eq!(
            eval("has(object.metadata.annotations.missing)"),
            Ok(Value::Bool(false))
        );
        assert_eq!(eval("has(object.metadata)"), Ok(Value::Bool(true)));
    }

    #[test]
    fn unsupported_constructs_are_compile_errors_never_silent_passes() {
        // `matches()` needs a regex engine: refused at compile time, so a policy that relies on it
        // can never be mistaken for an allow.
        let err = compile("object.metadata.name.matches(\"^web$\")").expect_err("must refuse");
        assert!(err.is_compile_error(), "{err:?}");
        assert!(matches!(err, CelError::Unsupported { .. }), "{err:?}");

        for source in [
            "timestamp(\"2020-01-01T00:00:00Z\")",
            "object.metadata.name.type()",
            "object.metadata.name =~ \"x\"",
            "object.metadata.name.notAMacro(x, x)",
            "object.unknownFunction(1)",
        ] {
            let err = compile(source).expect_err(source);
            assert!(err.is_compile_error(), "{source}: {err:?}");
        }

        // An unbound variable is a compile error too: a typo must not evaluate to `false` (a
        // violation) or `true` (an allow) by accident.
        let err = compile("objet.metadata.name == \"web\"").expect_err("must refuse");
        assert!(
            matches!(err, CelError::UnboundVariable { .. }),
            "an unbound root variable must be refused at compile time: {err:?}"
        );
    }

    #[test]
    fn a_malformed_expression_never_compiles() {
        for source in [
            "",
            "object.",
            "1 +",
            "object.metadata.name ==",
            "(1",
            "[1, 2",
        ] {
            assert!(
                compile(source).is_err(),
                "a malformed expression must be a compile error: {source:?}"
            );
        }
    }

    #[test]
    fn budgets_bound_the_expression_size_the_ast_and_the_nesting() {
        let long = format!("object.metadata.name == \"{}\"", "x".repeat(4096));
        assert!(matches!(
            compile(&long),
            Err(CelError::ExpressionTooLong { .. })
        ));

        let nodes = "1 + ".repeat(400) + "1";
        assert!(matches!(
            compile(&nodes),
            Err(CelError::TooManyNodes { .. })
        ));

        let deep = format!("{}1{}", "(".repeat(64), ")".repeat(64));
        assert!(matches!(compile(&deep), Err(CelError::TooDeep { .. })));
    }

    #[test]
    fn the_step_budget_is_the_deterministic_timeout() {
        // A comprehension over a 64-element list cannot finish inside 16 steps. No clock is read:
        // the same program over the same roots always exhausts the same fuel.
        let mut roots = roots();
        roots.insert(
            "object".to_owned(),
            json!({ "items": (0..64).collect::<Vec<_>>() }),
        );
        let program = compile_with(
            "object.items.all(x, x >= 0)",
            CelBudget::default().with_steps(16),
        )
        .expect("must compile");
        assert_eq!(
            program.evaluate(&roots),
            Err(CelError::FuelExhausted { steps: 16 })
        );
        assert_eq!(
            program.evaluate(&roots),
            Err(CelError::FuelExhausted { steps: 16 }),
            "fuel exhaustion must be reproducible, not timing dependent"
        );

        // The same expression inside the default budget finishes and uses a bounded number of
        // steps: cost is a counter, so it can be asserted exactly.
        let program = compile("object.items.all(x, x >= 0)").expect("must compile");
        let (value, steps) = program
            .evaluate_counting(&roots)
            .expect("the default budget is enough");
        assert_eq!(value, Value::Bool(true));
        assert!(
            steps < DEFAULT_MAX_STEPS,
            "one evaluation must stay well inside the fuel budget: {steps}"
        );
    }

    /// `T20.2` (finding M1): a failed evaluation reports the fuel it really burned, so a rule whose
    /// evaluations always error cannot escape the pass-level budget. "Charge one step per error"
    /// would let a policy exhaust the pass ceiling only after thousands of evaluations.
    #[test]
    fn a_failed_evaluation_reports_the_steps_it_consumed() {
        let object = json!({ "items": (0..64).collect::<Vec<_>>() });
        let roots = BTreeMap::new();
        let program = compile_with(
            "object.items.all(x, x >= 0)",
            CelBudget::default().with_steps(16),
        )
        .expect("must compile");
        let failure = program
            .evaluate_counting_with(&roots, Some(&object))
            .expect_err("the budget is exhausted");
        assert_eq!(failure.error, CelError::FuelExhausted { steps: 16 });
        // The counter overshoots the allowance by at most the charge that crossed it (here the copy
        // of the 65-node list), and never under-reports: an always-erroring rule must not be able
        // to spend real work while reporting almost no fuel.
        assert!(
            (16..=16 + value_nodes(&object)).contains(&failure.steps),
            "a fuel-exhausted evaluation is charged the allowance it burned, overshooting by at \
             most the charge that crossed it: {}",
            failure.steps
        );

        // A type error stopped early, so its counter is small but non-zero — never a free lunch.
        let object = json!({ "spec": { "replicas": 2 } });
        let program = compile("object.spec > 3").expect("must compile");
        let failure = program
            .evaluate_counting_with(&roots, Some(&object))
            .expect_err("comparing an object with an int fails");
        assert!(
            (1..16).contains(&failure.steps),
            "a value/type failure still charges what it spent: {}",
            failure.steps
        );
        assert!(
            matches!(failure.error, CelError::Eval { .. }),
            "{:?}",
            failure.error
        );
    }

    /// `T20.2` (finding M3): the `object` root can be **borrowed** instead of copied into `roots`.
    ///
    /// Both forms must evaluate identically — that is what lets the gate drop the per-`(rule,
    /// resource)` deep clone without changing any verdict.
    #[test]
    fn the_object_root_can_be_borrowed_instead_of_copied() {
        let mut roots = roots();
        let object = roots.remove("object").expect("the fixture holds an object");
        let program = compile("object.metadata.name == \"web\" && app.project == \"default\"")
            .expect("must compile");

        assert_eq!(
            program.evaluate_counting_with(&roots, Some(&object)),
            program.evaluate_counting(&{
                let mut with_object = roots.clone();
                with_object.insert("object".to_owned(), object.clone());
                with_object
            }),
            "borrowing the document must be indistinguishable from inserting a copy"
        );

        // Without the borrowed root, `object` really is unbound — not silently `null`.
        assert!(program.evaluate_counting(&roots).is_err());
    }

    /// A **chained** relational comparison is not CEL: `a < b < c` would have to mean
    /// `(a < b) < c`, comparing a boolean with a number. Refusing it at compile time keeps the
    /// failure mode "fix the policy" instead of "type error per resource", and keeps the parser from
    /// inventing a meaning the language does not have.
    #[test]
    fn a_chained_relational_comparison_is_refused_but_parenthesized_ones_work() {
        for source in [
            "1 < 2 < 3",
            "object.spec.replicas >= 1 == true",
            "\"a\" == \"a\" in [true]",
        ] {
            let err = compile(source).expect_err(source);
            assert!(
                err.is_compile_error(),
                "{source}: a chained comparison must never reach evaluation: {err:?}"
            );
            assert!(
                err.to_string().contains("chained relational"),
                "{source}: {err}"
            );
        }

        // Parenthesizing the first comparison is how CEL writes it, and it still compiles.
        assert_eq!(eval("(1 < 2) == true"), Ok(Value::Bool(true)));
        assert_eq!(eval("1 < 2 && 2 < 3"), Ok(Value::Bool(true)));
    }

    #[test]
    fn errors_never_quote_values() {
        // Type errors name types only. A policy author cannot use an error to echo a value, which
        // is what makes it safe to put a CEL error into `Application.status`.
        let mut roots = roots();
        roots.insert(
            "object".to_owned(),
            json!({ "data": { "password": "hunter2" } }),
        );
        let err = compile("object.data.password > 3")
            .expect("must compile")
            .evaluate(&roots)
            .expect_err("comparing a string with an int fails");
        let rendered = err.to_string();
        assert!(
            !rendered.contains("hunter2"),
            "an error must never quote an operand: {rendered}"
        );
        assert!(rendered.contains("cannot order"), "{rendered}");
    }

    #[test]
    fn json_bounds_reject_oversized_documents_iteratively() {
        let budget = CelBudget {
            json_nodes: 8,
            ..CelBudget::default()
        };
        let small = json!({ "a": [1, 2, 3] });
        assert_eq!(check_json_bounds(&small, &budget), Ok(()));
        let wide = json!({ "a": (0..64).collect::<Vec<_>>() });
        assert!(check_json_bounds(&wide, &budget).is_err());
    }

    /// A realistic rendered document: a `ConfigMap` with `entries` keys, the shape a big settings
    /// or Helm-values bundle actually renders to (roughly two JSON nodes per entry).
    fn large_config_map(entries: usize) -> Value {
        let mut data = serde_json::Map::new();
        for index in 0..entries {
            data.insert(
                format!("key-{index:04}"),
                Value::String(format!("value-{index:04}")),
            );
        }
        json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "settings",
                "namespace": "payments",
                "labels": { "cost-center": "cc-42", "app": "payments-api" },
            },
            "data": Value::Object(data),
        })
    }

    /// **`T20.2` finding H1:** fuel is a *work* counter, so it has to grow with the document.
    ///
    /// Before the fix `Var`/`Select`/`Index` deep-cloned the document once per evaluation while the
    /// counter only moved once per AST node: a four-node expression copied a multi-thousand-node
    /// resource for a handful of "steps", so the pass budget in [`super::gate`] bounded the shape of
    /// the policies and not the work they caused. The relationship asserted here is step-vs-size,
    /// over a realistic document, not step-vs-expression.
    #[test]
    fn the_fuel_counter_charges_for_the_copy_a_reference_makes() {
        const EXPRESSION: &str = "object.data.contains(\"key-0000\") || size(object.data) > 0";
        let program = compile(EXPRESSION).expect("must compile");
        let roots = BTreeMap::new();

        let small = large_config_map(50);
        let large = large_config_map(500);
        let (_, small_steps) = program
            .evaluate_counting_with(&roots, Some(&small))
            .expect("the small document evaluates");
        let (_, large_steps) = program
            .evaluate_counting_with(&roots, Some(&large))
            .expect("the large document evaluates");

        // The same expression over a document with 10x the entries must charge substantially more
        // fuel. Anything close to equality would mean the counter ignores the copy again.
        assert!(
            large_steps >= small_steps * 5,
            "fuel must scale with the copied document: {small_steps} steps for {} nodes, \
             {large_steps} steps for {} nodes",
            value_nodes(&small),
            value_nodes(&large)
        );
        // ... and at least one unit per copied node of the data map it selects.
        assert!(
            large_steps >= 500,
            "selecting a 500-entry map must charge at least 500 steps: {large_steps}"
        );

        // A per-expression allowance sized for the small document therefore cannot pay for the
        // large one: the budget refuses *before* the copy, so no work is done it cannot afford.
        let tight = compile_with(EXPRESSION, CelBudget::default().with_steps(small_steps))
            .expect("must compile");
        let refusal = tight
            .evaluate_counting_with(&roots, Some(&large))
            .expect_err("a 50-entry budget must fail closed on a 500-entry document");
        assert_eq!(
            refusal.error,
            CelError::FuelExhausted { steps: small_steps }
        );
        assert!(
            refusal.steps >= small_steps,
            "the refused evaluation is charged for the work it requested: {}",
            refusal.steps
        );
        assert_eq!(
            tight
                .evaluate_counting_with(&roots, Some(&small))
                .map(|(value, _)| value),
            Ok(Value::Bool(true)),
            "the same allowance still pays for the document it was sized for"
        );
    }

    /// **`T20.2` finding H1, second half:** a `Var`/`Select`/`Index` path is walked **by
    /// reference**, so a leaf selection costs the leaf, not the document.
    ///
    /// Without the borrow walk the chain `object.metadata.name` would copy the whole document once
    /// per segment, and a policy over a large resource would spend thousands of steps (and real
    /// time) to read one string.
    #[test]
    fn a_path_is_walked_by_reference_and_costs_only_its_leaf() {
        let document = large_config_map(1_000);
        let nodes = value_nodes(&document);
        assert!(nodes > 1_000, "the fixture must be large: {nodes} nodes");
        let roots = BTreeMap::new();

        let leaf = compile("object.metadata.name == \"settings\"")
            .expect("must compile")
            .evaluate_counting_with(&roots, Some(&document))
            .expect("the leaf selection evaluates");
        assert_eq!(leaf.0, Value::Bool(true));
        assert!(
            leaf.1 < nodes / 4,
            "reading one leaf must not cost anything like the whole document: {} steps for {nodes} \
             nodes",
            leaf.1
        );

        // The bare root really does copy the document, and is charged for it: that is the cost the
        // pass budget has to be able to refuse.
        let whole = compile("size(object) > 0")
            .expect("must compile")
            .evaluate_counting_with(&roots, Some(&document))
            .expect("the root evaluates");
        assert_eq!(whole.0, Value::Bool(true));
        assert!(
            whole.1 >= nodes,
            "a whole-document copy must be charged at least one unit per node: {} steps for {nodes} \
             nodes",
            whole.1
        );
    }

    /// A rendered `ConfigMap` whose `data` is the given object.
    ///
    /// **`T20.2` finding M2:** the byte-charge fixture is a rendered `ConfigMap` blob, not a
    /// `Secret.data` value. The gate replaces every `Secret` payload with `<redacted>` *before* the
    /// evaluator sees it (see [`super::gate`]), so a 256 KiB Secret leaf is a shape no policy can
    /// ever meet; the large string payload a policy *can* be made to walk is a rendered `ConfigMap`
    /// value (or any other rendered document's string data).
    fn config_map(data: Value) -> Value {
        json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": "settings", "namespace": "payments" },
            "data": data,
        })
    }

    /// Proves that `charged` pays for the operation under test, not merely for its reads.
    ///
    /// `control` performs the **same** reads — so it pays the same copy charges — without the
    /// operation under test, and must succeed under the identical `budget`. That is the only shape
    /// of assertion that can distinguish a charge from the copies around it: a `steps >=
    /// byte_units` assertion is satisfied by the leaf copies alone and therefore passes with or
    /// without the charge (`T20.2`, finding H2).
    ///
    /// Both expressions produce a small value, because [`check_output`] rejects a produced string
    /// over the output budget — a control that exfiltrated the blob would fail for the wrong reason.
    #[track_caller]
    fn assert_charged(charged: &str, control: &str, document: &Value, budget: u64) {
        let roots = BTreeMap::new();
        let limited = compile_with(charged, CelBudget::default().with_steps(budget))
            .expect("the charged expression must compile");
        let refusal = limited
            .evaluate_counting_with(&roots, Some(document))
            .expect_err("a budget the charge does not fit in must run out of fuel");
        assert_eq!(
            refusal.error,
            CelError::FuelExhausted { steps: budget },
            "`{charged}` must be refused by fuel, not by another budget"
        );
        assert!(
            refusal.steps >= budget,
            "the refused evaluation is charged for the work it asked to do: {} of {budget}",
            refusal.steps
        );
        let allowed = compile_with(control, CelBudget::default().with_steps(budget))
            .expect("the control expression must compile");
        assert!(
            allowed
                .evaluate_counting_with(&roots, Some(document))
                .is_ok(),
            "the {budget}-unit budget must pay for the reads alone: `{control}` failed, so the \
             refusal above proves nothing about the charge under test"
        );
    }

    /// **`T20.2` findings M-A/H2:** fuel charges *bytes*, not just nodes — and every
    /// byte-proportional operation is proved by a budget only its own charge can exhaust.
    ///
    /// One huge string leaf is **one** JSON node, so a node-priced counter let a policy pay a single
    /// unit for a leaf and then have the machine walk (copy, order, scan, or substring-search) all of
    /// its bytes. Every such operation charges `bytes / FUEL_BYTES_PER_STEP` units *before* the work
    /// happens, so a budget sized for the reads refuses the work instead.
    #[test]
    fn a_huge_string_leaf_is_charged_for_its_bytes_not_its_node_count() {
        const BLOB: usize = 256 * 1024;
        const SMALL: &str = "xxxx";
        let blob = "x".repeat(BLOB);
        let byte_units = u64::try_from(BLOB).expect("fits") / FUEL_BYTES_PER_STEP;
        let roots = BTreeMap::new();

        let one_blob = config_map(json!({ "blob": blob.clone() }));
        let two_blobs = config_map(json!({ "blob": blob.clone(), "other": blob }));
        let list = config_map(json!({ "list": ["x".repeat(BLOB), "y".repeat(BLOB)] }));

        // (1) A substring search walks the haystack's bytes.
        let (value, steps) = compile("object.data.blob.startsWith(\"xxx\")")
            .expect("must compile")
            .evaluate_counting_with(&roots, Some(&one_blob))
            .expect("the leaf evaluates");
        assert_eq!(value, Value::Bool(true));
        assert!(
            steps >= byte_units * 2,
            "a {BLOB}-byte leaf must be charged for its bytes twice (the copy, then the search): \
             {steps} steps"
        );
        // The copy of the same bytes fits in two thirds of this budget, the search does not.
        assert_charged(
            "object.data.blob.startsWith(\"xxx\")",
            "size(object.data) > 0",
            &one_blob,
            byte_units + byte_units / 2,
        );

        // (2) Ordering two strings walks their bytes too, and used to charge nothing at all: the two
        // leaf copies fit in the budget below, the ordering charge does not (`T20.2`, finding H2).
        let (value, steps) = compile("object.data.blob > object.data.other")
            .expect("must compile")
            .evaluate_counting_with(&roots, Some(&two_blobs))
            .expect("the comparison evaluates");
        assert_eq!(value, Value::Bool(false));
        assert!(
            steps >= byte_units * 3,
            "ordering two {BLOB}-byte strings must be charged for their bytes on top of the copies \
             of both operands: {steps} steps"
        );
        assert_charged(
            "object.data.blob > object.data.other",
            "size(object.data) > 0",
            &two_blobs,
            byte_units * 3,
        );

        // (3) A membership test scans the elements of a list, and every element comparison walks its
        // bytes: the scan is priced by payload, not one unit per element.
        let (value, steps) = compile("\"x\" in object.data.list")
            .expect("must compile")
            .evaluate_counting_with(&roots, Some(&list))
            .expect("the membership test evaluates");
        assert_eq!(value, Value::Bool(false));
        assert!(
            steps >= byte_units * 3,
            "scanning two {BLOB}-byte strings must be charged for their bytes on top of the copy of \
             the list: {steps} steps"
        );
        assert_charged(
            "\"x\" in object.data.list",
            "size(object.data) > 0",
            &list,
            byte_units * 3,
        );

        // (4) `size()` of a *string* counts its characters, so it walks the bytes as well — the case
        // the node charge alone could not see (finding H2).
        assert_charged(
            "size(object.data.blob) > 0",
            "size(object.data) > 0",
            &one_blob,
            byte_units + byte_units / 2,
        );

        // (5) A per-expression allowance sized for the *node* count cannot pay for that work, and the
        // refusal happens before the copy: the counter is charged for what it was about to walk.
        let tight = compile_with(
            "object.data.blob.startsWith(\"xxx\")",
            CelBudget::default().with_steps(64),
        )
        .expect("must compile");
        let refusal = tight
            .evaluate_counting_with(&roots, Some(&one_blob))
            .expect_err("64 units cannot pay for a 256 KiB leaf");
        assert_eq!(refusal.error, CelError::FuelExhausted { steps: 64 });
        assert!(
            refusal.steps >= byte_units,
            "the refused evaluation is charged for the bytes it asked to walk: {}",
            refusal.steps
        );

        // (6) The same allowance is plenty for a small leaf: the charge is proportional, not a
        // blanket rejection of string builtins.
        let small = config_map(json!({ "blob": SMALL }));
        assert_eq!(
            tight
                .evaluate_counting_with(&roots, Some(&small))
                .map(|(value, _)| value),
            Ok(Value::Bool(true))
        );
    }

    /// **`T20.2` finding M3:** concatenation and case mapping allocate, so they are charged for what
    /// they allocate — before the allocation, like every other byte-proportional operation.
    ///
    /// `+` on strings built a fresh `String`, and `lowerAscii`/`upperAscii` built a second copy of
    /// their operand, while fuel only moved per AST node and for the *reads*: the operand's copy was
    /// paid for, the write that duplicated it was not. Array `+` charged `a.len() + b.len()`, so two
    /// lists holding megabyte-sized elements cost two units to copy.
    #[test]
    fn concatenation_and_case_mapping_are_charged_for_their_allocations() {
        // Large enough that the bytes dominate the node count, small enough that the produced string
        // stays inside `DEFAULT_MAX_STRING_BYTES`.
        const TEXT: usize = 4_000;
        const BLOB: usize = 256 * 1024;
        let units = u64::try_from(TEXT).expect("fits") / FUEL_BYTES_PER_STEP;
        let text = config_map(json!({ "blob": "x".repeat(TEXT) }));

        // String `+` writes both operands again; the result stays under the output budget so only the
        // fuel charge can refuse it.
        assert_charged(
            "object.data.blob + \"\"",
            "size(object.data) > 0",
            &text,
            units * 2,
        );

        // A case mapping allocates a second copy of its operand.
        assert_charged(
            "object.data.blob.lowerAscii()",
            "size(object.data) > 0",
            &text,
            units * 2,
        );
        assert_charged(
            "object.data.blob.upperAscii()",
            "size(object.data) > 0",
            &text,
            units * 2,
        );

        // Array `+` copies both lists: the element count alone is not the cost.
        let byte_units = u64::try_from(BLOB).expect("fits") / FUEL_BYTES_PER_STEP;
        let list = config_map(json!({ "list": ["x".repeat(BLOB), "y".repeat(BLOB)] }));
        assert_charged(
            "object.data.list + object.data.list",
            "size(object.data) > 0",
            &list,
            byte_units * 4 + byte_units / 2,
        );

        // ... and the charge is proportional, so a small concatenation is unaffected.
        assert_eq!(
            compile("(\"a\" + \"b\").size() == 2 && \"AB\".lowerAscii() == \"ab\"")
                .expect("must compile")
                .evaluate(&BTreeMap::new()),
            Ok(Value::Bool(true))
        );
    }

    /// **`T20.2` finding H4:** `list.filter(x, p)` selects the **items** that satisfy `p`.
    ///
    /// Pushing the predicate's boolean instead is the kind of wrong answer that still "works":
    /// `filter(...).size() == 2` was satisfied by `[true, true]`, so the roadmap's own advice
    /// (`containers.filter(c, c.image.startsWith(\"ghcr.io/\")).size() == size(containers)`) proved
    /// nothing. The assertions below name a field of the element, which only a real element can
    /// answer.
    #[test]
    fn filter_pushes_the_matching_items_not_the_predicate_results() {
        let object = object();
        let roots = BTreeMap::from([(OBJECT_ROOT.to_owned(), object.clone())]);

        assert_eq!(
            compile("object.spec.template.spec.containers.filter(c, c.name == \"app\")[0].name")
                .expect("must compile")
                .evaluate(&roots),
            Ok(Value::String("app".to_owned())),
            "the element bound by filter() must be the container itself"
        );
        assert_eq!(
            compile("object.spec.template.spec.containers.filter(c, c.name == \"app\")")
                .expect("must compile")
                .evaluate(&roots),
            Ok(json!([{
                "name": "app",
                "image": "ghcr.io/example/app:1.2.3",
                "securityContext": { "privileged": false },
                "resources": { "limits": { "cpu": "100m" } }
            }]))
        );

        // An empty result, and the roadmap's registry policy expressed through `filter()`: only a
        // real element list makes this comparison meaningful.
        assert_eq!(
            compile("object.spec.template.spec.containers.filter(c, c.name == \"missing\")")
                .expect("must compile")
                .evaluate(&roots),
            Ok(json!([]))
        );
        assert_eq!(
            compile(
                "object.spec.template.spec.containers.filter(c, \
                 c.image.startsWith(\"ghcr.io/example/\")).size() == 1"
            )
            .expect("must compile")
            .evaluate(&roots),
            Ok(Value::Bool(true))
        );

        // A predicate that errors still fails the whole evaluation (fail closed), and the
        // comprehension frame is restored so a later iteration cannot see a stale binding.
        assert!(matches!(
            compile("object.spec.template.spec.containers.filter(c, c.name > 3)")
                .expect("must compile")
                .evaluate(&roots),
            Err(CelError::Eval { .. })
        ));
        assert_eq!(
            compile("object.spec.template.spec.containers.map(c, c.name)")
                .expect("must compile")
                .evaluate(&roots),
            Ok(json!(["app", "sidecar"])),
            "map() still projects the expression, sharing the comprehension loop with filter()"
        );
    }

    /// **`T20.2` finding M5:** integer comparison is exact, including above 2^53.
    ///
    /// Casting both operands to `f64` first — the previous implementation — made
    /// `9007199254740993 > 9007199254740992` false and `i64::MAX > i64::MAX - 1` false, so a policy
    /// guarding on a large count or generation silently allowed what it was written to refuse.
    #[test]
    fn integer_comparisons_are_exact_above_the_double_precision_boundary() {
        // 2^53 + 1 and 2^53 are distinct `i64`s that collapse to the same `f64`.
        assert_eq!(
            eval("9007199254740993 > 9007199254740992"),
            Ok(Value::Bool(true))
        );
        assert_eq!(
            eval("9007199254740992 < 9007199254740993"),
            Ok(Value::Bool(true))
        );
        assert_eq!(
            eval("9007199254740993 == 9007199254740992"),
            Ok(Value::Bool(false))
        );
        assert_eq!(
            eval("9007199254740992 >= 9007199254740992"),
            Ok(Value::Bool(true))
        );

        // The ends of the `i64` range, and the negative side of the same boundary.
        assert_eq!(
            eval("9223372036854775807 > 9223372036854775806"),
            Ok(Value::Bool(true))
        );
        assert_eq!(
            eval("-9223372036854775807 < -9223372036854775806"),
            Ok(Value::Bool(true))
        );
        // (`-9223372036854775808` is not writable as a literal: the lexer reads the magnitude
        // first, so `i64::MIN` is out of range exactly as in CEL. The negative side of the 2^53
        // boundary is what matters here.)
        assert_eq!(
            eval("-9007199254740993 < -9007199254740992"),
            Ok(Value::Bool(true))
        );

        // Mixed int/double still orders (through `f64`, as CEL does), and a comparison that has no
        // order is an error rather than an invented `false`.
        assert_eq!(eval("1 < 1.5"), Ok(Value::Bool(true)));
        assert_eq!(eval("2.0 <= 2"), Ok(Value::Bool(true)));
        assert_eq!(
            eval("9007199254740993 < 9007199254740993.5"),
            Ok(Value::Bool(true))
        );
        assert!(matches!(
            compile("object.metadata > 3")
                .expect("must compile")
                .evaluate(&roots()),
            Err(CelError::Eval { .. })
        ));
    }

    #[test]
    fn programs_are_reusable_and_cheap_to_hold() {
        let program = compile("object.kind == \"Deployment\"").expect("must compile");
        assert!(program.nodes() > 0);
        assert_eq!(
            program.source_length(),
            "object.kind == \"Deployment\"".len()
        );
        assert_eq!(program.clone(), program);
    }
}
