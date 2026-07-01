//! Symbolic expression and constraint representation.
//!
//! Expr is a simple recursive value language: integers, symbols, boolean ops,
//! arithmetic, and comparisons. Constraints are boolean Exprs used as path
//! conditions during backward slicing.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A symbolic expression.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Expr {
    /// Named symbolic variable (e.g. "x", "env_HOME").
    Sym(String),
    /// Integer literal.
    Int(i64),
    /// Boolean literal.
    Bool(bool),
    /// Arithmetic: left op right.
    BinOp {
        op: ArithOp,
        left: Box<Expr>,
        right: Box<Expr>,
    },
    /// Comparison: left rel right → Bool.
    Cmp {
        rel: CmpRel,
        left: Box<Expr>,
        right: Box<Expr>,
    },
    /// Logical not.
    Not(Box<Expr>),
    /// Logical and.
    And(Vec<Expr>),
    /// Logical or.
    Or(Vec<Expr>),
    /// Select/ternary: cond ? then : else.
    Ite {
        cond: Box<Expr>,
        then: Box<Expr>,
        else_: Box<Expr>,
    },
    /// Function / call site (uninterpreted): f(args…).
    App { func: String, args: Vec<Expr> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArithOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    BitAnd,
    BitOr,
    BitXor,
    Shl,
    Shr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CmpRel {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Expr::Sym(s) => write!(f, "{s}"),
            Expr::Int(n) => write!(f, "{n}"),
            Expr::Bool(b) => write!(f, "{b}"),
            Expr::BinOp { op, left, right } => {
                write!(f, "({left} {op} {right})")
            }
            Expr::Cmp { rel, left, right } => {
                write!(f, "({left} {rel} {right})")
            }
            Expr::Not(e) => write!(f, "¬{e}"),
            Expr::And(es) => {
                let parts: Vec<_> = es.iter().map(|e| format!("{e}")).collect();
                write!(f, "({})", parts.join(" ∧ "))
            }
            Expr::Or(es) => {
                let parts: Vec<_> = es.iter().map(|e| format!("{e}")).collect();
                write!(f, "({})", parts.join(" ∨ "))
            }
            Expr::Ite { cond, then, else_ } => {
                write!(f, "({cond} ? {then} : {else_})")
            }
            Expr::App { func, args } => {
                let parts: Vec<_> = args.iter().map(|e| format!("{e}")).collect();
                write!(f, "{func}({})", parts.join(", "))
            }
        }
    }
}

impl fmt::Display for ArithOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ArithOp::Add => "+",
                ArithOp::Sub => "-",
                ArithOp::Mul => "*",
                ArithOp::Div => "/",
                ArithOp::Mod => "%",
                ArithOp::BitAnd => "&",
                ArithOp::BitOr => "|",
                ArithOp::BitXor => "^",
                ArithOp::Shl => "<<",
                ArithOp::Shr => ">>",
            }
        )
    }
}

impl fmt::Display for CmpRel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                CmpRel::Eq => "==",
                CmpRel::Ne => "!=",
                CmpRel::Lt => "<",
                CmpRel::Le => "<=",
                CmpRel::Gt => ">",
                CmpRel::Ge => ">=",
            }
        )
    }
}

impl Expr {
    /// Simplify obvious constant sub-expressions without a full SMT solver.
    /// Returns a new Expr that is semantically equivalent but possibly smaller.
    pub fn simplify(self) -> Expr {
        match self {
            Expr::Not(inner) => match inner.simplify() {
                Expr::Bool(b) => Expr::Bool(!b),
                Expr::Not(e) => *e,
                other => Expr::Not(Box::new(other)),
            },
            Expr::And(es) => {
                let mut simplified: Vec<Expr> = es
                    .into_iter()
                    .map(|e| e.simplify())
                    .filter(|e| *e != Expr::Bool(true))
                    .collect();
                if simplified.iter().any(|e| *e == Expr::Bool(false)) {
                    return Expr::Bool(false);
                }
                match simplified.len() {
                    0 => Expr::Bool(true),
                    1 => simplified.remove(0),
                    _ => Expr::And(simplified),
                }
            }
            Expr::Or(es) => {
                let mut simplified: Vec<Expr> = es
                    .into_iter()
                    .map(|e| e.simplify())
                    .filter(|e| *e != Expr::Bool(false))
                    .collect();
                if simplified.iter().any(|e| *e == Expr::Bool(true)) {
                    return Expr::Bool(true);
                }
                match simplified.len() {
                    0 => Expr::Bool(false),
                    1 => simplified.remove(0),
                    _ => Expr::Or(simplified),
                }
            }
            Expr::BinOp { op, left, right } => {
                let l = left.simplify();
                let r = right.simplify();
                if let (Expr::Int(a), Expr::Int(b)) = (&l, &r) {
                    if let Some(result) = eval_arith(op, *a, *b) {
                        return Expr::Int(result);
                    }
                }
                Expr::BinOp {
                    op,
                    left: Box::new(l),
                    right: Box::new(r),
                }
            }
            Expr::Cmp { rel, left, right } => {
                let l = left.simplify();
                let r = right.simplify();
                if let (Expr::Int(a), Expr::Int(b)) = (&l, &r) {
                    return Expr::Bool(eval_cmp(rel, *a, *b));
                }
                Expr::Cmp {
                    rel,
                    left: Box::new(l),
                    right: Box::new(r),
                }
            }
            other => other,
        }
    }

    /// Collect all symbolic variable names referenced in this expression.
    pub fn free_vars(&self) -> Vec<String> {
        let mut vars = Vec::new();
        collect_vars(self, &mut vars);
        vars.sort();
        vars.dedup();
        vars
    }

    /// True iff the expression is a concrete boolean (no free vars).
    pub fn is_concrete(&self) -> bool {
        self.free_vars().is_empty()
    }
}

fn eval_arith(op: ArithOp, a: i64, b: i64) -> Option<i64> {
    match op {
        ArithOp::Add => a.checked_add(b),
        ArithOp::Sub => a.checked_sub(b),
        ArithOp::Mul => a.checked_mul(b),
        ArithOp::Div if b != 0 => Some(a / b),
        ArithOp::Mod if b != 0 => Some(a % b),
        ArithOp::BitAnd => Some(a & b),
        ArithOp::BitOr => Some(a | b),
        ArithOp::BitXor => Some(a ^ b),
        ArithOp::Shl if b >= 0 => a.checked_shl(b as u32),
        ArithOp::Shr if b >= 0 => a.checked_shr(b as u32),
        _ => None,
    }
}

fn eval_cmp(rel: CmpRel, a: i64, b: i64) -> bool {
    match rel {
        CmpRel::Eq => a == b,
        CmpRel::Ne => a != b,
        CmpRel::Lt => a < b,
        CmpRel::Le => a <= b,
        CmpRel::Gt => a > b,
        CmpRel::Ge => a >= b,
    }
}

fn collect_vars(e: &Expr, out: &mut Vec<String>) {
    match e {
        Expr::Sym(s) => out.push(s.clone()),
        Expr::BinOp { left, right, .. } => {
            collect_vars(left, out);
            collect_vars(right, out);
        }
        Expr::Cmp { left, right, .. } => {
            collect_vars(left, out);
            collect_vars(right, out);
        }
        Expr::Not(inner) => collect_vars(inner, out),
        Expr::And(es) | Expr::Or(es) => es.iter().for_each(|e| collect_vars(e, out)),
        Expr::Ite { cond, then, else_ } => {
            collect_vars(cond, out);
            collect_vars(then, out);
            collect_vars(else_, out);
        }
        Expr::App { args, .. } => args.iter().for_each(|e| collect_vars(e, out)),
        Expr::Int(_) | Expr::Bool(_) => {}
    }
}
