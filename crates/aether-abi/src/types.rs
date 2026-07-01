//! Shared ABI type representation used by both C and Rust parsers.

use serde::{Deserialize, Serialize};

/// Canonical type representation that bridges C and Rust.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CType {
    Void,
    Bool,
    I8,
    U8,
    I16,
    U16,
    I32,
    U32,
    I64,
    U64,
    F32,
    F64,
    /// Pointer with indirection depth (1 = *, 2 = **).
    Ptr(Box<CType>, usize),
    /// Named / opaque type (struct reference, typedef, etc.).
    Named(String),
    /// Unrecognised / complex type.
    Unknown(String),
}

impl std::fmt::Display for CType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CType::Void => write!(f, "void"),
            CType::Bool => write!(f, "bool"),
            CType::I8 => write!(f, "i8"),
            CType::U8 => write!(f, "u8"),
            CType::I16 => write!(f, "i16"),
            CType::U16 => write!(f, "u16"),
            CType::I32 => write!(f, "i32"),
            CType::U32 => write!(f, "u32"),
            CType::I64 => write!(f, "i64"),
            CType::U64 => write!(f, "u64"),
            CType::F32 => write!(f, "f32"),
            CType::F64 => write!(f, "f64"),
            CType::Ptr(inner, depth) => {
                write!(f, "{}", "*".repeat(*depth))?;
                write!(f, "{inner}")
            }
            CType::Named(n) => write!(f, "{n}"),
            CType::Unknown(s) => write!(f, "?{s}"),
        }
    }
}

impl CType {
    /// Return true if this type is ABI-compatible with `other`.
    /// This is conservative: Named/Unknown types match if names match.
    pub fn abi_compatible(&self, other: &CType) -> bool {
        use CType::*;
        match (self, other) {
            (Void, Void) | (Bool, Bool) => true,
            (I8, I8) | (U8, U8) => true,
            (I16, I16) | (U16, U16) => true,
            (I32, I32) | (U32, U32) => true,
            (I64, I64) | (U64, U64) => true,
            (F32, F32) | (F64, F64) => true,
            (Ptr(a, da), Ptr(b, db)) => da == db && a.abi_compatible(b),
            (Named(a), Named(b)) => a == b,
            // usize / u64 on 64-bit platforms
            (U64, Named(n)) | (Named(n), U64) if n == "usize" || n == "size_t" => true,
            // i64 / isize
            (I64, Named(n)) | (Named(n), I64) if n == "isize" => true,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CField {
    pub name: String,
    pub ty: CType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CStruct {
    pub name: String,
    pub fields: Vec<CField>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CParam {
    pub name: String,
    pub ty: CType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CFunction {
    pub name: String,
    pub return_type: CType,
    pub params: Vec<CParam>,
}
