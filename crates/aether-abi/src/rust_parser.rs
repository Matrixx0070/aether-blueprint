//! Rust FFI binding parser — extracts `extern "C"` functions and `#[repr(C)]` structs.

use crate::types::{CField, CFunction, CParam, CStruct, CType};
use once_cell::sync::Lazy;
use regex::Regex;

static RE_REPR_C_STRUCT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"#\[repr\(C\)\]\s*(?:pub\s+)?struct\s+(\w+)\s*\{([^}]*)\}").unwrap()
});
static RE_EXTERN_FN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?s)pub\s+fn\s+(\w+)\s*\(([^)]*)\)\s*(?:->\s*([\w\s\*:<>]+?))?\s*;"#).unwrap()
});
static RE_FIELD: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:pub\s+)?(\w+)\s*:\s*([\w\s\*:<>\[\]]+),?").unwrap());

/// Extract `#[repr(C)]` structs from a Rust source string.
pub fn parse_repr_c_structs(source: &str) -> Vec<CStruct> {
    let mut structs = Vec::new();
    for cap in RE_REPR_C_STRUCT.captures_iter(source) {
        let name = cap[1].to_string();
        let body = &cap[2];
        let fields: Vec<CField> = RE_FIELD
            .captures_iter(body)
            .map(|fc| CField {
                name: fc[1].to_string(),
                ty: parse_rust_type(fc[2].trim()),
            })
            .collect();
        structs.push(CStruct { name, fields });
    }
    structs
}

/// Extract `extern "C"` function signatures from a Rust source string.
/// Caller should pass the content of an `extern "C" { ... }` block.
pub fn parse_extern_fns(source: &str) -> Vec<CFunction> {
    let mut funcs = Vec::new();
    for cap in RE_EXTERN_FN.captures_iter(source) {
        let name = cap[1].to_string();
        let params = parse_rust_params(cap[2].trim());
        let ret = cap
            .get(3)
            .map(|m| parse_rust_type(m.as_str().trim()))
            .unwrap_or(CType::Void);
        funcs.push(CFunction {
            name,
            return_type: ret,
            params,
        });
    }
    funcs
}

fn parse_rust_params(s: &str) -> Vec<CParam> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split(',')
        .filter_map(|part| {
            let part = part.trim();
            if part.is_empty() {
                return None;
            }
            let mut it = part.splitn(2, ':');
            let name = it.next()?.trim().to_string();
            let ty_str = it.next()?.trim();
            let ty = parse_rust_type(ty_str);
            Some(CParam { name, ty })
        })
        .collect()
}

/// Map Rust type strings to CType.
pub fn parse_rust_type(s: &str) -> CType {
    let s = s.trim();
    // Raw pointer: *mut T or *const T
    if let Some(inner) = s.strip_prefix("*mut ").or_else(|| s.strip_prefix("*const ")) {
        return CType::Ptr(Box::new(parse_rust_type(inner)), 1);
    }
    match s {
        "c_void" | "libc::c_void" | "()" => CType::Void,
        "i8" | "c_char" | "libc::c_char" => CType::I8,
        "u8" | "c_uchar" | "libc::c_uchar" => CType::U8,
        "i16" | "c_short" | "libc::c_short" => CType::I16,
        "u16" | "c_ushort" | "libc::c_ushort" => CType::U16,
        "i32" | "c_int" | "libc::c_int" => CType::I32,
        "u32" | "c_uint" | "libc::c_uint" => CType::U32,
        "i64" | "c_long" | "libc::c_long" | "c_longlong" | "libc::c_longlong" => CType::I64,
        "u64" | "c_ulong" | "libc::c_ulong" | "usize" | "c_ulonglong" => CType::U64,
        "f32" | "c_float" | "libc::c_float" => CType::F32,
        "f64" | "c_double" | "libc::c_double" => CType::F64,
        "bool" => CType::Bool,
        other => CType::Named(other.to_string()),
    }
}
