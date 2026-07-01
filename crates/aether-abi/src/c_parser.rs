//! Lightweight C header parser — extracts struct layouts and function declarations.
//!
//! Handles common FFI headers. Does NOT handle C preprocessor macros or
//! complex typedefs involving function pointers (those are flagged as Unknown).

use crate::types::{CField, CFunction, CParam, CStruct, CType};
use once_cell::sync::Lazy;
use regex::Regex;

static RE_STRUCT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"typedef\s+struct\s*\w*\s*\{([^}]*)\}\s*(\w+)\s*;").unwrap());
static RE_FUNC: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(\w[\w\s\*]+?)\s+(\w+)\s*\(([^)]*)\)\s*;").unwrap()
});
static RE_FIELD: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"([\w][\w\s\*]*?)\s+(\w+)\s*(?:\[\d*\])?$").unwrap());

/// Parse a C header string and return all typedef structs found.
pub fn parse_structs(header: &str) -> Vec<CStruct> {
    let mut structs = Vec::new();
    for cap in RE_STRUCT.captures_iter(header) {
        let fields_text = &cap[1];
        let name = cap[2].to_string();
        // Split on `;` so single-line and multi-line structs both work.
        let fields: Vec<CField> = fields_text
            .split(';')
            .filter_map(|chunk| {
                let chunk = chunk.trim();
                if chunk.is_empty() {
                    return None;
                }
                RE_FIELD.captures(chunk).map(|fc| CField {
                    name: fc[2].to_string(),
                    ty: parse_c_type(fc[1].trim()),
                })
            })
            .collect();
        structs.push(CStruct { name, fields });
    }
    structs
}

/// Parse function declarations from a C header.
/// Returns only top-level declarations (not struct members).
pub fn parse_functions(header: &str) -> Vec<CFunction> {
    let mut funcs = Vec::new();
    // Strip struct bodies first to avoid false positives
    let stripped = RE_STRUCT.replace_all(header, "");
    for cap in RE_FUNC.captures_iter(&stripped) {
        let ret_type = parse_c_type(cap[1].trim());
        let name = cap[2].to_string();
        // Skip keywords that look like function decls
        if matches!(name.as_str(), "if" | "while" | "for" | "switch" | "return") {
            continue;
        }
        let params = parse_params(cap[3].trim());
        funcs.push(CFunction {
            name,
            return_type: ret_type,
            params,
        });
    }
    funcs
}

fn parse_params(params_str: &str) -> Vec<CParam> {
    if params_str.is_empty() || params_str == "void" {
        return Vec::new();
    }
    params_str
        .split(',')
        .enumerate()
        .map(|(i, part)| {
            let part = part.trim();
            // Last word is the param name, rest is type
            let mut words: Vec<&str> = part.split_whitespace().collect();
            let name = if words.len() > 1 {
                words.pop().unwrap_or("_").to_string()
            } else {
                format!("arg{i}")
            };
            let ty = parse_c_type(&words.join(" "));
            CParam { name, ty }
        })
        .collect()
}

/// Map C type strings to our CType enum.
pub fn parse_c_type(s: &str) -> CType {
    let s = s.trim();
    // Strip pointer stars to get base type
    let stars = s.chars().filter(|&c| c == '*').count();
    let base = s.trim_end_matches('*').trim().trim_end_matches("const").trim();

    let base_ty = match base {
        "void" => CType::Void,
        "char" | "signed char" => CType::I8,
        "unsigned char" | "uint8_t" => CType::U8,
        "short" | "int16_t" | "signed short" => CType::I16,
        "unsigned short" | "uint16_t" => CType::U16,
        "int" | "int32_t" | "signed int" | "signed" => CType::I32,
        "unsigned int" | "uint32_t" | "unsigned" => CType::U32,
        "long" | "int64_t" | "signed long" => CType::I64,
        "unsigned long" | "uint64_t" | "size_t" | "uintptr_t" => CType::U64,
        "float" => CType::F32,
        "double" => CType::F64,
        "bool" | "_Bool" => CType::Bool,
        other => CType::Named(other.to_string()),
    };

    if stars > 0 {
        CType::Ptr(Box::new(base_ty), stars)
    } else {
        base_ty
    }
}
