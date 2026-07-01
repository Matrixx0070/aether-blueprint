//! AetherCode cross-language ABI checker.
//!
//! Validates that C headers and Rust FFI bindings agree on:
//!   - struct field names, ordering, and types
//!   - function return types and parameter types
//!
//! ## Quick start
//!
//! ```rust
//! use aether_abi::{check_abi, AbiCheckConfig};
//!
//! let c_header = r#"
//! typedef struct { int32_t x; int32_t y; } Point;
//! void move_point(Point* p, int32_t dx, int32_t dy);
//! "#;
//!
//! let rust_ffi = r#"
//! #[repr(C)]
//! pub struct Point { pub x: i32, pub y: i32 }
//! extern "C" { pub fn move_point(p: *mut Point, dx: i32, dy: i32); }
//! "#;
//!
//! let report = check_abi(c_header, rust_ffi, &AbiCheckConfig::default());
//! assert!(report.mismatches.is_empty(), "ABI mismatch: {:?}", report.mismatches);
//! ```

pub mod c_parser;
pub mod rust_parser;
pub mod types;

pub use types::{CField, CFunction, CParam, CStruct, CType};

use serde::{Deserialize, Serialize};

/// Severity of an ABI mismatch.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    /// Likely causes undefined behaviour at runtime.
    Critical,
    /// May work on some platforms but is not portable.
    High,
    /// Name mismatch only — same type family.
    Low,
}

/// A single ABI incompatibility finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiMismatch {
    pub severity: Severity,
    pub entity: String,
    pub field_or_param: Option<String>,
    pub c_type: String,
    pub rust_type: String,
    pub description: String,
}

impl std::fmt::Display for AbiMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{:?}] {} {} C={} Rust={}: {}",
            self.severity,
            self.entity,
            self.field_or_param.as_deref().unwrap_or(""),
            self.c_type,
            self.rust_type,
            self.description,
        )
    }
}

/// Configuration for ABI checking.
#[derive(Debug, Clone, Default)]
pub struct AbiCheckConfig {
    /// If true, only report Critical findings.
    pub critical_only: bool,
    /// If true, warn when a C struct has no matching Rust struct.
    pub warn_unmatched: bool,
}

/// Full ABI check report.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AbiReport {
    pub mismatches: Vec<AbiMismatch>,
    pub checked_structs: usize,
    pub checked_functions: usize,
    pub unmatched_c_structs: Vec<String>,
    pub unmatched_c_functions: Vec<String>,
}

impl AbiReport {
    pub fn is_clean(&self) -> bool {
        self.mismatches.is_empty()
    }

    pub fn critical_count(&self) -> usize {
        self.mismatches
            .iter()
            .filter(|m| m.severity == Severity::Critical)
            .count()
    }

    pub fn summary(&self) -> String {
        format!(
            "structs={} fns={} mismatches={} critical={}",
            self.checked_structs,
            self.checked_functions,
            self.mismatches.len(),
            self.critical_count(),
        )
    }
}

/// Check ABI compatibility between a C header and a Rust FFI source.
pub fn check_abi(c_header: &str, rust_source: &str, config: &AbiCheckConfig) -> AbiReport {
    let mut report = AbiReport::default();

    let c_structs = c_parser::parse_structs(c_header);
    let rust_structs = rust_parser::parse_repr_c_structs(rust_source);
    let c_funcs = c_parser::parse_functions(c_header);
    let rust_funcs = rust_parser::parse_extern_fns(rust_source);

    // ── Check structs ────────────────────────────────────────────────────────
    for cs in &c_structs {
        let rs = rust_structs.iter().find(|s| s.name == cs.name);
        match rs {
            None => {
                report.unmatched_c_structs.push(cs.name.clone());
            }
            Some(rs) => {
                report.checked_structs += 1;
                check_struct(cs, rs, &mut report.mismatches, config);
            }
        }
    }

    // ── Check functions ──────────────────────────────────────────────────────
    for cf in &c_funcs {
        let rf = rust_funcs.iter().find(|f| f.name == cf.name);
        match rf {
            None => {
                report.unmatched_c_functions.push(cf.name.clone());
            }
            Some(rf) => {
                report.checked_functions += 1;
                check_function(cf, rf, &mut report.mismatches, config);
            }
        }
    }

    report
}

fn check_struct(
    c: &CStruct,
    r: &CStruct,
    mismatches: &mut Vec<AbiMismatch>,
    config: &AbiCheckConfig,
) {
    // Field count mismatch
    if c.fields.len() != r.fields.len() {
        mismatches.push(AbiMismatch {
            severity: Severity::Critical,
            entity: c.name.clone(),
            field_or_param: None,
            c_type: format!("{} fields", c.fields.len()),
            rust_type: format!("{} fields", r.fields.len()),
            description: "struct field count differs — memory layout will be wrong".into(),
        });
        return;
    }
    for (i, (cf, rf)) in c.fields.iter().zip(r.fields.iter()).enumerate() {
        // Field order matters for repr(C)
        if cf.name != rf.name {
            if !config.critical_only {
                mismatches.push(AbiMismatch {
                    severity: Severity::Low,
                    entity: c.name.clone(),
                    field_or_param: Some(format!("field[{i}]")),
                    c_type: cf.name.clone(),
                    rust_type: rf.name.clone(),
                    description: "field names differ (types may still align)".into(),
                });
            }
        }
        if !cf.ty.abi_compatible(&rf.ty) {
            mismatches.push(AbiMismatch {
                severity: Severity::Critical,
                entity: c.name.clone(),
                field_or_param: Some(cf.name.clone()),
                c_type: cf.ty.to_string(),
                rust_type: rf.ty.to_string(),
                description: "field types are not ABI-compatible".into(),
            });
        }
    }
}

fn check_function(
    c: &CFunction,
    r: &CFunction,
    mismatches: &mut Vec<AbiMismatch>,
    config: &AbiCheckConfig,
) {
    // Return type
    if !c.return_type.abi_compatible(&r.return_type) {
        mismatches.push(AbiMismatch {
            severity: Severity::Critical,
            entity: c.name.clone(),
            field_or_param: Some("return".into()),
            c_type: c.return_type.to_string(),
            rust_type: r.return_type.to_string(),
            description: "return type mismatch — calling convention broken".into(),
        });
    }
    // Param count
    if c.params.len() != r.params.len() {
        mismatches.push(AbiMismatch {
            severity: Severity::Critical,
            entity: c.name.clone(),
            field_or_param: None,
            c_type: format!("{} params", c.params.len()),
            rust_type: format!("{} params", r.params.len()),
            description: "parameter count differs".into(),
        });
        return;
    }
    for (cp, rp) in c.params.iter().zip(r.params.iter()) {
        if !cp.ty.abi_compatible(&rp.ty) {
            mismatches.push(AbiMismatch {
                severity: Severity::Critical,
                entity: c.name.clone(),
                field_or_param: Some(cp.name.clone()),
                c_type: cp.ty.to_string(),
                rust_type: rp.ty.to_string(),
                description: "parameter type mismatch".into(),
            });
        }
        if cp.name != rp.name && !config.critical_only {
            mismatches.push(AbiMismatch {
                severity: Severity::Low,
                entity: c.name.clone(),
                field_or_param: Some(cp.name.clone()),
                c_type: cp.name.clone(),
                rust_type: rp.name.clone(),
                description: "parameter names differ (non-critical for ABI)".into(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const C_POINT: &str = r#"
typedef struct { int32_t x; int32_t y; } Point;
void move_point(Point* p, int32_t dx, int32_t dy);
"#;

    const RUST_POINT_OK: &str = r#"
#[repr(C)]
pub struct Point { pub x: i32, pub y: i32 }
extern "C" { pub fn move_point(p: *mut Point, dx: i32, dy: i32); }
"#;

    const RUST_POINT_BAD: &str = r#"
#[repr(C)]
pub struct Point { pub x: f32, pub y: i32 }
extern "C" { pub fn move_point(p: *mut Point, dx: i32, dy: i32); }
"#;

    #[test]
    fn clean_abi_passes() {
        let report = check_abi(C_POINT, RUST_POINT_OK, &AbiCheckConfig::default());
        assert!(
            report.mismatches.is_empty(),
            "expected no mismatches, got: {:?}",
            report.mismatches
        );
        assert_eq!(report.checked_structs, 1);
    }

    #[test]
    fn field_type_mismatch_detected() {
        let report = check_abi(C_POINT, RUST_POINT_BAD, &AbiCheckConfig::default());
        let crits: Vec<_> = report
            .mismatches
            .iter()
            .filter(|m| m.severity == Severity::Critical)
            .collect();
        assert!(!crits.is_empty(), "expected critical mismatch for x:f32 vs i32");
    }

    #[test]
    fn field_count_mismatch_critical() {
        let c = r#"typedef struct { int32_t x; int32_t y; int32_t z; } Vec3;"#;
        let r = r#"#[repr(C)] pub struct Vec3 { pub x: i32, pub y: i32 }"#;
        let report = check_abi(c, r, &AbiCheckConfig::default());
        assert!(
            report
                .mismatches
                .iter()
                .any(|m| m.severity == Severity::Critical),
            "expected critical for field count mismatch"
        );
    }

    #[test]
    fn function_return_type_mismatch() {
        let c = r#"int32_t compute(int32_t a, int32_t b);"#;
        let r = r#"extern "C" { pub fn compute(a: i32, b: i32) -> f64; }"#;
        let report = check_abi(c, r, &AbiCheckConfig::default());
        assert!(
            report
                .mismatches
                .iter()
                .any(|m| m.field_or_param.as_deref() == Some("return")),
            "expected return type mismatch"
        );
    }

    #[test]
    fn param_count_mismatch_critical() {
        let c = r#"void foo(int32_t a, int32_t b);"#;
        let r = r#"extern "C" { pub fn foo(a: i32); }"#;
        let report = check_abi(c, r, &AbiCheckConfig::default());
        assert!(report.mismatches.iter().any(|m| m.severity == Severity::Critical));
    }

    #[test]
    fn c_type_abi_compatible_symmetry() {
        assert!(CType::I32.abi_compatible(&CType::I32));
        assert!(!CType::I32.abi_compatible(&CType::U32));
        assert!(!CType::F32.abi_compatible(&CType::F64));
    }

    #[test]
    fn ptr_depth_mismatch_not_compatible() {
        let c_ptr = CType::Ptr(Box::new(CType::I32), 1);
        let c_pptr = CType::Ptr(Box::new(CType::I32), 2);
        assert!(!c_ptr.abi_compatible(&c_pptr));
    }

    #[test]
    fn c_parser_extracts_struct() {
        let structs = c_parser::parse_structs(C_POINT);
        assert_eq!(structs.len(), 1);
        assert_eq!(structs[0].name, "Point");
        assert_eq!(structs[0].fields.len(), 2);
    }

    #[test]
    fn rust_parser_extracts_repr_c_struct() {
        let structs = rust_parser::parse_repr_c_structs(RUST_POINT_OK);
        assert_eq!(structs.len(), 1);
        assert_eq!(structs[0].name, "Point");
        assert_eq!(structs[0].fields.len(), 2);
    }

    #[test]
    fn report_summary_format() {
        let report = check_abi(C_POINT, RUST_POINT_OK, &AbiCheckConfig::default());
        let s = report.summary();
        assert!(s.contains("structs=1"), "got: {s}");
    }
}
