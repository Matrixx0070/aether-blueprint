//! AetherCode symbolic constraint solver — backward slicing and path
//! condition enumeration over control-flow graphs.
//!
//! ## Architecture
//!
//! ```text
//! Source code
//!      │
//!      ▼
//!  [Cfg builder]  ─────────────────────────────────────────────────
//!      │                                                            │
//!      ▼                                                            ▼
//!  cfg::Cfg ──► slice::backward_slice() ──► SliceResult      expr::Expr
//!                       │                       │         (path conditions)
//!                       ▼                       ▼
//!               SlicePath (per path)    slice::format_path()
//! ```
//!
//! ## Typical usage
//!
//! ```
//! use aether_symexec::{Cfg, BasicBlock, Instr, SliceConfig, backward_slice};
//! use aether_symexec::expr::{Expr, CmpRel};
//!
//! let mut cfg = Cfg::default();
//! let mut entry = BasicBlock::new(0, "entry");
//! entry.push(Instr::source("x", Expr::App { func: "env::var".into(), args: vec![Expr::Sym("KEY".into())] }));
//! cfg.add_block(entry);
//! let mut sink_block = BasicBlock::new(1, "sink");
//! sink_block.push(Instr::sink("write(x)"));
//! cfg.add_block(sink_block);
//! cfg.add_edge(0, 1, None);
//!
//! let res = backward_slice(&cfg, 1, &SliceConfig::default());
//! assert_eq!(res.paths.len(), 1);
//! assert!(res.paths[0].from_source);
//! ```

pub mod cfg;
pub mod expr;
pub mod slice;

pub use cfg::{BasicBlock, BlockId, Cfg, CfgEdge, Instr};
pub use expr::{ArithOp, CmpRel, Expr};
pub use slice::{
    backward_slice, format_path, format_path_instrs, SliceConfig, SlicePath, SliceResult,
};

/// Convenience: compute backward slices for ALL sink blocks in a CFG and
/// return the combined results.
pub fn slice_all_sinks(cfg: &Cfg, config: &SliceConfig) -> Vec<SliceResult> {
    cfg.sink_blocks()
        .into_iter()
        .map(|sink| backward_slice(cfg, sink, config))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use expr::{CmpRel, Expr};

    fn simple_cfg() -> Cfg {
        // entry ──(x > 0)──► check ──► sink
        //        ◄──(x <= 0)──┘
        let mut cfg = Cfg::default();

        let mut entry = BasicBlock::new(0, "entry");
        entry.push(Instr::source(
            "x",
            Expr::App {
                func: "env::var".into(),
                args: vec![Expr::Sym("KEY".into())],
            },
        ));
        cfg.add_block(entry);

        let mut check = BasicBlock::new(1, "check");
        check.push(Instr::stmt("if x > 0"));
        cfg.add_block(check);

        let mut sink_b = BasicBlock::new(2, "sink");
        sink_b.push(Instr::sink("write(x)"));
        cfg.add_block(sink_b);

        cfg.add_edge(
            0,
            1,
            None,
        );
        cfg.add_edge(
            1,
            2,
            Some(Expr::Cmp {
                rel: CmpRel::Gt,
                left: Box::new(Expr::Sym("x".into())),
                right: Box::new(Expr::Int(0)),
            }),
        );
        cfg.entry = 0;
        cfg
    }

    #[test]
    fn backward_slice_finds_source_path() {
        let cfg = simple_cfg();
        let res = backward_slice(&cfg, 2, &SliceConfig::default());
        assert!(!res.paths.is_empty(), "expected at least one path");
        let src_path = res.paths.iter().find(|p| p.from_source);
        assert!(src_path.is_some(), "expected a source-originating path");
    }

    #[test]
    fn path_condition_captures_branch() {
        let cfg = simple_cfg();
        let res = backward_slice(&cfg, 2, &SliceConfig::default());
        let path = &res.paths[0];
        let pc_str = path.path_condition.to_string();
        assert!(
            pc_str.contains("x") || pc_str == "true",
            "unexpected pc: {pc_str}"
        );
    }

    #[test]
    fn sources_only_config_filters() {
        let cfg = simple_cfg();
        let cfg2 = {
            // CFG with no source blocks
            let mut c = Cfg::default();
            let mut b0 = BasicBlock::new(0, "plain");
            b0.push(Instr::stmt("x = 5"));
            c.add_block(b0);
            let mut b1 = BasicBlock::new(1, "sink");
            b1.push(Instr::sink("write(x)"));
            c.add_block(b1);
            c.add_edge(0, 1, None);
            c.entry = 0;
            c
        };
        let res = backward_slice(
            &cfg2,
            1,
            &SliceConfig {
                sources_only: true,
                ..Default::default()
            },
        );
        // No source blocks → sources_only should yield no paths
        assert!(res.paths.is_empty(), "expected no paths from non-source entry");
    }

    #[test]
    fn expr_simplify_constant_fold() {
        let e = Expr::BinOp {
            op: ArithOp::Add,
            left: Box::new(Expr::Int(3)),
            right: Box::new(Expr::Int(4)),
        };
        assert_eq!(e.simplify(), Expr::Int(7));
    }

    #[test]
    fn expr_simplify_and_false_short_circuits() {
        let e = Expr::And(vec![Expr::Bool(false), Expr::Sym("x".into())]);
        assert_eq!(e.simplify(), Expr::Bool(false));
    }

    #[test]
    fn expr_free_vars_collected() {
        let e = Expr::And(vec![
            Expr::Cmp {
                rel: CmpRel::Gt,
                left: Box::new(Expr::Sym("x".into())),
                right: Box::new(Expr::Int(0)),
            },
            Expr::Sym("y".into()),
        ]);
        let vars = e.free_vars();
        assert!(vars.contains(&"x".to_string()));
        assert!(vars.contains(&"y".to_string()));
    }

    #[test]
    fn slice_all_sinks_covers_both_sinks() {
        let mut cfg = Cfg::default();
        let mut b0 = BasicBlock::new(0, "entry");
        b0.push(Instr::source(
            "data",
            Expr::App {
                func: "stdin".into(),
                args: vec![],
            },
        ));
        cfg.add_block(b0);
        let mut b1 = BasicBlock::new(1, "sink1");
        b1.push(Instr::sink("exec(data)"));
        cfg.add_block(b1);
        let mut b2 = BasicBlock::new(2, "sink2");
        b2.push(Instr::sink("log(data)"));
        cfg.add_block(b2);
        cfg.add_edge(0, 1, None);
        cfg.add_edge(0, 2, None);
        cfg.entry = 0;

        let results = slice_all_sinks(&cfg, &SliceConfig::default());
        assert_eq!(results.len(), 2, "expected one result per sink");
        assert!(results.iter().all(|r| !r.paths.is_empty()));
    }
}
