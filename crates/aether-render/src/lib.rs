//! Output renderer.
//!
//! Skeleton: a `Renderer` trait + a no-op `PlainRenderer` for headless mode.
//! Real ANSI / ratatui implementations sit behind feature flags so the
//! library compiles on every host without a TTY dependency.

pub trait Renderer: Send {
    fn write_text(&mut self, s: &str);
    fn write_diff(&mut self, before: &str, after: &str);
    fn flush(&mut self);
}

#[derive(Default)]
pub struct PlainRenderer {
    pub buf: String,
}

impl Renderer for PlainRenderer {
    fn write_text(&mut self, s: &str) {
        self.buf.push_str(s);
    }
    fn write_diff(&mut self, before: &str, after: &str) {
        for line in before.lines() {
            self.buf.push_str("- ");
            self.buf.push_str(line);
            self.buf.push('\n');
        }
        for line in after.lines() {
            self.buf.push_str("+ ");
            self.buf.push_str(line);
            self.buf.push('\n');
        }
    }
    fn flush(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_renderer_accumulates_text() {
        let mut r = PlainRenderer::default();
        r.write_text("hello ");
        r.write_text("world");
        r.flush();
        assert_eq!(r.buf, "hello world");
    }

    #[test]
    fn plain_renderer_diffs_with_prefixes() {
        let mut r = PlainRenderer::default();
        r.write_diff("a\nb", "a\nc");
        assert!(r.buf.contains("- a\n- b\n+ a\n+ c\n"));
    }
}
