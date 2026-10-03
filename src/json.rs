//! A very small JSON writer.
//!
//! No `serde`: the output of this tool is a handful of objects with known shapes,
//! and a dependency that runs elevated and does nothing but print is not worth
//! its supply chain. The escaping (the only part that can be wrong in a way that
//! matters) is unit-tested.

#[derive(Debug, Clone, PartialEq)]
pub enum J {
    Null,
    Bool(bool),
    Num(i64),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

impl J {
    pub fn str(s: impl Into<String>) -> J {
        J::Str(s.into())
    }

    pub fn num(n: i64) -> J {
        J::Num(n)
    }

    pub fn bool(b: bool) -> J {
        J::Bool(b)
    }

    /// `null` when absent - never an empty string, so consumers can tell
    /// "not readable" from "read as empty".
    pub fn opt_str(s: Option<impl Into<String>>) -> J {
        match s {
            Some(v) => J::Str(v.into()),
            None => J::Null,
        }
    }

    pub fn opt_num(n: Option<i64>) -> J {
        match n {
            Some(v) => J::Num(v),
            None => J::Null,
        }
    }

    pub fn strings<I, S>(items: I) -> J
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        J::Arr(items.into_iter().map(|s| J::Str(s.into())).collect())
    }

    pub fn obj(pairs: Vec<(&str, J)>) -> J {
        J::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    pub fn push(&mut self, key: &str, value: J) {
        if let J::Obj(pairs) = self {
            pairs.push((key.to_string(), value));
        }
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        self.write(&mut out, 0);
        out
    }

    fn write(&self, out: &mut String, indent: usize) {
        match self {
            J::Null => out.push_str("null"),
            J::Bool(true) => out.push_str("true"),
            J::Bool(false) => out.push_str("false"),
            J::Num(n) => out.push_str(&n.to_string()),
            J::Str(s) => escape_into(out, s),
            J::Arr(items) => {
                if items.is_empty() {
                    out.push_str("[]");
                    return;
                }
                out.push_str("[\n");
                for (i, item) in items.iter().enumerate() {
                    pad(out, indent + 1);
                    item.write(out, indent + 1);
                    if i + 1 < items.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                pad(out, indent);
                out.push(']');
            }
            J::Obj(pairs) => {
                if pairs.is_empty() {
                    out.push_str("{}");
                    return;
                }
                out.push_str("{\n");
                for (i, (k, v)) in pairs.iter().enumerate() {
                    pad(out, indent + 1);
                    escape_into(out, k);
                    out.push_str(": ");
                    v.write(out, indent + 1);
                    if i + 1 < pairs.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                pad(out, indent);
                out.push('}');
            }
        }
    }
}

fn pad(out: &mut String, indent: usize) {
    for _ in 0..indent {
        out.push_str("  ");
    }
}

/// JSON string escaping, per RFC 8259. Non-ASCII is emitted as UTF-8 rather
/// than `\u` escapes, which is legal and keeps ECIDs and paths readable.
pub fn escape_into(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_quotes_backslashes_and_control_characters() {
        let mut s = String::new();
        escape_into(&mut s, "a\"b\\c\nd\te\u{1}f");
        assert_eq!(s, "\"a\\\"b\\\\c\\nd\\te\\u0001f\"");
    }

    #[test]
    fn windows_paths_survive_round_trip_shape() {
        let mut s = String::new();
        escape_into(&mut s, r"C:\Windows\INF\oem46.inf");
        assert_eq!(s, r#""C:\\Windows\\INF\\oem46.inf""#);
    }

    #[test]
    fn non_ascii_is_preserved_as_utf8() {
        let mut s = String::new();
        escape_into(&mut s, "Apple Mobile Device (DFU Mode) \u{b0}");
        assert!(s.contains('\u{b0}'));
        assert!(!s.contains("\\u"));
    }

    #[test]
    fn renders_nested_objects_and_arrays() {
        let v = J::obj(vec![
            ("ok", J::bool(true)),
            ("n", J::num(7)),
            ("missing", J::Null),
            ("list", J::strings(["a", "b"])),
            (
                "inner",
                J::obj(vec![("k", J::str("v"))]),
            ),
        ]);
        let text = v.render();
        assert!(text.starts_with("{\n"));
        assert!(text.contains("\"ok\": true"));
        assert!(text.contains("\"missing\": null"));
        assert!(text.contains("\"n\": 7"));
        assert!(text.contains("\"a\",\n"));
        assert!(text.contains("\"k\": \"v\""));
        assert_eq!(text.matches('{').count(), text.matches('}').count());
        assert_eq!(text.matches('[').count(), text.matches(']').count());
    }

    #[test]
    fn empty_collections_render_compactly() {
        assert_eq!(J::Arr(vec![]).render(), "[]");
        assert_eq!(J::Obj(vec![]).render(), "{}");
        assert_eq!(J::strings(Vec::<String>::new()).render(), "[]");
    }

    #[test]
    fn opt_helpers_distinguish_absent_from_empty() {
        assert_eq!(J::opt_str(None::<String>).render(), "null");
        assert_eq!(J::opt_str(Some("")).render(), "\"\"");
        assert_eq!(J::opt_num(None).render(), "null");
        assert_eq!(J::opt_num(Some(0)).render(), "0");
    }

    #[test]
    fn push_appends_to_an_object() {
        let mut o = J::obj(vec![("a", J::num(1))]);
        o.push("b", J::str("two"));
        let text = o.render();
        assert!(text.contains("\"a\": 1"));
        assert!(text.contains("\"b\": \"two\""));
        assert!(text.find("\"a\"").unwrap() < text.find("\"b\"").unwrap());
    }
}
