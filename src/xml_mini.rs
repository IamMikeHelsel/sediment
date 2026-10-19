// SPDX-License-Identifier: MIT OR Apache-2.0
//! Minimal, bounded XML parser for archive tables of contents (xar).
//!
//! Spec source: W3C XML 1.0 (Fifth Edition): elements, attributes (single
//! or double quoted), character data, CDATA sections, comments, processing
//! instructions, the predefined entities (`&amp; &lt; &gt; &quot; &apos;`)
//! and character references (`&#N;`, `&#xH;`). A DOCTYPE without an
//! internal subset is skipped; an internal subset (`[`) is rejected, so no
//! user-defined entities are ever expanded. Namespaces are not interpreted
//! (prefixes stay part of the name).
//!
//! The document is held as an arena of [`XmlNode`]s; node count, nesting
//! depth and input size are limited by [`XmlLimits`].

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XmlError {
    Syntax,
    UnknownEntity,
    Mismatch,
    Unsupported,
    LimitExceeded,
    Allocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XmlLimits {
    pub max_nodes: usize,
    pub max_depth: usize,
    pub max_input: usize,
}

impl Default for XmlLimits {
    fn default() -> Self {
        XmlLimits { max_nodes: 1 << 20, max_depth: 256, max_input: 64 << 20 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct XmlNode {
    pub name: String,
    pub attrs: Vec<(String, String)>,
    /// Concatenated character data directly inside this element.
    pub text: String,
    pub children: Vec<usize>,
}

impl XmlNode {
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
}

/// Parsed document; node 0 is the root element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmlDoc {
    pub nodes: Vec<XmlNode>,
}

impl XmlDoc {
    pub fn root(&self) -> &XmlNode {
        &self.nodes[0]
    }

    pub fn node(&self, i: usize) -> &XmlNode {
        &self.nodes[i]
    }

    /// Indices of the direct children of `parent` named `name`.
    pub fn children_named<'s>(&'s self, parent: usize, name: &'s str) -> impl Iterator<Item = usize> + 's {
        self.nodes[parent].children.iter().copied().filter(move |&c| self.nodes[c].name == name)
    }

    /// First direct child of `parent` named `name`.
    pub fn child(&self, parent: usize, name: &str) -> Option<usize> {
        self.children_named(parent, name).next()
    }

    /// Text of the first direct child named `name`.
    pub fn child_text(&self, parent: usize, name: &str) -> Option<&str> {
        self.child(parent, name).map(|c| self.nodes[c].text.as_str())
    }
}

fn is_name_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.' | b':') || c >= 0x80
}

fn is_ws(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\r' | b'\n')
}

struct P<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> P<'a> {
    fn starts(&self, pat: &[u8]) -> bool {
        self.s.get(self.i..).is_some_and(|r| r.starts_with(pat))
    }
    fn skip_ws(&mut self) {
        while self.i < self.s.len() && is_ws(self.s[self.i]) {
            self.i += 1;
        }
    }
    /// Advance past the next occurrence of `pat`; returns the skipped text.
    fn until(&mut self, pat: &[u8]) -> Result<&'a [u8], XmlError> {
        let rest = &self.s[self.i..];
        let k = rest.windows(pat.len()).position(|w| w == pat).ok_or(XmlError::Syntax)?;
        self.i += k + pat.len();
        Ok(&rest[..k])
    }
    fn name(&mut self) -> Result<&'a str, XmlError> {
        let st = self.i;
        while self.i < self.s.len() && is_name_char(self.s[self.i]) {
            self.i += 1;
        }
        if st == self.i || self.s[st].is_ascii_digit() || matches!(self.s[st], b'-' | b'.') {
            return Err(XmlError::Syntax);
        }
        std::str::from_utf8(&self.s[st..self.i]).map_err(|_| XmlError::Syntax)
    }
}

fn push_str(out: &mut String, s: &str) -> Result<(), XmlError> {
    out.try_reserve(s.len()).map_err(|_| XmlError::Allocation)?;
    out.push_str(s);
    Ok(())
}

/// Append `raw` to `out`, decoding entity and character references.
fn decode_into(out: &mut String, raw: &[u8]) -> Result<(), XmlError> {
    let s = std::str::from_utf8(raw).map_err(|_| XmlError::Syntax)?;
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        push_str(out, &rest[..amp])?;
        let after = &rest[amp + 1..];
        let semi = after.find(';').ok_or(XmlError::Syntax)?;
        let ent = &after[..semi];
        let ch = match ent {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            _ => {
                let code = if let Some(h) = ent.strip_prefix("#x") {
                    u32::from_str_radix(h, 16).map_err(|_| XmlError::Syntax)?
                } else if let Some(d) = ent.strip_prefix('#') {
                    d.parse::<u32>().map_err(|_| XmlError::Syntax)?
                } else {
                    return Err(XmlError::UnknownEntity);
                };
                if code == 0 {
                    return Err(XmlError::Syntax);
                }
                char::from_u32(code).ok_or(XmlError::Syntax)?
            }
        };
        out.try_reserve(4).map_err(|_| XmlError::Allocation)?;
        out.push(ch);
        rest = &after[semi + 1..];
    }
    push_str(out, rest)
}

/// Parse a complete document with exactly one root element.
pub fn parse_xml(input: &[u8], limits: &XmlLimits) -> Result<XmlDoc, XmlError> {
    if input.len() > limits.max_input {
        return Err(XmlError::LimitExceeded);
    }
    let mut p = P { s: input, i: 0 };
    if p.starts(b"\xEF\xBB\xBF") {
        p.i = 3;
    }
    let mut nodes: Vec<XmlNode> = Vec::new();
    let mut stack: Vec<usize> = Vec::new();
    let mut root_done = false;
    while p.i < input.len() {
        if p.starts(b"<?") {
            p.i += 2;
            p.until(b"?>")?;
        } else if p.starts(b"<!--") {
            p.i += 4;
            p.until(b"-->")?;
        } else if p.starts(b"<![CDATA[") {
            p.i += 9;
            let raw = p.until(b"]]>")?;
            let &top = stack.last().ok_or(XmlError::Syntax)?;
            let s = std::str::from_utf8(raw).map_err(|_| XmlError::Syntax)?;
            push_str(&mut nodes[top].text, s)?;
        } else if p.starts(b"<!DOCTYPE") {
            if !nodes.is_empty() {
                return Err(XmlError::Syntax);
            }
            let raw = p.until(b">")?;
            if raw.contains(&b'[') {
                return Err(XmlError::Unsupported);
            }
        } else if p.starts(b"</") {
            p.i += 2;
            let name = p.name()?;
            p.skip_ws();
            if !p.starts(b">") {
                return Err(XmlError::Syntax);
            }
            p.i += 1;
            let top = stack.pop().ok_or(XmlError::Mismatch)?;
            if nodes[top].name != name {
                return Err(XmlError::Mismatch);
            }
            if stack.is_empty() {
                root_done = true;
            }
        } else if p.starts(b"<") {
            p.i += 1;
            if root_done {
                return Err(XmlError::Syntax);
            }
            if nodes.len() >= limits.max_nodes || stack.len() >= limits.max_depth {
                return Err(XmlError::LimitExceeded);
            }
            let mut node = XmlNode { name: p.name()?.to_owned(), ..XmlNode::default() };
            let self_closing = loop {
                let before = p.i;
                p.skip_ws();
                if p.starts(b"/>") {
                    p.i += 2;
                    break true;
                }
                if p.starts(b">") {
                    p.i += 1;
                    break false;
                }
                if p.i == before {
                    return Err(XmlError::Syntax);
                }
                let k = p.name()?.to_owned();
                p.skip_ws();
                if !p.starts(b"=") {
                    return Err(XmlError::Syntax);
                }
                p.i += 1;
                p.skip_ws();
                let q = *input.get(p.i).ok_or(XmlError::Syntax)?;
                if q != b'"' && q != b'\'' {
                    return Err(XmlError::Syntax);
                }
                p.i += 1;
                let raw = p.until(&[q])?;
                if raw.contains(&b'<') {
                    return Err(XmlError::Syntax);
                }
                let mut v = String::new();
                decode_into(&mut v, raw)?;
                if node.attrs.iter().any(|(a, _)| *a == k) {
                    return Err(XmlError::Syntax);
                }
                node.attrs.try_reserve(1).map_err(|_| XmlError::Allocation)?;
                node.attrs.push((k, v));
            };
            let id = nodes.len();
            nodes.try_reserve(1).map_err(|_| XmlError::Allocation)?;
            nodes.push(node);
            if let Some(&parent) = stack.last() {
                nodes[parent].children.try_reserve(1).map_err(|_| XmlError::Allocation)?;
                nodes[parent].children.push(id);
            }
            if self_closing {
                if stack.is_empty() {
                    root_done = true;
                }
            } else {
                stack.try_reserve(1).map_err(|_| XmlError::Allocation)?;
                stack.push(id);
            }
        } else {
            let st = p.i;
            while p.i < input.len() && input[p.i] != b'<' {
                p.i += 1;
            }
            let raw = &input[st..p.i];
            match stack.last() {
                Some(&top) => decode_into(&mut nodes[top].text, raw)?,
                None if raw.iter().all(|&c| is_ws(c)) => {}
                None => return Err(XmlError::Syntax),
            }
        }
    }
    if !stack.is_empty() || !root_done {
        return Err(XmlError::Syntax);
    }
    Ok(XmlDoc { nodes })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basics() {
        let d = parse_xml(b"<?xml version=\"1.0\"?>\n<!-- c --><a x='1' y=\"&lt;&#65;\"><b>t&amp;u</b><c/><![CDATA[<z>]]></a>\n", &XmlLimits::default()).unwrap();
        assert_eq!(d.root().name, "a");
        assert_eq!(d.root().attr("y"), Some("<A"));
        assert_eq!(d.child_text(0, "b"), Some("t&u"));
        assert!(d.child(0, "c").is_some());
        assert!(d.root().text.contains("<z>"));
        for bad in [&b"<a>"[..], b"<a></b>", b"<a/><b/>", b"<a>&foo;</a>", b"x<a/>", b"<!DOCTYPE a [<!ENTITY e 'x'>]><a/>", b"<a x=1/>", b""] {
            assert!(parse_xml(bad, &XmlLimits::default()).is_err(), "{:?}", String::from_utf8_lossy(bad));
        }
        let deep = "<a>".repeat(300) + &"</a>".repeat(300);
        assert_eq!(parse_xml(deep.as_bytes(), &XmlLimits::default()), Err(XmlError::LimitExceeded));
    }
}
