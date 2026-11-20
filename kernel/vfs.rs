//! The root mount is the authenticated newc archive. All processes start at /.
use core::str;

pub const PATH_MAX: usize = 128;
pub enum Node { Directory, Regular(&'static [u8]) }
struct Initramfs(&'static [u8]);
pub struct Vfs { root: Initramfs }

impl Initramfs {
    fn lookup(&self, path: &[u8]) -> Result<Node, isize> {
        let mut rest = self.0;
        while rest.get(..6) == Some(b"070701") {
            let field = |at| -> Option<usize> {
                usize::from_str_radix(str::from_utf8(rest.get(at..at+8)?).ok()?, 16).ok()
            };
            let names_end = 110usize.checked_add(field(94).ok_or(-5isize)?).ok_or(-5isize)?;
            let name = rest.get(110..names_end).and_then(|n| n.strip_suffix(&[0])).ok_or(-5isize)?;
            if name == b"TRAILER!!!" { return Err(-2); }
            let start = names_end.checked_add(3).ok_or(-5isize)? & !3;
            let end = start.checked_add(field(54).ok_or(-5isize)?).ok_or(-5isize)?;
            let data = rest.get(start..end).ok_or(-5isize)?;
            if name.strip_prefix(b"./").unwrap_or(name) == path {
                return match field(14).ok_or(-5isize)? & 0o170000 {
                    0o100000 => Ok(Node::Regular(data)),
                    0o040000 => Ok(Node::Directory),
                    _ => Err(-95),
                };
            }
            rest = rest.get((end.checked_add(3).ok_or(-5isize)? & !3)..).ok_or(-5isize)?;
        }
        Err(-5)
    }
}

impl Vfs {
    pub fn new(archive: &'static [u8]) -> Self { Self { root: Initramfs(archive) } }

    pub fn file(&self, path: &[u8]) -> Result<&'static [u8], isize> {
        if path.is_empty() { return Err(-2); }
        if path.len() > PATH_MAX { return Err(-36); }
        if path.contains(&0) { return Err(-22); }
        let mut key = [0; PATH_MAX];
        let mut used = 0;
        let mut node = Node::Directory;
        for part in path.split(|&c| c == b'/') {
            if !matches!(node, Node::Directory) { return Err(-20); }
            match part {
                b"" | b"." => (),
                b".." => { used = key[..used].iter().rposition(|&b| b == b'/').unwrap_or(0); }
                _ => {
                    if used != 0 { key[used] = b'/'; used += 1; }
                    key[used..used+part.len()].copy_from_slice(part);
                    used += part.len();
                    node = self.root.lookup(&key[..used])?;
                }
            }
        }
        match node { Node::Regular(data) => Ok(data), Node::Directory => Err(-21) }
    }
}
