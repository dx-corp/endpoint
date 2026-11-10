//! A pickle opcode walker adapted from protectai/modelscan (Apache-2.0,
//! <https://github.com/protectai/modelscan>, `modelscan/settings.py`). It
//! reads the opcode stream of a pickle without unpickling it and reports
//! whether any import (GLOBAL, INST or STACK_GLOBAL) names a module or
//! function on modelscan's unsafe list. PyTorch zip checkpoints are read
//! through their stored `data.pkl`; legacy PyTorch files stop after their five
//! pickles, before the raw tensor bytes.
//!
//! The walker only claims `Clean` when it resolved every import. A string it
//! cannot decode the way Python would (an escape, a non-ASCII byte), a memo
//! index it cannot parse exactly, or an extension-registry import makes the
//! file `Unparsed`, never `Clean`.

use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::os::unix::fs::FileExt;

/// At most this many bytes of one file are read.
pub(super) const MAX_FILE_BYTES: u64 = 64 << 20;
/// A raw pickle is first walked from this many bytes; only a pickle that runs
/// past them is read again up to `MAX_FILE_BYTES`.
const FIRST_READ_BYTES: u64 = 1 << 20;
/// At most this many opcodes are walked per file.
pub(super) const MAX_OPS: usize = 1 << 22;
/// Longer strings are never module or function names; they are not kept.
const MAX_NAME_BYTES: usize = 256;
/// At most this many `data.pkl` entries are read from one zip.
const MAX_ZIP_PICKLES: usize = 8;
/// A zip central directory larger than this is not read.
const MAX_CENTRAL_DIRECTORY_BYTES: u64 = 16 << 20;

/// modelscan's CRITICAL and HIGH unsafe globals, (module, function or "*"),
/// plus the Python 2 module names pickle maps onto them (`cPickle` ->
/// `pickle`, `commands` -> `subprocess`, via `_compat_pickle`).
const UNSAFE_GLOBALS: &[(&str, &str)] = &[
    ("__builtin__", "eval"),
    ("__builtin__", "compile"),
    ("__builtin__", "getattr"),
    ("__builtin__", "apply"),
    ("__builtin__", "exec"),
    ("__builtin__", "open"),
    ("__builtin__", "breakpoint"),
    ("__builtin__", "__import__"),
    ("builtins", "eval"),
    ("builtins", "compile"),
    ("builtins", "getattr"),
    ("builtins", "apply"),
    ("builtins", "exec"),
    ("builtins", "open"),
    ("builtins", "breakpoint"),
    ("builtins", "__import__"),
    ("runpy", "*"),
    ("os", "*"),
    ("nt", "*"),
    ("posix", "*"),
    ("socket", "*"),
    ("subprocess", "*"),
    ("sys", "*"),
    ("operator", "attrgetter"),
    ("pty", "*"),
    ("pickle", "*"),
    ("_pickle", "*"),
    ("bdb", "*"),
    ("pdb", "*"),
    ("shutil", "*"),
    ("asyncio", "*"),
    ("webbrowser", "*"),
    ("httplib", "*"),
    ("requests.api", "*"),
    ("aiohttp.client", "*"),
    ("cPickle", "*"),
    ("commands", "*"),
];

/// The first pickle of a legacy (pre-zip) PyTorch file: protocol 2, the
/// LONG1 magic number 0x1950a86a20f9469cfc6c, STOP. `torch.load` then reads
/// four more pickles (protocol, system info, the object, storage keys)
/// followed by raw tensor bytes.
const TORCH_LEGACY_MAGIC: &[u8] = &[
    0x80, 0x02, 0x8a, 0x0a, 0x6c, 0xfc, 0x9c, 0x46, 0xf9, 0x20, 0x6a, 0xa8, 0x50, 0x19, b'.',
];
const TORCH_LEGACY_PICKLES: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Verdict {
    /// Every import was resolved and none is on the unsafe list.
    Clean,
    /// An import names an unsafe module or function.
    Unsafe,
    /// The pickle could not be walked or an import could not be resolved;
    /// nothing is claimed about it.
    Unparsed,
}

/// Why a walk of one pickle stopped early.
#[derive(Debug, PartialEq, Eq)]
enum Halt {
    Unsafe,
    /// An import whose module or name could not be resolved exactly.
    Unresolved,
    /// Bytes that are not a pickle opcode stream.
    Invalid,
    /// The bytes ended inside the pickle.
    Exhausted,
    /// More than `MAX_OPS` opcodes.
    OpCap,
}

/// A module or function name exactly as Python would decode it, or `None`
/// when that cannot be told without running Python's decoder.
type Name = Option<Box<str>>;

fn is_unsafe(module: &str, name: &str) -> bool {
    let listed = |module: &str, name: &str| {
        UNSAFE_GLOBALS.iter().any(|(m, f)| {
            (module == *m
                || module
                    .strip_prefix(m)
                    .is_some_and(|rest| rest.starts_with('.')))
                && (*f == "*" || *f == name)
        })
    };
    if listed(module, name) {
        return true;
    }
    // Protocol 4 resolves a dotted name attribute by attribute, so
    // `torch.serialization` + `os.system` reaches `os.system`. Any part of a
    // dotted name that is a listed module or function counts.
    name.contains('.')
        && name.split('.').any(|part| {
            UNSAFE_GLOBALS
                .iter()
                .any(|(m, f)| m.split('.').next() == Some(part) || (*f != "*" && *f == part))
        })
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Halt> {
        let end = self.at.checked_add(n).ok_or(Halt::Exhausted)?;
        let slice = self.bytes.get(self.at..end).ok_or(Halt::Exhausted)?;
        self.at = end;
        Ok(slice)
    }

    fn byte(&mut self) -> Result<u8, Halt> {
        Ok(self.take(1)?[0])
    }

    fn le(&mut self, n: usize) -> Result<u64, Halt> {
        let raw = self.take(n)?;
        Ok(raw
            .iter()
            .rev()
            .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte)))
    }

    /// A newline-terminated argument, without the newline.
    fn line(&mut self) -> Result<&'a [u8], Halt> {
        let rest = &self.bytes[self.at..];
        let end = rest
            .iter()
            .position(|byte| *byte == b'\n')
            .ok_or(Halt::Exhausted)?;
        self.at += end + 1;
        Ok(&rest[..end])
    }

    /// A length-prefixed argument; the length is `width` little-endian bytes.
    fn counted(&mut self, width: usize) -> Result<&'a [u8], Halt> {
        let len = usize::try_from(self.le(width)?).map_err(|_| Halt::Exhausted)?;
        self.take(len)
    }
}

/// UTF-8 text short enough to be a name (BINUNICODE and friends).
fn utf8_name(raw: &[u8]) -> Name {
    (raw.len() <= MAX_NAME_BYTES)
        .then(|| std::str::from_utf8(raw).ok().map(Box::from))
        .flatten()
}

/// Plain ASCII text with no escape, the only form of STRING, UNICODE and
/// BINSTRING arguments whose decoded value is the bytes themselves.
fn ascii_name(raw: &[u8]) -> Name {
    (raw.len() <= MAX_NAME_BYTES && raw.iter().all(|b| b.is_ascii() && *b != b'\\'))
        .then(|| std::str::from_utf8(raw).ok().map(Box::from))
        .flatten()
}

/// A text memo index (PUT, GET): only plain decimal digits are accepted, so
/// the index is exactly the one Python's `int()` computes.
fn memo_index(raw: &[u8]) -> Result<u64, Halt> {
    if raw.is_empty() || raw.len() > 19 || !raw.iter().all(u8::is_ascii_digit) {
        return Err(Halt::Unresolved);
    }
    std::str::from_utf8(raw)
        .ok()
        .and_then(|text| text.parse().ok())
        .ok_or(Halt::Unresolved)
}

fn check_import(module: &str, name: &str) -> Result<(), Halt> {
    if is_unsafe(module, name) {
        Err(Halt::Unsafe)
    } else {
        Ok(())
    }
}

/// Walks one pickle from the cursor to its STOP opcode.
///
/// `recent` holds what each stack-changing opcode pushed, a name when it
/// pushed a resolvable string and `None` otherwise. STACK_GLOBAL reads its
/// two operands from it: both are names only when the two opcodes before it
/// each pushed a string with nothing popped in between, which is exactly
/// when those strings are the top of Python's stack.
fn walk_one(cursor: &mut Cursor<'_>, ops: &mut usize) -> Result<(), Halt> {
    let mut recent: VecDeque<Name> = VecDeque::new();
    let mut memo: HashMap<u64, Name> = HashMap::new();
    loop {
        *ops += 1;
        if *ops > MAX_OPS {
            return Err(Halt::OpCap);
        }
        let op = cursor.byte()?;
        let pushed: Name = match op {
            b'.' => return Ok(()),
            // Opcodes with no argument.
            b'(' | b'0' | b'1' | b'2' | b'Q' | b'R' | b'a' | b'b' | b'd' | b'}' | b'e' | b'l'
            | b']' | b'o' | b's' | b't' | b')' | b'u' | b'N' | 0x81 | 0x85 | 0x86 | 0x87 | 0x88
            | 0x89 | 0x8f | 0x90 | 0x91 | 0x92 | 0x97 | 0x98 => None,
            // FLOAT, INT, LONG, PERSID: a text line.
            b'F' | b'I' | b'L' | b'P' => {
                cursor.line()?;
                None
            }
            // STRING: a quoted repr, unescaped by Python.
            b'S' => {
                let raw = cursor.line()?;
                let quoted = raw.len() >= 2
                    && raw[0] == raw[raw.len() - 1]
                    && matches!(raw[0], b'\'' | b'"');
                if !quoted {
                    return Err(Halt::Invalid);
                }
                ascii_name(&raw[1..raw.len() - 1])
            }
            // UNICODE: raw-unicode-escape text.
            b'V' => ascii_name(cursor.line()?),
            b'J' => {
                cursor.take(4)?;
                None
            }
            b'K' => {
                cursor.take(1)?;
                None
            }
            b'M' => {
                cursor.take(2)?;
                None
            }
            b'G' => {
                cursor.take(8)?;
                None
            }
            // LONG1, LONG4, BINBYTES, SHORT_BINBYTES, BINBYTES8, BYTEARRAY8.
            0x8a | b'C' => {
                cursor.counted(1)?;
                None
            }
            0x8b | b'B' => {
                cursor.counted(4)?;
                None
            }
            0x8e | 0x96 => {
                cursor.counted(8)?;
                None
            }
            // BINSTRING, SHORT_BINSTRING: decoded with the unpickler's
            // encoding, ASCII by default.
            b'T' => ascii_name(cursor.counted(4)?),
            b'U' => ascii_name(cursor.counted(1)?),
            // BINUNICODE, SHORT_BINUNICODE, BINUNICODE8.
            b'X' => utf8_name(cursor.counted(4)?),
            0x8c => utf8_name(cursor.counted(1)?),
            0x8d => utf8_name(cursor.counted(8)?),
            // PROTO and FRAME change nothing on the stack.
            0x80 => {
                cursor.take(1)?;
                continue;
            }
            0x95 => {
                cursor.take(8)?;
                continue;
            }
            // PUT, BINPUT, LONG_BINPUT, MEMOIZE: memo writes of the top.
            b'p' => {
                let index = memo_index(cursor.line()?)?;
                memo.insert(index, recent.back().cloned().flatten());
                continue;
            }
            b'q' => {
                let index = cursor.le(1)?;
                memo.insert(index, recent.back().cloned().flatten());
                continue;
            }
            b'r' => {
                let index = cursor.le(4)?;
                memo.insert(index, recent.back().cloned().flatten());
                continue;
            }
            0x94 => {
                let index = memo.len() as u64;
                memo.insert(index, recent.back().cloned().flatten());
                continue;
            }
            // GET, BINGET, LONG_BINGET.
            b'g' => {
                let index = memo_index(cursor.line()?)?;
                memo.get(&index).cloned().flatten()
            }
            b'h' => {
                let index = cursor.le(1)?;
                memo.get(&index).cloned().flatten()
            }
            b'j' => {
                let index = cursor.le(4)?;
                memo.get(&index).cloned().flatten()
            }
            // GLOBAL and INST: module and name on two lines.
            b'c' | b'i' => {
                let module = std::str::from_utf8(cursor.line()?).map_err(|_| Halt::Unresolved)?;
                let name = std::str::from_utf8(cursor.line()?).map_err(|_| Halt::Unresolved)?;
                check_import(module, name)?;
                None
            }
            // STACK_GLOBAL: module and name from the stack.
            0x93 => {
                let name = recent.pop_back().flatten();
                let module = recent.pop_back().flatten();
                let (Some(module), Some(name)) = (module, name) else {
                    return Err(Halt::Unresolved);
                };
                check_import(&module, &name)?;
                None
            }
            // EXT1, EXT2, EXT4 import through copyreg's extension registry,
            // which this walker cannot see.
            0x82..=0x84 => return Err(Halt::Unresolved),
            _ => return Err(Halt::Invalid),
        };
        recent.push_back(pushed);
        if recent.len() > 64 {
            recent.pop_front();
        }
    }
}

/// Walks the pickles in `bytes`. `truncated` says the file goes on past
/// `bytes`. `None` means the walk needs bytes past the end of a truncated
/// read.
///
/// A file may hold several pickles in a row; each is walked in turn, as
/// modelscan does. Bytes after the last pickle that do not form one (the
/// tensor data after a legacy PyTorch file's pickles, anything a loader never
/// reads) end the walk. A legacy PyTorch file stops after its five pickles.
fn scan_bytes(bytes: &[u8], truncated: bool) -> Option<Verdict> {
    let limit = if bytes.starts_with(TORCH_LEGACY_MAGIC) {
        TORCH_LEGACY_PICKLES
    } else {
        usize::MAX
    };
    let mut cursor = Cursor { bytes, at: 0 };
    let mut ops = 0;
    let mut walked = 0;
    loop {
        if walked == limit {
            return Some(Verdict::Clean);
        }
        if cursor.at == bytes.len() {
            if truncated {
                return None;
            }
            return Some(if walked > 0 {
                Verdict::Clean
            } else {
                Verdict::Unparsed
            });
        }
        match walk_one(&mut cursor, &mut ops) {
            Ok(()) => walked += 1,
            Err(Halt::Unsafe) => return Some(Verdict::Unsafe),
            Err(Halt::Unresolved | Halt::OpCap) => return Some(Verdict::Unparsed),
            // Trailing bytes that are not a pickle: nothing past them loads.
            Err(Halt::Invalid) if walked > 0 => return Some(Verdict::Clean),
            Err(Halt::Exhausted) if truncated => return None,
            Err(Halt::Exhausted) if walked > 0 => return Some(Verdict::Clean),
            Err(Halt::Invalid | Halt::Exhausted) => return Some(Verdict::Unparsed),
        }
    }
}

fn read_at(file: &File, offset: u64, len: u64) -> Option<Vec<u8>> {
    let mut bytes = vec![0; usize::try_from(len).ok()?];
    file.read_exact_at(&mut bytes, offset).ok()?;
    Some(bytes)
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u64> {
    let raw = bytes.get(at..at.checked_add(2)?)?;
    Some(u64::from(u16::from_le_bytes([raw[0], raw[1]])))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u64> {
    let raw = bytes.get(at..at.checked_add(4)?)?;
    Some(u64::from(u32::from_le_bytes([
        raw[0], raw[1], raw[2], raw[3],
    ])))
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    let raw = bytes.get(at..at.checked_add(8)?)?;
    let mut word = [0; 8];
    word.copy_from_slice(raw);
    Some(u64::from_le_bytes(word))
}

/// One `data.pkl` a zip's central directory names.
#[derive(Debug, PartialEq, Eq)]
struct ZipPickle {
    method: u64,
    size: u64,
    local_header: u64,
}

/// The `data.pkl` entries of a zip, from its central directory (the one
/// PyTorch's reader uses). `Err` when the zip cannot be read; an empty list
/// when it holds no `data.pkl` (not a PyTorch checkpoint).
fn zip_pickles(file: &File, size: u64) -> Result<Vec<ZipPickle>, ()> {
    const EOCD: &[u8] = b"PK\x05\x06";
    let tail_len = size.min(22 + 0xffff);
    let tail = read_at(file, size - tail_len, tail_len).ok_or(())?;
    let at = tail
        .windows(4)
        .rposition(|window| window == EOCD)
        .filter(|at| at + 22 <= tail.len())
        .ok_or(())?;
    let eocd_offset = size - tail_len + at as u64;
    let mut entries = u16_at(&tail, at + 10).ok_or(())?;
    let mut cd_size = u32_at(&tail, at + 12).ok_or(())?;
    let mut cd_offset = u32_at(&tail, at + 16).ok_or(())?;
    if entries == 0xffff || cd_size == 0xffff_ffff || cd_offset == 0xffff_ffff {
        // Zip64: the locator sits just before the end record.
        let locator = read_at(file, eocd_offset.checked_sub(20).ok_or(())?, 20).ok_or(())?;
        if &locator[..4] != b"PK\x06\x07" {
            return Err(());
        }
        let record = read_at(file, u64_at(&locator, 8).ok_or(())?, 56).ok_or(())?;
        if &record[..4] != b"PK\x06\x06" {
            return Err(());
        }
        entries = u64_at(&record, 32).ok_or(())?;
        cd_size = u64_at(&record, 40).ok_or(())?;
        cd_offset = u64_at(&record, 48).ok_or(())?;
    }
    if cd_size > MAX_CENTRAL_DIRECTORY_BYTES || cd_offset.checked_add(cd_size).ok_or(())? > size {
        return Err(());
    }
    let directory = read_at(file, cd_offset, cd_size).ok_or(())?;
    let mut pickles = Vec::new();
    let mut at = 0usize;
    for _ in 0..entries {
        if directory.get(at..at + 4) != Some(b"PK\x01\x02".as_slice()) {
            return Err(());
        }
        let method = u16_at(&directory, at + 10).ok_or(())?;
        let mut compressed = u32_at(&directory, at + 20).ok_or(())?;
        let mut uncompressed = u32_at(&directory, at + 24).ok_or(())?;
        let name_len = u16_at(&directory, at + 28).ok_or(())? as usize;
        let extra_len = u16_at(&directory, at + 30).ok_or(())? as usize;
        let comment_len = u16_at(&directory, at + 32).ok_or(())? as usize;
        let mut local_header = u32_at(&directory, at + 42).ok_or(())?;
        let name_at = at + 46;
        let name = directory.get(name_at..name_at + name_len).ok_or(())?;
        let extra = directory
            .get(name_at + name_len..name_at + name_len + extra_len)
            .ok_or(())?;
        at = name_at + name_len + extra_len + comment_len;
        if name != b"data.pkl" && !name.ends_with(b"/data.pkl") {
            continue;
        }
        // Zip64 extra field: the 64-bit values of the fields set to ~0, in
        // order.
        let mut field = 0usize;
        while let (Some(id), Some(len)) = (u16_at(extra, field), u16_at(extra, field + 2)) {
            let body = extra.get(field + 4..field + 4 + len as usize).ok_or(())?;
            if id == 1 {
                let mut next = 0;
                for value in [&mut uncompressed, &mut compressed, &mut local_header] {
                    if *value == 0xffff_ffff {
                        *value = u64_at(body, next).ok_or(())?;
                        next += 8;
                    }
                }
            }
            field += 4 + len as usize;
        }
        if pickles.len() == MAX_ZIP_PICKLES {
            return Err(());
        }
        pickles.push(ZipPickle {
            method,
            size: if method == 0 {
                compressed
            } else {
                uncompressed
            },
            local_header,
        });
    }
    Ok(pickles)
}

/// The verdict for a stored `data.pkl`.
fn scan_zip_pickle(file: &File, size: u64, pickle: &ZipPickle) -> Verdict {
    if pickle.method != 0 || pickle.size > MAX_FILE_BYTES {
        return Verdict::Unparsed;
    }
    let Some(header) = read_at(file, pickle.local_header, 30) else {
        return Verdict::Unparsed;
    };
    let (Some(name_len), Some(extra_len)) = (u16_at(&header, 26), u16_at(&header, 28)) else {
        return Verdict::Unparsed;
    };
    let start = pickle.local_header + 30 + name_len + extra_len;
    if &header[..4] != b"PK\x03\x04" || start.saturating_add(pickle.size) > size {
        return Verdict::Unparsed;
    }
    read_at(file, start, pickle.size)
        .and_then(|bytes| scan_bytes(&bytes, false))
        .unwrap_or(Verdict::Unparsed)
}

/// The verdict for one open regular file of `size` bytes, or `None` when it
/// is not a pickle: neither a raw pickle (protocol 2 to 5 header) nor a zip
/// holding a `data.pkl`.
pub(super) fn scan_file(file: &File, size: u64) -> Option<Verdict> {
    let mut head = [0u8; 4];
    file.read_exact_at(&mut head, 0).ok()?;
    if head[0] == 0x80 && (2..=5).contains(&head[1]) {
        for cap in [FIRST_READ_BYTES, MAX_FILE_BYTES] {
            let Some(bytes) = read_at(file, 0, size.min(cap)) else {
                return Some(Verdict::Unparsed);
            };
            if let Some(verdict) = scan_bytes(&bytes, size > cap) {
                return Some(verdict);
            }
        }
        return Some(Verdict::Unparsed);
    }
    if &head == b"PK\x03\x04" {
        let Ok(pickles) = zip_pickles(file, size) else {
            return Some(Verdict::Unparsed);
        };
        let mut verdict = None;
        for pickle in &pickles {
            match scan_zip_pickle(file, size, pickle) {
                Verdict::Unsafe => return Some(Verdict::Unsafe),
                Verdict::Unparsed => verdict = Some(Verdict::Unparsed),
                Verdict::Clean => {
                    verdict.get_or_insert(Verdict::Clean);
                }
            }
        }
        return verdict;
    }
    None
}

#[cfg(test)]
pub(super) mod fixtures {
    //! Hand-assembled pickles, so the tests need no Python. Each mirrors what
    //! `pickle.dumps` writes for the protocol named.

    /// Protocol 2: `GLOBAL module\nname\n`, an empty tuple, REDUCE, STOP.
    pub fn global_call(protocol: u8, module: &str, name: &str) -> Vec<u8> {
        let mut out = vec![0x80, protocol, b'c'];
        out.extend_from_slice(module.as_bytes());
        out.push(b'\n');
        out.extend_from_slice(name.as_bytes());
        out.push(b'\n');
        out.extend_from_slice(b")R.");
        out
    }

    /// Protocol 4/5: FRAME, SHORT_BINUNICODE module, MEMOIZE,
    /// SHORT_BINUNICODE name, MEMOIZE, STACK_GLOBAL, MEMOIZE, a
    /// SHORT_BINUNICODE argument, TUPLE1, REDUCE, STOP.
    pub fn stack_global_call(protocol: u8, module: &str, name: &str) -> Vec<u8> {
        let mut body = Vec::new();
        for text in [module, name] {
            body.push(0x8c);
            body.push(text.len() as u8);
            body.extend_from_slice(text.as_bytes());
            body.push(0x94);
        }
        body.extend_from_slice(&[0x93, 0x94, 0x8c, 0x02]);
        body.extend_from_slice(b"id");
        body.extend_from_slice(&[0x85, b'R', b'.']);
        let mut out = vec![0x80, protocol, 0x95];
        out.extend_from_slice(&(body.len() as u64).to_le_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// Protocol 2 dict `{"weight": 1}` with a memo PUT: no import at all.
    pub fn plain_dict(protocol: u8) -> Vec<u8> {
        let mut out = vec![0x80, protocol, b'}', b'q', 0x00, b'X', 6, 0, 0, 0];
        out.extend_from_slice(b"weight");
        out.extend_from_slice(&[b'q', 0x01, b'K', 0x01, b's', b'.']);
        out
    }

    /// What a PyTorch checkpoint's `data.pkl` looks like: an
    /// `collections.OrderedDict` rebuilt through `torch._utils`, with a
    /// persistent id for the storage.
    pub fn torch_state_dict() -> Vec<u8> {
        let mut out = vec![0x80, 0x02];
        out.extend_from_slice(b"ccollections\nOrderedDict\nq\x00)Rq\x01");
        out.extend_from_slice(b"X\x06\x00\x00\x00weightq\x02");
        out.extend_from_slice(b"ctorch._utils\n_rebuild_tensor_v2\nq\x03(");
        out.extend_from_slice(b"(X\x07\x00\x00\x00storageq\x04ctorch\nFloatStorage\nq\x05");
        out.extend_from_slice(b"X\x01\x00\x00\x000q\x06X\x03\x00\x00\x00cpuq\x07K\x04tq\x08Q");
        out.extend_from_slice(
            b"K\x00K\x04\x85K\x01\x85\x89ccollections\nOrderedDict\nq\x09)Rq\x0a",
        );
        out.extend_from_slice(b"tq\x0bRq\x0cs.");
        out
    }

    /// A stored (uncompressed) zip with the given entries, as
    /// `torch.save` writes it.
    pub fn zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut directory = Vec::new();
        for (name, body) in entries {
            let offset = out.len() as u32;
            let size = body.len() as u32;
            out.extend_from_slice(b"PK\x03\x04");
            out.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&[0, 0]);
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(body);
            directory.extend_from_slice(b"PK\x01\x02");
            directory.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            directory.extend_from_slice(&size.to_le_bytes());
            directory.extend_from_slice(&size.to_le_bytes());
            directory.extend_from_slice(&(name.len() as u16).to_le_bytes());
            directory.extend_from_slice(&[0; 12]);
            directory.extend_from_slice(&offset.to_le_bytes());
            directory.extend_from_slice(name.as_bytes());
        }
        let cd_offset = out.len() as u32;
        out.extend_from_slice(&directory);
        out.extend_from_slice(b"PK\x05\x06\0\0\0\0");
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(directory.len() as u32).to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    fn scan(bytes: &[u8]) -> Verdict {
        scan_bytes(bytes, false).expect("not truncated")
    }

    #[test]
    fn global_imports_of_unsafe_functions_are_unsafe_in_every_protocol() {
        for protocol in 2..=5 {
            assert_eq!(
                scan(&global_call(protocol, "os", "system")),
                Verdict::Unsafe
            );
            assert_eq!(
                scan(&global_call(protocol, "posix", "system")),
                Verdict::Unsafe
            );
            assert_eq!(
                scan(&global_call(protocol, "__builtin__", "eval")),
                Verdict::Unsafe
            );
            assert_eq!(
                scan(&global_call(protocol, "subprocess", "Popen")),
                Verdict::Unsafe
            );
            assert_eq!(
                scan(&global_call(protocol, "cPickle", "loads")),
                Verdict::Unsafe
            );
            assert_eq!(
                scan(&global_call(protocol, "collections", "OrderedDict")),
                Verdict::Clean
            );
            assert_eq!(
                scan(&global_call(protocol, "builtins", "set")),
                Verdict::Clean
            );
        }
    }

    #[test]
    fn python_pickle_dumps_of_an_os_system_reduce_is_unsafe() {
        // pickle.dumps(R(), protocol=2) and protocol=4, where R.__reduce__
        // returns (os.system, ("id",)), from CPython 3 on Linux.
        let protocol2 = b"\x80\x02cposix\nsystem\nq\x00X\x02\x00\x00\x00idq\x01\x85q\x02Rq\x03.";
        let protocol4 = b"\x80\x04\x95\x1d\x00\x00\x00\x00\x00\x00\x00\x8c\x05posix\x94\x8c\x06system\x94\x93\x94\x8c\x02id\x94\x85\x94R\x94.";
        assert_eq!(scan(protocol2), Verdict::Unsafe);
        assert_eq!(scan(protocol4), Verdict::Unsafe);
    }

    #[test]
    fn stack_global_imports_of_unsafe_functions_are_unsafe() {
        for protocol in 4..=5 {
            assert_eq!(
                scan(&stack_global_call(protocol, "os", "system")),
                Verdict::Unsafe
            );
            assert_eq!(
                scan(&stack_global_call(protocol, "builtins", "exec")),
                Verdict::Unsafe
            );
            assert_eq!(
                scan(&stack_global_call(protocol, "requests.api", "get")),
                Verdict::Unsafe
            );
            assert_eq!(
                scan(&stack_global_call(
                    protocol,
                    "torch.serialization",
                    "os.system"
                )),
                Verdict::Unsafe,
                "a dotted name reaches os through an attribute"
            );
            assert_eq!(
                scan(&stack_global_call(protocol, "collections", "OrderedDict")),
                Verdict::Clean
            );
        }
    }

    #[test]
    fn imports_through_the_memo_resolve_and_unresolvable_ones_are_never_clean() {
        // SHORT_BINUNICODE "os", BINPUT 0, POP, SHORT_BINUNICODE "x", POP,
        // BINGET 0, SHORT_BINUNICODE "system", STACK_GLOBAL.
        let memo = b"\x80\x04\x8c\x02osq\x000\x8c\x01x0h\x00\x8c\x06system\x93)R.";
        assert_eq!(scan(memo), Verdict::Unsafe);
        // A POP between module and name: the operands are not both known.
        let popped = b"\x80\x04\x8c\x02os\x8c\x04junk0\x8c\x06system\x93)R.";
        assert_eq!(scan(popped), Verdict::Unparsed);
        // STRING with an escape spells "os" only after Python unescapes it.
        let escaped = b"\x80\x02S'o\\x73'\nS'system'\n\x93)R.";
        assert_eq!(scan(escaped), Verdict::Unparsed);
        // A memo index Python's int() reads differently ("1_0" is 10).
        let underscored = b"\x80\x02S'os'\np1_0\n.";
        assert_eq!(scan(underscored), Verdict::Unparsed);
        // An extension-registry import.
        assert_eq!(scan(b"\x80\x02\x82\x01)R."), Verdict::Unparsed);
        // Text STRING operands with no escape resolve.
        assert_eq!(
            scan(b"\x80\x02S'os'\nS\"system\"\n\x93)R."),
            Verdict::Unsafe
        );
    }

    #[test]
    fn benign_pickles_and_torch_state_dicts_are_clean() {
        for protocol in 2..=5 {
            assert_eq!(scan(&plain_dict(protocol)), Verdict::Clean);
        }
        assert_eq!(scan(&torch_state_dict()), Verdict::Clean);
    }

    #[test]
    fn truncated_and_invalid_pickles_are_unparsed() {
        let whole = global_call(2, "collections", "OrderedDict");
        assert_eq!(scan(&whole[..whole.len() - 1]), Verdict::Unparsed);
        assert_eq!(scan(&whole[..5]), Verdict::Unparsed);
        assert_eq!(scan(b"\x80\x02\xff."), Verdict::Unparsed);
        // A truncated read asks for more bytes instead of guessing.
        assert_eq!(scan_bytes(&whole[..whole.len() - 1], true), None);
    }

    #[test]
    fn trailing_bytes_after_a_pickle_are_ignored_but_a_later_pickle_is_walked() {
        let mut trailing = plain_dict(2);
        trailing.extend_from_slice(&[0xe8, 0x03, 0, 0, 0, 0, 0, 0, 0xde, 0xad]);
        assert_eq!(scan(&trailing), Verdict::Clean);
        let mut second = plain_dict(2);
        second.extend_from_slice(&global_call(2, "os", "system"));
        assert_eq!(scan(&second), Verdict::Unsafe);
    }

    #[test]
    fn legacy_torch_files_stop_after_five_pickles() {
        let mut legacy = TORCH_LEGACY_MAGIC.to_vec();
        for _ in 0..3 {
            legacy.extend_from_slice(&plain_dict(2));
        }
        legacy.extend_from_slice(&torch_state_dict());
        // Raw tensor bytes that happen to spell an unsafe GLOBAL are data,
        // never loaded as a pickle.
        legacy.extend_from_slice(&global_call(2, "os", "system"));
        assert_eq!(scan(&legacy), Verdict::Clean);
        // A malicious object pickle inside the five is found.
        let mut malicious = TORCH_LEGACY_MAGIC.to_vec();
        malicious.extend_from_slice(&plain_dict(2));
        malicious.extend_from_slice(&global_call(2, "os", "system"));
        assert_eq!(scan(&malicious), Verdict::Unsafe);
    }

    #[test]
    fn the_opcode_cap_makes_a_pickle_unparsed() {
        let mut long = vec![0x80, 0x02];
        long.extend(vec![b'N'; MAX_OPS + 1]);
        long.push(b'.');
        assert_eq!(scan(&long), Verdict::Unparsed);
    }

    #[test]
    fn only_listed_imports_count_and_lookalikes_do_not() {
        assert!(is_unsafe("os.path", "join"));
        assert!(!is_unsafe("osmosis", "system"));
        assert!(!is_unsafe("operator", "add"));
        assert!(is_unsafe("operator", "attrgetter"));
        assert!(!is_unsafe("torch.nn.modules", "Linear"));
    }

    fn temp_file(name: &str, bytes: &[u8]) -> (std::path::PathBuf, File) {
        let path =
            std::env::temp_dir().join(format!("merlin-pickle-{name}-{}", std::process::id()));
        std::fs::write(&path, bytes).unwrap();
        let file = File::open(&path).unwrap();
        (path, file)
    }

    #[test]
    fn zip_checkpoints_are_read_through_their_stored_data_pkl() {
        let cases: [(&str, Vec<u8>, Option<Verdict>); 5] = [
            (
                "zip-clean",
                zip(&[
                    ("archive/data.pkl", &torch_state_dict()),
                    ("archive/data/0", b"\0\0\x80?"),
                ]),
                Some(Verdict::Clean),
            ),
            (
                "zip-unsafe",
                zip(&[("archive/data.pkl", &stack_global_call(4, "os", "system"))]),
                Some(Verdict::Unsafe),
            ),
            ("zip-other", zip(&[("weights.npy", b"\x93NUMPY")]), None),
            (
                "zip-truncated",
                {
                    let whole = zip(&[("archive/data.pkl", &torch_state_dict())]);
                    whole[..whole.len() - 10].to_vec()
                },
                Some(Verdict::Unparsed),
            ),
            (
                "zip-cut-pickle",
                {
                    let pickle = torch_state_dict();
                    zip(&[("archive/data.pkl", &pickle[..pickle.len() - 3])])
                },
                Some(Verdict::Unparsed),
            ),
        ];
        for (name, bytes, want) in cases {
            let (path, file) = temp_file(name, &bytes);
            assert_eq!(scan_file(&file, bytes.len() as u64), want, "{name}");
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn files_that_are_not_pickles_are_skipped() {
        for (name, bytes) in [
            ("gguf", b"GGUF\x03\0\0\0".as_slice()),
            ("protocol0", b"(lp0\n."),
            ("short", b"\x80"),
        ] {
            let (path, file) = temp_file(name, bytes);
            assert_eq!(scan_file(&file, bytes.len() as u64), None, "{name}");
            std::fs::remove_file(path).unwrap();
        }
    }
}
