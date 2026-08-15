//! Builds a parser on top of `cmd_registry`.
//!
//! Mechanically, it turns a raw user input into a `ResolvedCmdSpec`. This is
//! close to the format we use to actually process commands, but not quite.
//! Most importantly, while it identifies the command and its options, no logic
//! here is command-specific.

use std::collections::HashMap;
use std::fmt;
use std::ops::Range;
use std::str::FromStr;

use crate::cmd_registry::{
    Arg, ArgKind, Arity, Body, CmdSpec, Opt, OptType, Registry, Sigil, split_sigil,
};

//
// Errors
//

#[derive(Clone, Debug)]
pub enum ParseError {
    /// Doesn't look like a command at all. Caller should treat it as a prompt.
    NotACommand,
    UnknownCmd {
        sigil: Sigil,
        name: String,
        suggestion: Option<String>,
    },
    UnknownOption {
        spec: CmdSpec,
        got: String,
        suggestion: Option<String>,
    },
    OptionNeedsValue {
        spec: CmdSpec,
        opt: &'static Opt,
    },
    BadOptionValue {
        spec: CmdSpec,
        opt: &'static Opt,
        got: String,
    },
    MalformedOptions {
        spec: CmdSpec,
        got: String,
    },
    UnterminatedQuote,
    MissingArg {
        spec: CmdSpec,
        arg: Arg,
    },
    TooFewRepeated {
        spec: CmdSpec,
        arg: Arg,
        got: usize,
    },
    TooManyArgs {
        spec: CmdSpec,
        got: usize,
    },
    BadValue {
        spec: CmdSpec,
        arg: Arg,
        got: String,
        why: String,
    },
    UnknownSubcommand {
        spec: CmdSpec,
        got: String,
        choices: Vec<String>,
    },
    UnexpectedBody {
        spec: CmdSpec,
    },
    MissingBody {
        spec: CmdSpec,
    },
    BadPatch {
        spec: CmdSpec,
        why: &'static str,
    },
}

impl ParseError {
    pub fn spec(&self) -> Option<&CmdSpec> {
        use ParseError::*;
        match self {
            NotACommand | UnknownCmd { .. } | UnterminatedQuote => None,
            UnknownOption { spec, .. }
            | OptionNeedsValue { spec, .. }
            | BadOptionValue { spec, .. }
            | MalformedOptions { spec, .. }
            | MissingArg { spec, .. }
            | TooFewRepeated { spec, .. }
            | TooManyArgs { spec, .. }
            | BadValue { spec, .. }
            | UnknownSubcommand { spec, .. }
            | UnexpectedBody { spec }
            | MissingBody { spec }
            | BadPatch { spec, .. } => Some(spec),
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ParseError::*;
        match self {
            NotACommand => write!(f, "not a command")?,
            UnterminatedQuote => write!(f, "unterminated quote")?,
            UnknownCmd {
                sigil,
                name,
                suggestion,
            } => {
                write!(f, "unknown command {}{}", sigil.ch(), name)?;
                if let Some(s) = suggestion {
                    write!(f, " (did you mean {}{}?)", sigil.ch(), s)?;
                }
            }
            UnknownOption {
                spec,
                got,
                suggestion,
            } => {
                write!(f, "{}: unknown option .{}", spec.canonical(), got)?;
                if let Some(s) = suggestion {
                    write!(f, " (did you mean .{}?)", s)?;
                }
            }
            OptionNeedsValue { spec, opt } => write!(
                f,
                "{}: option .{} requires a value (.{}=<{}>)",
                spec.canonical(),
                opt.name,
                opt.name,
                opt.ty.label()
            )?,
            BadOptionValue { spec, opt, got } => {
                write!(
                    f,
                    "{}: bad value for .{}: {:?}",
                    spec.canonical(),
                    opt.name,
                    got
                )?;
                if let OptType::Enum(vals) = opt.ty {
                    write!(f, " (expected one of: {})", vals.join(", "))?;
                } else {
                    write!(f, " (expected {})", opt.ty.label())?;
                }
            }
            MalformedOptions { spec, got } => {
                write!(f, "{}: malformed options near {:?}", spec.canonical(), got)?
            }
            MissingArg { spec, arg } => {
                write!(f, "{}: missing required <{}>", spec.canonical(), arg.name)?
            }
            TooFewRepeated { spec, arg, got } => write!(
                f,
                "{}: expected at least one <{}>, got {}",
                spec.canonical(),
                arg.name,
                got
            )?,
            TooManyArgs { spec, got } => write!(
                f,
                "{}: too many arguments ({} given, at most {} expected)",
                spec.canonical(),
                got,
                spec.args.len()
            )?,
            BadValue {
                spec,
                arg,
                got,
                why,
            } => write!(
                f,
                "{}: bad <{}> {:?}: {}",
                spec.canonical(),
                arg.name,
                got,
                why
            )?,
            UnknownSubcommand { spec, got, choices } => write!(
                f,
                "{}: unknown subcommand {:?} (expected one of: {})",
                spec.canonical(),
                got,
                choices.join(", ")
            )?,
            UnexpectedBody { spec } => {
                write!(f, "{}: does not take a multi-line body", spec.canonical())?
            }
            MissingBody { spec } => write!(f, "{}: requires a multi-line body", spec.canonical())?,
            BadPatch { spec, why } => write!(f, "{}: {}", spec.canonical(), why)?,
        }
        if let Some(spec) = self.spec() {
            write!(f, "\nUsage: {}", spec.usage_canonical())?;
        }
        Ok(())
    }
}

impl std::error::Error for ParseError {}

//
// Option values
//

#[derive(Clone, Debug, PartialEq)]
pub enum OptVal {
    Bool(bool),
    Num(f64),
    Str(String),
    Enum(&'static str),
}

/// Typed options for one command. Absent options fall back to the registry
/// default, so callers never write `.unwrap_or(false)`.
#[derive(Clone, Debug)]
pub struct Opts {
    spec: CmdSpec,
    map: HashMap<&'static str, OptVal>,
}

impl Opts {
    fn declared(&self, name: &str) -> Option<&'static Opt> {
        let o = self.spec.find_opt(name);
        debug_assert!(
            o.is_some(),
            "{} has no option .{} — layer 3 and the registry disagree",
            self.spec.canonical(),
            name
        );
        o
    }

    #[allow(dead_code)]
    /// True if the user explicitly supplied the option (vs. inheriting a default).
    pub fn is_set(&self, name: &str) -> bool {
        self.map.contains_key(name)
    }

    pub fn bool(&self, name: &str) -> bool {
        match self.map.get(name) {
            Some(OptVal::Bool(b)) => *b,
            Some(_) => false,
            None => matches!(
                self.declared(name).and_then(|o| o.default),
                Some("true") | Some("1") | Some("on") | Some("yes")
            ),
        }
    }

    pub fn f64(&self, name: &str) -> Option<f64> {
        match self.map.get(name) {
            Some(OptVal::Num(n)) => Some(*n),
            _ => self
                .declared(name)
                .and_then(|o| o.default)
                .and_then(|d| d.parse().ok()),
        }
    }

    pub fn u32(&self, name: &str) -> Option<u32> {
        self.f64(name).and_then(|n| {
            if n >= 0.0 && n.fract() == 0.0 {
                Some(n as u32)
            } else {
                None
            }
        })
    }

    pub fn str(&self, name: &str) -> Option<&str> {
        match self.map.get(name) {
            Some(OptVal::Str(s)) => Some(s.as_str()),
            Some(OptVal::Enum(s)) => Some(s),
            _ => self.declared(name).and_then(|o| o.default),
        }
    }

    pub fn string(&self, name: &str) -> Option<String> {
        self.str(name).map(|s| s.to_string())
    }

    #[allow(dead_code)]
    pub fn enum_of(&self, name: &str) -> Option<&'static str> {
        match self.map.get(name) {
            Some(OptVal::Enum(s)) => Some(*s),
            _ => None,
        }
    }

    /// First explicitly-set option among `names`. For mutually-exclusive flag
    /// groups like the accent colors or the web-search time windows.
    pub fn first_set(&self, names: &[&'static str]) -> Option<&'static str> {
        names.iter().copied().find(|n| self.bool(n))
    }
}

//
// ResolvedCmdSpec
//

#[derive(Clone, Debug)]
pub struct Patch {
    pub search: String,
    pub replace: String,
    /// Length of the `=` run used as the delimiter
    #[allow(dead_code)]
    pub fence: usize,
}

#[derive(Clone, Debug)]
pub struct ResolvedCmdSpec {
    pub spec: CmdSpec,
    pub opts: Opts,
    /// Positionals in `spec.args` order. A trailing `Repeated` contributes
    /// multiple entries; a `Sub` contributes none (see `sub`).
    pub args: Vec<String>,
    /// Verbatim text after the command line's newline, for `Body::MultiLine`.
    pub body: Option<String>,
    /// Split body, for `Body::Patch`.
    pub patch: Option<Patch>,
    /// Resolved `ArgKind::Sub` table entry, e.g. `/std now`.
    pub sub: Option<Box<ResolvedCmdSpec>>,
}

/// Prefer the use of take() functions since these strings are ultimately owned
/// by `cmd.Cmd` structs.
impl ResolvedCmdSpec {
    #[allow(dead_code)]
    pub fn name(&self) -> &str {
        &self.spec.name
    }

    /// By value: `Arg` is `Copy`, so there's no reason to hand out a borrow
    /// that would pin `self` for the caller's benefit.
    fn arg_spec(&self, i: usize) -> Option<Arg> {
        self.spec.arg_at(i).map(|(_, a)| *a)
    }

    /// Positional `i`, or `""` if it was optional and omitted.
    pub fn arg(&self, i: usize) -> &str {
        self.args.get(i).map(|s| s.as_str()).unwrap_or("")
    }

    #[allow(dead_code)]
    pub fn opt_arg(&self, i: usize) -> Option<&str> {
        self.args
            .get(i)
            .map(|s| s.as_str())
            .filter(|s| !s.is_empty())
    }

    /// Move positional `i` out, leaving an empty string behind.
    pub fn take(&mut self, i: usize) -> String {
        match self.args.get_mut(i) {
            Some(s) => std::mem::take(s),
            None => String::new(),
        }
    }

    /// Move optional positional `i` out.
    ///
    /// We intentionally conflate "omitted" and "empty string" converting both
    /// to `None`.
    pub fn opt_take(&mut self, i: usize) -> Option<String> {
        match self.args.get_mut(i) {
            Some(s) if !s.is_empty() => Some(std::mem::take(s)),
            _ => None,
        }
    }

    /// All positionals from `i` onward.
    pub fn take_rest(&mut self, i: usize) -> Vec<String> {
        if i >= self.args.len() {
            Vec::new()
        } else {
            self.args.split_off(i)
        }
    }

    /// Parse positional `i` as a number.
    pub fn num<T: FromStr>(&self, i: usize) -> Result<Option<T>, ParseError> {
        let Some(raw) = self.args.get(i).filter(|s| !s.is_empty()) else {
            return Ok(None);
        };
        raw.parse::<T>()
            .map(Some)
            .map_err(|_| ParseError::BadValue {
                spec: self.spec.clone(),
                arg: self.arg_spec(i).unwrap_or(FALLBACK_ARG),
                got: raw.clone(),
                why: "expected a number".into(),
            })
    }

    #[allow(dead_code)]
    pub fn body_or_err(&self) -> Result<&str, ParseError> {
        self.body.as_deref().ok_or_else(|| ParseError::MissingBody {
            spec: self.spec.clone(),
        })
    }

    pub fn patch_or_err(&self) -> Result<&Patch, ParseError> {
        self.patch.as_ref().ok_or_else(|| ParseError::MissingBody {
            spec: self.spec.clone(),
        })
    }

    /// Attribute an arbitrary layer-3 coercion failure to a positional.
    pub fn bad_value(&self, i: usize, why: impl Into<String>) -> ParseError {
        ParseError::BadValue {
            spec: self.spec.clone(),
            arg: self.arg_spec(i).unwrap_or(FALLBACK_ARG),
            got: self.arg(i).to_string(),
            why: why.into(),
        }
    }
}

static FALLBACK_ARG: Arg = Arg {
    name: "arg",
    kind: ArgKind::Text,
    arity: Arity::Optional,
    doc: None,
};

//
// Entry points
//

/// Parse a full input string (sigil + command word + args + body).
pub fn parse(reg: &Registry, input: &str) -> Result<ResolvedCmdSpec, ParseError> {
    let (sigil, after_sigil) = split_sigil(input).ok_or(ParseError::NotACommand)?;
    let (name, consumed) = scan_name(after_sigil);
    if name.is_empty() {
        return Err(ParseError::NotACommand);
    }
    let spec = reg
        .lookup(sigil, name)
        .ok_or_else(|| ParseError::UnknownCmd {
            sigil,
            name: name.to_string(),
            suggestion: did_you_mean(reg, sigil, name).map(str::to_string),
        })?;
    parse_with_spec(spec, &after_sigil[consumed..])
}

/// Second-half of parsing an input: everything after the command word.
///
/// # Arguments
/// - `tail` is everything after the command word: dotted options, args, and
///   body.
pub fn parse_with_spec(spec: CmdSpec, tail: &str) -> Result<ResolvedCmdSpec, ParseError> {
    let (map, after_opts) = scan_options(&spec, tail)?;

    // Split the command line from any body.
    let (line, tail_after_nl) = match after_opts.find('\n') {
        Some(nl) => (&after_opts[..nl], Some(&after_opts[nl + 1..])),
        None => (after_opts, None),
    };

    let toks = tokenize(line)?;
    let (args, sub) = fill_args(&spec, after_opts, line, &toks)?;

    let has_rest = matches!(
        spec.args.last().map(|a| a.arity),
        Some(Arity::Rest | Arity::RestOpt)
    );
    let body_kind = spec.body;
    let (body, patch) = match body_kind {
        Body::None => {
            if !has_rest && tail_after_nl.map(|t| !t.trim().is_empty()).unwrap_or(false) {
                return Err(ParseError::UnexpectedBody { spec });
            }
            (None, None)
        }
        Body::MultiLine { .. } => (tail_after_nl.map(|s| s.to_string()), None),
        Body::Patch => {
            let body =
                tail_after_nl.ok_or_else(|| ParseError::MissingBody { spec: spec.clone() })?;
            (None, Some(split_patch(&spec, body)?))
        }
    };

    Ok(ResolvedCmdSpec {
        opts: Opts {
            spec: spec.clone(),
            map,
        },
        spec,
        args,
        body,
        patch,
        sub,
    })
}

//
// Command word
//

/// First-half of parsing an input: decide the command name/word.
///
/// # Returns
///
/// (command word, byte offset just past it)
fn scan_name(s: &str) -> (&str, usize) {
    // For /? special alias
    if s.starts_with('?') {
        return (&s[..1], 1);
    }
    let end = s
        .char_indices()
        .take_while(|(_, c)| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .map(|(i, c)| i + c.len_utf8())
        .last()
        .unwrap_or(0);
    (&s[..end], end)
}

/// Helper to find command word mispellings with edit distance <= 2.
fn did_you_mean<'a>(reg: &'a Registry, sigil: Sigil, name: &str) -> Option<&'a str> {
    let mut best: Option<(usize, &'a str)> = None;
    for c in reg.iter_cmds() {
        if c.sigil != sigil {
            continue;
        }
        for cand in std::iter::once(c.name.as_ref()).chain(c.aliases.iter().copied()) {
            let d = edit_distance(name, cand);
            if d <= 2 && best.map(|(bd, _)| d < bd).unwrap_or(true) {
                best = Some((d, cand));
            }
        }
    }
    best.map(|(_, n)| n)
}

fn edit_distance(a: &str, b: &str) -> usize {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for i in 1..=a.len() {
        cur[0] = i;
        for j in 1..=b.len() {
            let sub = prev[j - 1] + usize::from(a[i - 1] != b[j - 1]);
            cur[j] = sub.min(prev[j] + 1).min(cur[j - 1] + 1);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

//
// Options
//

struct Cur<'a> {
    s: &'a str,
    i: usize,
}

impl<'a> Cur<'a> {
    fn peek(&self) -> Option<char> {
        self.s[self.i..].chars().next()
    }
    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.i += c.len_utf8();
        Some(c)
    }
    fn eat(&mut self, c: char) -> bool {
        if self.peek() == Some(c) {
            self.i += c.len_utf8();
            true
        } else {
            false
        }
    }
}

/// Scan for options, i.e. `.opt=val.opt2`.
///
/// # Returns
///
/// (typed map, remaining argument text)
fn scan_options<'a>(
    spec: &CmdSpec,
    tail: &'a str,
) -> Result<(HashMap<&'static str, OptVal>, &'a str), ParseError> {
    let mut cur = Cur { s: tail, i: 0 };
    let mut map = HashMap::new();

    while cur.eat('.') {
        let start = cur.i;
        while matches!(cur.peek(), Some(c) if c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            cur.bump();
        }
        let name = &tail[start..cur.i];
        if name.is_empty() {
            return Err(ParseError::MalformedOptions {
                spec: spec.clone(),
                got: tail[start.saturating_sub(1)..].chars().take(12).collect(),
            });
        }
        let opt = spec
            .find_opt(name)
            .ok_or_else(|| ParseError::UnknownOption {
                spec: spec.clone(),
                got: name.to_string(),
                suggestion: nearest_opt(spec, name).map(str::to_string),
            })?;

        let raw = if cur.eat('=') {
            Some(read_opt_value(&mut cur)?)
        } else {
            None
        };
        map.insert(opt.name, coerce_opt(spec, opt, raw)?);
    }

    // Options must be followed by whitespace or end-of-input.
    if let Some(c) = cur.peek()
        && !c.is_whitespace()
    {
        return Err(ParseError::MalformedOptions {
            spec: spec.clone(),
            got: tail[cur.i..].chars().take(12).collect(),
        });
    }
    Ok((map, &tail[cur.i..]))
}

/// Read one option value.
///
/// Quoted values are taken verbatim. Unquoted values run to the next
/// whitespace or `.`, except that a `.` between digits is kept so that
/// decimals work (e.g. `.t=0.7`).
fn read_opt_value(cur: &mut Cur<'_>) -> Result<String, ParseError> {
    match cur.peek() {
        Some(q @ ('"' | '\'')) => {
            cur.bump();
            let mut out = String::new();
            loop {
                match cur.bump() {
                    None => return Err(ParseError::UnterminatedQuote),
                    Some('\\') => {
                        if let Some(c) = cur.bump() {
                            out.push(c);
                        }
                    }
                    Some(c) if c == q => return Ok(out),
                    Some(c) => out.push(c),
                }
            }
        }
        _ => {
            let mut out = String::new();
            let mut dot_used = false;
            loop {
                match cur.peek() {
                    None => break,
                    Some(c) if c.is_whitespace() => break,
                    Some('.') => {
                        let after = cur.s[cur.i + 1..].chars().next();
                        let numeric = !dot_used
                            && !out.is_empty()
                            && out.chars().all(|c| c.is_ascii_digit() || c == '-')
                            && matches!(after, Some(d) if d.is_ascii_digit());
                        if !numeric {
                            break;
                        }
                        dot_used = true;
                        out.push('.');
                        cur.bump();
                    }
                    Some(c) => {
                        out.push(c);
                        cur.bump();
                    }
                }
            }
            Ok(out)
        }
    }
}

fn coerce_opt(
    spec: &CmdSpec,
    opt: &'static Opt,
    raw: Option<String>,
) -> Result<OptVal, ParseError> {
    match (opt.ty, raw) {
        (OptType::Bool, None) => Ok(OptVal::Bool(true)),
        (OptType::Bool, Some(v)) => match v.to_ascii_lowercase().as_str() {
            "true" | "t" => Ok(OptVal::Bool(true)),
            "false" | "f" => Ok(OptVal::Bool(false)),
            _ => Err(ParseError::BadOptionValue {
                spec: spec.clone(),
                opt,
                got: v,
            }),
        },
        (_, None) => Err(ParseError::OptionNeedsValue {
            spec: spec.clone(),
            opt,
        }),
        (OptType::Number, Some(v)) => {
            v.parse::<f64>()
                .map(OptVal::Num)
                .map_err(|_| ParseError::BadOptionValue {
                    spec: spec.clone(),
                    opt,
                    got: v,
                })
        }
        (OptType::Str, Some(v)) => Ok(OptVal::Str(v)),
        (OptType::Enum(vals), Some(v)) => vals
            .iter()
            .copied()
            .find(|c| *c == v)
            .map(OptVal::Enum)
            .ok_or(ParseError::BadOptionValue {
                spec: spec.clone(),
                opt,
                got: v,
            }),
    }
}

/// Helper to find option name mispellings with edit distance <= 2.
fn nearest_opt(spec: &CmdSpec, name: &str) -> Option<&'static str> {
    spec.opts
        .iter()
        .map(|o| (edit_distance(name, o.name), o.name))
        .filter(|(d, _)| *d <= 2)
        .min_by_key(|(d, _)| *d)
        .map(|(_, n)| n)
}

// --

//
// Tokenizing
//

#[derive(Clone, Debug)]
struct Tok {
    text: String,
    span: Range<usize>,
}

/// Quote- and escape-aware split with byte spans, so `Arity::Rest` can recover
/// the raw, unmangled remainder (`/exec ls | grep "a b"`).
fn tokenize(s: &str) -> Result<Vec<Tok>, ParseError> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut start = 0usize;
    let mut started = false;
    let mut quote: Option<char> = None;
    let mut it = s.char_indices();

    while let Some((i, c)) = it.next() {
        let begin = |started: &mut bool, start: &mut usize| {
            if !*started {
                *start = i;
                *started = true;
            }
        };
        match c {
            '\\' => {
                begin(&mut started, &mut start);
                match it.next() {
                    Some((_, n)) => cur.push(n),
                    None => cur.push('\\'),
                }
            }
            '"' | '\'' => {
                begin(&mut started, &mut start);
                match quote {
                    Some(q) if q == c => quote = None,
                    Some(_) => cur.push(c),
                    None => quote = Some(c),
                }
            }
            c if c.is_whitespace() && quote.is_none() => {
                if started {
                    out.push(Tok {
                        text: std::mem::take(&mut cur),
                        span: start..i,
                    });
                    started = false;
                }
            }
            c => {
                begin(&mut started, &mut start);
                cur.push(c);
            }
        }
    }
    if quote.is_some() {
        return Err(ParseError::UnterminatedQuote);
    }
    if started {
        out.push(Tok {
            text: cur,
            span: start..s.len(),
        });
    }
    Ok(out)
}

// --

//
// Positionals
//

/// Walk `spec.args`, consuming tokens according to `Arity`.
///
/// `full` is the command line plus any body (the source for a multi-line
/// `Rest`); `line` is just the command line. Token spans index into both, since
/// `line` is a prefix of `full`.
fn fill_args(
    spec: &CmdSpec,
    full: &str,
    line: &str,
    toks: &[Tok],
) -> Result<(Vec<String>, Option<Box<ResolvedCmdSpec>>), ParseError> {
    let mut args: Vec<String> = Vec::new();
    let mut sub: Option<Box<ResolvedCmdSpec>> = None;
    let mut k = 0usize;

    for (idx, a) in spec.args.iter().enumerate() {
        match a.arity {
            Arity::Required => {
                let t = toks.get(k).ok_or(ParseError::MissingArg {
                    spec: spec.clone(),
                    arg: a.clone(),
                })?;
                if let ArgKind::Sub(table) = a.kind {
                    sub = Some(Box::new(parse_sub(
                        spec.clone(),
                        a.clone(),
                        table,
                        full,
                        line,
                        &toks[k..],
                    )?));
                    k = toks.len();
                    break;
                }
                check_enum(&spec, a, &t.text)?;
                args.push(t.text.clone());
                k += 1;
            }
            Arity::Optional => {
                if let Some(t) = toks.get(k) {
                    // HACK for /mcp-add (see `optional_guard`)
                    let takes = match optional_guard(&spec, idx) {
                        Some(g) => g(&t.text),
                        None => true,
                    };
                    if takes {
                        check_enum(&spec, a, &t.text)?;
                        args.push(t.text.clone());
                        k += 1;
                        continue;
                    }
                }
                args.push(String::new());
            }
            Arity::Repeated { at_least } => {
                let taken = &toks[k.min(toks.len())..];
                if taken.len() < at_least as usize {
                    return Err(ParseError::TooFewRepeated {
                        spec: spec.clone(),
                        arg: a.clone(),
                        got: taken.len(),
                    });
                }
                for t in taken {
                    check_enum(&spec, a, &t.text)?;
                    args.push(t.text.clone());
                }
                k = toks.len();
            }
            Arity::Rest | Arity::RestOpt => {
                // Body-less commands let `Rest` run past the newline, so
                // /prep, /prompt and !sh accept multi-line text.
                let src = if matches!(spec.body, Body::None) {
                    full
                } else {
                    line
                };
                let from = match toks.get(k) {
                    Some(t) => t.span.start,
                    None => k
                        .checked_sub(1)
                        .and_then(|i| toks.get(i))
                        .map_or(0, |t| t.span.end),
                };
                let rest: &str = src[from..].trim_start();
                if rest.is_empty() && matches!(a.arity, Arity::Rest) {
                    return Err(ParseError::MissingArg {
                        spec: spec.clone(),
                        arg: a.clone(),
                    });
                }
                args.push(rest.to_string());
                k = toks.len();
            }
        }
    }

    if k < toks.len() {
        return Err(ParseError::TooManyArgs {
            spec: spec.clone(),
            got: toks.len(),
        });
    }
    Ok((args, sub))
}

fn parse_sub(
    parent: CmdSpec,
    arg: Arg,
    table: &'static [CmdSpec],
    full: &str,
    line: &str,
    toks: &[Tok],
) -> Result<ResolvedCmdSpec, ParseError> {
    let head = &toks[0].text;
    let spec = table
        .iter()
        .find(|c| c.matches_name(head))
        .cloned()
        .ok_or_else(|| ParseError::UnknownSubcommand {
            spec: parent,
            got: head.clone(),
            choices: table.iter().map(|c| c.name.to_string()).collect(),
        })?;
    let _ = arg;
    let (args, sub) = fill_args(&spec, full, line, &toks[1..])?;
    Ok(ResolvedCmdSpec {
        opts: Opts {
            spec: spec.clone(),
            map: HashMap::new(),
        },
        spec,
        args,
        body: None,
        patch: None,
        sub,
    })
}

fn check_enum(spec: &CmdSpec, a: &Arg, got: &str) -> Result<(), ParseError> {
    if let ArgKind::Enum(vals) = a.kind
        && !vals.contains(&got)
    {
        return Err(ParseError::BadValue {
            spec: spec.clone(),
            arg: a.clone(),
            got: got.to_string(),
            why: format!("expected one of: {}", vals.join(", ")),
        });
    }
    Ok(())
}

/// Disambiguates a greedy `Optional` that sits in front of a `Rest`.
///
/// `/mcp-add <name> [<env>] <cmd>` is the only case today: `env` is a run of
/// `KEY=VALUE` pairs, so it's only an `env` if it contains `=`.
fn optional_guard(spec: &CmdSpec, arg_index: usize) -> Option<fn(&str) -> bool> {
    match (spec.name.as_ref(), arg_index) {
        ("mcp-add", 1) => Some(|s| s.contains('=')),
        _ => None,
    }
}

//
// Patch bodies
//

/// Split a patch body on the longest run of `=` that appears alone on a line.
/// Ambiguity (two runs of equal, maximal length) is an error.
fn split_patch(spec: &CmdSpec, body: &str) -> Result<Patch, ParseError> {
    let body = body.strip_suffix('\n').unwrap_or(body);
    let lines: Vec<&str> = body.split('\n').collect();

    let mut best = 0usize;
    let mut count = 0usize;
    let mut at = None;
    for (i, l) in lines.iter().enumerate() {
        let t = l.trim();
        if t.len() >= 3 && t.chars().all(|c| c == '=') {
            if t.len() > best {
                best = t.len();
                count = 1;
                at = Some(i);
            } else if t.len() == best {
                count += 1;
            }
        }
    }

    let Some(at) = at else {
        return Err(ParseError::BadPatch {
            spec: spec.clone(),
            why: "patch body has no `=======` delimiter line",
        });
    };
    if count > 1 {
        return Err(ParseError::BadPatch {
            spec: spec.clone(),
            why: "ambiguous patch: several delimiter lines of the same length. \
                  Use a longer run of `=` than any line in the content",
        });
    }

    Ok(Patch {
        search: lines[..at].join("\n"),
        replace: lines[at + 1..].join("\n"),
        fence: best,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd_registry::Registry;

    fn p(input: &str) -> Result<ResolvedCmdSpec, ParseError> {
        parse(&Registry::new(), input)
    }

    #[test]
    fn options_are_typed_and_defaulted() {
        let r = p("/file-read.n src/main.rs").unwrap();
        assert!(r.opts.bool("n"));
        assert!(!r.opts.bool("hq")); // registry default
        assert!(!r.opts.is_set("hq"));
        assert_eq!(r.arg(0), "src/main.rs");

        let r = p("/web-search rust").unwrap();
        assert_eq!(r.opts.u32("n"), Some(5)); // default from the registry
        let r = p("/web-search.n=10.pd rust async").unwrap();
        assert_eq!(r.opts.u32("n"), Some(10));
        assert!(r.opts.bool("pd"));
        assert_eq!(r.arg(0), "rust async");
    }

    #[test]
    fn dotted_values_need_care_only_when_ambiguous() {
        // A dot between digits stays inside the value.
        let r = p("/web-search.n=2 x").unwrap();
        assert_eq!(r.opts.u32("n"), Some(2));
        // Quoted values may contain anything.
        let r = p(r#"/web-search.range="2023-01-01to2023-12-31" x"#).unwrap();
        assert_eq!(r.opts.str("range"), Some("2023-01-01to2023-12-31"));
    }

    #[test]
    fn rest_is_verbatim_and_multiline_only_without_a_body() {
        let r = p(r#"/exec ls -la | grep "a b""#).unwrap();
        assert_eq!(r.arg(0), r#"ls -la | grep "a b""#);

        // Body::None + Rest -> newlines are part of the arg.
        let r = p("/prep line one\nline two").unwrap();
        assert_eq!(r.arg(0), "line one\nline two");

        // Body::MultiLine -> Rest stops at the newline.
        let r = p("/email Subject here\nbody line").unwrap();
        assert_eq!(r.arg(0), "Subject here");
        assert_eq!(r.body.as_deref(), Some("body line"));
    }

    #[test]
    fn stray_body_on_a_bodyless_command_is_an_error() {
        assert!(matches!(
            p("/asset-remove foo\nbar"),
            Err(ParseError::UnexpectedBody { .. })
        ));
    }

    #[test]
    fn arity_is_enforced() {
        assert!(matches!(
            p("/file-read"),
            Err(ParseError::TooFewRepeated { .. })
        ));
        assert!(matches!(
            p("/quit now"),
            Err(ParseError::TooManyArgs { .. })
        ));
        assert!(matches!(
            p("/asset-move a"),
            Err(ParseError::MissingArg { .. })
        ));
        let r = p("/asset-read a b c").unwrap();
        assert_eq!(r.args, vec!["a", "b", "c"]);
    }

    #[test]
    fn enum_args_are_checked_against_the_registry() {
        assert!(p("/hai-router on").is_ok());
        assert!(matches!(
            p("/hai-router maybe"),
            Err(ParseError::BadValue { .. })
        ));
    }

    #[test]
    fn aliases_normalize_to_canonical_names() {
        assert_eq!(p("/ls foo").unwrap().name(), "asset-list");
        assert_eq!(p("/?").unwrap().name(), "help");
    }

    #[test]
    fn patch_picks_the_longest_delimiter() {
        let r =
            p("/file-patch a.rs\nlet x = 1;\n=====\nstill search\n=======\nlet x = 2;").unwrap();
        let patch = r.patch.unwrap();
        assert_eq!(patch.fence, 7);
        assert_eq!(patch.search, "let x = 1;\n=====\nstill search");
        assert_eq!(patch.replace, "let x = 2;");
    }

    #[test]
    fn ambiguous_patch_is_rejected() {
        assert!(matches!(
            p("/file-patch a.rs\na\n=======\nb\n=======\nc"),
            Err(ParseError::BadPatch { .. })
        ));
    }

    #[test]
    fn mcp_add_optional_env_does_not_steal_the_command() {
        let r = p("/mcp-add git uvx -q mcp-server-git").unwrap();
        assert_eq!(
            (r.arg(0), r.arg(1), r.arg(2)),
            ("git", "", "uvx -q mcp-server-git")
        );
        let r = p("/mcp-add git V=1 uvx -q mcp-server-git").unwrap();
        assert_eq!(
            (r.arg(0), r.arg(1), r.arg(2)),
            ("git", "V=1", "uvx -q mcp-server-git")
        );
    }

    #[test]
    fn subcommands_resolve() {
        let r = p("/std which python3").unwrap();
        let sub = r.sub.unwrap();
        assert_eq!(sub.spec.name, "which");
        assert_eq!(sub.arg(0), "python3");
    }

    #[test]
    fn errors_carry_a_usage_line() {
        let e = p("/asset-move a").unwrap_err();
        assert!(e.to_string().contains("Usage: /asset-move <src> <dst>"));
    }

    /// Sanity check that every command can parse placeholder args
    #[test]
    fn every_command_parses_its_own_usage() {
        let reg = Registry::new();
        for spec in reg.cmds() {
            let mut line = spec.canonical();
            for a in spec.args.iter() {
                let v = placeholder(a);
                if !v.is_empty() {
                    line.push(' ');
                    line.push_str(&v);
                }
            }
            if matches!(spec.body, Body::MultiLine { .. }) {
                line.push_str("\nbody");
            } else if matches!(spec.body, Body::Patch) {
                line.push_str("\nsearch\n=======\nreplace");
            }
            parse(&reg, &line)
                .unwrap_or_else(|e| panic!("{} failed to parse {line:?}: {e}", spec.canonical()));
        }
    }

    fn placeholder(a: &Arg) -> String {
        match (a.arity, a.kind) {
            (Arity::Optional, _) => String::new(),
            (_, ArgKind::Enum(v)) => v[0].to_string(),
            (_, ArgKind::Sub(t)) => {
                let mut s = t[0].name.to_string();
                for sa in t[0].args.iter() {
                    s.push(' ');
                    s.push_str(&placeholder(sa));
                }
                s
            }
            (_, ArgKind::Number) => "1".into(),
            (_, ArgKind::Json) => "{}".into(),
            _ => "x".into(),
        }
    }

    #[test]
    fn optional_rest_allows_an_empty_tail() {
        let spec = Registry::new().lookup(Sigil::Bang, "py").unwrap();
        assert_eq!(parse_with_spec(spec.clone(), "").unwrap().arg(0), "");
        assert_eq!(parse_with_spec(spec.clone(), "   ").unwrap().arg(0), "");
        assert_eq!(
            parse_with_spec(spec.clone(), r#" print("a b")"#)
                .unwrap()
                .arg(0),
            r#"print("a b")"#
        );
        // required Rest is unaffected
        assert!(matches!(p("/exec"), Err(ParseError::MissingArg { .. })));
    }

    #[test]
    fn bare_tool_line_with_body_is_a_prompt_not_tool_mode() {
        let spec = Registry::new().lookup(Sigil::Bang, "py").unwrap();
        assert_eq!(
            parse_with_spec(spec, "\nwrite a script").unwrap().arg(0),
            "write a script"
        );
    }
}
