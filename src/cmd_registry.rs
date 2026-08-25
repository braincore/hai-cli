//! Source of truth for all command & tool specifications.
//!
//! Everything known about the prototype of a command lives here: name,
//! aliases, positional arguments, options, multi-line body, and documentation.
//!
//! These specifications are used for:
//!
//! 1. `/help` output for humans
//! 2. `!hai` tool schema for LLMs
//! 3. Tab-completion for the REPL
//! 4. Parsing user input into a `Cmd` struct for execution.
//!
//! The registry is an ordered list of `Entry`. Order is meaningful: it is the
//! order commands appear in both `/help` and the tool schema.

// --

//
// Audience
//

/// Who a given entry is written for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Audience {
    /// Only for things an LLM can't or shouldn't invoke (`/help`, `/quit`,
    /// account mgmt, ...)
    UserOnly,
    /// Only for LLM (/prompt, deprecated commands, ...)
    LlmOnly,
    /// Almost all entries should be both.
    Both,
    /// For internal-only commands
    Neither,
}

impl Audience {
    pub fn shows_to(&self, who: Who) -> bool {
        matches!(
            (self, who),
            (Audience::Both, _) | (Audience::UserOnly, Who::User) | (Audience::LlmOnly, Who::Llm)
        )
    }
}

/// The reader a render/filter pass is targeting.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Who {
    User,
    Llm,
}

// --

//
// Command traits (for filtering / policy)
//

/// Behavioral facts about a command. Used to build restricted command sets
/// (e.g. no filesystem access mode).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Traits {
    /// Writes to the local filesystem.
    pub mutates_fs: bool,
    /// Creates, modifies, or deletes assets.
    pub mutates_assets: bool,
    /// Runs arbitrary code on the user's machine.
    pub executes: bool,
    /// Talks to the network.
    pub network: bool,
    /// Requires a logged-in account.
    pub needs_account: bool,
    /// Blocks on a human at a terminal (editors, pickers, prompts).
    pub interactive: bool,
    /// Mutates REPL/conversation state rather than the outside world.
    pub repl_state: bool,
}

impl Traits {
    pub const NONE: Traits = Traits {
        mutates_fs: false,
        mutates_assets: false,
        executes: false,
        network: false,
        needs_account: false,
        interactive: false,
        repl_state: false,
    };

    pub const fn fs(mut self) -> Self {
        self.mutates_fs = true;
        self
    }
    pub const fn assets(mut self) -> Self {
        self.mutates_assets = true;
        self.network = true;
        self
    }
    pub const fn exec(mut self) -> Self {
        self.executes = true;
        self
    }
    pub const fn net(mut self) -> Self {
        self.network = true;
        self
    }
    pub const fn account(mut self) -> Self {
        self.needs_account = true;
        self
    }
    pub const fn interactive(mut self) -> Self {
        self.interactive = true;
        self
    }
    pub const fn repl(mut self) -> Self {
        self.repl_state = true;
        self
    }
}

/// Which traits to reject when building a filtered command set.
/// A `false` field means "don't care"; `true` means "exclude commands with it".
#[derive(Clone, Copy, Debug, Default)]
pub struct DenyTraits {
    pub mutates_fs: bool,
    pub mutates_assets: bool,
    pub executes: bool,
    pub network: bool,
    pub needs_account: bool,
    pub interactive: bool,
    pub repl_state: bool,
}

impl DenyTraits {
    pub const NONE: DenyTraits = DenyTraits {
        mutates_fs: false,
        mutates_assets: false,
        executes: false,
        network: false,
        needs_account: false,
        interactive: false,
        repl_state: false,
    };

    fn rejects(&self, t: &Traits) -> bool {
        (self.mutates_fs && t.mutates_fs)
            || (self.mutates_assets && t.mutates_assets)
            || (self.executes && t.executes)
            || (self.network && t.network)
            || (self.needs_account && t.needs_account)
            || (self.interactive && t.interactive)
            || (self.repl_state && t.repl_state)
    }
}

// --

/// Sigil (leading character of a command)
///
/// There are two types of commands: `/<cmd>` and `!tool`. The sigil for each
/// are `/` and `!` respectively.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Sigil {
    Slash,
    Bang,
}

impl Sigil {
    pub fn ch(&self) -> char {
        match self {
            Sigil::Slash => '/',
            Sigil::Bang => '!',
        }
    }
}

// --

//
// Arguments
//
// Args come after the command. Not to be confused with dotted options.
//

/// How many values an argument consumes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Arity {
    Required,
    Optional,
    /// Zero-or-more (`at_least: 0`) or one-or-more (`at_least: 1`) of the same
    /// kind, e.g. `/asset-read a b c`.
    Repeated {
        at_least: u8,
    },
    /// Consumes the entire rest of the line. Used for prompts, shell commands,
    /// and search queries. Must be the final argument.
    Rest,
    /// Like `Rest`, but the empty tail is legal and yields `""`. Used by
    /// `!<tool>`, where an absent prompt enters tool mode.
    RestOpt,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FilePathAccepts {
    Any,
    Dir,
    File,
}

/// What an argument refers to. Drives tab-completion, and doubles as a hint to
/// the LLM about what belongs in the slot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ArgKind {
    FilePath {
        accepts: FilePathAccepts,
        glob_ok: bool,
    },
    AssetName {
        glob_ok: bool,
    },
    AssetPrefix,
    /// Argument to an implicit (path components of blob entries) or explicit
    /// folder-asset.
    AssetFolder,
    /// A repo task fqn (`user/task-name`) or a path starting with `./`, `/`, `~`.
    TaskRef,
    /// A repo task fqn (`user/task-name`).
    TaskFqn,
    Username,
    ModelName,
    Url,
    /// A shell command. The completer should recurse into $PATH and file
    /// completion, and handle `@@asset` references.
    ShellCmd,
    /// Natural-language prompt for the AI or a tool.
    Prompt,
    /// Search query.
    Query,
    Number,
    /// A JSON value or object.
    Json,
    /// A fixed set of literal values.
    Enum(&'static [&'static str]),
    /// A nested command table, e.g. `/std now`.
    Sub(&'static [CmdSpec]),
    /// Opaque text; no completion.
    Text,
}

impl ArgKind {
    /// If argument is free text, completion isn't supported.
    pub fn is_free_text(&self) -> bool {
        matches!(self, ArgKind::Prompt | ArgKind::Query | ArgKind::Text)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Arg {
    /// Rendered as `<name>`.
    pub name: &'static str,
    pub kind: ArgKind,
    pub arity: Arity,
    /// Rarely needed; most argument names are self-evident.
    pub doc: Option<&'static str>,
}

pub const fn arg(name: &'static str, kind: ArgKind, arity: Arity) -> Arg {
    Arg {
        name,
        kind,
        arity,
        doc: None,
    }
}

pub const fn arg_doc(name: &'static str, kind: ArgKind, arity: Arity, doc: &'static str) -> Arg {
    Arg {
        name,
        kind,
        arity,
        doc: Some(doc),
    }
}

//
// Options
//
// An option for a command is specified after the `/<cmd>` prefix with a dot,
// option name, and (optional) option value.
//

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OptType {
    Bool,
    Number,
    Str,
    Enum(&'static [&'static str]),
}

impl OptType {
    pub fn label(&self) -> &'static str {
        match self {
            OptType::Bool => "BOOL",
            OptType::Number => "NUMBER",
            OptType::Str => "STRING",
            OptType::Enum(_) => "ENUM",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Opt {
    pub name: &'static str,
    pub ty: OptType,
    /// Rendered as "(default: <d>)". `None` for options with no meaningful
    /// default (unset flags).
    pub default: Option<&'static str>,
    pub doc: &'static str,
}

pub const fn opt(
    name: &'static str,
    ty: OptType,
    default: Option<&'static str>,
    doc: &'static str,
) -> Opt {
    Opt {
        name,
        ty,
        default,
        doc,
    }
}

pub const fn flag(name: &'static str, doc: &'static str) -> Opt {
    opt(name, OptType::Bool, Some("false"), doc)
}

// Options that recur across many commands.
const OPT_N: Opt = flag(
    "n",
    "Show line numbers (handy when asking for patches or referring to specific lines)",
);
const OPT_HQ: Opt = flag("hq", "For images, load the high-res version");
const OPT_CACHE: Opt = flag("cache", "Cache the result for the next execution");
const OPT_ACCENT_DANGER: Opt = flag("danger", "Render with the danger accent color");
const OPT_ACCENT_WARN: Opt = flag("warn", "Render with the warn accent color");
const OPT_ACCENT_INFO: Opt = flag("info", "Render with the info accent color");
const OPT_ACCENT_SUCCESS: Opt = flag("success", "Render with the success accent color");
const ACCENT_OPTS: &[Opt] = &[
    OPT_ACCENT_DANGER,
    OPT_ACCENT_WARN,
    OPT_ACCENT_INFO,
    OPT_ACCENT_SUCCESS,
];

//
// Multi-line Body
//

/// For commands that consume lines after the first.
/// Typically used to dump file or asset contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Body {
    None,
    /// Everything after the first line is content.
    MultiLine {
        name: &'static str,
        doc: &'static str,
    },
    /// A search/replace patch. See `PATCH_FORMAT`.
    Patch,
}

//
// Docs
//

/// Documentation for a command.
///
/// `summary` must read sensibly for humans and LLMs. `user_extra` and
/// `llm_extra` append audience-specific prose.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Doc {
    pub summary: Str,
    /// Stays `&'static` so `.user()`/`.llm()`/`.more()` can remain `const fn`.
    pub user_extra: Option<&'static str>,
    pub llm_extra: Option<&'static str>,
}

impl Doc {
    pub const fn new(summary: &'static str) -> Self {
        Doc {
            summary: Cow::Borrowed(summary),
            user_extra: None,
            llm_extra: None,
        }
    }

    /// For dynamically-generated commands
    pub fn owned(summary: impl Into<Str>) -> Self {
        Doc {
            summary: summary.into(),
            user_extra: None,
            llm_extra: None,
        }
    }
    pub const fn user(mut self, s: &'static str) -> Self {
        self.user_extra = Some(s);
        self
    }
    pub const fn llm(mut self, s: &'static str) -> Self {
        self.llm_extra = Some(s);
        self
    }
    /// Extra prose shown to user & llm after the summary line.
    ///
    /// WARN: Conflating "extra info" with audience-specific info.
    pub const fn more(mut self, s: &'static str) -> Self {
        self.user_extra = Some(s);
        self.llm_extra = Some(s);
        self
    }

    pub fn extra_for(&self, who: Who) -> Option<&'static str> {
        match who {
            Who::User => self.user_extra,
            Who::Llm => self.llm_extra,
        }
    }
}

// --

//
// Command
//

use std::borrow::Cow;

pub type Str = Cow<'static, str>;
pub type List<T> = Cow<'static, [T]>;

/// Only the fields that genuinely vary at runtime are `Cow`.
///
/// `aliases` and `opts` deliberately stay `&'static`: they are the only fields
/// the `const fn` builders below overwrite, and overwriting a field whose type
/// needs `Drop` is illegal in a `const fn` (E0493). Everything `Cow` here is
/// set once, by the constructor, which is fine in const context because no
/// destructor ever runs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CmdSpec {
    pub sigil: Sigil,
    /// Canonical name, without sigil. e.g. "asset-list".
    pub name: Str,
    /// Alternate names, without sigil. e.g. ["ls"].
    pub aliases: &'static [&'static str],
    /// Groups related commands for anchoring prose and for filtering.
    pub family: Str,
    pub args: List<Arg>,
    pub opts: &'static [Opt],
    pub body: Body,
    pub doc: Doc,
    pub audience: Audience,
    pub traits: Traits,
}

/// Builder pattern
impl CmdSpec {
    pub const fn alias(mut self, aliases: &'static [&'static str]) -> Self {
        self.aliases = aliases;
        self
    }
    pub const fn with_opts(mut self, opts: &'static [Opt]) -> Self {
        self.opts = opts;
        self
    }
    pub const fn with_body(mut self, body: Body) -> Self {
        self.body = body;
        self
    }
    pub const fn for_audience(mut self, a: Audience) -> Self {
        self.audience = a;
        self
    }
    pub const fn with_traits(mut self, t: Traits) -> Self {
        self.traits = t;
        self
    }
}

impl CmdSpec {
    /// All invocations, aliases first, canonical name last.
    /// e.g. `["/ls", "/asset-list"]`.
    pub fn invocations(&self) -> Vec<String> {
        let c = self.sigil.ch();
        self.aliases
            .iter()
            .copied()
            .chain(std::iter::once(self.name.as_ref()))
            .map(|n| format!("{c}{n}"))
            .collect()
    }

    pub fn canonical(&self) -> String {
        format!("{}{}", self.sigil.ch(), self.name)
    }

    pub fn aliases_with_sigil(&self) -> Vec<String> {
        let c = self.sigil.ch();
        self.aliases
            .iter()
            .copied()
            .map(|n| format!("{c}{n}"))
            .collect()
    }

    pub fn matches_name(&self, bare: &str) -> bool {
        self.name == bare || self.aliases.iter().any(|a| *a == bare)
    }

    /// The synthesized usage line, shared by `/help`, the tool schema, and
    /// parse-error messages, to maximize uniformity.
    pub fn usage(&self) -> String {
        let mut u = self.invocations().join(" ");
        for a in self.args.iter() {
            u.push(' ');
            u.push_str(&match a.arity {
                Arity::Required | Arity::Rest => format!("<{}>", a.name),
                Arity::Optional | Arity::RestOpt => format!("[<{}>]", a.name),
                Arity::Repeated { at_least: 0 } => format!("[<{0}> ...]", a.name),
                Arity::Repeated { .. } => format!("<{0}> [<{0}> ...]", a.name),
            });
        }
        match self.body {
            Body::MultiLine { name, .. } => u.push_str(&format!(" <multi-line {name}>")),
            Body::Patch => u.push_str(" <multi-line patch>"),
            Body::None => {}
        }
        u
    }

    /// Usage line using only the canonical name; for error messages.
    pub fn usage_canonical(&self) -> String {
        let full = self.usage();
        match full.split_once(&self.canonical()) {
            Some((_, tail)) => format!("{}{}", self.canonical(), tail),
            None => full,
        }
    }

    pub fn find_opt(&self, name: &str) -> Option<&'static Opt> {
        // Safe because `opts` is a &'static [Opt].
        self.opts.iter().find(|o| o.name == name)
    }

    /// Names of all valid options, for `validate_options_and_print_err`.
    pub fn opt_names(&self) -> Vec<&'static str> {
        self.opts.iter().map(|o| o.name).collect()
    }

    /// Option name -> type, for `validate_option_types`.
    pub fn opt_types(&self) -> Vec<(&'static str, OptType)> {
        self.opts.iter().map(|o| (o.name, o.ty)).collect()
    }

    /// Resolve a positional index to its `Arg`, honoring a trailing
    /// `Repeated`/`Rest` argument that soaks up everything past its position.
    pub fn arg_at(&self, index: usize) -> Option<(usize, &Arg)> {
        if let Some(a) = self.args.get(index) {
            return Some((index, a));
        }
        match self.args.last() {
            Some(a)
                if matches!(
                    a.arity,
                    Arity::Repeated { .. } | Arity::Rest | Arity::RestOpt
                ) =>
            {
                Some((self.args.len() - 1, a))
            }
            _ => None,
        }
    }
}

/// Convenience constructor for `CmdSpec`.
///
/// Sets `Audience::Both` and `Traits::None`.
///
/// Use builder pattern to customize.
pub const fn cmd(sigil: Sigil, name: Str, family: Str, args: List<Arg>, doc: Doc) -> CmdSpec {
    CmdSpec {
        sigil,
        name,
        aliases: &[],
        family,
        args,
        opts: &[],
        body: Body::None,
        doc,
        audience: Audience::Both,
        traits: Traits::NONE,
    }
}

/// Like `cmd()` but  for dynamic commands (fn-tools & MCP).
pub fn cmd_dyn(
    sigil: Sigil,
    name: impl Into<Str>,
    family: impl Into<Str>,
    args: impl Into<List<Arg>>,
    doc: Doc,
) -> CmdSpec {
    cmd(sigil, name.into(), family.into(), args.into(), doc)
}

/// All fn-tool take a single string argument. But, the string will likely be
/// interpreted as a expression by the tool itself: `"[1, 2]"` -> `[1, 2]`.
const FN_TOOL_ARGS: &[Arg] = &[arg("arg", Text, Rest)];

/// Like `cmd()` but specifically tailored to fn-tools.
pub fn fn_tool_cmd(name: impl Into<Str>, summary: impl Into<Str>) -> CmdSpec {
    cmd_dyn(Slash, name, "fn-tool", FN_TOOL_ARGS, Doc::owned(summary))
}

/// All MCP commands take a tool name and a JSON argument.
const MCP_ARGS: &[Arg] = &[arg("tool_name", Text, Required), arg("arg", Json, Rest)];

/// Like `cmd()` but specifically tailored to mcp fns.
pub fn mcp_cmd(name: impl Into<Str>, summary: impl Into<Str>) -> CmdSpec {
    cmd_dyn(Slash, name, "mcp", MCP_ARGS, Doc::owned(summary))
}

//
// Entries: sections, notes, commands
//

/// Ties a `Section` or `Note` to the commands it explains. When a filter is
/// applied, prose is retained only if at least one of its anchored commands
/// did.
#[derive(Clone, Copy, Debug)]
pub enum Anchor {
    Family(&'static str),
    /// Matches by command-name prefix, e.g. `"asset-crypt"`.
    Prefix(&'static str),
    Exact(&'static str),
}

impl Anchor {
    fn matches(&self, c: &CmdSpec) -> bool {
        match self {
            Anchor::Family(f) => c.family == *f,
            Anchor::Prefix(p) => c.name.starts_with(p),
            Anchor::Exact(n) => c.name == *n,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Section {
    /// `None` renders as a bare separator.
    pub title: Option<&'static str>,
    pub blurb: Option<&'static str>,
    pub anchors: &'static [Anchor],
    pub audience: Audience,
}

#[derive(Clone, Copy, Debug)]
pub struct Note {
    pub blurb: &'static str,
    pub anchors: &'static [Anchor],
    pub audience: Audience,
}

#[derive(Clone, Debug)]
pub enum Entry {
    Section(Section),
    Note(Note),
    Cmd(CmdSpec),
}

const fn section(
    title: Option<&'static str>,
    blurb: Option<&'static str>,
    anchors: &'static [Anchor],
) -> Entry {
    Entry::Section(Section {
        title,
        blurb,
        anchors,
        audience: Audience::Both,
    })
}

const fn note(blurb: &'static str, anchors: &'static [Anchor]) -> Entry {
    Entry::Note(Note {
        blurb,
        anchors,
        audience: Audience::Both,
    })
}

//
// Non-command-specific notes for registry
//

pub const PATCH_FORMAT: &str = "\
Patch format: the body contains a search block and a replace block separated
by a delimiter line. The search block must match full lines and EXACTLY ONE
location.

The delimiter is the LONGEST run of `=` characters appearing on its own line in
the body, so it can be disambiguated from any legitimate `=` runs in the
content. Default to 7 (`=======`); use a longer run if the content itself
contains lines of `=`.

    /file-patch path/to/file
    <search text>
    =======
    <replace text>

Use /file-read or /asset-read with .n to grab exact text and line context when
building the search block.";

pub const EXEC_ASSET_NOTE: &str = "\
`@@name` may be used anywhere a file path is expected; the referenced asset is
downloaded transparently. A shell redirect to `@@name` (`> @@name`) uploads the
output to that asset, making /asset-import and /asset-export unnecessary.";

pub const ASSET_NAMING: &str = "\
Asset names beginning with `/<username>` are public assets readable by anyone.
Names beginning with `//` expand to `/<username>/`.";

pub const ATTACHMENTS_DOC: &str = "\
Attachments are assets associated with a parent asset. An asset name containing
`:` refers to an attachment: the part before `:` is the parent asset name, and
the part after is the attachment name. For example, `doc.md:photo.jpg` refers
to the attachment `photo.jpg` of `doc.md`.

Attachments can be nested to any depth by chaining `:`, where each segment is
an attachment of the one before it. For example, `trip.md:day1.md:map.jpg` is
`map.jpg` attached to `day1.md`, which is itself attached to `trip.md`.

Use a trailing `:` to refer to an asset's list of attachments, e.g.
`/asset-list doc.md:`.";

pub const ASSET_ID_DOC: &str = "\
Referencing assets by ID: use `/asset-list.full` to find an asset's ID. The ID
is a stable reference even if the asset is moved or renamed. Reference it in
any command that takes an asset name by prefixing it with `:`, e.g.
`/asset-read :<ID>` or `/asset-md-get :<ID>`.";

pub const OPTION_SYNTAX: &str = "\
Option syntax:

    /<cmd>.<opt>=<value>
    /<cmd>.<opt>            (bool options default to true when bare)
    /<cmd>.<opt1>.<opt2>    (multiple options)

String values are quoted: /<cmd>.<opt>=\"...\"";

pub const BODY_SYNTAX: &str = "\
Multi-line body syntax: place the body on the lines following the command.

    /asset-write path/to/asset
    contents line 1
    contents line 2";

//
// Sub-command tables
//

static STD_SUBCMDS: &[CmdSpec] = &[
    cmd(
        Sigil::Slash,
        Cow::Borrowed("now"),
        Cow::Borrowed("std"),
        Cow::Borrowed(&[]),
        Doc::new("Print the current date and time"),
    ),
    cmd(
        Sigil::Slash,
        Cow::Borrowed("new-day-alert"),
        Cow::Borrowed("std"),
        Cow::Borrowed(&[]),
        Doc::new("Make the AI aware when a new day begins since the last interaction"),
    ),
    cmd(
        Sigil::Slash,
        Cow::Borrowed("which"),
        Cow::Borrowed("std"),
        Cow::Borrowed(&[arg("prog", ArgKind::Text, Arity::Required)]),
        Doc::new("Check whether a program is available"),
    ),
];

const ONOFF: &[&str] = &["on", "off"];

//
// The registry
//

use ArgKind::*;
use Arity::*;
use Sigil::{Bang, Slash};

pub static REGISTRY: &[Entry] = &[
    //
    // Meta commands
    //
    section(Some("Available Commands"), None, &[]),
    Entry::Cmd(
        cmd(Slash, Cow::Borrowed("help"), Cow::Borrowed("meta"), Cow::Borrowed(&[]), Doc::new("Show this help menu"))
            .alias(&["?", "h"])
            .for_audience(Audience::UserOnly),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("quit"),
            Cow::Borrowed("meta"),
            Cow::Borrowed(&[]),
            Doc::new("Bye").user("CTRL+D works too"),
        )
        .alias(&["q"])
        .for_audience(Audience::UserOnly),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("new"),
            Cow::Borrowed("meta"),
            Cow::Borrowed(&[]),
            Doc::new("Start a new conversation"),
        )
        .alias(&["n"])
        .for_audience(Audience::UserOnly)
        .with_traits(Traits::NONE.repl()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("reset"),
            Cow::Borrowed("meta"),
            Cow::Borrowed(&[]),
            Doc::new("Start a new conversation, retaining /pin /asset-read /file-read /http-get"),
        )
        .alias(&["r"])
        .for_audience(Audience::UserOnly)
        .with_traits(Traits::NONE.repl()),
    ),
    //
    // LLM options
    //
    section(Some("LLM"), None, &[Anchor::Family("ai")]),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("set-key"),
            Cow::Borrowed("ai"),
            Cow::Borrowed(&[arg("provider", Enum(&["openai", "anthropic", "deepseek", "google", "xai"]), Required),
            arg("key", Text, Required)
            ]),
            Doc::new("Set API key for LLM provider"),
        )
        .for_audience(Audience::UserOnly)
        .with_traits(Traits::NONE.account()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("ai"),
            Cow::Borrowed("ai"),
            Cow::Borrowed(&[arg("model", ModelName, Optional)]),
            Doc::new("Show the current AI model, or switch to <model>").user(
                "Available models: gpt5, o4mini, opus, sonnet, r1, grok, gpt-oss, ...\n\
                 Prefix provider for any model: openai/*, anthropic/*, ollama/*, google/*",
            ),
        )
        .for_audience(Audience::UserOnly),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("ai-default"),
            Cow::Borrowed("ai"),
            Cow::Borrowed(&[arg("model", ModelName, Optional)]),
            Doc::new("Show or set the default AI model used on start up"),
        )
        .for_audience(Audience::UserOnly),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("agentic"),
            Cow::Borrowed("ai"),
            Cow::Borrowed(&[arg("state", Enum(&["on", "on-without-cache", "off"]), Required)]),
            Doc::new("Agentic mode allows the LLM to loop autonomously"),
        )
        .for_audience(Audience::UserOnly)
        .with_traits(Traits::NONE.account()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("temperature"),
            Cow::Borrowed("ai"),
            Cow::Borrowed(&[arg("t", Number, Required)]),
            Doc::new("Set the AI model temperature")
                .user("0 for coding, higher for writing; depends on model. Use `none` to unset"),
        )
        .for_audience(Audience::UserOnly),
    ),
    //
    // Account management
    //
    section(Some("Accounts"), None, &[Anchor::Family("account")]),
    Entry::Cmd(cmd(
        Slash,
        Cow::Borrowed("account"),
        Cow::Borrowed("account"),
        Cow::Borrowed(&[arg("username", Username, Optional)]),
        Doc::new("See current and available accounts")
            .user("If a username is specified, switches to it. Use `_` to switch to no-user"),
    )),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("account-new"),
            Cow::Borrowed("account"),
            Cow::Borrowed(&[]),
            Doc::new("Make a new account"),
        )
        .for_audience(Audience::UserOnly)
        .with_traits(Traits::NONE.net().interactive()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("account-login"),
            Cow::Borrowed("account"),
            Cow::Borrowed(&[]),
            Doc::new("Log in to your account"),
        )
        .for_audience(Audience::UserOnly)
        .with_traits(Traits::NONE.net().interactive()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("account-logout"),
            Cow::Borrowed("account"),
            Cow::Borrowed(&[arg("username", Username, Optional)]),
            Doc::new("Remove credentials of a previously logged-in account"),
        )
        .for_audience(Audience::UserOnly),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("account-balance"),
            Cow::Borrowed("account"),
            Cow::Borrowed(&[]),
            Doc::new("Check credits remaining for hai-router"),
        )
        .for_audience(Audience::UserOnly)
        .with_traits(Traits::NONE.net().account()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("account-subscribe"),
            Cow::Borrowed("account"),
            Cow::Borrowed(&[]),
            Doc::new("Subscribe for hai-router and asset storage"),
        )
        .for_audience(Audience::UserOnly)
        .with_traits(Traits::NONE.net().interactive()),
    ),
    Entry::Cmd(cmd(
        Slash,
        Cow::Borrowed("whois"),
        Cow::Borrowed("account"),
        Cow::Borrowed(&[arg("username", Username, Required)]),
        Doc::new("Look up a user").user("try `ken`"),
    )
    .with_traits(Traits::NONE.net())),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("hai-router"),
            Cow::Borrowed("account"),
            Cow::Borrowed(&[arg("state", Enum(ONOFF), Required)]),
            Doc::new("Turn hai-router on or off").user("Requires credits"),
        )
        .for_audience(Audience::UserOnly)
        .with_traits(Traits::NONE.account()),
    ),
    //
    // Files
    //
    section(Some("Files (local machine)"), None, &[Anchor::Family("file")]),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("file-read"),
            Cow::Borrowed("file"),
            Cow::Borrowed(&[arg(
                "glob-path",
                FilePath { accepts: FilePathAccepts::File, glob_ok: true },
                Repeated { at_least: 1 },
            )]),
            Doc::new("Load files into the conversation (e.g. `/file-read src/**/*.py`)")
                .more("Supports text files or PNG/JPG images"),
        )
        .with_opts(&[OPT_N, OPT_HQ]),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("file-write"),
            Cow::Borrowed("file"),
            Cow::Borrowed(&[arg("path", FilePath { accepts: FilePathAccepts::File, glob_ok: false }, Required)]),
            Doc::new("Create or replace a file at <path>"),
        )
        .with_body(Body::MultiLine {
            name: "contents",
            doc: "Written to the file verbatim",
        })
        .with_traits(Traits::NONE.fs()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("file-patch"),
            Cow::Borrowed("file"),
            Cow::Borrowed(&[arg("path", FilePath { accepts: FilePathAccepts::File, glob_ok: false }, Required)]),
            Doc::new("Apply a search/replace patch to an existing file"),
        )
        .with_body(Body::Patch)
        .with_traits(Traits::NONE.fs()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("file-cat"),
            Cow::Borrowed("file"),
            Cow::Borrowed(&[arg(
                "glob-path",
                FilePath { accepts: FilePathAccepts::File, glob_ok: true },
                Repeated { at_least: 1 },
            )]),
            Doc::new("Load files into the conversation and print them"),
        )
        .with_opts(&[OPT_N, OPT_HQ]),
    ),
    Entry::Cmd(cmd(
        Slash,
        Cow::Borrowed("cd"),
        Cow::Borrowed("file"),
        Cow::Borrowed(&[arg("path", FilePath { accepts: FilePathAccepts::Dir, glob_ok: false }, Required)]),
        Doc::new("Change the current working directory"),
    )),
    //
    // HTTP
    //
    section(Some("HTTP"), None, &[Anchor::Family("http")]),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("http-get"),
            Cow::Borrowed("http"),
            Cow::Borrowed(&[arg("url", Url, Required)]),
            Doc::new("Load a URL into the conversation"),
        )
        .with_opts(&[
            OPT_N,
            flag("raw", "Return raw content rather than extracting markdown"),
            OPT_HQ,
        ])
        .with_traits(Traits::NONE.net()),
    ),
    //
    // Exec
    //
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("exec"),
            Cow::Borrowed("exec"),
            Cow::Borrowed(&[arg("cmd", ShellCmd, Rest)]),
            Doc::new("Execute a shell command and add the output to the conversation")
                .user("`!!<cmd>` is an alternative to /exec, not to be confused with tools"),
        )
        .alias(&["e"])
        .with_opts(&[
            flag(
                "i",
                "Interactive: inherit terminal stdin/stdout/stderr (required for vim, etc.)",
            ),
            OPT_CACHE,
        ])
        .with_traits(Traits::NONE.exec()),
    ),
    note(EXEC_ASSET_NOTE, &[Anchor::Exact("exec")]),
    //
    // Conversation management
    //
    section(Some("Conversation management"), None, &[Anchor::Family("convo")]),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("prep"),
            Cow::Borrowed("convo"),
            Cow::Borrowed(&[arg("msg", Prompt, Rest)]),
            Doc::new("Add a message to the conversation without prompting the AI")
                .user("Or end with two blank lines to queue it with your next message"),
        )
        .with_opts(ACCENT_OPTS)
        .with_traits(Traits::NONE.repl()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("pin"),
            Cow::Borrowed("convo"),
            Cow::Borrowed(&[arg("msg", Prompt, Rest)]),
            Doc::new("Like /prep, but the message is retained across /reset"),
        )
        .with_opts(ACCENT_OPTS)
        .with_traits(Traits::NONE.repl()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("system-prompt"),
            Cow::Borrowed("convo"),
            Cow::Borrowed(&[arg("prompt", Prompt, RestOpt)]),
            Doc::new("Set a system prompt for the conversation"),
        )
        .for_audience(Audience::UserOnly)
        .with_traits(Traits::NONE.repl()),
    ),
    Entry::Cmd(cmd(
        Slash,
        Cow::Borrowed("clip"),
        Cow::Borrowed("convo"),
        Cow::Borrowed(&[]),
        Doc::new("Copy the last message to your clipboard")
            .more("Unlike the !clip tool, the AI is not prompted"),
    )),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("forget"),
            Cow::Borrowed("convo"),
            Cow::Borrowed(&[arg("n", Number, Optional)]),
            Doc::new("Forget the last <n> messages in the conversation").user("Defaults to 1"),
        )
        .for_audience(Audience::UserOnly)
        .with_traits(Traits::NONE.repl()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("keep"),
            Cow::Borrowed("convo"),
            Cow::Borrowed(&[
                arg("bottom", Number, Required),
                arg("top", Number, Optional),
            ]),
            Doc::new("Keep the last <bottom> messages and forget the rest")
                .user("If <top> is specified, the first <top> messages are kept as well"),
        )
        .for_audience(Audience::UserOnly)
        .with_traits(Traits::NONE.repl()),
    ),
    //
    // Tools
    //
    section(
        Some("Tools"),
        Some(
            "Tools prompt the AI to write code for a tool: `!<tool> <prompt>`. `!<tool>` \
             without a prompt enters tool mode, where every message is treated as a prompt \
             for that tool; `!'<cmd>' <prompt>` runs any local program: the AI writes its \
             stdin, or an input file if the command contains a {file} / {file.ext} placeholder. \
             Exit with !exit or CTRL+D."
        ),
        &[Anchor::Family("tool")],
    ),
    Entry::Cmd(
        cmd(
            Bang,
            Cow::Borrowed("sh"),
            Cow::Borrowed("tool"),
            Cow::Borrowed(&[arg("prompt", Prompt, RestOpt)]),
            Doc::new("Ask AI to write a shell script/pipeline that is executed on your machine"),
        )
        .with_traits(Traits::NONE.exec()),
    ),
    Entry::Cmd(
        cmd(
            Bang,
            Cow::Borrowed("py"),
            Cow::Borrowed("tool"),
            Cow::Borrowed(&[arg("prompt", Prompt, RestOpt)]),
            Doc::new("Ask AI to write a Python script that is executed on your machine")
                .user("Searches for a virtualenv in the current dir & ancestors before falling back to python3"),
        )
        .with_traits(Traits::NONE.exec()),
    ),
    Entry::Cmd(
        cmd(
            Bang,
            Cow::Borrowed("pyuv"),
            Cow::Borrowed("tool"),
            Cow::Borrowed(&[arg("prompt", Prompt, RestOpt)]),
            Doc::new("Ask AI to write a Python script with inline dependencies auto-installed via uv"),
        )
        .with_traits(Traits::NONE.exec()),
    ),
    Entry::Cmd(
        cmd(
            Bang,
            Cow::Borrowed("html"),
            Cow::Borrowed("tool"),
            Cow::Borrowed(&[arg("prompt", Prompt, RestOpt)]),
            Doc::new("Ask AI to write HTML/CSS/JS and open it in the system browser"),
        )
        .with_traits(Traits::NONE.exec()),
    ),
    Entry::Cmd(
        cmd(
            Bang,
            Cow::Borrowed("hai"),
            Cow::Borrowed("tool"),
            Cow::Borrowed(&[arg("prompt", Prompt, RestOpt)]),
            Doc::new("Ask AI to write and execute REPL commands").llm(
                "Lets you recursively call yourself to construct a new set of commands \
                 based on new information in the conversation.",
            ),
        )
        .with_traits(Traits::NONE.exec()),
    ),
    Entry::Cmd(cmd(
        Bang,
        Cow::Borrowed("clip"),
        Cow::Borrowed("tool"),
        Cow::Borrowed(&[arg("prompt", Prompt, Rest)]),
        Doc::new("Ask AI to copy a part of the conversation to your clipboard"),
    )),
    Entry::Cmd(cmd(
        Bang,
        Cow::Borrowed("exit"),
        Cow::Borrowed("tool"),
        Cow::Borrowed(&[]),
        Doc::new("Exit tool mode"),
    )),
    note(
        "!'<cmd>' <prompt>  -- Ask AI to write a script piped to <cmd> through stdin.\n\
         e.g. !'uv run --python 3 --with geopy -' distance from san francisco to nyc\n\
         Vars from haivars & /setvar can be used: !'$psql' describe users table\n\
         If `{file}` appears in <cmd>, the AI output is written to a temporary file and\n\
         substituted for `{file}` in the command.\n\
         ! <prompt>         -- Re-use the previous tool with a new prompt.\n\
         !                  -- Re-use the previous tool and prompt.",
        &[Anchor::Family("tool")],
    ),
    //
    // Function tools
    //
    section(
        Some("Function Tools"),
        Some(
            "Function tools ask the AI to write a reusable function that takes a single \
             argument. Each is assigned a name `f<index>` and invoked with `/f<index> <arg>`. \
             For Python, <arg> must be an evaluable Python expression; for shell, a shell \
             value or expression.",
        ),
        &[Anchor::Family("fn-tool")],
    ),
    Entry::Cmd(
        cmd(
            Bang,
            Cow::Borrowed("fn-py"),
            Cow::Borrowed("fn-tool"),
            Cow::Borrowed(&[arg("prompt", Prompt, Rest)]),
            Doc::new("Ask AI to write a Python function to implement your prompt"),
        )
        .with_opts(&[
            opt("name", OptType::Str, None, "Custom name: `/f_<name>`"),
            OPT_CACHE,
            ])
        .with_traits(Traits::NONE.exec()),
    ),
    Entry::Cmd(
        cmd(
            Bang,
            Cow::Borrowed("fn-pyuv"),
            Cow::Borrowed("fn-tool"),
            Cow::Borrowed(&[arg("prompt", Prompt, Rest)]),
            Doc::new("Like !fn-py, but uv is used so the function may declare dependencies"),
        )
        .with_opts(&[
            opt("name", OptType::Str, None, "Custom name: `/f_<name>`"),
            OPT_CACHE])
        .with_traits(Traits::NONE.exec()),
    ),
    Entry::Cmd(
        cmd(
            Bang,
            Cow::Borrowed("fn-sh"),
            Cow::Borrowed("fn-tool"),
            Cow::Borrowed(&[arg("prompt", Prompt, Rest)]),
            Doc::new("Ask AI to write a shell function to implement your prompt"),
        )
        .with_opts(&[
            opt("name", OptType::Str, None, "Custom name: `/f_<name>`"),
            OPT_CACHE])
        .with_traits(Traits::NONE.exec()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("fns"),
            Cow::Borrowed("fn-tool"),
            Cow::Borrowed(&[]),
            Doc::new("List all available functions"),
        )
        .for_audience(Audience::UserOnly),
    ),
    //
    // Stdlib fns
    //
    section(Some("Standard Library Functions"), None, &[Anchor::Family("std")]),
    Entry::Cmd(cmd(
        Slash,
        Cow::Borrowed("std"),
        Cow::Borrowed("std"),
        Cow::Borrowed(&[arg("fn", Sub(STD_SUBCMDS), Required)]),
        Doc::new("Invoke a standard library function"),
    )),
    //
    // Assets
    //
    section(
        Some("Assets"),
        Some(ASSET_NAMING),
        &[Anchor::Family("asset")],
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[
                arg("name", AssetName { glob_ok: false }, Required),
                arg("editor", Text, Optional),
            ]),
            Doc::new("Open an asset in an editor (created if it does not exist)")
                .llm("Blocks on interactive human editing; avoid unless the user asked for it"),
        )
        .alias(&["a"])
        .with_opts(&[
            flag("no_create", "If asset does not exist, do not create it"),
        ])
        .with_traits(Traits::NONE.assets().interactive()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-list"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[arg("prefix", AssetPrefix, Optional)]),
            Doc::new("List assets with the given (optional) prefix. Supports globs.")
                .user("Legend: 📁 (folder), 📥 (log), 🔒 (encrypted)"),
        )
        .alias(&["ls", "asset-ls"])
        .with_opts(&[
            flag("desc", "Sort descending"),
            flag("full", "Include asset IDs"),
        ])
        .with_traits(Traits::NONE.net()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-search"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[arg("query", Query, Rest)]),
            Doc::new("Search for assets semantically"),
        )
        .alias(&["search"])
        .with_opts(&[opt(
            "path",
            OptType::Str,
            None,
            "Specify the asset-pool to search",
        )])
        .with_traits(Traits::NONE.net()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-read"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[arg(
                "name",
                AssetName { glob_ok: false },
                Repeated { at_least: 1 },
            )]),
            Doc::new("Load assets into the conversation"),
        )
        .alias(&["read"])
        .with_opts(&[OPT_N, OPT_HQ])
        .with_traits(Traits::NONE.net()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-write"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[arg("name", AssetName { glob_ok: false }, Required)]),
            Doc::new("Create or replace an asset"),
        )
        .alias(&["write"])
        .with_opts(&[
            flag("encrypt", "Force asset to be encrypted"),
        ])
        .with_body(Body::MultiLine {
            name: "contents",
            doc: "Written to the asset verbatim",
        })
        .with_traits(Traits::NONE.assets()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-cat"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[arg(
                "name",
                AssetName { glob_ok: false },
                Repeated { at_least: 1 },
            )]),
            Doc::new("Load assets into the conversation and print them"),
        )
        .alias(&["cat"])
        .with_opts(&[OPT_N, OPT_HQ])
        .with_traits(Traits::NONE.net()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-patch"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[arg("name", AssetName { glob_ok: false }, Required)]),
            Doc::new("Apply a search/replace patch to an existing asset"),
        )
        .with_body(Body::Patch)
        .with_traits(Traits::NONE.assets()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-link"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[arg("name", AssetName { glob_ok: false }, Required)]),
            Doc::new("Print a link to an asset (valid 24hr)"),
        )
        .with_traits(Traits::NONE.net()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-revisions"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[
                arg("name", AssetName { glob_ok: false }, Required),
                arg("count", Number, Optional),
            ]),
            Doc::new("List revisions of an asset")
                .user("Without <count>, revisions are listed one at a time, waiting for input"),
        )
        .with_opts(&[OPT_N])
        .with_traits(Traits::NONE.net()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-listen"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[
                arg("name", AssetName { glob_ok: false }, Required),
                arg("cursor", Text, Optional),
            ]),
            Doc::new("Block until an asset changes, then print information about it")
                .more("If <cursor> is set, listening begins at that revision so no changes are missed"),
        )
        .with_traits(Traits::NONE.net()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-push"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[arg("name", AssetName { glob_ok: false }, Required)]),
            Doc::new("Push data as a new asset revision").more(
                "For append-only data like logs or messages. History is viewable with \
                 /asset-revisions. This is not for editing or replacing an asset.",
            ),
        )
        .with_body(Body::MultiLine {
            name: "contents",
            doc: "Stored as a new revision",
        })
        .with_traits(Traits::NONE.assets()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-import"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[
                arg("name", AssetName { glob_ok: false }, Required),
                arg("path", FilePath { accepts: FilePathAccepts::File, glob_ok: false }, Required),
            ]),
            Doc::new("Import a local path into an asset"),
        )
        .with_traits(Traits::NONE.assets()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-export"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[
                arg("name", AssetName { glob_ok: false }, Required),
                arg("path", FilePath { accepts: FilePathAccepts::File, glob_ok: false }, Required),
            ]),
            Doc::new("Export an asset to a local path"),
        )
        .with_traits(Traits::NONE.fs().net()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-temp"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[
                arg("name", AssetName { glob_ok: false }, Required),
                arg("count", Number, Optional),
            ]),
            Doc::new("Export an asset and its metadata to temporary files")
                .more("If <count> is specified, that many revisions are exported"),
        )
        .with_traits(Traits::NONE.fs().net()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-revision-temp"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[
                arg("name", AssetName { glob_ok: false }, Required),
                arg("rev-id", Text, Optional),
            ]),
            Doc::new("Export a single revision of an asset to a temporary file"),
        )
        .with_traits(Traits::NONE.fs().net()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-sync-up"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[
                arg("path", FilePath { accepts: FilePathAccepts::Any, glob_ok: false }, Required),
                arg("prefix", AssetPrefix, Required),
            ]),
            Doc::new("Sync a local path up to an asset prefix")
                .more("A trailing / on the path syncs the folder's contents (rsync semantics)"),
        )
        .with_opts(&[
            flag("new", "Whether to sync up new files (default: false)"),
            flag("dry", "Whether to perform a dry run with no changes made"),
        ])
        .with_traits(Traits::NONE.assets()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-sync-down"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[
                arg("prefix", AssetPrefix, Required),
                arg("path", FilePath { accepts: FilePathAccepts::Any, glob_ok: false }, Required),
            ]),
            Doc::new("Sync assets with a prefix down to a local path")
                .more("A trailing / on the prefix syncs the folder's contents (rsync semantics)"),
        )
        .with_traits(Traits::NONE.fs().net()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-sync-diff"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[arg("path", FilePath { accepts: FilePathAccepts::File, glob_ok: false }, Required)]),
            Doc::new("Show which assets have changed locally since the last sync-down"),
        )
        .with_traits(Traits::NONE.net()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-remove"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[arg("name", AssetName { glob_ok: true }, Required)]),
            Doc::new("Remove an asset. Supports globs.")
                .more("Removes a folder-asset but not its contents"),
        )
        .with_traits(Traits::NONE.assets()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-remove-recursive"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[arg("name", AssetName { glob_ok: true }, Required)]),
            Doc::new("Recursively remove a folder-asset and its contents. Supports globs."),
        )
        .with_traits(Traits::NONE.assets()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-move"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[
                arg("src", AssetName { glob_ok: false }, Required),
                arg("dst", AssetName { glob_ok: false }, Required),
            ]),
            Doc::new("Move an asset"),
        )
        .with_traits(Traits::NONE.assets()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-copy"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[
                arg("src", AssetName { glob_ok: false }, Required),
                arg("dst", AssetName { glob_ok: false }, Required),
            ]),
            Doc::new("Copy an asset"),
        )
        .with_traits(Traits::NONE.assets()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-acl-get"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[arg("name", AssetName { glob_ok: false }, Required)]),
            Doc::new("List the ACL on an asset"),
        )
        .with_traits(Traits::NONE.net()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-acl-get-effective"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[arg("name", AssetName { glob_ok: false }, Required)]),
            Doc::new("Show effective permissions on an asset"),
        )
        .with_traits(Traits::NONE.net()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-acl-set"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[
                arg("name", AssetName { glob_ok: false }, Required),
                arg_doc(
                    "principal",
                    Text,
                    Required,
                    "`everyone` or `user:<username>`",
                ),
                arg_doc(
                    "ace",
                    Text,
                    Required,
                    "`<effect>:<permission>` where effect is allow|deny|inherit and \
                     permission is read-data|read-revisions|write-data|push-data",
                ),
            ]),
            Doc::new("Change the ACL on an asset"),
        )
        .with_traits(Traits::NONE.assets()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-md-get"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[arg("name", AssetName { glob_ok: false }, Required)]),
            Doc::new("Get the JSON-object metadata of an asset"),
        )
        .with_traits(Traits::NONE.net()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-md-set"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[
                arg("name", AssetName { glob_ok: false }, Required),
                arg("md", Json, Rest),
            ]),
            Doc::new("Set metadata for an asset. Must be a JSON object."),
        )
        .with_traits(Traits::NONE.assets()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-md-set-key"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[
                arg("name", AssetName { glob_ok: false }, Required),
                arg("key", Text, Required),
                arg("value", Json, Rest),
            ]),
            Doc::new("Set a metadata key to a JSON value"),
        )
        .with_traits(Traits::NONE.assets()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-md-del-key"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[
                arg("name", AssetName { glob_ok: false }, Required),
                arg("key", Text, Required),
            ]),
            Doc::new("Delete a key from an asset's metadata"),
        )
        .with_traits(Traits::NONE.assets()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-folder-new"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[arg("path", AssetFolder, Required)]),
            Doc::new(
                "Create a new folder-asset to collapse subtree and add metadata, attachments, and ACLs.",
            ),
        )
        .for_audience(Audience::Both)
        .with_traits(Traits::NONE.net()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-follow"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[arg("name", AssetName { glob_ok: false }, Required)]),
            Doc::new("Follow an asset and print a message when it changes"),
        )
        .with_traits(Traits::NONE.net()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-folder-collapse"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[arg("path", AssetPrefix, Required)]),
            Doc::new(
                "[Deprecated] Collapse a folder so it appears as a single entry when listing its parent",
            ),
        )
        .for_audience(Audience::LlmOnly)
        .with_traits(Traits::NONE.net()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-folder-expand"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[arg("path", AssetPrefix, Required)]),
            Doc::new("[Deprecated] Expand a previously collapsed folder"),
        )
        .for_audience(Audience::LlmOnly)
        .with_traits(Traits::NONE.net()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-folder-list"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[arg("path", AssetPrefix, Optional)]),
            Doc::new("[Deprecated] List collapsed folders, optionally filtered by a path prefix"),
        )
        .for_audience(Audience::LlmOnly)
        .with_traits(Traits::NONE.net()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-pools"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[]),
            Doc::new("List all asset pools available to your account"),
        )
        .for_audience(Audience::Both)
        .with_traits(Traits::NONE.net().account()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-pool-new"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[arg("username", Username, Repeated { at_least: 1 })]),
            Doc::new("Create a new shared asset pool"),
        )
        .for_audience(Audience::Both)
        .with_traits(Traits::NONE.net().account()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-crypt-setup"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[]),
            Doc::new("Set up asset encryption for your account"),
        )
        .for_audience(Audience::UserOnly)
        .with_traits(Traits::NONE.net().account().interactive()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-crypt-lock"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[arg("key-id", Text, Optional)]),
            Doc::new("Lock an encryption key (a password is required on next use)"),
        )
        .for_audience(Audience::UserOnly)
        .with_traits(Traits::NONE.interactive()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-crypt-unlock"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[arg("key-id", Text, Optional)]),
            Doc::new("Unlock an encryption key (no password until locked again)"),
        )
        .for_audience(Audience::UserOnly)
        .with_traits(Traits::NONE.interactive()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-crypt-recover"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[]),
            Doc::new("Recover asset encryption keys using your recovery code"),
        )
        .for_audience(Audience::UserOnly)
        .with_traits(Traits::NONE.interactive()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("inbox-setup"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[]),
            Doc::new("Set up your inbox"),
        )
        .for_audience(Audience::UserOnly)
        .with_traits(Traits::NONE.interactive()),
    ),
    //
    // Asset-apps
    //
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-app"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[arg("name", AssetName { glob_ok: false }, Required)]),
            Doc::new("Open an asset as an app in the browser"),
        )
        .alias(&["app"])
        .with_opts(&[
            flag("no_open", "Do not open the asset in the browser"),
            opt("dev_mode", OptType::Str, None, "Local path to a vite project"),
        ])
        .with_traits(Traits::NONE.net()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-app-perms-list"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[arg("name", AssetName { glob_ok: false }, Required)]),
            Doc::new("List the permissions of an asset-app"),
        )
        .alias(&["app-perms-list"])
        .for_audience(Audience::Both)
        .with_traits(Traits::NONE.net()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-app-perms-revoke"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[arg("name", AssetName { glob_ok: false }, Required)]),
            Doc::new("Revoke the permissions granted to an asset-app"),
        )
        .alias(&["app-perms-revoke"])
        .for_audience(Audience::Both)
        .with_traits(Traits::NONE.net()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("asset-open"),
            Cow::Borrowed("asset"),
            Cow::Borrowed(&[arg("name", AssetName { glob_ok: false }, Required)]),
            Doc::new("Open an asset using metadata-specified asset-app or fallback to default editor"),
        )
        .alias(&["o", "open"])
        .for_audience(Audience::Both)
        .with_traits(Traits::NONE.net()),
    ),
    note(ATTACHMENTS_DOC, &[Anchor::Family("asset")]),
    note(ASSET_ID_DOC, &[Anchor::Family("asset")]),
    //
    // Chats
    //
    section(Some("Chats"), None, &[Anchor::Family("chat")]),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("chats"),
            Cow::Borrowed("chat"),
            Cow::Borrowed(&[]),
            Doc::new("Interactive prompt to resume a recent conversation"),
        )
        .for_audience(Audience::UserOnly)
        .with_traits(Traits::NONE.interactive().repl()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("chat-save"),
            Cow::Borrowed("chat"),
            Cow::Borrowed(&[arg("name", AssetName { glob_ok: false }, Optional)]),
            Doc::new("Save the conversation as an asset")
                .more("If the name is omitted, one is generated automatically"),
        )
        .with_opts(&[flag(
            "fork",
            "If resumed from a saved chat, create a new asset when re-saving",
        )])
        .with_traits(Traits::NONE.assets()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("chat-resume"),
            Cow::Borrowed("chat"),
            Cow::Borrowed(&[arg("name", AssetName { glob_ok: false }, Optional)]),
            Doc::new("Replace the current chat with one saved via /chat-save")
                .more("If the name is omitted, resumes the last auto-saved chat"),
        )
        .with_opts(&[flag("fork", "Re-saves will create a new asset")])
        .with_traits(Traits::NONE.net().repl()),
    ),
    //
    // Tasks
    //
    section(
        Some("Tasks"),
        Some(
            "A task is loaded from the repo (`username/task-name`) or from a file path \
             starting with `./`, `/`, or `~`.",
        ),
        &[Anchor::Family("task")],
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("task"),
            Cow::Borrowed("task"),
            Cow::Borrowed(&[arg("name-or-path", TaskRef, Required)]),
            Doc::new("Enter task mode by loading a task"),
        )
        .alias(&["t"])
        .with_opts(&[
            opt("key", OptType::Str, None, "Namespace the cache"),
            flag("trust", "Do not prompt for user confirmations"),
        ])
        .with_traits(Traits::NONE.net().repl()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("task-search"),
            Cow::Borrowed("task"),
            Cow::Borrowed(&[arg("query", Query, Rest)]),
            Doc::new("Search for tasks in the repository"),
        )
        .with_traits(Traits::NONE.net()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("task-cat"),
            Cow::Borrowed("task"),
            Cow::Borrowed(&[arg("name-or-path", TaskRef, Required)]),
            Doc::new("View a task without loading it"),
        )
        .with_traits(Traits::NONE.net()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("task-versions"),
            Cow::Borrowed("task"),
            Cow::Borrowed(&[arg("name", TaskFqn, Required)]),
            Doc::new("List all versions of a task in the repository"),
        )
        .with_traits(Traits::NONE.net()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("task-end"),
            Cow::Borrowed("task"),
            Cow::Borrowed(&[]),
            Doc::new("End task mode").user("CTRL+D works too"),
        )
        .for_audience(Audience::UserOnly)
        .with_traits(Traits::NONE.repl()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("task-update"),
            Cow::Borrowed("task"),
            Cow::Borrowed(&[arg("name", TaskFqn, Required)]),
            Doc::new("Update a task to its latest version"),
        )
        .for_audience(Audience::UserOnly)
        .with_traits(Traits::NONE.net()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("task-publish"),
            Cow::Borrowed("task"),
            Cow::Borrowed(&[arg("path", FilePath { accepts: FilePathAccepts::File, glob_ok: false }, Required)]),
            Doc::new("Publish a task to the repository").user("Requires /account-login"),
        )
        .with_traits(Traits::NONE.net().account()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("task-edit"),
            Cow::Borrowed("task"),
            Cow::Borrowed(&[arg("name", TaskFqn, Required)]),
            Doc::new("Edit a task in the repository").user("Requires /account-login"),
        )
        .for_audience(Audience::UserOnly)
        .with_traits(Traits::NONE.net().account()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("task-fetch"),
            Cow::Borrowed("task"),
            Cow::Borrowed(&[arg("name", TaskFqn, Required)]),
            Doc::new("Fetch a task from the repository"),
        )
        .for_audience(Audience::Neither)
        .with_traits(Traits::NONE.net().account()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("task-forget"),
            Cow::Borrowed("task"),
            Cow::Borrowed(&[arg("name-or-path", TaskRef, Required)]),
            Doc::new("Forget all cached data (/ask-human.cache, /prompt.cache, ...) for a task"),
        )
        .with_opts(&[
            opt("key", OptType::Str, None, "Cache namespace to forget"),
        ])
        .for_audience(Audience::UserOnly),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("task-purge"),
            Cow::Borrowed("task"),
            Cow::Borrowed(&[arg("name", TaskFqn, Required)]),
            Doc::new("Remove a task from your machine"),
        )
        .for_audience(Audience::UserOnly),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("task-include"),
            Cow::Borrowed("task"),
            Cow::Borrowed(&[arg("name-or-path", TaskRef, Required)]),
            Doc::new("Include a task's commands in the conversation without entering task mode"),
        )
        .with_traits(Traits::NONE.net().repl()),
    ),
    // Prompting
    section(None, None, &[Anchor::Family("prompt")]),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("prompt"),
            Cow::Borrowed("prompt"),
            Cow::Borrowed(&[arg("prompt", Prompt, Rest)]),
            Doc::new("Prompt LLM with new message and get a response"),
        )
        .with_opts(&[OPT_CACHE])
        .for_audience(Audience::LlmOnly),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("ask-human"),
            Cow::Borrowed("prompt"),
            Cow::Borrowed(&[arg("question", Prompt, Rest)]),
            Doc::new("Ask the user a question and add their answer to the conversation"),
        )
        .with_opts(&[
            flag("secret", "Hide input from the terminal"),
            OPT_CACHE,
        ])
        .with_traits(Traits::NONE.interactive()),
    ),
    //
    // MCP
    //
    section(
        Some("MCPs (Experimental)"),
        Some(
            "Adding a Model Context Protocol server creates a new command to invoke its \
             tools: `/mcp_<name> <tool_name> <json_arg>`.",
        ),
        &[Anchor::Family("mcp")],
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("mcp-add"),
            Cow::Borrowed("mcp"),
            Cow::Borrowed(&[
                arg("name", Text, Required),
                // Hack so that [<env>] shows up in help string.
                // Otherwise, it's indistinguishable from cmd.
                arg_doc("env", Text, Optional, "KEY=VALUE pairs"),
                arg("cmd", ShellCmd, Rest),
            ]),
            Doc::new("Add a Model Context Protocol server")
                .more("e.g. `/mcp-add git V=1 uvx -q mcp-server-git`"),
        )
        .with_traits(Traits::NONE.exec().net()),
    ),
    //
    // Bot
    //
    section(
        Some("Bot"),
        Some(
            "Your hai bot runs a persistent hai process on a separate machine.",
        ),
        &[Anchor::Family("bot")],
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("bot-boot"),
            Cow::Borrowed("bot"),
            Cow::Borrowed(&[
                arg("hai_version", Text, Optional),
            ]),
            Doc::new("Boot and setup your hai bot"),
        )
        .for_audience(Audience::Both),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("bot-get-active"),
            Cow::Borrowed("bot"),
            Cow::Borrowed(&[]),
            Doc::new("Get active bot info (ID, hostname, ...)"),
        )
        .for_audience(Audience::Both),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("bot-probe"),
            Cow::Borrowed("bot"),
            Cow::Borrowed(&[]),
            Doc::new("Connect to hai bot and query basic info"),
        )
        .for_audience(Audience::Both),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("bot-setup"),
            Cow::Borrowed("bot"),
            Cow::Borrowed(&[]),
            Doc::new("Setup hai bot machine"),
        )
        .for_audience(Audience::Both),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("bot-ssh"),
            Cow::Borrowed("bot"),
            Cow::Borrowed(&[]),
            Doc::new("SSH into your hai bot"),
        )
        .for_audience(Audience::UserOnly),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("bot-shutdown"),
            Cow::Borrowed("bot"),
            Cow::Borrowed(&[]),
            Doc::new("Shutdown your hai bot"),
        )
        .for_audience(Audience::Both),
    ),
    //
    // Messaging
    //
    section(Some("Messaging"), None, &[Anchor::Family("msg")]),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("email"),
            Cow::Borrowed("msg"),
            Cow::Borrowed(&[arg("subject", Text, Rest)]),
            Doc::new("Send an email to the default address")
                .user("Requires setup with `/task hai/add-email`"),
        )
        .with_body(Body::MultiLine {
            name: "body",
            doc: "The email body",
        })
        .with_traits(Traits::NONE.net()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("notif"),
            Cow::Borrowed("msg"),
            Cow::Borrowed(&[arg("title", Text, Rest)]),
            Doc::new("Send a push notification to the mobile app")
                .user("Requires setup with the mobile app"),
        )
        .with_body(Body::MultiLine {
            name: "body",
            doc: "The notification body",
        })
        .with_traits(Traits::NONE.net()),
    ),
    //
    // Web search
    //
    section(Some("Web Search"), None, &[Anchor::Family("web")]),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("web-search"),
            Cow::Borrowed("web"),
            Cow::Borrowed(&[arg("query", Query, Rest)]),
            Doc::new("Search the web for relevant information").llm(
                "Output is noisy for humans: follow up with /prompt (or another !hai turn) \
                 to analyze the results and produce the final answer.",
            ),
        )
        .with_opts(&[
            opt("n", OptType::Number, Some("5"), "Number of results"),
            opt("pd", OptType::Bool, None, "Results in past day"),
            opt("pw", OptType::Bool, None, "Results in past 7 days"),
            opt("pm", OptType::Bool, None, "Results in past month"),
            opt("py", OptType::Bool, None, "Results in past year"),
            opt(
                "range",
                OptType::Str,
                None,
                "Results in a date range (e.g. \"2023-01-01to2023-12-31\")",
            ),
        ])
        .with_traits(Traits::NONE.net()),
    ),
    //
    // Utils
    //
    section(Some("Utils"), None, &[Anchor::Family("utils")]),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("cost"),
            Cow::Borrowed("utils"),
            Cow::Borrowed(&[]),
            Doc::new("See the cost of the current conversation"),
        )
        .for_audience(Audience::Both)
        .with_traits(Traits::NONE.repl()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("setvar"),
            Cow::Borrowed("utils"),
            Cow::Borrowed(&[
            arg("key", Text, Required),
            arg("value", Text, Required)
            ]),
            Doc::new("Set $variable"),
        )
        .for_audience(Audience::UserOnly)
        .with_traits(Traits::NONE.account()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("printvars"),
            Cow::Borrowed("utils"),
            Cow::Borrowed(&[]),
            Doc::new("Print all $variables"),
        )
        .for_audience(Audience::UserOnly)
        .with_traits(Traits::NONE.account()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("set-mask-secrets"),
            Cow::Borrowed("utils"),
            Cow::Borrowed(&[arg("state", Enum(ONOFF), Optional)]),
            Doc::new("Mask secrets (from /ask-human.secret) in the conversation (default: off)."),
        )
        .for_audience(Audience::UserOnly)
        .with_traits(Traits::NONE.account()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("queue-pop"),
            Cow::Borrowed("utils"),
            Cow::Borrowed(&[
            arg("queue-name", Text, Required),
            ]),
            Doc::new("Pop an item from the listen queue"),
        )
        .for_audience(Audience::UserOnly)
        .with_traits(Traits::NONE.account()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("assistant"),
            Cow::Borrowed("utils"),
            Cow::Borrowed(&[
            arg("msg", Prompt, Rest),
            ]),
            Doc::new("Mock a message as the LLM assistant"),
        )
        .for_audience(Audience::UserOnly)
        .with_traits(Traits::NONE.account()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("reprint-history"),
            Cow::Borrowed("utils"),
            Cow::Borrowed(&[]),
            Doc::new("Reprint the conversation"),
        )
        .for_audience(Audience::Neither)
        .with_traits(Traits::NONE.account()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("about"),
            Cow::Borrowed("utils"),
            Cow::Borrowed(&[]),
            Doc::new("About hai"),
        )
        .for_audience(Audience::Neither)
        .with_traits(Traits::NONE.repl()),
    ),
    //
    // Debugging
    //
    section(Some("Debugging"), None, &[Anchor::Family("debug")]),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("dump"),
            Cow::Borrowed("debug"),
            Cow::Borrowed(&[]),
            Doc::new("Dump conversation history"),
        )
        .for_audience(Audience::UserOnly)
        .with_traits(Traits::NONE.repl()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("dump-session"),
            Cow::Borrowed("debug"),
            Cow::Borrowed(&[]),
            Doc::new("Dump current session state"),
        )
        .for_audience(Audience::UserOnly)
        .with_traits(Traits::NONE.repl()),
    ),
    Entry::Cmd(
        cmd(
            Slash,
            Cow::Borrowed("gateway"),
            Cow::Borrowed("debug"),
            Cow::Borrowed(&[arg("auth_token", Text, Optional)]),
            Doc::new("Start a test WebSocket gateway without an associated asset-app"),
        )
        .for_audience(Audience::Neither)
        .with_traits(Traits::NONE.net()),
    ),
    //
    //
    // Syntax
    //
    section(Some("Syntax"), None, &[]),
    note(OPTION_SYNTAX, &[]),
    note(BODY_SYNTAX, &[]),
    note(
        PATCH_FORMAT,
        &[Anchor::Exact("file-patch"), Anchor::Exact("asset-patch")],
    ),
];

// --

/// The `!'<program>' <prompt>` form isn't a named command since its name is
/// arbitrary/user-specified (no logical lookup).
///
/// It still needs a spec so `cmd_parse::parse_with_spec` can handle the tail,
/// which is what this is. Document the form in the Tools section prose.
pub const CUSTOM_TOOL_SPEC: CmdSpec = cmd(
    Bang,
    Cow::Borrowed("'<cmd>'"),
    Cow::Borrowed("tool"),
    Cow::Borrowed(&[arg("prompt", Prompt, RestOpt)]),
    Doc::new("Ask AI to write the stdin (or an input file) for an arbitrary local program")
        .user("Use a {file} or {file.ext} placeholder to get a temp file instead of stdin"),
)
.with_traits(Traits::NONE.exec());

// --

//
// Registry: static entries + runtime-injected ones
//

/// Where a dynamically-added entry should be spliced into the static registry.
#[derive(Clone, Debug)]
pub enum InsertAt {
    /// After the last command in the given family (so `/f3` lands under
    /// Function Tools, `/mcp_git` under MCPs).
    AfterFamily(String),
    /// Immediately after a specific command.
    AfterCmd(String),
    End,
}

#[derive(Clone, Debug)]
pub struct DynEntry {
    pub entry: Entry,
    pub at: InsertAt,
}

/// The static registry plus any commands injected at runtime (function tools
/// `/f<index>`, MCP servers `/mcp_<name>`, task-defined commands).
#[derive(Clone, Debug, Default)]
pub struct Registry {
    dynamic: Vec<DynEntry>,
}

impl Registry {
    pub fn new() -> Self {
        Registry {
            dynamic: Vec::new(),
        }
    }

    /// Add a dynamic entry (section, note, or cmd)
    pub fn add(&mut self, entry: Entry, at: InsertAt) {
        self.dynamic.push(DynEntry { entry, at });
    }

    /// Add a dynamic command
    pub fn add_cmd(&mut self, c: CmdSpec, at: InsertAt) {
        self.add(Entry::Cmd(c), at);
    }

    /// Remove dynamic commands whose canonical name matches `pred`.
    pub fn remove_cmds<F: Fn(&CmdSpec) -> bool>(&mut self, pred: F) {
        self.dynamic.retain(|d| match &d.entry {
            Entry::Cmd(c) => !pred(c),
            _ => true,
        });
    }

    /// Remove dynamic command
    pub fn remove_cmd_by_name(&mut self, name: &str) {
        self.dynamic.retain(|d| match &d.entry {
            Entry::Cmd(cmd_spec) => cmd_spec.name != name,
            _ => true,
        });
    }

    pub fn clear_dynamic(&mut self) {
        self.dynamic.clear();
    }

    /// The full, ordered entry list with dynamic entries spliced in.
    pub fn entries(&self) -> Vec<Entry> {
        let mut out: Vec<Entry> = REGISTRY.to_vec();

        // Splice in reverse-resolution order so multiple inserts at the same
        // anchor keep their relative order.
        let mut tail: Vec<Entry> = Vec::new();
        for d in &self.dynamic {
            let pos = match &d.at {
                InsertAt::End => None,
                InsertAt::AfterCmd(name) => out.iter().position(|e| match e {
                    Entry::Cmd(c) => c.name == name.as_str(),
                    _ => false,
                }),
                InsertAt::AfterFamily(fam) => out.iter().rposition(|e| match e {
                    Entry::Cmd(c) => c.family == fam.as_str(),
                    _ => false,
                }),
            };
            match pos {
                Some(i) => out.insert(i + 1, d.entry.clone()),
                None => tail.push(d.entry.clone()),
            }
        }
        out.extend(tail);
        out
    }

    /// All commands, static and dynamic, in registry order.
    pub fn cmds(&self) -> Vec<CmdSpec> {
        self.entries()
            .into_iter()
            .filter_map(|e| match e {
                Entry::Cmd(c) => Some(c),
                _ => None,
            })
            .collect()
    }

    /// All commands by reference, **unordered** (statics then dynamics).
    ///
    /// Prefer this over `cmds()` for lookups and scans: `cmds()` clones the
    /// whole table just to splice dynamic entries into their display position,
    /// which only `/help` and the tool schema actually care about.
    pub fn iter_cmds(&self) -> impl Iterator<Item = &CmdSpec> {
        let statics = REGISTRY.iter();
        let dynamics = self.dynamic.iter().map(|d| &d.entry);
        statics.chain(dynamics).filter_map(|e| match e {
            Entry::Cmd(c) => Some(c),
            _ => None,
        })
    }

    pub fn lookup(&self, sigil: Sigil, bare_name: &str) -> Option<CmdSpec> {
        self.cmds()
            .into_iter()
            .find(|c| c.sigil == sigil && c.matches_name(bare_name))
    }

    /// Look up by a full invocation such as `"/asset-list"` or `"!sh"`.
    pub fn lookup_invocation(&self, invocation: &str) -> Option<CmdSpec> {
        let (sigil, bare) = split_sigil(invocation)?;
        self.lookup(sigil, bare.split('.').next().unwrap_or(bare))
    }
}

pub fn split_sigil(s: &str) -> Option<(Sigil, &str)> {
    match s.chars().next()? {
        '/' => Some((Sigil::Slash, &s[1..])),
        '!' => Some((Sigil::Bang, &s[1..])),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Filtering
// ---------------------------------------------------------------------------

/// Selects a subset of the registry. `include`/`exclude` patterns match a
/// command's name or any alias, and may end in `*`.
#[derive(Clone, Debug)]
pub struct Filter {
    pub who: Who,
    /// `None` means everything.
    pub include: Option<Vec<String>>,
    pub exclude: Vec<String>,
    pub deny: DenyTraits,
}

impl Filter {
    pub fn user() -> Self {
        Filter {
            who: Who::User,
            include: None,
            exclude: Vec::new(),
            deny: DenyTraits::NONE,
        }
    }

    pub fn llm() -> Self {
        Filter {
            who: Who::Llm,
            include: None,
            exclude: Vec::new(),
            deny: DenyTraits {
                interactive: false,
                ..DenyTraits::NONE
            },
        }
    }

    #[allow(dead_code)]
    pub fn including(mut self, pats: &[&str]) -> Self {
        self.include = Some(pats.iter().map(|s| s.to_string()).collect());
        self
    }

    #[allow(dead_code)]
    pub fn excluding(mut self, pats: &[&str]) -> Self {
        self.exclude = pats.iter().map(|s| s.to_string()).collect();
        self
    }

    #[allow(dead_code)]
    pub fn denying(mut self, deny: DenyTraits) -> Self {
        self.deny = deny;
        self
    }

    pub fn keeps(&self, c: &CmdSpec) -> bool {
        if !c.audience.shows_to(self.who) {
            return false;
        }
        if self.deny.rejects(&c.traits) {
            return false;
        }
        let names: Vec<&str> = std::iter::once(c.name.as_ref())
            .chain(c.aliases.iter().copied())
            .collect();
        if self
            .exclude
            .iter()
            .any(|p| names.iter().any(|n| glob_match(p, n)))
        {
            return false;
        }
        match &self.include {
            None => true,
            Some(inc) => inc.iter().any(|p| names.iter().any(|n| glob_match(p, n))),
        }
    }
}

fn glob_match(pat: &str, name: &str) -> bool {
    match pat.strip_suffix('*') {
        Some(p) => name.starts_with(p),
        None => pat == name,
    }
}

/// Select entries in registry order.
///
/// Sections and Notes survive only if one of their anchors matched a surviving
/// command; anchor-less prose survives if anything at all survived. Sections
/// that end up with no commands beneath them are dropped.
pub fn select(reg: &Registry, f: &Filter) -> Vec<Entry> {
    let all = reg.entries();

    let kept: Vec<&CmdSpec> = all
        .iter()
        .filter_map(|e| match e {
            Entry::Cmd(c) if f.keeps(c) => Some(c),
            _ => None,
        })
        .collect();

    if kept.is_empty() {
        return Vec::new();
    }

    let anchored = |anchors: &[Anchor], aud: Audience| -> bool {
        aud.shows_to(f.who)
            && (anchors.is_empty() || kept.iter().any(|c| anchors.iter().any(|a| a.matches(c))))
    };

    let mut out: Vec<Entry> = Vec::new();
    for e in &all {
        let keep = match e {
            Entry::Cmd(c) => f.keeps(c),
            Entry::Note(n) => anchored(n.anchors, n.audience),
            Entry::Section(s) => anchored(s.anchors, s.audience),
        };
        if keep {
            out.push(e.clone());
        }
    }

    prune_empty_sections(out)
}

/// Drop a Section if no Cmd appears between it and the next Section.
fn prune_empty_sections(entries: Vec<Entry>) -> Vec<Entry> {
    let mut keep = vec![true; entries.len()];
    for (i, e) in entries.iter().enumerate() {
        if let Entry::Section(_) = e {
            let has_cmd = entries[i + 1..]
                .iter()
                .take_while(|e| !matches!(e, Entry::Section(_)))
                .any(|e| matches!(e, Entry::Cmd(_)));
            if !has_cmd {
                keep[i] = false;
            }
        }
    }
    entries
        .into_iter()
        .zip(keep)
        .filter_map(|(e, k)| if k { Some(e) } else { None })
        .collect()
}

// --

//
// Rendering
//

const HELP_COL: usize = 31;
const WRAP_WIDTH: usize = 80;

fn wrap(text: &str, width: usize, indent: &str) -> String {
    let mut out = String::new();
    for para in text.split('\n') {
        if para.trim().is_empty() {
            out.push('\n');
            continue;
        }
        // Preserve pre-indented lines (code samples) verbatim.
        if para.starts_with("    ") {
            out.push_str(indent);
            out.push_str(para);
            out.push('\n');
            continue;
        }
        let mut line = String::new();
        for word in para.split_whitespace() {
            if !line.is_empty() && line.len() + 1 + word.len() > width {
                out.push_str(indent);
                out.push_str(&line);
                out.push('\n');
                line.clear();
            }
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(word);
        }
        if !line.is_empty() {
            out.push_str(indent);
            out.push_str(&line);
            out.push('\n');
        }
    }
    out
}

pub fn render_opt(o: &Opt) -> String {
    let ty = match o.ty {
        OptType::Enum(v) => v.join("|"),
        other => other.label().to_string(),
    };
    match o.default {
        Some(d) => format!(".{}={} {} (default: {})", o.name, ty, o.doc, d),
        None => format!(".{}={} {}", o.name, ty, o.doc),
    }
}

/// The `/help` output.
pub fn render_help(reg: &Registry, f: &Filter) -> String {
    let mut o = String::new();
    let pad = " ".repeat(HELP_COL);
    let mut first = true;

    for e in select(reg, f) {
        match e {
            Entry::Section(s) => {
                if !first {
                    o.push_str("\n");
                }
                if let Some(t) = s.title {
                    o.push_str(&"=".repeat(HELP_COL));
                    o.push_str("  ");
                    o.push_str(&t.to_uppercase());
                    o.push_str("\n\n");
                }
                if let Some(b) = s.blurb {
                    o.push_str(&wrap(b, WRAP_WIDTH, ""));
                    o.push('\n');
                }
            }
            Entry::Note(n) => {
                o.push('\n');
                o.push_str(&wrap(n.blurb, WRAP_WIDTH, ""));
            }
            Entry::Cmd(c) => {
                let usage = c.usage();
                if usage.len() < HELP_COL {
                    o.push_str(&format!(
                        "{:<width$}- {}\n",
                        usage,
                        c.doc.summary,
                        width = HELP_COL
                    ));
                } else {
                    o.push_str(&format!("{}\n{}- {}\n", usage, pad, c.doc.summary));
                }
                if let Some(extra) = c.doc.extra_for(Who::User) {
                    for line in extra.lines() {
                        o.push_str(&format!("{}  {}\n", pad, line.trim()));
                    }
                }
                for a in c.args.iter() {
                    if let Some(d) = a.doc {
                        o.push_str(&format!("{}  <{}> {}\n", pad, a.name, d));
                    }
                    match a.kind {
                        ArgKind::Sub(sub_cmds) => {
                            for sub_cmd in sub_cmds {
                                let mut sub_cmd_line = String::new();
                                sub_cmd_line.push_str(&format!(
                                    "{}  <{}> subcommand: {}",
                                    pad, a.name, sub_cmd.name
                                ));
                                for sub_arg in sub_cmd.args.iter() {
                                    sub_cmd_line.push_str(&format!(" <{}>", sub_arg.name));
                                }
                                sub_cmd_line.push_str(&format!(" -- {}\n", sub_cmd.doc.summary));
                                o.push_str(&sub_cmd_line);
                            }
                        }
                        ArgKind::Enum(variants) => {
                            let variants_str = variants.join("|");
                            o.push_str(&format!("{}  <{}> enum: {}\n", pad, a.name, variants_str));
                        }
                        _ => {}
                    }
                }
                for opt in c.opts.iter() {
                    o.push_str(&format!("{}  {}\n", pad, render_opt(opt)));
                }
                if let Body::MultiLine { name, doc } = c.body {
                    o.push_str(&format!(
                        "{}  <multi-line {}> on the following lines. {}\n",
                        pad, name, doc
                    ));
                }
            }
        }
        first = false;
    }
    o
}

/// The command list embedded in the `hai-repl` tool schema.
///
/// Kept deliberately tighter than `/help`: no column alignment, no ANSI, and
/// only `llm_extra` prose. Run your tokenizer over the result to report the
/// schema's token cost.
pub fn render_llm(reg: &Registry, f: &Filter) -> String {
    let mut o = String::new();

    for e in select(reg, f) {
        match e {
            Entry::Section(s) => {
                o.push('\n');
                if let Some(t) = s.title {
                    o.push_str(&format!("## {}\n\n", t));
                }
                if let Some(b) = s.blurb {
                    o.push_str(&wrap(b, WRAP_WIDTH, ""));
                    o.push('\n');
                }
            }
            Entry::Note(n) => {
                o.push('\n');
                o.push_str(&wrap(n.blurb, WRAP_WIDTH, ""));
            }
            Entry::Cmd(c) => {
                o.push_str(&format!("{} -- {}\n", c.usage(), c.doc.summary));
                if let Some(extra) = c.doc.extra_for(Who::Llm) {
                    o.push_str(&wrap(extra, WRAP_WIDTH - 4, "    "));
                }
                for a in c.args.iter() {
                    if let Some(d) = a.doc {
                        o.push_str(&format!("    <{}>: {}\n", a.name, d));
                    }
                }
                for opt in c.opts.iter() {
                    o.push_str(&format!("    {}\n", render_opt(opt)));
                }
                if let Body::MultiLine { name, doc } = c.body {
                    o.push_str(&format!(
                        "    <multi-line {}> follows on subsequent lines. {}\n",
                        name, doc
                    ));
                }
            }
        }
    }
    o
}

// --

//
// Tab completion
//

/// What the completer determined the cursor is sitting on. The caller resolves
/// the result against the filesystem, the asset index, etc.
#[derive(Clone, Debug)]
pub enum Completion {
    /// The command word itself
    Command {
        prefix: String,
        candidates: Vec<CmdSpec>,
    },
    /// Part after `/<cmd>.`
    OptName {
        #[allow(dead_code)]
        cmd: CmdSpec,
        prefix: String,
        candidates: Vec<Opt>,
    },
    /// Part after `/<cmd>.<opt>=`
    OptValue {
        #[allow(dead_code)]
        cmd: CmdSpec,
        #[allow(dead_code)]
        opt: Opt,
        prefix: String,
        candidates: Vec<&'static str>,
    },
    /// A positional argument
    Arg {
        cmd: CmdSpec,
        /// Index into `cmd.args` (a trailing Repeated/Rest arg absorbs
        /// everything past its own position).
        #[allow(dead_code)]
        index: usize,
        kind: ArgKind,
        prefix: String,
    },
    /// Inside a ShellCmd rest-arg. The caller resolves `ShellWord::Program`
    /// against $PATH and `ShellWord::Path` against the filesystem.
    Shell {
        #[allow(dead_code)]
        cmd: CmdSpec,
        word: ShellWord,
        prefix: String,
    },
    /// No completion (free text area, e.g. prompt or multi-line body)
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShellWord {
    /// First word of the shell command -> complete against $PATH.
    Program,
    /// Any later word -> complete as a file path.
    Path,
    /// A word starting with `@@` -> complete against the asset index.
    AssetName,
}

#[derive(Debug)]
struct Token {
    text: String,
}

/// Quote-aware split. If the input ends in unquoted whitespace, a trailing empty
/// token is emitted so the caller knows a new word has begun.
fn tokenize(s: &str) -> Vec<Token> {
    let mut toks = Vec::new();
    let mut cur = String::new();
    let mut started = false;
    let mut quote: Option<char> = None;
    let mut escaped = false;

    for ch in s.chars() {
        if escaped {
            cur.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' => {
                escaped = true;
                started = true;
            }
            '"' | '\'' => {
                started = true;
                match quote {
                    Some(q) if q == ch => quote = None,
                    Some(_) => cur.push(ch),
                    None => quote = Some(ch),
                }
            }
            c if c.is_whitespace() && quote.is_none() => {
                if started {
                    toks.push(Token { text: cur.clone() });
                    cur.clear();
                    started = false;
                }
            }
            c => {
                cur.push(c);
                started = true;
            }
        }
    }
    // Always push the final token, even if empty, so "cmd " yields a blank
    // trailing token meaning "starting a new argument".
    toks.push(Token { text: cur });
    toks
}

/// Complete the dotted-option portion of a command word.
fn complete_opts(cmd: &CmdSpec, optpart: &str) -> Completion {
    // The segment under the cursor is everything after the last '.'.
    let seg = optpart.rsplit('.').next().unwrap_or("");
    match seg.split_once('=') {
        Some((name, val)) => match cmd.find_opt(name) {
            Some(o) => {
                let candidates: Vec<&'static str> = match o.ty {
                    OptType::Bool => vec!["true", "false"],
                    OptType::Enum(v) => v.to_vec(),
                    _ => vec![],
                };
                let candidates = candidates
                    .into_iter()
                    .filter(|c| c.starts_with(val))
                    .collect();
                Completion::OptValue {
                    cmd: cmd.clone(),
                    opt: *o,
                    prefix: val.to_string(),
                    candidates,
                }
            }
            None => Completion::None,
        },
        None => {
            // Don't re-offer options already present in the word.
            let used: Vec<&str> = optpart
                .split('.')
                .map(|s| s.split('=').next().unwrap_or(""))
                .collect();
            let candidates: Vec<Opt> = cmd
                .opts
                .iter()
                .filter(|o| o.name.starts_with(seg))
                .filter(|o| o.name == seg || !used.contains(&o.name))
                .cloned()
                .collect();
            Completion::OptName {
                cmd: cmd.clone(),
                prefix: seg.to_string(),
                candidates,
            }
        }
    }
}

/// Given the text of the current line up to `cursor`, decide what to complete.
///
/// The caller needs to match on the completion type to decide how to provide
/// candidates. Moreover, certain completion variants require additional
/// discrimination (e.g. `ArgKind`).
pub fn complete(reg: &Registry, line: &str, cursor: usize) -> Completion {
    let cursor = cursor.min(line.len());
    let head = &line[..cursor];

    // No completion once inside a multi-line body.
    if head.contains('\n') {
        return Completion::None;
    }

    let trimmed = head.trim_start();
    if !(trimmed.starts_with('/') || trimmed.starts_with('!')) {
        // It's a prompt -> no completion
        return Completion::None;
    }

    // HACK for custom-tool: !'<prog>' <prompt>
    // Handle before tokenize since it doesn't know about the single-quote
    // syntax.
    if let Some(after_bang) = trimmed.strip_prefix('!')
        && let Some(rest) = after_bang.strip_prefix('\'')
    {
        return match rest.find('\'') {
            // No closing quote yet so auto-complete program name
            None => Completion::Shell {
                cmd: CUSTOM_TOOL_SPEC.clone(),
                word: ShellWord::Program,
                prefix: rest.to_string(),
            },
            // Single-quote already closed (prompt text)
            Some(_) => Completion::None,
        };
    }

    let toks = tokenize(trimmed);
    let word = toks.last().map(|t| t.text.as_str()).unwrap_or("");

    //
    // Determine command word + options
    //

    // Command word (or options) are not complete, provide suggestions
    if toks.len() == 1 {
        let Some((sigil, rest)) = split_sigil(word) else {
            return Completion::None;
        };
        return match rest.split_once('.') {
            None => {
                let candidates: Vec<CmdSpec> = reg
                    .cmds()
                    .into_iter()
                    .filter(|c| {
                        c.sigil == sigil
                            && (c.name.starts_with(rest)
                                || c.aliases.iter().any(|a| a.starts_with(rest)))
                    })
                    .collect();
                Completion::Command {
                    prefix: rest.to_string(),
                    candidates,
                }
            }
            Some((name, optpart)) => match reg.lookup(sigil, name) {
                Some(c) => complete_opts(&c, optpart),
                None => Completion::None,
            },
        };
    }

    //
    // Extract completed command word
    //
    let Some((sigil, rest)) = split_sigil(&toks[0].text) else {
        return Completion::None;
    };
    let name = rest.split('.').next().unwrap_or(rest);
    let Some(cmd) = reg.lookup(sigil, name) else {
        return Completion::None;
    };

    let arg_index = toks.len() - 2;
    let Some((slot, kind)) = cmd.arg_at(arg_index).map(|(i, a)| (i, a.kind)) else {
        // More tokens than defined args, and the last arg isn't variadic.
        return Completion::None;
    };

    match kind {
        // Nested command tables (/std functions)
        ArgKind::Sub(table) => {
            let candidates: Vec<CmdSpec> = table
                .iter()
                .filter(|c| {
                    c.name.starts_with(word) || c.aliases.iter().any(|x| x.starts_with(word))
                })
                .cloned()
                .collect();
            Completion::Command {
                prefix: word.to_string(),
                candidates,
            }
        }
        // Shell command rest-arg: tokenize it further (in greater detail) to
        // make it easier to implement auto complete.
        ArgKind::ShellCmd => {
            let start = rest_arg_start(head);
            let shell_body = &head[start..];

            let shell_toks = tokenize(shell_body);
            let cur = shell_toks.last().map(|t| t.text.as_str()).unwrap_or("");

            // `@@name` overrides positional hint and is always an asset name.
            if let Some(asset_prefix) = cur.strip_prefix("@@") {
                return Completion::Shell {
                    cmd,
                    word: ShellWord::AssetName,
                    prefix: asset_prefix.to_string(),
                };
            }

            let shell_word = if shell_toks.len() <= 1 {
                ShellWord::Program
            } else {
                ShellWord::Path
            };

            Completion::Shell {
                cmd,
                word: shell_word,
                prefix: cur.to_string(),
            }
        }
        // Rest-args that are free text have nothing to offer.
        k if k.is_free_text() => Completion::None,
        k => Completion::Arg {
            cmd,
            index: slot,
            kind: k,
            prefix: word.to_string(),
        },
    }
}

/// Byte offset in `head` just past the first whitespace-delimited word
fn rest_arg_start(head: &str) -> usize {
    let trimmed_start = head.len() - head.trim_start().len();
    let after_cmd = head[trimmed_start..]
        .find(char::is_whitespace)
        .map(|i| trimmed_start + i)
        .unwrap_or(head.len());
    // Skip the whitespace between the command word and the shell body.
    let ws_end = head[after_cmd..]
        .find(|c: char| !c.is_whitespace())
        .map(|i| after_cmd + i)
        .unwrap_or(head.len());
    ws_end
}

// --

#[cfg(test)]
mod tests {
    use super::*;

    fn reg() -> Registry {
        Registry::new()
    }

    #[test]
    fn names_are_unique_per_sigil() {
        let cmds = reg().cmds();
        let mut seen: Vec<(Sigil, String)> = Vec::new();
        for c in cmds.iter() {
            for n in std::iter::once(c.name.as_ref()).chain(c.aliases.iter().copied()) {
                let key = (c.sigil, n.to_string());
                assert!(
                    !seen.contains(&key),
                    "duplicate command name: {}{}",
                    c.sigil.ch(),
                    n
                );
                seen.push(key);
            }
        }
    }

    #[test]
    fn summaries_are_single_line_and_short() {
        for c in reg().cmds() {
            assert!(
                !c.doc.summary.contains('\n'),
                "{} summary is multi-line",
                c.name
            );
            assert!(
                c.doc.summary.len() <= 88,
                "{} summary too long ({})",
                c.name,
                c.doc.summary.len()
            );
        }
    }

    #[test]
    fn variadic_args_are_last() {
        for c in reg().cmds() {
            for (i, a) in c.args.iter().enumerate() {
                if matches!(a.arity, Arity::Rest | Arity::Repeated { .. }) {
                    assert_eq!(
                        i,
                        c.args.len() - 1,
                        "{}: variadic arg <{}> is not last",
                        c.name,
                        a.name
                    );
                }
            }
        }
    }

    #[test]
    fn optional_args_follow_required_ones() {
        for c in reg().cmds() {
            let mut seen_optional = false;
            for a in c.args.iter() {
                match a.arity {
                    Arity::Required => assert!(
                        !seen_optional,
                        "{}: required arg <{}> follows an optional one",
                        c.name, a.name
                    ),
                    Arity::Optional => seen_optional = true,
                    _ => {}
                }
            }
        }
    }

    #[test]
    fn asset_filter_drags_along_asset_prose() {
        let f = Filter::user().including(&["asset*", "ls", "cat", "a"]);
        let out = select(&reg(), &f);

        let has_section = out.iter().any(|e| {
            matches!(
                e, Entry::Section(s) if s.title == Some("Assets")
            )
        });
        let has_attachments = out
            .iter()
            .any(|e| matches!(e, Entry::Note(n) if n.blurb == ATTACHMENTS_DOC));
        let has_ids = out
            .iter()
            .any(|e| matches!(e, Entry::Note(n) if n.blurb == ASSET_ID_DOC));
        let has_patch = out
            .iter()
            .any(|e| matches!(e, Entry::Note(n) if n.blurb == PATCH_FORMAT));

        assert!(has_section, "Assets section missing");
        assert!(has_attachments, "attachments note missing");
        assert!(has_ids, "asset-id note missing");
        assert!(has_patch, "patch note missing (asset-patch survived)");

        // No unrelated commands leaked in.
        assert!(
            !out.iter()
                .any(|e| matches!(e, Entry::Cmd(c) if c.family == "task"))
        );
    }

    #[test]
    fn file_filter_excludes_asset_prose() {
        let f = Filter::user().including(&["file*"]);
        let out = select(&reg(), &f);
        assert!(
            !out.iter()
                .any(|e| matches!(e, Entry::Note(n) if n.blurb == ATTACHMENTS_DOC))
        );
        // Check the patch note stays, since /file-patch survived.
        assert!(
            out.iter()
                .any(|e| matches!(e, Entry::Note(n) if n.blurb == PATCH_FORMAT))
        );
    }

    #[test]
    fn empty_sections_are_pruned() {
        let f = Filter::user().including(&["file*"]);
        let out = select(&reg(), &f);
        assert!(!out.iter().any(|e| matches!(
            e, Entry::Section(s) if s.title == Some("Tasks")
        )));
    }

    #[test]
    fn usage_lines() {
        let r = reg();
        let ls = r.lookup(Sigil::Slash, "ls").unwrap();
        assert_eq!(ls.usage(), "/ls /asset-ls /asset-list [<prefix>]");

        let read = r.lookup(Sigil::Slash, "asset-read").unwrap();
        assert_eq!(read.usage(), "/read /asset-read <name> [<name> ...]");

        let write = r.lookup(Sigil::Slash, "file-write").unwrap();
        assert_eq!(write.usage(), "/file-write <path> <multi-line contents>");
    }

    #[test]
    fn complete_command_names() {
        let r = reg();
        match complete(&r, "/asset-li", 9) {
            Completion::Command { prefix, candidates } => {
                assert_eq!(prefix, "asset-li");
                assert!(candidates.iter().any(|c| c.name == "asset-list"));
                assert!(candidates.iter().any(|c| c.name == "asset-link"));
            }
            other => panic!("expected Command, got {:?}", other),
        }
    }

    #[test]
    fn complete_alias() {
        let r = reg();
        match complete(&r, "/l", 2) {
            Completion::Command { candidates, .. } => {
                assert!(candidates.iter().any(|c| c.name == "asset-list"));
            }
            other => panic!("expected Command, got {:?}", other),
        }
    }

    #[test]
    fn complete_option_name_and_value() {
        let r = reg();
        match complete(&r, "/file-cat.", 10) {
            Completion::OptName { candidates, .. } => {
                assert!(candidates.iter().any(|o| o.name == "n"));
                assert!(candidates.iter().any(|o| o.name == "hq"));
            }
            other => panic!("expected OptName, got {:?}", other),
        }
        match complete(&r, "/file-cat.n=t", 13) {
            Completion::OptValue {
                prefix, candidates, ..
            } => {
                assert_eq!(prefix, "t");
                assert_eq!(candidates, vec!["true"]);
            }
            other => panic!("expected OptValue, got {:?}", other),
        }
        // Already-used options aren't re-offered.
        match complete(&r, "/file-cat.n=true.", 17) {
            Completion::OptName { candidates, .. } => {
                assert!(candidates.iter().any(|o| o.name == "hq"));
                assert!(!candidates.iter().any(|o| o.name == "n"));
            }
            other => panic!("expected OptName, got {:?}", other),
        }
    }

    #[test]
    fn complete_args_by_kind() {
        let r = reg();
        let line = "/file-cat src/ma";
        match complete(&r, line, line.len()) {
            Completion::Arg { kind, prefix, .. } => {
                assert_eq!(
                    kind,
                    ArgKind::FilePath {
                        accepts: FilePathAccepts::File,
                        glob_ok: true
                    }
                );
                assert_eq!(prefix, "src/ma");
            }
            other => panic!("expected Arg, got {:?}", other),
        }

        // Options on the command word don't disturb argument resolution.
        let line = "/file-cat.n=true src/ma";
        match complete(&r, line, line.len()) {
            Completion::Arg { kind, .. } => {
                assert_eq!(
                    kind,
                    ArgKind::FilePath {
                        accepts: FilePathAccepts::File,
                        glob_ok: true
                    }
                )
            }
            other => panic!("expected Arg, got {:?}", other),
        }

        // Second positional of /asset-import is a local path.
        let line = "/asset-import my/asset ./loc";
        match complete(&r, line, line.len()) {
            Completion::Arg { kind, index, .. } => {
                assert_eq!(
                    kind,
                    ArgKind::FilePath {
                        accepts: FilePathAccepts::File,
                        glob_ok: false
                    }
                );
                assert_eq!(index, 1);
            }
            other => panic!("expected Arg, got {:?}", other),
        }

        // A trailing Repeated arg absorbs later positions.
        let line = "/asset-read one two thr";
        match complete(&r, line, line.len()) {
            Completion::Arg { kind, index, .. } => {
                assert_eq!(kind, ArgKind::AssetName { glob_ok: false });
                assert_eq!(index, 0);
            }
            other => panic!("expected Arg, got {:?}", other),
        }
    }

    #[test]
    fn complete_subcommands() {
        let r = reg();
        let line = "/std n";
        match complete(&r, line, line.len()) {
            Completion::Command { candidates, .. } => {
                assert!(candidates.iter().any(|c| c.name == "now"));
                assert!(candidates.iter().any(|c| c.name == "new-day-alert"));
            }
            other => panic!("expected Command, got {:?}", other),
        }
    }

    #[test]
    fn complete_shell_program_then_paths() {
        let r = reg();

        // First word -> program completion.
        let line = "/exec gi";
        match complete(&r, line, line.len()) {
            Completion::Shell { word, prefix, .. } => {
                assert_eq!(word, ShellWord::Program);
                assert_eq!(prefix, "gi");
            }
            o => panic!("expected Shell/Program, got {:?}", o),
        }

        // Second word -> path completion.
        let line = "/exec cat src/ma";
        match complete(&r, line, line.len()) {
            Completion::Shell { word, prefix, .. } => {
                assert_eq!(word, ShellWord::Path);
                assert_eq!(prefix, "src/ma");
            }
            o => panic!("expected Shell/Path, got {:?}", o),
        }

        // Options on the command word don't disturb shell tokenization.
        let line = "/exec.i cat foo";
        match complete(&r, line, line.len()) {
            Completion::Shell { word, prefix, .. } => {
                assert_eq!(word, ShellWord::Path);
                assert_eq!(prefix, "foo");
            }
            o => panic!("expected Shell/Path, got {:?}", o),
        }
    }

    #[test]
    fn complete_shell_asset_refs() {
        let r = reg();

        // @@ in the argument slot.
        let line = "/exec cat @@my/ass";
        match complete(&r, line, line.len()) {
            Completion::Shell { word, prefix, .. } => {
                assert_eq!(word, ShellWord::AssetName);
                assert_eq!(prefix, "my/ass"); // @@ stripped
            }
            o => panic!("expected Shell/AssetName, got {:?}", o),
        }

        // @@ even in the program slot (e.g. running a downloaded script).
        let line = "/exec @@scr";
        match complete(&r, line, line.len()) {
            Completion::Shell { word, prefix, .. } => {
                assert_eq!(word, ShellWord::AssetName);
                assert_eq!(prefix, "scr");
            }
            o => panic!("expected Shell/AssetName, got {:?}", o),
        }

        // Bare @@ offers all assets.
        let line = "/exec cat @@";
        match complete(&r, line, line.len()) {
            Completion::Shell { word, prefix, .. } => {
                assert_eq!(word, ShellWord::AssetName);
                assert_eq!(prefix, "");
            }
            o => panic!("expected Shell/AssetName, got {:?}", o),
        }

        // Redirect target `> @@out` also completes as asset
        let line = "/exec echo hi > @@out";
        match complete(&r, line, line.len()) {
            Completion::Shell { word, prefix, .. } => {
                assert_eq!(word, ShellWord::AssetName);
                assert_eq!(prefix, "out");
            }
            o => panic!("expected Shell/AssetName, got {:?}", o),
        }
    }

    #[test]
    fn complete_custom_tool_program() {
        let r = reg();

        // Inside the quotes, mid-name.
        match complete(&r, "!'gi", 4) {
            Completion::Shell { word, prefix, .. } => {
                assert_eq!(word, ShellWord::Program);
                assert_eq!(prefix, "gi")
            }
            o => panic!("expected Shell/Program, got {:?}", o),
        }

        // Just opened the quote -> empty prefix (all programs).
        match complete(&r, "!'", 2) {
            Completion::Shell { word, prefix, .. } => {
                assert_eq!(word, ShellWord::Program);
                assert_eq!(prefix, "")
            }
            o => panic!("expected Shell/Program, got {:?}", o),
        }

        // Closing quote present -> now in prompt text, no completion.
        let line = "!'git' commit the";
        assert!(matches!(complete(&r, line, line.len()), Completion::None));

        // Bare closing quote, nothing after.
        assert!(matches!(complete(&r, "!'git'", 6), Completion::None));
    }

    #[test]
    fn no_completion_for_prompts_or_bodies() {
        let r = reg();
        assert!(matches!(complete(&r, "what is rust", 12), Completion::None));
        let line = "/prompt tell me about ";
        assert!(matches!(complete(&r, line, line.len()), Completion::None));
        let line = "/file-write foo.txt\nsome content";
        assert!(matches!(complete(&r, line, line.len()), Completion::None));
    }

    #[test]
    fn dynamic_commands_are_injected_in_place() {
        let mut r = Registry::new();
        r.add_cmd(
            cmd(
                Sigil::Slash,
                Cow::Borrowed("f1"),
                Cow::Borrowed("fn-tool"),
                vec![arg("arg", ArgKind::Text, Arity::Rest)].into(),
                Doc::new("Invoke AI-defined function 1"),
            ),
            InsertAt::AfterFamily("fn-tool".to_string()),
        );

        let cmds = r.cmds();
        let f1 = cmds.iter().position(|c| c.name == "f1").unwrap();
        let fns = cmds.iter().position(|c| c.name == "fns").unwrap();
        let asset = cmds.iter().position(|c| c.name == "asset-list").unwrap();
        assert!(f1 > fns, "f1 should land after the static fn commands");
        assert!(f1 < asset, "f1 should land before the asset commands");

        assert!(r.lookup(Sigil::Slash, "f1").is_some());
        match complete(&r, "/f", 2) {
            Completion::Command { candidates, .. } => {
                assert!(candidates.iter().any(|c| c.name == "f1"));
            }
            other => panic!("expected Command, got {:?}", other),
        }

        r.remove_cmds(|c| c.name == "f1");
        assert!(r.lookup(Sigil::Slash, "f1").is_none());
    }

    #[test]
    fn deny_traits_shrink_the_llm_surface() {
        let r = reg();
        let f = Filter::llm().denying(DenyTraits {
            executes: true,
            ..DenyTraits::NONE
        });
        let kept: Vec<CmdSpec> = r.cmds().into_iter().filter(|c| f.keeps(c)).collect();
        assert!(!kept.iter().any(|c| c.name == "exec"));
        assert!(!kept.iter().any(|c| c.name == "sh"));
        assert!(kept.iter().any(|c| c.name == "asset-list"));
    }

    #[test]
    fn renderers_produce_output() {
        let r = reg();
        let help = render_help(&r, &Filter::user());
        assert!(help.contains("/ls /asset-ls /asset-list"));
        assert!(help.contains("Show this help menu"));

        let llm = render_llm(&r, &Filter::llm());
        assert!(llm.contains("/asset-list"));
        // User-only commands stay out of the tool schema.
        assert!(!llm.contains("Show this help menu"));
    }
}
