# Assets

Assets are data objects stored in the cloud with a filesystem-like interface.
In addition to basic blob storage, there are additional conveniences for you
and your LLM: syncing changed data down, listening for changes to assets,
temporarily making assets available locally, and revision control.

## Create an asset

To create or open an existing asset, use:

```
/asset <name>
/a <name>
```

!!!tip "Asset names as paths"
    Asset names can mimic paths by using forward slash, e.g. `/asset a/b/c`

This opens your [configured editor](../config.md#default-editor) (defaults to
`vim`) to write the contents.

To skip the editor, write a multi-line command (`Alt + Enter` or
`Option + Enter`) to set the contents:

```
/asset <name>
test
1 2 3
```

To use another editor:

```
/asset <name> <editor-cmd>
```

## Load an asset

To load an asset into a conversation, use:

```
/asset-load <name>
```

!!!tip "Tab complete for asset names"
    When specifying asset names, use tab for auto-completion.

To load an asset and print its contents in the repl, use:

```
/asset-view <name>
```

Similar local files loaded with `/load`, loaded assets are retained after a
`/reset`.

## Temporary local copy of asset

It's undesirable to load an asset into a conversation when the data is better
transformed by a function written by the LLM rather than by the LLM itself.

Having an LLM transform data is prone to many issues: slow data processing,
costly output tokens, hallucinations, exceeding the context window, and lack of
support for non-unicode data.

The solution is to make a temporary copy of an asset and have the LLM operate
on the file:

```
/asset-temp <name>
```

This makes a temporary local copy of the asset and adds the file path to the
conversation.

Here's an example processing The Odyssey by Homer:

```
[0]: /asset-temp book/odyssey.txt
```
```
Asset 'book/odyssey.txt' copied to '/var/folders/nv/ytdlylsn7kn_x53vcy4pz1xr0000gn/T/asset_RPcI7k.txt'
```
```
[2] !sh count occurrences of ulysses
```
```
↓↓↓

grep -io 'ulysses' /var/folders/nv/ytdlylsn7kn_x53vcy4pz1xr0000gn/T/asset_RPcI7k.txt | wc -l
```
```
⚙ ⚙ ⚙

580
```

The temporary file is automatically cleaned up when the conversation ends.

To make copies of the most recent `n` revisions of an asset, try:

```
/asset-temp <name> <n>
```

## Syncing assets locally

To sync local copies of assets, use:

```
/asset-sync-down <prefix> <path>
```

This does a one-way sync of all assets with the given prefix to a local path.
Asset names are reproduced on the local filesystem and forward slashes are
converted to folders. Existing assets are not downloaded again unless their contents have changed.

No information is added to the conversation history. You will need to inform
the LLM of relevant files. For example, by listing the files: `!!ls <path>`

Any assets with metadata will have those synced as well as separate files with
a `.metadata` extension.

## Sharing links to assets

To generate a link to an asset that's valid for 24 hours, use:

```
/asset-link <name>
```

## Iterating through revisions

To see revisions of an asset, use:

```
/asset-revisions <name>
```

This is interactive and requires input to jump to each revision. To simply dump
`count` revisions to the conversation, use:

```
/asset-revisions <name> <count>
```

## Import or export assets

To import an asset from a local file:

```
/asset-import <name> <path>
```

To export an asset to a local file:

```
/asset-export <name> <path>
```

## Listing assets

To list assets, use:

```
/asset-list [<prefix>]
/ls [<prefix>]
```

Specifying a `prefix` filters the result set. The `prefix` can be arbitrary and
does not need to be aligned with a folder segment.

## Public assets

Public assets start with a forward slash followed by a username (`/<username>`):

For example, substituting your username you can create a public file:

```
/asset /<username>/public.txt
```

Any other user can view it with:

```
/asset-view /<username>/public.txt
```

!!!tip "Public assets shortcut"
    You can also use `//` as a shortcut to refer to your own public asset path.
    For example, `/asset //public.txt` is equivalent to
    `/asset /<username>/public.txt`. This makes it easier to access your
    public assets and lets you write task steps that are generic to the
    logged-in account.

## Search

Assets can be searched semantically based on their contents:

```
/asset-search cook salmon
```

The search is powered by embeddings on the content and the `title` metadata key
if it's set. The latter is especially important if the content is non-unicode.

## Usage with `/exec`

When executing a shell command, use `@name` to reference an asset. The asset
will be transparently downloaded into a temporary file.

```
[0] !!cat @/hai/changelog | grep -A 2 v1.3.0
equivalent to:
[0] !!grep -A 2 v1.3.0 @/hai/changelog
```

```
## v1.3.0

- Add syntax highlighting for code blocks.
```

Note: `!!` is shorthand for `/exec`.

If a shell redirects (`>` or `>>`) to an @asset, the output file will be
uploaded as well.

```
[0] !!grep -A 2 v1.3.0 @/hai/changelog > @changes-v1.3.0
```

This processes a public asset from the `hai` account and saves a filtered
version to the `changes-v1.3.0` private asset.

### Glob Patterns

Asset references support glob patterns (`*`, `?`, `[...]`) for matching multiple
assets at once.

```
[0] !!cat @data/*.txt
```

This expands to all `.txt` files in the `data/` folder, downloading each to a
temporary file.

More examples:

```
[0] !!wc -l @logs/2024-*.log
[0] !!cat @chapters/part_?.md > @full-book.md
[0] !!grep "error" @logs/[0-9][0-9][0-9].log
[0] !!grep -l "TODO" @hai-cli/**/*.rs
```

!!!warning "Glob Limitations"
Glob patterns are only supported for input assets. Using a glob pattern
with output redirections (`>` or `>>`) will result in an error.

!!!warning "Limitations"
The implementation uses simple string substitution to replace `@asset`
markers with temporary files. Complex shell operations involving quotes or
escapes around asset references may not work as expected.

## Write conflicts

When the same asset is modified simultaneously by two separate `hai` processes,
a write conflict occurs. The version that loses the race will be preserved as a
new asset with the same name as the original but with a random suffix.

An easy way to see the difference is to:

```
!!diff @file @file(suffix)
```

## Metadata

Each asset can have a JSON object associated with it to store metadata:

| Command                        | Description                                               |
|---------------------------------|-----------------------------------------------------------|
| `/asset-md-get <name>`          | Fetches metadata for an asset and adds it to the conversation. |
| `/asset-md-set <name> <json>`   | Sets the entire metadata blob.                            |
| `/asset-md-set-key <name> <key> <value>` | Sets/replaces a metadata key.                   |
| `/asset-md-del-key <name> <key>`| Deletes a metadata key.                                   |

If the `title` metadata key is set, it's shown in `/asset-list` and
`/asset-search` in `[]` brackets.

!!!question "🙋 Help Wanted"
    Interested in using metadata to make asset encryption the default way of life? All ideas welcome. Please reach out or open an issue.

## Asset Push & ACL

Your public assets (prefixed by your username `/username/...`) can have ACLs
set so that an asset can be used as a write-only "asset/document drop".

```
/asset-acl /ken/hai-feedback deny:read-data
/asset-acl /ken/hai-feedback allow:push-data
```

With these ACLs, any user can push data (`/asset-push`) into the
`/ken/hai-feedback` asset, but no one except the owner can read what's been
pushed.

The owner (user `ken` in this example) can read the contents of
`/ken/hai-feedback` using `/asset-list-revisions` and can access revisions with
`/asset-get-revision`.

## Listening for changes

`/asset-listen <name>` can be used to block the REPL until a change to the
asset. You can test this by:

```
# Console 1 (create asset)
/asset test-listen

# Console 2 (listen for changes -- blocking)
/asset-listen test-listen

# Console 1 (modify, unblocking console 2)
/asset test-listen
```

For an example of sending emails based on asset changes, see the
[hai/email-asset-updates](https://hai.superego.ai/task/hai/email-asset-updates@1.0.0)
task: `/task hai/email-asset-updates`

Note that the API exposes a websockets interface that pushes notifications when
changes occur.

## Collapsing Folders

The underlying asset store uses a key-value structure. While asset keys may
contain forward slashes to resemble directory paths, these are purely cosmetic.

By default, when listing your assets, they appear as a flat list:

```
[0] /ls
```
```
a/b/c
a/b/d
a/b/e/f
```

To make browsing easier, you can choose to "collapse" specific folders:

- `/asset-folder-collapse <path>` - Collapse a folder when listing a parent prefix.
- `/asset-folder-expand <path>` - Uncollapse a folder when listing a parent prefix.
  **Note** that all folders are expanded by default.
- `/asset-folder-list [<prefix>]` - List all collapsed folders with the given
  path prefix.

Collapsing the `a/b` folder:

```
[1] /asset-collapse a/b
```

Now, listing the root shows the collapsed folder:

```
[2] /ls
```
```
a/b📁
```

To view the contents of the collapsed folder, list it directly:

```
[3] /ls a/b/
```
```
a/b/c
a/b/d
a/b/e/f
```

There's a limit of 100 collapsed folders each for your private and public assets.

## Quota

Each account gets 1GB of asset storage.

!!!note "Revisions"
    The size of each revision is counted towards your storage. When an asset is
    removed, the total size of all of its revisions is removed from your quota.

To increase your account's storage quota, see `/account-subscribe`.
