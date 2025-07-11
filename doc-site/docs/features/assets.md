# Assets

Assets are objects stored in the cloud for your direct and indirect use via AIs.

- `/asset <name>` - Open/create asset in editor (`/a` shorthand)
  - Default editor is `vim`.
  - Override with `default_editor` in `~/.hai/hai.toml`
    - e.g. VS Code `code --new-window --disable-workspace-trust --wait`
  - `/a <name> [<editor>]` to override in the command 
- `/asset-view <name>` - Add an asset to the conversation for the AI to use.
- `/asset-load <name>` - Mimics `/load`, but for assets. Unlike `/asset-view`,
  the contents aren’t printed, and they are retained even after a `/reset`.
- `/asset-temp <name> [<count>]` - Downloads the asset to a temporary file and
  adds the file path to the conversation. This is a convenient way for the AI
  to access assets by path especially when using tools. If `count` is set, that
  number of revisions of an asset is written to files.
- `/asset-sync-down <prefix> <path>` - Syncs all assets with the given prefix
  to a local path.
  - Does not re-download assets that already exist locally.
  - Does not add info to the conversation. You will need to inform the AI of
    relevant files in the conversation typically by calling `!!ls <path>`.
  - Syncs asset metadata (if available) as the asset name with `.metadata`
    appended.
- `/asset-link <name>` - Generate a link to an asset (valid for 24 hours).
- `/asset-revisions <name> [<count>]` - Iterate through every revision of an asset.
- `/asset-import <name> <path>` - Import asset from a local file.
- `/asset-export <name> <path>` - Export asset to a local file.

Asset names can mimic file paths with slashes.

!!!tip "🙋 Help Wanted"
    Interested in writing a query language (ala LINQ or SQL) for assets?
    All ideas welcome. Please reach out or open an issue.

## Public

Public assets start with a frontslash followed by your username (`/<username>`):

- Here's how user `ken` creates a public file: `/asset /ken/public.txt`
- Anyone can see it with: `/asset-view /ken/public.txt`
- Here's how user `ken` creates a private file: `/asset private.txt`

You can also use `//` as a shortcut to refer to your own public asset path.
For example, if you are user `ken`, the command `/asset //public.txt` is
equivalent to `/asset /ken/public.txt`. This makes it easier to access your
public assets and lets you write task steps that are generic to the logged-in
account.

## Search

Assets can be listed by prefix:

```
/asset-list todo_docs/2025-
# OR use /ls as shorthand
/ls todo_docs/2025-
```

Or, they can be searched semantically:

```
/asset-search cooking salmon
```

## Using with shell

When running a shell command, use `@name` to reference an asset. The asset will
be transparently downloaded.

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

**Limitations:** The implementation uses simple string substitution to replace
`@asset` markers with temporary files. Complex shell operations involving
quotes or escapes around asset references may not work as expected.

## Conflicts

When the same asset is modified simultaneously by two separate `hai` processes,
a conflict occurs. The version that loses the race will be preserved as a
new asset with the same name as the original but with a random suffix.

## Metadata

Each asset can have a JSON object associated with it to store metadata:

- `/asset-md-get <name>` - Fetches metadata for an asset and adds it to the
  conversation.
- `/asset-md-set <name> <json>` - Sets the entire metadata blob.
- `/asset-md-set-key <name> <key> <value>` - Sets/replaces a metadata key.
- `/asset-md-del-key <name> <key>` - Delete a metadata key.

If a `title` metadata key is set, it's shown in `/asset-list` and
`/asset-search` in `[]` brackets.

| 🙋 **Help Wanted** |
|-------------------|
| Interested in using metadata to make asset encryption the default way of life? |
| All ideas welcome. Please reach out or open an issue. |

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
