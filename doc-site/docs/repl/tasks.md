# Tasks

A *task* in hai is a prompt-on-steroids that can be:

1. Published publicly: `/task-publish <path>`
2. Executed by anyone using the task repo: `/task <username>/<task_name>`
3. Or, executed from a file: `/task <path>` (must start with `./`, `/`, or `~`)

A *task* is made up of steps: a sequence of repl-commands. The commands are the
same as the ones you use. A step can:

- Provide context
- Load resources (file, image, asset, URL)
- Execute local programs
- Prompt the user with a question
- Prompt the AI
- Cache program executions, functions, prompt responses, and answers-by-users

Tasks make sharing workflows easy and improve their reproducibility given the
non-deterministic nature of LLMs.

## Use a task from the repository

The command to launch a task is as follows:

```
/task <task-fully-qualified-name>
```

Every task is published under a user account. The fully-qualified name follows
the following format: `<username>/<task-name>`

As an example, try:

```
/task ken/absolute-mode
```

This runs the `absolute-mode` task published by the user `ken`.

It's a simple task that does only one thing: adds a system-prompt that removes
all bedside manner from the LLM. You can view the task
[here](https://hai.superego.ai/task/ken/absolute-mode).

Alternatively, you can view the task with:

```
/task-view ken/absolute-mode
```

### Task mode

When running a task, the repl enters task-mode. You can see this in the repl's
left-hand prompt which includes the task's fully-qualified name:

```
ken/absolute-mode[1]:
```

In task mode, `/new` (`/n`) resets the conversation to the initial task state.

To exit task mode, use `/task-end` or `Ctrl + D`.

### Examples

Here are some interesting tasks:

- [`ken/pelican-bicycle`](https://hai.superego.ai/task/ken/pelican-bicycle) -
  simonw's [pelicans on a bicycle](https://github.com/simonw/pelican-bicycle)
  test
- [`hai/help`](https://hai.superego.ai/task/hai/help) - Get help using hai. Ask
  what's possible and how to do things.
- [`hai/api`](https://hai.superego.ai/task/hai/api) - Use or learn about hai's
  API.
  - [`hai/get-api-token`](https://hai.superego.ai/task/hai/get-api-token) -
    Get an API token.
- [`hai/code`](https://hai.superego.ai/task/hai/code) - Ask the AI about
  hai's source code.
- [`hai/email-asset-updates`](https://hai.superego.ai/task/hai/email-asset-updates) -
  Get emails every time an asset is updated.
  - [`hai/add-email`](https://hai.superego.ai/task/hai/add-email) - Verify your
    email address.
- [`hai/keypair-setup`](https://hai.superego.ai/task/hai/keypair-setup) -
  Setup an RSA public & private key pair in your assets. The public key is made
  available to other users via your public asset pool
  (`/<username>/pubkey/public_rsa.pem`) which they can use to encrypt messages
  to you.
- [`ken/asset-crypt`](https://hai.superego.ai/task/ken/asset-crypt) -
  Encrypt and upload files from your machine to your assets. Or, download and
  decrypt assets you've encrypted with this task. Requires that the user has
  setup an RSA keypair with the
  [`hai/keypair-setup`](https://hai.superego.ai/task/hai/keypair-setup) task.
- [`ken/weather`](https://hai.superego.ai/task/ken/weather) - Get the weekly
  weather forecast.
- [`ken/absolute-mode`](https://hai.superego.ai/task/ken/absolute-mode) - Chat
  with an AI lacking all bedside manner.
- [`ken/baby-play`](https://hai.superego.ai/task/ken/baby-play) - Based on your
  baby's age, gives age-appropriate ideas for activities.
- [`ken/flashcard-add`](https://hai.superego.ai/task/ken/flashcard-add) - Helps
  you generate and save flashcards based on the current conversation.
  - Saves your flashcards as an asset: `flaschard/deck`
  - [`ken/flashcard-review`](https://hai.superego.ai/task/ken/flashcard-review) -
    Review random flashcards
- [`ken/music-player`](https://hai.superego.ai/task/ken/music-player) - Plays
  random MP3s from your `music/*.mp3` assets. If lyrics are available in the
  file’s `lrc` metadata, it can display them line-by-line as the song plays.
- [`ken/youtube`](https://hai.superego.ai/task/ken/youtube) - Get the transcript
  of a YouTube video using [`yt-dlp`](https://github.com/yt-dlp/yt-dlp).
- [`ken/pure-md-search`](https://hai.superego.ai/task/ken/pure-md-search) - Add
  search results in markdown to your conversation. Needs API token (free tier
  available) from [pure.md](https://pure.md).
  [[Video](https://www.youtube.com/watch?v=YfSnY-MFrNw)]
- [`ken/code-review`](https://hai.superego.ai/task/ken/code-review) - Get a
  code review of unstaged/staged/committed changes in your local git repo.
- [`hai/quick-task`](https://hai.superego.ai/task/hai/quick-task) - Ask AI to
  help you write a task.
- [`ken/task-safety-checker`](https://hai.superego.ai/task/ken/task-safety-checker) -
  Check that a task in the hai task repo isn't _obviously_ destructive.
- [`ken/calendar`](https://hai.superego.ai/task/ken/calendar) -
  Manage your personal calendar using plain text assets.
- [`ken/cargo-build-fix`](https://hai.superego.ai/task/ken/cargo-build-fix) -
  Tries to patch rust code to fix `cargo build` errors automatically.

### Searching for a task

You can find tasks that other users have published using:

```
/task-search <query>
```

To see tasks published by a specific user, use:

```
/whois <username>
```

### Updating a task

When a task is run, it's cached on your machine for folllow up invocations. To
replace your cached copy with the latest version of a task, use:

```
/task-update <task-fully-qualified-name>
```

### Run a specific version

List all versions of a task:

```
/task-versions <task-fully-qualified-name>
```

Run a specific version:

```
/task <task-fully-qualified-name>@<version>
```

### Task cache

Tasks can cache some of their steps: `/ask-human.cache`, `/exec.cache`,
and `/prompt.cache`. To purge this cache, try:

```
/task-purge <task-fully-qualified-name>
```

To invoke a task with a non-default cache bucket, use the `key` option:

```
/task.key="<cache_bucket>" <task-fully-qualified-name>
```

This lets you run a single task with a different configuration per key.

### Trusting a task

Some task steps require user confirmation because of the danger they pose (see
[Security Warning](#security-warning)). To skip these confirmations, you can
set the `trust` option: `/task.trust`

## Writing a task

Tasks are written in toml with a set of required fields:

```toml
# Replace <username> with your own
name = "<username>/demo-task"

# Semantic version
version = "1.0.0"

# Displayed in /task-search
description = "A demo task to learn how to write them."

# Uncomment to require a specific version of hai
#dependencies = [
#    "hai >= 1.19.0"
#]

# Uncomment to hide this task from your /whois profile and search
# unlisted = true

# List of repl-commands to execute to setup the task
steps = [
    "/system-prompt you're sherlock holmes",
    "!!ls ~/Documents",
    "/prompt based on the documents i keep, which star trek character am i?",
]
```

Replace `<username>` and save this to a file called `demo-task.toml`. You can
now run the task from this local file:

```
/task ./demo-task.toml
```

!!!tip Referencing local paths
    To avoid ambiguity with tasks in the repo, when specifying a local file the
    file path must begin with `./`, `/`, or `~`.

### Task TOML Reference

| Field | Description |
|---------------|--------------------------------------------|
| `name`        | This must be your username followed by the name of your task. All tasks are namespaced by a username to avoid duplicates and confusion. |
| `version`     | Must be a [semantic version](https://semver.org/) (semver). |
| `description` | Explain what the task is for. Helps for task search. |
| `dependencies`| Require the `hai` client to satisfy a semver. Useful if the task uses a command that only became available after a certain version. |
| `unlisted`    | Hides the task from search and your /whois profile. |
| `steps`       | Every step is something you could have typed yourself into the CLI. At the conclusion of the steps, the user takes over with the context fully populated. |

### Publish a task

When your task is ready to publish, run:

```
/task-publish ./path/to/demo-task.toml
```

The version must be greater than the latest currently in the repo.

Anyone can run your task by using its fully-qualified name:

```
/task <username>/demo-task
```

### Using a task to make a task

To have the AI help you write a task, use:

```
/task hai/quick-task
```

You can discuss with the AI what you want the task to accomplish. When you're
done, save the task definition to a toml file and `/task-publish` it.

If you already have an active conversation with loaded resources (files, URLs,
or assets), you can ask the AI to use the current context as the basis for your
new task. This is especially useful for creating reusable tasks that
automatically load your commonly-used resources.

### Task-specific commands

There are some `hai`-repl commands that are specifically made for tasks:

| Command | Description |
|---------|-------------|
| `/ask-human <prompt>` | Ask the user a question. |
| `/ask-human.secret <prompt>` | Ask a question; user's answer is treated as a secret and hidden. |
| `/ask-human.cache <prompt>` | Ask a question; previous answer is reused on rerun. Use `/task-forget` to reset. |
| `/set-mask-secrets on` | Mask AI output that includes secrets in the terminal. Useful for hiding sensitive info like API tokens. |
| `/exec <cmd>` | Execute a command on the local machine. Always prompts the user for confirmation. |
| `/exec.cache <cmd>` | Execute a command; output is cached and reused on rerun. |
| `/prompt <message>` | Explicitly prompt the AI with a message. |
| `/prompt.cache <message>` | Prompt the AI; cached output is reused on rerun to save time and cost. |
| `/task-include <name|path>` | Run task steps without entering or exiting task-mode. Useful for including tasks within other tasks. |
| `/ai <model>` | Set the AI model. In tasks, if the model isn't available, the current model remains unchanged. |
| `/keep <bottom> [<top>]` | Forget messages to bound conversation size; useful for looping tasks. |
| `/pin(<accent>) <message>` | Add a message for the AI or user without prompting the AI for a response. Accent can be `danger`, `warn`, `info`, or `success`. |

### Security warning

The primary attack vector to defend against is a published task that's crafted
to delete or exfiltrate your data. Be careful when running any task. All
potentially dangerous commands require a "yes/no" confirmation.

Specifically, tasks may `/exec` commands on your machine which can both delete
and exfiltrate data (e.g. make an http request). Tasks may `/load` data that can
then be exfiltrated. Tasks may use a tool (e.g. `!sh` or `!py`) which can delete
and exfiltrate. Tasks may use the `!hai` tool which may generate a list of
commands that can delete and exfiltrate.
