# Tasks

## FIXME: Start with using a task? Put examples here?

> I often need to setup the same conversation context repeatedly.

> I got tired of sending AI prompt-pasta to friends and coworkers.

A *task* in hai is a prompt-on-steroids that can be:

1. Published publicly: `/task-publish <path>`
2. Executed by anyone using the task repo: `/task <username>/<task_name>`
3. Or, executed from a file: `/task <path>` (must start with `./`, `/`, or `~`)

A *task* is made up of steps: a sequence of repl-commands. The commands are the
same as the ones you use. A step can:

- Provide context
- Load resources (file, image, asset, URL)
- Execute local commands
- Prompt the user with a question
- Prompt the AI
- Cache local commands, prompt responses, and answers-to-questions.

Tasks make sharing workflows easy and improve their reproducibility given the
non-deterministic nature of LLMs.

Here's [`ken/pelican-bicycle`](https://hai.superego.ai/task/ken/pelican-bicycle):

```toml
name = "ken/pelican-bicycle"
version = "2.0.0"

description = "Runs simonw's \"Pelicans on a bicycle\" test"

steps = [
    """/pin The test is simple: Ask an AI to draw a pelican on a bicycle.

    https://github.com/simonw/pelican-bicycle
    """,
    "/pin Checking what image tools you have",
    "/exec cairosvg --version",
    "/exec convert -version",
    "!sh Generate an SVG of a pelican riding a bicycle and pipe it into `cairosvg` or `convert` and output a png named `pelican-bicycle.png`",
    "/load pelican-bicycle.png",
    "/prompt Describe this image in one sentence."
]
```

![](doc-site/docs/image/hai-pelican.gif)

#### Trusting a task

Some task steps require user confirmation because of the danger they pose (see
[Security Warning](#security-warning)). To skip these confirmations, you can
set the `trust` option to true: `/task(trust=true)` or `/task(trust)`

### Task creation & publishing

Tasks are defined in toml. For example, here's the `ken/strava-api` task defined
in a file on my machine called `strava-api.toml`.

```toml
name = "ken/strava-api"
version = "1.0.0"

description = "Playground for the Strava API"

# Uncomment to require a specific version of hai
#dependencies = [
#    "hai >= 1.16.0"
#]

# Uncomment to hide this task from your /whois profile and search
# unlisted = true

steps = [
    "/load-url https://developers.strava.com/swagger/swagger.json",
    "/pin Loaded Strava API's swagger definition.",
    "/pin Next, you'll need an access token from https://www.strava.com/settings/api",
    "/ask-human(secret,cache) What's you're strava access token?",
    """\
/pin When making requests to the Strava API from the shell, use HTTPie (`http`)
with the `--pretty=all` flag. If unavailable, fallback to curl.
""",
    "/pin Because the swagger definition is large, be wary of the cost",
    "/cost",
    "/pin Entering !sh tool mode to make it easier to make API requests",
    "!sh",
]
```

- `name` - This must be your username followed by the name of your task. All
  tasks are namespaced by a username to avoid duplicates and confusion.
- `version` - Must be a [semantic version](https://semver.org/) (semver).
- `description` - Explain what the task is for. Helps for task search.
- `dependencies` - Require the `hai` client to satisfy a semver. Useful if
  the task uses a command that only became available after a certain version.
- `unlisted` - Hides the task from search and your /whois profile.
- `steps` - Every step is something you could have typed yourself into the CLI.
  At the conclusion of the steps, the user takes over with the context fully
  populated.

You can test your task by referencing it by file path. To avoid ambiguity with
tasks in the repo, the file path must begin with `./`, `/`, or `~`:

```
/task ./path/to/strava-api.toml
```

When your task is ready to publish, run:

```
/task-publish ./path/to/strava-api.toml
```

The version must be greater than the latest currently in the repo.

Anyone can run your task by using its `name`:

```
/task ken/strava-api
```

#### Using a task to make a task

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

#### Examples

All published tasks are viewable. You can whois a user (e.g. `/whois ken`), see
what tasks they've published, and view them via
`/task-view <username>/<task_name>`. Or, you can use `/task-search` to find
tasks you're interested in.

Here are some interesting ones:

- [`hai/help`](https://hai.superego.ai/task/hai/help) - Get help using hai. Ask
  what's possible and how to do things.
- [`hai/api`](https://hai.superego.ai/task/hai/api) - Use or learn about hai's
  API.
  - [`hai/get-api-token`](https://hai.superego.ai/task/hai/get-api-token) -
    Get an API token.
- [`hai/code`](https://hai.superego.ai/task/ken/weather) - Ask the AI about
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
- [`ken/task-safety-checker`](https://hai.superego.ai/task/ken/task-safety-checker) -
  Check that a task in the hai task repo isn't _obviously_ destructive.
- [`ken/calendar`](https://hai.superego.ai/task/ken/calendar) -
  Manage your personal calendar using plain text assets.
- [`ken/cargo-build-fix`](https://hai.superego.ai/task/ken/cargo-build-fix) -
  Tries to patch rust code to fix `cargo build` errors automatically.

#### Task-specific commands

In task mode, `/new` (`/n`) resets the task to the beginning rather than
clearing the entire conversation. To clear, use `/task-end`.

There are some `hai`-repl commands that are specifically made for tasks:

- `/ask-human <prompt>` - Ask the question.
- `/ask-human(secret) <prompt>` - User's answer is treated as a secret and
  hidden.
- `/ask-human(cache) <prompt>` - When a user runs the task again, their
  previous answer is used. `/task-forget` to reset.

- `/set-mask-secrets on` - AI output that includes the secret is masked in the
  terminal.
  - An example use case is asking the user for their API token to a service.
    With masking, the AI can use the token in its tool-invocations and it'll
    show as masked `*******` in the terminal.

- `/exec <cmd>` - Execute a command on the local machine. The user is always
  prompted yes/no.
- `/exec(cache) <cmd>` - When a user runs the task again, the output from
  the previous invocation is used.
  - An example use of `/exec` is to make the first task command
    `/exec(cache) ffmpeg -version` so that the AI knows to tweak its
    `fmpeg` command-line with the exact version in mind.

- `/prompt <message>` - Makes it explicit that the line is prompting the AI.
- `/prompt(cache) <message>` - When a user runs the task again, the AI
  output from the previous invocation is used instead of re-prompting.
  - The cache is useful for avoiding the delay of an AI response and reducing
    costs for expensive prompts.

- `/task-include <name|path>` - Runs the task steps without entering task-mode
  or exiting another task-mode. Useful when you want to use a task even if
  you're in another task-mode. For example, I'll `/task-include
  ken/absolute-mode` while in other tasks.

- `/ai <model>` - While this isn't a task-only command, its behavior is subtly
  different. In a task step, if the user doesn't have hai-router or an API key
  set for the requested model, the current model isn't changed. This means a
  task author can use `/ai <model>` without fearing that a task will try to use
  a model without a key set.

- `/keep <bottom> [<top>]` - Not only for tasks, but this is useful for tasks
  running in a loop that want to forget messages to bound the size of the
  conversation.

- `/pin(danger|warn|info|success)` - Add a message for the AI or user without
  prompting the AI for a response.


### Security warning

The primary attack vector to defend against is a published task that's crafted
to delete or exfiltrate your data. Be careful when running any task. All
potentially dangerous commands require a "yes/no" confirmation.

Specifically, tasks may `/exec` commands on your machine which can both delete
and exfiltrate data (e.g. make an http request). Tasks may `/load` data that can
then be exfiltrated. Tasks may use a tool (e.g. `!sh` or `!py`) which can delete
and exfiltrate. Tasks may use the `!hai` tool which may generate a list of
commands that can delete and exfiltrate.
