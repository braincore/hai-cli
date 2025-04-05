# hai ≡ Hacker AI

[![Crates.io](https://img.shields.io/crates/v/hai-cli)](https://crates.io/crates/hai-cli)
[![Crates.io](https://img.shields.io/crates/d/hai-cli)](https://crates.io/crates/hai-cli)
![License](https://img.shields.io/crates/l/hai-cli)
[![Discord](https://img.shields.io/badge/Discord-%235865F2.svg?logo=discord&logoColor=white)](https://discord.gg/2nzb4PSAWT)

A CLI (`hai`) with a REPL for hackers using LLMs.

![](doc/hai-intro.gif)

## Highlights

- ⚡️ Starts in 30ms (on my machine).
- 🪶 Lightweight for your machine, SBCs, and servers.
- 🗯 Run many instances for simultaneous conversations.
- 🤖 Supports AIs from OpenAI, Anthropic, DeepSeek, Google, and Ollama (local)
  all in a single conversation.
- 🕶 Go incognito `hai -i`.
- ⚙ Give AI the power to run programs on your computer.
- 🍝 Share AI prompt-pasta publicly using the task repository.
- 📂 Load images, code, or text into the conversation.
- 🎨 Highlights syntax for code snippets.
- 💾 Auto-saves last conversation for easy resumption.
- ☁ Store and share data on the cloud for easy access by AIs.
- 🛠 Open source: Apache License 2.0
- 💻 Supports Linux and macOS. Windows needs testing (help!).

## Installation

### Installer [Linux, macOS]

```
curl -LsSf https://raw.githubusercontent.com/braincore/hai-cli/refs/heads/master/scripts/hai-installer.sh | sh
```

### Alt: Download binary [Linux, macOS, Windows]

Go to [releases](https://github.com/braincore/hai-cli/releases) and download the version for your machine.

### Alt: Build from source [Linux, macOS, Windows]

```
cargo install hai-cli
```

## Features

### Fast

> I got tired of opening up browser windows to chat with AIs.

- Run `hai` and immediately drop into an AI conversation prompt.
- Run `hai` in as many terminals as you'd like to have multiple simultaneous
  conversations.
- Start a new conversation with `/new` (`/n` for short).
  - Keep loaded files/assets/urls with `/reset` (`/r/`).

### Multi-AI

> I wasn't using the right AI for the right job because it was too annoying to
> switch around.

![](doc/hai-multi-ai.gif)

- `/ai [model]` - Switch with one command (tab-completion and abbreviations
  supported)
- Switch between OpenAI, Anthropic, DeepSeek, Google, and local Ollama models

```
[0]: /ai 4om
Using AI Model: gpt-4o-mini
```
```
[0]: /ai sonnet
Using AI Model: sonnet-3.7
```
```
[0]: /ai r1
Using AI Model: deepseek-reasoner
```
```
[0]: /ai flash
Using AI Model: flash-2.0
```
```
[0]: /ai ollama/gemma3:27b
Using AI Model: gemma3:27b
```

- Switch mid conversation

```
[0] How many "r"s in strawberry?
```
```
↓↓↓
There are two 'r's in the word "strawberry."
```
```
[2]: /ai o3-mini
Using AI Model: o3-mini
```
```
[2]: Uhh, your thoughts?
```

#### Authenticating with AI Providers

You have two options:

1. Set an API key for each AI provider you plan to use.
    - via config: `~/.hai/hai.toml`
    - via CLI: `$ hai set-key <provider> <key>`
    - via REPL: `/set-key <provider> <key>`
2. Subscribe to `hai router` and your account will automatically work with OpenAI, Anthropic, DeepSeek, and Google. Learn more with `/account-subscribe`

#### Incognito

> I wasn't asking all the crazy-person questions I wanted to.

![](doc/hai-incognito.gif)

- Run `hai --incognito` (`hai -i` for short).
- Local conversation history isn't saved.
- Since AI Providers keep logs of your conversations, consider configuring a
  local ollama setup in `~/.hai/hai.toml` and set `default_incognito_ai_model`
  (e.g. `ollama/gemma3:27b`).

### Tasks

> I often need to setup the same conversation context repeatedly.

> I got tired of sending AI prompt-pasta to friends and coworkers.

A *task* in hai is a prompt-on-steroids that can be:

1. Published publicly: `/task-publish <path>`
2. Executed by anyone easily: `/task <username>/<task_name>`
3. Or, loaded from a local file: `/task <path>`

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

The [hai-tasks repo](https://github.com/braincore/hai-tasks) has examples.
Here's `ken/pelican-bicycle`:

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
    "!shscript Generate an SVG of a pelican riding a bicycle and pipe it into `cairosvg` or `convert` and output a png named `pelican-bicycle.png`",
    "/load pelican-bicycle.png",
    "/prompt Describe this image in one sentence."
]
```

![](doc/hai-pelican.gif)

### !Tools

> I got tired of being the people-person between the AI and my terminal.

![](doc/hai-tool.gif)

`!sh <prompt>` - Ask the AI to execute shell commands directly.

```
[0]: /exec ls ~/.hai
```
```
data.db
data.db-shm
data.db-wal
hai.toml
```
```
[2]: !sh list tables
```
```
↓↓↓
sqlite3 ~/.hai/data.db ".tables"
⚙ ⚙ ⚙
account          asset            task_step_cache
ask_cache        misc
```

If I feel like being a manager I provide valuable oversight with `!?sh`

```
[0]: !?sh delete evidence.txt
```
```
↓↓↓
rm evidence.txt
⚙ ⚙ ⚙
[QUESTION] Execute? y/[n]:
```

- `!?` - Also gives the AI freedom to respond to you without executing the tool.
- Other tools: `!py` (Python), `!shscript` (shell script), and `!clip` (copy to
  clipboard).
- `!'<cmd>' <prompt>` - Support for any program that AI can pass stdin to.
  Example below:

```
[0]: !'uv run --python python3 --with geopy -' distance from sf to nyc
```
```python
↓↓↓

from geopy.distance import geodesic

sf_coords = (37.7749, -122.4194)  # San Francisco coordinates
nyc_coords = (40.7128, -74.0060)   # New York City coordinates

distance = geodesic(sf_coords, nyc_coords).miles
print(distance)

⚙ ⚙ ⚙

2571.9457567914133
```

### Assets [Experimental]

> I'm tired of SaaS data silos being the biggest impediment to feeding my data
> to AIs the way I want.

Assets are objects stored in the cloud for your direct and indirect use via AIs.

- `/asset <name>` - Open asset in editor (create if does not exist)
- `/asset-new <name>` - Create a new asset and open editor
- `/asset-edit <name>` - Open existing asset in editor
- Create/edit will open a text editor defined in `~/.hai/hai.toml` (default
  `vim`).
- `/asset-{import,export} <name> <path>` - Import / export from files
- `/asset-view <name>` - Add an asset to the conversation for the AI to use.
- `/asset-load <name>` - Add an asset without printing its contents (not cleared with `/reset`).
- `/asset-list-revisions <name>` - Iterate through every revision of an asset.
- `/asset-link <name>` - Generate a link to an asset (valid for 24 hours).

Asset names can mimic file paths with slashes.

#### Public

Public assets start with a frontslash followed by your username (`/<username>`):

- Here's how user `ken` creates a public file: `/asset /ken/public.txt`
- Anyone can see it with: `/asset-view /ken/public.txt`
- Here's how user `ken` creates a private file: `/asset private.txt`

#### Search

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

#### Using with shell

When running a shell command, use `@name` to reference an asset. The asset will
be transparently downloaded.

```
[0] !!cat @/hai/changelog | grep -A 2 v1.3.0
equivalent to:
[0] !!!grep -A 2 v1.3.0 @/hai/changelog
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

#### Conflicts

When the same asset is modified simultaneously by two separate `hai` processes,
a conflict occurs. The version that loses the race will be preserved as a
new asset with the same name as the original but with a random suffix.

## Advanced Usage

See all client commands with `/help` (`/h`).

### Account(s) management

- `/account` - See your current account
- `/account-new` - Create a new account
- `/account-login` - Login to an account
- `/account <username>` - Switch account
- `/account-subscribe` - Subscribe to support the project
- `/account-balance` - See AI credits remaining

### Tools

Nothing makes me more secure as a human than the neverending mistakes AI makes
when using tools. Use a lone `!` to repeat the previous tool command & prompt.
Often, the AI will read the error message and fix itself:

```
[0]: !sh what's the weather in santa clara, ca
```
```
↓↓↓

curl -s 'wttr.in/Santa+Clara,CA?format=%C+%t'

⚙ ⚙ ⚙

Unknown location; please try ~37.2333253,-121.6846349
```
```
[3]: !
```
```
↓↓↓

curl -s 'wttr.in/Santa+Clara?format=%C+%t'

⚙ ⚙ ⚙

Partly cloudy +51°F
```

Or, if you need to change your prompt while using the same tool, use
`! <prompt>` (note that `sh` is omitted):

```
[6]: ! how about tokyo?
```
```
↓↓↓

curl -s 'wttr.in/Tokyo?format=%C+%t'

⚙ ⚙ ⚙

Clear +59°F
```

### Tool mode

If you find yourself using the same tool over-and-over, you can enter tool-mode
by specifying a tool without a prompt (e.g. `!sh`).

```
[0]: !sh
```
```
Entering tool mode; All messages are treated as prompts for !sh. Use `!exit` when done
```
```
[0] !sh: what's the weather in alexandria, egypt?
```
```
↓↓↓

curl -s 'http://wttr.in/Alexandria?format=%C+%t+%w'

⚙ ⚙ ⚙

Clear +77°F ↙11mph
```

A more realistic example is when using `hai` with `psql` (postgres client) to
avoid typing in the connection string each time.

```
[0]: !'psql -h localhost -p 5432 -U ken -d grapdb_1'
```
```
Entering tool mode; All messages are treated as prompts for !'psql -h localhost -p 5432 -U ken -d grapdb_1'. Use `!exit` when done
```
```
[3] !'psql -h localhost -p 5432 -U ken -d grapdb_1': what db users are there?
```
```
↓↓↓

SELECT usename FROM pg_user;

⚙ ⚙ ⚙

 usename
---------
 ken
```
```
[5] !'psql -h localhost -p 5432 -U ken -d grapdb_1': is query logging turned on?

↓↓↓

SHOW logging_collector;

⚙ ⚙ ⚙

 logging_collector
-------------------
 off
```

When publishing tasks, you can place users directly into tool-mode by making it
the final command in your task's command list. This approach is helpful when
writing tasks for less technical folks.

Lastly, variables can come in handy:

```
[11]: /setvar db psql -h localhost -p 5432 -U ken -d grapdb_1
```
```
[12]: !'$db' what version is the db?
```
```
↓↓↓

SELECT version();

⚙ ⚙ ⚙
...
```

### For general software development

Use `/load <path>` to load files (e.g. code) as context for the AI. You can use
globs, e.g. `/load src/**/*.rs`.

Instead of `/new`, you can use `/reset` (`/r`) to keep context from `/load`
while clearing the rest of the conversation.

In a similar vein, any `/pin <message>` is kept around on `/reset`.

### For Python development

When using the `!py` tool, the system python will be used unless a virtualenv
(`.venv`) is available anywhere in the current directory tree.

### Cost estimation

The prompt shows you the number of tokens in your current conversation. Use
`/cost` to see how much your conversation has cost so far and the input cost of
your next prompt. Useful when you've loaded lots of files for context.

| ⚠ **Warning** |
|----------------|
| Tokens are always estimated using the GPT-3.5 tokenizer because of its smaller size and therefore faster loading time. Unscientifically, I've seen estimates inaccurate by as much as 20%. |

### Task creation & publishing

Tasks are defined in toml. For example, here's the `ken/strava-api` task defined
in a file on my machine called `strava-api.toml`.

```toml
name = "ken/strava-api"
version = "1.0.0"

description = "Playground for the Strava API"

# Uncomment to hide this task from your /whois profile and search
# unlisted = true

steps = [
    "/load-url https://developers.strava.com/swagger/swagger.json",
    "/pin Loaded Strava API's swagger definition.",
    "/pin Next, you'll need an access token from https://www.strava.com/settings/api",
    "/ask-human(secret=true,cache=true) What's you're strava access token?",
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

#### Examples

See the [hai tasks](https://github.com/braincore/hai-tasks) repo.

Alternatively, you can whois a user (e.g. `/whois ken`), see what tasks they've
published, and view them via `/task-view <username>/<task_name>`.

#### Task-specific commands

In task mode, `/new` (`/n`) resets the task to the beginning rather than
clearing the entire conversation. To clear, use `/task-end`.

There are some `hai`-repl command that are specifically made for tasks:

- `/ask-human <prompt>` - Ask the question.
- `/ask-human(secret=true) <prompt>` - User's answer is treated as a secret and
  hidden.
- `/ask-human(cache=true) <prompt>` - When a user runs the task again, their
  previous answer is used. `/task-forget` to reset.
- `/set-mask-secrets on` - AI output that includes the secret is masked in the
  terminal.

An example use case is asking the user for their API token to a service. This
way the AI can formulate API requests with it and the token itself is hidden
when tool-invocations are printed to the terminal.

- `/exec <cmd>` - Execute a command on the local machine. The user is always
  prompted yes/no.
- `/exec(cache=true) <cmd>` - When a user runs the task again, the output from
  the previous invocation is used.

An example use of `/exec` is to make the first task command
`/exec(cache=true) ffmpeg -version` so that the AI knows to tweak its `fmpeg`
command-line with the exact version in mind.

- `/prompt <message>` - Makes it explicit that the line is prompting the AI.
- `/prompt(cache=true) <message>` - When a user runs the task again, the AI
  output from the previous invocation is used instead of re-prompting.

The cache is useful for avoiding the delay of an AI response and reducing costs
for expensive prompts.

- `/task-include <name|path>` - Rather than clearing the conversation and
  entering a new task-mode, this command injects tasks commands into the current
  conversation. If you find yourself giving the same instructions to the AI
  over-and-over again, just make a (pseudo-)task with your instructions and
  include it any time even if you're in another task-mode. For example, I have a
  `ken/be-terse` task and `ken/code-preference` task that I inject as necessary.

### Command-line options

- `hai task <task_name>` - Immediately drops user into task-mode.
- `hai bye '<cmd>'...` - Run any command(s) as if using the CLI without entering
  the CLI. Use single-quotes to minimize issues. Multiple commands can be
  specified. All printouts go to the terminal and `hai` exits at the end.
  - e.g. `hai bye '!sh convert apple1.jpg to webp'`
  - If running in non-interactive mode (e.g. as a cron job), use `-y` to
    automatically confirm all user prompts.
- `hai -i` - Enter incognito mode to keep no history. Pair with
  `default_incognito_ai_model` to a local LLM (e.g. ollama) to be fully
  incognito.
- `hai -u <username>` - Guarantees you use a specific account rather than the
  last active account. Pairs well with `hai task ...` and `hai bye ...` for
  multi-account setups.
- `hai set-key <provider> <key>` - Set API keys for providers (openai,
  anthropic, deepseek, google). You don't need to do this if you've subscribed
  to hai.

### More config options

See `~/.hai/hai.toml` for all options. Some options to highlight:

- Set `tool_confirm = true` to require your confirmation before executing any
  tool. Use this if you're worried about your AI going rogue.
- By default, `temperature` is set to 0 across all AIs. That's hacker-friendly
  because it works uniformly across providers (minus some reasoning AIs) and
  optimizes for highest likelihood rather than whimsical exploration. Set
  `default_ai_temperature_to_absolute_zero = false` to use the AI providers
  default or specify your own with `/temperature`.
- Set `check_for_updates = false` to disable anonymous version checks when `hai`
  runs. When disabled, `hai` makes no network requests that aren't initiated by
  you.

### Asking the AI to use the REPL

If I'm feeling lazy, I'll ask the AI to write the hai-repl commands:

```
[7]: !hai use /load-url to get hacker news frontpage and use /prompt to ask the AI to write a numbered-list of headlines
```
```
↓↓↓

- /load-url https://news.ycombinator.com/
- /prompt Please write a numbered list of the headlines extracted from the Hacker News frontpage HTML code.

⚙ ⚙ ⚙

[QUESTION] Execute? y/[n]: y
Pushed 2 command(s) into queue

---

hai-tool[10]: /load-url https://news.ycombinator.com/

hai-tool[11]: /prompt Please write a numbered list of the headlines extracted from the Hacker News frontpage HTML code.

↓↓↓

1. **Kerning, the Hard Way**
2. **Samsung Q990D unresponsive after 1020 firmware update**
3. **Decrypting encrypted files from Akira ransomware using a bunch of GPUs**
4. **Athena landed in a dark crater where the temperature was minus 280° F**
...
```

#### !hai recursion

Some AIs (`sonnet-3.7` was used below; `gpt-4o` never works) are able to work
out whether they need to re-prompt themselves to act on intermediate
information.

In this example, only the first command is prompted by the user. The rest,
prefixed by `hai-tool[ ]:`, are prompted by the AI. For brevity, user confirmations
are omitted.

```
[0]: !hai get a random number. if it is even, ask the AI how large the sun is. if it is odd, delete `file1.txt`.

↓↓↓

- !py Generate a random number and determine if it's even or odd
- !hai Based on the random number generated, if it's even, ask how large the sun is. If it's odd, delete file1.txt

⚙ ⚙ ⚙

Pushed 2 command(s) into queue
```

```
hai-tool[3]: !py Generate a random number and determine if it's even or odd

↓↓↓

import random

# Generate a random number between 1 and 100
random_number = random.randint(1, 100)

# Check if the number is even or odd
if random_number % 2 == 0:
    result = "even"
else:
    result = "odd"

print(f"The random number is: {random_number}")
print(f"The number is {result}")

⚙ ⚙ ⚙

The random number is: 86
The number is even
```

```
hai-tool[6]: !hai Based on the random number generated, if it's even, ask how large the sun is. If it's odd, delete file1.txt

↓↓↓

- /prompt How large is the sun? Please provide information about its diameter, volume, and mass compared to Earth.


⚙ ⚙ ⚙

Pushed 1 command(s) into queue
```

```
hai-tool[9]: /prompt How large is the sun? Please provide information about its diameter, volume, and mass compared to Earth.

↓↓↓

# The Size of the Sun

The Sun is enormously large compared to Earth. Here are the key measurements:

- Sun's diameter: approximately 1.39 million kilometers (864,000 miles)
- Sun's volume: approximately 1.41 × 10^18 cubic kilometers
- Sun's mass: approximately 1.989 × 10^30 kilograms
```

### More on Assets

#### Metadata

Each asset can have a JSON object associated with it to store metadata:

- `/asset-md-get <name>` - Fetches metadata for an asset and adds it to the
  conversation.
- `/asset-md-set <name> <json>` - Sets the entire metadata blob.
- `/asset-md-set-key <name> <key> <value>` - Sets/replaces a metadata key.
- `/asset-md-del-key <name> <key>` - Delete a metadata key.

If a `title` metadata key is set, it's shown in `/asset-list` and
`/asset-search` in `[]` brackets.

#### Asset Push & ACL

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

### Saving and resuming chats

You can resume your last chat using:

```
/chat-resume
```

Your last chat is saved locally when exiting `hai` or starting a new
conversation via `/new` or `/reset`.

To save a chat for the long term as an asset, use:

```
/chat-save [<name>]
```

If `name` is omitted, a default name `chat/...` is used. Specify the name to
resume it:

```
/chat-resume <name>
```

### Open Source

> I don't like running software that I and others can't audit the code of.

The `hai` CLI is available under the Apache 2.0 license. You can freely use it,
modify it, and contribute back.

You can enter a prompt with the source code loaded as context using the
`hai/code` task:

```
[0]: /task hai/code
```
```
hai/code[22]: is hai privacy conscious? does it keep my data safe?
```
```
↓↓↓

The `hai` CLI takes steps to respect user privacy and provide options for users
to safeguard their information. Here's a detailed analysis based on the code
and documentation:

...
```

### API

To query the API, use the `hai/api` task:

```
/task hai/api
```

You can use this task to ask the AI about available options or to make actual
requests using an API token. You can get an api token with the `hai/get-api-token` task:

```
/task hai/get-api-token
```

If you want to read about the details, use:

```
/task-view hai/api
```

### Security warning

The primary attack vector to defend against is a published task that's crafted
to delete or exfiltrate your data. Be careful when running any task. All
potentially dangerous commands require a "yes/no" confirmation.

Specifically, tasks may `/exec` commands on your machine which can both delete
and exfiltrate data (e.g. make an http request). Tasks may `/load` data that can
then be exfiltrated. Tasks may use a tool (e.g. `!sh` or `!py`) which can delete
and exfiltrate. Tasks may use the `!hai` tool which may generate a list of
commands that can delete and exfiltrate.
