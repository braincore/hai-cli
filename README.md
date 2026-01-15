# hai ≡ Hacker AI

[![Crates.io](https://img.shields.io/crates/v/hai-cli)](https://crates.io/crates/hai-cli)
[![Crates.io](https://img.shields.io/crates/d/hai-cli)](https://crates.io/crates/hai-cli)
![License](https://img.shields.io/crates/l/hai-cli)
[![Discord](https://img.shields.io/badge/Discord-%235865F2.svg?logo=discord&logoColor=white)](https://discord.gg/2nzb4PSAWT)

A CLI (`hai`) with a REPL for hackers using LLMs.

![hai](doc-site/docs/cast/hai-hi.gif)

## Documentation

Documentation is available at [braincore.github.io/hai-cli](https://braincore.github.io/hai-cli/)

Or, you can dive in and rely on `hai -h` (CLI), `/help` (REPL), and
`/task hai/help` (LLM helper within REPL).

## Highlights

- ⚡️ Starts in 30ms (on my machine).
- 📦 Single, standalone binary—no installation or dependencies required.
- 🪶 Lightweight (< 9MB compressed) for your machine, SBCs, and servers.
- 🗯 Run many instances for simultaneous conversations.
- 🤖 Supports AIs from OpenAI, Anthropic, DeepSeek, Google, xAI, and
  llama.cpp/Ollama (local) all in a single conversation.
- 🕶 Go incognito `hai -i`.
- ⚙ Give AI the power to run programs on your computer.
- 🍝 Share AI prompt-pasta publicly using the task repository.
- 📂 Load images, code, or text into the conversation.
- 🔗 Load URLs with automatic article extraction and markdown conversion.
- 🎨 Highlights syntax for markdown and code snippets.
- 🖼 Render output to browser.
- 💾 Auto-saves last conversation for easy resumption.
- ☁ Store and share data on the cloud for easy access by AIs.
- 📧 Get emails from AI—send notifications or share data.
- 🛠 Open source: Apache License 2.0
- 💻 Supports Linux and macOS. Windows needs testing (help!).

## Installation

### Installer [Linux, macOS]

```
curl -LsSf https://hai.dog/hai-installer.sh | sh
```

### Alt: Download binary [Linux, macOS, Windows]

Go to [releases](https://github.com/braincore/hai-cli/releases) and download the version for your machine.

### Alt: Build from source [Linux, macOS, Windows]

```
cargo install hai-cli
```

## Demo

### Markdown & code syntax highlighting

![Syntax highlighting](doc-site/docs/cast/hai-syntax-highlight.gif)

### Load image

![Load image](doc-site/docs/cast/hai-load-image.gif)

### Load URL

![Load URL](doc-site/docs/cast/hai-load-url.gif)

### Using the shell `!sh` tool

![Using the shell tool](doc-site/docs/cast/hai-sh-tool.gif)

### Using the Python `!py` tool

![Using the Python tool](doc-site/docs/cast/hai-py-tool.gif)

### Using the Python-uv `!pyuv` tool

Like `!py` but delegates to the LLM the responsibility of defining and
installing Python library dependencies.

![Using the Python-uv tool](doc-site/docs/cast/hai-pyuv-tool.gif)

### Using the HTML `!html` tool

<video src="https://github.com/user-attachments/assets/a799a066-3d08-43c3-b190-86e7f0b08735"></video>

### Using the `!hai` tool

![Using the !hai tool](doc-site/docs/cast/hai-hai-tool.gif)

### Using the function tool (Python) `!fn-py`

![Using the function tool (Python)](doc-site/docs/cast/hai-fn-py-tool.gif)

### Using a task

Example uses [`ken/code-review`](https://hai.superego.ai/task/ken/code-review) task.

![Using the code review task](doc-site/docs/cast/hai-task-codereview.gif)

Example uses [`ken/weather`](https://hai.superego.ai/task/ken/weather) task.

![Using the weather task](doc-site/docs/cast/hai-task-weather.gif)

NOTE: Human input and code generation is cached so the next invocation of task
doesn't require the LLM at all.

### Using assets

Assets are a key-value object store in the cloud that you and the LLM can read
or write to. Assets can be shared publicly, monitored for changes, and support
revisions.

![Using assets](doc-site/docs/cast/hai-asset-create.gif)

The LLM can use assets without loading them into the conversation:

![Using /asset-temp](doc-site/docs/cast/hai-asset-temp.gif)

### Multi AI

![Using the Multi AI tool](doc-site/docs/cast/hai-multi-ai.gif)

### Send email

![Send email](doc-site/docs/cast/hai-send-email.gif)

## Video Walkthrough ([YouTube](https://www.youtube.com/watch?v=F6qAy8PF2WU))

[![Watch Walkthrough on YouTube](https://img.youtube.com/vi/F6qAy8PF2WU/maxresdefault.jpg)](https://www.youtube.com/watch?v=F6qAy8PF2WU)

### More videos

- [Using hai to manage a personal calendar](https://www.youtube.com/watch?v=vfAnEs_Fpx8)
- [Using hai to get a code review](https://www.youtube.com/watch?v=vuf8FkpVBgo)
- [Using the hai api](https://www.youtube.com/watch?v=WbncAz7yxj0)
- [Using hai to encrypt/decrypt local files as assets](https://www.youtube.com/watch?v=_CA59Fzt-TY)
- [Using hai to analyze YouTube transcripts](https://www.youtube.com/watch?v=hcv6N_mfpaw)
- [Using hai with a search engine](https://www.youtube.com/watch?v=YfSnY-MFrNw)
- [Making the hai walkthrough with ffmpeg](https://www.youtube.com/watch?v=fXd22bR9Vks)
