# Config

## Configuration File

The `hai` configuration file is stored in `~/.hai/hai.toml` where `~` is your
home directory.

### Creation

You won't find the configuration file until you've launched `hai` at least
once.

### Default AI model

```toml
default_ai_model = "gpt-4.1"
```

The `/ai-default` command is a REPL-command that updates this key-value.

### Default editor

Some commands require an editor, for example, editing an asset. `vim` is the
default editor, but you can change it to anything that takes a file path as
argument including `emacs`, `code`, `kate`, and `nano`:

```toml
default_editor = "vim"
```

Some editors require additional arguments to prevent forking. For example,
VSCode is best configured as follows:

```toml
default_editor = "code --new-window --disable-workspace-trust --wait"
```

### Default shell

Programs are executed using a shell. By default, the shell is `bash` except on
Windows where it's `powershell`.

```toml
default_shell = "bash"
```

### Check for updates

To disable automatic anonymous version checks when `hai` is launched, set:

```toml
check_for_updates = false
```

!!!tip "Pro Privacy"
    By default (`check_for_updates = true`), this version check is the **only**
    outgoing request that `hai` makes automatically. All other requests occur
    solely as a result of explicit user actions. You can verify this with the
    `hai/code` task.

### Tool confirmation

You can require confirmation before executing any tool:

```toml
tool_confirm = true
```

Use this if you're worried about your AI going rogue.

### Temperature

By default, `temperature` is set to 0 across all AIs. That's hacker-friendly
because it works uniformly across providers (minus some reasoning AIs) and
optimizes for highest likelihood answers rather than whimsical exploration.

To use the default temperature set by AI providers, set:

```toml
default_ai_temperature_to_absolute_zero = false
```

Alternatively, you can use the `/temperature` command in the REPL.

## Environment Variables

The following environment variables are recognized:

| Environment variable   | Description |
| ---------------------- | ----------- |
| `OPENAI_API_KEY`       | API key for OpenAI. |
| `GOOGLE_API_KEY`       | API key for Google AI. |
| `ANTHROPIC_API_KEY`    | API key for Anthropic. |
| `DEEPSEEK_API_KEY`     | API key for DeepSeek. |
| `XAI_API_KEY`          | API key for xAI. |
| `HAI_NO_PRETTY_IMAGES` | Disables high-resolution terminal image protocols (set to any value to enable). |
