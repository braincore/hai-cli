# Subcommands and options

The `hai` CLI has additional functionality that supplements the REPL.

## Specify user

If you've logged into multiple `hai` user accounts, the default behavior is to
use the last user account. You can force `hai` to run with a specific user
account:

```
hai -u <username>
```

This requires that you've previously logged into the account with
`/account-login`.

## Specify model

To override the default LLM model for an invocation of `hai`, use `-m`:

```
hai -m <model>
```

This option is especially helpful when creating command aliases. For example,
I use `hai1` and `hai2` to start `hai` with different models depending on what
I'm doing.

```bash
# Use GPT‑5.2 for general prompts
alias hai1='hai -m gpt-52'

# Use Sonnet-4.5 for coding prompts
alias hai2='hai -m sonnet45'
```

## Task mode

To immediately drop a user into task-mode:

```console
$ hai task <task-fully-qualified-name>
```

To [trust](../repl/tasks.md#trusting-a-task) a task, use `--trust`.

## Set API key for LLM provider

```
$ hai set-key <provider> <key>
```

Supported providers: `openai`, `anthropic`, `google`, `deepseek`,
`xai`
