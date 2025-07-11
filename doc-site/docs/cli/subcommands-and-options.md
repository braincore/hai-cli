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
