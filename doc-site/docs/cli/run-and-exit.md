# Run and exit

Use `bye` mode to run commands non-interactively and exit immediately, without
entering the REPL interface:

```
$ hai bye '<cmd1>' '<cmd2>' ...
```

!!! Escaping commands
    Use single-quotes around each repl-command to minimize escaping issues.

## Reading from stdin

Use `-` as a command to create a
[`/prep` message](../repl/basics.md#pin-and-prep-messages) with data from
stdin. For example:

```
$ cat meeting_notes.txt | hai bye - 'summary please'
The following is a summary of the meeting on June 6th:
...
```

## Use with UNIX pipes

By default, only the final message from the LLM is printed. This is the most
natural behavior for use with UNIX pipes:

```
$ echo "hello" | hai bye - "in japanese" | cat
こんにちは (Konnichiwa)
```

To print the full set of messages you'd see in REPL mode, use the `-p` /
`--print-all` flag:

```
$ echo "hello" | hai bye --print-all - "in japanese" | cat
bye[0]: /prep hello

bye[1]: in japanese

↓↓↓

「こんにちは、世界。」
```

## Set model and user for consistency

Use `-m` to set the model, and `-u` to set the user account:

```
$ hai -u <username> -m <model> bye '<cmd1>' '<cmd2>' ...
```

This eliminates variations due to the default user and model fluctuating.

## Non-interactive mode

If running in non-interactive mode (e.g. as a cron job), use `-y` to
automatically confirm all user prompts.
