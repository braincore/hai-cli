# Run and exit

To run commands and exit without entering the REPL interface, use:

```
$ hai bye '<cmd1>' '<cmd2>' ...
```

Multiple commands can be specified. All printouts go to the terminal and `hai`
exits at the end.

!!! Escaping commands
    Use single-quotes around each repl-command to minimize escaping issues.

## Reading from stdin

Use `-` as a command to create a
[`/prep` message](../repl/basics.md#pin-and-prep-messages) with data from
stdin. For example:

```
cat meeting_notes.txt | hai bye - 'summary please'`
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
