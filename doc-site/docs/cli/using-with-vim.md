# Using with vim

The motivation for calling `hai` from `vim` is to rewrite highlighted text
using the same `hai` machinery you're accustomed to.

The feature leverages [`hai bye`](./run-and-exit.md#run-and-exit) to call `hai`
from the command-line with standard input (the highlighted text) substituting
for the `-` argument.

## Define custom key mapping

Add the following to your `~/.vimrc`:

```
vnoremap <leader>h :!hai bye - 
```

Usage:

1. Highlight text in visual mode (`v` or `V`)
2. Type `\h` (`\` is the default leader)
3. Complete the command with a quoted instruction, e.g., `'make concise'`
4. Press Enter

The full vim command line will look like: `:'<,'>!hai bye - 'make concise'`

Note: When you press `:` in visual mode, vim automatically inserts `:'<,'>` to
indicate the selected range.

## Define custom user command

Define `H` as a command to invoke `hai bye` by adding the following to your
`~/.vimrc`:

```
command! -range -nargs=* H <line1>,<line2>!hai bye - <args>
```

Usage:
1. Highlight text in visual mode (`v` or `V`)
2. Type `:H 'clean up'`
3. Press Enter

The full vim command line will look like: `:'<,'>H 'clean up'`

## Extending functionality

Since `hai bye` accepts multiple commands, you can add `/prep` commands for
default instructions:

```
vnoremap <leader>h :!hai bye - '/prep use simple language'
```

You may also want to use the
[`-m` and `-u` flags](run-and-exit.md#set-model-and-user-for-consistency) for
better consistency.
