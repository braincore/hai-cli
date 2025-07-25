# REPL basics

## Launch

```console
$ hai
```

To exit, use `/quit` or `Ctrl + D`.

## Chat

Any message that isn't a `/command` or `!tool` is a chat message that triggers
a chat response from the LLM.

```
[0] hi
```
```
↓↓↓

Hello! How can I help you today?
```

## REPL Prompt

On the left-hand side is the index of the message in the conversation. For
example, the first message is always `[0]` or `[1]` if a system-prompt is set.

On the right-hand side is a set of status information:

- The current working directory which is important for tools that use the local
  filesystem.
- The token count of the conversation. See [Cost estimation](#cost-estimation).
- The active LLM model.
- The current timestamp.

## New Chat

To start a new conversation:

```
/new
/n -- shortcut
```

This removes all messages unless the REPL is in task mode.

## Reset Chat

Resetting a conversation removes all conversational messages but keeps loaded
data (`/load`, `/load-url`, `/asset-load`):

```
/reset
/r -- shortcut
```

## Load a file

To load a file into the chat conversation, use:

```
/load <path>
```

To be vigilant about token usage, check the token count on the status line.

## Load a URL

To load a URL into the chat conversation, use:

```
/load-url <url>
```

PNG and JPG responses will be rendered in the terminal and can be used with
image-capable LLM models.

HTML responses are automatically converted to markdown for significantly
improved token efficiency. If this is undesirable, use:

```
/load-url(raw) <url>
```

## Execute program and load stdout/stderr

To execute a program, use:

```
/exec <prog>
```

Both the standard output and standard error will be added to the chat
conversation. If the status code is non-zero, it is added to the conversation
as well.

The LLM is not prompted for a response until your next message.

The shortcut for execution is double-exclamation:

```
!!<prog>
```

Programs are executed using `bash` or `powershell` on Windows but can be
changed in [default shell](../config.md#default-shell).

### Example

```
[0]: /exec ls ~/Documents

OR

[0]: !!ls ~/Documents
```

```
fetch_and_analyze_tweets.py
psql_index_notes.txt
...
```

```
[2]: what do my docs say about me?
```

```
↓↓↓

You engage in technical, organizational, and analytical work. You handle SQL, PostgreSQL, and security topics.
```

## Switch LLM model

To switch LLM models, use:

```
/ai <model>
```

For information on available models, see [LLM models](./llm-models.md).

## Forget a message

If you make a mistake, you can forget the last interaction with:

```
/forget [<n>]
```

By default, one interaction is removed from the conversation, but `n` can be
specified to forget that many interactions.

## Tab completion

`hai` supports tab completion for commands and some arguments. When tab
completion is unavailable, it falls back to local file path completion.

## Command history

Command history is stored in `~/.hai/history`. To access it in the REPL:

- Arrow up/down cycles through recently used commands.
- `Ctrl + R` performs a reverse-search with partial string matching.

## Save and resume chats

Resume your last chat with:

```
/chat-resume
```

!!!note "When is a chat saved?"
    Your last chat is saved locally whenever you exit `hai` or start a new
    conversation with `/new` or `/reset`.

To save a chat for the long term as an [asset](./assets.md):

```
/chat-save
```

By default, chats are saved as assets named `chat/<timestamp>`. A descriptive
title is automatically generated and stored in the
[asset metadata](./assets.md#metadata) for easier discovery. For example:

```
[0] /ls
chat/2025-04-08-203003 [Public/Private Key Management for Encryption and Signing]
```

Resume a saved chat:

```
/chat-resume <name>
```

Save with a custom name:

```
/chat-save [<name>]
```

## Cost estimation

The REPL's right-hand prompt shows the number of tokens in the current
conversation. To understand how much the converation has cost so far and what
the input cost is for the next prompt, use:

```
/cost
```

This is especially useful when files, urls, images, and assets have been loaded
for context.

!!!warning "Tokenizer"
    Token counts are estimated using the GPT-3.5 tokenizer because of its
    smaller size and therefore faster loading time. Unscientifically, token
    counts can differ by as much as 20%.

!!!warning "Tokens for images"
    Token counts for images are only accurate for OpenAI models because all
    images are assumed to consume the hard coded number of tokens for a "low
    detail" image in the OpenAI API.
