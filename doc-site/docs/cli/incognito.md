# Incognito

Incognito disables local conversation history and optionally set a different
default AI model.

![](../image/hai-incognito.gif)

## Start in incognito

```console
$ hai -i
```

## Setting a default incognito AI model

Modify `~/.hai/hai.toml`:

```
# The default AI model in incognito mode.
#default_incognito_ai_model = "ollama/gemma3:27b"
```

While any AI model can be specified, a local model (e.g. `ollama/gemma3:27b`)
lets you be fully discrete: no conversation history and no data leaves your
machine.

## What history does `hai` keep

There are two logs that `hai` maintains:

- A log of recent repl-commands accessible by the up-arrow.
- The most recent conversation which is retrievable using `/chat-resume`.

Incognito disables both of these.
