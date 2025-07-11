# API keys

To use AI/LLMs with `hai`, you'll need to authenticate with AI providers in one
of two ways:

## Use your own API keys

Set an API key for each provider (`openai`, `anthropic`, `google`, `deepseek`,
`xai`) you intend to use. Choose any of the following methods:

- **CLI command:**
  ```console
  $ hai set-key <provider> <key>
  ```
- **REPL command:**
  ```
  /set-key <provider> <key>
  ```
- **Environment variable:**
  ```console
  $ <PROVIDER>_API_KEY=<key> hai
  ```
- **Config file:** Add your keys to `~/.hai/hai.toml`
    ```toml
    [openai]
    api_key = "<key>"

    [anthropic]
    api_key = "<key>"

    [google]
    api_key = "<key>"

    [deepseek]
    api_key = "<key>"

    [xai]
    api_key = "<key>"
    ```

## Use `hai router`

`hai router` is a subscription service that gives you access to all supported AI
providers without using your own keys.

- See subscription details and subscribe:
  ```
  /account-subscribe
  ```
- Enable via REPL:
  ```
  /hai-router on
  ```
- Works on every machine once you login:
  ```
  /account-login
  ```

`hai router` is an easy way to support the hai project and its ongoing
development.
