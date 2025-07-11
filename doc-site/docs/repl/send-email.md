# Send email

## Add and verify email

Before you can send emails with `hai`, you'll need to add and and verify an
email. Do this with the `hai/add-email` task:

```
/task hai/add-email
```

The AI will prompt you for an email and then verification code:

```
[0] /task hai/add-email
...
[5] add x@y.com as email recipient
[9] verify code 'xyzabc'
```

For now, you can only add one registered email and the intent is for it to be
your primary email account.

## Send command

To send an email, use `/email` with a multi-line input (`Alt + Enter` or
`Option + Enter`):

```
/email <subject>
<body>
```

`/email` sends an email to a default address you've verified. Use the
`hai/add-email` task to configure it:

```
[0] /task hai/add-email
...
[1] add x@y.com as an email recipient
[2] verify it with code 'xyzabc'  # from email
```

To have the AI send you an email, you'll need to use the `!hai` tool:

## How to have the LLM send an email

To have the LLM send an email, use the [!hai tool](./tools.md#hai-tool-hai)
which lets the LLM write repl commands:

```
[0] !hai send me an email with an uplifting quote of the day
```
```
↓↓↓

/email Uplifting Quote of the Dayay
Hi there!

Here’s your uplifting quote for today:

"The only way to do great work is to love what you do." – Steve Jobs

Wishing you a wonderful and inspiring day ahead!

Best regards,
Your AI Assistant
```
```
⚙ ⚙ ⚙

Pushed 1 command(s) into queue
```

## Quota

Each account gets 100 emails per month.

To increase your account's email quota, see `/account-subscribe`.
