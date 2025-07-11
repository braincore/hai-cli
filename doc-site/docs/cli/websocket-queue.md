# Websocket queue

!!!warning "Experimental"
    Websocket queues are subject to breaking changes within a major version.

`hai` can expose a WebSocket interface, allowing other programs, processes, or
even web services to enqueue commands for execution.

## Start the Queue Listener

Launch the listener with:

```sh
hai listen -a <address> -w <whitelisted_origin_header>
```

- If `-a` is omitted, the listener defaults to `127.0.0.1:1338`.
- To prevent unauthorized access, use `-w` to whitelist an `Origin` header
  value. Only requests with a matching `Origin` header will be accepted.

!!!note
    If a request does **not** include an `Origin` header (it does not originate
    from a browser), the whitelist is not enforced and the request is allowed.

## Enqueue Commands via WebSocket

Connect to the WebSocket and send a JSON payload like:

```json
{
  ".tag": "push",
  "cmds": [
    "/load-url <url-populated-by-requester>",
    "Key takeaways?",
  ]
}
```

- The `cmds` array can contain one or more commands to enqueue.

As long as the `hai listen` process is running, incoming commands will be added
to the queue.

## Process the Queue

From within any REPL instance, use:

```
/queue-pop
```

This will run all commands from a single websocket message.

