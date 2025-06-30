# Demo using ttyd

## Motivation

Makes it easy for users to try `hai` without installing it on their machines.

## How to

Build container:

```bash
$ podman build --build-arg DEMO_PASS=<hn_demo_user_password> -t hai-ttyd-demo .
```

Run container:

```bash
podman run \
  --cap-drop=ALL \
  --memory=30g \
  --cpus=7 \
  --pids-limit=1000 \
  --user 1000:1000 \
  --security-opt no-new-privileges \
  -p 1337:1337 hai-ttyd-demo
```
