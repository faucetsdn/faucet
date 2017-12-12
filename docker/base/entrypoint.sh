#!/bin/bash

# Add local user
# Either use the LOCAL_USER_ID if passed in at runtime or
# fallback

USER_ID=${LOCAL_USER_ID:-9001}

echo "Starting with UID : $USER_ID"
export HOME=/home/faucet
adduser -u $USER_ID -g "" -h $HOME -D faucet >/dev/null 2>&1 || true

exec /sbin/su-exec faucet "$@"
