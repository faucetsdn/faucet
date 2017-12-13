#!/bin/bash

# Add local user
# Either use the LOCAL_USER_ID if passed in at runtime or
# fallback to 0 to maintain backwards compatibility

USER_ID=${LOCAL_USER_ID:-0}
GROUP_ID=${LOCAL_GROUP_ID:-0}

echo "Starting with UID : $USER_ID GID=$GROUP_ID"
export HOME=/home/faucet
adduser -u $USER_ID -G faucet -g "" -h $HOME -D faucet >/dev/null 2>&1 || true

# Update permissions on directories installed by pip before we su-exec
chown faucet:faucet /var/log/ryu/faucet/
chown -R faucet:faucet /etc/ryu/faucet/

exec /sbin/su-exec faucet "$@"
