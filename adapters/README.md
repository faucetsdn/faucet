# Event Notification Adapter Support

Currently FAUCET allows for an experimental environment variable
`FAUCET_EVENT_SOCK` which if set to a socket file in `/var/run` sends JSON
object events to a Unix Domain Socket (UDS).

This directory is intended for community contributed adapters that sit
alongside FAUCET to capture those events and send them on in more useful ways.

All adapters will require this environment variable `FAUCET_EVENT_SOCK` to be
set.
