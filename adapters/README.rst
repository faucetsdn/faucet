Event Notification Adapter Support
==================================

Currently FAUCET allows for an experimental environment variable
``FAUCET_EVENT_SOCK`` which if set sends JSON object events to a Unix
Domain Socket (UDS) at ``/var/run/faucet/faucet.sock``.

This directory is intended for community contributed adapters that sit
alongside FAUCET to capture those events and send them on in more useful
ways.

All adapters will require this environment variable
``FAUCET_EVENT_SOCK`` to be set.
