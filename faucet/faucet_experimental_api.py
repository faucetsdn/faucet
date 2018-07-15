"""Implement experimental API."""

#### THIS API IS EXPERIMENTAL.
#### Discuss with faucet-dev list before relying on this API,
#### review http://www.hyrumslaw.com/.
#### It is subject to change without notice.

# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2018 The Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


class FaucetExperimentalAPI:
    """An experimental API for communicating with Faucet.

    Contains methods for interacting with a running Faucet controller from
    within a RyuApp. This app should be run together with Faucet in the same
    ryu-manager process.
    """

    def __init__(self, *_args, **_kwargs):
        self.faucet = None

    def is_registered(self):
        """Return True if registered and ready to serve API requests."""
        return self.faucet is not None

    def _register(self, faucet):
        """Register with FAUCET RyuApp."""
        if self.faucet is None:
            self.faucet = faucet

    def reload_config(self):
        """Reload config from config file in FAUCET_CONFIG env variable."""
        if self.faucet is not None:
            self.faucet.reload_config(None)

    def get_config(self):
        """Get the current running config of Faucet as a python dictionary."""
        if self.faucet is not None:
            return self.faucet.get_config()
        return None

    def get_tables(self, dp_id):
        """Get current FAUCET tables as a dict of table name: table no."""
        if self.faucet is not None:
            return self.faucet.get_tables(dp_id)
        return None

    def push_config(self, config):
        """Push supplied config to FAUCET."""
        raise NotImplementedError # pragma: no cover

    def add_port_acl(self, port, acl):
        """Add an ACL to a port."""
        raise NotImplementedError # pragma: no cover

    def add_vlan_acl(self, vlan, acl):
        """Add an ACL to a VLAN."""
        raise NotImplementedError # pragma: no cover

    def delete_port_acl(self, port, acl):
        """Delete an ACL from a port."""
        raise NotImplementedError # pragma: no cover

    def delete_vlan_acl(self, vlan, acl):
        """Delete an ACL from a VLAN."""
        raise NotImplementedError # pragma: no cover
