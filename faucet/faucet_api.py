"""Implement configuration API."""

# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2017 The Contributors
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


class FaucetAPI(object):
    """An API for communicating with Faucet.

    Contains methods for interacting with a running faucet controller from
    within a RyuApp. This app should be run together with faucet in the same
    ryu-manager process.

    It can be accessed by use of the _CONTEXTS dictionary within a RyuApp.
    eg.

    class ExampleApp(app_manager.RyuApp):

        _CONTEXTS = {
            'faucet_api': FaucetAPI
            }

        def __init__(self, *args, **kwargs):
            self.is_api_registered = False
            self.faucet_api = kwargs['faucet_api']

        @set_ev_cls(EventFaucetAPIRegistered, MAIN_DISPATCHER)
        def _api_registered(self):
            self.is_api_registered = True

        def print_faucet_config(self):
            if self.is_api_registered:
                print(self.faucet_api.get_config())
    """

    def __init__(self, *args, **kwargs):
        self.faucet = None

    def is_registered(self):
        return self.faucet is not None

    def _register(self, faucet):
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
        else:
            return None

    def get_tables(self, dp_id):
        """Get the current table structure used by faucet as a dict of table name: table no."""
        if self.faucet is not None:
            return self.faucet.get_tables(dp_id)
        else:
            return None

    # TODO: here are some other features I would like to see sometime:
    def push_config(self, config):
        raise NotImplementedError

    def add_port_acl(self, port, acl):
        raise NotImplementedError

    def add_vlan_acl(self, vlan, acl):
        raise NotImplementedError

    def delete_port_acl(self, port, acl):
        raise NotImplementedError

    def delete_vlan_acl(self, vlan, acl):
        raise NotImplementedError
