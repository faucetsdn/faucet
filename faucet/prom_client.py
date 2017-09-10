"""Implement Prometheus client."""

# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
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
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from pbr.version import VersionInfo
from prometheus_client import start_http_server, Gauge


class PromClient(object):
    """Prometheus client."""

    running = False

    def __init__(self):
        version = VersionInfo('faucet').semantic_version().release_string()
        self.faucet_version = Gauge('faucet_pbr_version', 'Faucet PBR version', ['version'])
        # pylint: disable=no-member
        self.faucet_version.labels(version=version).set(1)

    def start(self, prom_port, prom_addr):
        """Start webserver if not already running."""
        if not self.running:
            start_http_server(int(prom_port), prom_addr)
            self.running = True
