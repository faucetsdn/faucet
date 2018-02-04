"""Manage a collection of Valves."""

# pylint: disable=too-many-arguments
# pylint: disable=too-many-instance-attributes

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
# distributed under the License is distributed on an "AS IS" BASIS
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


class ValvesManager(object):
    """Manage a collection of Valves."""

    def __init__(self, logname, logger, metrics, notifier, bgp):
        self.logname = logname
        self.logger = logger
        self.metrics = metrics
        self.notifier = notifier
        self.bgp = bgp
        self.valves = {}
        self.config_hashes = None
        self.config_file_stats = None

    def update_metrics(self):
        """Update metrics in all Valves."""
        self.bgp.update_metrics()
        for valve in list(self.valves.values()):
            valve.update_metrics(self.metrics)

    def update_configs(self):
        """Update configs in all Valves."""
        self.bgp.reset(self.valves)
