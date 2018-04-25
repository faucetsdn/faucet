"""Manage a collection of Valves."""

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

import time

from faucet.conf import InvalidConfigError
from faucet.config_parser_util import config_changed
from faucet.config_parser import dp_parser
from faucet.valve import valve_factory, SUPPORTED_HARDWARE
from faucet.valve_util import dpid_log, stat_config_files


class ConfigWatcher(object):
    """Watch config for file or content changes."""

    config_file = None
    config_hashes = None
    config_file_stats = None

    def files_changed(self):
        """Return True if any config files changed."""
        # TODO: Better to use an inotify method that doesn't conflict with eventlets.
        changed = False
        if self.config_hashes:
            new_config_file_stats = stat_config_files(self.config_hashes)
            if self.config_file_stats:
                if new_config_file_stats != self.config_file_stats:
                    changed = True
            self.config_file_stats = new_config_file_stats
        return changed

    def content_changed(self, new_config_file):
        """Return True if config file content actually changed."""
        return config_changed(self.config_file, new_config_file, self.config_hashes)

    def update(self, new_config_file, new_config_hashes=None):
        """Update state with new config file/hashes."""
        self.config_file = new_config_file
        if new_config_hashes is None:
            new_config_hashes = {new_config_file: None}
        self.config_hashes = new_config_hashes


class ValvesManager(object):
    """Manage a collection of Valves."""

    valves = {} # type: dict

    def __init__(self, logname, logger, metrics, notifier, bgp,
                 send_flows_to_dp_by_id):
        """Initialize ValvesManager.

        Args:
            logname (str): log name to use in logging.
            logger  (logging.logging): logger instance to use for logging.
            metrics (FaucetMetrics): metrics instance.
            notifier (FaucetExperimentalEvent): event notifier instance.
            bgp (FaucetBgp): BGP instance.
            send_flows_to_dp_by_id: callable, two args - DP ID and list of flows to send to DP.
        """
        self.logname = logname
        self.logger = logger
        self.metrics = metrics
        self.notifier = notifier
        self.bgp = bgp
        self.send_flows_to_dp_by_id = send_flows_to_dp_by_id
        self.config_watcher = ConfigWatcher()

    def parse_configs(self, new_config_file):
        """Return parsed configs for Valves, or None."""
        try:
            new_config_hashes, new_dps = dp_parser(new_config_file, self.logname)
            self.config_watcher.update(new_config_file, new_config_hashes)
        except InvalidConfigError as err:
            self.logger.error('New config bad (%s) - rejecting', err)
            return None
        return new_dps

    def new_valve(self, new_dp):
        valve_cl = valve_factory(new_dp)
        if valve_cl is not None:
            return valve_cl(new_dp, self.logname, self.metrics, self.notifier)
        self.logger.error(
            '%s hardware %s must be one of %s',
            new_dp.name,
            new_dp.hardware,
            sorted(list(SUPPORTED_HARDWARE.keys())))
        return None

    def load_configs(self, new_config_file, delete_dp=None):
        """Load/apply new config to all Valves."""
        new_dps = self.parse_configs(new_config_file)
        if new_dps is not None:
            deleted_dpids = (
                set(list(self.valves.keys())) -
                set([dp.dp_id for dp in new_dps]))
            for new_dp in new_dps:
                dp_id = new_dp.dp_id
                if dp_id in self.valves:
                    self.logger.info('Reconfiguring existing datapath %s', dpid_log(dp_id))
                    valve = self.valves[dp_id]
                    ofmsgs = valve.reload_config(new_dp)
                    if ofmsgs:
                        self.send_flows_to_dp_by_id(valve, ofmsgs)
                else:
                    self.logger.info('Add new datapath %s', dpid_log(new_dp.dp_id))
                    valve = self.new_valve(new_dp)
                    if valve is None:
                        continue
                valve.update_config_metrics()
                self.valves[dp_id] = valve
            if delete_dp is not None:
                for deleted_dp in deleted_dpids:
                    delete_dp(deleted_dp)
                    del self.valves[deleted_dp]
            self.bgp.reset(self.valves)

    def request_reload_configs(self, new_config_file, delete_dp=None):
        """Process a request to load config changes."""
        if self.config_watcher.content_changed(new_config_file):
            self.logger.info('configuration %s changed, analyzing differences', new_config_file)
            self.load_configs(new_config_file, delete_dp=delete_dp)
        else:
            self.logger.info('configuration is unchanged, not reloading')
        self.metrics.faucet_config_reload_requests.inc() # pylint: disable=no-member

    def update_metrics(self):
        """Update metrics in all Valves."""
        for valve in list(self.valves.values()):
            valve.update_metrics(rate_limited=False)
        self.bgp.update_metrics()

    def valve_flow_services(self, valve_service):
        """Call a method on all Valves and send any resulting flows."""
        for dp_id, valve in list(self.valves.items()):
            ofmsgs = getattr(valve, valve_service)()
            if ofmsgs:
                self.send_flows_to_dp_by_id(valve, ofmsgs)

    def valve_packet_in(self, valve, pkt_meta):
        """Time a call to Valve packet in handler."""
        other_valves = [other_valve for other_valve in list(self.valves.values()) if valve != other_valve]
        self.metrics.of_packet_ins.labels( # pylint: disable=no-member
            **valve.base_prom_labels).inc()
        packet_in_start = time.time()
        ofmsgs = valve.rcv_packet(other_valves, pkt_meta)
        packet_in_stop = time.time()
        self.metrics.faucet_packet_in_secs.labels( # pylint: disable=no-member
            **valve.base_prom_labels).observe(packet_in_stop - packet_in_start)
        if ofmsgs:
            self.send_flows_to_dp_by_id(valve, ofmsgs)
            valve.update_metrics(pkt_meta.port, rate_limited=True)
