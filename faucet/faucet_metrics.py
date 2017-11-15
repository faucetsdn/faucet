"""Implement Prometheus statistics."""

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

from prometheus_client import Counter, Gauge, Histogram

from faucet.prom_client import PromClient


class FaucetMetrics(PromClient):
    """Container class for objects that can be exported to Prometheus."""

    _dpid_counters = {}
    _dpid_gauges = {}

    def _dpid_counter(self, var, var_help):
        counter = Counter(var, var_help, ['dp_id'])
        self._dpid_counters[var] = counter
        return counter

    def _dpid_gauge(self, var, var_help):
        gauge = Gauge(var, var_help, ['dp_id'])
        self._dpid_gauges[var] = gauge
        return gauge

    def reset_dpid(self, dp_id):
        """Set all DPID-only counter/gauges to 0."""
        for counter in list(self._dpid_counters.values()):
            counter.labels(dp_id=hex(dp_id)).inc(0)
        for gauge in list(self._dpid_gauges.values()):
            gauge.labels(dp_id=hex(dp_id)).set(0)

    def __init__(self):
        super(FaucetMetrics, self).__init__()
        self.of_packet_ins = self._dpid_counter(
            'of_packet_ins',
            'number of OF packet_ins received from DP')
        self.of_flowmsgs_sent = self._dpid_counter(
            'of_flowmsgs_sent',
            'number of OF flow messages (and packet outs) sent to DP')
        self.of_errors = self._dpid_counter(
            'of_errors',
            'number of OF errors received from DP')
        self.of_dp_connections = self._dpid_counter(
            'of_dp_connections',
            'number of OF connections from a DP')
        self.of_dp_disconnections = self._dpid_counter(
            'of_dp_disconnections',
            'number of OF connections from a DP')
        self.faucet_config_reload_requests = Counter(
            'faucet_config_reload_requests',
            'number of config reload requests', [])
        self.faucet_config_reload_warm = self._dpid_counter(
            'faucet_config_reload_warm',
            'number of warm, differences only config reloads executed')
        self.faucet_config_reload_cold = self._dpid_counter(
            'faucet_config_reload_cold',
            'number of cold, complete reprovision config reloads executed')
        self.vlan_hosts_learned = Gauge(
            'vlan_hosts_learned',
            'number of hosts learned on a VLAN', ['dp_id', 'vlan'])
        self.vlan_neighbors = Gauge(
            'vlan_neighbors',
            'number of neighbors on a VLAN', ['dp_id', 'vlan', 'ipv'])
        self.vlan_learn_bans = Gauge(
            'vlan_learn_bans',
            'number of times learning was banned on a VLAN', ['dp_id', 'vlan'])
        self.faucet_config_table_names = Gauge(
            'faucet_config_table_names',
            'number to names map of FAUCET pipeline tables', ['dp_id', 'name'])
        self.faucet_config_dp_name = Gauge(
            'faucet_config_dp_name',
            'map of DP name to DP ID', ['dp_id', 'name'])
        self.faucet_packet_in_secs = Histogram(
            'faucet_packet_in_secs',
            'FAUCET packet in processing time', ['dp_id'],
            buckets=(0.0001, 0.001, 0.01, 0.1, 1))
        self.bgp_neighbor_uptime_seconds = Gauge(
            'bgp_neighbor_uptime',
            'BGP neighbor uptime in seconds', ['dp_id', 'vlan', 'neighbor'])
        self.bgp_neighbor_routes = Gauge(
            'bgp_neighbor_routes',
            'BGP neighbor route count', ['dp_id', 'vlan', 'neighbor', 'ipv'])
        self.learned_macs = Gauge(
            'learned_macs',
            ('MAC address stored as 64bit number to DP ID, port, VLAN, '
             'and n (discrete index)'),
            ['dp_id', 'port', 'vlan', 'n'])
        self.port_status = Gauge(
            'port_status',
            'status of switch ports',
            ['dp_id', 'port'])
        self.port_learn_bans = Gauge(
            'port_learn_bans',
            'number of times learning was banned on a port',
            ['dp_id', 'port'])
        self.dp_status = self._dpid_gauge(
            'dp_status',
            'status of datapaths')
