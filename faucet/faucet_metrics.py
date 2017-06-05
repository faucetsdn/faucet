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


from prometheus_client import Counter, Gauge, start_http_server


class FaucetMetrics(object):
    """Container class for objects that can be exported to Prometheus."""

    def __init__(self, prom_port, prom_addr):
        self.of_packet_ins = Counter(
            'of_packet_ins',
            'number of OF packet_ins received from DP', ['dpid'])
        self.of_flowmsgs_sent = Counter(
            'of_flowmsgs_sent',
            'number of OF flow messages (and packet outs) sent to DP', ['dpid'])
        self.of_errors = Counter(
            'of_errors',
            'number of OF errors received from DP', ['dpid'])
        self.of_dp_connections = Counter(
            'of_dp_connections',
            'number of OF connections from a DP', ['dpid'])
        self.of_dp_disconnections = Counter(
            'of_dp_disconnections',
            'number of OF connections from a DP', ['dpid'])
        self.faucet_config_reload_requests = Counter(
            'faucet_config_reload_requests',
            'number of config reload requests', [])
        self.vlan_hosts_learned = Gauge(
            'vlan_hosts_learned',
            'number of hosts learned on a vlan', ['dpid', 'vlan'])
        self.vlan_neighbors = Gauge(
            'vlan_neighbors',
            'number of neighbors on a vlan', ['dpid', 'vlan', 'ipv'])
        self.faucet_config_table_names = Gauge(
            'faucet_config_table_names',
            'number to names map of FAUCET pipeline tables', ['dpid', 'name'])
        self.faucet_config_dp_name = Gauge(
            'faucet_config_dp_name',
            'map of DP name to DP ID', ['dpid', 'name'])
        self.bgp_neighbor_uptime_seconds = Gauge(
            'bgp_neighbor_uptime',
            'BGP neighbor uptime in seconds', ['dpid', 'vlan', 'neighbor'])
        self.bgp_neighbor_routes = Gauge(
            'bgp_neighbor_routes',
            'BGP neighbor route count', ['dpid', 'vlan', 'neighbor', 'ipv'])
        self.learned_macs = Gauge(
            'learned_macs',
            ('max address stored as 64bit number to DP ID, port, VLAN, '
             'and n (maximum number of hosts on the port)'),
            ['dpid', 'port', 'vlan', 'n'])
        self.port_status = Gauge(
            'port_status',
            'status of switch ports',
            ['dpid', 'port'])
        self.dp_status = Gauge(
            'dp_status',
            'status of datapaths',
            ['dpid'])
        start_http_server(prom_port, prom_addr)
