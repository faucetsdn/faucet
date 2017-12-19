"""Prometheus for Gauge."""

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

from prometheus_client import Gauge as PromGauge # avoid collision

from faucet.gauge_pollers import GaugePortStatsPoller, GaugeFlowTablePoller
from faucet.prom_client import PromClient
from faucet.valve_of import MATCH_FIELDS


PROM_PREFIX_DELIM = '_'
PROM_PORT_PREFIX = 'of_port'
PROM_PORT_VARS = (
    'tx_packets',
    'rx_packets',
    'tx_bytes',
    'rx_bytes',
    'tx_dropped',
    'rx_dropped',
    'rx_errors')
PROM_FLOW_VARS = (
    'flow_byte_count',
    'flow_packet_count'
)


class GaugePrometheusClient(PromClient):
    """Wrapper for Prometheus client that is shared between all pollers."""

    metrics = {}

    def __init__(self):
        super(GaugePrometheusClient, self).__init__()
        self.dp_status = PromGauge(
            'dp_status',
            'status of datapaths',
            self.REQUIRED_LABELS)
        for prom_var in PROM_PORT_VARS:
            exported_prom_var = PROM_PREFIX_DELIM.join(
                (PROM_PORT_PREFIX, prom_var))
            self.metrics[exported_prom_var] = PromGauge(
                exported_prom_var, '', self.REQUIRED_LABELS + ['port_name'])
        flow_labels = (
            self.REQUIRED_LABELS +
            ['table_id', 'priority', 'inst_count', 'vlan'])
        for prom_var in PROM_FLOW_VARS:
            self.metrics[prom_var] = PromGauge(
                prom_var, '', flow_labels)


class GaugePortStatsPrometheusPoller(GaugePortStatsPoller):
    """Exports port stats to Prometheus."""

    def __init__(self, conf, logger, prom_client):
        super(GaugePortStatsPrometheusPoller, self).__init__(
            conf, logger, prom_client)
        self.prom_client.start(
            self.conf.prometheus_port, self.conf.prometheus_addr)

    def _format_port_stats(self, delim, stat):
        formatted_port_stats = []
        for prom_var in PROM_PORT_VARS:
            stat_name = delim.join((PROM_PORT_PREFIX, prom_var))
            stat_val = getattr(stat, prom_var)
            if stat_val != 2**64-1:
                formatted_port_stats.append((stat_name, stat_val))
        return formatted_port_stats

    def update(self, rcv_time, dp_id, msg):
        super(GaugePortStatsPrometheusPoller, self).update(rcv_time, dp_id, msg)
        for stat in msg.body:
            port_name = self._stat_port_name(msg, stat, dp_id)
            port_labels = dict(dp_id=hex(dp_id), dp_name=self.dp.name, port_name=port_name)
            for stat_name, stat_val in self._format_port_stats(
                    PROM_PREFIX_DELIM, stat):
                self.prom_client.metrics[stat_name].labels(**port_labels).set(stat_val)


class GaugeFlowTablePrometheusPoller(GaugeFlowTablePoller):

    def update(self, rcv_time, dp_id, msg):
        super(GaugeFlowTablePrometheusPoller, self).update(rcv_time, dp_id, msg)
        jsondict = msg.to_jsondict()
        for stats_reply in jsondict['OFPFlowStatsReply']['body']:
            stats = stats_reply['OFPFlowStats']
            for var, tags, count in self._parse_flow_stats(stats):
                for match in MATCH_FIELDS:
                     if match in tags:
                         del tags[match]
                if 'vlan' not in tags:
                    tags['vlan'] = ''
                self.prom_client.metrics[var].labels(**tags).set(count)
