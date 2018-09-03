"""Prometheus for Gauge."""

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
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import collections

from prometheus_client import Gauge

from faucet.gauge_pollers import GaugePortStatsPoller, GaugePortStatePoller, GaugeFlowTablePoller
from faucet.prom_client import PromClient


PROM_PREFIX_DELIM = '_'
PROM_PORT_PREFIX = 'of_port'
PROM_PORT_STATE_VARS = (
    'reason',
    'state',
    'curr_speed',
    'max_speed',
)
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

    def __init__(self, reg=None):
        super(GaugePrometheusClient, self).__init__(reg=reg)
        self.table_tags = collections.defaultdict(set)
        self.metrics = {}
        self.dp_status = Gauge( # pylint: disable=unexpected-keyword-arg
            'dp_status',
            'status of datapaths',
            self.REQUIRED_LABELS,
            registry=self._reg)
        for prom_var in PROM_PORT_VARS + PROM_PORT_STATE_VARS:
            exported_prom_var = PROM_PREFIX_DELIM.join(
                (PROM_PORT_PREFIX, prom_var))
            self.metrics[exported_prom_var] = Gauge( # pylint: disable=unexpected-keyword-arg
                exported_prom_var, '', self.REQUIRED_LABELS + ['port_name'],
                registry=self._reg)

    def reregister_flow_vars(self, table_name, table_tags):
        """Register the flow variables needed for this client"""
        for prom_var in PROM_FLOW_VARS:
            table_prom_var = PROM_PREFIX_DELIM.join((prom_var, table_name))
            try:
                self._reg.unregister(self.metrics[table_prom_var])
            except KeyError:
                pass
            self.metrics[table_prom_var] = Gauge( # pylint: disable=unexpected-keyword-arg
                table_prom_var, '', list(table_tags), registry=self._reg)


class GaugePortStatsPrometheusPoller(GaugePortStatsPoller):
    """Exports port stats to Prometheus."""

    def __init__(self, conf, logger, prom_client):
        super(GaugePortStatsPrometheusPoller, self).__init__(
            conf, logger, prom_client)
        self.prom_client.start(
            self.conf.prometheus_port, self.conf.prometheus_addr, self.conf.prometheus_test_thread)

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


class GaugePortStatePrometheusPoller(GaugePortStatePoller):
    """Export port state changes to Prometheus."""

    def update(self, rcv_time, dp_id, msg):
        super(GaugePortStatePrometheusPoller, self).update(rcv_time, dp_id, msg)
        port_no = msg.desc.port_no
        if port_no in self.dp.ports:
            port_name = self.dp.ports[port_no].name
            port_labels = dict(dp_id=hex(dp_id), dp_name=self.dp.name, port_name=port_name)
            for prom_var in PROM_PORT_STATE_VARS:
                exported_prom_var = PROM_PREFIX_DELIM.join((PROM_PORT_PREFIX, prom_var))
                msg_value = msg.reason if prom_var == 'reason' else getattr(msg.desc, prom_var)
                self.prom_client.metrics[exported_prom_var].labels(**port_labels).set(msg_value)


class GaugeFlowTablePrometheusPoller(GaugeFlowTablePoller):
    """Export flow table entries to Prometheus."""

    def update(self, rcv_time, dp_id, msg):
        super(GaugeFlowTablePrometheusPoller, self).update(rcv_time, dp_id, msg)
        jsondict = msg.to_jsondict()
        for stats_reply in jsondict['OFPFlowStatsReply']['body']:
            stats = stats_reply['OFPFlowStats']
            # TODO: labels based on matches will be dynamic
            # Work around this by unregistering/registering the entire variable.
            for var, tags, count in self._parse_flow_stats(stats):
                table_id = int(tags['table_id'])
                table_name = self.dp.table_by_id(table_id).name
                table_tags = self.prom_client.table_tags[table_name]
                tags_keys = set(tags.keys())
                if tags_keys != table_tags:
                    unreg_tags = tags_keys - table_tags
                    if unreg_tags:
                        table_tags.update(unreg_tags)
                        self.prom_client.reregister_flow_vars(
                            table_name, table_tags)
                        self.logger.info( # pylint: disable=logging-not-lazy
                            'Adding tags %s to %s for table %s' % (
                                unreg_tags, table_tags, table_name))
                    # Add blank tags for any tags not present.
                    missing_tags = table_tags - tags_keys
                    for tag in missing_tags:
                        tags[tag] = ''
                table_prom_var = PROM_PREFIX_DELIM.join((var, table_name))
                try:
                    self.prom_client.metrics[table_prom_var].labels(**tags).set(count)
                except ValueError:
                    self.logger.error( # pylint: disable=logging-not-lazy
                        'labels %s versus %s incorrect on %s' % (
                            tags, table_tags, table_prom_var))
