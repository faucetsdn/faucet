"""Prometheus for Gauge."""

# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2019 The Contributors
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
from functools import partial
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
    'tx_errors',
    'rx_errors')
PROM_FLOW_VARS = (
    'flow_byte_count',
    'flow_packet_count'
)
PROM_METER_PREFIX = 'of_meter'
PROM_METER_VARS = (
    'flow_count',
    'byte_in_count',
    'packet_in_count',
    'byte_band_count',
    'packet_band_count'
)

class GaugePrometheusClient(PromClient):
    """Wrapper for Prometheus client that is shared between all pollers."""

    def __init__(self, reg=None):
        super().__init__(reg=reg)
        self.table_tags = collections.defaultdict(set)
        self.metrics = {}
        self.dp_status = Gauge( # pylint: disable=unexpected-keyword-arg
            'dp_status',
            'status of datapaths',
            self.REQUIRED_LABELS,
            registry=self._reg)
        self.reregister_nonflow_vars()

    def _reregister_var(self, var_key, var_func):
        try:
            self._reg.unregister(self.metrics[var_key])
        except KeyError:
            pass
        self.metrics[var_key] = var_func()

    def reregister_nonflow_vars(self):
        """Reset all metrics to empty."""
        for prom_var in PROM_PORT_VARS + PROM_PORT_STATE_VARS:
            exported_prom_var = PROM_PREFIX_DELIM.join(
                (PROM_PORT_PREFIX, prom_var))
            self._reregister_var(
                exported_prom_var,
                partial(
                    Gauge,
                    exported_prom_var,
                    '',
                    self.REQUIRED_LABELS + ['port', 'port_description'],
                    registry=self._reg))
        for prom_var in PROM_METER_VARS:
            exported_prom_var = PROM_PREFIX_DELIM.join(
                (PROM_METER_PREFIX, prom_var))
            self._reregister_var(
                exported_prom_var,
                partial(
                    Gauge,
                    exported_prom_var,
                    '',
                    self.REQUIRED_LABELS + ['meter_id'],
                    registry=self._reg))

    def reregister_flow_vars(self, table_name, table_tags):
        """Register the flow variables needed for this client"""
        for prom_var in PROM_FLOW_VARS:
            table_prom_var = PROM_PREFIX_DELIM.join((prom_var, table_name))
            self._reregister_var(
                table_prom_var,
                partial(
                    Gauge,
                    table_prom_var,
                    '',
                    list(table_tags),
                    registry=self._reg))


class GaugePortStatsPrometheusPoller(GaugePortStatsPoller):
    """Exports port stats to Prometheus."""

    def __init__(self, conf, logger, prom_client):
        super().__init__(
            conf, logger, prom_client)
        self.prom_client.start(
            self.conf.prometheus_port, self.conf.prometheus_addr, self.conf.prometheus_test_thread)

    def _format_stat_pairs(self, delim, stat):
        stat_pairs = (
            ((delim.join((PROM_PORT_PREFIX, prom_var)),), getattr(stat, prom_var))
            for prom_var in PROM_PORT_VARS)
        return self._format_stats(delim, stat_pairs)

    def _update(self, rcv_time, msg):
        for stat in msg.body:
            port_labels = self.dp.port_labels(stat.port_no)
            for stat_name, stat_val in self._format_stat_pairs(
                    PROM_PREFIX_DELIM, stat):
                self.prom_client.metrics[stat_name].labels(**port_labels).set(stat_val)


class GaugeMeterStatsPrometheusPoller(GaugePortStatsPoller):
    """Exports meter stats to Prometheus."""

    def __init__(self, conf, logger, prom_client):
        super().__init__(
            conf, logger, prom_client)
        self.prom_client.start(
            self.conf.prometheus_port, self.conf.prometheus_addr, self.conf.prometheus_test_thread)

    def _format_stat_pairs(self, delim, stat):
        band_stats = stat.band_stats[0]
        stat_pairs = (
            (('flow', 'count'), stat.flow_count),
            (('byte', 'in', 'count'), stat.byte_in_count),
            (('packet', 'in', 'count'), stat.packet_in_count),
            (('byte', 'band', 'count'), band_stats.byte_band_count),
            (('packet', 'band', 'count'), band_stats.packet_band_count),
        )
        return self._format_stats(delim, stat_pairs)

    def _update(self, rcv_time, msg):
        for stat in msg.body:
            meter_labels = self.dp.base_prom_labels()
            meter_labels.update({'meter_id': stat.meter_id})
            for stat_name, stat_val in self._format_stat_pairs(
                    PROM_PREFIX_DELIM, stat):
                stat_name = PROM_PREFIX_DELIM.join((PROM_METER_PREFIX, stat_name))
                self.prom_client.metrics[stat_name].labels(**meter_labels).set(stat_val)


class GaugePortStatePrometheusPoller(GaugePortStatePoller):
    """Export port state changes to Prometheus."""

    def _update(self, rcv_time, msg):
        port_no = msg.desc.port_no
        port = self.dp.ports.get(port_no, None)
        if port is None:
            return
        port_labels = self.dp.port_labels(port_no)
        for prom_var in PROM_PORT_STATE_VARS:
            exported_prom_var = PROM_PREFIX_DELIM.join((PROM_PORT_PREFIX, prom_var))
            msg_value = msg.reason if prom_var == 'reason' else getattr(msg.desc, prom_var)
            self.prom_client.metrics[exported_prom_var].labels(**port_labels).set(msg_value)


class GaugeFlowTablePrometheusPoller(GaugeFlowTablePoller):
    """Export flow table entries to Prometheus."""

    def _update(self, rcv_time, msg):
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
