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

from prometheus_client import start_http_server
from prometheus_client import Gauge as PromGauge # avoid collision
try:
    from gauge_pollers import GaugePortStatsPoller
except ImportError:
    from faucet.gauge_pollers import GaugePortStatsPoller


class GaugePortStatsPrometheusPoller(GaugePortStatsPoller):
    '''Exports port stats to prometheus.

    Note: the prometheus server starts in a separate thread. Whereas Ryu is
    single-threaded and event based.
    '''

    def __init__(self, conf, logger):
        super(GaugePortStatsPrometheusPoller, self).__init__(conf, logger)
        self.bytes_in = PromGauge(
            'bytes_in',
            '',
            ['dp_id', 'port_name'])
        self.bytes_out = PromGauge(
            'bytes_out',
            '',
            ['dp_id', 'port_name'])
        self.dropped_in = PromGauge(
            'dropped_in',
            '',
            ['dp_id', 'port_name'])
        self.dropped_out = PromGauge(
            'dropped_out',
            '',
            ['dp_id', 'port_name'])
        self.errors_in = PromGauge(
            'errors_in',
            '',
            ['dp_id', 'port_name'])
        self.packets_in = PromGauge(
            'packets_in',
            '',
            ['dp_id', 'port_name'])
        self.packets_out = PromGauge(
            'packets_out',
            '',
            ['dp_id', 'port_name'])
        self.port_state_reason = PromGauge(
            'port_state_reason',
            '',
            ['dp_id', 'port_name'])
        try:
            self.logger.debug('Attempting to start Prometheus server')
            start_http_server(
                self.conf.prometheus_port,
                self.conf.prometheus_addr
                )
        except OSError:
            # Prometheus server already started
            self.logger.debug('Prometheus server already running')

    def update(self, rcv_time, dp_id, msg):
        super(GaugePortStatsPrometheusPoller, self).update(rcv_time, dp_id, msg)
        self.logger.debug('Updating Prometheus Stats')
        for stat in msg.body:
            port_name = self._stat_port_name(msg, stat, dp_id)
            for stat_name, stat_val in self._format_port_stats('_', stat):
                self.__dict__[stat_name].labels(
                    dp_id=hex(dp_id), port_name=port_name).set(stat_val)
