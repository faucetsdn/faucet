import os
from prometheus_client import Counter, start_http_server
from prometheus_client import Gauge as PromGauge # *sigh*
try:
    from gauge_pollers import GaugePortStatsPoller
    from valve_of import devid_present
    from valve_util import dpid_log
except ImportError:
    from faucet.gauge_pollers import GaugePortStatsPoller
    from faucet.valve_of import devid_present
    from faucet.valve_util import dpid_log

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
            start_http_server(9303, os.getenv('FAUCET_PROMETHEUS_ADDR', ''))
        except OSError:
            # Prometheus server already started
            self.logger.debug('Prometheus server already running')
            pass

    def update(self, rcv_time, dp_id, msg):
        super(GaugePortStatsPrometheusPoller, self).update(rcv_time, dp_id, msg)
        self.logger.debug('Updating Prometheus Stats')
        for stat in msg.body:
            port_name = self._stat_port_name(msg, stat, dp_id)
            for stat_name, stat_val in self._format_port_stats('_', stat):
                self.__dict__[stat_name].labels(
                    dp_id=hex(dp_id), port_name=port_name).set(stat_val)
