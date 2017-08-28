import os
from prometheus_client import Counter, start_http_server
from prometheus_client import Gauge as PromGauge # avoid collision
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
    # Ensure only one PromGauge objects are shared across all
    # GaugePortStatsPrometheusPollers
    # TODO: when we add another prometheus watcher it will probably make sense
    # to split this into a superclass that we inherit from
    _prom_initialised = False
    _counters = {}

    def _init_counter(self, name):
        self.__dict__[name] = self._counters.setdefault(name, PromGauge(
            name,
            '',
            ['dp_id', 'port_name']
            ))
        #if name not in self._counters:
        #    self.__dict__[name] = PromGauge(
        #        name,
        #        '',
        #        ['dp_id', 'port_name'])
        #    self._counters[name] = self.__dict__[name]
        #else:
        #    self.__dict__[name] = self._counters

    def __init__(self, conf, logger):
        super(GaugePortStatsPrometheusPoller, self).__init__(conf, logger)
        for counter in (
                'bytes_in',
                'bytes_out',
                'dropped_in',
                'dropped_out',
                'errors_in',
                'packets_in',
                'packets_out',
                'port_state_reason'
                ):
            self._init_counter(counter)
        try:
            if not self._prom_initialised:
                self.logger.debug('Attempting to start Prometheus server')
                start_http_server(
                    self.conf.prometheus_port,
                    self.conf.prometheus_addr
                    )
                self._prom_initialised = True
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
