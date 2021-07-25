"""RyuApp shim between Ryu and Gauge."""

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

import time

from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import ofp_event

from faucet import valve_of
from faucet.conf import InvalidConfigError
from faucet.config_parser import watcher_parser
from faucet.gauge_pollers import GaugePortStatePoller
from faucet.gauge_prom import GaugePrometheusClient
from faucet.valves_manager import ConfigWatcher
from faucet.valve_of import ofp, parser
from faucet.valve_ryuapp import EventReconfigure, RyuAppBase
from faucet.valve_util import dpid_log, kill_on_exception
from faucet.watcher import watcher_factory


class Gauge(RyuAppBase):
    """Ryu app for polling Faucet controlled datapaths for stats/state.

    It can poll multiple datapaths. The configuration files for each datapath
    should be listed, one per line, in the file set as the environment variable
    GAUGE_CONFIG. It logs to the file set as the environment variable
    GAUGE_LOG,
    """
    logname = 'gauge'
    exc_logname = logname + '.exception'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.watchers = {}
        self.config_watcher = ConfigWatcher()
        self.faucet_config_watchers = []
        self.prom_client = GaugePrometheusClient(reg=self._reg)
        self.thread_managers = (self.prom_client,)

    @kill_on_exception(exc_logname)
    def _check_thread_exception(self):
        super()._check_thread_exception()

    def _get_watchers(self, ryu_event):
        """Get Watchers instances to response to an event.

        Args:
            ryu_event (ryu.controller.event.EventReplyBase): DP event.
        Returns:
        """
        return self._get_datapath_obj(self.watchers, ryu_event)

    @kill_on_exception(exc_logname)
    def _load_config(self):
        """Load Gauge config."""
        try:
            conf_hash, _faucet_config_files, faucet_conf_hashes, new_confs = watcher_parser(
                self.config_file, self.logname, self.prom_client)
            watchers = [
                watcher_factory(watcher_conf)(watcher_conf, self.logname, self.prom_client)
                for watcher_conf in new_confs]
            self.prom_client.reregister_nonflow_vars()
        except InvalidConfigError as err:
            self.config_watcher.update(self.config_file)
            self.logger.error('invalid config: %s', err)
            return

        for old_watchers in self.watchers.values():
            self._stop_watchers(old_watchers)
        new_watchers = {}
        for watcher in watchers:
            watcher_dpid = watcher.dp.dp_id
            watcher_type = watcher.conf.type
            if watcher_dpid not in new_watchers:
                new_watchers[watcher_dpid] = {}
            if watcher_type not in new_watchers[watcher_dpid]:
                new_watchers[watcher_dpid][watcher_type] = []
            new_watchers[watcher_dpid][watcher_type].append(watcher)

        timestamp = time.time()
        for watcher_dpid, watchers in new_watchers.items():
            ryu_dp = self.dpset.get(watcher_dpid)
            if ryu_dp:
                self._start_watchers(ryu_dp, watchers, timestamp)

        self.watchers = new_watchers
        self.config_watcher.update(
            self.config_file, {self.config_file: conf_hash})
        self.faucet_config_watchers = []
        for faucet_config_file, faucet_conf_hash in faucet_conf_hashes.items():
            faucet_config_watcher = ConfigWatcher()
            faucet_config_watcher.update(faucet_config_file, faucet_conf_hash)
            self.faucet_config_watchers.append(faucet_config_watcher)
            self.logger.info('watching FAUCET config %s', faucet_config_file)
        self.logger.info('config complete')

    @kill_on_exception(exc_logname)
    def _update_watcher(self, name, ryu_event):
        """Call watcher with event data."""
        watchers, _ryu_dp, msg = self._get_watchers(ryu_event)
        if watchers is None:
            return
        if name in watchers:
            for watcher in watchers[name]:
                watcher.update(ryu_event.timestamp, msg)

    def _config_files_changed(self):
        for config_watcher in [self.config_watcher] + self.faucet_config_watchers:
            if config_watcher.files_changed():
                return True
        return False

    @set_ev_cls(EventReconfigure, MAIN_DISPATCHER)
    def reload_config(self, ryu_event):
        """Handle request for Gauge config reload."""
        super().reload_config(ryu_event)
        self._load_config()

    @staticmethod
    def _start_watchers(ryu_dp, watchers, timestamp):
        """Start watchers for DP if active."""
        for watchers_by_name in watchers.values():
            for i, watcher in enumerate(watchers_by_name):
                is_active = i == 0
                watcher.report_dp_status(1)
                watcher.start(ryu_dp, is_active)
                if isinstance(watcher, GaugePortStatePoller):
                    for port in ryu_dp.ports.values():
                        msg = parser.OFPPortStatus(
                            ryu_dp, desc=port, reason=ofp.OFPPR_ADD)
                        watcher.update(timestamp, msg)

    @kill_on_exception(exc_logname)
    def _datapath_connect(self, ryu_event):
        """Handle DP up.

        Args:
            ryu_event (ryu.controller.event.EventReplyBase): DP event.
        """
        watchers, ryu_dp, _ = self._get_watchers(ryu_event)
        if watchers is None:
            return
        self.logger.info('%s up', dpid_log(ryu_dp.id))
        ryu_dp.send_msg(valve_of.faucet_config(datapath=ryu_dp))
        ryu_dp.send_msg(valve_of.faucet_async(datapath=ryu_dp, packet_in=False))
        self._start_watchers(ryu_dp, watchers, time.time())

    @staticmethod
    def _stop_watchers(watchers):
        """Stop watchers for DP."""
        for watchers_by_name in watchers.values():
            for watcher in watchers_by_name:
                watcher.report_dp_status(0)
                if watcher.is_active():
                    watcher.stop()

    @kill_on_exception(exc_logname)
    def _datapath_disconnect(self, ryu_event):
        """Handle DP down.

        Args:
           ryu_event (ryu.controller.event.EventReplyBase): DP event.
        """
        watchers, ryu_dp, _ = self._get_watchers(ryu_event)
        if watchers is None:
            return
        self.logger.info('%s down', dpid_log(ryu_dp.id))
        self._stop_watchers(watchers)

    _WATCHER_HANDLERS = {
        ofp_event.EventOFPPortStatus: 'port_state',  # pylint: disable=no-member
        ofp_event.EventOFPPortStatsReply: 'port_stats',  # pylint: disable=no-member
        ofp_event.EventOFPFlowStatsReply: 'flow_table',  # pylint: disable=no-member
        ofp_event.EventOFPMeterStatsReply: 'meter_stats',  # pylint: disable=no-member
    }

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)  # pylint: disable=no-member
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)  # pylint: disable=no-member
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)  # pylint: disable=no-member
    @set_ev_cls(ofp_event.EventOFPMeterStatsReply, MAIN_DISPATCHER)  # pylint: disable=no-member
    @kill_on_exception(exc_logname)
    def update_watcher_handler(self, ryu_event):
        """Handle any kind of stats/change event.

        Args:
           ryu_event (ryu.controller.event.EventReplyBase): stats/change event.
        """
        self._update_watcher(self._WATCHER_HANDLERS[type(ryu_event)], ryu_event)
