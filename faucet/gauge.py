"""RyuApp shim between Ryu and Gauge."""

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

import time

from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import dpset
from ryu.controller import ofp_event
from ryu.lib import hub

from faucet import valve_of
from faucet.config_parser import watcher_parser
from faucet.gauge_prom import GaugePrometheusClient
from faucet.valves_manager import ConfigWatcher
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
    _CONTEXTS = {'dpset': dpset.DPSet}
    logname = 'gauge'
    exc_logname = logname + '.exception'

    def __init__(self, *args, **kwargs):
        super(Gauge, self).__init__(*args, **kwargs)
        self.prom_client = GaugePrometheusClient()
        self.watchers = {}
        self.config_watcher = ConfigWatcher()

    def start(self):
        super(Gauge, self).start()

        self._load_config()
        self.threads.extend([
            hub.spawn(thread) for thread in (self._config_file_stat,)])

    def _get_watchers(self, ryu_dp, handler_name):
        """Get Watchers instances to response to an event.

        Args:
            ryu_dp (ryu.controller.controller.Datapath): datapath.
            handler_name (string): handler name to log if datapath unknown.
        Returns:
            dict of Watchers instances or None.
        """
        dp_id = ryu_dp.id
        if dp_id in self.watchers:
            return self.watchers[dp_id]
        ryu_dp.close()
        self.logger.error(
            '%s: unknown datapath %s', handler_name, dpid_log(dp_id))
        return None

    @kill_on_exception(exc_logname)
    def _load_config(self):
        """Load Gauge config."""
        for watcher_dpid, old_watchers in list(self.watchers.items()):
            self._stop_watchers(watcher_dpid, old_watchers)

        new_confs = watcher_parser(self.config_file, self.logname, self.prom_client)
        new_watchers = {}

        for conf in new_confs:
            watcher = watcher_factory(conf)(conf, self.logname, self.prom_client)
            watcher_dpid = watcher.dp.dp_id
            watcher_type = watcher.conf.type
            if watcher_dpid not in new_watchers:
                new_watchers[watcher_dpid] = {}
            if watcher_type not in new_watchers[watcher_dpid]:
                new_watchers[watcher_dpid][watcher_type] = []
            new_watchers[watcher_dpid][watcher_type].append(watcher)

        for watcher_dpid, watchers in list(new_watchers.items()):
            ryu_dp = self.dpset.get(watcher_dpid)
            if ryu_dp:
                self._start_watchers(ryu_dp, watcher_dpid, watchers)

        self.watchers = new_watchers
        self.config_watcher.update(self.config_file)
        self.logger.info('config complete')

    @kill_on_exception(exc_logname)
    def _update_watcher(self, ryu_dp, name, msg):
        """Call watcher with event data."""
        rcv_time = time.time()
        watchers = self._get_watchers(ryu_dp, '_update_watcher')
        if watchers is None:
            return
        if name in watchers:
            for watcher in watchers[name]:
                watcher.update(rcv_time, ryu_dp.id, msg)

    @kill_on_exception(exc_logname)
    def _config_file_stat(self):
        """Periodically stat config files for any changes."""
        while True:
            if self.config_watcher.files_changed():
                if self.stat_reload:
                    self.send_event('Gauge', EventReconfigure())
            self._thread_jitter(3)

    @set_ev_cls(EventReconfigure, MAIN_DISPATCHER)
    def reload_config(self, _):
        """Handle request for Gauge config reload."""
        self.logger.warning('reload config requested')
        self._load_config()

    def _start_watchers(self, ryu_dp, dp_id, watchers):
        """Start watchers for DP if active."""
        for watchers_by_name in list(watchers.values()):
            for i, watcher in enumerate(watchers_by_name):
                is_active = i == 0
                watcher.report_dp_status(1)
                watcher.start(ryu_dp, is_active)
                if is_active:
                    self.logger.info(
                        '%s %s watcher starting', dpid_log(dp_id), watcher.conf.type)

    @kill_on_exception(exc_logname)
    def _handler_datapath_up(self, ryu_dp):
        """Handle DP up.

        Args:
            ryu_dp (ryu.controller.controller.Datapath): datapath.
        """
        watchers = self._get_watchers(ryu_dp, '_handler_datapath_up')
        if watchers is None:
            return
        self.logger.info('%s up', dpid_log(ryu_dp.id))
        ryu_dp.send_msg(valve_of.faucet_config(datapath=ryu_dp))
        ryu_dp.send_msg(valve_of.gauge_async(datapath=ryu_dp))
        self._start_watchers(ryu_dp, ryu_dp.id, watchers)

    def _stop_watchers(self, dp_id, watchers):
        """Stop watchers for DP."""
        for watchers_by_name in list(watchers.values()):
            for watcher in watchers_by_name:
                watcher.report_dp_status(0)
                if watcher.is_active():
                    self.logger.info(
                        '%s %s watcher stopping', dpid_log(dp_id), watcher.conf.type)
                    watcher.stop()

    @kill_on_exception(exc_logname)
    def _handler_datapath_down(self, ryu_dp):
        """Handle DP down.

        Args:
            ryu_dp (ryu.controller.controller.Datapath): datapath.
        """
        watchers = self._get_watchers(ryu_dp, '_handler_datapath_down')
        if watchers is None:
            return
        self.logger.info('%s down', dpid_log(ryu_dp.id))
        self._stop_watchers(ryu_dp.id, watchers)

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    @kill_on_exception(exc_logname)
    def handler_connect_or_disconnect(self, ryu_event):
        """Handle DP dis/connect.

        Args:
           ryu_event (ryu.controller.event.EventReplyBase): DP reconnection.
        """
        ryu_dp = ryu_event.dp
        if ryu_event.enter:
            self._handler_datapath_up(ryu_dp)
        else:
            self._handler_datapath_down(ryu_dp)

    @set_ev_cls(dpset.EventDPReconnected, dpset.DPSET_EV_DISPATCHER)
    @kill_on_exception(exc_logname)
    def handler_reconnect(self, ryu_event):
        """Handle a DP reconnection event.

        Args:
           ryu_event (ryu.controller.event.EventReplyBase): DP reconnection.
        """
        ryu_dp = ryu_event.dp
        self._handler_datapath_up(ryu_dp)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER) # pylint: disable=no-member
    @kill_on_exception(exc_logname)
    def port_status_handler(self, ryu_event):
        """Handle port status change event.

        Args:
           ryu_event (ryu.controller.event.EventReplyBase): port status change event.
        """
        self._update_watcher(
            ryu_event.msg.datapath, 'port_state', ryu_event.msg)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER) # pylint: disable=no-member
    @kill_on_exception(exc_logname)
    def port_stats_reply_handler(self, ryu_event):
        """Handle port stats reply event.

        Args:
           ryu_event (ryu.controller.event.EventReplyBase): port stats event.
        """
        self._update_watcher(
            ryu_event.msg.datapath, 'port_stats', ryu_event.msg)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER) # pylint: disable=no-member
    @kill_on_exception(exc_logname)
    def flow_stats_reply_handler(self, ryu_event):
        """Handle flow stats reply event.

        Args:
           ryu_event (ryu.controller.event.EventReplyBase): flow stats event.
        """
        self._update_watcher(
            ryu_event.msg.datapath, 'flow_table', ryu_event.msg)
