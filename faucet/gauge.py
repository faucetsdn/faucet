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

import logging
import time
import random
import signal
import sys

from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import dpset
from ryu.controller import event
from ryu.controller import ofp_event
from ryu.lib import hub

from faucet import valve_of
from faucet.config_parser import watcher_parser
from faucet.gauge_prom import GaugePrometheusClient
from faucet.valve_util import dpid_log, kill_on_exception, stat_config_files
from faucet.watcher import watcher_factory
from faucet import valve_ryuapp


class EventGaugeReconfigure(event.EventBase):
    """Event sent to Gauge to cause config reload."""

    pass


class Gauge(valve_ryuapp.RyuAppBase):
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
        self.config_file_stats = None

    def start(self):
        super(Gauge, self).start()

        if self.stat_reload:
            self.logger.info('will automatically reload new config on changes')
        self._load_config()

        self.threads.extend([
            hub.spawn(thread) for thread in (self._config_file_stat,)])

        # Set the signal handler for reloading config file
        signal.signal(signal.SIGHUP, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)

    @kill_on_exception(exc_logname)
    def _load_config(self):
        """Load Gauge config."""
        new_confs = watcher_parser(self.config_file, self.logname, self.prom_client)
        new_watchers = {}

        for conf in new_confs:
            watcher = watcher_factory(conf)(conf, self.logname, self.prom_client)
            watcher_dpid = watcher.dp.dp_id
            ryu_dp = self.dpset.get(watcher_dpid)
            watcher_type = watcher.conf.type
            watcher_msg = '%s %s watcher' % (dpid_log(watcher_dpid), watcher_type)

            if watcher_dpid not in new_watchers:
                new_watchers[watcher_dpid] = {}

            if watcher_type not in new_watchers[watcher_dpid]:

                # remove old watchers for this stat
                if (watcher_dpid in self.watchers and
                        watcher_type in self.watchers[watcher_dpid]):
                    old_watchers = self.watchers[watcher_dpid][watcher_type]
                    for old_watcher in old_watchers:
                        if old_watcher.running():
                            self.logger.info('%s stopped', watcher_msg)
                            old_watcher.stop()
                    del self.watchers[watcher_dpid][watcher_type]

                # start new watcher
                new_watchers[watcher_dpid][watcher_type] = [watcher]
                if ryu_dp is None:
                    watcher.report_dp_status(0)
                    self.logger.info('%s added but DP currently down', watcher_msg)
                else:
                    watcher.report_dp_status(1)
                    watcher.start(ryu_dp, True)
                    self.logger.info('%s started', watcher_msg)
            else:
                new_watchers[watcher_dpid][watcher_type].append(watcher)
                watcher.start(ryu_dp, False)

        for watcher_dpid, leftover_watchers in list(self.watchers.items()):
            for watcher_type, watcher in list(leftover_watchers.items()):
                watcher.report_dp_status(0)
                if watcher.running():
                    self.logger.info(
                        '%s %s deconfigured', dpid_log(watcher_dpid), watcher_type)
                    watcher.stop()

        self.watchers = new_watchers
        self.logger.info('config complete')

    @kill_on_exception(exc_logname)
    def _update_watcher(self, dp_id, name, msg):
        """Call watcher with event data."""
        rcv_time = time.time()
        if dp_id in self.watchers and name in self.watchers[dp_id]:
            for watcher in self.watchers[dp_id][name]:
                watcher.update(rcv_time, dp_id, msg)
        else:
            self.logger.info('%s event, unknown', dpid_log(dp_id))

    @kill_on_exception(exc_logname)
    def signal_handler(self, sigid, _):
        """Handle signal and cause config reload.

        Args:
            sigid (int): signal received.
        """
        if sigid == signal.SIGHUP:
            self.send_event('Gauge', EventGaugeReconfigure())
        elif sigid == signal.SIGINT:
            self.close()
            sys.exit(0)

    @kill_on_exception(exc_logname)
    def _config_file_stat(self):
        """Periodically stat config files for any changes."""
        # TODO: Better to use an inotify method that doesn't conflict with eventlets.
        while True:
            # TODO: also stat FAUCET config.
            if self.config_file:
                config_hashes = {self.config_file: None}
                new_config_file_stats = stat_config_files(config_hashes)
                if self.config_file_stats:
                    if new_config_file_stats != self.config_file_stats:
                        if self.stat_reload:
                            self.send_event('Gauge', EventGaugeReconfigure())
                        self.logger.info('config file(s) changed on disk')
                self.config_file_stats = new_config_file_stats
            self._thread_jitter(3)

    @set_ev_cls(EventGaugeReconfigure, MAIN_DISPATCHER)
    def reload_config(self, _):
        """Handle request for Gauge config reload."""
        self.logger.warning('reload config requested')
        self._load_config()

    @kill_on_exception(exc_logname)
    def _handler_datapath_up(self, ryu_dp):
        """Handle DP up.

        Args:
            ryu_dp (ryu.controller.controller.Datapath): datapath.
        """
        dp_id = ryu_dp.id
        if dp_id in self.watchers:
            self.logger.info('%s up', dpid_log(dp_id))
            for watchers in list(self.watchers[dp_id].values()):
                is_active = True
                for watcher in watchers:
                    watcher.report_dp_status(1)
                    watcher.start(ryu_dp, is_active)
                    if is_active:
                        self.logger.info(
                            '%s %s watcher starting',
                            dpid_log(dp_id),
                            watcher.conf.type
                            )
                        is_active = False
            ryu_dp.send_msg(valve_of.faucet_config(datapath=ryu_dp))
            ryu_dp.send_msg(valve_of.gauge_async(datapath=ryu_dp))
        else:
            self.logger.info('%s up, unknown', dpid_log(dp_id))

    @kill_on_exception(exc_logname)
    def _handler_datapath_down(self, ryu_dp):
        """Handle DP down.

        Args:
            ryu_dp (ryu.controller.controller.Datapath): datapath.
        """
        dp_id = ryu_dp.id
        if dp_id in self.watchers:
            self.logger.info('%s down', dpid_log(dp_id))
            for watchers in list(self.watchers[dp_id].values()):
                for watcher in watchers:
                    watcher.report_dp_status(0)
                    if watcher.is_active():
                        self.logger.info(
                            '%s %s watcher stopping',
                            dpid_log(dp_id),
                            watcher.conf.type
                            )
                    watcher.stop()
        else:
            self.logger.info('%s down, unknown', dpid_log(dp_id))

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
            ryu_event.msg.datapath.id, 'port_state', ryu_event.msg)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER) # pylint: disable=no-member
    @kill_on_exception(exc_logname)
    def port_stats_reply_handler(self, ryu_event):
        """Handle port stats reply event.

        Args:
           ryu_event (ryu.controller.event.EventReplyBase): port stats event.
        """
        self._update_watcher(
            ryu_event.msg.datapath.id, 'port_stats', ryu_event.msg)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER) # pylint: disable=no-member
    @kill_on_exception(exc_logname)
    def flow_stats_reply_handler(self, ryu_event):
        """Handle flow stats reply event.

        Args:
           ryu_event (ryu.controller.event.EventReplyBase): flow stats event.
        """
        self._update_watcher(
            ryu_event.msg.datapath.id, 'flow_table', ryu_event.msg)
