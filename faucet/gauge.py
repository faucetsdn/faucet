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
import os
import signal

from config_parser import watcher_parser
from valve_util import dpid_log, get_logger, kill_on_exception, get_sys_prefix
import valve_of
from watcher import watcher_factory

from ryu.base import app_manager
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import dpset
from ryu.controller import event
from ryu.controller import ofp_event


class EventGaugeReconfigure(event.EventBase):
    pass


class Gauge(app_manager.RyuApp):
    """Ryu app for polling Faucet controlled datapaths for stats/state.

    It can poll multiple datapaths. The configuration files for each datapath
    should be listed, one per line, in the file set as the environment variable
    GAUGE_CONFIG. It logs to the file set as the environment variable
    GAUGE_LOG,
    """
    OFP_VERSIONS = valve_of.OFP_VERSIONS
    _CONTEXTS = {'dpset': dpset.DPSet}
    logname = 'gauge'
    exc_logname = logname + '.exception'

    def __init__(self, *args, **kwargs):
        super(Gauge, self).__init__(*args, **kwargs)
        sysprefix = get_sys_prefix()
        self.config_file = os.getenv(
            'GAUGE_CONFIG', sysprefix + '/etc/ryu/faucet/gauge.yaml')
        self.exc_logfile = os.getenv(
            'GAUGE_EXCEPTION_LOG',
            sysprefix + '/var/log/ryu/faucet/gauge_exception.log')
        self.logfile = os.getenv(
            'GAUGE_LOG', sysprefix + '/var/log/ryu/faucet/gauge.log')

        # Setup logging
        self.logger = get_logger(
            self.logname, self.logfile, logging.DEBUG, 0)
        # Set up separate logging for exceptions
        self.exc_logger = get_logger(
            self.exc_logname, self.exc_logfile, logging.DEBUG, 1)

        # Set the signal handler for reloading config file
        signal.signal(signal.SIGHUP, self.signal_handler)

        # dict of watchers/handlers:
        # indexed by dp_id and then by name
        self.watchers = {}
        confs = watcher_parser(self.config_file, self.logname)
        for conf in confs:
            watcher = watcher_factory(conf)(conf, self.logname)
            self.watchers.setdefault(watcher.dp.dp_id, {})
            self.watchers[watcher.dp.dp_id][watcher.conf.type] = watcher
        # Create dpset object for querying Ryu's DPSet application
        self.dpset = kwargs['dpset']

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    @kill_on_exception(exc_logname)
    def handler_connect_or_disconnect(self, ryu_event):
        ryu_dp = ryu_event.dp
        dp_id = ryu_dp.id
        if dp_id not in self.watchers:
            self.logger.info('no watcher configured for %s', dpid_log(dp_id))
            return

        if ryu_event.enter: # DP is connecting
            self.logger.info('%s up', dpid_log(dp_id))
            for watcher in list(self.watchers[dp_id].values()):
                watcher.start(ryu_dp)
        else: # DP is disconnecting
            if ryu_dp.id in self.watchers:
                for watcher in list(self.watchers[dp_id].values()):
                    watcher.stop()
                del self.watchers[dp_id]
            self.logger.info('%s down', dpid_log(dp_id))

    def signal_handler(self, sigid, _):
        if sigid == signal.SIGHUP:
            self.send_event('Gauge', EventGaugeReconfigure())

    @set_ev_cls(EventGaugeReconfigure, MAIN_DISPATCHER)
    def reload_config(self, _):
        self.config_file = os.getenv('GAUGE_CONFIG', self.config_file)

        new_confs = watcher_parser(self.config_file, self.logname)
        new_watchers = {}
        for conf in new_confs:
            watcher = watcher_factory(conf)(conf, self.logname)
            new_watchers.setdefault(watcher.dp.dp_id, {})
            new_watchers[watcher.dp.dp_id][watcher.conf.type] = watcher

        for dp_id, watchers in self.watchers:
            for watcher_type, watcher in watchers:
                try:
                    new_watcher = new_watchers[dp_id][watcher_type]
                    self.watchers[dp_id][watcher_type] = new_watcher
                except KeyError:
                    del self.watchers[dp_id][watcher_type]
                if watcher.running():
                    watcher.stop()
                    new_watcher.start(self.dpset.get(dp_id))

    @set_ev_cls(dpset.EventDPReconnected, dpset.DPSET_EV_DISPATCHER)
    @kill_on_exception(exc_logname)
    def handler_reconnect(self, ryu_event):
        ryu_dp = ryu_event.dp
        self.logger.info('%s reconnected', dpid_log(ryu_dp.id))
        for watcher in list(self.watchers[ryu_dp.id].values()):
            watcher.start(ryu_dp)

    def update_watcher(self, dp_id, name, msg):
        rcv_time = time.time()
        if dp_id in self.watchers and name in self.watchers[dp_id]:
            self.watchers[dp_id][name].update(rcv_time, msg)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER) # pylint: disable=no-member
    @kill_on_exception(exc_logname)
    def port_status_handler(self, ryu_event):
        self.update_watcher(ryu_event.msg.datapath.id, 'port_state', ryu_event.msg)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER) # pylint: disable=no-member
    @kill_on_exception(exc_logname)
    def port_stats_reply_handler(self, ryu_event):
        self.update_watcher(ryu_event.msg.datapath.id, 'port_stats', ryu_event.msg)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER) # pylint: disable=no-member
    @kill_on_exception(exc_logname)
    def flow_stats_reply_handler(self, ryu_event):
        self.update_watcher(ryu_event.msg.datapath.id, 'flow_table', ryu_event.msg)
