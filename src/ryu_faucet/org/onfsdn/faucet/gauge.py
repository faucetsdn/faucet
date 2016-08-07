# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
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
import os
import signal

import logging
from logging.handlers import TimedRotatingFileHandler

from util import kill_on_exception

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller import event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3

from config_parser import watcher_parser
from watcher import watcher_factory

class EventGaugeReconfigure(event.EventBase):
    pass

class Gauge(app_manager.RyuApp):
    """Ryu app for polling Faucet controlled datapaths for stats/state.

    It can poll multiple datapaths. The configuration files for each datapath
    should be listed, one per line, in the file set as the environment variable
    GAUGE_CONFIG. It logs to the file set as the environment variable
    GAUGE_LOG,
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {'dpset': dpset.DPSet}

    logname = 'gauge'
    exc_logname = logname + '.exception'

    def __init__(self, *args, **kwargs):
        super(Gauge, self).__init__(*args, **kwargs)
        self.config_file = os.getenv(
            'GAUGE_CONFIG', '/etc/ryu/faucet/gauge.conf')
        self.exc_logfile = os.getenv(
            'GAUGE_EXCEPTION_LOG', '/var/log/ryu/faucet/gauge_exception.log')
        self.logfile = os.getenv('GAUGE_LOG', '/var/log/ryu/faucet/gauge.log')

        # Setup logging
        self.logger = logging.getLogger(self.logname)
        logger_handler = TimedRotatingFileHandler(
            self.logfile,
            when='midnight')
        log_fmt = '%(asctime)s %(name)-6s %(levelname)-8s %(message)s'
        date_fmt = '%b %d %H:%M:%S'
        default_formatter = logging.Formatter(log_fmt, date_fmt)
        logger_handler.setFormatter(default_formatter)
        self.logger.addHandler(logger_handler)
        self.logger.propagate = 0

        # Set up separate logging for exceptions
        exc_logger = logging.getLogger(self.exc_logname)
        exc_logger_handler = logging.FileHandler(self.exc_logfile)
        exc_logger_handler.setFormatter(
            logging.Formatter(log_fmt, date_fmt))
        exc_logger.addHandler(exc_logger_handler)
        exc_logger.propagate = 1
        exc_logger.setLevel(logging.ERROR)

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
    def handler_connect_or_disconnect(self, ev):
        ryudp = ev.dp
        if ryudp.id not in self.watchers:
            self.logger.info("no watcher configured for {0}".format(ryudp.id))
            return

        if ev.enter: # DP is connecting
            self.logger.info("datapath up %x", ryudp.id)
            for watcher in self.watchers[ryudp.id].values():
                watcher.start(ryudp)
        else: # DP is disconnecting
            if ryudp.id in self.watchers:
                for watcher in self.watchers[ryudp.id].values():
                    watcher.stop()
                del self.watchers[ryudp.id]
            self.logger.info("datapath down %x", ryudp.id)

    def signal_handler(self, sigid, frame):
        if sigid == signal.SIGHUP:
            self.send_event('Gauge', EventGaugeReconfigure())

    @set_ev_cls(EventGaugeReconfigure, MAIN_DISPATCHER)
    def reload_config(self, ev):
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
    def handler_reconnect(self, ev):
        self.logger.info("datapath reconnected %x", ev.dp.id)
        for watcher in self.watchers[ev.dp.id].values():
            watcher.start(ev.dp)

    def update_watcher(self, dp_id, name, msg):
        rcv_time = time.time()
        if dp_id in self.watchers and name in self.watchers[dp_id]:
            self.watchers[dp_id][name].update(rcv_time, msg)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER) # pylint: disable=no-member
    @kill_on_exception(exc_logname)
    def port_status_handler(self, ev):
        self.update_watcher(ev.msg.datapath.id, 'port_state', ev.msg)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER) # pylint: disable=no-member
    @kill_on_exception(exc_logname)
    def port_stats_reply_handler(self, ev):
        self.update_watcher(ev.msg.datapath.id, 'port_stats', ev.msg)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER) # pylint: disable=no-member
    @kill_on_exception(exc_logname)
    def flow_stats_reply_handler(self, ev):
        self.update_watcher(ev.msg.datapath.id, 'flow_table', ev.msg)
