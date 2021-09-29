"""Gauge watcher implementations."""

# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
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

import os
import json
import gzip
import time

from ryu.ofproto import ofproto_v1_3 as ofp

from faucet.conf import InvalidConfigError
from faucet.valve_util import dpid_log
from faucet.gauge_influx import (
    GaugePortStateInfluxDBLogger, GaugePortStatsInfluxDBLogger, GaugeFlowTableInfluxDBLogger)
from faucet.gauge_pollers import (
    GaugePortStatePoller, GaugePortStatsPoller, GaugeFlowTablePoller, GaugeMeterStatsPoller)
from faucet.gauge_prom import (
    GaugePortStatsPrometheusPoller, GaugePortStatePrometheusPoller, GaugeFlowTablePrometheusPoller,
    GaugeMeterStatsPrometheusPoller)


def watcher_factory(conf):
    """Return a Gauge object based on type.

    Args:
        conf (GaugeConf): object with the configuration for this valve.
    """

    watcher_types = {
        'port_state': {
            'text': GaugePortStateLogger,
            'influx': GaugePortStateInfluxDBLogger,
            'prometheus': GaugePortStatePrometheusPoller,
        },
        'port_stats': {
            'text': GaugePortStatsLogger,
            'influx': GaugePortStatsInfluxDBLogger,
            'prometheus': GaugePortStatsPrometheusPoller,
        },
        'flow_table': {
            'text': GaugeFlowTableLogger,
            'influx': GaugeFlowTableInfluxDBLogger,
            'prometheus': GaugeFlowTablePrometheusPoller,
        },
        'meter_stats': {
            'text': GaugeMeterStatsLogger,
            'prometheus': GaugeMeterStatsPrometheusPoller,
        },
    }

    w_type = conf.type
    db_type = conf.db_type
    try:
        return watcher_types[w_type][db_type]
    except KeyError as key_error:
        raise InvalidConfigError('invalid water config') from key_error


class GaugePortStateLogger(GaugePortStatePoller):
    """Abstraction for port state logger."""

    def _update(self, rcv_time, msg):
        rcv_time_str = self._rcv_time(rcv_time)
        reason = msg.reason
        port_no = msg.desc.port_no
        log_msg = f'port {port_no} unknown state {reason}'
        if reason == ofp.OFPPR_ADD:
            log_msg = f'port {port_no} added'
        elif reason == ofp.OFPPR_DELETE:
            log_msg = f'port {port_no} deleted'
        elif reason == ofp.OFPPR_MODIFY:
            link_down = (msg.desc.state & ofp.OFPPS_LINK_DOWN)
            if link_down:
                log_msg = f'port {port_no} down'
            else:
                log_msg = f'port {port_no} up'
        log_msg = f'{dpid_log(self.dp.dp_id)} {log_msg}'
        self.logger.info(log_msg)
        if self.conf.file:
            with open(self.conf.file, 'a', encoding='utf-8') as logfile:
                logfile.write('\t'.join((rcv_time_str, log_msg)) + '\n')

    def send_req(self):
        """Send a stats request to a datapath."""
        raise NotImplementedError  # pragma: no cover

    def no_response(self):
        """Called when a polling cycle passes without receiving a response."""
        raise NotImplementedError  # pragma: no cover


class GaugePortStatsLogger(GaugePortStatsPoller):
    """Abstraction for port statistics logger."""

    def _dp_stat_name(self, stat, stat_name):
        port_name = self.dp.port_labels(stat.port_no)['port']
        return '-'.join((self.dp.name, port_name, stat_name))


class GaugeMeterStatsLogger(GaugeMeterStatsPoller):
    """Abstraction for meter statistics logger."""

    def _format_stat_pairs(self, delim, stat):
        band_stats = stat.band_stats[0]
        stat_pairs = (
            (('flow', 'count'), stat.flow_count),
            (('byte', 'in', 'count'), stat.byte_in_count),
            (('packet', 'in', 'count'), stat.packet_in_count),
            (('byte', 'band', 'count'), band_stats.byte_band_count),
            (('packet', 'band', 'count'), band_stats.packet_band_count))
        return self._format_stats(delim, stat_pairs)

    def _dp_stat_name(self, stat, stat_name):
        return '-'.join((self.dp.name, str(stat.meter_id), stat_name))


class GaugeFlowTableLogger(GaugeFlowTablePoller):
    """Periodically dumps the current datapath flow table as a yaml object.

    Includes a timestamp and a reference ($DATAPATHNAME-flowtables). The
    flow table is dumped as an OFFlowStatsReply message (in yaml format) that
    matches all flows.

    optionally the output can be compressed by setting compressed: true in the
    config for this watcher
    """

    def _rcv_time(self, rcv_time):
        # Use ISO8601 times for filenames
        return time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(rcv_time))

    def _update(self, rcv_time, msg):
        rcv_time_str = self._rcv_time(rcv_time)
        path = self.conf.path
        # Double Hyphen to avoid confusion with ISO8601 times
        filename = os.path.join(
            path,
            f"{self.dp.name}--flowtable--{rcv_time_str}.json"
        )
        if os.path.isfile(filename):
            # If this filename already exists, add an increment to the filename
            # (for dealing with parts of a multipart message arriving at the same time)
            inc = 1
            while os.path.isfile(filename):
                filename = os.path.join(path, f"{self.dp.name}--flowtable--{rcv_time_str}--{inc}.json")
                inc += 1

        if self.conf.compress:
            with gzip.open(filename, 'wt') as outfile:
                outfile.write(json.dumps(msg.to_jsondict()))
        else:
            with open(filename, 'w', encoding='utf-8') as outfile:
                json.dump(msg.to_jsondict(), outfile, indent=2)
