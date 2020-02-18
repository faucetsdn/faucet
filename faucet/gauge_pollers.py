"""Library for polling dataplanes for statistics."""

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

import logging
import random
import time

from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3 as ofp
from ryu.ofproto import ofproto_v1_3_parser as parser

from faucet.valve_of import devid_present
from faucet.valve_of_old import OLD_MATCH_FIELDS


class GaugePoller:
    """Abstraction for a poller for statistics."""

    def __init__(self, conf, logname, prom_client):
        self.dp = conf.dp # pylint: disable=invalid-name
        self.conf = conf
        self.prom_client = prom_client
        self.reply_pending = False
        self.ryudp = None
        self.logger = logging.getLogger(
            logname + '.{0}'.format(self.conf.type)
            )
        # _running indicates that the watcher is receiving data
        self._running = False
        self.req = None

    def report_dp_status(self, dp_status):
        """Report DP status."""
        self.prom_client.dp_status.labels(
            **dict(dp_id=hex(self.dp.dp_id), dp_name=self.dp.name)).set(dp_status) # pylint: disable=no-member

    def start(self, ryudp, active):
        """Start the poller."""
        self.ryudp = ryudp
        self._running = True
        if active:
            self.logger.info('starting')

    def stop(self):
        """Stop the poller."""
        self.logger.info('stopping')
        self._running = False

    def running(self):
        """Return True if the poller is running."""
        return self._running

    @staticmethod
    def is_active():
        """Return True if the poller is controlling the request loop for its stat"""
        return False

    def send_req(self):
        """Send a stats request to a datapath."""
        raise NotImplementedError # pragma: no cover

    def no_response(self):
        """Called when a polling cycle passes without receiving a response."""

        dpid_str = ''
        if self.req and 'datapath' in self.req:
            dpid_str = 'DPID %s (%s)' % (self.req.datapath.id, hex(self.req.datapath.id))

        self.logger.info('%s no response to %s', dpid_str, self.req)

    def update(self, rcv_time, msg):
        """Handle the responses to requests.

        Called when a reply to a stats request sent by this object is received
        by the controller.

        It should acknowledge the receipt by setting self.reply_pending to
        false.

        Args:
            rcv_time: the time the response was received
            msg: the stats reply message
        """
        # TODO: it may be worth while verifying this is the correct stats
        # response before doing this
        if not self.running():
            self.logger.debug('update received when not running')
            return
        self.reply_pending = False
        self._update(rcv_time, msg)

    @staticmethod
    def _format_stat_pairs(_delim, _stat):
        return ()

    @staticmethod
    def _dp_stat_name(_stat, _stat_name):
        return ''

    @staticmethod
    def _rcv_time(rcv_time):
        return time.strftime('%b %d %H:%M:%S', time.localtime(rcv_time))

    def _update(self, rcv_time, msg):
        if not self.conf.file:
            return
        rcv_time_str = self._rcv_time(rcv_time)
        log_lines = []
        for stat in msg.body:
            for stat_name, stat_val in self._format_stat_pairs('-', stat):
                dp_stat_name = self._dp_stat_name(stat, stat_name)
                log_lines.append(self._update_line(rcv_time_str, dp_stat_name, stat_val))
        with open(self.conf.file, 'a') as logfile:
            logfile.writelines(log_lines)

    @staticmethod
    def _format_stats(delim, stat_pairs):
        formatted_stats = []
        for stat_name_list, stat_val in stat_pairs:
            stat_name = delim.join(stat_name_list)
            # OVS reports unsupported statistics as all-1-bits (UINT64_MAX)
            if stat_val == 2**64-1:
                stat_val = 0
            formatted_stats.append((stat_name, stat_val))
        return formatted_stats

    @staticmethod
    def _update_line(rcv_time_str, stat_name, stat_val):
        return '\t'.join((rcv_time_str, stat_name, str(stat_val))) + '\n'


class GaugeThreadPoller(GaugePoller):
    """A ryu thread object for sending and receiving OpenFlow stats requests.

    The thread runs in a loop sending a request, sleeping then checking a
    response was received before sending another request.

    The methods send_req, update and no_response should be implemented by
    subclasses.
    """

    def __init__(self, conf, logname, prom_client):
        super(GaugeThreadPoller, self).__init__(conf, logname, prom_client)
        self.thread = None
        self.interval = self.conf.interval
        self.ryudp = None

    def start(self, ryudp, active):
        self.stop()
        super(GaugeThreadPoller, self).start(ryudp, active)
        if active:
            self.thread = hub.spawn(self)
            self.thread.name = 'GaugeThreadPoller'

    def stop(self):
        super(GaugeThreadPoller, self).stop()
        if self.is_active():
            hub.kill(self.thread)
            hub.joinall([self.thread])
            self.thread = None

    def is_active(self):
        return self.thread is not None

    def __call__(self):
        """Send request loop.

        Delays the initial request for a random interval to reduce load.
        Then sends a request to the datapath, waits the specified interval and
        checks that a response has been received in a loop."""
        # TODO: this should use a deterministic method instead of random
        hub.sleep(random.randint(1, self.conf.interval))
        while True:
            self.send_req()
            self.reply_pending = True
            hub.sleep(self.conf.interval)
            if self.reply_pending:
                self.no_response()

    def send_req(self):
        """Send a stats request to a datapath."""
        raise NotImplementedError # pragma: no cover


class GaugeMeterStatsPoller(GaugeThreadPoller):
    """Poll for all meter stats."""

    def send_req(self):
        if self.ryudp:
            self.req = parser.OFPMeterStatsRequest(self.ryudp, 0, ofp.OFPM_ALL)
            self.ryudp.send_msg(self.req)


class GaugePortStatsPoller(GaugeThreadPoller):
    """Periodically sends a port stats request to the datapath and parses
       and outputs the response.
    """

    def send_req(self):
        if self.ryudp:
            self.req = parser.OFPPortStatsRequest(self.ryudp, 0, ofp.OFPP_ANY)
            self.ryudp.send_msg(self.req)

    def _format_stat_pairs(self, delim, stat):
        stat_pairs = (
            (('packets', 'out'), stat.tx_packets),
            (('packets', 'in'), stat.rx_packets),
            (('bytes', 'out'), stat.tx_bytes),
            (('bytes', 'in'), stat.rx_bytes),
            (('dropped', 'out'), stat.tx_dropped),
            (('dropped', 'in'), stat.rx_dropped),
            (('errors', 'out'), stat.tx_errors),
            (('errors', 'in'), stat.rx_errors))
        return self._format_stats(delim, stat_pairs)


class GaugeFlowTablePoller(GaugeThreadPoller):
    """Periodically dumps the current datapath flow table as a yaml object.

    Includes a timestamp and a reference ($DATAPATHNAME-flowtables). The
    flow table is dumped as an OFFlowStatsReply message (in yaml format) that
    matches all flows.
    """

    def send_req(self):
        if self.ryudp:
            match = parser.OFPMatch()
            self.req = parser.OFPFlowStatsRequest(
                self.ryudp, 0, ofp.OFPTT_ALL, ofp.OFPP_ANY, ofp.OFPG_ANY,
                0, 0, match)
            self.ryudp.send_msg(self.req)

    def _parse_flow_stats(self, stats):
        """Parse flow stats reply message into tags/labels and byte/packet counts."""
        packet_count = int(stats['packet_count'])
        byte_count = int(stats['byte_count'])
        instructions = stats['instructions']
        tags = {
            'dp_name': self.dp.name,
            'dp_id': hex(self.dp.dp_id),
            'table_id': int(stats['table_id']),
            'priority': int(stats['priority']),
            'inst_count': len(instructions),
            'cookie': int(stats['cookie']),
        }
        oxm_matches = stats['match']['OFPMatch']['oxm_fields']
        for oxm_match in oxm_matches:
            oxm_tlv = oxm_match['OXMTlv']
            mask = oxm_tlv['mask']
            val = oxm_tlv['value']
            orig_field = oxm_tlv['field']
            if mask is not None:
                val = '/'.join((str(val), str(mask)))
            field = OLD_MATCH_FIELDS.get(orig_field, orig_field)
            tags[field] = val
            if field == 'vlan_vid' and mask is None:
                tags['vlan'] = devid_present(int(val))
        return (
            ('flow_packet_count', tags, packet_count),
            ('flow_byte_count', tags, byte_count))


class GaugePortStatePoller(GaugePoller):
    """Abstraction for port state poller."""

    def send_req(self):
        """Send a stats request to a datapath."""
        raise NotImplementedError # pragma: no cover

    def no_response(self):
        """Called when a polling cycle passes without receiving a response."""
        raise NotImplementedError # pragma: no cover
