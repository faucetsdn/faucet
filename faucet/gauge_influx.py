"""Library for interacting with InfluxDB."""

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

import numpy

from influxdb import InfluxDBClient
from influxdb.exceptions import InfluxDBClientError, InfluxDBServerError
from requests.exceptions import ConnectionError, ReadTimeout


try:
    from gauge_pollers import GaugePortStateBaseLogger, GaugeFlowTablePoller, GaugePortStatsPoller
    from valve_of import devid_present
    from valve_util import dpid_log
except ImportError:
    from faucet.gauge_pollers import GaugePortStateBaseLogger, GaugeFlowTablePoller, GaugePortStatsPoller
    from faucet.valve_of import devid_present
    from faucet.valve_util import dpid_log


class InfluxShipper(object):
    """Convenience class for shipping values to InfluxDB.

    Inheritors must have a WatcherConf object as conf.
    """
    conf = None

    def ship_points(self, points):
        """Make a connection to InfluxDB and ship points."""
        if self.conf is None:
            return False
        else:
            try:
                client = InfluxDBClient(
                    host=self.conf.influx_host,
                    port=self.conf.influx_port,
                    username=self.conf.influx_user,
                    password=self.conf.influx_pwd,
                    database=self.conf.influx_db,
                    timeout=self.conf.influx_timeout)
                return client.write_points(points=points, time_precision='s')
            except (ConnectionError, ReadTimeout, InfluxDBClientError, InfluxDBServerError):
                return False
            return True

    def make_point(self, tags, rcv_time, stat_name, stat_val):
        """Make an InfluxDB point."""
        # InfluxDB has only one integer type, int64. We are logging OF
        # stats that are uint64. Use float64 to prevent an overflow.
        # q.v. https://docs.influxdata.com/influxdb/v1.2/write_protocols/line_protocol_reference/
        point = {
            'measurement': stat_name,
            'tags': tags,
            'time': int(rcv_time),
            # pylint: disable=no-member
            'fields': {'value': numpy.float64(stat_val)}}
        return point

    def make_port_point(self, dp_name, port_name, rcv_time, stat_name, stat_val):
        """Make an InfluxDB point about a port measurement."""
        port_tags = {
            'dp_name': dp_name,
            'port_name': port_name,
        }
        return self.make_point(port_tags, rcv_time, stat_name, stat_val)


class GaugePortStateInfluxDBLogger(GaugePortStateBaseLogger, InfluxShipper):
    """
> use faucet
Using database faucet
> precision rfc3339
> select * from port_state_reason where port_name = 'port1.0.1' order by time desc limit 10;
name: port_state_reason
-----------------------
time                    dp_name                 port_name       value
2017-02-21T02:12:29Z    windscale-faucet-1      port1.0.1       2
2017-02-21T02:12:25Z    windscale-faucet-1      port1.0.1       2
2016-07-27T22:05:08Z    windscale-faucet-1      port1.0.1       2
2016-05-25T04:33:00Z    windscale-faucet-1      port1.0.1       2
2016-05-25T04:32:57Z    windscale-faucet-1      port1.0.1       2
2016-05-25T04:31:21Z    windscale-faucet-1      port1.0.1       2
2016-05-25T04:31:18Z    windscale-faucet-1      port1.0.1       2
2016-05-25T04:27:07Z    windscale-faucet-1      port1.0.1       2
2016-05-25T04:27:04Z    windscale-faucet-1      port1.0.1       2
2016-05-25T04:24:53Z    windscale-faucet-1      port1.0.1       2
    """

    def update(self, rcv_time, dp_id, msg):
        super(GaugePortStateInfluxDBLogger, self).update(rcv_time, dp_id, msg)
        reason = msg.reason
        port_no = msg.desc.port_no
        if port_no in self.dp.ports:
            port_name = self.dp.ports[port_no].name
            points = [
                self.make_port_point(
                    self.dp.name, port_name, rcv_time, 'port_state_reason', reason)]
            if not self.ship_points(points):
                self.logger.warning(
                    '%s error shipping port_state_reason points', dpid_log(dp_id))


class GaugePortStatsInfluxDBLogger(GaugePortStatsPoller, InfluxShipper):
    """Periodically sends a port stats request to the datapath and parses
       and outputs the response.

> use faucet
Using database faucet
> show measurements
name: measurements
------------------
bytes_in
bytes_out
dropped_in
dropped_out
errors_in
packets_in
packets_out
port_state_reason
> precision rfc3339
> select * from packets_out where port_name = 'port1.0.1' order by time desc limit 10;
name: packets_out
-----------------
time                    dp_name                 port_name       value
2017-03-06T05:21:42Z    windscale-faucet-1      port1.0.1       76083431
2017-03-06T05:21:33Z    windscale-faucet-1      port1.0.1       76081172
2017-03-06T05:21:22Z    windscale-faucet-1      port1.0.1       76078727
2017-03-06T05:21:12Z    windscale-faucet-1      port1.0.1       76076612
2017-03-06T05:21:02Z    windscale-faucet-1      port1.0.1       76074546
2017-03-06T05:20:52Z    windscale-faucet-1      port1.0.1       76072730
2017-03-06T05:20:42Z    windscale-faucet-1      port1.0.1       76070528
2017-03-06T05:20:32Z    windscale-faucet-1      port1.0.1       76068211
2017-03-06T05:20:22Z    windscale-faucet-1      port1.0.1       76065982
2017-03-06T05:20:12Z    windscale-faucet-1      port1.0.1       76063941
    """

    def update(self, rcv_time, dp_id, msg):
        super(GaugePortStatsInfluxDBLogger, self).update(rcv_time, dp_id, msg)
        points = []
        for stat in msg.body:
            port_name = self._stat_port_name(msg, stat, dp_id)
            for stat_name, stat_val in self._format_port_stats('_', stat):
                points.append(
                    self.make_port_point(
                        self.dp.name, port_name, rcv_time, stat_name, stat_val))
        if not self.ship_points(points):
            self.logger.warning(
                '%s error shipping port_stats points', dpid_log(dp_id))


class GaugeFlowTableInfluxDBLogger(GaugeFlowTablePoller, InfluxShipper):
    """
> use faucet
Using database faucet
> show series where table_id = '0' and in_port = '2'
key
---
flow_byte_count,dp_name=windscale-faucet-1,eth_type=2048,in_port=2,ip_proto=17,priority=9099,table_id=0,udp_dst=53
flow_byte_count,dp_name=windscale-faucet-1,eth_type=2048,in_port=2,ip_proto=6,priority=9098,table_id=0,tcp_dst=53
flow_byte_count,dp_name=windscale-faucet-1,in_port=2,priority=9097,table_id=0
flow_packet_count,dp_name=windscale-faucet-1,eth_type=2048,in_port=2,ip_proto=17,priority=9099,table_id=0,udp_dst=53
flow_packet_count,dp_name=windscale-faucet-1,eth_type=2048,in_port=2,ip_proto=6,priority=9098,table_id=0,tcp_dst=53
flow_packet_count,dp_name=windscale-faucet-1,in_port=2,priority=9097,table_id=0
> select * from flow_byte_count where table_id = '0' and in_port = '2' and ip_proto = '17' and time > now() - 5m
name: flow_byte_count
time                arp_tpa dp_name            eth_dst eth_src eth_type icmpv6_type in_port ip_proto ipv4_dst ipv6_dst priority table_id tcp_dst udp_dst value vlan_vid
----                ------- -------            ------- ------- -------- ----------- ------- -------- -------- -------- -------- -------- ------- ------- ----- --------
1501154797000000000         windscale-faucet-1                 2048                 2       17                         9099     0                53      9414
1501154857000000000         windscale-faucet-1                 2048                 2       17                         9099     0                53      10554
1501154917000000000         windscale-faucet-1                 2048                 2       17                         9099     0                53      10554
1501154977000000000         windscale-faucet-1                 2048                 2       17                         9099     0                53      12164
1501155037000000000         windscale-faucet-1                 2048                 2       17                         9099     0                53      12239
"""

    def update(self, rcv_time, dp_id, msg):
        super(GaugeFlowTableInfluxDBLogger, self).update(rcv_time, dp_id, msg)
        jsondict = msg.to_jsondict()
        points = []
        for stats_reply in jsondict['OFPFlowStatsReply']['body']:
            stats = stats_reply['OFPFlowStats']
            packet_count = int(stats['packet_count'])
            byte_count = int(stats['byte_count'])
            instructions = stats['instructions']
            tags = {
                'dp_name': self.dp.name,
                'table_id': int(stats['table_id']),
                'priority': int(stats['priority']),
                'inst_count': len(instructions),
            }
            oxm_matches = stats['match']['OFPMatch']['oxm_fields']
            for oxm_match in oxm_matches:
                oxm_tlv = oxm_match['OXMTlv']
                mask = oxm_tlv['mask']
                val = oxm_tlv['value']
                field = oxm_tlv['field']
                if mask is not None:
                    val = '/'.join((val, mask))
                tags[field] = val
                if field == 'vlan_vid' and mask is None:
                    tags['vlan'] = devid_present(int(val))
            points.append(
                self.make_point(tags, rcv_time, 'flow_packet_count', packet_count))
            points.append(
                self.make_point(tags, rcv_time, 'flow_byte_count', byte_count))
        if not self.ship_points(points):
            self.logger.warning(
                '%s error shipping flow_table points', dpid_log(dp_id))
