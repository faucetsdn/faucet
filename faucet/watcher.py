import logging
import random
import json
import time

import numpy

from influxdb import InfluxDBClient
from influxdb.exceptions import InfluxDBClientError, InfluxDBServerError
from requests.exceptions import ConnectionError
from ryu.lib import hub
from nsodbc import nsodbc_factory, init_switch_db, init_flow_db

from valve_util import dpid_log


def watcher_factory(conf):
    """Return a Gauge object based on type.

    Arguments:
    gauge_conf -- a GaugeConf object with the configuration for this valve.
    """

    WATCHER_TYPES = {
        'port_state': {
            'text': GaugePortStateLogger,
            'influx': GaugePortStateInfluxDBLogger,
            },
        'port_stats': {
            'text': GaugePortStatsPoller,
            'influx': GaugePortStatsInfluxDBPoller,
            },
        'flow_table': {
            'text': GaugeFlowTablePoller,
            'gaugedb': GaugeFlowTableDBLogger,
            },
    }

    w_type = conf.type
    db_type = conf.db_type
    if w_type in WATCHER_TYPES and db_type in WATCHER_TYPES[w_type]:
        return WATCHER_TYPES[w_type][db_type]
    else:
        return None


def _rcv_time(rcv_time):
    return time.strftime('%b %d %H:%M:%S', time.localtime(rcv_time))


class InfluxShipper(object):
    """Convenience class for shipping values to influx db.

    Inheritors must have a WatcherConf object as conf.
    """
    conf = None

    def ship_points(self, points):
        try:
            client = InfluxDBClient(
                host=self.conf.influx_host,
                port=self.conf.influx_port,
                username=self.conf.influx_user,
                password=self.conf.influx_pwd,
                database=self.conf.influx_db,
                timeout=self.conf.influx_timeout)
            return client.write_points(points=points, time_precision='s')
        except (ConnectionError, InfluxDBClientError, InfluxDBServerError):
            return False

    def make_point(self, dp_name, port_name, rcv_time, stat_name, stat_val):
        port_tags = {
            'dp_name': dp_name,
            'port_name': port_name,
        }
        # InfluxDB has only one integer type, int64. We are logging OF
        # stats that are uint64. Use float64 to prevent an overflow.
        # q.v. https://docs.influxdata.com/influxdb/v1.2/write_protocols/line_protocol_reference/
        point = {
            'measurement': stat_name,
            'tags': port_tags,
            'time': int(rcv_time),
            # pylint: disable=no-member
            'fields': {'value': numpy.float64(stat_val)}}
        return point


class GaugeDBHelper(object):
    """
    Helper class for gaugedb operations

    Inheritors must have a WatcherConf object as conf.
    """
    conf = None
    db_update_counter = None
    conn_string = None
    switch_database = None
    flow_database = None
    conn = None

    def setup(self):
        self.conn_string = (
            'driver={0};server={1};port={2};uid={3};pwd={4}'.format(
                self.conf.driver, self.conf.db_ip, self.conf.db_port,
                self.conf.db_username, self.conf.db_password))
        nsodbc = nsodbc_factory()
        self.conn = nsodbc.connect(self.conn_string)
        self.switch_database, exists = self.conn.create(self.conf.switches_doc)
        if not exists:
            init_switch_db(self.switch_database)
        self.flow_database, exists = self.conn.create(self.conf.flows_doc)
        if not exists:
            init_flow_db(self.flow_database)
        self.db_update_counter = int(self.conf.db_update_counter)

    def refresh_switchdb(self):
        self.conn.delete(self.conf.switches_doc)
        self.switch_database, _ = self.conn.create(self.conf.switches_doc)
        init_switch_db(self.switch_database)

    def refresh_flowdb(self):
        self.conn.delete(self.conf.flows_doc)
        self.flow_database, _ = self.conn.create(self.conf.flows_doc)
        init_flow_db(self.flow_database)


class GaugePortStateLogger(object):

    def __init__(self, conf, logname):
        self.dp = conf.dp
        self.conf = conf
        self.logger = logging.getLogger(
            logname + '.{0}'.format(self.conf.type)
            )

    def update(self, rcv_time, dp_id, msg):
        rcv_time_str = _rcv_time(rcv_time)
        reason = msg.reason
        port_no = msg.desc.port_no
        ofp = msg.datapath.ofproto
        log_msg = 'port %s unknown state %s' % (port_no, reason)
        if reason == ofp.OFPPR_ADD:
            log_msg = 'port %s added' % port_no
        elif reason == ofp.OFPPR_DELETE:
            log_msg = 'port %s deleted' % port_no
        elif reason == ofp.OFPPR_MODIFY:
            link_down = (msg.desc.state & ofp.OFPPS_LINK_DOWN)
            if link_down:
                log_msg = 'port %s down' % port_no
            else:
                log_msg = 'port %s up' % port_no
        log_msg = '%s %s' % (dpid_log(dp_id), log_msg)
        self.logger.info(log_msg)
        if self.conf.file:
            with open(self.conf.file, 'a') as logfile:
                logfile.write('\t'.join((rcv_time_str, log_msg)) + '\n')

    def start(self, ryudp):
        pass

    def stop(self):
        pass


class GaugePortStateInfluxDBLogger(GaugePortStateLogger, InfluxShipper):
    """
> use faucet
Using database faucet
> precision rfc3339
> select * from port_state_reason where port_name = 'port1.0.1' order by time desc limit 10;
name: port_state_reason
-----------------------
time			dp_name			port_name	value
2017-02-21T02:12:29Z	windscale-faucet-1	port1.0.1	2
2017-02-21T02:12:25Z	windscale-faucet-1	port1.0.1	2
2016-07-27T22:05:08Z	windscale-faucet-1	port1.0.1	2
2016-05-25T04:33:00Z	windscale-faucet-1	port1.0.1	2
2016-05-25T04:32:57Z	windscale-faucet-1	port1.0.1	2
2016-05-25T04:31:21Z	windscale-faucet-1	port1.0.1	2
2016-05-25T04:31:18Z	windscale-faucet-1	port1.0.1	2
2016-05-25T04:27:07Z	windscale-faucet-1	port1.0.1	2
2016-05-25T04:27:04Z	windscale-faucet-1	port1.0.1	2
2016-05-25T04:24:53Z	windscale-faucet-1	port1.0.1	2
    """

    def __init__(self, conf, logname):
        super(GaugePortStateInfluxDBLogger, self).__init__(conf, logname)

    def update(self, rcv_time, dp_id, msg):
        super(GaugePortStateInfluxDBLogger, self).update(rcv_time, dp_id, msg)
        reason = msg.reason
        port_no = msg.desc.port_no
        if port_no in self.dp.ports:
            port_name = self.dp.ports[port_no].name
            points = [
                self.make_point(
                    self.dp.name, port_name, rcv_time, 'port_state_reason', reason)]
            if not self.ship_points(points):
                self.logger.warning(
                    '%s error shipping port_state_reason points', dpid_log(dp_id))


class GaugePoller(object):
    """A ryu thread object for sending and receiving openflow stats requests.

    The thread runs in a loop sending a request, sleeping then checking a
    response was received before sending another request.

    The methods send_req, update and no_response should be implemented by
    subclasses.
    """

    def __init__(self, conf, logname):
        self.dp = conf.dp
        self.conf = conf
        self.thread = None
        self.reply_pending = False
        self.interval = self.conf.interval
        self.logger = logging.getLogger(
            logname + '.{0}'.format(self.conf.type)
            )
        self.ryudp = None

    def start(self, ryudp):
        self.ryudp = ryudp
        self.stop()
        self.thread = hub.spawn(self)

    def stop(self):
        if self.running():
            hub.kill(self.thread)
            hub.joinall([self.thread])
            self.thread = None

    def __call__(self):
        """Send request loop.

        Delays the initial request for a random interval to reduce load.
        Then sends a request to the datapath, waits the specified interval and
        checks that a response has been received in a loop."""
        #TODO: this should use a deterministic method instead of random
        hub.sleep(random.randint(1, self.conf.interval))
        while True:
            self.send_req()
            self.reply_pending = True
            hub.sleep(self.conf.interval)
            if self.reply_pending:
                self.no_response()

    def running(self):
        return self.thread is not None

    def send_req(self):
        """Send a stats request to a datapath."""
        raise NotImplementedError

    def update(self, rcv_time, dp_id, msg):
        """Handle the responses to requests.

        Called when a reply to a stats request sent by this object is received
        by the controller.

        It should acknowledge the receipt by setting self.reply_pending to
        false.

        Arguments:
        rcv_time -- the time the response was received
        dp_id -- DP ID
        msg -- the stats reply message
        """
        raise NotImplementedError

    def no_response(self):
        """Called when a polling cycle passes without receiving a response."""
        raise NotImplementedError

    def _stat_port_name(self, msg, stat, dp_id):
        if stat.port_no == msg.datapath.ofproto.OFPP_CONTROLLER:
            return 'CONTROLLER'
        elif stat.port_no == msg.datapath.ofproto.OFPP_LOCAL:
            return 'LOCAL'
        elif stat.port_no in self.dp.ports:
            return self.dp.ports[stat.port_no].name
        else:
            self.logger.info('%s stats for unknown port %u',
                             dpid_log(dp_id), stat.port_no)
            return None

    def _format_port_stats(self, delim, stat):
        formatted_port_stats = []
        for stat_name_list, stat_val in (
                (('packets', 'out'), stat.tx_packets),
                (('packets', 'in'), stat.rx_packets),
                (('bytes', 'out'), stat.tx_bytes),
                (('bytes', 'in'), stat.rx_bytes),
                (('dropped', 'out'), stat.tx_dropped),
                (('dropped', 'in'), stat.rx_dropped),
                (('errors', 'in'), stat.rx_errors)):
            # For openvswitch, unsupported statistics are set to
            # all-1-bits (UINT64_MAX), skip reporting them
            if stat_val != 2**64-1:
                stat_name = delim.join(stat_name_list)
                formatted_port_stats.append((stat_name, stat_val))
        return formatted_port_stats


class GaugePortStatsPoller(GaugePoller):
    """Periodically sends a port stats request to the datapath and parses
       and outputs the response.
    """

    def __init__(self, conf, logname):
        super(GaugePortStatsPoller, self).__init__(conf, logname)

    def send_req(self):
        ofp = self.ryudp.ofproto
        ofp_parser = self.ryudp.ofproto_parser
        req = ofp_parser.OFPPortStatsRequest(self.ryudp, 0, ofp.OFPP_ANY)
        self.ryudp.send_msg(req)

    def _update_line(self, rcv_time_str, stat_name, stat_val):
        return '\t'.join((rcv_time_str, stat_name, str(stat_val))) + '\n'

    def update(self, rcv_time, dp_id, msg):
        # TODO: it may be worth while verifying this is the correct stats
        # response before doing this
        rcv_time_str = _rcv_time(rcv_time)
        self.reply_pending = False
        for stat in msg.body:
            port_name = self._stat_port_name(msg, stat, dp_id)
            if port_name is not None:
                with open(self.conf.file, 'a') as logfile:
                    log_lines = []
                    for stat_name, stat_val in self._format_port_stats('-', stat):
                        dp_port_name = '-'.join((
                            self.dp.name, port_name, stat_name))
                        log_lines.append(
                            self._update_line(
                                rcv_time_str, dp_port_name, stat_val))
                    logfile.writelines(log_lines)

    def no_response(self):
        self.logger.info(
            'port stats request timed out for %s', self.dp.name)


class GaugePortStatsInfluxDBPoller(GaugePoller, InfluxShipper):
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
time			dp_name			port_name	value
2017-03-06T05:21:42Z	windscale-faucet-1	port1.0.1	76083431
2017-03-06T05:21:33Z	windscale-faucet-1	port1.0.1	76081172
2017-03-06T05:21:22Z	windscale-faucet-1	port1.0.1	76078727
2017-03-06T05:21:12Z	windscale-faucet-1	port1.0.1	76076612
2017-03-06T05:21:02Z	windscale-faucet-1	port1.0.1	76074546
2017-03-06T05:20:52Z	windscale-faucet-1	port1.0.1	76072730
2017-03-06T05:20:42Z	windscale-faucet-1	port1.0.1	76070528
2017-03-06T05:20:32Z	windscale-faucet-1	port1.0.1	76068211
2017-03-06T05:20:22Z	windscale-faucet-1	port1.0.1	76065982
2017-03-06T05:20:12Z	windscale-faucet-1	port1.0.1	76063941
    """

    def __init__(self, conf, logname):
        super(GaugePortStatsInfluxDBPoller, self).__init__(conf, logname)

    def send_req(self):
        ofp = self.ryudp.ofproto
        ofp_parser = self.ryudp.ofproto_parser
        req = ofp_parser.OFPPortStatsRequest(self.ryudp, 0, ofp.OFPP_ANY)
        self.ryudp.send_msg(req)

    def update(self, rcv_time, dp_id, msg):
        # TODO: it may be worth while verifying this is the correct stats
        # response before doing this
        self.reply_pending = False
        points = []
        for stat in msg.body:
            port_name = self._stat_port_name(msg, stat, dp_id)
            for stat_name, stat_val in self._format_port_stats('_', stat):
                points.append(
                    self.make_point(
                        self.dp.name, port_name, rcv_time, stat_name, stat_val))
        if not self.ship_points(points):
            self.logger.warn(
                '%s error shipping port_stats points', dpid_log(dp_id))

    def no_response(self):
        self.logger.info(
            'port stats request timed out for %s', self.dp.name)


class GaugeFlowTablePoller(GaugePoller):
    """Periodically dumps the current datapath flow table as a yaml object.

    Includes a timestamp and a reference ($DATAPATHNAME-flowtables). The
    flow table is dumped as an OFFlowStatsReply message (in yaml format) that
    matches all flows.
    """

    def __init__(self, conf, logname):
        super(GaugeFlowTablePoller, self).__init__(conf, logname)

    def send_req(self):
        ofp = self.ryudp.ofproto
        ofp_parser = self.ryudp.ofproto_parser
        match = ofp_parser.OFPMatch()
        req = ofp_parser.OFPFlowStatsRequest(
            self.ryudp, 0, ofp.OFPTT_ALL, ofp.OFPP_ANY, ofp.OFPG_ANY,
            0, 0, match)
        self.ryudp.send_msg(req)

    def update(self, rcv_time, dp_id, msg):
        # TODO: it may be worth while verifying this is the correct stats
        # response before doing this
        rcv_time_str = _rcv_time(rcv_time)
        self.reply_pending = False
        jsondict = msg.to_jsondict()
        with open(self.conf.file, 'a') as logfile:
            ref = '-'.join((self.dp.name, 'flowtables'))
            logfile.write(
                '\n'.join((
                    '---',
                    'time: %s' % rcv_time_str,
                    'ref: %s' % ref,
                    'msg: %s' % json.dumps(jsondict, indent=4))))

    def no_response(self):
        self.logger.info(
            'flow dump request timed out for %s', self.dp.name)


class GaugeFlowTableDBLogger(GaugePoller, GaugeDBHelper):
    """Periodically dumps the current datapath flow table as a yaml object.

    Includes a timestamp and a reference ($DATAPATHNAME-flowtables). The
    flow table is dumped as an OFFlowStatsReply message (in yaml format) that
    matches all flows.
    """

    def __init__(self, conf, logname):
        super(GaugeFlowTableDBLogger, self).__init__(conf, logname)
        self.setup()

    def send_req(self):
        ofp = self.ryudp.ofproto
        ofp_parser = self.ryudp.ofproto_parser
        match = ofp_parser.OFPMatch()
        req = ofp_parser.OFPFlowStatsRequest(
            self.ryudp, 0, ofp.OFPTT_ALL, ofp.OFPP_ANY, ofp.OFPG_ANY,
            0, 0, match)
        self.ryudp.send_msg(req)

    def update(self, rcv_time, dp_id, msg):
        # TODO: it may be worth while verifying this is the correct stats
        # response before doing this
        self.reply_pending = False
        jsondict = msg.to_jsondict()
        if self.db_update_counter == self.conf.db_update_counter:
            self.refresh_switchdb()
            switch_object = {'_id': str(hex(self.dp.dp_id)),
                             'data': {'flows': []}}
            self.switch_database.insert_update_doc(switch_object,
                                                   'data')
            try:
                rows = self.switch_database.get_docs(
                    self.conf.views['switch_view'],
                    key=str(hex(self.dp.dp_id)))
                switch = rows[0]
            except IndexError:
                switch = None

            if switch:
                self.refresh_flowdb()
                for f_msg in jsondict['OFPFlowStatsReply']['body']:
                    flow_object = {'data': f_msg, 'tags': []}
                    flow_id = self.flow_database.insert_update_doc(
                        flow_object, '')
                    switch.value['data']['flows'].append(flow_id)
                    self.switch_database.insert_update_doc(
                        switch.value, 'data')
        self.db_update_counter -= 1
        if not self.db_update_counter:
            self.db_update_counter = self.conf.db_update_counter

    def no_response(self):
        self.logger.info(
            'flow dump request timed out for %s', self.dp.name)
