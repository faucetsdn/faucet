import logging
import random
import json
import time
import yaml
import os

from ryu.lib import hub
from influxdb import InfluxDBClient
from nsodbc import nsodbc_factory

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
            }
    }

    w_type = conf.type
    db_type = conf.db_type
    if w_type in WATCHER_TYPES and db_type in WATCHER_TYPES[w_type]:
        return WATCHER_TYPES[w_type][db_type]
    else:
        return None

def init_flow_db(flow_database):
    """
    Initialize/Refresh flow database
    Args:
        flow_database
    """
    views = {}
    views["flow"] = {}
    views["flow"]["map"] = "function(doc) " + \
                           "{\n  emit(doc._id, doc);\n}"
    views["match"] = {}
    views["match"]["map"] = "function(doc) " + \
                            "{\nif(doc.data.OFPFlowStats.match)" + \
                            "{\n  emit(" + \
                            "[doc.data.OFPFlowStats.table_id, " + \
                            "doc.data.OFPFlowStats.match], " + \
                            "doc );\n}\n}"
    flow_database.create_view("flows", views)


def init_switch_db(switch_database):
    """
    Initialize/refresh switch database
    Args:
        switch_database
    """
    views = {}
    views["switch"] = {}
    views["switch"]["map"] = "function(doc) " + \
                             "{\n  emit(doc._id, doc);\n}"
    switch_database.create_view("switches", views)

class InfluxShipper(object):
    """Convenience class for shipping values to influx db.

    Inheritors must have a WatcherConf object as conf.
    """
    def ship_points(self, points):
        client = InfluxDBClient(
            host=self.conf.influx_host,
            port=self.conf.influx_port,
            username=self.conf.influx_user,
            password=self.conf.influx_pwd,
            database=self.conf.influx_db,
            timeout=self.conf.influx_timeout)
        return client.write_points(points=points, time_precision='s')

class GaugePortStateLogger(object):

    def __init__(self, conf, logname):
        self.dp = conf.dp
        self.conf = conf
        self.logger = logging.getLogger(
            logname + '.{0}'.format(self.conf.type)
            )

    def update(self, rcv_time, msg):
        reason = msg.reason
        port_no = msg.desc.port_no
        ofp = msg.datapath.ofproto
        if reason == ofp.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofp.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofp.OFPPR_MODIFY:
            link_down = (msg.desc.state & ofp.OFPPS_LINK_DOWN)
            if link_down:
                self.logger.info("port deleted %s", port_no)
            else:
                self.logger.info("port added %s", port_no)
        else:
            self.logger.info("Illegal port state %s %s", port_no, reason)

    def start(self, ryudp):
        pass

    def stop(self, ryudp):
        pass

class GaugePortStateInfluxDBLogger(GaugePortStateLogger, InfluxShipper):

    def __init__(self, conf, logname):
        super(GaugePortStateInfluxDBLogger, self).__init__(conf, logname)

    def update(self, rcv_time, msg):
        super(GaugePortStateInfluxDBLogger, self).update(rcv_time, msg)
        reason = msg.reason
        port_no = msg.desc.port_no
        if port_no in self.dp.ports:
            port_name = self.dp.ports[port_no].name
            port_tags = {
                "dp_name": self.dp.name,
                "port_name": port_name,
            }
            points = [{
                "measurement": "port_state_reason",
                "tags": port_tags,
                "time": int(rcv_time),
                "fields": {"value": reason}}]
            if not self.ship_points(points):
                self.logger.warning("error shipping port_state_reason points")


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

    def update(self, rcv_time, msg):
        """Handle the responses to requests.

        Called when a reply to a stats request sent by this object is received
        by the controller.

        It should acknowledge the receipt by setting self.reply_pending to
        false.

        Arguments:
        rcv_time -- the time the response was received
        msg -- the stats reply message
        """
        raise NotImplementedError

    def no_response(self):
        """Called when a polling cycle passes without receiving a response."""
        raise NotImplementedError


class GaugePortStatsPoller(GaugePoller):
    """Periodically sends a port stats request to the datapath and parses and
    outputs the response."""

    def __init__(self, conf, logname):
        super(GaugePortStatsPoller, self).__init__(conf, logname)

    def send_req(self):
        ofp = self.ryudp.ofproto
        ofp_parser = self.ryudp.ofproto_parser
        req = ofp_parser.OFPPortStatsRequest(self.ryudp, 0, ofp.OFPP_ANY)
        self.ryudp.send_msg(req)

    def update(self, rcv_time, msg):
        # TODO: it may be worth while verifying this is the correct stats
        # response before doing this
        self.reply_pending = False
        rcv_time_str = time.strftime('%b %d %H:%M:%S')

        for stat in msg.body:
            if stat.port_no == msg.datapath.ofproto.OFPP_CONTROLLER:
                ref = self.dp.name + "-CONTROLLER"
            elif stat.port_no == msg.datapath.ofproto.OFPP_LOCAL:
                ref = self.dp.name + "-LOCAL"
            elif stat.port_no not in self.dp.ports:
                self.logger.info("stats for unknown port %s", stat.port_no)
                continue
            else:
                ref = self.dp.name + "-" + self.dp.ports[stat.port_no].name

            with open(self.conf.file, 'a') as logfile:
                logfile.write('{0}\t{1}\t{2}\n'.format(rcv_time_str,
                                                       ref + "-packets-out",
                                                       stat.tx_packets))
                logfile.write('{0}\t{1}\t{2}\n'.format(rcv_time_str,
                                                       ref + "-packets-in",
                                                       stat.rx_packets))
                logfile.write('{0}\t{1}\t{2}\n'.format(rcv_time_str,
                                                       ref + "-bytes-out",
                                                       stat.tx_bytes))
                logfile.write('{0}\t{1}\t{2}\n'.format(rcv_time_str,
                                                       ref + "-bytes-in",
                                                       stat.rx_bytes))
                logfile.write('{0}\t{1}\t{2}\n'.format(rcv_time_str,
                                                       ref + "-dropped-out",
                                                       stat.tx_dropped))
                logfile.write('{0}\t{1}\t{2}\n'.format(rcv_time_str,
                                                       ref + "-dropped-in",
                                                       stat.rx_dropped))
                logfile.write('{0}\t{1}\t{2}\n'.format(rcv_time_str,
                                                       ref + "-errors-in",
                                                       stat.rx_errors))

    def no_response(self):
        self.logger.info(
            "port stats request timed out for {0}".format(self.dp.name))


class GaugePortStatsInfluxDBPoller(GaugePoller, InfluxShipper):
    """Periodically sends a port stats request to the datapath and parses and
    outputs the response."""

    def __init__(self, conf, logname):
        super(GaugePortStatsInfluxDBPoller, self).__init__(conf, logname)

    def send_req(self):
        ofp = self.ryudp.ofproto
        ofp_parser = self.ryudp.ofproto_parser
        req = ofp_parser.OFPPortStatsRequest(self.ryudp, 0, ofp.OFPP_ANY)
        self.ryudp.send_msg(req)

    def update(self, rcv_time, msg):
        # TODO: it may be worth while verifying this is the correct stats
        # response before doing this
        self.reply_pending = False
        points = []

        for stat in msg.body:
            if stat.port_no == msg.datapath.ofproto.OFPP_CONTROLLER:
                port_name = "CONTROLLER"
            elif stat.port_no == msg.datapath.ofproto.OFPP_LOCAL:
                port_name = "LOCAL"
            elif stat.port_no not in self.dp.ports:
                self.logger.info("stats for unknown port %s", stat.port_no)
                continue
            else:
                port_name = self.dp.ports[stat.port_no].name

            port_tags = {
                "dp_name": self.dp.name,
                "port_name": port_name,
            }

            for stat_name, stat_value in (
                ("packets_out", stat.tx_packets),
                ("packets_in", stat.rx_packets),
                ("bytes_out", stat.tx_bytes),
                ("bytes_in", stat.rx_bytes),
                ("dropped_out", stat.tx_dropped),
                ("dropped_in", stat.rx_dropped),
                ("errors_in", stat.rx_errors)):
                points.append({
                    "measurement": stat_name,
                    "tags": port_tags,
                    "time": int(rcv_time),
                    "fields": {"value": stat_value}})
        if not self.ship_points(points):
            self.logger.warn("error shipping port_stats points")

    def no_response(self):
        self.logger.info(
            "port stats request timed out for {0}".format(self.dp.name))


class GaugeFlowTablePoller(GaugePoller):
    """Periodically dumps the current datapath flow table as a yaml object.

    Includes a timestamp and a reference ($DATAPATHNAME-flowtables). The
    flow table is dumped as an OFFlowStatsReply message (in yaml format) that
    matches all flows."""

    def __init__(self, conf, logname):
        super(GaugeFlowTablePoller, self).__init__(conf, logname)
        # Database specific config file read
        self.db_config = os.getenv(
            'GAUGE_DB_CONFIG', '/etc/ryu/faucet/gauge_db.yaml')
        self.db_enabled = False
        self.flow_database = None
        self.switch_database = None
        self.conn = None
        with open(self.db_config, 'r') as stream:
            data = yaml.load(stream)
            if data['database']:
                self.db_enabled = True
                self.conn_string = "driver={0};server={1};port={2};" \
                                   "uid={3};pwd={4}".format(
                    data['driver'], data['db_ip'], str(data['db_port']),
                    str(data['db_username']), str(data['db_password'])
                )
                nsodbc = nsodbc_factory()
                self.conn = nsodbc.connect(self.conn_string)
                self.switch_database, exists = self.conn.create(
                    data['switches_doc'])
                # Create database specific views for querying
                if not exists:
                    init_switch_db(self.switch_database)

                self.flow_database, exists = self.conn.create(
                    data['flows_doc'])
                # Create database specific views for querying
                if not exists:
                    init_flow_db(self.flow_database)
                self.db_conf_data = data
        # TODO: DB update counter can be made configurable
        self.db_update_counter = 5

    def send_req(self):
        ofp = self.ryudp.ofproto
        ofp_parser = self.ryudp.ofproto_parser
        match = ofp_parser.OFPMatch()
        req = ofp_parser.OFPFlowStatsRequest(
            self.ryudp, 0, ofp.OFPTT_ALL, ofp.OFPP_ANY, ofp.OFPG_ANY,
            0, 0, match)
        self.ryudp.send_msg(req)

    def update(self, rcv_time, msg):
        # TODO: it may be worth while verifying this is the correct stats
        # response before doing this
        self.reply_pending = False
        jsondict = msg.to_jsondict()
        rcv_time_str = time.strftime('%b %d %H:%M:%S')

        with open(self.conf.file, 'a') as logfile:
            ref = self.dp.name + "-flowtables"
            logfile.write("---\n")
            logfile.write("time: {0}\nref: {1}\nmsg: {2}\n".format(
                rcv_time_str, ref, json.dumps(jsondict, indent=4)))

        if self.db_enabled and self.db_update_counter == 5:
            self.conn.delete(self.db_conf_data['switches_doc'])
            self.switch_database, _ = self.conn.create(
                    self.db_conf_data['switches_doc'])
            init_switch_db(self.switch_database)
            switch_object = {'_id': str(hex(self.dp.dp_id)),
                            'data':{'flows':[]}}
            self.switch_database.insert_update_doc(switch_object,
                                                   'data')
            try:
                rows = self.switch_database.get_docs(
                    self.db_conf_data['views']['v1'],
                    key=str(hex(self.dp.dp_id)))
                switch = rows[0]
            except IndexError:
                switch = None

            if switch:
                self.conn.delete(self.db_conf_data['flows_doc'])
                self.flow_database, _ = self.conn.create(
                    self.db_conf_data['flows_doc'])
                init_flow_db(self.flow_database)
                for f_msg in jsondict['OFPFlowStatsReply']['body']:
                    flow_object = {'data': f_msg, 'tags': []}
                    flow_id = self.flow_database.insert_update_doc(
                        flow_object, '')
                    switch.value['data']['flows'].append(flow_id)
                    self.switch_database.insert_update_doc(
                        switch.value, 'data')

        self.db_update_counter -= 1
        if not self.db_update_counter:
            self.db_update_counter = 5

    def no_response(self):
        self.logger.info(
            "flow dump request timed out for {0}".format(self.dp.name))


