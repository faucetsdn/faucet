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

import time, os, random, json

import logging
from logging.handlers import TimedRotatingFileHandler

from dp import DP
from util import kill_on_exception

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub

from influxdb import InfluxDBClient


# TODO: configurable
INFLUXDB_DB = "gauge"
INFLUXDB_HOST = "faucet-2"
INFLUXDB_PORT = 8086
INFLUXDB_USER = ""
INFLUXDB_PASS = ""


def ship_points_to_influxdb(points):
    client = InfluxDBClient(
        host=INFLUXDB_HOST, port=INFLUXDB_PORT,
        username=INFLUXDB_USER, password=INFLUXDB_PASS,
        database=INFLUXDB_DB, timeout=10)
    return client.write_points(points=points, time_precision='s')


class GaugePortStateLogger(object):

    def __init__(self, dp, ryudp, logname):
        self.dp = dp
        self.ryudp = ryudp
        self.logger = logging.getLogger(logname)

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


class GaugePortStateInfluxDBLogger(GaugePortStateLogger):

    def ship_points(self, points):
        return ship_points_to_influxdb(points)

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
    def __init__(self, dp, ryudp, logname):
        self.dp = dp
        self.ryudp = ryudp
        self.thread = None
        self.reply_pending = False
        self.logger = logging.getLogger(logname)
        # These values should be set by subclass
        self.interval = None
        self.logfile = None

    def start(self):
        self.stop()
        self.thread = hub.spawn(self)

    def stop(self):
        if self.thread is not None:
            hub.kill(self.thread)
            hub.joinall([self.thread])
            self.thread = None

    def __call__(self):
        """Send request loop.

        Delays the initial request for a random interval to reduce load.
        Then sends a request to the datapath, waits the specified interval and
        checks that a response has been received in a loop."""
        hub.sleep(random.randint(1, self.interval))
        while True:
            self.send_req()
            self.reply_pending = True
            hub.sleep(self.interval)
            if self.reply_pending:
                self.no_response()

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


class GaugeInfluxDBPoller(GaugePoller):

    def ship_points(self, points):
        return ship_points_to_influxdb(points)


class GaugePortStatsPoller(GaugePoller):
    """Periodically sends a port stats request to the datapath and parses and
    outputs the response."""
    def __init__(self, dp, ryudp, logname):
        super(GaugePortStatsPoller, self).__init__(dp, ryudp, logname)
        self.interval = self.dp.monitor_ports_interval
        self.logfile = self.dp.monitor_ports_file

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

            with open(self.logfile, 'a') as logfile:
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


class GaugePortStatsInfluxDBPoller(GaugeInfluxDBPoller):
    """Periodically sends a port stats request to the datapath and parses and
    outputs the response."""
    def __init__(self, dp, ryudp, logname):
        super(GaugePortStatsInfluxDBPoller, self).__init__(dp, ryudp, logname)
        self.interval = self.dp.monitor_ports_interval

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


class GaugeFlowTablePoller(GaugeInfluxDBPoller):
    """Periodically dumps the current datapath flow table as a yaml object.

    Includes a timestamp and a reference ($DATAPATHNAME-flowtables). The
    flow table is dumped as an OFFlowStatsReply message (in yaml format) that
    matches all flows."""
    def __init__(self, dp, ryudp, logname):

        super(GaugeFlowTablePoller, self).__init__(dp, ryudp, logname)
        self.interval = self.dp.monitor_flow_table_interval
        self.logfile = self.dp.monitor_flow_table_file

        #our internal record
        self.usageDict = {} #raw info with port level stat
        self.calDict = {} #byte count, IP level

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

        with open(self.logfile, 'a') as logfile:
            ref = self.dp.name + "-flowtables"
            
            # TODO: continue port stat to Inlfux DB
            #jsondict = msg.to_jsondict()
            #self.logger.info(json.dumps(jsondict, indent=4))
            
            body = msg.body
            testPoints = []
            for f in [flow for flow in body if (flow.priority == 20000 and flow.table_id == 0)]:
            #for f in [flow for flow in body]:

                dpid  = msg.datapath.id
                cookie = f.cookie
                packet_count = f.packet_count
                byte_count = f.byte_count

                '''
                self.logger.info('%016x %8x %8d %8d',
                                msg.datapath.id,
                                f.instructions[0].actions[0].port,
                                f.packet_count, f.byte_count)
                '''

                logfile.write("time: {0}\nref: {1}\nmsg: {2}\n".format(
                msg.datapath.id, f.cookie, f.byte_count)) 

                
                #Test Influx DB stuff
                testTags = {         
                        "flow_id":cookie,
                        }

                testPoints.append({
                            "measurement": "test1",
                            "tags": testTags,
                            "time": int(rcv_time),
                            "fields": {"value": int(f.byte_count + random.randint(1, 1000)) } })
            

                '''checking'''  
                if byte_count == 0:
                    continue

                #if (not hasattr(f.match, 'tcp_src') or not hasattr(a, 'tcp_dst')):
                 #   logfile.write("match: {0}\n".format(str(f.match))) 
                  #  continue

                logfile.write("Found Flow of Interest") 
                
                ip_src = str(f.match['ipv4_src'])
                ip_dst = str(f.match['ipv4_dst'])

                #process raw info and push to Influx DB
                #TODO: more processing
                points = []

                #Influx DB stuff

                if(f.match['tcp_src'] == 80):
                    endPointStr = "Mobile"
                else:
                    endPointStr = "Web browser"

                tags = {
                        "dst_ip": ip_dst,
                        "src_ip": ip_src,
                        "src_port":f.match['tcp_src'],
                        "dst_port":f.match['tcp_dst'],
                        "flow_id":cookie,
                        "Endpoint":endPointStr
                        }


                if cookie not in self.usageDict:
                    flowDict = {}
                    
                    flowDict["Time"] = int(rcv_time)
                    flowDict["cookie"] = cookie
                    flowDict["SourceIP"] = ip_src
                    flowDict["DestinationIP"] = ip_dst 
                    flowDict["tp_dst"] = f.match['tcp_dst']
                    flowDict["tp_src"] = f.match['tcp_src']
                    flowDict["Bytes"] = f.byte_count
                    flowDict["Duration"] = f.duration_sec
                    flowDict["RTime"] = 0
                    flowDict["RBytes"] = 0

                    self.usageDict[cookie] = flowDict

                    points.append({
                            "measurement": "volume",
                            "tags": tags,
                            "time": int(rcv_time),
                            "fields": {"value": float(f.byte_count) } })

                else:
                    flowDict = self.usageDict[cookie]

                    #only update if the count are different
                    if flowDict["Bytes"] != f.byte_count:

                        byteIncrement = f.byte_count - flowDict["Bytes"]
                        timeIncrement = int(rcv_time) - flowDict["Time"]

                        flowDict["Time"] = int(rcv_time)
                        flowDict["Bytes"] = f.byte_count
                        flowDict["Duration"] = f.duration_sec
                        flowDict["RTime"] = 0
                        flowDict["RBytes"] = 0

                        points.append({
                            "measurement": "volume",
                            "tags": tags,
                            "time": int(rcv_time),
                            "fields": {"value": float(f.byte_count) } })

                        points.append({
                            "measurement": "rate",
                            "tags": tags,
                            "time": int(rcv_time),
                            "fields": {"value": float(byteIncrement) } })

                        #avoid buffering time, mark byte count at 60s
                        if f.duration_sec > 60 and flowDict["RTime"] == 0:

                            flowDict["RTime"] = f.duration_sec
                            flowDict["RBytes"] = f.byte_count

                        self.usageDict[cookie] = flowDict


                        '''MBPS calculation'''
                        if ip_src not in self.calDict:
                            
                            entryDict = {}
                            #first entry
                            entryDict["Byte"] = byteIncrement;
                            entryDict["Time"] = int(rcv_time);
                            entryDict["TimePrevious"] = int(rcv_time);
                            entryDict["BytePrevious"] = byteIncrement;

                            dstDict = {}
                            dstDict[ip_dst] = entryDict
                            self.calDict[ip_src] = dstDict
                        else:
                            dstDict = self.calDict[ip_src]

                            if ip_dst not in dstDict:
                                entryDict = {}
                                #first entry
                                entryDict["Byte"] = byteIncrement;
                                entryDict["Time"] = int(rcv_time);
                                entryDict["TimePrevious"] = int(rcv_time);
                                entryDict["BytePrevious"] = byteIncrement;
                                dstDict[ip_dst] = entryDict
                            else:
                                entryDict = dstDict[ip_dst]
                                newByteCount = entryDict["Byte"] + byteIncrement;
                                entryDict["Byte"] = newByteCount 
                                entryDict["Time"] = int(rcv_time);

                                #if more than 10 sec from previous measurement
                                timeDiff = int(rcv_time) - entryDict["TimePrevious"]
                                if  timeDiff > 10:
                                    totalByteInc = float(newByteCount  - entryDict["BytePrevious"])
                                    Mbps = float(totalByteInc) * 8 / (timeDiff * 1024000)

                                    #reset previous record
                                    entryDict["TimePrevious"] = int(rcv_time);
                                    entryDict["BytePrevious"] = newByteCount;


                                    QualityStr = "???"
                                    if Mbps > 15:
                                        QualityStr = "???"
                                    elif Mbps > 10:
                                        QualityStr = "UHD"
                                    elif Mbps > 8:
                                        QualityStr = "UHD/HD"
                                    elif Mbps > 5:
                                        QualityStr = "HD"
                                    elif Mbps > 2:
                                        QualityStr = "HD/SD"
                                    elif Mbps > 0.3:
                                        QualityStr = "SD"
                                    else:
                                        QualityStr = "???"
                                        pass

                                    MbpsTags = {
                                                "dst_ip": ip_dst,
                                                "src_ip": ip_src,
                                                "src_port":f.match['tcp_src'],
                                                "Quality" :QualityStr,
                                                "Endpoint":endPointStr
                                        }

                                    #update Mbps measurement
                                    points.append({
                                        "measurement": "Mbps",
                                        "tags": MbpsTags,
                                        "time": int(rcv_time),
                                        "fields": {"value": float(Mbps } })

                self.ship_points(points)

            self.ship_points(testPoints)

                    
    def no_response(self):
        self.logger.info(
            "flow dump request timed out for {0}".format(self.dp.name))


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
            'FAUCET_EXCEPTION_LOG', '/var/log/faucet/faucet_exception.log')
        self.logfile = os.getenv('GAUGE_LOG', '/var/log/faucet/gauge.log')

        # Setup logging
        self.logger = logging.getLogger(__name__)
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

        self.dps = {}
        with open(self.config_file, 'r') as config_file:
            for dp_conf_file in config_file:
                # config_file should be a list of faucet config filenames
                # separated by linebreaks
                dp = DP.parser(dp_conf_file.strip(), self.logname)
                try:
                    dp.sanity_check()
                except AssertionError:
                    self.logger.exception(
                        "Error in config file {0}".format(dp_conf_file))
                else:
                    self.dps[dp.dp_id] = dp

        # Create dpset object for querying Ryu's DPSet application
        self.dpset = kwargs['dpset']

        # dict of polling threads:
        # polling threads are indexed by dp_id and then by name
        # eg: self.pollers[0x1]['port_stats']
        self.pollers = {}
        # dict of async event handlers
        self.handlers = {}

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    @kill_on_exception(exc_logname)
    def handler_datapath(self, ev):
        ryudp = ev.dp
        if ryudp.id not in self.dps:
            self.logger.info("dp not in self.dps {0}".format(ryudp.id))
            return

        dp = self.dps[ryudp.id]

        if ev.enter:
            # Set up a thread to poll for port stats
            # TODO: set up threads to poll for other stats as well
            # TODO: allow the different things to be polled for to be
            # configurable
            self.logger.info("datapath up %x", dp.dp_id)
            dp.running = True
            if dp.dp_id not in self.pollers:
                self.pollers[dp.dp_id] = {}
                self.handlers[dp.dp_id] = {}

            if dp.influxdb_stats:
                port_state_handler = GaugePortStateInfluxDBLogger(
                    dp, ryudp, self.logname)
            else:
                port_state_handler = GaugePortStateLogger(
                    dp, ryudp, self.logname)
            self.handlers[dp.dp_id]['port_state'] = port_state_handler

            if dp.monitor_ports:
                if dp.influxdb_stats:
                    port_stats_poller = GaugePortStatsInfluxDBPoller(
                       dp, ryudp, self.logname)
                else:
                    port_stats_poller = GaugePortStatsPoller(
                        dp, ryudp, self.logname)
                self.pollers[dp.dp_id]['port_stats'] = port_stats_poller
                port_stats_poller.start()

            if dp.monitor_flow_table:
                flow_table_poller = GaugeFlowTablePoller(
                    dp, ryudp, self.logname)
                self.pollers[dp.dp_id]['flow_table'] = flow_table_poller
                flow_table_poller.start()

        else:
            if dp.dp_id in self.pollers:
                for poller in self.pollers[dp.dp_id].values():
                    poller.stop()
                    del self.pollers[dp.dp_id]
            self.logger.info("datapath down %x", dp.dp_id)
            dp.running = False

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    @kill_on_exception(exc_logname)
    def port_status_handler(self, ev):
        rcv_time = time.time()
        dp = self.dps[ev.msg.datapath.id]
        self.handlers[dp.dp_id]['port_state'].update(rcv_time, ev.msg)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    @kill_on_exception(exc_logname)
    def port_stats_reply_handler(self, ev):
        rcv_time = time.time()
        dp = self.dps[ev.msg.datapath.id]
        self.pollers[dp.dp_id]['port_stats'].update(rcv_time, ev.msg)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    @kill_on_exception(exc_logname)
    def flow_stats_reply_handler(self, ev):
        rcv_time = time.time()
        dp = self.dps[ev.msg.datapath.id]
        self.pollers[dp.dp_id]['flow_table'].update(rcv_time, ev.msg)



