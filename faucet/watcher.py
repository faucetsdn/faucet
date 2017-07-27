import logging
import json
import time

try:
    from valve_util import dpid_log
    from gauge_influx import InfluxShipper
    from gauge_nsodbc import GaugeNsODBC
    from gauge_pollers import GaugePortStatsPoller, GaugeFlowTablePoller
except ImportError:
    from faucet.valve_util import dpid_log
    from faucet.gauge_influx import InfluxShipper
    from faucet.gauge_nsodbc import GaugeNsODBC
    from faucet.gauge_pollers import GaugePortStatsPoller, GaugeFlowTablePoller


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
            'text': GaugePortStatsLogger,
            'influx': GaugePortStatsInfluxDBLogger,
            },
        'flow_table': {
            'text': GaugeFlowTableLogger,
            'gaugedb': GaugeFlowTableDBLogger,
            },
    }

    w_type = conf.type
    db_type = conf.db_type
    if w_type in WATCHER_TYPES and db_type in WATCHER_TYPES[w_type]:
        return WATCHER_TYPES[w_type][db_type]
    return None


def _rcv_time(rcv_time):
    return time.strftime('%b %d %H:%M:%S', time.localtime(rcv_time))


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


class GaugePortStatsLogger(GaugePortStatsPoller):

    def _update_line(self, rcv_time_str, stat_name, stat_val):
        return '\t'.join((rcv_time_str, stat_name, str(stat_val))) + '\n'

    def update(self, rcv_time, dp_id, msg):
        super(GaugePortStatsLogger, self).update(rcv_time, dp_id, msg)
        rcv_time_str = _rcv_time(rcv_time)
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
            self.logger.warn(
                '%s error shipping port_stats points', dpid_log(dp_id))


class GaugeFlowTableLogger(GaugeFlowTablePoller):
    """Periodically dumps the current datapath flow table as a yaml object.

    Includes a timestamp and a reference ($DATAPATHNAME-flowtables). The
    flow table is dumped as an OFFlowStatsReply message (in yaml format) that
    matches all flows.
    """

    def update(self, rcv_time, dp_id, msg):
        super(GaugeFlowTableLogger, self).update(rcv_time, dp_id, msg)
        rcv_time_str = _rcv_time(rcv_time)
        jsondict = msg.to_jsondict()
        with open(self.conf.file, 'a') as logfile:
            ref = '-'.join((self.dp.name, 'flowtables'))
            logfile.write(
                '\n'.join((
                    '---',
                    'time: %s' % rcv_time_str,
                    'ref: %s' % ref,
                    'msg: %s' % json.dumps(jsondict, indent=4))))


class GaugeFlowTableDBLogger(GaugeFlowTablePoller, GaugeNsODBC):
    """Periodically dumps the current datapath flow table to ODBC DB."""

    def __init__(self, conf, logname):
        super(GaugeFlowTableDBLogger, self).__init__(conf, logname)
        self.setup()

    def update(self, rcv_time, dp_id, msg):
        super(GaugeFlowTableDBLogger, self).update(rcv_time, dp_id, msg)
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
