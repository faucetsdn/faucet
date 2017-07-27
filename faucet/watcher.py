import json
import time

try:
    from valve_util import dpid_log
    from gauge_influx import GaugePortStateInfluxDBLogger, GaugePortStatsInfluxDBLogger, GaugeFlowTableInfluxDBLogger
    from gauge_nsodbc import GaugeFlowTableDBLogger
    from gauge_pollers import GaugePortStateBaseLogger, GaugePortStatsPoller, GaugeFlowTablePoller
except ImportError:
    from faucet.valve_util import dpid_log
    from faucet.gauge_influx import GaugePortStateInfluxDBLogger, GaugePortStatsInfluxDBLogger, GaugeFlowTableInfluxDBLogger
    from faucet.gauge_nsodbc import GaugeFlowTableDBLogger
    from faucet.gauge_pollers import GaugePortStateBaseLogger, GaugePortStatsPoller, GaugeFlowTablePoller


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
            'influx': GaugeFlowTableInfluxDBLogger,
            },
    }

    w_type = conf.type
    db_type = conf.db_type
    if w_type in WATCHER_TYPES and db_type in WATCHER_TYPES[w_type]:
        return WATCHER_TYPES[w_type][db_type]
    return None


def _rcv_time(rcv_time):
    return time.strftime('%b %d %H:%M:%S', time.localtime(rcv_time))


class GaugePortStateLogger(GaugePortStateBaseLogger):

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
