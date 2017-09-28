"""Unit tests for gauge"""

try:
    # Python 2
    from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
    import mock
except ImportError:
    # Python 3
    from http.server import HTTPServer, BaseHTTPRequestHandler
    from unittest import mock
import unittest
import time
import math
import threading
import requests

from faucet import gauge_prom, gauge_influx
from ryu.ofproto import ofproto_v1_3 as ofproto
from ryu.ofproto import ofproto_v1_3_parser as parser


def create_mock_datapath(num_ports):
    """Mock a datapath by creating mocked datapath ports."""
    ports = {}
    for i in range(1, num_ports + 1):
        port = mock.Mock()
        port_name = mock.PropertyMock(return_value='port' + str(i))
        type(port).name = port_name
        ports[i] = port

    datapath = mock.Mock(ports=ports, id=1)
    dp_name = mock.PropertyMock(return_value='datapath')
    type(datapath).name = dp_name
    return datapath

def start_server():
    server = HTTPServer(('', 0), PretendInflux)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    return server


class PretendInflux(BaseHTTPRequestHandler):

    def do_POST(self):
        if hasattr(self.server, 'output_file'):
            content_length = int(self.headers['content-length'])
            data = self.rfile.read(content_length)
            self.server.output_file.write(data)
            self.server.output_file.flush()

        self.send_response(204)
        self.end_headers()

    def log_message(self, format_, *args):
        return

class GaugePrometheusTests(unittest.TestCase):
    """Tests the GaugePortStatsPrometheusPoller update method"""

    def parse_prom_output(self, output):
        """Parses the port stats from prometheus into a dictionary"""

        parsed_output = {}
        for line in output.split('\n'):
            # discard comments and stats not related to port stats
            if line.startswith('#') or not line.startswith(gauge_prom.PROM_PORT_PREFIX):
                continue

            index = line.find('{')
            #get the stat name e.g. of_port_rx_bytes and strip 'of_port_'
            prefix = gauge_prom.PROM_PORT_PREFIX + gauge_prom.PROM_PREFIX_DELIM
            stat_name = line[0:index].replace(prefix, '')
            #get the labels within {}
            labels = line[index + 1:line.find('}')].split(',')

            for label in labels:
                lab_name, lab_val = label.split('=')
                lab_val = lab_val.replace('"', '')
                if lab_name == 'dp_id':
                    dp_id = int(lab_val, 16)
                elif lab_name == 'port_name':
                    port_name = lab_val

            key = (dp_id, port_name)
            stat_val = line.split(' ')[1]
            if key not in parsed_output:
                parsed_output[key] = []

            parsed_output[key].append((stat_name, float(stat_val)))

        return parsed_output

    def get_prometheus_stats(self, addr, port):
        """Attempts to contact the prometheus server
        at the address to grab port stats."""

        url = 'http://{}:{}'.format(addr, port)
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(max_retries=10)
        session.mount('http://', adapter)
        return session.get(url).text

    def test_poller(self):
        """Test the update method to see if it pushes port stats"""

        prom_client = gauge_prom.GaugePrometheusClient()
        datapath = create_mock_datapath(2)

        conf = mock.Mock(dp=datapath,
                         type='',
                         interval=1,
                         prometheus_port=9303,
                         prometheus_addr='localhost'
                        )


        prom_poller = gauge_prom.GaugePortStatsPrometheusPoller(conf, '__name__', prom_client)
        port1 = parser.OFPPortStats(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 100, 50)
        port2 = parser.OFPPortStats(2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 100, 50)
        message = parser.OFPPortStatsReply(datapath, body=[port1, port2])
        dp_id = 1
        prom_poller.update(time.time(), dp_id, message)

        prom_lines = self.get_prometheus_stats(conf.prometheus_addr, conf.prometheus_port)
        prom_lines = self.parse_prom_output(prom_lines)

        for port_num, port in datapath.ports.items():
            stats = prom_lines[(dp_id, port.name)]
            stats_found = set()

            for stat_name, stat_val in stats:
                self.assertAlmostEqual(stat_val, port_num)
                stats_found.add(stat_name)

            self.assertEqual(stats_found, set(gauge_prom.PROM_PORT_VARS))

class GaugeInfluxShipperTest(unittest.TestCase):
    """Tests the InfluxShipper"""

    def create_config_obj(self, port=12345):
        """Create a mock config object that contains the necessary InfluxDB config"""

        conf = mock.Mock(influx_host='localhost',
                         influx_port=port,
                         influx_user='gauge',
                         influx_pwd='',
                         influx_db='gauge',
                         influx_timeout=10
                        )
        return conf

    def get_values(self, dict_to_unpack):
        """Get all the values from a nested dictionary"""

        values = []
        for value in dict_to_unpack.values():
            if isinstance(value, dict):
                values.extend(self.get_values(value))
            else:
                values.append(value)
        return values

    def test_ship_success(self):
        """Checks that the shipper successsfully connects
        to a HTTP server when the points are shipped"""

        try:
            server = start_server()
            shipper = gauge_influx.InfluxShipper()
            shipper.conf = self.create_config_obj(server.server_port)
            points = [{'measurement': 'test_stat_name', 'fields' : {'value':1}},]
            shipper.ship_points(points)

        except Exception as err:
            self.fail("Code threw an exception: {}".format(err))
        finally:
            server.shutdown()


    def test_ship_connection_err(self):
        """Checks that even when there is a connection error,
        there is no exception thrown"""

        try:
            shipper = gauge_influx.InfluxShipper()
            shipper.conf = self.create_config_obj()
            shipper.logger = mock.Mock()
            points = [{'measurement': 'test_stat_name', 'fields' : {'value':1}},]
            shipper.ship_points(points)

        except Exception as err:
            self.fail("Code threw an exception: {}".format(err))

    def test_ship_no_config(self):
        """Check that no exceptions are thrown when
        there is no config"""

        try:
            shipper = gauge_influx.InfluxShipper()
            points = [{'measurement': 'test_stat_name', 'fields' : {'value':1}},]
            shipper.ship_points(points)

        except Exception as err:
            self.fail("Code threw an exception: {}".format(err))

    def test_point(self):
        """Checks that the points produced still have the variables given to it"""

        shipper = gauge_influx.InfluxShipper()
        dp_name = 'windscale-faucet-1'
        port_name = 'port1.0.1'
        rcv_time = int(time.time())
        stat_name = 'test_stat_name'
        #max uint64 number
        stat_val = math.pow(2, 64) - 1

        port_point = shipper.make_port_point(dp_name, port_name, rcv_time, stat_name, stat_val)
        values = {dp_name, port_name, rcv_time, stat_name, stat_val}
        port_vals = self.get_values(port_point)
        self.assertEqual(set(port_vals), values)

        tags = {'dp_name': dp_name, 'port_name': port_name}
        point = shipper.make_point(tags, rcv_time, stat_name, stat_val)
        point_vals = self.get_values(point)
        self.assertEqual(set(point_vals), values)



if __name__ == "__main__":
    unittest.main()
