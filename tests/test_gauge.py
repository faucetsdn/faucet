"""Unit tests for gauge"""

try:
    import mock  # Python 2
except ImportError:
    from unittest import mock  # Python 3
import unittest
import time
import requests

import faucet.gauge_prom as gauge_prom
from ryu.ofproto.ofproto_v1_3_parser import OFPPortStatsReply, OFPPortStats

class GaugePrometheusTests(unittest.TestCase):
    """Tests the GaugePortStatsPrometheusPoller update method"""

    def parse_prom_output(self, output):
        """Parses the port stats from prometheus into a dictionary"""

        parsed_output = {}
        for line in output.split("\n"):
            # discard comments and stats not related to port stats
            if line.startswith("#") or not line.startswith(gauge_prom.PROM_PORT_PREFIX):
                continue

            index = line.find("{")
            #get the stat name e.g. of_port_rx_bytes and strip "of_port_"
            prefix = gauge_prom.PROM_PORT_PREFIX + gauge_prom.PROM_PREFIX_DELIM
            stat_name = line[0:index].replace(prefix, "")
            #get the labels within {}
            labels = line[index + 1:line.find("}")].split(",")

            for label in labels:
                lab_name, lab_val = label.split("=")
                lab_val = lab_val.replace('"', '')
                if lab_name == "dp_id":
                    dp_id = int(lab_val, 16)
                elif lab_name == "port_name":
                    port_name = lab_val

            key = (dp_id, port_name)
            stat_val = line.split(" ")[1]
            if key not in parsed_output:
                parsed_output[key] = []

            parsed_output[key].append((stat_name, float(stat_val)))

        return parsed_output

    def create_mock_datapath(self, num_ports):
        """Mock a datapath by creating mocked datapath ports."""
        ports = {}
        for i in range(1, num_ports + 1):
            port = mock.Mock()
            port_name = mock.PropertyMock(return_value="port" + str(i))
            type(port).name = port_name

        return mock.Mock(ports=ports)

    def get_prometheus_stats(self, addr, port):
        """Attempts to contact the prometheus server
        at the address to grab port stats."""

        url = "http://{}:{}".format(addr, port)
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(max_retries=10)
        session.mount("http://", adapter)
        return session.get(url).text

    def test_poller(self):
        """Test the update method to see if it pushes port stats"""

        prom_client = gauge_prom.GaugePrometheusClient()
        datapath = self.create_mock_datapath(2)

        conf = mock.Mock(dp=datapath,
                         type="",
                         interval=1,
                         prometheus_port=9303,
                         prometheus_addr="localhost"
                        )


        prom_poller = gauge_prom.GaugePortStatsPrometheusPoller(conf, "__name__", prom_client)
        port1 = OFPPortStats(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 100, 50)
        port2 = OFPPortStats(2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 100, 50)
        message = OFPPortStatsReply(datapath, body=[port1, port2])
        dp_id = 1
        prom_poller.update(time.time(), dp_id, message)

        prom_lines = self.get_prometheus_stats(conf.prometheus_addr, conf.prometheus_port)
        prom_lines = self.parse_prom_output(prom_lines)

        for port_num, port in datapath.ports.items():
            stats = prom_lines[(dp_id, port.name)]
            for _, stat_val in stats:
                self.assertAlmostEqual(stat_val, port_num)


if __name__ == "__main__":
    unittest.main()
