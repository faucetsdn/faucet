"""Unit tests for Mininet Topologies in mininet_test_topo"""

from unittest import TestCase, main

from clib.mininet_test_topo import FaucetStringOfDPSwitchTopo
from clib.mininet_test_util import flat_test_name


class FaucetStringOfDPSwitchTopoTest(TestCase):
    """Tests for FaucetStringOfDPSwitchTopoTest"""

    serial = 0
    maxDiff = None
    dpids = ['1', '2', '3']

    def get_serialno(self, *_args, **_kwargs):
        """"Return mock serial number"""
        self.serial += 1
        return self.serial

    def string_of_dp_args(self, **kwargs):
        """Return default topo constructor params"""
        defaults = dict(
            ovs_type='user',
            ports_sock=None,
            dpids=self.dpids,
            test_name=flat_test_name(self.id()),
            get_serialno=self.get_serialno,
            switch_to_switch_links=2)
        defaults.update(kwargs)
        return defaults

    def test_string_of_dp_sanity(self):
        """FaucetStringOfDPSwitchTopo sanity test"""

        # Create a basic string topo
        peer_link = FaucetStringOfDPSwitchTopo.peer_link
        args = self.string_of_dp_args(
            n_tagged=2,
            n_untagged=2,
            links_per_host=1,
            switch_to_switch_links=2,
            start_port=1)
        topo = FaucetStringOfDPSwitchTopo(**args)

        # Verify switch ports
        self.assertEqual(
            {dpid:topo.dpid_ports(dpid) for dpid in self.dpids},
            # 4 host ports and 2/4/2 peer links, respectively
            {
                '1': [1, 2, 3, 4, 5, 6],
                '2': [1, 2, 3, 4, 5, 6, 7, 8],
                '3': [1, 2, 3, 4, 5, 6]
            }, "switch ports are incorrect")

        # Verify peer links

        self.assertEqual(
            {dpid:topo.dpid_peer_links(dpid) for dpid in self.dpids},
            # Should be linked to previous and next switch
            {
                '1': [
                    peer_link(port=5, peer_dpid='2', peer_port=5),
                    peer_link(port=6, peer_dpid='2', peer_port=6)
                ],
                '2': [
                    peer_link(port=5, peer_dpid='1', peer_port=5),
                    peer_link(port=6, peer_dpid='1', peer_port=6),
                    peer_link(port=7, peer_dpid='3', peer_port=5),
                    peer_link(port=8, peer_dpid='3', peer_port=6)
                ],
                '3': [
                    peer_link(port=5, peer_dpid='2', peer_port=7),
                    peer_link(port=6, peer_dpid='2', peer_port=8)
                ]
            }, "peer links are incorrect")


if __name__ == "__main__":
    main()
