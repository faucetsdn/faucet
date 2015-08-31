#!/usr/bin/python

# Copyright (C) 2015 Research and Innovation Advanced Network New Zealand Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys, os, unittest

testdir = os.path.dirname(__file__)
srcdir = '..'
sys.path.insert(0, os.path.abspath(os.path.join(testdir, srcdir)))

from ryu.ofproto import ether
from ryu.ofproto import ofproto_v1_3 as ofp
from valve import OVSStatelessValve
from dp import DP
from fakeoftable import FakeOFTable

class ValveTestCase(unittest.TestCase):
    def setUp(self):
        dp = DP.parser("tests/config/valve-test.yaml")
        self.valve = OVSStatelessValve(dp)
        self.table = FakeOFTable()
        self.table.apply_ofmsgs(self.valve.datapath_connect(1, [1,2,3,4,5,6]))
        rcv_packet_ofmsgs = self.valve.rcv_packet(
            dp_id=1,
            in_port=1,
            vlan_vid=10,
            eth_src="00:00:00:00:00:01",
            eth_dst="00:00:00:00:00:02")
        self.table.apply_ofmsgs(rcv_packet_ofmsgs)
        rcv_packet_ofmsgs = self.valve.rcv_packet(
            dp_id=1,
            in_port=3,
            vlan_vid=11,
            eth_src="00:00:00:00:00:03",
            eth_dst="00:00:00:00:00:04")
        self.table.apply_ofmsgs(rcv_packet_ofmsgs)


    def test_drop_rule(self):
        """Test that packets with incorrect vlan tagging get dropped.

        Packets arriving on a tagged port with vlan tags that are not
        configured on that port should be dropped."""
        drop_matches = [
            {'in_port': 3, 'vlan_vid': 92398012983},
            {   'in_port': 3,
                'vlan_vid': 92398012983,
                'eth_src': "00:00:00:00:00:03"},
            {'in_port': 3, 'vlan_vid': 10|ofp.OFPVID_PRESENT},
            {'in_port': 2}]
        for drop_match in drop_matches:
            self.assertFalse(
                self.table.is_output(drop_match),
                msg="Packets with incorrect vlan tags are output")

    def test_unknown_eth_src_rule_tagged(self):
        """Test that tagged packets from unknown macs are sent to controller.
        """
        matches = [
            {'in_port': 3, 'vlan_vid': 11|ofp.OFPVID_PRESENT},
            {'in_port': 2, 'vlan_vid': 11|ofp.OFPVID_PRESENT},
            {   'in_port': 2,
                'vlan_vid': 11|ofp.OFPVID_PRESENT,
                'eth_dst' : "00:00:00:00:00:03"},
            {'in_port': 2, 'vlan_vid': 10|ofp.OFPVID_PRESENT}]
        for match in matches:
            self.assertTrue(
                self.table.is_output(match, ofp.OFPP_CONTROLLER),
                msg="Packet with unknown ethernet src not sent to controller")


    def test_unknown_eth_src_rule_untagged(self):
        """Test that untagged packets with unknown macs are sent to controller.

        Untagged packets should have VLAN tags pushed before they are sent to
        the controler.
        """
        matches = [
            {'in_port': 4, 'eth_dst' : "00:00:00:00:00:03"},
            {'in_port': 4},
            {'in_port': 1},
            {'in_port': 1}]
        for match in matches:
            self.assertTrue(
                self.table.is_output(match, ofp.OFPP_CONTROLLER),
                msg="Packets with unknown ethernet src not sent to controller")

    def test_unknown_eth_dst_rule(self):
        """Test that packets with unkown eth dst addrs get flooded correctly.

        They must be output to each port on the associated vlan, with the
        correct vlan tagging."""
        matches = [
            {'in_port': 4},
            {'in_port': 3, 'vlan_vid': 11|ofp.OFPVID_PRESENT},
            {   'in_port': 3,
                'vlan_vid': 11|ofp.OFPVID_PRESENT,
                'eth_src': "00:00:00:00:00:03"},
            {'in_port': 2, 'vlan_vid': 11|ofp.OFPVID_PRESENT},
            {'in_port': 2, 'vlan_vid': 10|ofp.OFPVID_PRESENT},
            {'in_port': 1, 'eth_src': "00:00:00:00:00:01"},
            {'in_port': 1}]
        dp = self.valve.dp
        for match in matches:
            in_port = match['in_port']

            if 'vlan_vid' in match:
                vlan = dp.vlans[match['vlan_vid'] & ~ofp.OFPVID_PRESENT]
            else:
                vlan = self.valve.dp.get_native_vlan(in_port)

            remaining_ports = set(range(1, 6))

            # Check packets are output to each port on vlan
            for p in vlan.get_ports():
                remaining_ports.discard(p.number)
                if p.number != in_port and p.running():
                    if vlan.port_is_tagged(p.number):
                        vid = vlan.vid|ofp.OFPVID_PRESENT
                    else:
                        vid = 0
                    self.assertTrue(
                        self.table.is_output(match, port=p.number, vlan=vid),
                        msg="packet with unknown eth dst ({0}) not output "
                            "correctly on vlan {1} to port {2}".format(match, vlan.vid, p.number))


            # Check packets are not output to ports not on vlan
            for p in remaining_ports:
                self.assertFalse(
                    self.table.is_output(match, port=p),
                    msg="packet with unkown eth dst output to port not on its vlan ({0})".format(p))


    def test_known_eth_src_rule(self):
        """test that packets with known eth src addrs are not sent to controller."""
        matches = [
            {   'in_port': 3,
                'vlan_vid': 11|ofp.OFPVID_PRESENT,
                'eth_src': "00:00:00:00:00:03"},
            {   'in_port': 1,
                'eth_src': "00:00:00:00:00:01"}]
        for match in matches:
            self.assertFalse(
                self.table.is_output(match, port=ofp.OFPP_CONTROLLER),
                msg="Packet output to controller when eth_src address is known")

    def test_known_eth_src_deletion(self):
        """Verify that when a mac changes port the old rules get deleted.

        If a mac address is seen on one port, then seen on a different port on
        the same vlan the rules associated with that mac address on previous
        port need to be deleted. IE packets with that mac address arriving on
        the old port should be output to the controller."""
        rcv_packet_ofmsgs = self.valve.rcv_packet(
            dp_id=1,
            in_port=2,
            vlan_vid=11,
            eth_src="00:00:00:00:00:03",
            eth_dst="00:00:00:00:00:04")
        self.table.apply_ofmsgs(rcv_packet_ofmsgs)

        match = {
            'in_port': 3,
            'vlan_vid': 11|ofp.OFPVID_PRESENT,
            'eth_src': "00:00:00:00:00:03"}
        self.assertTrue(
            self.table.is_output(match, ofp.OFPP_CONTROLLER),
            msg='eth src rule not deleted when mac seen on another port')

    def test_known_eth_src_vlan_separation(self):
        """Test that when a mac is seen on a second vlan the original vlan
        rules are unaffected."""
        rcv_packet_ofmsgs = self.valve.rcv_packet(
            dp_id=1,
            in_port=2,
            vlan_vid=10,
            eth_src="00:00:00:00:00:03",
            eth_dst="00:00:00:00:00:04")
        self.table.apply_ofmsgs(rcv_packet_ofmsgs)

        match = {
            'in_port': 3,
            'vlan_vid': 11|ofp.OFPVID_PRESENT,
            'eth_src': "00:00:00:00:00:03"}
        self.assertFalse(
            self.table.is_output(match, ofp.OFPP_CONTROLLER),
            msg="mac address being seen on a vlan interferes with rules on other vlans")

    def test_known_eth_dst_rule(self):
        """Test that packets with known eth dst addrs are output correctly.

        Output to the correct port with the correct vlan tagging."""
        tagged_matches = [
            {   'in_port': 2,
                'vlan_vid': 11|ofp.OFPVID_PRESENT,
                'eth_dst': "00:00:00:00:00:03"},
            {   'in_port': 4,
                'eth_dst': "00:00:00:00:00:03"}]

        for tagged_match in tagged_matches:
            self.assertTrue(
                self.table.is_output(tagged_match, port=3, vlan=11|ofp.OFPVID_PRESENT),
                msg="packet not output to untagged port correctly when eth dst is known")
            for port in [1, 2, 4, 5, 6]:
                self.assertFalse(
                    self.table.is_output(tagged_match, port=port),
                    msg="packet output to incorrect port when eth dst is known")

        untagged_match = {
            'in_port': 2,
            'vlan_vid': 10|ofp.OFPVID_PRESENT,
            'eth_dst': "00:00:00:00:00:01"}
        self.assertTrue(
            self.table.is_output(untagged_match, port=1, vlan=0),
            msg="packet not output to tagged port correctly when eth dst is known")
        for port in range(2, 7):
            self.assertFalse(
                self.table.is_output(untagged_match, port=port),
                msg="packet output to incorrect port when eth dst is known")

    def test_known_eth_dst_rule_deletion(self):
        """Test that eth dst rules are deleted when the mac is learned on another port.

        This should only occur when the mac is seen on the same vlan."""
        rcv_packet_ofmsgs = self.valve.rcv_packet(
            dp_id=1,
            in_port=2,
            vlan_vid=11,
            eth_src="00:00:00:00:00:03",
            eth_dst="00:00:00:00:00:04")
        self.table.apply_ofmsgs(rcv_packet_ofmsgs)
        match = {
            'in_port': 4,
            'vlan_vid': 11|ofp.OFPVID_PRESENT,
            'eth_dst': "00:00:00:00:00:03"}
        self.assertFalse(
            self.table.is_output(match, port=3),
            msg="Packet output on old port after mac is learnt on new port")

    def test_multicast_eth_src_rcv_packet(self):
        """Test that no rules are installed in for packets with multicast eth src."""
        self.assertEqual(
            [],
            self.valve.rcv_packet(
                dp_id=1,
                in_port=2,
                vlan_vid=10,
                eth_src="01:00:00:00:00:01",
                eth_dst="00:00:00:00:00:02"))

    def test_bpdu_drop(self):
        """Test that STP BPDUs are dropped."""
        matches = [
            {   'in_port': 2,
                'vlan_vid': 11|ofp.OFPVID_PRESENT,
                'eth_dst': "01:80:C2:00:00:00"},
            {   'in_port': 4,
                'eth_dst': "01:00:0C:CC:CC:CD"}]
        for match in matches:
            self.assertFalse(
                self.table.is_output(match),
                msg="STP BPDU output")

    def test_lldp_drop(self):
        """Test that LLDP packets are dropped."""
        match = {
            'in_port': 2,
            'vlan_vid': 11|ofp.OFPVID_PRESENT,
            'eth_type': ether.ETH_TYPE_LLDP}
        self.assertFalse(
            self.table.is_output(match),
            msg="LLDP packet output")

    def test_port_delete(self):
        """Test that when a port is disabled packets are correctly output. """
        match = {
            'in_port': 2,
            'vlan_vid': 11|ofp.OFPVID_PRESENT,
            'eth_dst': "00:00:00:00:00:03"}

        vlan = self.valve.dp.vlans[match['vlan_vid'] & ~ofp.OFPVID_PRESENT]

        ofmsgs = self.valve.port_delete(dp_id=1, portnum=3)
        self.table.apply_ofmsgs(ofmsgs)

        # Check packets are output to each port on vlan
        for p in vlan.get_ports():
            if p.number != match['in_port'] and p.running():
                if vlan.port_is_tagged(p.number):
                    vid = vlan.vid|ofp.OFPVID_PRESENT
                else:
                    vid = 0
                self.assertTrue(
                    self.table.is_output(match, port=p.number, vlan=vid),
                    msg="packet ({0}) with eth dst learnt on deleted port not output "
                        "correctly on vlan {1} to port {2}".format(match, vlan.vid, p.number))

    def test_port_add_input(self):
        """test that when a port is enabled packets are input correctly."""
        match = {'in_port': 7}
        ofmsgs = self.valve.port_add(dp_id=1, portnum=7)
        self.table.apply_ofmsgs(ofmsgs)
        self.assertTrue(
            self.table.is_output(match),
            msg="Packet arriving on port after add not output")

    def test_port_add_flood(self):
        """test that when a port is enabled packets are correctly output."""
        match = {'in_port': 5}
        ofmsgs = self.valve.port_add(dp_id=1, portnum=7)
        self.table.apply_ofmsgs(ofmsgs)
        self.assertTrue(
            self.table.is_output(match, port=7),
            msg="Packet not output to port after add")

    def test_reload_drop(self):
        """Test that after a config reload packets with invalid vlan tags are
        dropped.
        """
        match = {
            'in_port': 3,
            'vlan_vid': 11|ofp.OFPVID_PRESENT}
        new_dp = DP.parser("tests/config/valve-test-reload.yaml")
        ofmsgs = self.valve.reload_config(new_dp)
        self.table.apply_ofmsgs(ofmsgs)
        self.assertFalse(
            self.table.is_output(match),
            msg='Output action  when packet should be dropped after reload')

    def test_reload_unknown_eth_dst_rule(self):
        """Test that packets with unkown eth dst addrs get flooded correctly
        after a config reload.

        They must be output to each currently running port on the associated
        vlan, with the correct vlan tagging."""
        matches = [
            {'in_port': 4},
            {'in_port': 3, 'vlan_vid': 10|ofp.OFPVID_PRESENT},
            {   'in_port': 3,
                'vlan_vid': 10|ofp.OFPVID_PRESENT,
                'eth_src': "00:00:00:00:00:01"},
            {'in_port': 2, 'vlan_vid': 11|ofp.OFPVID_PRESENT},
            {   'in_port': 2,
                'vlan_vid': 11|ofp.OFPVID_PRESENT,
                'eth_dst': "00:00:00:00:00:01"},
            {'in_port': 2, 'vlan_vid': 10|ofp.OFPVID_PRESENT},
            {'in_port': 1, 'eth_src': "00:00:00:00:00:03"},
            {'in_port': 1}]
        dp = DP.parser("tests/config/valve-test-reload.yaml")
        ofmsgs = self.valve.reload_config(dp)
        self.table.apply_ofmsgs(ofmsgs)
        for match in matches:
            in_port = match['in_port']

            if 'vlan_vid' in match:
                vlan = dp.vlans[match['vlan_vid'] & ~ofp.OFPVID_PRESENT]
            else:
                # if a tagged port arrives on an untagged interface, we can
                # ignore the label
                vlan = dp.get_native_vlan(in_port)

            # the ports that have not yet had packets output to them
            remaining_ports = set(range(1, 7))
            for p in vlan.get_ports():
                remaining_ports.discard(p.number)
                if p.number != in_port and p.running():
                    if vlan.port_is_tagged(p.number):
                        vid = vlan.vid|ofp.OFPVID_PRESENT
                    else:
                        vid = 0

                    self.assertTrue(
                        self.table.is_output(match, port=p.number, vlan=vid),
                        msg="packet ({0}) not output correctly to port {1} on "
                            "vlan {2} when flooding after reload".format(match, p.number, vid))
            for p in remaining_ports:
                self.assertFalse(
                    self.table.is_output(match, p),
                    msg="packet output to port not on vlan after reload")


    def test_reload_port_disable(self):
        """Test that when a port is disabled in a reload packets are not output
        to it. """
        matches = [
            {'in_port': 4},
            {   'in_port': 2,
                'vlan_vid': 11|ofp.OFPVID_PRESENT,
                'eth_dst': "00:00:00:00:00:05"}]
        rcv_packet_ofmsgs = self.valve.rcv_packet(
            dp_id=1,
            in_port=5,
            vlan_vid=11,
            eth_src="00:00:00:00:00:05",
            eth_dst="00:00:00:00:00:06")
        self.table.apply_ofmsgs(rcv_packet_ofmsgs)
        dp = DP.parser("tests/config/valve-test-reload.yaml")
        ofmsgs = self.valve.reload_config(dp)
        self.table.apply_ofmsgs(ofmsgs)
        for match in matches:
            self.assertFalse(
                self.table.is_output(match, port=5),
                msg="packet output to disabled port")

if __name__ == "__main__":
    unittest.main()
