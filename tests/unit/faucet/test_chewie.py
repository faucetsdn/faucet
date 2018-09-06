#!/usr/bin/env python

"""Unit tests run as PYTHONPATH=.. python3 ./test_chewie.py."""


import unittest

from chewie.mac_address import MacAddress
from tests.unit.faucet import test_valve

DP1_CONFIG = """
        dp_id: 1
        dot1x:
            nfv_intf: abcdef"""

CONFIG = """
acls:
    eapol_to_nfv:
        - rule:
            dl_type: 0x888e
            actions:
                output:
                    # set_fields:
                        # - eth_dst: NFV_MAC
                    port: p2
        - rule:
            eth_src: ff:ff:ff:ff:ff:ff
            actions:
                allow: 0
        - rule:
            actions:
                allow: 0
    eapol_from_nfv:
        - rule:
            dl_type: 0x888e
            # eth_dst: NFV_MAC
            actions:
                output:
                    # set_fields:
                        # - eth_dst: 01:80:c2:00:00:03
                    port: p1
        - rule:
            actions:
                allow: 0
    allowall:
        - rule:
            actions:
                allow: 1
dps:
    s1:
        hardware: 'GenericTFM'
%s
        interfaces:
            p1:
                number: 1
                native_vlan: v100
                dot1x: True
                acl_in: eapol_to_nfv
            p2:
                number: 2
                native_vlan: v100
                acl_in: eapol_from_nfv
            p3:
                number: 3
                native_vlan: v100
                acl_in: allowall
vlans:
    v100:
        vid: 0x100
""" % DP1_CONFIG


class FaucetDot1XTest(test_valve.ValveTestBases.ValveTestSmall):
    """Test chewie api"""

    def setUp(self):
        self.setup_valve(CONFIG)

    def test_success_dot1x(self):
        """Test success api"""
        self.dot1x.reset(valves=self.valves_manager.valves)
        self.assertEqual(len(self.last_flows_to_dp[1]), 0)
        self.dot1x.dot1x_speaker.auth_success(MacAddress.from_string('00:00:00:00:ab:01'))  #,
                                              # MacAddress.from_string('00:00:00:00:00:01'))
        # 2 = 1 FlowMod + 1 Barrier
        self.assertEqual(len(self.last_flows_to_dp[1]), 2, self.last_flows_to_dp[1])
    #
    # def _test_failure_dot1x(self):
    #     """Test failure api"""
    #     self.dot1x.reset(valves=self.valves_manager.valves)
    #     self.assertEqual(len(self.last_flows_to_dp[1]), 0)
    #     self.dot1x.dot1x_speaker.auth_faliure(MacAddress.from_string('00:00:00:00:ab:01'),
    #                                           MacAddress.from_string('00:00:00:00:00:01'))
    #
    # def _test_logoff_dot1x(self):
    #     """Test logoff api"""
    #     self.dot1x.reset(valves=self.valves_manager.valves)
    #     self.assertEqual(len(self.last_flows_to_dp[1]), 0)
    #     self.dot1x.dot1x_speaker.auth_logoff(MacAddress.from_string('00:00:00:00:ab:01'),
    #                                           MacAddress.from_string('00:00:00:00:00:01'))
    #     # 2 = 1 FlowMod + 1 Barrier
    #     self.assertEqual(len(self.last_flows_to_dp[1]), 2, self.last_flows_to_dp[1])


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
