#!/usr/bin/env python

"""Unit tests run as PYTHONPATH=../../.. python3 ./test_chewie.py."""

from queue import Queue
import random
import time
import unittest
from unittest.mock import patch

from netils import build_byte_string

from test_valve import ValveTestBases

DOT1X_DP1_CONFIG = """
        dp_id: 1
        dot1x:
            nfv_intf: lo
            nfv_sw_port: 2
            radius_ip: 127.0.0.1
            radius_port: 1812
            radius_secret: SECRET"""

DOT1X_CONFIG = """
dps:
    s1:
        hardware: 'GenericTFM'
%s
        interfaces:
            p1:
                number: 1
                native_vlan: v100
                dot1x: True
            p2:
                number: 2
                native_vlan: v100
            p3:
                number: 3
                native_vlan: v100
vlans:
    v100:
        vid: 0x100
""" % DOT1X_DP1_CONFIG

FROM_SUPPLICANT = Queue()
TO_SUPPLICANT = Queue()
FROM_RADIUS = Queue()
TO_RADIUS = Queue()


def supplicant_replies():
    """generator for packets supplicant sends"""
    header = "0000000000010242ac17006f888e"
    replies = [build_byte_string(header + "01000009027400090175736572"),
               build_byte_string(header + "010000160275001604103abcadc86714b2d75d09dd7ff53edf6b")]

    for reply in replies:
        yield reply


def radius_replies():
    """generator for packets radius sends"""
    replies = [build_byte_string("0b040050e5e40d846576a2310755e906c4b2b5064f180175001604101a16a3baa37a0238f33384f6c11067425012ce61ba97026b7a05b194a930a922405218126aa866456add628e3a55a4737872cad6"),
               build_byte_string("02050032fb4c4926caa21a02f74501a65c96f9c74f06037500045012c060ca6a19c47d0998c7b20fd4d771c1010675736572")]
    for reply in replies:
        yield reply


def urandom():
    """generator for urandom"""
    _list = [b'\x87\xf5[\xa71\xeeOA;}\\t\xde\xd7.=',
             b'\xf7\xe0\xaf\xc7Q!\xa2\xa9\xa3\x8d\xf7\xc6\x85\xa8k\x06']
    for item in _list:
        yield item


URANDOM_GENERATOR = urandom()


def urandom_helper(size):  # pylint: disable=unused-argument
    """helper for urandom_generator"""
    return next(URANDOM_GENERATOR)


SUPPLICANT_REPLY_GENERATOR = supplicant_replies()
RADIUS_REPLY_GENERATOR = radius_replies()


def do_nothing(chewie):  # pylint: disable=unused-argument
    """mocked function that does nothing"""
    pass


def eap_receive(chewie):  # pylint: disable=unused-argument
    """mocked chewie.eap_receive"""
    return FROM_SUPPLICANT.get()


def eap_send(chewie, data):  # pylint: disable=unused-argument
    """mocked chewie.eap_send"""

    TO_SUPPLICANT.put(data)
    try:
        _next = next(SUPPLICANT_REPLY_GENERATOR)
    except StopIteration:
        return
    if _next:
        FROM_SUPPLICANT.put(_next)


def radius_receive(chewie):  # pylint: disable=unused-argument
    """mocked chewie.radius_radius"""
    return FROM_RADIUS.get()


def radius_send(chewie, data):  # pylint: disable=unused-argument
    """mocked chewie.radius_send"""
    TO_RADIUS.put(data)
    try:
        _next = next(RADIUS_REPLY_GENERATOR)
    except StopIteration:
        return
    if _next:
        FROM_RADIUS.put(_next)


def nextId(eap_sm):  # pylint: disable=invalid-name
    """Determines the next identifier value to use, based on the previous one.
    Returns:
        integer"""
    if eap_sm.currentId is None:
        # I'm assuming we cant have ids wrap around in the same series.
        #  so the 200 provides a large buffer.
        return 116
    _id = eap_sm.currentId + 1
    if _id > 255:
        return random.randint(0, 200)
    return _id


def get_next_radius_packet_id(chewie):
    """Calulate the next RADIUS Packet ID
    Returns:
        int
    """
    if chewie.radius_id == -1:
        chewie.radius_id = 4
        return chewie.radius_id
    chewie.radius_id += 1
    if chewie.radius_id > 255:
        chewie.radius_id = 0
    return chewie.radius_id


class FaucetDot1XTest(ValveTestBases.ValveTestSmall):
    """Test chewie api"""

    def setUp(self):
        self.setup_valve(DOT1X_CONFIG)

    @patch('faucet.faucet_dot1x.chewie.os.urandom', urandom_helper)
    @patch('faucet.faucet_dot1x.chewie.FullEAPStateMachine.nextId', nextId)
    @patch('faucet.faucet_dot1x.chewie.Chewie.get_next_radius_packet_id', get_next_radius_packet_id)
    @patch('faucet.faucet_dot1x.chewie.Chewie.radius_send', radius_send)
    @patch('faucet.faucet_dot1x.chewie.Chewie.radius_receive', radius_receive)
    @patch('faucet.faucet_dot1x.chewie.Chewie.eap_send', eap_send)
    @patch('faucet.faucet_dot1x.chewie.Chewie.eap_receive', eap_receive)
    @patch('faucet.faucet_dot1x.chewie.Chewie.open_socket', do_nothing)
    @patch('faucet.faucet_dot1x.chewie.Chewie.get_interface_info', do_nothing)
    @patch('faucet.faucet_dot1x.chewie.Chewie.join_multicast_group', do_nothing)
    def test_success_dot1x(self):
        """Test success api"""

        FROM_SUPPLICANT.put(build_byte_string("0000000000010242ac17006f888e01010000"))
        time.sleep(5)
        with open('%s/faucet.log' % self.tmpdir, 'r') as log:
            for line in log.readlines():
                if 'Successful auth' in line:
                    break
            else:
                self.fail('Cannot find "Successful auth" string in faucet.log')
        self.assertEqual(1,
                         len(self.last_flows_to_dp[1]), self.last_flows_to_dp)


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
